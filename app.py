from datetime import datetime, timedelta, timezone
from collections.abc import Mapping
import base64
import csv
import io
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import sys
import tempfile
import threading
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from joserfc.errors import JoseError
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template_string,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.serving import make_server
from cloud_security_services import (
    MalwareScannerUnavailable,
    scan_with_clamav,
    upload_immutable_backup,
)

try:
    import pyotp
except ImportError:  # Optional during legacy upgrades; enabled when dependency is installed.
    pyotp = None

try:
    import razorpay  # type: ignore[import-not-found]
except ImportError:  # Optional until payment credentials and dependency are configured.
    razorpay = None


APP_FOLDER = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
RESOURCE_FOLDER = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
load_dotenv(APP_FOLDER / ".env", override=False)
app = Flask(__name__)

SHARED_FOLDER = Path(os.getenv("SHARED_FOLDER", APP_FOLDER / "storage")).resolve()
DATABASE = Path(os.getenv("FILE_SERVER_DATABASE", SHARED_FOLDER / "cloud_rdx.sqlite3")).resolve()
SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))
LOGIN_WINDOW_MINUTES = int(os.getenv("LOGIN_WINDOW_MINUTES", "15"))
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_LOCKOUT_MINUTES = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))
TRUSTED_PROXY_HOPS = int(os.getenv("TRUSTED_PROXY_HOPS", "0"))
INACTIVE_USER_DAYS = int(os.getenv("INACTIVE_USER_DAYS", "30"))
MAINTENANCE_DURATION_HOURS = 6
EMERGENCY_CONTROL_LABELS = {
    "global_read_only": ("Global read-only mode", "Blocks all user file writes and changes."),
    "disable_uploads": ("Disable uploads", "Prevents new file uploads."),
    "disable_downloads": ("Disable downloads", "Prevents file downloads."),
    "disable_deletion": ("Disable file deletion", "Prevents moving files or folders to the recycle bin."),
    "disable_editing": ("Disable file editing", "Prevents folder creation, copy, move, and rename."),
    "disable_file_sharing": ("Disable file sharing", "Blocks new share links and public access to existing links."),
    "revoke_active_share_links": ("Revoke active share links", "Temporarily suspends every active public share link without deleting it."),
    "freeze_registrations": ("Freeze new account registration", "Blocks password and social-provider account creation."),
    "force_reauthentication": ("Force re-authentication", "Revokes all user sessions except the authorized administrator."),
    "force_password_reset": ("Force password reset", "Requires password users to change their password after sign-in."),
    "require_two_factor": ("Require two-factor authentication", "Requires users to enroll in authenticator-based 2FA."),
    "disable_api_access": ("Disable API access", "Blocks application API routes; payment webhooks remain available."),
    "disable_sync_automation": ("Disable sync/automation", "Pauses scheduled Azure sync jobs until the control is cleared."),
    "block_public_access": ("Block public access", "Blocks unauthenticated access to shared files."),
    "block_new_devices": ("Block new devices", "Only previously approved browser devices may sign in."),
    "enhanced_monitoring": ("Enhanced security monitoring", "Records additional security-relevant activity."),
    "emergency_rate_limit": ("Emergency rate-limit mode", "Applies stricter limits to API and file-transfer routes."),
    "backup_protection": ("Backup protection mode", "Backups are append-only in the current application."),
    "maintenance_mode": ("Maintenance mode", "Shows a maintenance page to users while retaining owner access."),
}
EMERGENCY_PRESETS = {
    "NORMAL MODE": {},
    "RESTRICTED MODE": {
        "disable_uploads": True,
        "disable_deletion": True,
        "disable_editing": True,
        "disable_file_sharing": True,
    },
    "SECURITY MODE": {
        "disable_uploads": True,
        "disable_downloads": True,
        "disable_deletion": True,
        "disable_file_sharing": True,
        "disable_api_access": True,
        "block_new_devices": True,
        "enhanced_monitoring": True,
    },
    "FULL LOCKDOWN": {
        "global_read_only": True,
        "disable_uploads": True,
        "disable_downloads": True,
        "disable_deletion": True,
        "disable_editing": True,
        "disable_file_sharing": True,
        "revoke_active_share_links": True,
        "freeze_registrations": True,
        "force_reauthentication": True,
        "disable_api_access": True,
        "block_public_access": True,
        "enhanced_monitoring": True,
    },
}
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_MB", "100")) * 1024 * 1024
PORT = int(os.getenv("PORT", "8000"))
HOST = os.getenv("HOST", os.getenv("APP_HOST", "0.0.0.0"))
GOOGLE_OAUTH_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip()
GOOGLE_OAUTH_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
GITHUB_OAUTH_CLIENT_ID = os.getenv("GITHUB_OAUTH_CLIENT_ID", "").strip()
GITHUB_OAUTH_CLIENT_SECRET = os.getenv("GITHUB_OAUTH_CLIENT_SECRET", "").strip()
FLASK_SECRET_KEY_CONFIGURED = bool(os.getenv("FLASK_SECRET_KEY"))
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0") == "1",
)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
app.config["PREFERRED_URL_SCHEME"] = "https"
if TRUSTED_PROXY_HOPS < 0:
    raise ValueError("TRUSTED_PROXY_HOPS must be zero or greater")
if TRUSTED_PROXY_HOPS:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXY_HOPS, x_proto=TRUSTED_PROXY_HOPS)
oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=GOOGLE_OAUTH_CLIENT_ID,
    client_secret=GOOGLE_OAUTH_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)
github = oauth.register(
    name="github",
    client_id=GITHUB_OAUTH_CLIENT_ID,
    client_secret=GITHUB_OAUTH_CLIENT_SECRET,
    authorize_url="https://github.com/login/oauth/authorize",
    access_token_url="https://github.com/login/oauth/access_token",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "read:user user:email"},
)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admindivya")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
PAYMENT_QR_URL = os.getenv("PAYMENT_QR_URL", "/payment-qr")
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "")
RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "")
STORAGE_COST_PER_GB_INR = float(os.getenv("STORAGE_COST_PER_GB_INR", "0"))
RECOVERY_PASSWORD_CHARS = "RDxcloud.div@16"
ADMIN_ROLE = "system_admin"
OWNER_USERNAME = ADMIN_USERNAME
CSRF_SESSION_KEY = "csrf_token"
PASSWORD_HASHER = PasswordHasher()


PAGE = """
<!doctype html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }} - Cloud Rdx</title>
    <script src="{{ url_for('static', filename='cloud-dashboard.js') }}"></script>
    <style>
        :root {
            --ink: #17212b;
            --muted: #647483;
            --line: #d8e1e8;
            --paper: #f2f6f8;
            --panel: #ffffff;
            --mint: #dff5f1;
            --green: #087f73;
            --green-dark: #122b3a;
            --gold: #f0b44d;
            --shadow: 0 12px 30px rgba(25, 49, 66, .08);
        }
        * { box-sizing: border-box; }
        html { overflow-x: hidden; }
        body {
            margin: 0;
            color: var(--ink);
            background: var(--paper);
            font-family: 'Segoe UI', Arial, sans-serif;
            background-image: linear-gradient(rgba(216, 225, 232, .28) 1px, transparent 1px), linear-gradient(90deg, rgba(216, 225, 232, .28) 1px, transparent 1px);
            background-size: 32px 32px;
        }
        button, input { font: inherit; }
        button, a, label { -webkit-tap-highlight-color: transparent; }
        button, .upload-label, .download { min-height: 44px; }
        a { color: inherit; }
        .shell { min-height: 100vh; display: grid; grid-template-columns: 248px 1fr; }
        .rail {
            padding: 30px 22px;
            color: #eaf8ef;
            background: #122b3a;
            display: flex;
            flex-direction: column;
        }
        .brand { display: flex; align-items: center; gap: 12px; font: 700 14px Consolas, monospace; letter-spacing: .02em; }
        .brand-mark { width: 35px; height: 35px; display: grid; place-items: center; color: #122b3a; background: var(--gold); border-radius: 6px; font: 800 15px Consolas, monospace; }
        .rail-nav { margin-top: 70px; display: grid; gap: 10px; font-family: Arial, sans-serif; font-size: 14px; }
        .rail-link { display: flex; align-items: center; gap: 12px; padding: 12px 13px; color: #a9bfcd; text-decoration: none; border-radius: 6px; }
        .rail-link.active, .rail-link:hover { color: #fff; background: rgba(255,255,255,.11); }
        .rail-icon { width: 18px; text-align: center; font-size: 16px; }
        .rail-bottom { margin-top: auto; padding: 17px 14px; border-top: 1px solid rgba(255,255,255,.15); color: #a9cbb6; font: 12px/1.6 Arial, sans-serif; }
        .menu-toggle { display: none; margin-left: auto; padding: 9px 12px; color: #eaf8ef; background: transparent; border: 1px solid rgba(255,255,255,.3); border-radius: 7px; cursor: pointer; font-size: 20px; line-height: 1; }
        .menu-backdrop { display: none; }
        .main { padding: 36px clamp(22px, 5vw, 72px); min-width: 0; }
        .topbar { display: flex; justify-content: space-between; align-items: center; gap: 24px; margin-bottom: 43px; }
        .eyebrow { margin: 0 0 10px; color: var(--green); text-transform: uppercase; letter-spacing: .16em; font: 700 11px Arial, sans-serif; }
        h1, h2, p { margin-top: 0; }
        h1 { margin-bottom: 9px; font-size: clamp(30px, 4vw, 48px); line-height: 1; font-weight: 650; letter-spacing: -.03em; }
        .subtitle { margin-bottom: 0; color: var(--muted); font: 14px Arial, sans-serif; }
        .user-chip { display: flex; align-items: center; gap: 10px; padding: 8px 12px 8px 8px; color: var(--ink); background: var(--panel); border: 1px solid var(--line); border-radius: 999px; font: 13px Arial, sans-serif; white-space: nowrap; }
        .avatar { display: grid; place-items: center; width: 29px; height: 29px; color: #fff; background: var(--green); border-radius: 50%; font-weight: 700; }
        .layout { display: grid; grid-template-columns: minmax(0, 1fr) 285px; gap: 25px; align-items: start; }
        .panel { background: rgba(255,255,255,.94); border: 1px solid var(--line); border-radius: 8px; box-shadow: var(--shadow); }
        .browser { overflow: hidden; }
        .browser-head { display: flex; justify-content: space-between; align-items: center; padding: 18px 23px; border-bottom: 1px solid var(--line); gap: 14px; }
        .crumbs { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; font: 13px Consolas, monospace; }
        .crumbs a { color: var(--green); text-decoration: none; }
        .crumb-sep { color: #aab9b1; }
        .upload-label, .action-button { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 14px; color: #fff; background: var(--green); border: 0; border-radius: 8px; cursor: pointer; font: 700 12px Arial, sans-serif; text-decoration: none; }
        .upload-label:hover, .action-button:hover { background: var(--green-dark); }
        .file-list { padding: 5px 23px 14px; }
        .file-row { display: grid; grid-template-columns: 24px 38px minmax(0, 1fr) 110px 100px; gap: 12px; align-items: center; min-height: 62px; border-bottom: 1px solid #e8eef2; font-family: Consolas, monospace; }
        .file-row:last-child { border-bottom: 0; }
        .file-icon { width: 34px; height: 34px; display: grid; place-items: center; border-radius: 6px; font-size: 15px; background: #e5f5f2; color: var(--green); }
        .file-icon.doc { color: #b06b0c; background: #fff3dc; }
        .file-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; }
        .file-name a { text-decoration: none; }
        .file-name a:hover { color: var(--green); }
        .file-meta { color: var(--muted); font-size: 11px; }
        .download { justify-self: end; color: var(--green); font-size: 12px; font-weight: 700; text-decoration: none; }
        .download:hover { text-decoration: underline; }
        .empty { padding: 65px 20px; color: var(--muted); text-align: center; font-family: Arial, sans-serif; }
        .empty strong { display: block; margin-bottom: 8px; color: var(--ink); font: 18px Georgia, serif; }
        .side { display: grid; gap: 17px; }
        .side-card { padding: 20px; }
        .side-card h2 { margin-bottom: 17px; font-size: 18px; font-weight: 500; }
        .storage-stat { display: flex; justify-content: space-between; margin-bottom: 10px; font: 12px Arial, sans-serif; }
        .storage-stat span:last-child { color: var(--green); font-weight: 700; }
        .meter { height: 8px; overflow: hidden; background: #e3ebef; border-radius: 3px; }
        .meter span { display: block; width: 100%; height: 100%; background: var(--gold); border-radius: inherit; }
        .storage-detail { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin: 16px 0 12px; }
        .storage-detail div { padding: 10px; background: #f7fafc; border: 1px solid var(--line); border-radius: 8px; }
        .storage-detail small { display: block; margin-bottom: 4px; color: var(--muted); font: 10px Arial, sans-serif; text-transform: uppercase; letter-spacing: .06em; }
        .storage-detail strong { color: var(--ink); font: 700 14px Consolas, monospace; }
        .storage-warning { margin: 12px 0 0; padding: 10px 12px; color: #875d0b; background: #fff5d9; border: 1px solid #f0d58c; border-radius: 7px; font: 12px/1.45 Arial, sans-serif; }
        .storage-warning.critical { color: #963d2c; background: #fff0ec; border-color: #efb7aa; }
        .file-row button.download { min-height: 36px; padding: 7px 10px; color: #fff; background: var(--green); border: 0; border-radius: 6px; cursor: pointer; font: 700 11px Arial, sans-serif; }
        .file-row button.download:hover { background: var(--green-dark); }
        .file-select { width: 16px; height: 16px; accent-color: var(--green); }
        .bulk-actions { display: flex; align-items: center; gap: 10px; padding: 12px 23px; background: #f7fafc; border-bottom: 1px solid var(--line); font: 12px Arial, sans-serif; }
        .bulk-actions button { padding: 8px 11px; color: #fff; background: var(--green); border: 0; border-radius: 6px; cursor: pointer; font-weight: 700; }
        .bulk-actions button:disabled { opacity: .45; cursor: not-allowed; }
        .upload-status { display: none; margin: 0 23px 16px; padding: 14px; background: #f7fafc; border: 1px solid var(--line); border-radius: 8px; font: 12px Arial, sans-serif; }
        .upload-status.visible { display: block; }
        .upload-status-head { display: flex; justify-content: space-between; gap: 12px; margin-bottom: 8px; }
        .upload-status progress { width: 100%; height: 9px; accent-color: var(--green); }
        .upload-status small { display: block; margin-top: 7px; color: var(--muted); }
        .cancel-upload { padding: 7px 10px; color: #963d2c; background: #fff0ec; border: 1px solid #efb7aa; border-radius: 6px; cursor: pointer; font-size: 11px; font-weight: 700; }
        .dropzone { padding: 22px 18px; text-align: center; background: var(--mint); border: 1px dashed #55aaa0; border-radius: 6px; }
        .dropzone-icon { margin-bottom: 9px; font-size: 22px; }
        .dropzone p { margin-bottom: 14px; color: #456c54; font: 12px/1.5 Arial, sans-serif; }
        .dropzone input { width: 100%; color: #456c54; font: 11px Arial, sans-serif; }
        .flash { margin: -25px 0 25px; padding: 12px 15px; color: #7a5311; background: #fff4d7; border: 1px solid #f3db9d; border-radius: 8px; font: 13px Arial, sans-serif; }
        .logout { color: #b9d7c3; text-decoration: none; }
        @media (max-width: 900px) { .shell { grid-template-columns: 72px 1fr; } .rail { padding: 22px 13px; } .brand span, .rail-link span:not(.rail-icon), .rail-bottom { display: none; } .rail-nav { margin-top: 45px; } .rail-link { justify-content: center; padding: 13px 8px; } .layout { grid-template-columns: 1fr; } .side { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
        @media (max-width: 620px) { .shell { display: block; } .rail { position: sticky; top: 0; z-index: 10; display: block; padding: 10px 15px; box-shadow: 0 3px 14px rgba(18,43,58,.2); } .brand { min-height: 42px; } .brand span { display: inline; } .menu-toggle { display: block; position: absolute; top: 10px; right: 15px; } .rail-nav { display: none; margin: 10px 0 0; padding-top: 8px; border-top: 1px solid rgba(255,255,255,.15); } .rail.open .rail-nav { display: grid; } .rail-link { justify-content: flex-start; min-height: 44px; padding: 10px 8px; } .rail-link span:not(.rail-icon) { display: inline; } .rail-bottom { display: none; } .main { padding: 22px 12px 32px; } .topbar { align-items: flex-start; margin-bottom: 25px; } .topbar h1 { font-size: 34px; } .user-chip { display: none; } .browser-head { align-items: stretch; flex-direction: column; padding: 15px; } .browser-head > div:last-child { display: grid !important; grid-template-columns: 1fr 1fr; } .upload-label { width: 100%; padding: 10px 8px; } .browser-head input[name=name] { width: 100% !important; } .file-list { padding: 5px 12px 12px; } .file-row { grid-template-columns: 22px 34px minmax(0, 1fr) auto; gap: 8px; min-height: 60px; } .file-meta { display: none; } .file-row > div:last-child, .file-row > form { grid-column: 4; grid-row: 1; } .file-row > div:last-child { display: flex; flex-wrap: wrap; gap: 4px; justify-content: flex-end; } .file-row > div:last-child > form { display: block; } .file-row .download { min-height: 40px; padding: 8px; } .bulk-actions { flex-wrap: wrap; padding: 12px 15px; } .bulk-actions button { flex: 1 1 100%; min-height: 44px; } .upload-status { margin-left: 15px; margin-right: 15px; } .side { grid-template-columns: 1fr; } .side-card { padding: 16px; } }
        @media (max-width: 900px) { .shell { display: block; } body.menu-open { overflow: hidden; } .mobile-menu-toggle { display: grid; place-items: center; position: fixed; top: 12px; left: 12px; z-index: 31; width: 48px; height: 48px; margin: 0; padding: 0; color: #fff; background: var(--green); border: 0; border-radius: 8px; box-shadow: 0 5px 16px rgba(18,43,58,.28); cursor: pointer; font-size: 22px; } .menu-backdrop { display: block; position: fixed; inset: 0; z-index: 19; width: 100%; height: 100%; padding: 0; border: 0; background: rgba(5,16,25,.58); opacity: 0; pointer-events: none; transition: opacity .28s ease; } body.menu-open .menu-backdrop { opacity: 1; pointer-events: auto; } .rail { position: fixed; inset: 0 auto 0 0; z-index: 20; display: flex; width: 50vw; max-width: 360px; min-width: 260px; height: 100dvh; padding: 22px 18px; overflow-y: auto; box-shadow: 12px 0 32px rgba(18,43,58,.34); transform: translate3d(-105%, 0, 0); transition: transform .28s cubic-bezier(.22,.61,.36,1); will-change: transform; } .rail.open { transform: translate3d(0, 0, 0); } .rail .brand span, .rail .rail-link span:not(.rail-icon) { display: inline; } .rail-nav { display: none; margin-top: 42px; } .rail.open .rail-nav { display: grid; } .rail-link { justify-content: flex-start; min-height: 48px; padding: 11px 10px; } .rail-bottom { display: block; } .main { width: 100%; margin: 0; padding-top: 78px; } }
        @media (max-width: 620px) { .rail.open .brand span, .rail.open .rail-link span:not(.rail-icon) { display: inline !important; } }
        @media (prefers-reduced-motion: reduce) { *, *::before, *::after { scroll-behavior: auto !important; transition-duration: .01ms !important; animation-duration: .01ms !important; } }
    </style>
    <link rel="stylesheet" href="{{ url_for('static', filename='cloud-dashboard.css') }}">
</head>
<body class="cloud-dashboard">
<div class="shell">
    <button class="menu-toggle mobile-menu-toggle" type="button" aria-label="Open navigation" aria-expanded="false">☰</button>
    <button class="menu-backdrop" type="button" aria-label="Close navigation" tabindex="-1"></button>
    <aside class="rail">
        <a class="brand" href="{{ url_for('files') }}"><span class="brand-mark">C</span><span>Cloud Rdx</span></a>
        <nav class="rail-nav" aria-label="Main navigation">
            <a class="rail-link active" href="{{ url_for('files') }}"><span class="rail-icon">[ ]</span><span>My storage</span></a>
            <a class="rail-link" href="{{ url_for('storage_plan') }}"><span class="rail-icon">$</span><span>Storage plan</span></a>
            <a class="rail-link" href="{{ url_for('profile') }}"><span class="rail-icon">@</span><span>My profile</span></a>
            <a class="rail-link" href="{{ url_for('cloud_storage_guide') }}"><span class="rail-icon">?</span><span>Storage guide</span></a>
            <a class="rail-link" href="{{ url_for('user_trash') }}"><span class="rail-icon">~</span><span>Recycle bin</span></a>
            {% if has_admin_access %}<a class="rail-link" href="{{ url_for('admin_panel') }}"><span class="rail-icon">#</span><span>{{ admin_title }}</span></a>{% endif %}
            <a class="rail-link" href="{{ url_for('logout') }}"><span class="rail-icon">&lt;</span><span>Sign out</span></a>
        </nav>
        <div class="rail-bottom">Private storage<br>Local and secure</div>
    </aside>
    <main class="main">
        <header class="topbar">
            <div><p class="eyebrow">Cloud Rdx / storage node</p><h1>My storage</h1><p class="subtitle">Private object workspace · session protected</p></div>
            <div class="topbar-actions">
                <button class="theme-toggle" id="theme-toggle" type="button" aria-label="Switch to light theme" aria-pressed="false"><span aria-hidden="true">◉</span><span id="theme-toggle-label">Dark mode</span></button>
                <div class="user-chip"><span class="avatar">{{ username[0]|upper }}</span><span>{{ username }}{% if is_admin %} · admin{% endif %} <b class="session-status">◌ signed in</b></span></div>
                <span id="theme-status" class="visually-hidden" role="status" aria-live="polite"></span>
            </div>
        </header>
        <nav class="quick-access" aria-label="Quick access">
            <a class="quick-link" href="{{ url_for('storage_plan') }}"><span class="quick-link-icon" aria-hidden="true">$</span><span><strong>Storage plan</strong><small>Manage your allocation</small></span><span class="quick-link-arrow" aria-hidden="true">→</span></a>
            <a class="quick-link" href="{{ url_for('profile') }}"><span class="quick-link-icon" aria-hidden="true">@</span><span><strong>My profile</strong><small>Account and password</small></span><span class="quick-link-arrow" aria-hidden="true">→</span></a>
            <a class="quick-link" href="{{ url_for('user_trash') }}"><span class="quick-link-icon" aria-hidden="true">🗑</span><span><strong>Recycle bin</strong><small>Review deleted items</small></span><span class="quick-link-arrow" aria-hidden="true">→</span></a>
        </nav>
        {% with messages = get_flashed_messages() %}{% for message in messages %}<div class="flash" role="status" aria-live="polite">{{ message }}</div>{% endfor %}{% endwith %}
        <div class="layout">
            <section class="panel browser">
                <div class="browser-head">
                    <div class="crumbs"><a href="{{ url_for('files') }}">Root</a>{% for crumb in breadcrumbs %}<span class="crumb-sep">/</span><a href="{{ crumb.url }}">{{ crumb.name }}</a>{% endfor %}</div>
                    <div style="display:flex;gap:8px;flex-wrap:wrap">{% if allow_share %}<a class="upload-label" href="{{ url_for('user_shares') }}">Manage links</a>{% endif %}{% if allow_upload %}<form method="post" action="{{ url_for('upload', subpath=subpath) }}" enctype="multipart/form-data"><label class="upload-label" for="top-file">+ Add file</label><input id="top-file" name="file" type="file" hidden></form>{% endif %}<form method="post" action="{{ url_for('create_folder', subpath=subpath) }}"><input name="name" placeholder="New folder" required style="padding:9px;border:1px solid var(--line);border-radius:8px;width:110px"><button class="upload-label" type="submit">+ Folder</button></form></div>
                </div>
                <div class="drive-tools">
                    <label class="drive-search"><span aria-hidden="true">⌕</span><input id="file-search" type="search" placeholder="Search in this folder" autocomplete="off"><span class="search-hint" aria-hidden="true">Search</span></label>
                    <div class="view-controls" role="group" aria-label="File layout">
                        <button class="view-button active" type="button" data-view="grid" aria-pressed="true" aria-label="Show files as cards">▦<span>Grid</span></button>
                        <button class="view-button" type="button" data-view="list" aria-pressed="false" aria-label="Show files as a list">☷<span>List</span></button>
                    </div>
                </div>
                <p class="visually-hidden" id="file-search-status" role="status" aria-live="polite" aria-atomic="true"></p>
                {% if allow_download %}<form id="bulk-download-form" method="post" action="{{ url_for('bulk_download') }}"></form><div class="bulk-actions"><label><input id="select-all-files" type="checkbox"> Select all</label><span id="selected-file-count">0 selected</span><button id="bulk-download-button" type="submit" form="bulk-download-form" disabled>Download selected</button></div>{% else %}<div class="flash" role="status" aria-live="polite">Downloads are disabled for this account. Contact an administrator to request access.</div>{% endif %}
                {% if allow_upload %}<div id="upload-status" class="upload-status" role="status" aria-live="polite"><div class="upload-status-head"><strong id="upload-status-title">Preparing upload…</strong><button id="cancel-upload" class="cancel-upload" type="button">Cancel</button></div><progress id="upload-progress" max="100" value="0"></progress><small id="upload-status-detail">Waiting to start.</small></div>{% endif %}
                <div class="file-list" id="file-list" data-view="grid">
                    {% if parent %}<div class="file-row" data-name="Parent folder" data-file-type="folder"><div></div><div class="file-icon">↑</div><div class="file-name"><a href="{{ url_for('files', subpath=parent) }}">Parent folder</a></div><div class="file-meta">Folder</div><div></div></div>{% endif %}
                    {% for item in items %}
                    <div class="file-row" data-name="{{ item.name|lower }}" data-file-type="{{ 'folder' if item.is_dir else 'file' }}"><div>{% if allow_download and not item.is_dir %}<input class="file-select" type="checkbox" name="paths" value="{{ item.path }}" form="bulk-download-form" aria-label="Select {{ item.name }}">{% endif %}</div><div class="file-icon{% if not item.is_dir %} doc{% endif %}" aria-hidden="true">{% if item.is_dir %}▰{% else %}..{% endif %}</div><div class="file-name">{% if item.is_dir %}<a href="{{ url_for('files', subpath=item.path) }}">{{ item.name }}</a>{% else %}{{ item.name }}{% endif %}</div><div class="file-meta">{% if item.is_dir %}Folder{% else %}{{ item.size|filesize }}{% endif %}</div>{% if item.is_dir %}<form method="post" action="{{ url_for('delete_item', subpath=item.path) }}" onsubmit="return confirm('Delete this folder and its contents?')"><button class="download" type="submit">Delete</button></form>{% else %}<div style="display:flex;gap:10px;justify-content:flex-end;align-items:center">{% if allow_download %}<a class="download" href="{{ url_for('download', subpath=item.path) }}">Download</a>{% endif %}{% if allow_share %}<form method="post" action="{{ url_for('share_create', subpath=item.path) }}" style="display:flex;gap:4px;align-items:center"><select name="expires_days" aria-label="Share link expiry" style="max-width:70px;padding:5px;border:1px solid var(--line);border-radius:5px"><option value="1">1 day</option><option value="7" selected>7 days</option><option value="30">30 days</option></select><button class="download" type="submit">Share</button></form>{% endif %}<form method="post" action="{{ url_for('delete_item', subpath=item.path) }}" onsubmit="return confirm('Delete this file?')"><button class="download" type="submit">Delete</button></form></div>{% endif %}</div>
                    {% else %}<div class="empty"><strong>This folder is empty</strong>Add a file to start building your storage.</div>{% endfor %}
                    <p class="empty search-empty" id="search-empty" hidden><strong>No matching files</strong>Try a different search term.</p>
                </div>
            </section>
            <aside class="side">
                <section class="panel side-card"><h2>Storage overview</h2><div class="storage-stat"><span>OBJECTS / {{ item_count }}</span><span>{{ total_size|filesize }}{% if quota %} / {{ quota|filesize }}{% else %} / UNLIMITED{% endif %}</span></div><div class="meter" {% if quota %}role="progressbar" aria-valuenow="{{ quota_percent }}" aria-valuemin="0" aria-valuemax="100" aria-label="Storage quota used"{% else %}aria-hidden="true"{% endif %}><span style="width:{{ quota_percent }}%"></span></div><div class="storage-detail"><div><small>Used</small><strong>{{ total_size|filesize }}</strong></div><div><small>Remaining</small><strong>{% if quota %}{{ remaining_size|filesize }}{% else %}Unlimited{% endif %}</strong></div></div><p style="margin:0;color:var(--muted);font:11px Consolas,monospace">STATUS: {% if quota and quota_percent >= 100 %}QUOTA REACHED{% elif quota and quota_percent >= 80 %}NEAR LIMIT{% elif quota %}AVAILABLE{% else %}UNMETERED{% endif %}</p>{% if quota and quota_percent >= 95 %}<p class="storage-warning critical">Storage is almost full. Delete files or upgrade your allocation.</p>{% elif quota and quota_percent >= 80 %}<p class="storage-warning">You have used most of your allocated storage.</p>{% endif %}</section>
                {% if allow_upload %}<section class="panel side-card"><h2>Quick upload</h2><form class="dropzone" method="post" action="{{ url_for('upload', subpath=subpath) }}" enctype="multipart/form-data"><div class="dropzone-icon">+</div><p>Choose a file to add it to this folder.</p><input name="file" type="file" required></form></section>{% endif %}
            </aside>
        </div>
    </main>
    <nav class="mobile-dock" aria-label="Mobile quick navigation">
        <a href="{{ url_for('files') }}" aria-current="page"><span aria-hidden="true">⌂</span><span>Drive</span></a>
        <a href="{{ url_for('storage_plan') }}"><span aria-hidden="true">⚑</span><span>Storage</span></a>
        <a href="{{ url_for('user_trash') }}"><span aria-hidden="true">🗑</span><span>Trash</span></a>
        <a href="{{ url_for('profile') }}"><span aria-hidden="true">◉</span><span>Profile</span></a>
    </nav>
</div>
<script>
(() => {
    const fileSearch = document.getElementById('file-search');
    const fileList = document.getElementById('file-list');
    const searchStatus = document.getElementById('file-search-status');
    const noSearchResults = document.getElementById('search-empty');
    const fileRows = Array.from(document.querySelectorAll('.file-row[data-name]'));
    if (fileSearch && fileList && searchStatus && noSearchResults) {
        const updateSearch = () => {
            const query = fileSearch.value.trim().toLocaleLowerCase();
            let visibleCount = 0;
            fileRows.forEach(row => {
                const visible = row.dataset.name.includes(query);
                row.hidden = !visible;
                if (visible) visibleCount += 1;
            });
            noSearchResults.hidden = !query || visibleCount > 0 || fileRows.length === 0;
            searchStatus.textContent = query
                ? `${visibleCount} of ${fileRows.length} items match ${fileSearch.value.trim()}.`
                : `${fileRows.length} items in this folder.`;
        };
        fileSearch.addEventListener('input', updateSearch);
        fileSearch.addEventListener('keydown', event => {
            if (event.key === 'Escape' && fileSearch.value) {
                fileSearch.value = '';
                updateSearch();
            }
        });
        updateSearch();
    }

    const fileView = document.getElementById('file-list');
    document.querySelectorAll('.view-button[data-view]').forEach(button => {
        button.addEventListener('click', () => {
            if (!fileView) return;
            const view = button.dataset.view;
            fileView.dataset.view = view;
            document.querySelectorAll('.view-button[data-view]').forEach(option => {
                const active = option === button;
                option.classList.toggle('active', active);
                option.setAttribute('aria-pressed', String(active));
            });
            const status = document.getElementById('file-search-status');
            if (status) status.textContent = `${view === 'grid' ? 'Card' : 'List'} layout selected.`;
        });
    });

    const rail = document.querySelector('.rail');
    const menuToggle = document.querySelector('.menu-toggle');
    const menuBackdrop = document.querySelector('.menu-backdrop');
    const setMenuState = open => {
        rail.classList.toggle('open', open);
        document.body.classList.toggle('menu-open', open);
        menuToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        menuToggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
    };
    menuToggle.addEventListener('click', () => {
        setMenuState(!rail.classList.contains('open'));
    });
    menuBackdrop.addEventListener('click', () => setMenuState(false));
    rail.querySelectorAll('.rail-link').forEach(link => link.addEventListener('click', () => {
        setMenuState(false);
    }));
    let activeRequest = null;
    const status = document.getElementById('upload-status');
    const title = document.getElementById('upload-status-title');
    const detail = document.getElementById('upload-status-detail');
    const progress = document.getElementById('upload-progress');
    const cancel = document.getElementById('cancel-upload');
    const selections = () => Array.from(document.querySelectorAll('.file-select'));
    const updateSelection = () => {
        const checked = selections().filter(input => input.checked).length;
        const count = document.getElementById('selected-file-count');
        const bulkButton = document.getElementById('bulk-download-button');
        if (count) count.textContent = `${checked} selected`;
        if (bulkButton) bulkButton.disabled = checked === 0;
        const all = selections();
        const selectAll = document.getElementById('select-all-files');
        if (selectAll) selectAll.checked = all.length > 0 && checked === all.length;
    };
    selections().forEach(input => input.addEventListener('change', updateSelection));
    const selectAll = document.getElementById('select-all-files');
    if (selectAll) selectAll.addEventListener('change', event => {
        selections().forEach(input => input.checked = event.target.checked);
        updateSelection();
    });
    const bulkForm = document.getElementById('bulk-download-form');
    if (bulkForm) bulkForm.addEventListener('submit', event => {
        if (!selections().some(input => input.checked)) event.preventDefault();
    });
    function formatSeconds(seconds) {
        if (!Number.isFinite(seconds) || seconds < 0) return 'calculating…';
        seconds = Math.ceil(seconds);
        return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    }
    function startUpload(form) {
        const input = form.querySelector('input[type=file]');
        if (!input.files.length) return;
        if (activeRequest) activeRequest.abort();
        const file = input.files[0], started = performance.now();
        let uploadFinishedAt = null;
        const xhr = new XMLHttpRequest();
        activeRequest = xhr;
        status.classList.add('visible'); progress.value = 0; cancel.disabled = false;
        title.textContent = `Uploading ${file.name}`;
        xhr.upload.onprogress = event => {
            if (!event.lengthComputable) { detail.textContent = 'Uploading…'; return; }
            const elapsed = (performance.now() - started) / 1000;
            const speed = event.loaded / Math.max(elapsed, 0.001);
            const remaining = (event.total - event.loaded) / Math.max(speed, 1);
            progress.value = event.loaded * 100 / event.total;
            if (event.loaded === event.total && !uploadFinishedAt) uploadFinishedAt = performance.now();
            detail.textContent = `${Math.round(progress.value)}% · ${formatSeconds(elapsed)} elapsed · about ${formatSeconds(remaining)} remaining`;
        };
        xhr.onreadystatechange = () => {
            if (xhr.readyState !== XMLHttpRequest.DONE) return;
            if (xhr.status >= 200 && xhr.status < 400) {
                const processedAt = performance.now();
                const uploadSeconds = ((uploadFinishedAt || processedAt) - started) / 1000;
                const processingSeconds = (processedAt - (uploadFinishedAt || started)) / 1000;
                title.textContent = 'Upload complete';
                detail.textContent = `Upload: ${formatSeconds(uploadSeconds)} · Processing: ${formatSeconds(processingSeconds)}`;
                cancel.disabled = true;
                window.setTimeout(() => window.location.reload(), 900);
            } else if (xhr.status !== 0) {
                title.textContent = 'Upload failed';
                detail.textContent = xhr.status === 503
                    ? 'The upload service is temporarily unavailable. Please try again shortly.'
                    : xhr.status === 403
                        ? 'Your account or a security policy does not currently allow uploads.'
                        : `The server rejected this upload (HTTP ${xhr.status}). Please try again.`;
                cancel.disabled = true;
            }
            activeRequest = null;
        };
        xhr.open('POST', form.action); xhr.send(new FormData(form));
    }
    document.querySelectorAll('form[action^="/upload/"]').forEach(form => {
        form.addEventListener('submit', event => { event.preventDefault(); startUpload(form); });
        form.querySelector('input[type=file]').addEventListener('change', () => startUpload(form));
    });
    if (cancel) cancel.addEventListener('click', () => {
        if (!activeRequest) return;
        activeRequest.abort(); activeRequest = null;
        title.textContent = 'Upload cancelled'; detail.textContent = 'The upload request was cancelled before completion.'; cancel.disabled = true;
    });
    updateSelection();
})();
</script>
</body>
</html>
"""


PAGE = PAGE.replace(
    '<nav class="rail-nav" aria-label="Main navigation">',
    '<nav class="rail-nav" aria-label="Main navigation"><a class="rail-link" href="{{ url_for(\'login\') }}"><span class="rail-icon">→</span><span>Sign in</span></a>',
)
PAGE = PAGE.replace("{% if is_admin %}<a class=\"rail-link\" href=\"{{ url_for('admin_panel') }}\">", "{% if admin_access %}<a class=\"rail-link\" href=\"{{ url_for('admin_panel') }}\">")


HOME_PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>RDx Cloud Storage</title>
    <style>
        :root { --ink:#17212b; --muted:#647483; --green:#087f73; --dark:#122b3a; --gold:#f0b44d; --paper:#f2f6f8; }
        * { box-sizing:border-box; }
        body.home-page { margin:0; min-height:100vh; color:#fff; background:#05060b; font-family:'Segoe UI',Arial,sans-serif; }
        .home-background-video, .home-video-overlay { position:fixed; inset:0; width:100%; height:100%; }
        .home-background-video { z-index:0; object-fit:cover; }
        .home-video-overlay { z-index:1; background:linear-gradient(135deg,rgba(2,7,22,.88),rgba(13,1,27,.72)); }
        .nav, .hero { position:relative; z-index:2; }
        .nav { display:flex; justify-content:space-between; align-items:center; gap:18px; padding:22px clamp(22px,6vw,82px); background:rgba(4,9,25,.58); border-bottom:1px solid rgba(255,255,255,.2); }
        .brand { display:flex; align-items:center; gap:10px; color:#fff; font:700 14px Consolas,monospace; text-shadow:0 2px 8px rgba(0,0,0,.7); }
        .mark { display:grid; place-items:center; width:38px; height:38px; color:var(--dark); background:var(--gold); border-radius:7px; font:800 16px Consolas,monospace; }
        .nav a { min-height:44px; display:inline-flex; align-items:center; color:#fff; font:700 13px Arial,sans-serif; text-decoration:none; }
        .hero { width:min(1050px,calc(100% - 36px)); margin:0 auto; padding:clamp(70px,12vw,145px) 0 90px; }
        .eyebrow { margin:0 0 14px; color:#8cecff; text-transform:uppercase; letter-spacing:.16em; font:700 11px Consolas,monospace; text-shadow:0 2px 8px rgba(0,0,0,.8); }
        h1 { max-width:760px; margin:0; color:#fff; font-size:clamp(42px,8vw,82px); line-height:.98; letter-spacing:-.06em; text-shadow:0 4px 18px rgba(0,0,0,.8); }
        .lead { max-width:610px; margin:25px 0 30px; color:#f1f7ff; font:18px/1.6 Arial,sans-serif; text-shadow:0 2px 10px rgba(0,0,0,.85); }
        .actions { display:flex; gap:12px; flex-wrap:wrap; }
        .button { display:inline-flex; padding:13px 18px; color:#fff !important; background:var(--green); border-radius:7px; font-weight:700 !important; }
        .button.secondary { color:#102033 !important; background:#f5fbff; border:1px solid #fff; }
        .features { display:grid; grid-template-columns:repeat(3,1fr); gap:16px; margin-top:70px; }
        .card { padding:22px; background:rgba(4,9,25,.62); border:1px solid rgba(255,255,255,.25); border-radius:16px; backdrop-filter:blur(8px); }
        .card h2 { margin:0 0 8px; color:#fff; font-size:18px; text-shadow:0 2px 8px rgba(0,0,0,.65); }
        .card p { margin:0; color:#e6f1fb; font:14px/1.55 Arial,sans-serif; text-shadow:0 2px 8px rgba(0,0,0,.7); }
        @media(max-width:700px) { .nav { padding:13px 18px; } .brand span:last-child { max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; } .hero { width:min(100% - 32px, 560px); padding-top:70px; padding-bottom:55px; } h1 { font-size:clamp(40px, 13vw, 62px); } .lead { font-size:16px; } .actions { display:grid; grid-template-columns:1fr; } .button { justify-content:center; min-height:48px; } .features { grid-template-columns:1fr; gap:12px; margin-top:48px; } .card { padding:18px; } }
        @media (prefers-reduced-motion: reduce), (max-width:700px) { .home-background-video { display:none; } }
    </style>
</head>
<body class="home-page">
    <video class="home-background-video" autoplay muted loop playsinline aria-hidden="true">
        <source src="{{ url_for('background_video') }}" type="video/mp4">
    </video>
    <div class="home-video-overlay" aria-hidden="true"></div>
    <nav class="nav" aria-label="Primary navigation"><div class="brand"><span class="mark">C</span><span>RDx Cloud Storage-DB16</span></div><a href="{{ url_for('login') }}">Sign in →</a></nav>
    <main class="hero"><p class="eyebrow">Private storage workspace</p><h1>Your files, organized and secure.</h1><p class="lead">Cloud Rdx gives you a simple private space to upload, organize, download, and manage your files from one place.</p><div class="actions"><a class="button" href="{{ url_for('login') }}">Sign in to storage</a><a class="button secondary" href="{{ url_for('register') }}">Create an account</a></div><section class="features"><article class="card"><h2>Private by default</h2><p>Your storage is protected by account access and secure password hashing.</p></article><article class="card"><h2>Simple organization</h2><p>Create folders, upload files, download items, and keep your workspace tidy.</p></article><article class="card"><h2>Recovery support</h2><p>Account recovery and administration tools help keep important data accessible.</p></article></section></main>
</body>
</html>
"""


CONSENT_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Policies and consent - RDx Cloud Storage</title><style>
body{margin:0;min-height:100vh;background:#f2f6f8;color:#17212b;font-family:'Segoe UI',Arial,sans-serif}.wrap{width:min(760px,calc(100% - 28px));margin:32px auto}.card{padding:28px;background:#fff;border:1px solid #d8e1e8;border-radius:12px;box-shadow:0 12px 30px #19314214}h1{margin:0 0 10px;font-size:clamp(28px,6vw,44px)}.lead{color:#647483;line-height:1.55}.notice{padding:12px 14px;margin:18px 0;color:#8b3d2d;background:#fff0ec;border:1px solid #efb7aa;border-radius:7px;font-size:13px}.policies{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:22px 0}.policy{padding:14px;color:#087f73;background:#f4fbfa;border:1px solid #b9e1dc;border-radius:8px;text-decoration:none;font-weight:700}.check{display:flex;align-items:flex-start;gap:10px;margin:20px 0;font-size:14px;line-height:1.5}.check input{width:20px;height:20px;flex:0 0 auto;accent-color:#087f73}.submit{width:100%;min-height:48px;color:#fff;background:#087f73;border:0;border-radius:8px;cursor:pointer;font-weight:700}@media(max-width:560px){.wrap{margin:16px auto}.card{padding:20px}.policies{grid-template-columns:1fr}}
</style></head><body><main class="wrap"><section class="card"><p style="color:#087f73;font-weight:700;letter-spacing:.12em;font-size:11px">RDx CLOUD STORAGE</p><h1>Before you continue</h1><p class="lead">To use RDx Cloud Storage, please read and accept all four policies. We ask once for this account; your choice is saved securely and will not be requested on every visit.</p>{% if error %}<div class="notice">{{ error }}</div>{% endif %}<div class="policies"><a class="policy" href="{{ url_for('policy_page', policy_name='terms') }}">Terms and conditions →</a><a class="policy" href="{{ url_for('policy_page', policy_name='privacy') }}">Privacy policy →</a><a class="policy" href="{{ url_for('policy_page', policy_name='cookies') }}">Cookie policy →</a><a class="policy" href="{{ url_for('policy_page', policy_name='disclaimer') }}">Disclaimer →</a></div><form method="post" action="{{ url_for('accept_policies') }}"><label class="check"><input type="checkbox" name="accept_all" required><span>I have read and agree to the Terms and Conditions, Privacy Policy, Cookie Policy, and Disclaimer.</span></label><button class="submit" type="submit">Accept all and continue</button></form></section></main></body></html>
"""


POLICY_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{ policy.title }} - RDx Cloud Storage</title><style>body{margin:0;background:#f2f6f8;color:#17212b;font-family:'Segoe UI',Arial,sans-serif}.wrap{width:min(800px,calc(100% - 28px));margin:30px auto}.card{padding:26px;background:#fff;border:1px solid #d8e1e8;border-radius:10px}h1{margin-top:0}p,li{line-height:1.65}.back{display:inline-block;margin-top:18px;color:#087f73;font-weight:700}</style></head><body><main class="wrap"><article class="card"><p style="color:#087f73;font-weight:700;letter-spacing:.1em;font-size:11px">RDx CLOUD STORAGE</p><h1>{{ policy.title }}</h1><p>{{ policy.summary }}</p><h2>Using this website</h2><p>By using RDx Cloud Storage, you agree to use the service lawfully, protect your account credentials, and respect other users and stored content.</p><h2>Your responsibilities</h2><ul><li>Keep your account information accurate and your password confidential.</li><li>Do not upload unlawful, harmful, or unauthorized content.</li><li>Review changes to these policies before continuing to use the service.</li></ul><a class="back" href="{{ back_url }}">→ Back to consent</a></article></main></body></html>
"""


LOGIN_PAGE = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign in - RDx Cloud Storage-DB16</title><style>
:root{--green:#105437;--mint:#d9f3e5;--ink:#16221f;--muted:#71817b}*{box-sizing:border-box}body{min-height:100vh;margin:0;display:grid;place-items:center;background:#f7faf7;color:var(--ink);font-family:Georgia,'Times New Roman',serif}.login{width:min(420px,calc(100% - 34px));padding:42px;background:#fff;border:1px solid #dfe8e2;border-radius:18px;box-shadow:0 18px 50px rgba(25,64,45,.08)}.mark{width:42px;height:42px;display:grid;place-items:center;margin-bottom:35px;color:var(--green);background:#f2be58;border-radius:12px 12px 12px 2px;font:bold 20px Arial}.eyebrow{margin:0 0 11px;color:#18794e;text-transform:uppercase;letter-spacing:.16em;font:700 11px Arial}h1{margin:0 0 10px;font-size:37px;font-weight:500;letter-spacing:-.03em}.intro{margin:0 0 30px;color:var(--muted);font:14px/1.5 Arial}.field{display:block;margin-bottom:9px;font:700 12px Arial}.password{width:100%;padding:13px 14px;border:1px solid #cbd9cf;border-radius:8px;outline:0;font:15px Arial}.password:focus{border-color:#18794e;box-shadow:0 0 0 3px var(--mint)}button{width:100%;margin-top:14px;padding:13px;border:0;border-radius:8px;color:#fff;background:var(--green);cursor:pointer;font:bold 13px Arial}button:hover{background:#18794e}.google-signin{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;min-height:46px;margin-top:18px;padding:12px;color:#263238;background:#fff;border:1px solid #cbd2d5;border-radius:8px;text-decoration:none;font:700 13px Arial;transition:background-color .16s,border-color .16s,box-shadow .16s}.google-signin:hover{background:#f8fafb;border-color:#9aa5aa;box-shadow:0 3px 10px #26323814}.google-mark{font:800 17px Arial;background:conic-gradient(from -45deg,#4285f4 0 25%,#34a853 25% 50%,#fbbc05 50% 75%,#ea4335 75%);background-clip:text;-webkit-text-fill-color:transparent}.login-divider{display:flex;align-items:center;gap:12px;margin:18px 0;color:#89938f;font:11px Arial;text-transform:uppercase}.login-divider:before,.login-divider:after{content:"";height:1px;flex:1;background:#e4eae6}.error{margin:16px 0 0;color:#9b4c2d;font:13px Arial}
</style></head><body><main class="login"><div class="mark">C</div><p class="eyebrow">Cloud Rdx Storage</p><h1>Welcome back</h1><p class="intro">Sign in to access your private local file space.</p>{% if google_login_enabled %}<a class="google-signin" href="{{ url_for('google_login_start') }}"><span class="google-mark" aria-hidden="true">G</span><span>Continue with Google</span></a><p style="font:11px/1.5 Arial;color:var(--muted);text-align:center;margin:8px 0 17px">New here? A standard Cloud Rdx account will be created.</p><div class="login-divider">or sign in with password</div>{% endif %}<form method="post"><label class="field" for="username">Username</label><input class="password" id="username" name="username" required autofocus><label class="field" for="password" style="margin-top:14px">Password</label><input class="password" id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Enter storage</button></form><p style="font:13px Arial;color:var(--muted);margin-top:20px"><a href="{{ url_for('forgot_password') }}" style="color:#18794e">Forgot password?</a></p><p style="font:13px Arial;color:var(--muted);margin-top:10px">New here? <a href="{{ url_for('register') }}" style="color:#18794e">Create an account</a></p>{% if error %}<p class="error" role="alert">{{ error }}</p>{% endif %}</main></body></html>
"""

LOGIN_PAGE = LOGIN_PAGE.replace(
    '<main class="login"><div class="mark">',
    '<main class="login"><nav style="display:flex;justify-content:flex-end;margin:-15px 0 28px;font:700 12px Arial" aria-label="Primary navigation"><a href="{{ url_for(\'login\') }}" style="color:#18794e;text-decoration:none">Home</a></nav><div class="mark">',
)
LOGIN_PAGE = LOGIN_PAGE.replace("url_for('login')", "url_for('home')", 1)


MAINTENANCE_PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Maintenance in progress - RDx Cloud Storage</title>
    <style>
        :root{--green:#105437;--gold:#f2be58;--ink:#16221f;--muted:#71817b}
        *{box-sizing:border-box}
        body{min-height:100vh;margin:0;display:grid;place-items:center;background:#f7faf7;color:var(--ink);font-family:Arial,sans-serif}
        .maintenance{width:min(560px,calc(100% - 34px));padding:42px;background:#fff;border:1px solid #dfe8e2;border-radius:18px;box-shadow:0 18px 50px rgba(25,64,45,.08);text-align:center}
        .mark{width:48px;height:48px;display:grid;place-items:center;margin:0 auto 28px;color:var(--green);background:var(--gold);border-radius:14px 14px 14px 3px;font:bold 21px Arial}
        .eyebrow{margin:0 0 12px;color:#18794e;text-transform:uppercase;letter-spacing:.16em;font-size:11px;font-weight:700}
        h1{margin:0 0 14px;font:500 36px Georgia,'Times New Roman',serif;letter-spacing:-.03em}
        .lead{margin:0 auto 12px;max-width:430px;color:var(--muted);font-size:15px;line-height:1.6}
        .notice{margin:24px 0;padding:14px;color:#76551a;background:#fff5d9;border:1px solid #f0d18a;border-radius:9px;font-size:13px}
        .mark-link{display:inline-block;text-decoration:none}
        .mark-link:focus-visible{outline:3px solid #18794e;outline-offset:5px;border-radius:16px}
    </style>
</head>
<body>
    <main class="maintenance">
        <a class="mark-link" href="{{ url_for('login', maintenance=1) }}" aria-label="Administrator sign in"><div class="mark">C</div></a>
        <p class="eyebrow">Cloud Rdx Storage</p>
        <h1>Website under maintenance</h1>
        <p class="lead">We are temporarily making improvements. Storage access and new sign-ins are paused while maintenance mode is active.</p>
        <div class="notice">Please visit again after 6 hours, or wait for the administrator to bring the website back online.</div>
    </main>
</body>
</html>
"""


REGISTER_PAGE = LOGIN_PAGE.replace(
    "Welcome back</h1><p class=\"intro\">Sign in to access your private local file space.</p><form method=\"post\"><label class=\"field\" for=\"username\">Username</label><input class=\"password\" id=\"username\" name=\"username\" required autofocus><label class=\"field\" for=\"password\" style=\"margin-top:14px\">Password</label><input class=\"password\" id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required><button type=\"submit\">Enter storage</button></form><p style=\"font:13px Arial;color:var(--muted);margin-top:20px\">New here? <a href=\"{{ url_for('register') }}\" style=\"color:#18794e\">Create an account</a></p>",
    "Create your space</h1><p class=\"intro\">Register for a private file space of your own.</p><form method=\"post\"><label class=\"field\" for=\"username\">Username</label><input class=\"password\" id=\"username\" name=\"username\" pattern=\"[A-Za-z0-9_-]{3,32}\" required autofocus><label class=\"field\" for=\"password\" style=\"margin-top:14px\">Password</label><input class=\"password\" id=\"password\" name=\"password\" type=\"password\" minlength=\"8\" required><button type=\"submit\">Create account</button></form><p style=\"font:13px Arial;color:var(--muted);margin-top:20px\">Already registered? <a href=\"{{ url_for('login') }}\" style=\"color:#18794e\">Sign in</a></p>",
)


REGISTER_PAGE = REGISTER_PAGE.replace(
    '<label class="field" for="password" style="margin-top:14px">Password</label><input class="password" id="password" name="password" type="password" minlength="8" required>',
    '<label class="field" for="full_name" style="margin-top:14px">Full name</label><input class="password" id="full_name" name="full_name" required><label class="field" for="email" style="margin-top:14px">Email address</label><input class="password" id="email" name="email" type="email" required><label class="field" for="mobile" style="margin-top:14px">Mobile number</label><input class="password" id="mobile" name="mobile" type="tel" required><label class="field" for="dob" style="margin-top:14px">Date of birth</label><input class="password" id="dob" name="dob" type="date" required><label class="field" for="password" style="margin-top:14px">Password</label><input class="password" id="password" name="password" type="password" minlength="8" required>',
)


REGISTER_PAGE = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Create account - Cloud Rdx</title><style>
:root{--ink:#17212b;--muted:#647483;--line:#d8e1e8;--paper:#f2f6f8;--panel:#fff;--green:#087f73;--dark:#122b3a;--gold:#f0b44d;--danger:#a34f3a}*{box-sizing:border-box}body{margin:0;min-height:100vh;color:var(--ink);background:var(--paper);font-family:'Segoe UI',Arial,sans-serif;background-image:linear-gradient(#d8e1e844 1px,transparent 1px),linear-gradient(90deg,#d8e1e844 1px,transparent 1px);background-size:32px 32px}.register-shell{width:min(880px,calc(100% - 32px));margin:34px auto 50px}.register-head{display:flex;justify-content:space-between;align-items:start;gap:24px;margin-bottom:24px}.brand{display:flex;align-items:center;gap:10px;color:var(--dark);font:700 13px Consolas,monospace}.mark{display:grid;place-items:center;width:38px;height:38px;color:var(--dark);background:var(--gold);border-radius:6px;font:800 16px Consolas,monospace}.eyebrow{margin:0 0 9px;color:var(--green);text-transform:uppercase;letter-spacing:.15em;font:700 11px Consolas,monospace}h1{margin:0;font-size:clamp(30px,5vw,46px);letter-spacing:-.04em}.intro{max-width:560px;margin:10px 0 0;color:var(--muted);font:14px/1.5 Arial}.signin{color:var(--green);font:700 12px Consolas,monospace;text-decoration:none;white-space:nowrap}.card{overflow:hidden;background:rgba(255,255,255,.96);border:1px solid var(--line);border-radius:8px;box-shadow:0 12px 30px #19314214}.section{padding:24px 28px;border-bottom:1px solid #e8eef2}.section-title{display:flex;align-items:baseline;gap:10px;margin-bottom:17px}.section-title h2{margin:0;font-size:18px;font-weight:650}.section-title span{color:var(--muted);font:11px Consolas,monospace}.grid{display:grid;grid-template-columns:1fr 1fr;gap:17px 20px}.field{display:block;color:var(--ink);font:700 11px Consolas,monospace}.input{display:block;width:100%;margin-top:7px;padding:12px 13px;color:var(--ink);background:#fbfdfe;border:1px solid #cbd8e0;border-radius:6px;outline:0;font:14px 'Segoe UI',Arial}.input:focus{border-color:var(--green);box-shadow:0 0 0 3px #dff5f1}.hint{margin:7px 0 0;color:var(--muted);font:11px/1.4 Arial}.privacy{margin:0;padding:16px 28px;color:#45616c;background:#edf8f7;font:12px/1.5 Arial}.privacy strong{color:var(--green)}.actions{display:flex;align-items:center;justify-content:space-between;gap:18px;padding:20px 28px;background:#f8fbfc}.submit{padding:12px 18px;color:#fff;background:var(--green);border:0;border-radius:6px;cursor:pointer;font:700 12px Consolas,monospace}.submit:hover{background:var(--dark)}.error{margin:0 0 18px;padding:12px 15px;color:var(--danger);background:#fff1ed;border:1px solid #e8c9c0;border-radius:6px;font:13px Arial}@media(max-width:620px){.register-shell{margin-top:22px}.register-head{display:block}.signin{display:inline-block;margin-top:17px}.section{padding:20px 17px}.grid{grid-template-columns:1fr}.privacy,.actions{padding-left:17px;padding-right:17px}.actions{align-items:stretch;flex-direction:column}.submit{width:100%}}
</style></head><body><main class="register-shell"><header class="register-head"><div><div class="brand"><span class="mark">C</span><span>Cloud Rdx / identity setup</span></div><p class="eyebrow" style="margin-top:29px">Private storage account</p><h1>Create your workspace</h1><p class="intro">Set up your secure file space. Your recovery details are stored privately and used only to verify account ownership.</p></div><a class="signin" href="{{ url_for('login') }}">ALREADY REGISTERED →</a></header>{% if error %}<p class="error">{{ error }}</p>{% endif %}<form class="card" method="post"><section class="section"><div class="section-title"><h2>Profile</h2><span>01 / IDENTITY</span></div><div class="grid"><label class="field">FULL NAME<input class="input" name="full_name" autocomplete="name" placeholder="Your name" required></label><label class="field">USERNAME<input class="input" name="username" pattern="[A-Za-z0-9_-]{3,32}" autocomplete="username" placeholder="3-32 characters" required></label><label class="field">EMAIL ADDRESS<input class="input" name="email" type="email" autocomplete="email" placeholder="you@example.com" required></label><label class="field">MOBILE NUMBER<input class="input" name="mobile" type="tel" autocomplete="tel" placeholder="+91 98765 43210" required></label></div></section><section class="section"><div class="section-title"><h2>Recovery details</h2><span>02 / PRIVATE VERIFICATION</span></div><div class="grid"><label class="field">DATE OF BIRTH<input class="input" name="dob" type="date" autocomplete="bday" required></label><div><p class="hint" style="margin-top:0">Your mobile number and date of birth help an administrator verify a recovery request. They are not shown to other users.</p></div></div></section><section class="section"><div class="section-title"><h2>Secure sign-in</h2><span>03 / CREDENTIALS</span></div><div class="grid"><label class="field">PASSWORD<input class="input" name="password" type="password" minlength="8" autocomplete="new-password" placeholder="At least 8 characters" required><span class="hint">Use a unique password with 8 or more characters.</span></label><label class="field">CONFIRM PASSWORD<input class="input" name="password_confirm" type="password" minlength="8" autocomplete="new-password" placeholder="Repeat your password" required></label></div></section><p class="privacy"><strong>Private by design.</strong> Your profile data is visible only from your own profile or to the administrator. Files remain inside your separate personal storage folder.</p><div class="actions"><span class="hint">Your details are stored for account access and recovery.</span><button class="submit" type="submit">CREATE SECURE ACCOUNT</button></div></form></main></body></html>
"""
REGISTER_PAGE = REGISTER_PAGE.replace('[A-Za-z0-9_-]', '[A-Za-z0-9_\\-]')


FORGOT_PAGE = LOGIN_PAGE.replace(
    '<h1>Welcome back</h1><p class="intro">Sign in to access your private local file space.</p><form method="post"><label class="field" for="username">Username</label><input class="password" id="username" name="username" required autofocus><label class="field" for="password" style="margin-top:14px">Password</label><input class="password" id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Enter storage</button></form><p style="font:13px Arial;color:var(--muted);margin-top:20px"><a href="{{ url_for(\'forgot_password\') }}" style="color:#18794e">Forgot password?</a></p><p style="font:13px Arial;color:var(--muted);margin-top:10px">New here? <a href="{{ url_for(\'register\') }}" style="color:#18794e">Create an account</a></p>',
    '<h1>Password recovery</h1><p class="intro">Submit your details. An administrator will verify your identity before resetting your password.</p><form method="post"><label class="field" for="username">Username</label><input class="password" id="username" name="username" required autofocus><label class="field" for="email" style="margin-top:14px">Email address</label><input class="password" id="email" name="email" type="email" required><label class="field" for="mobile" style="margin-top:14px">Mobile number</label><input class="password" id="mobile" name="mobile" type="tel" required><label class="field" for="dob" style="margin-top:14px">Date of birth</label><input class="password" id="dob" name="dob" type="date" required><button type="submit">Send recovery request</button></form><p style="font:13px Arial;color:var(--muted);margin-top:20px"><a href="{{ url_for(\'login\') }}" style="color:#18794e">Return to sign in</a></p>',
)
FORGOT_PAGE = FORGOT_PAGE.replace(
    "{% if error %}<p class=\"error\">{{ error }}</p>{% endif %}",
    "{% if error %}<p class=\"error\">{{ error }}</p>{% endif %}{% if message %}<p style=\"margin:16px 0 0;padding:12px 15px;color:#087f73;background:#edf8f7;border:1px solid #b9e1dc;border-radius:8px;font:13px Arial\">{{ message }}</p>{% endif %}",
)


# Use the attached animated login design only for sign-in. Registration and
# recovery keep their dedicated forms and existing validation behavior.
LOGIN_PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in - RDx Cloud Storage-DB16</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='login.css') }}">
    <link rel="stylesheet" href="{{ url_for('static', filename='auth.css') }}">
</head>
<body class="login-page">
    <video class="login-background-video" autoplay muted loop playsinline aria-hidden="true">
        <source src="{{ url_for('background_video') }}" type="video/mp4">
    </video>
    <section aria-label="Cloud Rdx sign in">
        <main class="login-box">
            <div class="login-brand">RDx Cloud Storage-DB16</div>
            <h1>Welcome back</h1>
            {% with messages = get_flashed_messages() %}
                {% for message in messages %}<p class="login-notice">{{ message }}</p>{% endfor %}
            {% endwith %}
            {% if google_login_enabled or not google_oauth_configured or github_login_enabled or not github_oauth_configured %}
                <div class="provider-actions" aria-label="Social sign-in options">
            {% if google_login_enabled or not google_oauth_configured %}
                <a class="google-signin" href="{{ url_for('google_login_start') }}"
                   aria-label="Continue with Google or create an account" title="Google">
                    <svg class="provider-logo google-mark" viewBox="0 0 48 48" aria-hidden="true">
                        <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
                        <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.89c-.58 2.96-2.26 5.48-4.73 7.18l7.27 5.64c4.25-3.92 6.7-9.7 6.7-17.29z"/>
                        <path fill="#FBBC05" d="M10.53 28.59A14.4 14.4 0 0 1 9.75 24c0-1.59.27-3.13.76-4.59l-7.98-6.19A23.9 23.9 0 0 0 0 24c0 3.87.93 7.54 2.56 10.78l7.97-6.19z"/>
                        <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.91-5.8l-7.27-5.64c-2.02 1.35-4.6 2.14-8.64 2.14-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
                    </svg>
                </a>
            {% endif %}
            {% if github_login_enabled or not github_oauth_configured %}
                <a class="github-signin" href="{{ url_for('github_login_start') }}"
                   aria-label="Continue with GitHub or create an account" title="GitHub">
                    <svg class="provider-logo github-mark" viewBox="0 0 24 24" aria-hidden="true">
                        <path fill="currentColor" d="M12 .9a11.1 11.1 0 0 0-3.51 21.63c.56.1.76-.24.76-.54v-2.08c-3.1.67-3.76-1.32-3.76-1.32-.5-1.29-1.24-1.63-1.24-1.63-1.01-.69.08-.68.08-.68 1.12.08 1.71 1.15 1.71 1.15 1 1.71 2.62 1.22 3.26.93.1-.72.39-1.22.71-1.5-2.47-.28-5.07-1.23-5.07-5.48 0-1.21.43-2.2 1.15-2.97-.12-.28-.5-1.41.11-2.94 0 0 .94-.3 3.05 1.14a10.6 10.6 0 0 1 5.55 0c2.11-1.44 3.05-1.14 3.05-1.14.61 1.53.23 2.66.11 2.94.72.77 1.15 1.76 1.15 2.97 0 4.26-2.61 5.2-5.09 5.48.4.35.76 1.02.76 2.06v3.07c0 .3.2.65.77.54A11.1 11.1 0 0 0 12 .9z"/>
                    </svg>
                </a>
            {% endif %}
                </div>
            {% endif %}
            {% if google_login_enabled or github_login_enabled %}
                <p class="google-signup-note">Sign in or create an account with either provider.</p>
                <div class="login-divider" aria-hidden="true"><span>or use your password</span></div>
            {% else %}
                {% if google_oauth_configured or github_oauth_configured %}
                    <p class="google-signup-note google-setup-note" role="status">Social sign-in is disabled by the site administrator.</p>
                {% else %}
                    <p class="google-signup-note google-setup-note" role="status">Social sign-in is not configured on this server yet. Use password sign-in or ask the site administrator to configure OAuth.</p>
                {% endif %}
            {% endif %}
            <form method="post" action="{{ url_for('login') }}">
                <div class="input-box">
                    <span class="icon" aria-hidden="true">⚑</span>
                    <input id="username" name="username" type="text" autocomplete="username" placeholder=" " required autofocus>
                    <label for="username">Username</label>
                </div>
                <div class="input-box">
                    <button class="password-toggle" type="button" aria-label="Show password" aria-controls="password">👁</button>
                    <input id="password" name="password" type="password" autocomplete="current-password" placeholder=" " required>
                    <label for="password">Password</label>
                </div>
                <div class="remember-forget">
                    <label><input type="checkbox" name="remember" disabled> Remember me</label>
                    <a href="{{ url_for('forgot_password') }}">Forgot password?</a>
                </div>
                <button type="submit">Sign in</button>
            </form>
            {% if error %}<p class="login-message" role="alert">{{ error }}</p>{% endif %}
            <div class="register-link">
                <p>Don't have an account? <a href="{{ url_for('register') }}">Create one</a></p>
                <p><a href="{{ url_for('home') }}">→ Back to home</a></p>
            </div>
        </main>
    </section>
    <script>
        const password = document.getElementById('password');
        const toggle = document.querySelector('.password-toggle');
        const eyeSvg = `
            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                <circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="1.8"/>
            </svg>`;
        const eyeOffSvg = `
            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                <path d="M3 3l18 18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                <path d="M10.6 10.6A2 2 0 0 1 13.4 13.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                <path d="M9.1 5.5A10.6 10.6 0 0 1 12 5c6.5 0 10 7 10 7a17.7 17.7 0 0 1-4.2 5.2M6.6 6.6A17.7 17.7 0 0 0 2 12s3.5 7 10 7a10.8 10.8 0 0 0 5.2-1.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>`;
        const setToggleState = () => {
            const visible = password.type === 'text';
            toggle.innerHTML = visible ? eyeOffSvg : eyeSvg;
            toggle.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
            toggle.setAttribute('title', visible ? 'Hide password' : 'Show password');
        };
        toggle.addEventListener('click', () => {
            password.type = password.type === 'text' ? 'password' : 'text';
            setToggleState();
        });
        setToggleState();
    </script>
</body>
</html>
"""


PROFILE_PAGE = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>My profile - Cloud Rdx</title><style>
:root{--ink:#17212b;--muted:#647483;--line:#d8e1e8;--paper:#f2f6f8;--panel:#fff;--green:#087f73;--dark:#122b3a;--gold:#f0b44d}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--paper);color:var(--ink);font-family:'Segoe UI',Arial,sans-serif;background-image:linear-gradient(#d8e1e844 1px,transparent 1px),linear-gradient(90deg,#d8e1e844 1px,transparent 1px);background-size:32px 32px}.wrap{width:min(760px,calc(100% - 32px));margin:44px auto}.top{display:flex;justify-content:space-between;align-items:start;margin-bottom:25px}.eyebrow{margin:0 0 9px;color:var(--green);text-transform:uppercase;letter-spacing:.15em;font:700 11px Consolas,monospace}h1{margin:0;font-size:40px;letter-spacing:-.03em}.sub{margin:9px 0 0;color:var(--muted);font:13px Consolas,monospace}.back{color:var(--green);font:700 12px Consolas,monospace;text-decoration:none}.panel{overflow:hidden;background:rgba(255,255,255,.96);border:1px solid var(--line);border-radius:8px;box-shadow:0 12px 30px #19314214}.head{padding:22px;border-bottom:1px solid var(--line)}.head h2{margin:0 0 5px;font-size:19px;font-weight:600}.head p{margin:0;color:var(--muted);font:12px Arial}.data{display:grid;grid-template-columns:1fr 1fr}.field{padding:19px 22px;border-bottom:1px solid #e8eef2}.field:nth-child(odd){border-right:1px solid #e8eef2}.label{display:block;margin-bottom:7px;color:var(--muted);font:700 10px Consolas,monospace;text-transform:uppercase;letter-spacing:.08em}.value{font:14px Consolas,monospace;overflow-wrap:anywhere}@media(max-width:580px){.wrap{margin:25px auto}.top{display:block}.back{display:inline-block;margin-top:17px}.data{display:block}.field:nth-child(odd){border-right:0}}
</style></head><body><main class="wrap"><header class="top"><div><p class="eyebrow">Private account record</p><h1>{{ profile.full_name }}</h1><p class="sub">/{{ profile.username }} · visible only to you and the administrator</p></div><a class="back" href="{{ back_url }}">→ BACK</a></header><section class="panel"><div class="head"><h2>Identity and recovery data</h2><p>This information is protected and used for account recovery verification.</p></div><div class="data"><div class="field"><span class="label">Username</span><span class="value">{{ profile.username }}</span></div><div class="field"><span class="label">Email address</span><span class="value">{{ profile.email }}</span></div><div class="field"><span class="label">Mobile number</span><span class="value">{{ profile.mobile }}</span></div><div class="field"><span class="label">Date of birth</span><span class="value">{{ profile.date_of_birth }}</span></div><div class="field"><span class="label">Account created</span><span class="value">{{ profile.created_at[:10] }}</span></div></div></section><section class="panel" style="margin-top:20px"><div class="head"><h2>Change password</h2><p>Update your password without administrator assistance.</p></div><form method="post" action="{{ url_for('change_password') }}" style="padding:22px"><label class="label" for="current_password">CURRENT PASSWORD</label><input id="current_password" name="current_password" type="password" required style="display:block;width:100%;margin:7px 0 14px;padding:12px;border:1px solid #cbd8e0;border-radius:6px"><label class="label" for="new_password">NEW PASSWORD</label><input id="new_password" name="new_password" type="password" minlength="8" required style="display:block;width:100%;margin:7px 0 14px;padding:12px;border:1px solid #cbd8e0;border-radius:6px"><label class="label" for="confirm_password">CONFIRM NEW PASSWORD</label><input id="confirm_password" name="confirm_password" type="password" minlength="8" required style="display:block;width:100%;margin:7px 0 14px;padding:12px;border:1px solid #cbd8e0;border-radius:6px"><button type="submit" style="padding:11px 15px;color:#fff;background:#087f73;border:0;border-radius:6px;cursor:pointer;font:700 12px Consolas,monospace">UPDATE PASSWORD</button></form></section></main></body></html>
"""
PROFILE_PAGE = PROFILE_PAGE.replace(
    '<header class="top">',
    '{% with messages = get_flashed_messages() %}{% for message in messages %}<p style="padding:12px 15px;color:#087f73;background:#edf8f7;border:1px solid #b9e1dc;border-radius:8px;font:13px Arial">{{ message }}</p>{% endfor %}{% endwith %}<header class="top">',
)
PROFILE_PAGE = PROFILE_PAGE.replace(
    "</style>",
    ".profile-form{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:22px}.profile-form label{display:block;color:var(--muted);font:700 10px Consolas,monospace;text-transform:uppercase;letter-spacing:.08em}.profile-form input{display:block;width:100%;margin-top:7px;padding:11px;border:1px solid var(--line);border-radius:6px;font:14px Arial}.profile-form .wide{grid-column:1/-1}.profile-note{padding:0 22px 18px;color:var(--muted);font:12px/1.5 Arial}.profile-picture{width:72px;height:72px;border-radius:50%;object-fit:cover}.profile-links{display:flex;gap:12px;flex-wrap:wrap;padding:16px 22px;font:13px Arial}.profile-links span{padding:8px 11px;background:#edf8f7;border-radius:999px}@media(max-width:580px){.profile-form{grid-template-columns:1fr}.profile-form .wide{grid-column:auto}}\\n</style>",
    1,
)
PROFILE_PAGE = PROFILE_PAGE.replace(
    '<section class="panel" style="margin-top:20px"><div class="head"><h2>Change password</h2>',
    """{% if can_edit_profile %}<section class="panel" style="margin-top:20px"><div class="head"><h2>Recovery and profile details</h2><p>Only provide details you are comfortable sharing. Phone and date of birth are used by the existing account-recovery verification flow.</p></div><form class="profile-form" method="post" action="{{ url_for('profile') }}"><label class="wide" for="profile-full-name">Full name<input id="profile-full-name" name="full_name" maxlength="160" value="{{ profile.full_name or '' }}" required autocomplete="name"></label><label for="profile-mobile">Phone number<input id="profile-mobile" name="mobile" type="tel" maxlength="32" value="{{ profile.mobile or '' }}" autocomplete="tel"></label><label for="profile-dob">Date of birth<input id="profile-dob" name="date_of_birth" type="date" value="{{ profile.date_of_birth or '' }}" autocomplete="bday"></label><label for="profile-gender">Gender (optional)<input id="profile-gender" name="gender" maxlength="80" value="{{ profile.gender or '' }}" autocomplete="off"></label><label for="profile-location">Location (optional)<input id="profile-location" name="location" maxlength="160" value="{{ profile.location or '' }}" autocomplete="address-level2"></label><button class="wide" type="submit" style="padding:11px 15px;color:#fff;background:#087f73;border:0;border-radius:6px;cursor:pointer;font:700 12px Consolas,monospace">SAVE PROFILE</button></form><p class="profile-note">Your OAuth provider password is never shared with Cloud Rdx. We do not ask for or store security-question answers. Keep recovery details current and use a unique Cloud Rdx password if you set one.</p></section>{% endif %}<section class="panel" style="margin-top:20px"><div class="head"><h2>Change password</h2>""",
    1,
)
PROFILE_PAGE = PROFILE_PAGE.replace(
    '<div class="field"><span class="label">Account created</span><span class="value">{{ profile.created_at[:10] }}</span></div>',
    '''<div class="field"><span class="label">Account created</span><span class="value">{{ profile.created_at[:10] }}</span></div><div class="field"><span class="label">Gender</span><span class="value">{{ profile.gender or 'Not provided' }}</span></div><div class="field"><span class="label">Location</span><span class="value">{{ profile.location or 'Not provided' }}</span></div><div class="field"><span class="label">Last login</span><span class="value">{{ profile.last_login_at|prettydate if profile.last_login_at else 'Not recorded' }}</span></div><div class="field"><span class="label">Last account activity</span><span class="value">{{ profile.last_seen|prettydate if profile.last_seen else 'Not recorded' }}</span></div><div class="field"><span class="label">Two-factor authentication</span><span class="value">{{ 'Enabled' if profile.totp_enabled else 'Not enabled' }}</span></div>''',
    1,
)
PROFILE_PAGE = PROFILE_PAGE.replace(
    '<h1>{{ profile.full_name }}</h1>',
    '{% if profile.profile_picture %}<img class="profile-picture" src="{{ profile.profile_picture }}" alt="Profile picture" referrerpolicy="no-referrer">{% endif %}<h1>{{ profile.full_name or profile.username }}</h1>',
    1,
)
PROFILE_PAGE = PROFILE_PAGE.replace(
    "<p>This information is protected and used for account recovery verification.</p>",
    "<p>Your profile is visible to you and authorized administrators. Phone number and date of birth are used for recovery verification.</p>",
    1,
)
PROFILE_PAGE = PROFILE_PAGE.replace(
    '</div></section>{% if can_edit_profile %}',
    '''</div>{% if profile.google_sub or profile.github_sub %}<div class="profile-links">{% if profile.google_sub %}<span>Google linked · {{ profile.google_username or profile.google_profile_name or 'Account' }} · {{ profile.google_email }}</span>{% endif %}{% if profile.github_sub %}<span>GitHub linked · {{ profile.github_username or profile.github_profile_name or 'Account' }} · {{ profile.github_email }}</span>{% endif %}</div>{% endif %}</section>{% if can_edit_profile %}''',
    1,
)
PROFILE_PAGE = PROFILE_PAGE.replace(
    '<section class="panel" style="margin-top:20px"><div class="head"><h2>Change password</h2>',
    '{% if can_edit_profile %}<section class="panel" style="margin-top:20px"><div class="head"><h2>Change password</h2>',
    1,
)
PROFILE_PAGE = PROFILE_PAGE.replace(
    "</form></section></main></body></html>",
    "</form></section>{% endif %}</main></body></html>",
    1,
)


USER_ALLOCATION_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Storage allocation - Cloud Rdx</title>
<style>body{margin:0;background:#f8f9fc;color:#3a3b45;font-family:Arial,sans-serif}.wrap{width:min(1040px,calc(100% - 32px));margin:32px auto}.top{display:flex;justify-content:space-between;gap:20px;align-items:start;margin-bottom:22px}.top a{color:#4e73df;font-weight:700;text-decoration:none}.panel{margin-bottom:20px;padding:22px;background:#fff;border:1px solid #e3e6f0;border-radius:8px;box-shadow:0 .15rem 1.2rem #3a3b4512}.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.stat{padding:16px;background:#f8f9fc;border-left:4px solid #4e73df}.stat small{display:block;color:#858796;font-size:11px;text-transform:uppercase}.stat strong{display:block;margin-top:8px;font-size:20px}.meter{height:12px;margin-top:20px;overflow:hidden;background:#eaecf4;border-radius:8px}.meter span{display:block;height:100%;background:#4e73df;border-radius:inherit}.plans{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.plan{padding:18px;border:1px solid #e3e6f0;border-radius:8px}.plan h3{margin:0 0 8px}.price{margin:12px 0;font-size:22px;font-weight:700}.button{padding:10px 13px;color:#fff;background:#4e73df;border:0;border-radius:5px;cursor:pointer;font-weight:700}.button:disabled{background:#b8bfce;cursor:not-allowed}.qr{max-width:220px;margin:10px 0;border:1px solid #e3e6f0}.notice{padding:12px 15px;margin-bottom:18px;color:#856404;background:#fff3cd;border:1px solid #ffeeba;border-radius:5px}.muted{color:#858796;font-size:13px}@media(max-width:800px){.summary,.plans{grid-template-columns:1fr 1fr}}@media(max-width:520px){.summary,.plans{grid-template-columns:1fr}.top{display:block}}</style></head><body><main class="wrap"><header class="top"><div><p class="muted">CLOUD RDX / STORAGE</p><h1>Storage allocation</h1><p class="muted">Monitor your personal quota and request an upgrade.</p></div><a href="{{ url_for('files') }}">→ BACK TO STORAGE</a></header>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="notice">{{ message }}</div>{% endfor %}{% endwith %}<section class="panel"><h2>My storage</h2><div class="summary"><div class="stat"><small>Used</small><strong>{{ used|filesize }}</strong></div><div class="stat"><small>Remaining</small><strong>{{ remaining|filesize }}</strong></div><div class="stat"><small>Allocation</small><strong>{{ quota|filesize }}</strong></div><div class="stat"><small>Status</small><strong>{{ subscription.status|upper if subscription else 'FREE' }}</strong></div></div><div class="meter" role="progressbar" aria-valuenow="{{ percent }}" aria-valuemin="0" aria-valuemax="100" aria-label="Storage allocation used"><span style="width:{{ percent }}%"></span></div><p class="muted">{{ percent }}% used · Current plan: {{ subscription.plan_name if subscription else 'Free Plan' }}</p></section><section class="panel"><h2>Upgrade storage</h2><p class="muted">Choose a plan. Payment requests are linked to your signed-in account and cannot change another user’s quota.</p><div class="plans">{% for plan in plans %}<article class="plan"><h3>{{ plan.name }}</h3><p>{{ plan.quota_bytes|filesize }} total storage</p><div class="price">₹{{ '%.2f'|format(plan.price_paise / 100) }}{% if plan.price_paise %}<small>/month</small>{% endif %}</div><form method="post" action="{{ url_for('manual_payment_request') }}"><input type="hidden" name="plan_id" value="{{ plan.id }}"><label class="visually-hidden" for="payment-reference-{{ plan.id }}">UPI transaction reference for {{ plan.name }}</label><input id="payment-reference-{{ plan.id }}" name="transaction_reference" required placeholder="UPI reference" style="width:100%;padding:9px;border:1px solid #d1d3e2;border-radius:5px"><button class="button" type="submit"{% if not plan.price_paise %} disabled{% endif %}>Submit payment reference</button></form></article>{% endfor %}</div><p class="muted">Scan the payment QR, then submit the transaction reference. Storage is activated after administrator verification.</p>{% if qr_url %}<img class="qr" src="{{ qr_url }}" alt="Payment QR code">{% else %}<p class="notice">Payment QR is not configured. Set PAYMENT_QR_URL before accepting manual payments.</p>{% endif %}</section></main></body></html>
"""


USER_PAGE_NAV = """
<nav class="account-nav" aria-label="Account navigation">
    <div class="account-nav-links">
        <a href="{{ url_for('files') }}" {% if request.endpoint == 'files' %}aria-current="page"{% endif %}><span aria-hidden="true">▦</span> My Drive</a>
        <a href="{{ url_for('storage_plan') }}" {% if request.endpoint == 'storage_plan' %}aria-current="page"{% endif %}><span aria-hidden="true">⚑</span> Storage plan</a>
        <a href="{{ url_for('profile') }}" {% if request.endpoint in ('profile', 'admin_user_profile') %}aria-current="page"{% endif %}><span aria-hidden="true">◉</span> My Profile</a>
        <a href="{{ url_for('user_trash') }}" {% if request.endpoint == 'user_trash' %}aria-current="page"{% endif %}><span aria-hidden="true">🗑</span> Recycle bin</a>
    </div>
    <div class="account-theme">
        <button class="account-theme-toggle" id="theme-toggle" type="button" aria-pressed="false" aria-label="Switch to light theme">
            <span aria-hidden="true">◉</span><span id="theme-toggle-label">Dark theme</span>
        </button>
        <span class="visually-hidden" id="theme-status" role="status" aria-live="polite"></span>
    </div>
</nav>
"""


def apply_user_page_theme(template):
    """Apply the shared account-page navigation, theme assets, and page class."""
    template = template.replace(
        "</head>",
        '<link rel="stylesheet" href="{{ url_for(\'static\', filename=\'cloud-account.css\') }}">'
        '<script src="{{ url_for(\'static\', filename=\'cloud-account.js\') }}" defer></script></head>',
        1,
    )
    template = template.replace('<html lang="en"', '<html lang="en" data-theme="dark"', 1)
    template = template.replace("<body>", '<body class="cloud-account-page">', 1)
    template = template.replace("</header>", "</header>" + USER_PAGE_NAV, 1)
    return template


PROFILE_PAGE = apply_user_page_theme(PROFILE_PAGE)
USER_ALLOCATION_PAGE = apply_user_page_theme(USER_ALLOCATION_PAGE)


ADMIN_PAYMENT_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Payment verification - Cloud Rdx</title></head><body class="admin-theme"><main class="main" style="width:auto"><header class="topbar"><div><p class="eyebrow">CLOUD RDX / BILLING</p><h1>Payment verification</h1><p class="subtitle">Review QR payment references and allocate storage to the verified account.</p></div><a href="{{ url_for('admin_panel') }}">→ ADMIN DASHBOARD</a></header>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}{% endwith %}<section class="panel"><div class="panel-head"><h2>Pending payment requests</h2><p>Approve only after checking the payment in your provider dashboard.</p></div><div class="table-responsive"><table><thead><tr><th>User</th><th>Plan</th><th>Amount</th><th>Reference</th><th>Submitted</th><th>Action</th></tr></thead><tbody>{% for item in requests %}<tr><td>{{ item.username }}<br><span class="muted">{{ item.email or 'No email' }}</span></td><td>{{ item.plan_name }}<br><span class="muted">{{ item.quota_bytes|filesize }}</span></td><td>₹{{ '%.2f'|format(item.amount_paise / 100) }}</td><td>{{ item.transaction_reference }}</td><td>{{ item.created_at|prettydate }}</td><td><form method="post" action="{{ url_for('admin_review_payment', payment_id=item.id) }}"><button class="button" name="decision" value="approve" type="submit">Approve</button> <button class="button danger" name="decision" value="reject" type="submit">Reject</button></form></td></tr>{% else %}<tr><td colspan="6">No pending payment requests.</td></tr>{% endfor %}</tbody></table></div></section></main></body></html>
"""


ADMIN_PROFIT_PAGE = """
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Profit and usage - Cloud Rdx</title>
<style>
:root{--ink:#16221f;--muted:#71817b;--line:#dfe8e2;--paper:#f7faf7;--panel:#fff;--green:#18794e;--dark:#105437;--gold:#f2be58;--red:#a34f3a;--blue:#356aa8}
*{box-sizing:border-box}body{margin:0;color:var(--ink);background:var(--paper);font-family:Arial,sans-serif}.wrap{width:min(1240px,calc(100% - 34px));margin:32px auto 50px}
.top{display:flex;justify-content:space-between;align-items:start;gap:22px;margin-bottom:25px}.eyebrow{margin:0 0 9px;color:var(--green);text-transform:uppercase;letter-spacing:.15em;font-size:11px;font-weight:700}h1{margin:0 0 8px;font:500 clamp(30px,4vw,46px) Georgia,serif;letter-spacing:-.03em}.subtitle,.muted{color:var(--muted);font-size:13px}.top a{color:var(--green);font-weight:700;text-decoration:none;white-space:nowrap}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:0 12px 30px #19314212}.card{padding:19px}.card small{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}.card strong{display:block;margin-top:9px;font:700 25px Consolas,monospace}.card .hint{display:block;margin-top:7px;color:var(--muted);font-size:11px}.positive{color:var(--green)}.negative{color:var(--red)}.blue{color:var(--blue)}
.panel{overflow:hidden;margin-bottom:20px}.head{padding:20px 22px;border-bottom:1px solid var(--line)}.head h2{margin:0 0 6px;font:500 20px Georgia,serif}.head p{margin:0;color:var(--muted);font-size:13px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--line)}.metric{padding:17px 20px;background:#fff}.metric span{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em}.metric b{display:block;margin-top:7px;font-size:18px}.table-wrap{overflow-x:auto}table{width:100%;min-width:680px;border-collapse:collapse;font-size:13px}th{padding:12px 18px;color:var(--muted);background:#f8fbf8;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.06em}td{padding:13px 18px;border-top:1px solid #edf2ee}.note{padding:14px 20px;color:#52675d;background:#f0f8f2;border-top:1px solid var(--line);font-size:12px;line-height:1.5}
@media(max-width:850px){.cards{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:560px){.wrap{width:min(100% - 24px,1240px);margin-top:22px}.top{display:block}.top a{display:inline-block;margin-top:16px}.cards,.grid{grid-template-columns:1fr}.card strong{font-size:22px}}
</style></head>
<body><main class="wrap"><header class="top"><div><p class="eyebrow">Cloud Rdx / owner analytics</p><h1>Profit and usage</h1><p class="subtitle">Private business, account, payment, and storage health overview for {{ owner_username }}.</p></div><a href="{{ url_for('admin_panel') }}">→ ADMIN DASHBOARD</a></header>
<section class="cards">
<article class="card"><small>Collected revenue</small><strong class="positive">₹{{ '%.2f'|format(metrics.revenue) }}</strong><span class="hint">Approved payments</span></article>
<article class="card"><small>Estimated operating cost</small><strong>₹{{ '%.2f'|format(metrics.estimated_cost) }}</strong><span class="hint">{{ '%.2f'|format(metrics.cost_per_gb) }} per used GB/month</span></article>
<article class="card"><small>Estimated net profit</small><strong class="{{ 'positive' if metrics.net_profit >= 0 else 'negative' }}">₹{{ '%.2f'|format(metrics.net_profit) }}</strong><span class="hint">Revenue minus estimated cost</span></article>
<article class="card"><small>Payment pipeline</small><strong class="blue">₹{{ '%.2f'|format(metrics.pending_revenue) }}</strong><span class="hint">{{ metrics.pending_payments }} pending requests</span></article>
</section>
<section class="panel"><div class="head"><h2>Users and activity</h2><p>Activity is based on the configured {{ inactive_days }}-day inactivity window and excludes the owner account.</p></div><div class="grid"><div class="metric"><span>Total users</span><b>{{ metrics.total_users }}</b></div><div class="metric"><span>Active users</span><b class="positive">{{ metrics.active_users }}</b></div><div class="metric"><span>Inactive users</span><b class="negative">{{ metrics.inactive_users }}</b></div><div class="metric"><span>Suspended users</span><b>{{ metrics.suspended_users }}</b></div><div class="metric"><span>New users (30 days)</span><b class="blue">{{ metrics.new_users }}</b></div><div class="metric"><span>Active sessions</span><b>{{ metrics.active_sessions }}</b></div></div></section>
<section class="panel"><div class="head"><h2>Data usage and capacity</h2><p>Usage is calculated from each account's private storage folder.</p></div><div class="grid"><div class="metric"><span>Data in use</span><b>{{ metrics.used_bytes|filesize }}</b></div><div class="metric"><span>Allocated capacity</span><b>{{ metrics.quota_bytes|filesize }}</b></div><div class="metric"><span>Capacity remaining</span><b>{{ metrics.remaining_bytes|filesize }}</b></div><div class="metric"><span>Stored files</span><b>{{ metrics.total_files }}</b></div><div class="metric"><span>Average usage / user</span><b>{{ metrics.average_usage|filesize }}</b></div><div class="metric"><span>Capacity utilization</span><b>{{ metrics.capacity_percent }}%</b></div></div><div class="note">Estimated cost is configurable with <code>STORAGE_COST_PER_GB_INR</code>; the default is ₹0 because no infrastructure cost has been configured.</div></section>
<section class="panel"><div class="head"><h2>Billing summary</h2><p>Payment request totals from the local billing records.</p></div><div class="grid"><div class="metric"><span>Approved requests</span><b class="positive">{{ metrics.approved_payments }}</b></div><div class="metric"><span>Pending requests</span><b>{{ metrics.pending_payments }}</b></div><div class="metric"><span>Rejected requests</span><b>{{ metrics.rejected_payments }}</b></div><div class="metric"><span>Rejected amount</span><b class="negative">₹{{ '%.2f'|format(metrics.rejected_revenue) }}</b></div><div class="metric"><span>Active subscriptions</span><b>{{ metrics.active_subscriptions }}</b></div><div class="metric"><span>Monthly recurring plan value</span><b>₹{{ '%.2f'|format(metrics.monthly_plan_value) }}</b></div></div></section>
<section class="panel"><div class="head"><h2>Plan distribution</h2><p>Current active subscriptions by storage plan.</p></div><div class="table-wrap"><table><thead><tr><th>Plan</th><th>Subscribers</th><th>Monthly price</th><th>Allocated capacity</th></tr></thead><tbody>{% for plan in plan_summary %}<tr><td>{{ plan.name }}</td><td>{{ plan.subscribers }}</td><td>₹{{ '%.2f'|format(plan.price_paise / 100) }}</td><td>{{ plan.capacity|filesize }}</td></tr>{% else %}<tr><td colspan="4">No active paid plans yet.</td></tr>{% endfor %}</tbody></table></div></section>
</main></body></html>
"""

ADMIN_INTELLIGENCE_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cloud Intelligence Center - Cloud Rdx</title>
<link rel="stylesheet" href="{{ url_for('static', filename='admin-theme.css') }}">
<style>
.intel{--bg:#08111f;--panel:#101d30;--line:#253954;--text:#e7effb;--muted:#9db0ca;max-width:1520px;margin:auto;color:var(--text)}
.intel .topbar{margin-bottom:20px;padding:20px;background:linear-gradient(115deg,#102039,#142b48);border:1px solid var(--line);border-radius:16px}
.intel .eyebrow{color:#5eead4}.intel h1{color:#f8fbff}.intel .subtitle,.intel .muted{color:var(--muted)}
.intel .panel,.intel .card{margin-bottom:16px;background:var(--panel);border:1px solid var(--line);border-radius:14px;box-shadow:0 16px 40px #02061755}
.intel .panel-head{border-color:var(--line)}.intel .panel-head h2{color:#f8fbff}.intel .panel-head p{color:var(--muted)}
.intel-actions{display:flex;align-items:center;justify-content:flex-end;flex-wrap:wrap;gap:8px}
.intel-actions a,.intel-actions button{min-height:40px;padding:9px 12px;color:#e6f3ff;background:#172943;border:1px solid #35516e;border-radius:9px;text-decoration:none;cursor:pointer}
.intel-actions button:hover,.intel-actions a:hover{background:#203958}
.intel-status{display:inline-flex;align-items:center;gap:7px;padding:7px 10px;border:1px solid #1d765f;border-radius:99px;background:#0f332e;font-size:11px;font-weight:700}
.intel-status:before{content:"";width:8px;height:8px;background:#34d399;border-radius:50%}
.intel-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:16px}
.intel-stat{position:relative;overflow:hidden;padding:17px;background:linear-gradient(145deg,#12233a,#0e1a2b);border:1px solid var(--line);border-radius:12px}
.intel-stat:after{content:"";position:absolute;right:-27px;top:-34px;width:84px;height:84px;border:1px solid #35d6c033;border-radius:50%;box-shadow:0 0 22px #35d6c018}
.intel-stat small{display:block;color:var(--muted);font-size:10px;letter-spacing:.09em;text-transform:uppercase}
.intel-stat strong{display:block;margin:9px 0 4px;color:#f8fbff;font:700 clamp(19px,2vw,27px) Consolas,monospace}
.intel-stat .tag{color:#70dfc8;font:10px Arial,sans-serif;text-transform:uppercase;letter-spacing:.07em}
.intel-layout{display:grid;grid-template-columns:1.2fr 1fr;gap:16px;align-items:stretch}
.intel-viz{min-height:320px;padding:14px 18px}
.intel-canvas{display:block;width:100%;height:230px}.intel-viz-label{display:flex;justify-content:space-between;gap:12px;color:var(--muted);font-size:11px}
.intel-category-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;padding:14px 18px}
.intel-category{padding:12px;background:#0b1728;border:1px solid #243851;border-radius:9px}
.intel-category b,.intel-category small{display:block}.intel-category small{margin-top:5px;color:var(--muted)}
.intel-empty{padding:18px;color:#b9c9dc;background:#0c1829;border:1px dashed #38506a;border-radius:10px}
.intel-table{overflow:auto}.intel table{width:100%;min-width:560px;border-collapse:collapse;font-size:12px}.intel th,.intel td{padding:11px 13px;color:var(--text);border-bottom:1px solid #253954;text-align:left}.intel th{color:var(--muted);background:#14243b;text-transform:uppercase;font-size:10px}
.intel-filter{display:flex;flex-wrap:wrap;gap:8px;padding:14px 18px}.intel-filter button{min-height:36px;padding:7px 10px;color:#cbd8eb;background:#102038;border:1px solid #304968;border-radius:8px;cursor:pointer}.intel-filter button[aria-pressed=true]{color:#08111f;background:#5eead4;border-color:#5eead4}
.intel-sphere-wrap{position:relative;display:grid;place-items:center;height:230px;overflow:hidden;background:radial-gradient(ellipse at center,#153a5070,transparent 66%)}
.intel-sphere{position:absolute;width:min(190px,55%);aspect-ratio:1;border:1px solid #46e0d188;border-radius:50%;background:radial-gradient(circle at 34% 30%,#68eadf65,#192b60a8 52%,#091423 72%);box-shadow:inset -18px -20px 36px #020617aa,0 0 34px #30d6c133;animation:orbit 18s linear infinite}
.intel-sphere:before,.intel-sphere:after{content:"";position:absolute;inset:14% -20%;border:1px solid #5eead477;border-radius:50%;transform:rotate(-23deg)}
.intel-sphere:after{inset:26% -26%;transform:rotate(55deg);border-color:#818cf866}
.intel-performance .intel-sphere{animation:none}.intel-globe{width:125px;height:125px;border:1px solid #818cf877;border-radius:50%;background:radial-gradient(circle at 35% 30%,#5eead455,#172554 65%,#091423);box-shadow:0 0 25px #818cf822}
@keyframes orbit{to{transform:rotate(360deg)}}
.intel :where(a,button,input,select):focus-visible{outline:3px solid #5eead4;outline-offset:3px}
.intel-fullscreen:fullscreen{overflow:auto;background:var(--bg);padding:14px}.intel-fullscreen:fullscreen .rail{display:none}.intel-fullscreen:fullscreen .main{width:100%;padding:10px 20px}
.intel-toast{position:fixed;right:18px;bottom:18px;z-index:8;padding:12px 16px;color:#08111f;background:#5eead4;border-radius:9px;box-shadow:0 10px 30px #0008}
@media(max-width:940px){.intel-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.intel-layout{grid-template-columns:1fr}}
@media(max-width:600px){.intel{padding:0 4px}.intel .topbar{display:grid;gap:12px;padding:15px}.intel-actions{justify-content:flex-start}.intel-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.intel-stat{padding:13px}.intel-category-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.intel-viz{min-height:285px;padding:12px}.intel-canvas{height:190px}}
@media(prefers-reduced-motion:reduce){.intel *, .intel *:before,.intel *:after{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
</style></head><body class="admin-theme"><div class="shell intel-fullscreen" id="intel-dashboard">
<aside class="rail"><a class="brand" href="{{ url_for('admin_panel') }}"><span class="brand-mark">C</span><span>Cloud Rdx</span></a><nav class="rail-nav" aria-label="Command center">
<a class="rail-link active" href="{{ url_for('admin_intelligence') }}"><span class="rail-icon">◌</span><span>Intelligence</span></a>
<a class="rail-link" href="{{ url_for('admin_profit') }}"><span class="rail-icon">₹</span><span>Profit & usage</span></a>
<a class="rail-link" href="{{ url_for('admin_emergency') }}"><span class="rail-icon">⚙</span><span>Security response</span></a>
<a class="rail-link" href="{{ url_for('admin_audit') }}"><span class="rail-icon">≪</span><span>Audit log</span></a>
<a class="rail-link" href="{{ url_for('admin_storage') }}"><span class="rail-icon">◇</span><span>Storage</span></a>
<a class="rail-link" href="{{ url_for('admin_panel') }}"><span class="rail-icon">⌂</span><span>Admin dashboard</span></a></nav></aside>
<main class="main intel"><header class="topbar"><div><p class="eyebrow">CLOUD INFRASTRUCTURE / INTELLIGENCE</p><h1>Cloud Intelligence Center</h1><p class="subtitle">Aggregated operational data from the application database and private storage.</p></div>
<div class="intel-actions"><span class="intel-status" id="system-status">CHECKING</span><span class="muted" id="last-updated">Not refreshed</span><button type="button" id="refresh-data">Refresh analytics</button><button type="button" id="performance-toggle" aria-pressed="false">Performance mode</button><button type="button" id="fullscreen-toggle">Fullscreen</button></div></header>
<section class="intel-grid" aria-live="polite">
<article class="intel-stat"><small>Registered users</small><strong id="total-users">—</strong><span class="tag">Actual database count</span></article>
<article class="intel-stat"><small>Active sessions</small><strong id="active-sessions">—</strong><span class="tag">Actual session records</span></article>
<article class="intel-stat"><small>Storage in use</small><strong id="storage-used">—</strong><span class="tag">Measured from user files</span></article>
<article class="intel-stat"><small>Allocated capacity</small><strong id="storage-quota">—</strong><span class="tag">Account quota total</span></article>
<article class="intel-stat"><small>Collected revenue</small><strong id="revenue">—</strong><span class="tag">Approved payments · actual</span></article>
<article class="intel-stat"><small>Estimated storage cost</small><strong id="cost">Data unavailable</strong><span class="tag">Only when cost rate configured</span></article>
<article class="intel-stat"><small>Failed logins · 24h</small><strong id="failed-logins">—</strong><span class="tag">Recorded attempts</span></article>
<article class="intel-stat"><small>Open security alerts</small><strong id="open-alerts">—</strong><span class="tag">Actual alert queue</span></article>
</section>
<div class="intel-layout">
<section class="panel"><div class="panel-head"><h2>Storage galaxy</h2><p>Core size and usage ring are driven by measured storage. No estimated capacity is substituted for missing data.</p></div>
<div class="intel-viz"><div class="intel-sphere-wrap"><div class="intel-sphere" aria-hidden="true"></div><canvas class="intel-canvas" id="storage-ring" role="img" aria-label="Storage usage ring. Exact values are shown below."></canvas></div>
<div class="intel-viz-label"><span id="storage-caption">Loading measured storage…</span><span id="storage-percent">—</span></div></div></section>
<section class="panel"><div class="panel-head"><h2>Profit planet</h2><p>Actual approved payment total and explicitly estimated costs. No projection is shown.</p></div>
<div class="intel-viz"><div class="intel-sphere-wrap"><div class="intel-sphere" aria-hidden="true"></div></div>
<div class="intel-viz-label"><span id="profit-caption">Collected revenue: loading</span><span id="profit-detail">Estimated net: —</span></div>
<div class="intel-empty" id="finance-note">Operating expenses and profit margin are unavailable unless the deployment configures its cost model.</div></div></section></div>
<section class="panel"><div class="panel-head"><h2>Usage mountain · audited file activity</h2><p>Counts include activity written to the audit log only. This application does not currently collect bandwidth or geographic telemetry.</p></div>
<div class="intel-filter" role="group" aria-label="Activity range">{% for value,label in ranges %}<button type="button" data-range="{{ value }}" aria-pressed="{{ 'true' if value == '7d' else 'false' }}">{{ label }}</button>{% endfor %}</div>
<div class="intel-viz"><canvas class="intel-canvas" id="activity-chart" role="img" aria-label="Audited file activity chart."></canvas><div class="intel-viz-label"><span id="activity-caption">Loading activity…</span><span>Historical sample from audit_events</span></div></div></section>
<div class="intel-layout">
<section class="panel"><div class="panel-head"><h2>Storage distribution</h2><p>Aggregated from actual files by file type.</p></div><div class="intel-category-grid" id="storage-categories"><div class="intel-empty">Loading file categories…</div></div></section>
<section class="panel"><div class="panel-head"><h2>Platform signals</h2><p>Measurements the current deployment can verify.</p></div><div class="ec-grid">
<article class="ec-stat"><small>Host disk free</small><strong id="disk-free">Data unavailable</strong></article>
<article class="ec-stat"><small>CPU / memory / network</small><strong>Data unavailable</strong></article>
<article class="ec-stat"><small>Bandwidth totals</small><strong>Data unavailable</strong></article>
<article class="ec-stat"><small>Regional activity</small><strong>Data unavailable</strong></article>
</div><p class="muted" style="padding:0 18px 16px">CPU, RAM, bandwidth, geography, scheduled backups, and real-time request rates require telemetry sources not present in this application.</p></section></div>
<section class="panel"><div class="panel-head"><h2>Top storage accounts</h2><p>Owner-only, aggregated storage usage; no profile, email, or location data is exposed here.</p></div><div class="intel-table"><table><thead><tr><th>Account</th><th>Stored files</th><th>Storage used</th></tr></thead><tbody id="top-users"><tr><td colspan="3">Loading…</td></tr></tbody></table></div></section>
</main></div><div id="intel-toast" class="intel-toast" role="status" hidden></div>
<script>
(() => {
 const api="{{ url_for('admin_analytics_overview') }}", activityApi="{{ url_for('admin_analytics_activity') }}";
 const $=id=>document.getElementById(id), fmtBytes=n=>{if(n===null||n===undefined)return'Data unavailable';const units=['B','KB','MB','GB','TB'];let i=0,v=Number(n);while(v>=1024&&i<units.length-1){v/=1024;i++}return`${v.toFixed(i?1:0)} ${units[i]}`};
 const fmtMoney=n=>n===null||n===undefined?'Data unavailable':`₹${Number(n).toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2})}`;
 const toast=(text)=>{const el=$('intel-toast');el.textContent=text;el.hidden=false;setTimeout(()=>el.hidden=true,3200)};
 let overview=null, range='7d';
 function drawRing(){const c=$('storage-ring'),ctx=c.getContext('2d'),dpr=window.devicePixelRatio||1,r=c.getBoundingClientRect();c.width=r.width*dpr;c.height=r.height*dpr;ctx.scale(dpr,dpr);const x=r.width/2,y=r.height/2,rad=Math.min(r.width,r.height)*.39;ctx.lineWidth=12;ctx.strokeStyle='#203752';ctx.beginPath();ctx.arc(x,y,rad,0,Math.PI*2);ctx.stroke();if(!overview)return;const p=overview.storage.utilization_percent;if(p===null)return;ctx.strokeStyle='#5eead4';ctx.lineCap='round';ctx.shadowColor='#5eead4';ctx.shadowBlur=14;ctx.beginPath();ctx.arc(x,y,rad,-Math.PI/2,-Math.PI/2+Math.PI*2*Math.min(100,p)/100);ctx.stroke();ctx.shadowBlur=0}
 function drawActivity(data){const c=$('activity-chart'),ctx=c.getContext('2d'),dpr=window.devicePixelRatio||1,r=c.getBoundingClientRect();c.width=r.width*dpr;c.height=r.height*dpr;ctx.scale(dpr,dpr);ctx.clearRect(0,0,r.width,r.height);const points=data.points||[],pad=22,w=r.width-pad*2,h=r.height-pad*2;ctx.strokeStyle='#263c56';ctx.lineWidth=1;for(let i=0;i<4;i++){const y=pad+h*i/3;ctx.beginPath();ctx.moveTo(pad,y);ctx.lineTo(pad+w,y);ctx.stroke()}if(!points.length)return;const vals=points.map(p=>p.operations),max=Math.max(1,...vals),step=w/Math.max(points.length-1,1);ctx.beginPath();points.forEach((p,i)=>{const x=pad+i*step,y=pad+h-(p.operations/max*h);i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.lineTo(pad+w,pad+h);ctx.lineTo(pad,pad+h);ctx.closePath();const g=ctx.createLinearGradient(0,pad,0,pad+h);g.addColorStop(0,'#5eead466');g.addColorStop(1,'#5eead400');ctx.fillStyle=g;ctx.fill();ctx.beginPath();points.forEach((p,i)=>{const x=pad+i*step,y=pad+h-(p.operations/max*h);i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.strokeStyle='#5eead4';ctx.lineWidth=2;ctx.stroke()}
 function populate(o){overview=o;$('total-users').textContent=o.users.total.toLocaleString();$('active-sessions').textContent=o.sessions.active.toLocaleString();$('storage-used').textContent=fmtBytes(o.storage.used_bytes);$('storage-quota').textContent=fmtBytes(o.storage.quota_bytes);$('storage-caption').textContent=`${fmtBytes(o.storage.used_bytes)} used / ${fmtBytes(o.storage.quota_bytes)} allocated`;$('storage-percent').textContent=o.storage.utilization_percent===null?'—':`${o.storage.utilization_percent}% used`;$('revenue').textContent=fmtMoney(o.finance.collected_revenue);$('cost').textContent=fmtMoney(o.finance.estimated_storage_cost);$('failed-logins').textContent=o.security.failed_logins_24h.toLocaleString();$('open-alerts').textContent=o.security.open_alerts.toLocaleString();$('profit-caption').textContent=`Collected: ${fmtMoney(o.finance.collected_revenue)}`;$('profit-detail').textContent=o.finance.estimated_net===null?'Net: Data unavailable':`Estimated net: ${fmtMoney(o.finance.estimated_net)}`;$('disk-free').textContent=fmtBytes(o.host.disk_free_bytes);$('system-status').textContent=o.status;$('last-updated').textContent=`Updated ${new Date().toLocaleTimeString()}`;
 const cat=$('storage-categories');cat.replaceChildren();if(!o.storage.categories.length){cat.innerHTML='<div class="intel-empty">No files recorded.</div>'}else{o.storage.categories.forEach(item=>{const el=document.createElement('div');el.className='intel-category';el.innerHTML=`<b>${item.category}</b><small>${item.files.toLocaleString()} files · ${fmtBytes(item.bytes)}</small>`;cat.appendChild(el)})}
 const tb=$('top-users');tb.replaceChildren();if(!o.users.top_storage.length){tb.innerHTML='<tr><td colspan="3">No user storage data.</td></tr>'}else{o.users.top_storage.forEach(item=>{const tr=document.createElement('tr');[item.username,item.files.toLocaleString(),fmtBytes(item.bytes)].forEach(value=>{const td=document.createElement('td');td.textContent=value;tr.appendChild(td)});tb.appendChild(tr)})}
 drawRing()}
 async function loadActivity(){const response=await fetch(`${activityApi}?range=${encodeURIComponent(range)}`,{credentials:'same-origin',headers:{Accept:'application/json'}});if(!response.ok)throw new Error('Activity analytics could not be loaded.');const data=await response.json();drawActivity(data);$('activity-caption').textContent=`${data.total_operations.toLocaleString()} audited operations · ${data.range_label}`}
 async function refresh(){try{const response=await fetch(api,{credentials:'same-origin',headers:{Accept:'application/json'}});if(!response.ok)throw new Error('Analytics could not be loaded.');populate(await response.json());await loadActivity()}catch(error){toast(error.message||'Analytics refresh failed.');$('system-status').textContent='UNAVAILABLE'}}
 $('refresh-data').addEventListener('click',refresh);document.querySelectorAll('[data-range]').forEach(button=>button.addEventListener('click',()=>{range=button.dataset.range;document.querySelectorAll('[data-range]').forEach(b=>b.setAttribute('aria-pressed',String(b===button)));loadActivity().catch(e=>toast(e.message))}));
 const dashboard=$('intel-dashboard'),mode=$('performance-toggle');try{if(localStorage.getItem('cloud-rdx-performance-mode')==='true'){dashboard.classList.add('intel-performance');mode.setAttribute('aria-pressed','true')}}catch{}
 mode.addEventListener('click',()=>{const on=!dashboard.classList.contains('intel-performance');dashboard.classList.toggle('intel-performance',on);mode.setAttribute('aria-pressed',String(on));try{localStorage.setItem('cloud-rdx-performance-mode',String(on))}catch{}});
 $('fullscreen-toggle').addEventListener('click',async()=>{try{if(!document.fullscreenElement)await dashboard.requestFullscreen();else await document.exitFullscreen()}catch{toast('Fullscreen is not available in this browser or was denied.')}});
 window.addEventListener('resize',()=>{if(overview)drawRing();loadActivity().catch(()=>{})},{passive:true});
 refresh();
})();
</script></body></html>
"""


ADMIN_STORAGE_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>User storage quotas - Cloud Rdx</title><style>
body{margin:0;background:#f8f9fc;color:#3a3b45;font-family:Arial,sans-serif}.wrap{width:min(1180px,calc(100% - 32px));margin:32px auto}.top{display:flex;justify-content:space-between;align-items:start;gap:18px;margin-bottom:24px}.top a{color:#4e73df;font-weight:700;text-decoration:none}.panel{overflow:hidden;background:#fff;border:1px solid #e3e6f0;border-radius:8px;box-shadow:0 .15rem 1.2rem #3a3b4512}.head{padding:20px 22px;border-bottom:1px solid #e3e6f0}.head h1{margin:0 0 7px;font-size:28px}.head p{margin:0;color:#858796;font-size:13px}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:760px;font-size:13px}th{padding:13px 18px;color:#6e707e;background:#f8f9fc;text-align:left;font-size:11px;text-transform:uppercase}td{padding:15px 18px;border-top:1px solid #eaecf4;vertical-align:middle}.muted{color:#858796;font-size:12px}.quota-form{display:flex;gap:7px;align-items:center}.quota-form input{width:110px;padding:8px;border:1px solid #d1d3e2;border-radius:4px}.button{padding:8px 11px;color:#fff;background:#4e73df;border:1px solid #4e73df;border-radius:4px;cursor:pointer;font-weight:700}.notice{margin-bottom:18px;padding:12px 15px;color:#856404;background:#fff3cd;border:1px solid #ffeeba;border-radius:5px}@media(max-width:700px){.top{display:block}.top a{display:inline-block;margin-top:14px}}
</style></head><body><main class="wrap"><header class="top"><div><p class="muted">CLOUD RDX / ADMINISTRATION</p><h1>User storage quotas</h1><p class="muted">Review storage usage, quotas, and per-user upload/download access.</p></div><a href="{{ url_for('admin_panel') }}">→ ADMIN DASHBOARD</a></header>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="notice">{{ message }}</div>{% endfor %}{% endwith %}<section class="panel"><div class="head"><h1>Storage allocation and access by user</h1><p>Each change applies only to the selected user and is recorded in the audit trail.</p></div><div class="table-wrap"><table><thead><tr><th>User ID</th><th>Username</th><th>Total Storage Used</th><th>Allocated Quota</th><th>Remaining Quota</th><th>Set Quota</th><th>Storage access</th></tr></thead><tbody>{% for item in users %}<tr><td>{{ item.id }}</td><td><strong>{{ item.username }}</strong><br><span class="muted">{{ item.status }}</span></td><td>{{ item.used|filesize }}</td><td>{% if item.quota %}{{ item.quota|filesize }}{% else %}Unlimited{% endif %}</td><td>{% if item.quota %}{{ item.remaining|filesize }}{% else %}Unlimited{% endif %}</td><td><form class="quota-form" method="post" action="{{ url_for('admin_storage_quota', user_id=item.id) }}"><input type="number" name="quota_mb" min="0" value="{{ item.quota_mb }}" required><span class="muted">MB</span><button class="button" type="submit">Save</button></form></td><td><form method="post" action="{{ url_for('admin_storage_permissions', user_id=item.id) }}"><label><input type="checkbox" name="allow_upload"{% if item.allow_upload %} checked{% endif %}> Upload</label><br><label><input type="checkbox" name="allow_download"{% if item.allow_download %} checked{% endif %}> Download</label><br><button class="button" type="submit">Save access</button></form></td></tr>{% else %}<tr><td colspan="7">No non-administrator users found.</td></tr>{% endfor %}</tbody></table></div></section></main></body></html>
"""


ADMIN_PERMISSIONS_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access control - Cloud Rdx</title>
<style>
:root{--ink:#14231e;--muted:#71817b;--line:#dfe9e2;--paper:#f4f8f5;--panel:#fff;--green:#18794e;--dark:#105437;--gold:#f2be58;--shadow:0 16px 40px rgba(25,64,45,.09)}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font-family:Arial,sans-serif}.shell{min-height:100vh;display:grid;grid-template-columns:230px 1fr}.rail{padding:28px 18px;color:#eaf8ef;background:var(--dark);display:flex;flex-direction:column}.brand{display:flex;align-items:center;gap:10px;color:#fff;text-decoration:none;font-weight:700}.brand-mark{width:34px;height:34px;display:grid;place-items:center;color:var(--dark);background:var(--gold);border-radius:10px 10px 10px 2px;font-weight:800}.rail-nav{margin-top:55px;display:grid;gap:7px}.rail-link{padding:11px 12px;color:#b9d7c3;text-decoration:none;border-radius:9px;font-size:13px}.rail-link:hover,.rail-link.active{color:#fff;background:#ffffff1c}.rail-bottom{margin-top:auto;padding:15px 12px;border-top:1px solid #ffffff26;color:#a9cbb6;font-size:11px;line-height:1.6}.main{padding:38px clamp(20px,5vw,70px);max-width:1500px}.topbar{display:flex;justify-content:space-between;gap:20px;align-items:start;margin-bottom:28px}.eyebrow{margin:0 0 9px;color:var(--green);text-transform:uppercase;letter-spacing:.14em;font-size:11px;font-weight:700}.topbar h1{margin:0 0 8px;font:500 clamp(30px,4vw,46px) Georgia,serif;letter-spacing:-.03em}.subtitle{margin:0;color:var(--muted);font-size:14px;line-height:1.6}.actions{display:flex;gap:9px;flex-wrap:wrap}.button{display:inline-block;padding:10px 14px;color:#fff;background:var(--green);border:0;border-radius:8px;cursor:pointer;text-decoration:none;font-weight:700;font-size:12px}.button.secondary{color:var(--green);background:#e4f1e8}.flash{padding:12px 15px;margin-bottom:18px;color:#72500d;background:#fff4d7;border:1px solid #f1d79a;border-radius:9px;font-size:13px}.intro{display:grid;grid-template-columns:1.4fr 1fr;gap:18px;margin-bottom:20px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:15px;box-shadow:var(--shadow);overflow:hidden}.intro-card{padding:22px}.intro-card h2{margin:0 0 8px;font:500 23px Georgia,serif}.intro-card p{margin:0;color:var(--muted);font-size:13px;line-height:1.6}.stat-list{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.stat{padding:16px;background:#f7fbf8;border:1px solid var(--line);border-radius:10px}.stat b{display:block;font-size:20px;color:var(--green)}.stat span{color:var(--muted);font-size:11px}.head{padding:21px 23px;border-bottom:1px solid var(--line)}.head h2{margin:0 0 5px;font:500 21px Georgia,serif}.head p{margin:0;color:var(--muted);font-size:13px}.role-create{display:grid;grid-template-columns:1fr 2fr auto;gap:10px;padding:20px 23px}.input{width:100%;padding:11px 12px;border:1px solid #cbd9cf;border-radius:8px;background:#fff;font:13px Arial}.roles{display:grid;gap:16px;padding:18px}.role-card{border:1px solid var(--line);border-radius:12px;overflow:hidden}.role-head{display:flex;justify-content:space-between;gap:12px;align-items:start;padding:17px 18px;background:#f8fbf9}.role-head h3{margin:0 0 4px;font-size:16px}.role-head p{margin:0;color:var(--muted);font-size:12px}.permission-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:9px;padding:17px 18px}.permission{display:flex;gap:9px;align-items:center;padding:10px;background:#f7faf8;border:1px solid #e4ede7;border-radius:8px;color:#35463e;font-size:12px}.permission input{accent-color:var(--green)}.role-save{padding:0 18px 17px;text-align:right}@media(max-width:800px){.shell{display:block}.rail{padding:18px}.rail-nav{margin-top:22px;display:flex;overflow:auto}.rail-link{white-space:nowrap}.main{padding:25px 16px}.topbar,.intro{display:block}.actions{margin-top:16px}.intro-card{margin-bottom:12px}.role-create{grid-template-columns:1fr}.role-save{text-align:left}}
</style></head><body><div class="shell"><aside class="rail"><a class="brand" href="{{ url_for('files') }}"><span class="brand-mark">C</span><span>Cloud Rdx</span></a><nav class="rail-nav"><a class="rail-link" href="{{ url_for('admin_panel') }}">Dashboard</a><a class="rail-link" href="{{ url_for('admin_manage') }}">Administration</a><a class="rail-link active" href="{{ url_for('admin_permissions') }}">Access control</a><a class="rail-link" href="{{ url_for('admin_security') }}">Security center</a><a class="rail-link" href="{{ url_for('logout') }}">Sign out</a></nav><div class="rail-bottom">Owner-only security controls<br>Every permission change is audited</div></aside><main class="main"><header class="topbar"><div><p class="eyebrow">Cloud Rdx / governance</p><h1>Access control</h1><p class="subtitle">Design delegated roles and apply least-privilege permissions from one focused workspace.</p></div><div class="actions"><a class="button secondary" href="{{ url_for('admin_manage') }}">Administration</a><a class="button" href="{{ url_for('admin_panel') }}">Dashboard</a></div></header>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}{% endwith %}<section class="intro"><div class="panel intro-card"><h2>Permission governance</h2><p>The owner is the only administrator. Delegated roles let other users perform specific tasks without granting full administrator access. Role changes are separate from account status and storage quota operations.</p></div><div class="stat-list"><div class="stat"><b>{{ roles|length }}</b><span>Delegated roles</span></div><div class="stat"><b>{{ permissions|length }}</b><span>Available permissions</span></div></div></section><section class="panel" style="margin-bottom:20px"><div class="head"><h2>Create a custom role</h2><p>Use a clear name and configure its permissions immediately after creation.</p></div><form class="role-create" method="post" action="{{ url_for('admin_role_create') }}"><input class="input" name="name" required maxlength="48" pattern="[A-Za-z0-9_-]+" placeholder="role_name"><input class="input" name="description" maxlength="160" placeholder="What can this role do?"><button class="button" type="submit">Create role</button></form></section><section class="panel"><div class="head"><h2>Delegated roles</h2><p>Each role is independent. Save only the permissions this role needs.</p></div><div class="roles">{% for role in roles %}<form class="role-card" method="post" action="{{ url_for('admin_role_permissions', role_id=role.id) }}"><div class="role-head"><div><h3>{{ role.name|replace('_',' ')|title }}</h3><p>{{ role.description or 'No description provided.' }}</p></div><span class="stat"><span>Role permissions</span></span></div><div class="permission-grid">{% for permission in permissions %}<label class="permission"><input type="checkbox" name="permissions" value="{{ permission.key }}"{% if permission.key in role.permissions %} checked{% endif %}> <span>{{ permission.label }}</span></label>{% endfor %}</div><div class="role-save"><button class="button" type="submit">Save permissions</button></div></form>{% else %}<div class="intro-card"><p>No delegated roles exist yet. Create one above to begin.</p></div>{% endfor %}</div></section></main></div></body></html>
"""


ADMIN_PAGE = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{ admin_title }} - Cloud Rdx</title>
<style>
:root{--ink:#16221f;--muted:#71817b;--line:#dfe8e2;--paper:#f7faf7;--panel:#fff;--green:#18794e;--dark:#105437;--gold:#f2be58;--red:#a34f3a;--shadow:0 18px 50px rgba(25,64,45,.08)}*{box-sizing:border-box}body{margin:0;color:var(--ink);background:var(--paper);font-family:Georgia,'Times New Roman',serif}.shell{min-height:100vh;display:grid;grid-template-columns:248px 1fr}.rail{padding:30px 22px;color:#eaf8ef;background:var(--dark);display:flex;flex-direction:column}.brand{display:flex;align-items:center;gap:12px;color:#fff;text-decoration:none;font-weight:700}.brand-mark{width:35px;height:35px;display:grid;place-items:center;color:var(--dark);background:var(--gold);border-radius:10px 10px 10px 2px;font:bold 16px Arial}.rail-nav{margin-top:70px;display:grid;gap:10px;font:14px Arial}.rail-link{display:flex;gap:12px;padding:12px 13px;color:#b9d7c3;text-decoration:none;border-radius:10px}.rail-link:hover,.rail-link.active{color:#fff;background:#ffffff1c}.rail-bottom{margin-top:auto;padding:17px 14px;border-top:1px solid #ffffff26;color:#a9cbb6;font:12px/1.6 Arial}.main{padding:36px clamp(22px,5vw,72px)}.topbar{display:flex;justify-content:space-between;gap:20px;align-items:start;margin-bottom:35px}.eyebrow{margin:0 0 10px;color:var(--green);text-transform:uppercase;letter-spacing:.16em;font:700 11px Arial}h1{margin:0 0 9px;font-size:clamp(30px,4vw,48px);font-weight:500;letter-spacing:-.03em}.subtitle{margin:0;color:var(--muted);font:14px Arial}.user-chip{display:flex;align-items:center;gap:10px;padding:8px 12px 8px 8px;background:#fff;border:1px solid var(--line);border-radius:999px;font:13px Arial}.avatar{display:grid;place-items:center;width:29px;height:29px;color:#fff;background:var(--green);border-radius:50%;font-weight:700}.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow);overflow:hidden}.panel-head{padding:23px;border-bottom:1px solid var(--line)}.panel-head h2{margin:0 0 6px;font-size:20px;font-weight:500}.panel-head p{margin:0;color:var(--muted);font:13px Arial}.flash{margin:0 0 20px;padding:12px 15px;color:#7a5311;background:#fff4d7;border:1px solid #f3db9d;border-radius:8px;font:13px Arial}.user-row{display:grid;grid-template-columns:minmax(120px,1fr) 145px 150px 270px;gap:18px;align-items:center;padding:17px 23px;border-bottom:1px solid #edf2ee;font-family:Arial}.user-row:last-child{border-bottom:0}.user-name{font-size:14px;font-weight:700}.user-name small{display:block;margin-top:5px;color:var(--muted);font-size:11px;font-weight:400}.status{font-size:12px;color:var(--green)}.status.stale{color:var(--red);font-weight:700}.user-form{display:flex;gap:7px}.user-form input{min-width:0;width:130px;padding:9px;border:1px solid var(--line);border-radius:7px;font:12px Arial}.button{padding:9px 11px;border:0;border-radius:7px;background:var(--green);color:#fff;cursor:pointer;font:bold 11px Arial}.button:hover{background:var(--dark)}.button.danger{background:#fff;color:var(--red);border:1px solid #e8c9c0}.button.danger:hover{background:#fff1ed}.empty{padding:50px;text-align:center;color:var(--muted);font:14px Arial}@media(max-width:900px){.shell{grid-template-columns:72px 1fr}.rail{padding:22px 13px}.brand span,.rail-link span:not(.rail-icon),.rail-bottom{display:none}.rail-nav{margin-top:45px}.rail-link{justify-content:center}.user-row{grid-template-columns:1fr 1fr}.user-form{grid-column:1/-1}}@media(max-width:620px){.main{padding:25px 15px}.topbar{flex-direction:column}.user-row{grid-template-columns:1fr}.user-form{grid-column:auto;flex-wrap:wrap}.user-form input{flex:1}.panel{border-radius:12px}}
</style></head><body><div class="shell"><aside class="rail"><a class="brand" href="{{ url_for('files') }}"><span class="brand-mark">C</span><span>Cloud Rdx</span></a><nav class="rail-nav"><a class="rail-link" href="{{ url_for('files') }}"><span class="rail-icon">[ ]</span><span>My storage</span></a><a class="rail-link active" href="{{ url_for('admin_panel') }}"><span class="rail-icon">#</span><span>{{ admin_title }}</span></a>{% if is_owner %}<a class="rail-link" href="{{ url_for('admin_settings') }}"><span class="rail-icon">⚙</span><span>Website &amp; security settings</span></a><a class="rail-link" href="{{ url_for('admin_security') }}"><span class="rail-icon">!</span><span>Security center</span></a><a class="rail-link" href="{{ url_for('admin_emergency') }}"><span class="rail-icon">!</span><span>Emergency controls</span></a>{% endif %}{% if can_manage_users %}<a class="rail-link" href="{{ url_for('admin_manage') }}"><span class="rail-icon">+</span><span>User administration</span></a>{% endif %}{% if can_manage_storage %}<a class="rail-link" href="{{ url_for('admin_storage') }}"><span class="rail-icon">$</span><span>Storage administration</span></a>{% endif %}{% if can_review_payments %}<a class="rail-link" href="{{ url_for('admin_payments') }}"><span class="rail-icon">₹</span><span>Payment administration</span></a>{% endif %}{% if can_view_audit %}<a class="rail-link" href="{{ url_for('admin_audit') }}"><span class="rail-icon">=</span><span>Audit administration</span></a>{% endif %}<a class="rail-link" href="{{ url_for('logout') }}"><span class="rail-icon">&lt;</span><span>Sign out</span></a></nav><div class="rail-bottom">{{ admin_role_label }}<br>Restricted permissions</div></aside><main class="main"><header class="topbar"><div><p class="eyebrow">Role-based administration</p><h1>{{ admin_title }}</h1><p class="subtitle">{{ admin_description }}</p></div><div class="user-chip"><span class="avatar">{{ username[0]|upper }}</span><span>{{ username }} · {{ admin_role_label }}</span></div></header>{% with messages = get_flashed_messages() %}{% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}{% endwith %}<section class="panel"><div class="panel-head"><h2>Accounts</h2><p>Inactive means no recorded activity for {{ inactive_days }} days. Only inactive non-admin accounts can be removed.</p></div>{% for item in users %}<div class="user-row"><div class="user-name">{{ item.username }}{% if item.is_admin %}<small>Administrator account</small>{% else %}<small>Joined {{ item.created_at|dateonly }}</small>{% endif %}</div><div class="status{% if item.inactive %} stale{% endif %}">{% if item.inactive %}Inactive{% else %}Active{% endif %}<small style="display:block;color:var(--muted);margin-top:4px">{{ item.last_seen|prettydate }}</small></div><div style="font:12px Arial;color:var(--muted)">{{ item.files }} files · {{ item.bytes|filesize }}</div>{% if not item.is_admin %}<div class="user-form"><form method="post" action="{{ url_for('admin_password', user_id=item.id) }}"><input name="password" type="password" minlength="8" placeholder="New password" required><button class="button" type="submit">Change password</button></form>{% if item.inactive %}<form method="post" action="{{ url_for('admin_delete_user', user_id=item.id) }}" onsubmit="return confirm('Remove this inactive user and all their files?')"><button class="button danger" type="submit">Remove user</button></form>{% endif %}</div>{% else %}<div style="font:12px Arial;color:var(--muted)">Protected account</div>{% endif %}</div>{% else %}<div class="empty">No accounts found.</div>{% endfor %}</section></main></div></body></html>
"""


ADMIN_PAGE = ADMIN_PAGE.replace(
    "{{ item.username }}",
    "<a href=\"{{ url_for('admin_user_files', user_id=item.id) }}\">{{ item.username }}</a> <a href=\"{{ url_for('admin_user_profile', user_id=item.id) }}\" style=\"font-size:10px\">[profile]</a>",
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<section class="panel"><div class="panel-head"><h2>Accounts</h2>',
    '<section class="admin-stat-grid"><article class="panel admin-stat"><span class="admin-stat-label">Total users</span><strong class="admin-stat-value">{{ dashboard.total_users }}</strong></article><article class="panel admin-stat success"><span class="admin-stat-label">Active users</span><strong class="admin-stat-value">{{ dashboard.active_users }}</strong></article><article class="panel admin-stat info"><span class="admin-stat-label">Files / storage</span><strong class="admin-stat-value">{{ dashboard.total_files }} / {{ dashboard.total_bytes|filesize }}</strong></article><article class="panel admin-stat warning"><span class="admin-stat-label">Security alerts</span><strong class="admin-stat-value">{{ dashboard.open_alerts }}</strong></article></section><section class="panel" style="margin-bottom:20px"><div class="panel-head"><h2>System health</h2><p>Live operational indicators from the application database and storage roots.</p></div><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;padding:18px;font:12px Arial"><div><b>API</b><br><span class="status">ONLINE</span></div><div><b>Database</b><br><span class="status">ONLINE</span></div><div><b>Storage</b><br><span class="status">{{ dashboard.total_bytes|filesize }} used</span></div><div><b>Failed logins / 24h</b><br><span class="status{% if dashboard.failed_logins %} stale{% endif %}">{{ dashboard.failed_logins }}</span></div><div><b>Emergency mode</b><br><span class="status{% if dashboard.read_only or dashboard.maintenance %} stale{% endif %}">{% if dashboard.read_only or dashboard.maintenance %}RESTRICTED{% else %}NORMAL{% endif %}</span></div></div></section><section class="panel"><div class="panel-head"><h2>Accounts</h2>',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<section class="admin-stat-grid">',
    """<section class="dashboard-welcome" data-dashboard-user="{{ session.get('user_id', 'admin') }}" aria-label="Admin dashboard shortcuts">
    <div class="dashboard-welcome-copy">
        <p class="dashboard-kicker">Your workspace at a glance</p>
        <h2>Welcome back, {{ username }}.</h2>
        <p>Choose a tool to jump straight into the work that needs your attention.</p>
    </div>
    <nav class="dashboard-quick-links" aria-label="Frequently used admin tools">
        {% if is_owner %}<a class="dashboard-quick-link security" href="{{ url_for('admin_security') }}"><span class="quick-icon" aria-hidden="true">!</span><span><strong>Security center</strong><small>Alerts and rate limits</small></span><span class="quick-arrow" aria-hidden="true">→</span></a>{% endif %}
        {% if can_manage_users %}<a class="dashboard-quick-link users" href="{{ url_for('admin_manage') }}"><span class="quick-icon" aria-hidden="true">+</span><span><strong>User administration</strong><small>Accounts and access</small></span><span class="quick-arrow" aria-hidden="true">→</span></a>{% endif %}
        {% if can_manage_storage %}<a class="dashboard-quick-link storage" href="{{ url_for('admin_storage') }}"><span class="quick-icon" aria-hidden="true">◇</span><span><strong>Storage quotas</strong><small>Usage and permissions</small></span><span class="quick-arrow" aria-hidden="true">→</span></a>{% endif %}
        {% if can_review_payments %}<a class="dashboard-quick-link payments" href="{{ url_for('admin_payments') }}"><span class="quick-icon" aria-hidden="true">₹</span><span><strong>Payments</strong><small>Review requests</small></span><span class="quick-arrow" aria-hidden="true">→</span></a>{% endif %}
        {% if can_view_audit %}<a class="dashboard-quick-link audit" href="{{ url_for('admin_audit') }}"><span class="quick-icon" aria-hidden="true">≡</span><span><strong>Audit activity</strong><small>Recent changes</small></span><span class="quick-arrow" aria-hidden="true">→</span></a>{% endif %}
    </nav>
    <div class="dashboard-personalize">
        <button class="dashboard-customize-button" id="dashboard-customize" type="button" aria-expanded="false" aria-controls="dashboard-preferences">Customize dashboard</button>
        <div class="dashboard-preferences" id="dashboard-preferences" hidden>
            <p>Show dashboard cards</p>
            <label><input type="checkbox" data-widget-toggle="users" checked> Total users</label>
            <label><input type="checkbox" data-widget-toggle="active-users" checked> Active users</label>
            <label><input type="checkbox" data-widget-toggle="storage" checked> Files and storage</label>
            <label><input type="checkbox" data-widget-toggle="alerts" checked> Security alerts</label>
            <label><input type="checkbox" data-widget-toggle="health" checked> System health</label>
            <button class="dashboard-reset-button" id="dashboard-reset" type="button">Reset to default</button>
            <span class="dashboard-preference-status" id="dashboard-preference-status" role="status" aria-live="polite"></span>
        </div>
    </div>
</section><section class="admin-stat-grid">""",
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<article class="panel admin-stat">',
    '<article class="panel admin-stat" data-dashboard-widget="users">',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<article class="panel admin-stat success">',
    '<article class="panel admin-stat success" data-dashboard-widget="active-users">',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<article class="panel admin-stat info">',
    '<article class="panel admin-stat info" data-dashboard-widget="storage">',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<article class="panel admin-stat warning">',
    '<article class="panel admin-stat warning" data-dashboard-widget="alerts">',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<section class="panel" style="margin-bottom:20px"><div class="panel-head"><h2>System health</h2>',
    '<section class="panel dashboard-health" data-dashboard-widget="health" style="margin-bottom:20px"><div class="panel-head"><h2>System health</h2>',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    "</body></html>",
    '<script src="{{ url_for(\'static\', filename=\'admin-dashboard.js\') }}" defer></script></body></html>',
    1,
)


ADMIN_SETTINGS_PAGE = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Website settings - Cloud Rdx</title><link rel="stylesheet" href="{{ url_for('static', filename='admin-theme.css') }}">
<style>
.settings-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,360px),1fr));gap:18px;max-width:1100px}.settings-card{overflow:hidden}.settings-form{padding:22px;display:grid;gap:16px}.setting-row{display:grid;gap:7px;font-size:14px;font-weight:700}.setting-row input[type=number]{max-width:220px;padding:10px 12px;border:1px solid #cbd9cf;border-radius:8px;font:14px Arial}.setting-help{margin:0;color:var(--admin-muted);font-size:12px;line-height:1.55}.setting-toggle{display:flex;gap:11px;align-items:flex-start;padding:13px;background:#f5faf6;border:1px solid var(--admin-line);border-radius:10px;font-size:13px;line-height:1.5}.setting-toggle input{width:18px;height:18px;margin:1px 0 0;accent-color:var(--admin-green)}.oauth-status{padding:11px 13px;border-radius:9px;background:#eef8f1;color:#185a37;font-size:13px;line-height:1.5}.oauth-status.offline{background:#fff4d7;color:#72500d}.settings-actions{display:flex;flex-wrap:wrap;gap:10px;align-items:center}.settings-actions .secondary{display:inline-block;padding:10px 13px;border-radius:8px;background:#e4f1e8;color:var(--admin-blue);font-size:12px;font-weight:700;text-decoration:none}.settings-full{grid-column:1/-1}
</style></head><body class="admin-theme"><main class="main">
<header class="topbar"><div><p class="eyebrow">System configuration</p><h1>Website settings</h1><p class="subtitle">Manage sign-up, Google and GitHub sign-in, login protection, sharing, and retention.</p></div><div class="settings-actions"><a class="button secondary" href="{{ url_for('admin_security') }}">Security reports</a><a class="button" href="{{ url_for('admin_panel') }}">Back to dashboard</a></div></header>
{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="flash" role="status">{{ message }}</div>{% endfor %}{% endwith %}
<form method="post"><div class="settings-grid">
<section class="panel settings-card"><div class="panel-head"><h2>Account access</h2><p>Choose which account creation and sharing options are available to site visitors.</p></div><div class="settings-form">
<label class="setting-toggle"><input type="checkbox" name="allow_registration"{% if settings.allow_registration %} checked{% endif %}><span><strong>Allow new account registration</strong><br><span class="setting-help">Controls password sign-up and whether new Google users can create accounts.</span></span></label>
<label class="setting-toggle"><input type="checkbox" name="allow_google_signin"{% if settings.allow_google_signin %} checked{% endif %}><span><strong>Allow Google sign-in</strong><br><span class="setting-help">When disabled, the Google login and sign-up buttons cannot start authentication. Existing linked accounts are not removed.</span></span></label>
<div class="oauth-status{% if not settings.google_oauth_configured %} offline{% endif %}"><strong>Google OAuth configuration:</strong> {% if settings.google_oauth_configured %}{% if settings.google_oauth_admin_managed %}Credentials are saved encrypted in admin settings.{% else %}Credentials are loaded from the server environment.{% endif %} The client secret is never displayed.{% else %}Credentials are not configured. Add them below or provide GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET in the server environment.{% endif %}</div>
<label class="setting-row" for="google-client-id">Google OAuth Client ID<input id="google-client-id" name="google_oauth_client_id" type="text" maxlength="512" autocomplete="off" placeholder="Leave blank to keep the current Client ID"><span class="setting-help">Current Client ID: {{ settings.google_oauth_client_id or 'not configured' }}. Client IDs are not secret.</span></label>
<label class="setting-row" for="google-client-secret">Google OAuth Client Secret<input id="google-client-secret" name="google_oauth_client_secret" type="password" maxlength="4096" autocomplete="new-password" placeholder="{% if settings.google_oauth_configured %}Saved; leave blank to keep current secret{% else %}Paste Google OAuth Client Secret{% endif %}"><span class="setting-help">Stored encrypted and never shown again. Requires a persistent FLASK_SECRET_KEY.</span></label>
<label class="setting-toggle"><input type="checkbox" name="clear_google_oauth_credentials"><span><strong>Remove admin-managed Google credentials</strong><br><span class="setting-help">Environment credentials, if present, remain active as a fallback.</span></span></label>
<label class="setting-toggle"><input type="checkbox" name="allow_github_signin"{% if settings.allow_github_signin %} checked{% endif %}><span><strong>Allow GitHub sign-in</strong><br><span class="setting-help">When disabled, GitHub login and sign-up cannot start authentication. Existing linked accounts are not removed.</span></span></label>
<div class="oauth-status{% if not settings.github_oauth_configured %} offline{% endif %}"><strong>GitHub OAuth configuration:</strong> {% if settings.github_oauth_configured %}{% if settings.github_oauth_admin_managed %}Credentials are saved encrypted in admin settings.{% else %}Credentials are loaded from the server environment.{% endif %} The client secret is never displayed.{% else %}Credentials are not configured. Add them below or provide GITHUB_OAUTH_CLIENT_ID and GITHUB_OAUTH_CLIENT_SECRET in the server environment.{% endif %}</div>
<label class="setting-row" for="github-client-id">GitHub OAuth Client ID<input id="github-client-id" name="github_oauth_client_id" type="text" maxlength="512" autocomplete="off" placeholder="Leave blank to keep the current Client ID"><span class="setting-help">Current Client ID: {{ settings.github_oauth_client_id or 'not configured' }}. Client IDs are not secret.</span></label>
<label class="setting-row" for="github-client-secret">GitHub OAuth Client Secret<input id="github-client-secret" name="github_oauth_client_secret" type="password" maxlength="4096" autocomplete="new-password" placeholder="{% if settings.github_oauth_configured %}Saved; leave blank to keep current secret{% else %}Paste GitHub OAuth App Client Secret{% endif %}"><span class="setting-help">Stored encrypted and never shown again. Requires a persistent FLASK_SECRET_KEY.</span></label>
<label class="setting-toggle"><input type="checkbox" name="clear_github_oauth_credentials"><span><strong>Remove admin-managed GitHub credentials</strong><br><span class="setting-help">Environment credentials, if present, remain active as a fallback.</span></span></label>
<label class="setting-toggle"><input type="checkbox" name="allow_public_sharing"{% if settings.allow_public_sharing %} checked{% endif %}><span><strong>Allow public sharing</strong><br><span class="setting-help">Enable or disable public file sharing across the site.</span></span></label>
<label class="setting-row" for="trash-retention">Recycle-bin retention (days)<input id="trash-retention" name="trash_retention_days" type="number" min="1" max="3650" value="{{ settings.trash_retention_days }}" required><span class="setting-help">Deleted files are automatically retained for this duration.</span></label>
</div></section>
<section class="panel settings-card"><div class="panel-head"><h2>Login protection</h2><p>Adjust when repeated failed passwords trigger progressively longer lockouts.</p></div><div class="settings-form">
<label class="setting-row" for="login-max-attempts">Failed attempts before lockout<input id="login-max-attempts" name="login_max_attempts" type="number" min="1" max="100" value="{{ settings.login_max_attempts }}" required><span class="setting-help">Applies per account and source address. Further retries return HTTP 429 with a Retry-After header.</span></label>
<label class="setting-row" for="login-window">Failure counting window (minutes)<input id="login-window" name="login_window_minutes" type="number" min="1" max="1440" value="{{ settings.login_window_minutes }}" required></label>
<label class="setting-row" for="login-lockout">Initial lockout duration (minutes)<input id="login-lockout" name="login_lockout_minutes" type="number" min="1" max="1440" value="{{ settings.login_lockout_minutes }}" required><span class="setting-help">Repeat lockouts increase progressively, up to eight times this duration.</span></label>
<div class="settings-actions"><button class="button" type="submit">Save website and security settings</button><a class="secondary" href="{{ url_for('admin_security') }}">Review security activity →</a></div>
</div></section></div></form></main></body></html>
"""


ADMIN_MANAGEMENT_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Administration - Cloud Rdx</title>
<style>body{margin:0;background:#f2f6f8;color:#17212b;font-family:Arial,sans-serif}.wrap{width:min(1180px,calc(100% - 32px));margin:32px auto}.top{display:flex;justify-content:space-between;gap:18px;align-items:start;margin-bottom:24px}.top a{color:#087f73;font-weight:700;text-decoration:none}.panel{margin-bottom:22px;overflow:hidden;background:#fff;border:1px solid #d8e1e8;border-radius:10px;box-shadow:0 12px 30px #19314214}.head{padding:19px 22px;border-bottom:1px solid #d8e1e8}.head h2{margin:0 0 5px;font-size:19px}.head p{margin:0;color:#647483;font-size:13px}.row{display:grid;grid-template-columns:1.2fr 1fr 1fr 1.5fr;gap:12px;align-items:center;padding:14px 22px;border-bottom:1px solid #edf1f3;font-size:13px}.row:last-child{border:0}.muted{color:#647483;font-size:12px}.form{display:flex;gap:7px;flex-wrap:wrap}.input{min-width:0;padding:8px;border:1px solid #cbd8e0;border-radius:6px}.button{padding:8px 10px;color:#fff;background:#087f73;border:0;border-radius:6px;cursor:pointer;font-weight:700}.danger{background:#a34f3a}.notice{padding:12px 15px;background:#fff4d7;border:1px solid #f3db9d;color:#7a5311;border-radius:7px;margin-bottom:18px}@media(max-width:800px){.row{grid-template-columns:1fr}.wrap{margin:22px auto}}</style></head><body><main class="wrap"><header class="top"><div><p class="muted">CLOUD RDX / ADMINISTRATION</p><h1>Control center</h1><p class="muted">Sensitive actions are audited. Deletes move data to recoverable trash first.</p></div><div><a href="{{ url_for('admin_panel') }}">→ ADMIN DASHBOARD</a><form method="post" action="{{ url_for('admin_backup') }}" style="margin-top:12px"><button class="button" type="submit">Create local backup</button></form></div></header>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="notice">{{ message }}</div>{% endfor %}{% endwith %}
<section class="panel"><div class="head"><h2>Accounts and lifecycle</h2><p>Manage account status and storage quotas here. The owner is the only administrator; delegated roles define exactly what other users can do.</p></div>{% for item in users %}<div class="row"><div><strong>{{ item.username }}</strong><div class="muted">{{ item.files }} files · {{ item.bytes|filesize }} used · {{ item.status }}</div></div><div class="muted">{% if item.is_admin %}Administrator{% elif item.roles %}{{ item.roles|join(', ') }}{% else %}Normal user{% endif %}</div><form class="form" method="post" action="{{ url_for('admin_user_status', user_id=item.id) }}"><input class="input" type="hidden" name="status" value="{{ 'suspended' if item.status == 'active' else 'active' }}"><button class="button{% if item.status == 'active' %} danger{% endif %}" type="submit">{{ 'Suspend' if item.status == 'active' else 'Activate' }}</button></form><form class="form" method="post" action="{{ url_for('admin_user_quota', user_id=item.id) }}"><input class="input" name="quota_mb" type="number" min="0" value="{{ item.quota_mb }}" placeholder="Quota MB"><button class="button" type="submit">Save quota</button></form>{% if is_owner and item.username|lower != owner_username|lower %}<form class="form" method="post" action="{{ url_for('admin_user_role', user_id=item.id) }}"><select class="input" name="role_name"><option value="__normal_user__"{% if not item.is_admin and not item.roles %} selected{% endif %}>Normal user - no delegated access</option>{% for role in roles %}<option value="{{ role.name }}" title="{{ role.description }}">{{ role.name|replace('_', ' ')|title }} - {{ role.description }}</option>{% endfor %}</select><button class="button" type="submit">Save role</button></form>{% elif item.username|lower == owner_username|lower %}<span class="muted">Protected owner account</span>{% else %}<span class="muted">Owner-managed role</span>{% endif %}</div>{% endfor %}</section>
<section class="panel"><div class="head"><h2>Groups</h2><p>Create teams and assign users explicitly.</p></div><div class="row"><form class="form" method="post" action="{{ url_for('admin_group_create') }}"><input class="input" name="name" required placeholder="Group name"><input class="input" name="description" placeholder="Description"><button class="button" type="submit">Create group</button></form></div>{% for group in groups %}<div class="row"><div><strong>{{ group.name }}</strong><div class="muted">{{ group.description }}</div></div><div class="muted">{{ group.members }} members</div><form class="form" method="post" action="{{ url_for('admin_group_member', group_id=group.id) }}"><select class="input" name="user_id" required>{% for item in users if item.status == 'active' %}<option value="{{ item.id }}">{{ item.username }}</option>{% endfor %}</select><button class="button" type="submit">Add member</button></form><span></span></div>{% endfor %}</section>
<section class="panel"><div class="head"><h2>Audit trail</h2><p>Recent administrative and security-sensitive activity.</p></div>{% for event in events %}<div class="row"><div><strong>{{ event.action }}</strong><div class="muted">{{ event.created_at|prettydate }}</div></div><div>{{ event.actor or 'System' }}</div><div>{{ event.target_type }} {{ event.target_id or '' }}</div><div class="muted">{{ event.details }}</div></div>{% else %}<div class="row">No events recorded yet.</div>{% endfor %}</section></main></body></html>
"""

# Keep Control Center focused on account status and delegated roles. Storage
# quotas and audit activity have dedicated admin pages.
ADMIN_MANAGEMENT_PAGE = re.sub(
    r'<section class="panel"><div class="head"><h2>Groups</h2>.*?</section>',
    '',
    ADMIN_MANAGEMENT_PAGE,
    flags=re.DOTALL,
)
ADMIN_MANAGEMENT_PAGE = ADMIN_MANAGEMENT_PAGE.replace(
    '<a href="{{ url_for(\'admin_panel\') }}">→ ADMIN DASHBOARD</a>',
    '<a href="{{ url_for(\'admin_panel\') }}">→ ADMIN DASHBOARD</a>{% if is_owner %} <a href="{{ url_for(\'admin_permissions\') }}">ACCESS CONTROL →</a>{% endif %}',
)
ADMIN_MANAGEMENT_PAGE = re.sub(
    r'<section class="panel"><div class="head"><h2>Audit trail</h2>.*?</section>',
    '',
    ADMIN_MANAGEMENT_PAGE,
    flags=re.DOTALL,
)
ADMIN_MANAGEMENT_PAGE = re.sub(
    r'<form class="form" method="post" action="{{ url_for\(\'admin_user_quota\'.*?</form>',
    '',
    ADMIN_MANAGEMENT_PAGE,
    flags=re.DOTALL,
)
ADMIN_MANAGEMENT_PAGE = re.sub(
    r'<form class="form" method="post" action="{{ url_for\(\'admin_user_status\'.*?</form>',
    '{% if not item.is_admin %}<form class="form" method="post" action="{{ url_for(\'admin_user_status\', user_id=item.id) }}"><input class="input" type="hidden" name="status" value="{{ \'suspended\' if item.status == \'active\' else \'active\' }}"><button class="button{% if item.status == \'active\' %} danger{% endif %}" type="submit">{{ \'Suspend\' if item.status == \'active\' else \'Activate\' }}</button></form>{% else %}<span class="muted">Administrator account protected</span>{% endif %}',
    ADMIN_MANAGEMENT_PAGE,
    flags=re.DOTALL,
)


ADMIN_AUDIT_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Audit activity - Cloud Rdx</title>
<style>body{margin:0;background:#f8f9fc;color:#3a3b45;font-family:Arial,sans-serif}.wrap{width:min(1180px,calc(100% - 36px));margin:28px auto}.top{display:flex;justify-content:space-between;align-items:start;margin-bottom:22px}.top a{color:#4e73df;font-weight:700;text-decoration:none}.card{background:#fff;border:1px solid #e3e6f0;border-radius:6px;box-shadow:0 .15rem 1.75rem #3a3b4515}.head{padding:20px 22px;border-bottom:1px solid #e3e6f0}.head h1{margin:0 0 6px;font-size:27px}.head p{margin:0;color:#858796;font-size:13px}.filters{display:flex;gap:8px;flex-wrap:wrap;padding:16px 22px;border-bottom:1px solid #e3e6f0}.filters input,.filters select{padding:9px;border:1px solid #d1d3e2;border-radius:4px}.filters button{padding:9px 14px;color:#fff;background:#4e73df;border:0;border-radius:4px;font-weight:700}.table-wrap{overflow:auto}table{width:100%;min-width:760px;border-collapse:collapse;font-size:13px}th{padding:12px;color:#6e707e;background:#f8f9fc;text-align:left;font-size:10px;text-transform:uppercase}td{padding:12px;border-top:1px solid #eaecf4;vertical-align:top}.muted{color:#858796;font-size:11px}.badge{display:inline-block;padding:4px 7px;border-radius:10px;font-size:10px;font-weight:700}.success{color:#0f684c;background:#d7f8ec}.denied{color:#8c2f27;background:#fbdcd9}@media(max-width:620px){.top{display:block}.top a{display:inline-block;margin-top:14px}}</style></head><body><main class="wrap"><header class="top"><div><p class="muted">CLOUD RDX / SECURITY</p><h1>Audit activity</h1><p class="muted">Review administrative actions, file activity, and security events.</p></div><a href="{{ url_for('admin_manage') }}">→ BACK TO CONTROLS</a></header><section class="card"><form class="filters" method="get"><input name="action" value="{{ filters.action }}" placeholder="Action"><input name="actor" value="{{ filters.actor }}" placeholder="Actor"><select name="status"><option value="">All statuses</option><option value="success"{% if filters.status == 'success' %} selected{% endif %}>Success</option><option value="denied"{% if filters.status == 'denied' %} selected{% endif %}>Denied</option></select><button type="submit">Filter activity</button></form><div class="table-wrap"><table><thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Target</th><th>Details</th><th>Status</th></tr></thead><tbody>{% for event in events %}<tr><td class="muted">{{ event.created_at|prettydate }}</td><td><strong>{{ event.action }}</strong></td><td>{{ event.actor or 'System' }}</td><td>{{ event.target_type }} {{ event.target_id or '' }}</td><td class="muted">{{ event.details }}</td><td><span class="badge {{ 'success' if event.status == 'success' else 'denied' }}">{{ event.status|upper }}</span></td></tr>{% else %}<tr><td colspan="6">No matching activity.</td></tr>{% endfor %}</tbody></table></div></section></main></body></html>
"""


ADMIN_AUDIT_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Audit activity - Cloud Rdx</title>
<style>body{margin:0;background:#f8f9fc;color:#3a3b45;font-family:Arial,sans-serif}.wrap{width:min(1180px,calc(100% - 36px));margin:28px auto}.top{display:flex;justify-content:space-between;align-items:start;margin-bottom:22px}.top a{color:#4e73df;font-weight:700;text-decoration:none}.card{background:#fff;border:1px solid #e3e6f0;border-radius:6px;box-shadow:0 .15rem 1.75rem #3a3b4515}.filters{display:flex;gap:8px;flex-wrap:wrap;padding:16px 22px;border-bottom:1px solid #e3e6f0}.filters input,.filters select{padding:9px;border:1px solid #d1d3e2;border-radius:4px}.filters button{padding:9px 14px;color:#fff;background:#4e73df;border:0;border-radius:4px;font-weight:700}.user-group{margin:18px 22px;border:1px solid #e3e6f0;border-radius:6px;overflow:hidden}.user-heading{padding:12px 15px;color:#224abe;background:#f0f4ff;font-weight:700}.table-wrap{overflow:auto}table{width:100%;min-width:700px;border-collapse:collapse;font-size:13px}th{padding:12px;color:#6e707e;background:#f8f9fc;text-align:left;font-size:10px;text-transform:uppercase}td{padding:12px;border-top:1px solid #eaecf4;vertical-align:top}.muted{color:#858796;font-size:11px}.badge{display:inline-block;padding:4px 7px;border-radius:10px;font-size:10px;font-weight:700}.success{color:#0f684c;background:#d7f8ec}.denied{color:#8c2f27;background:#fbdcd9}@media(max-width:620px){.top{display:block}.top a{display:inline-block;margin-top:14px}.user-group{margin-left:12px;margin-right:12px}}</style></head><body><main class="wrap"><header class="top"><div><p class="muted">CLOUD RDX / SECURITY</p><h1>Audit activity by username</h1><p class="muted">Review security and storage actions grouped by the account that performed them.</p></div><a href="{{ url_for('admin_manage') }}">→ BACK TO CONTROLS</a></header><section class="card"><form class="filters" method="get"><input name="action" value="{{ filters.action }}" placeholder="Action"><input name="actor" value="{{ filters.actor }}" placeholder="Username"><select name="status"><option value="">All statuses</option><option value="success"{% if filters.status == 'success' %} selected{% endif %}>Success</option><option value="denied"{% if filters.status == 'denied' %} selected{% endif %}>Denied</option></select><button type="submit">Filter activity</button></form>{% for group in audit_groups %}<section class="user-group"><div class="user-heading">Username: {{ group.username }} · {{ group.events|length }} event{% if group.events|length != 1 %}s{% endif %}</div><div class="table-wrap"><table><thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Details</th><th>Status</th></tr></thead><tbody>{% for event in group.events %}<tr><td class="muted">{{ event.created_at|prettydate }}</td><td><strong>{{ event.action }}</strong></td><td>{{ event.target_type }} {{ event.target_id or '' }}</td><td class="muted">{{ event.details }}</td><td><span class="badge {{ 'success' if event.status == 'success' else 'denied' }}">{{ event.status|upper }}</span></td></tr>{% endfor %}</tbody></table></div></section>{% else %}<p style="padding:22px">No matching activity.</p>{% endfor %}</section></main></body></html>
"""


ADMIN_TRASH_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Recycle bin - Cloud Rdx</title></head><body class="admin-theme"><div class="shell"><aside class="rail"><a class="brand" href="{{ url_for('admin_panel') }}"><span class="brand-mark">C</span><span>Cloud Rdx</span></a><nav class="rail-nav"><a class="rail-link" href="{{ url_for('admin_panel') }}"><span class="rail-icon">#</span><span>Dashboard</span></a><a class="rail-link" href="{{ url_for('admin_manage') }}"><span class="rail-icon">+</span><span>Controls</span></a><a class="rail-link active" href="{{ url_for('admin_trash') }}"><span class="rail-icon">~</span><span>Recycle bin</span></a><a class="rail-link" href="{{ url_for('admin_audit') }}"><span class="rail-icon">≡</span><span>Audit activity</span></a><a class="rail-link" href="{{ url_for('cloud_storage_guide') }}"><span class="rail-icon">?</span><span>Storage guide</span></a><a class="rail-link" href="{{ url_for('logout') }}"><span class="rail-icon">&lt;</span><span>Sign out</span></a></nav><div class="rail-bottom">Administrator console<br>Recoverable deletion enabled</div></aside><main class="main"><header class="topbar"><div><p class="eyebrow">Cloud Rdx / recovery</p><h1>Recycle bin</h1><p class="subtitle">Deleted items remain recoverable until an administrator restores them.</p></div><div class="user-chip"><span class="avatar">{{ username[0]|upper }}</span><span>{{ username }} · admin</span></div></header>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}{% endwith %}<section class="panel"><div class="panel-head"><h2>Recoverable items</h2><p>Permanent purge is intentionally unavailable until a separate audited workflow is implemented.</p></div><div class="table-responsive"><table><thead><tr><th>User</th><th>Item</th><th>Type</th><th>Original path</th><th>Deleted at</th><th>Action</th></tr></thead><tbody>{% for item in items %}<tr><td><strong>{{ item.username }}</strong></td><td>{{ item.item_name }}</td><td><span class="badge badge-info">{{ 'Folder' if item.is_dir else 'File' }}</span></td><td>{{ item.original_path }}</td><td class="muted">{{ item.deleted_at|prettydate }}</td><td><form method="post" action="{{ url_for('admin_restore_trash', trash_id=item.id) }}"><button class="button" type="submit">Restore</button></form></td></tr>{% else %}<tr><td colspan="6" class="muted">Recycle bin is empty.</td></tr>{% endfor %}</tbody></table></div></section></main></div></body></html>
"""


USER_TRASH_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Recycle bin - RDx Cloud Storage</title><style>body{margin:0;background:#f2f6f8;color:#17212b;font-family:'Segoe UI',Arial,sans-serif}.wrap{width:min(980px,calc(100% - 28px));margin:28px auto}.top{display:flex;justify-content:space-between;gap:18px;align-items:start;margin-bottom:22px}.top a{color:#087f73;font-weight:700;text-decoration:none}.panel{overflow:hidden;background:#fff;border:1px solid #d8e1e8;border-radius:10px;box-shadow:0 12px 30px #19314214}.head{padding:20px 22px;border-bottom:1px solid #d8e1e8}.head h1{margin:0 0 7px}.head p,.muted{color:#647483;font-size:13px}.table-wrap{overflow:auto}table{width:100%;min-width:680px;border-collapse:collapse}th{padding:12px 16px;background:#f7fafc;color:#647483;text-align:left;font-size:11px;text-transform:uppercase}td{padding:13px 16px;border-top:1px solid #e8eef2}.actions{display:flex;gap:7px;flex-wrap:wrap}button{min-height:38px;padding:8px 11px;color:#fff;background:#087f73;border:0;border-radius:6px;cursor:pointer;font-weight:700}button.danger{background:#a34f3a}.notice{margin-bottom:16px;padding:12px 14px;color:#7a5311;background:#fff4d7;border:1px solid #f3db9d;border-radius:7px}@media(max-width:620px){.top{display:block}.top a{display:inline-block;margin-top:14px}.head{padding:17px}}
</style></head><body><main class="wrap"><header class="top"><div><p class="muted">RDx CLOUD STORAGE / RECOVERY</p><h1>Recycle bin</h1><p class="muted">Deleted files stay here until you restore or permanently delete them.</p></div><a href="{{ url_for('files') }}">→ BACK TO STORAGE</a></header>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="notice">{{ message }}</div>{% endfor %}{% endwith %}<section class="panel"><div class="head"><h1>Your deleted items</h1><p>Only your deleted files and folders are shown.</p></div><div class="table-wrap"><table><thead><tr><th>Item</th><th>Type</th><th>Original location</th><th>Deleted</th><th>Actions</th></tr></thead><tbody>{% for item in items %}<tr><td>{{ item.item_name }}</td><td>{{ 'Folder' if item.is_dir else 'File' }}</td><td>{{ item.original_path }}</td><td>{{ item.deleted_at[:19].replace('T',' ') }}</td><td><div class="actions"><form method="post" action="{{ url_for('restore_user_trash', trash_id=item.id) }}"><button type="submit">Restore</button></form><form method="post" action="{{ url_for('purge_user_trash', trash_id=item.id) }}" onsubmit="return confirm('Permanently delete this item?')"><button class="danger" type="submit">Delete forever</button></form></div></td></tr>{% else %}<tr><td colspan="5" class="muted">Your recycle bin is empty.</td></tr>{% endfor %}</tbody></table></div></section></main></body></html>
"""


USER_TRASH_PAGE = apply_user_page_theme(USER_TRASH_PAGE)


# Recycle bin shows all users' deleted items and supports restore or permanent deletion.
ADMIN_TRASH_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Recycle bin - Cloud Rdx</title><style>body{margin:0;background:#f8f9fc;color:#3a3b45;font-family:Arial,sans-serif}.wrap{width:min(1180px,calc(100% - 32px));margin:32px auto}.top{display:flex;justify-content:space-between;align-items:start;gap:18px;margin-bottom:24px}.top a{color:#4e73df;font-weight:700;text-decoration:none}.panel{overflow:hidden;background:#fff;border:1px solid #e3e6f0;border-radius:8px;box-shadow:0 .15rem 1.2rem #3a3b4512}.head{padding:20px 22px;border-bottom:1px solid #e3e6f0}.head h1{margin:0 0 7px;font-size:28px}.head p{margin:0;color:#858796;font-size:13px}.notice{margin-bottom:18px;padding:12px 15px;color:#856404;background:#fff3cd;border:1px solid #ffeeba;border-radius:5px}.table-wrap{overflow-x:auto}table{width:100%;min-width:850px;border-collapse:collapse;font-size:13px}th{padding:13px 18px;color:#6e707e;background:#f8f9fc;text-align:left;font-size:11px;text-transform:uppercase}td{padding:15px 18px;border-top:1px solid #eaecf4;vertical-align:middle}.muted{color:#858796;font-size:12px}.button{padding:8px 11px;color:#fff;background:#4e73df;border:1px solid #4e73df;border-radius:4px;cursor:pointer;font-weight:700}.danger{background:#e74a3b;border-color:#e74a3b}.actions{display:flex;gap:7px;flex-wrap:wrap}@media(max-width:700px){.top{display:block}.top a{display:inline-block;margin-top:14px}}</style></head><body><main class="wrap"><header class="top"><div><p class="muted">CLOUD RDX / RECOVERY</p><h1>Recycle bin</h1><p class="muted">Deleted files and folders from every user. Restore items or permanently delete them.</p></div><a href="{{ url_for('admin_panel') }}">→ ADMIN DASHBOARD</a></header>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="notice">{{ message }}</div>{% endfor %}{% endwith %}<section class="panel"><div class="head"><h1>Deleted items by user</h1><p>Permanent deletion cannot be undone. Verify the user and path before acting.</p></div><div class="table-wrap"><table><thead><tr><th>User</th><th>Item</th><th>Type</th><th>Original path</th><th>Deleted at</th><th>Actions</th></tr></thead><tbody>{% for item in items %}<tr><td><strong>{{ item.username }}</strong><br><span class="muted">User ID {{ item.user_id }}</span></td><td>{{ item.item_name }}</td><td>{{ 'Folder' if item.is_dir else 'File' }}</td><td>{{ item.original_path }}</td><td>{{ item.deleted_at|prettydate }}</td><td><div class="actions"><form method="post" action="{{ url_for('admin_restore_trash', trash_id=item.id) }}"><button class="button" type="submit">Restore</button></form><form method="post" action="{{ url_for('admin_purge_trash', trash_id=item.id) }}" onsubmit="return confirm('Permanently delete this item? This cannot be undone.')"><button class="button danger" type="submit">Permanently delete</button></form></div></td></tr>{% else %}<tr><td colspan="6">No deleted items in the recycle bin.</td></tr>{% endfor %}</tbody></table></div></section></main></body></html>
"""


CLOUD_STORAGE_GUIDE_PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cloud storage guide - Cloud Rdx</title>
<style>
:root{--ink:#17212b;--muted:#647483;--line:#d8e1e8;--paper:#f2f6f8;--panel:#fff;--green:#087f73;--dark:#122b3a;--gold:#f0b44d;--mint:#e5f5f2}*{box-sizing:border-box}body{margin:0;color:var(--ink);background:var(--paper);font-family:'Segoe UI',Arial,sans-serif;background-image:linear-gradient(#d8e1e844 1px,transparent 1px),linear-gradient(90deg,#d8e1e844 1px,transparent 1px);background-size:32px 32px}.wrap{width:min(1120px,calc(100% - 32px));margin:32px auto 60px}.top{display:flex;justify-content:space-between;gap:24px;align-items:start;margin-bottom:25px}.brand{display:flex;align-items:center;gap:10px;color:var(--dark);font:700 13px Consolas,monospace}.mark{display:grid;place-items:center;width:38px;height:38px;color:var(--dark);background:var(--gold);border-radius:7px;font:800 16px Consolas,monospace}.back{color:var(--green);font:700 12px Consolas,monospace;text-decoration:none}.eyebrow{margin:27px 0 9px;color:var(--green);text-transform:uppercase;letter-spacing:.15em;font:700 11px Consolas,monospace}h1{margin:0;font-size:clamp(32px,5vw,56px);letter-spacing:-.04em;line-height:1.02}.lead{max-width:780px;color:var(--muted);font-size:17px;line-height:1.6}.panel{margin-top:18px;padding:25px 28px;background:rgba(255,255,255,.96);border:1px solid var(--line);border-radius:10px;box-shadow:0 12px 30px #19314214}h2{margin:0 0 12px;font-size:24px}h3{margin:20px 0 7px;color:var(--green);font-size:17px}p,li{line-height:1.6}li{margin:5px 0}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}.card{padding:17px;background:#f8fbfc;border:1px solid var(--line);border-radius:8px}.card h3{margin-top:0}.note{padding:14px 16px;background:var(--mint);border-left:4px solid var(--green);border-radius:5px}.flow{display:grid;grid-template-columns:repeat(5,1fr);gap:9px}.step{padding:14px 12px;background:var(--dark);color:#fff;border-radius:7px;font-size:13px}.step b{display:block;color:var(--gold);margin-bottom:7px}.table-wrap{overflow-x:auto}table{width:100%;min-width:760px;border-collapse:collapse;font-size:13px}th,td{padding:12px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}th{color:#fff;background:var(--dark)}tr:nth-child(even){background:#f8fbfc}.small{color:var(--muted);font-size:13px}@media(max-width:720px){.top{display:block}.back{display:inline-block;margin-top:18px}.grid{grid-template-columns:1fr}.flow{grid-template-columns:1fr}}
</style>
</head>
<body><main class="wrap"><header class="top"><div><div class="brand"><span class="mark">C</span><span>Cloud Rdx / learning center</span></div><p class="eyebrow">Beginner guide</p><h1>Understanding cloud storage</h1><p class="lead">Cloud storage lets you keep files on internet-connected servers instead of only on one computer. You can access those files from a browser, phone, or desktop app, as long as you have permission and an internet connection.</p></div><a class="back" href="{{ back_url }}">→ BACK TO STORAGE</a></header>
<section class="panel"><h2>1. What is cloud storage?</h2><p>Think of cloud storage as a secure online filing cabinet. A provider stores your data in data centers, while an application shows you folders and files. “Cloud” does not mean the files float in the air: they are stored on physical computers managed by the provider.</p><p>Compared with saving only to a laptop, cloud storage makes access, sharing, synchronization, backup, and recovery easier. The provider normally handles servers, disks, availability, and some security controls.</p></section>
<section class="panel"><h2>2. Main actions</h2><div class="grid"><div class="card"><h3>Upload and download</h3><p><b>Upload</b> sends a file from your device to online storage. <b>Download</b> copies it back to your device for viewing or offline use.</p></div><div class="card"><h3>Create, rename, move, and copy</h3><p>Folders organize files. Rename gives an item a clearer name. Move changes its folder. Copy creates another independent copy.</p></div><div class="card"><h3>Delete and restore</h3><p>Delete usually moves an item to a recycle bin first. Restore brings it back. Permanent deletion may be restricted or delayed by a retention policy.</p></div><div class="card"><h3>Share and collaborate</h3><p>Sharing grants selected people access through an account or link. Collaboration lets several people comment or edit, depending on their permission.</p></div><div class="card"><h3>Sync across devices</h3><p>A desktop or mobile app watches a folder and keeps approved changes aligned between devices. Conflicts can happen if two devices edit the same file at once.</p></div><div class="card"><h3>Backup and restore data</h3><p>Backup keeps a separate copy so data can be recovered after accidental deletion, device failure, or an attack. Restore returns a backup copy to active storage.</p></div></div></section>
<section class="panel"><h2>3. Common cloud-storage functions</h2><ul><li><b>File management:</b> folders, names, uploads, downloads, moves, copies, and deletion.</li><li><b>Data synchronization:</b> changes are shared between web, desktop, and mobile clients.</li><li><b>Data backup:</b> scheduled or manual copies protect against loss.</li><li><b>Sharing and collaboration:</b> links, invitations, comments, editing, and team folders.</li><li><b>Access control:</b> owners choose who can view, comment, edit, or administer content.</li><li><b>Version history:</b> earlier versions can be inspected or restored after an unwanted edit.</li><li><b>Search and organization:</b> names, types, owners, dates, labels, and full-text search help find files.</li><li><b>Encryption and security:</b> encryption, sign-in protection, audit logs, malware checks, and recovery controls protect data.</li></ul></section>
<section class="panel"><h2>4. User experience (UX)</h2><div class="grid"><div class="card"><h3>Upload and access</h3><p>A user opens the web app or desktop folder, chooses <b>Upload</b>, selects a file, and sees progress. After completion, the file appears in the chosen folder and can be opened, downloaded, or shared from another device.</p></div><div class="card"><h3>Organize folders</h3><p>Users create folders by project, year, or team. Breadcrumbs show where they are. Good names such as <i>Invoices / 2026 / March</i> are easier to search than names such as <i>New folder (7)</i>.</p></div><div class="card"><h3>Sharing and permissions</h3><p>The owner chooses people or a link, then selects a level such as viewer, commenter, or editor. A viewer cannot change content; an editor can. Sensitive links should expire or be revoked when no longer needed.</p></div><div class="card"><h3>Recovery</h3><p>Deleted files normally appear in a trash area. Version history lets a user compare or restore an earlier version. Retention periods differ by service and plan, so users should not treat trash as a permanent backup.</p></div><div class="card"><h3>Web, desktop, and mobile</h3><p><b>Web:</b> works from a browser without installation. <b>Desktop:</b> shows synced files in the normal file explorer and may support offline work. <b>Mobile:</b> provides previews, camera uploads, sharing, and offline favorites.</p></div><div class="card"><h3>What makes good UX?</h3><p>Clear progress, understandable permission labels, search, breadcrumbs, undo, visible storage limits, conflict warnings, and plain-language error messages reduce mistakes.</p></div></div></section>
<section class="panel"><h2>5. Real-world examples</h2><ul><li><b>Google Drive:</b> people create Docs, Sheets, or folders, share them as viewers/commenters/editors, and use Drive for web, desktop, and mobile access.</li><li><b>Microsoft OneDrive:</b> integrates with Windows and Microsoft 365. A file can be edited in Word, synchronized, shared, and recovered through version history or the recycle bin.</li><li><b>Dropbox:</b> focuses on synchronized folders, link sharing, collaboration, and file recovery features.</li><li><b>Amazon S3:</b> is primarily a developer and infrastructure service. Applications store objects in buckets using APIs, IAM permissions, lifecycle rules, versioning, and storage classes. It is not normally a consumer folder interface by itself.</li></ul></section>
<section class="panel"><h2>6. User-facing functions vs backend infrastructure</h2><div class="grid"><div class="card"><h3>User-facing</h3><p>These are the visible actions: upload, download, folders, search, sharing, comments, permissions, trash, version restore, and sync status. They answer: <i>“What can I do?”</i></p></div><div class="card"><h3>Backend/cloud infrastructure</h3><p>These are the systems underneath: object storage, databases, identity services, encryption-key management, replication, data-center networking, monitoring, billing, lifecycle tiers, APIs, and disaster recovery. They answer: <i>“How does the service operate reliably?”</i></p></div></div><p class="note"><b>Example:</b> “Download report.pdf” is user-facing. Behind it, the service authenticates the user, checks an access policy, locates replicated data, decrypts it when authorized, logs the event, and streams bytes over HTTPS.</p></section>
<section class="panel"><h2>7. Simple upload-to-download workflow</h2><div class="flow"><div class="step"><b>1 · Upload</b>The user selects a file. The client sends bytes securely.</div><div class="step"><b>2 · Store</b>The service checks size and permission, saves the file, and records metadata.</div><div class="step"><b>3 · Share</b>The owner invites a person or creates a restricted link.</div><div class="step"><b>4 · Edit</b>The recipient edits if allowed. Sync and version history record the change.</div><div class="step"><b>5 · Download</b>A permitted user requests the file; the service checks access and streams it.</div></div></section>
<section class="panel"><h2>8. Security features and best practices</h2><div class="grid"><div class="card"><h3>Common features</h3><ul><li>Encryption in transit with HTTPS and encryption at rest.</li><li>Strong passwords, multi-factor authentication, and single sign-on.</li><li>Role-based permissions and least privilege.</li><li>Share-link expiration, passwords, download limits, and revocation.</li><li>Version history, recycle bins, backups, retention policies, and audit logs.</li><li>Alerts for unusual downloads, sign-ins, or sharing.</li></ul></div><div class="card"><h3>Good habits</h3><ul><li>Use a unique password and enable MFA.</li><li>Share with named people instead of “anyone with the link” when possible.</li><li>Give viewer access unless editing is necessary.</li><li>Review shared links and remove old collaborators.</li><li>Keep important files backed up in a separate location.</li><li>Do not upload secrets or regulated data without checking policy.</li><li>Verify the recipient before sending confidential files.</li></ul></div></div></section>
<section class="panel"><h2>9. Quick reference table</h2><div class="table-wrap"><table><thead><tr><th>Action</th><th>Function</th><th>User experience</th><th>Example</th></tr></thead><tbody><tr><td>Upload</td><td>Send local data to storage</td><td>Choose a file and watch progress</td><td>Upload a travel receipt to Drive</td></tr><tr><td>Download</td><td>Copy stored data to a device</td><td>Click Download or mark offline</td><td>Download a report from OneDrive</td></tr><tr><td>Folder</td><td>Organize related files</td><td>Create a folder and use breadcrumbs</td><td>Dropbox / Projects / Website</td></tr><tr><td>Share</td><td>Grant controlled access</td><td>Invite a person and choose viewer/editor</td><td>Share a presentation for comments</td></tr><tr><td>Sync</td><td>Keep approved copies aligned</td><td>Edit on laptop and see the update on mobile</td><td>OneDrive Windows folder</td></tr><tr><td>Version/restore</td><td>Recover an earlier or deleted copy</td><td>Open history or recycle bin and restore</td><td>Recover yesterday’s spreadsheet</td></tr><tr><td>Backup</td><td>Keep a separate recovery copy</td><td>Run a schedule or snapshot</td><td>Archive application data to Amazon S3</td></tr></tbody></table></div></section>
<p class="small">Cloud storage behavior varies by provider, account plan, administrator policy, file type, and region. Always check the service’s current retention, sharing, and recovery rules.</p></main></body></html>
"""
ADMIN_PAGE = ADMIN_PAGE.replace(
    "Manage accounts without opening their private files.",
    "Manage accounts and inspect user files in read-only mode.",
).replace(
    "Only inactive non-admin accounts can be removed.",
    "Any account except the active administrator can be removed.",
).replace(
    "{% if not item.is_admin %}",
    "{% if item.id != current_user_id %}",
).replace(
    "{% if item.inactive %}<form method=\"post\" action=\"{{ url_for('admin_delete_user', user_id=item.id) }}\" onsubmit=\"return confirm('Remove this inactive user and all their files?')\"><button class=\"button danger\" type=\"submit\">Remove user</button></form>{% endif %}",
    "<form method=\"post\" action=\"{{ url_for('admin_delete_user', user_id=item.id) }}\" onsubmit=\"return confirm('Remove this user and all their files?')\"><button class=\"button danger\" type=\"submit\">Remove user</button></form>",
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<a class="rail-link active" href="{{ url_for(\'admin_panel\') }}"><span class="rail-icon">#</span><span>{{ admin_title }}</span></a>',
    '<a class="rail-link active" href="{{ url_for(\'admin_panel\') }}"><span class="rail-icon">#</span><span>{{ admin_title }}</span></a>{% if is_owner %}<a class="rail-link" href="{{ url_for(\'admin_intelligence\') }}"><span class="rail-icon">◌</span><span>Cloud Intelligence</span></a><a class="rail-link" href="{{ url_for(\'admin_profit\') }}"><span class="rail-icon">₹</span><span>Profit and usage</span></a>{% endif %}',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<a class="rail-link active" href="{{ url_for(\'admin_panel\') }}"><span class="rail-icon">#</span><span>Admin panel</span></a>',
    '<a class="rail-link active" href="{{ url_for(\'admin_panel\') }}"><span class="rail-icon">#</span><span>Admin panel</span></a>{% if is_owner %}<a class="rail-link" href="{{ url_for(\'admin_intelligence\') }}"><span class="rail-icon">◌</span><span>Cloud Intelligence</span></a><a class="rail-link" href="{{ url_for(\'admin_profit\') }}"><span class="rail-icon">₹</span><span>Profit and usage</span></a>{% endif %}<a class="rail-link" href="{{ url_for(\'admin_manage\') }}"><span class="rail-icon">+</span><span>Controls</span></a><a class="rail-link" href="{{ url_for(\'admin_permissions\') }}"><span class="rail-icon">*</span><span>Access control</span></a><a class="rail-link" href="{{ url_for(\'admin_storage\') }}"><span class="rail-icon">%</span><span>Storage quotas</span></a><a class="rail-link" href="{{ url_for(\'admin_payments\') }}"><span class="rail-icon">$</span><span>Payment verification</span></a><a class="rail-link" href="{{ url_for(\'admin_audit\') }}"><span class="rail-icon">≡</span><span>Audit activity</span></a><a class="rail-link" href="{{ url_for(\'admin_settings\') }}"><span class="rail-icon">⚙</span><span>Website settings</span></a><a class="rail-link" href="{{ url_for(\'admin_trash\') }}"><span class="rail-icon">~</span><span>Recycle bin</span></a><a class="rail-link" href="{{ url_for(\'cloud_storage_guide\') }}"><span class="rail-icon">?</span><span>Storage guide</span></a>',
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    "</style>",
    ".config-section{margin-top:24px}.config-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;padding:20px 23px}.config-card{display:flex;flex-direction:column;gap:9px;padding:18px;background:#f8fbf8;border:1px solid var(--line);border-left:4px solid var(--green);border-radius:10px}.config-card h3{margin:0;color:var(--ink);font:700 16px Arial,sans-serif}.config-card p{margin:0;color:var(--muted);font:13px/1.5 Arial,sans-serif}.config-card .help{display:inline-grid;place-items:center;width:19px;height:19px;margin-left:5px;color:#fff;background:var(--green);border-radius:50%;font:700 12px Arial;cursor:help}.config-card a{align-self:flex-start;margin-top:auto;padding:9px 12px;color:#fff;background:var(--green);border-radius:6px;font:700 11px Arial,sans-serif;text-decoration:none}.config-card a:hover{background:var(--dark)}@media(max-width:700px){.config-grid{grid-template-columns:1fr;padding:16px}.config-card a{min-height:40px;display:inline-flex;align-items:center}} </style>",
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<section class="panel" style="margin-top:24px"><div class="panel-head"><h2>Password recovery requests</h2>',
    '''<section class="panel config-section"><div class="panel-head"><h2>Administration configuration</h2><p>Each area is separated so changes are easier to understand, review, and audit. Hover or focus the <b title="Help">?</b> icon for guidance.</p></div><div class="config-grid"><article class="config-card"><h3>User accounts <span class="help" title="Activate, suspend, remove users, change passwords, and review account profiles.">?</span></h3><p>Manage account status, credentials, profiles, groups, and delegated roles.</p><a href="{{ url_for('admin_manage') }}">Open user management →</a></article><article class="config-card"><h3>Access control <span class="help" title="Choose which permissions each delegated role receives.">?</span></h3><p>Configure role permissions for user, storage, recovery, payment, and audit administration.</p><a href="{{ url_for('admin_permissions') }}">Configure permissions →</a></article><article class="config-card"><h3>Storage quotas <span class="help" title="Set storage limits in megabytes. Zero means unlimited.">?</span></h3><p>Review usage and customize each user’s allocated storage quota.</p><a href="{{ url_for('admin_storage') }}">Manage quotas →</a></article><article class="config-card"><h3>Payments and plans <span class="help" title="Approve or reject payment references before allocating storage.">?</span></h3><p>Review payment requests and apply storage-plan allocations.</p><a href="{{ url_for('admin_payments') }}">Review payments →</a></article><article class="config-card"><h3>Audit activity <span class="help" title="Audit records are read-only evidence of security and administration actions.">?</span></h3><p>Filter and review actions performed by administrators and users.</p><a href="{{ url_for('admin_audit') }}">View audit activity →</a></article><article class="config-card"><h3>Recycle bin <span class="help" title="Restore deleted items or permanently purge them after checking the original path.">?</span></h3><p>Recover or permanently remove deleted user files and folders.</p><a href="{{ url_for('admin_trash') }}">Open recycle bin →</a></article></div></section><section class="panel" style="margin-top:24px"><div class="panel-head"><h2>Password recovery requests</h2>''',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    "</section></main>",
    """{% if can_view_recovery %}<section class=\"panel\" style=\"margin-top:24px\"><div class=\"panel-head\"><h2>Password recovery requests</h2><p>Compare the request details with the registered account record before resetting.</p></div>{% for item in recovery_requests %}<div class=\"user-row\"><div class=\"user-name\">{{ item.username }}<small>{{ item.email }} · registered {{ item.account_email }}</small></div><div class=\"status\">{{ item.created_at|prettydate }}</div><div style=\"font:12px Arial;color:var(--muted)\">Request DOB: {{ item.date_of_birth }}<br>Account DOB: {{ item.account_dob }}<br>Request mobile: {{ item.mobile }}<br>Account mobile: {{ item.account_mobile }}</div><div class=\"user-form\"><form method=\"post\" action=\"{{ url_for('admin_reset_password', request_id=item.id) }}\"><button class=\"button\" type=\"submit\" onclick=\"return confirm('I verified the DOB and mobile number. Reset to the default password?')\">Verify & reset</button></form></div></div>{% else %}<div class=\"empty\">No pending recovery requests.</div>{% endfor %}</section>{% endif %}</main>""",
)
ADMIN_CONFIG_HUB = '''<section class="panel config-section"><div class="panel-head"><h2>Administration configuration</h2><p>Each area is separated so changes are easier to understand, review, and audit. Hover or focus a <b title="Help">?</b> icon for guidance.</p></div><div class="config-grid"><article class="config-card"><h3>User accounts <span class="help" title="Activate, suspend, remove users, change passwords, and review profiles.">?</span></h3><p>Manage account status, credentials, profiles, groups, and delegated roles.</p><a href="{{ url_for('admin_manage') }}">Open user management →</a></article><article class="config-card"><h3>Access control <span class="help" title="Choose permissions for delegated administrator roles.">?</span></h3><p>Configure role permissions for user, storage, recovery, payment, and audit administration.</p><a href="{{ url_for('admin_permissions') }}">Configure permissions →</a></article><article class="config-card"><h3>Storage quotas <span class="help" title="Set limits in megabytes. Zero means unlimited.">?</span></h3><p>Review usage and customize each user’s allocated storage quota.</p><a href="{{ url_for('admin_storage') }}">Manage quotas →</a></article><article class="config-card"><h3>Payments and plans <span class="help" title="Approve or reject payment references before allocating storage.">?</span></h3><p>Review payment requests and apply storage-plan allocations.</p><a href="{{ url_for('admin_payments') }}">Review payments →</a></article><article class="config-card"><h3>Audit activity <span class="help" title="Audit records are read-only evidence of administration activity.">?</span></h3><p>Filter and review actions performed by administrators and users.</p><a href="{{ url_for('admin_audit') }}">View audit activity →</a></article><article class="config-card"><h3>Recycle bin <span class="help" title="Restore deleted items or permanently purge them after checking the path.">?</span></h3><p>Recover or permanently remove deleted user files and folders.</p><a href="{{ url_for('admin_trash') }}">Open recycle bin →</a></article></div></section>'''
ADMIN_CONFIG_HUB = ADMIN_CONFIG_HUB.replace(
    '<article class="config-card"><h3>User accounts',
    '{% if can_manage_users %}<article class="config-card"><h3>User accounts',
).replace(
    '</a></article><article class="config-card"><h3>Access control',
    '</a></article>{% endif %}<article class="config-card"><h3>Access control',
).replace(
    '<article class="config-card"><h3>Access control',
    '{% if is_owner %}<article class="config-card"><h3>Access control',
).replace(
    '</a></article><article class="config-card"><h3>Storage quotas',
    '</a></article>{% endif %}<article class="config-card"><h3>Storage quotas',
).replace(
    '<article class="config-card"><h3>Storage quotas',
    '{% if can_manage_storage %}<article class="config-card"><h3>Storage quotas',
).replace(
    '</a></article><article class="config-card"><h3>Payments and plans',
    '</a></article>{% endif %}<article class="config-card"><h3>Payments and plans',
).replace(
    '<article class="config-card"><h3>Payments and plans',
    '{% if can_review_payments %}<article class="config-card"><h3>Payments and plans',
).replace(
    '</a></article><article class="config-card"><h3>Audit activity',
    '</a></article>{% endif %}<article class="config-card"><h3>Audit activity',
).replace(
    '<article class="config-card"><h3>Audit activity',
    '{% if can_view_audit %}<article class="config-card"><h3>Audit activity',
).replace(
    '</a></article><article class="config-card"><h3>Recycle bin',
    '</a></article>{% endif %}<article class="config-card"><h3>Recycle bin',
).replace(
    '<article class="config-card"><h3>Recycle bin',
    '{% if can_manage_storage %}<article class="config-card"><h3>Recycle bin',
).replace(
    '</a></article></div></section>',
    '</a></article>{% endif %}</div></section>',
)
ADMIN_CONFIG_HUB = ADMIN_CONFIG_HUB.replace(
    '</div></section>',
    '''{% if is_owner %}<article class="config-card"><h3>Website and security settings</h3><p>Control Google sign-in, new account registration, login lockout thresholds, and retention.</p><a href="{{ url_for('admin_settings') }}">Manage site settings →</a></article><article class="config-card"><h3>Security center</h3><p>Review open security alerts and aggregate rate-limit events without exposing client identifiers.</p><a href="{{ url_for('admin_security') }}">Review security activity →</a></article>{% endif %}</div></section>''',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<section class="panel" style="margin-top:24px"><div class="panel-head"><h2>Password recovery requests</h2>',
    ADMIN_CONFIG_HUB + '<section class="panel" style="margin-top:24px"><div class="panel-head"><h2>Password recovery requests</h2>',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<section class="panel"><div class="panel-head"><h2>Accounts</h2>',
    '{% if can_manage_users %}<section class="panel"><div class="panel-head"><h2>Accounts</h2>',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(ADMIN_CONFIG_HUB, '{% endif %}' + ADMIN_CONFIG_HUB, 1)
ADMIN_PAGE = ADMIN_PAGE.replace(
    "</style>",
    """.account-filter{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:16px 23px;border-bottom:1px solid var(--line);font:13px Arial}.account-filter select{padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:#fff;color:var(--ink)}.provider-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:0 0 18px}.provider-stat{padding:16px;border:1px solid var(--line);border-radius:12px;background:#fff;box-shadow:var(--shadow);font:13px Arial}.provider-stat strong{display:block;margin-top:7px;color:var(--green);font-size:22px}.user-row{grid-template-columns:minmax(120px,1fr) minmax(210px,1.3fr) 130px 145px minmax(230px,1fr)}.account-meta{display:flex;gap:10px;align-items:center;min-width:0;font:12px/1.5 Arial;color:var(--muted)}.account-meta img{width:38px;height:38px;flex:0 0 38px;border-radius:50%;object-fit:cover}.account-meta small{display:block;overflow-wrap:anywhere}.account-meta strong{color:var(--ink);font-size:12px}@media(max-width:900px){.provider-summary{grid-template-columns:repeat(2,minmax(0,1fr))}.user-row{grid-template-columns:repeat(2,minmax(0,1fr))}.account-meta,.user-form{grid-column:1/-1}}@media(max-width:620px){.user-row{grid-template-columns:1fr}.account-meta,.user-form{grid-column:auto}}@media(max-width:520px){.provider-summary{grid-template-columns:1fr}}</style>""",
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<section class="panel"><div class="panel-head"><h2>Accounts</h2>',
    """<section class="provider-summary" aria-label="Sign-in method report"><article class="provider-stat">Password sign-in<strong>{{ provider_counts.password }}</strong></article><article class="provider-stat">Google accounts<strong>{{ provider_counts.google }}</strong></article><article class="provider-stat">GitHub accounts<strong>{{ provider_counts.github }}</strong></article><article class="provider-stat">All accounts<strong>{{ provider_counts.all }}</strong></article></section><section class="panel"><div class="account-filter"><label for="account-type">Filter accounts by sign-in</label><select id="account-type" name="account_type" form="account-filter-form"><option value="all"{% if account_type == 'all' %} selected{% endif %}>All sign-in types</option><option value="password"{% if account_type == 'password' %} selected{% endif %}>Password</option><option value="google"{% if account_type == 'google' %} selected{% endif %}>Google</option><option value="github"{% if account_type == 'github' %} selected{% endif %}>GitHub</option></select><form id="account-filter-form" method="get"><button class="button" type="submit">Apply filter</button></form><a class="button" href="{{ url_for('admin_user_report', account_type=account_type) }}">Download CSV report</a></div><div class="panel-head"><h2>Accounts</h2>""",
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '</div><div class="status{% if item.inactive %} stale{% endif %}">',
    '''</div><div class="account-meta">{% if item.picture_url %}<img src="{{ item.picture_url }}" alt="" loading="lazy" referrerpolicy="no-referrer">{% endif %}<div><strong>{{ item.email or 'No email' }}</strong><small>Sign-in: {{ item.auth_methods|join(' + ') }}</small>{% if item.google_sub %}<small>Google · {{ item.google_username or item.google_profile_name or 'Account' }} · {{ item.google_email }}</small>{% endif %}{% if item.github_sub %}<small>GitHub · {{ item.github_username or item.github_profile_name or 'Account' }} · {{ item.github_email }}</small>{% endif %}</div></div><div class="status{% if item.inactive %} stale{% endif %}">''',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<form id="account-filter-form" method="get">',
    '<form id="account-filter-form" action="{{ url_for(\'admin_panel\') }}" method="get">',
    1,
)


ADMIN_ACCOUNT_FILTERS = {
    "all": "",
    "password": "WHERE password_login_enabled = 1",
    "google": "WHERE google_sub IS NOT NULL",
    "github": "WHERE github_sub IS NOT NULL",
}


def spreadsheet_safe_cell(value):
    text = "" if value is None else str(value)
    if text.lstrip(" \t\r\n")[:1] in ("=", "+", "-", "@"):
        return "'" + text
    return text


def admin_console_context():
    user = current_user()
    owner = bool(user and user["username"].lower() == ADMIN_USERNAME.lower())
    permissions = set()
    role_names = []
    if not owner and user:
        with database_connection() as connection:
            rows = connection.execute("""
                SELECT roles.name, roles.description, role_permissions.permission
                FROM user_roles
                JOIN roles ON roles.id = user_roles.role_id
                LEFT JOIN role_permissions ON role_permissions.role_id = roles.id
                WHERE user_roles.user_id = ? AND roles.name != ?
            """, (user["id"], ADMIN_ROLE)).fetchall()
        role_names = sorted({row["name"] for row in rows})
        permissions = {row["permission"] for row in rows if row["permission"]}
    if owner:
        role_label = "Owner administrator"
        title = "Owner administration"
        description = "Full system administration. Permission governance is owner-only."
    elif role_names:
        role_label = ", ".join(name.replace("_", " ").title() for name in role_names)
        title = f"{role_label} console"
        description = "This console contains only the functions granted to your delegated role."
    else:
        role_label = "Restricted administrator"
        title = "Restricted administration"
        description = "No delegated administration permissions are assigned to this account."
    return {
        "admin_title": title,
        "admin_role_label": role_label,
        "admin_description": description,
        "is_owner": owner,
        "has_admin_access": owner or bool(permissions),
        "can_manage_users": owner or "users.manage" in permissions,
        "can_manage_storage": owner or "storage.manage" in permissions,
        "can_review_payments": owner or "payments.review" in permissions,
        "can_view_audit": owner or "audit.view" in permissions,
        "can_view_recovery": owner or "users.recovery" in permissions,
    }


def format_size(value):
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


def generate_recovery_password():
    return "".join(secrets.SystemRandom().sample(RECOVERY_PASSWORD_CHARS, len(RECOVERY_PASSWORD_CHARS)))


def hash_password(password):
    """Create a salted, one-way Argon2id password hash."""
    return PASSWORD_HASHER.hash(password)


def verify_password(password_hash, password):
    """Verify Argon2id hashes and support one-time migration of old hashes."""
    try:
        PASSWORD_HASHER.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False
    except (InvalidHashError, VerificationError):
        # Existing installations may contain Werkzeug hashes. They are still
        # verified safely, then replaced with Argon2id after a successful login.
        return check_password_hash(password_hash, password)


def password_hash_needs_upgrade(password_hash):
    return not password_hash.startswith("$argon2")


app.jinja_env.filters["filesize"] = format_size


@app.template_filter("dateonly")
def date_only(value):
    return value[:10] if value else "Unknown"


@app.template_filter("prettydate")
def pretty_date(value):
    if not value:
        return "Never signed in"
    try:
        return datetime.fromisoformat(value).astimezone().strftime("Last seen %d %b %Y, %H:%M")
    except ValueError:
        return "Unknown activity"


def database_connection():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    with database_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_seen TEXT,
                is_admin INTEGER NOT NULL DEFAULT 0,
                full_name TEXT,
                email TEXT,
                mobile TEXT,
                date_of_birth TEXT,
                last_login_at TEXT,
                password_login_enabled INTEGER NOT NULL DEFAULT 1
            )
        """)
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
        if "last_seen" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN last_seen TEXT")
        if "is_admin" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        if "status" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
        if "suspended_at" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN suspended_at TEXT")
        for column in (
            "full_name", "email", "mobile", "date_of_birth", "google_sub",
            "google_email", "google_profile_name", "google_username",
            "google_picture", "github_email", "github_username", "github_picture",
            "github_profile_name", "gender", "location",
        ):
            if column not in columns:
                connection.execute(f"ALTER TABLE users ADD COLUMN {column} TEXT")
        if "password_login_enabled" not in columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN password_login_enabled "
                "INTEGER NOT NULL DEFAULT 1"
            )
        if "last_login_at" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN last_login_at TEXT")
        if "github_sub" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN github_sub TEXT")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub "
            "ON users(google_sub) WHERE google_sub IS NOT NULL"
        )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_github_sub "
            "ON users(github_sub) WHERE github_sub IS NOT NULL"
        )
        for column, definition in (("totp_secret", "TEXT"), ("totp_enabled", "INTEGER NOT NULL DEFAULT 0"), ("must_change_password", "INTEGER NOT NULL DEFAULT 0")):
            if column not in columns:
                connection.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS device_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token_hash TEXT NOT NULL UNIQUE,
                device_label TEXT NOT NULL DEFAULT 'Unknown device',
                ip_address TEXT,
                user_agent TEXT,
                created_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                revoked_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_device_sessions_user ON device_sessions(user_id, revoked_at)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS trusted_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_token_hash TEXT NOT NULL,
                device_label TEXT NOT NULL DEFAULT 'Unknown device',
                ip_address TEXT,
                user_agent TEXT,
                status TEXT NOT NULL CHECK(status IN ('pending', 'trusted', 'rejected')),
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                approved_at TEXT,
                approved_by INTEGER,
                UNIQUE(user_id, device_token_hash),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_trusted_devices_status "
            "ON trusted_devices(status, created_at DESC)"
        )
        connection.execute("""
            CREATE TABLE IF NOT EXISTS share_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                relative_path TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                last_accessed_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_share_links_user "
            "ON share_links(user_id, created_at DESC)"
        )
        connection.execute("""
            CREATE TABLE IF NOT EXISTS quarantined_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL UNIQUE,
                sha256 TEXT NOT NULL,
                detection TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'quarantined'
                    CHECK(status IN ('quarantined', 'released')),
                created_at TEXT NOT NULL,
                reviewed_at TEXT,
                reviewed_by INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_quarantined_files_status "
            "ON quarantined_files(status, created_at DESC)"
        )
        connection.execute("""
            CREATE TABLE IF NOT EXISTS sync_jobs (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                enabled INTEGER NOT NULL DEFAULT 0,
                interval_minutes INTEGER NOT NULL DEFAULT 60,
                next_run_at TEXT NOT NULL,
                last_run_at TEXT,
                updated_at TEXT NOT NULL,
                updated_by INTEGER,
                FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS sync_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                uploaded_count INTEGER NOT NULL DEFAULT 0,
                unchanged_count INTEGER NOT NULL DEFAULT 0,
                unstable_count INTEGER NOT NULL DEFAULT 0,
                summary TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (job_id) REFERENCES sync_jobs(id) ON DELETE CASCADE
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_sync_runs_started "
            "ON sync_runs(started_at DESC)"
        )
        connection.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT,
                attempted_at TEXT NOT NULL,
                success INTEGER NOT NULL DEFAULT 0
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_lookup ON login_attempts(username, ip_address, attempted_at)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS rate_limit_buckets (
                bucket_key TEXT PRIMARY KEY,
                endpoint TEXT NOT NULL,
                scope TEXT NOT NULL,
                window_started_at INTEGER NOT NULL,
                request_count INTEGER NOT NULL,
                blocked_count INTEGER NOT NULL DEFAULT 0
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_recent ON rate_limit_buckets(window_started_at, blocked_count)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                severity TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                username TEXT,
                ip_address TEXT,
                details TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                reviewed_by INTEGER,
                reviewed_at TEXT,
                FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_security_alerts_status ON security_alerts(status, created_at DESC)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS password_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                mobile TEXT NOT NULL,
                date_of_birth TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                reviewed_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT ''
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS user_roles (
                user_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                assigned_at TEXT NOT NULL,
                assigned_by INTEGER,
                PRIMARY KEY (user_id, role_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS role_permissions (
                role_id INTEGER NOT NULL,
                permission TEXT NOT NULL,
                assigned_at TEXT NOT NULL,
                assigned_by INTEGER,
                PRIMARY KEY (role_id, permission),
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                assigned_at TEXT NOT NULL,
                assigned_by INTEGER,
                PRIMARY KEY (group_id, user_id),
                FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS quotas (
                user_id INTEGER PRIMARY KEY,
                quota_bytes INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS storage_permissions (
                user_id INTEGER PRIMARY KEY,
                allow_upload INTEGER NOT NULL DEFAULT 1,
                allow_download INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL,
                updated_by INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            INSERT OR IGNORE INTO storage_permissions (user_id, allow_upload, allow_download, updated_at)
            SELECT id, 1, 1, ?
            FROM users
        """, (datetime.now(timezone.utc).isoformat(),))
        connection.execute("""
            CREATE TABLE IF NOT EXISTS storage_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                quota_bytes INTEGER NOT NULL,
                price_paise INTEGER NOT NULL DEFAULT 0,
                currency TEXT NOT NULL DEFAULT 'INR',
                billing_period TEXT NOT NULL DEFAULT 'monthly',
                provider_plan_id TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plan_id INTEGER NOT NULL,
                provider TEXT NOT NULL DEFAULT 'manual',
                provider_subscription_id TEXT UNIQUE,
                status TEXT NOT NULL DEFAULT 'pending',
                quota_bytes INTEGER NOT NULL,
                current_period_end TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (plan_id) REFERENCES storage_plans(id)
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS payment_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plan_id INTEGER NOT NULL,
                provider TEXT NOT NULL DEFAULT 'manual_qr',
                transaction_reference TEXT NOT NULL UNIQUE,
                amount_paise INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                proof_path TEXT,
                reviewed_by INTEGER,
                reviewed_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (plan_id) REFERENCES storage_plans(id),
                FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_payment_requests_status ON payment_requests(status, created_at)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON subscriptions(user_id, status)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS webhook_events (
                event_id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                processed_at TEXT NOT NULL
            )
        """)
        now = datetime.now(timezone.utc).isoformat()
        plans = (
            ("free", "Free Plan", 5 * 1024**3, 0),
            ("100gb", "100 GB Plan", 100 * 1024**3, 9900),
            ("500gb", "500 GB Plan", 500 * 1024**3, 19900),
            ("1tb", "1 TB Plan", 1024 * 1024**3, 39900),
        )
        for code, name, quota_bytes, price_paise in plans:
            connection.execute("""
                INSERT OR IGNORE INTO storage_plans
                (code, name, quota_bytes, price_paise, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (code, name, quota_bytes, price_paise, now, now))
        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT,
                details TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'success',
                created_at TEXT NOT NULL,
                FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        audit_columns = {row["name"] for row in connection.execute("PRAGMA table_info(audit_events)")}
        for column, definition in (("ip_address", "TEXT"), ("risk_level", "TEXT NOT NULL DEFAULT 'LOW'"), ("session_id", "TEXT")):
            if column not in audit_columns:
                connection.execute(f"ALTER TABLE audit_events ADD COLUMN {column} {definition}")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events(created_at DESC)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS trash_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                original_path TEXT NOT NULL,
                trash_path TEXT NOT NULL UNIQUE,
                item_name TEXT NOT NULL,
                is_dir INTEGER NOT NULL DEFAULT 0,
                deleted_by INTEGER,
                deleted_at TEXT NOT NULL,
                restored_at TEXT,
                purged_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (deleted_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS policy_acceptances (
                user_id INTEGER PRIMARY KEY,
                terms_accepted INTEGER NOT NULL DEFAULT 0,
                privacy_accepted INTEGER NOT NULL DEFAULT 0,
                cookies_accepted INTEGER NOT NULL DEFAULT 0,
                disclaimer_accepted INTEGER NOT NULL DEFAULT 0,
                accepted_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS policies (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by INTEGER,
                FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS emergency_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                affected_services TEXT NOT NULL DEFAULT '[]',
                previous_state TEXT NOT NULL,
                emergency_state TEXT NOT NULL,
                recovery_state TEXT,
                started_at TEXT NOT NULL,
                resolved_at TEXT,
                created_by INTEGER,
                resolved_by INTEGER,
                status TEXT NOT NULL DEFAULT 'active',
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (resolved_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS emergency_incident_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                admin_id INTEGER,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE CASCADE,
                FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS emergency_account_freezes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                group_id INTEGER,
                previous_status TEXT NOT NULL,
                freeze_batch_id TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                frozen_at TEXT NOT NULL,
                frozen_by INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE SET NULL,
                FOREIGN KEY (frozen_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_emergency_account_freezes_batch "
            "ON emergency_account_freezes(freeze_batch_id)"
        )
        connection.execute("""
            CREATE TABLE IF NOT EXISTS emergency_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER,
                incident_id INTEGER,
                ip_address TEXT,
                action TEXT NOT NULL,
                previous_state TEXT NOT NULL DEFAULT '{}',
                new_state TEXT NOT NULL DEFAULT '{}',
                reason TEXT NOT NULL DEFAULT '',
                affected_users INTEGER NOT NULL DEFAULT 0,
                affected_user_ids TEXT NOT NULL DEFAULT '[]',
                affected_services TEXT NOT NULL DEFAULT '[]',
                result TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE SET NULL
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_emergency_events_created "
            "ON emergency_events(created_at DESC)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_emergency_incidents_status "
            "ON emergency_incidents(status, started_at DESC)"
        )
        emergency_event_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(emergency_events)")
        }
        if "affected_user_ids" not in emergency_event_columns:
            connection.execute(
                "ALTER TABLE emergency_events ADD COLUMN affected_user_ids TEXT NOT NULL DEFAULT '[]'"
            )
        role_descriptions = {
            "system_admin": "Full administration with protected account safeguards.",
            "user_admin": "Manage user accounts and recovery requests.",
            "storage_admin": "Manage quotas and storage operations.",
            "auditor": "Read-only access to reports and audit events.",
        }
        for role_name, description in role_descriptions.items():
            connection.execute("INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)", (role_name, description))
        permission_defaults = {
            "user_admin": ("users.view", "users.manage", "users.recovery"),
            "storage_admin": ("storage.manage", "storage.recycle_bin", "payments.review"),
            "auditor": ("audit.view",),
        }
        for role_name, permissions in permission_defaults.items():
            role = connection.execute("SELECT id FROM roles WHERE name = ?", (role_name,)).fetchone()
            for permission in permissions:
                connection.execute("INSERT OR IGNORE INTO role_permissions (role_id, permission, assigned_at) VALUES (?, ?, ?)", (role["id"], permission, datetime.now(timezone.utc).isoformat()))
        connection.execute("UPDATE users SET is_admin = 0 WHERE username != ? COLLATE NOCASE", (ADMIN_USERNAME,))
        admin = connection.execute("SELECT id FROM users WHERE username = ? COLLATE NOCASE", (ADMIN_USERNAME,)).fetchone()
        if not admin:
            initial_password = ADMIN_PASSWORD or secrets.token_urlsafe(18)
            connection.execute("INSERT INTO users (username, password_hash, created_at, last_seen, is_admin, full_name, email, status) VALUES (?, ?, ?, ?, 1, ?, ?, 'active')", (ADMIN_USERNAME, hash_password(initial_password), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat(), "Cloud Rdx Administrator", ""))
            print(f"Initial administrator password: {initial_password}")
        else:
            connection.execute("UPDATE users SET is_admin = 1, status = 'active' WHERE id = ?", (admin["id"],))
        admin = connection.execute("SELECT id FROM users WHERE username = ? COLLATE NOCASE", (ADMIN_USERNAME,)).fetchone()
        system_role = connection.execute("SELECT id FROM roles WHERE name = ?", (ADMIN_ROLE,)).fetchone()
        connection.execute("INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_at) VALUES (?, ?, ?)", (admin["id"], system_role["id"], datetime.now(timezone.utc).isoformat()))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('allow_registration', '1', ?)", (datetime.now(timezone.utc).isoformat(),))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('allow_public_sharing', '0', ?)", (datetime.now(timezone.utc).isoformat(),))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('trash_retention_days', '30', ?)", (datetime.now(timezone.utc).isoformat(),))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('allow_google_signin', '1', ?)", (datetime.now(timezone.utc).isoformat(),))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('allow_github_signin', '1', ?)", (datetime.now(timezone.utc).isoformat(),))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('login_window_minutes', ?, ?)", (str(LOGIN_WINDOW_MINUTES), datetime.now(timezone.utc).isoformat()))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('login_max_attempts', ?, ?)", (str(LOGIN_MAX_ATTEMPTS), datetime.now(timezone.utc).isoformat()))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('login_lockout_minutes', ?, ?)", (str(LOGIN_LOCKOUT_MINUTES), datetime.now(timezone.utc).isoformat()))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('global_read_only', '0', ?)", (datetime.now(timezone.utc).isoformat(),))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('disable_uploads', '0', ?)", (datetime.now(timezone.utc).isoformat(),))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('disable_downloads', '0', ?)", (datetime.now(timezone.utc).isoformat(),))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('maintenance_mode', '0', ?)", (datetime.now(timezone.utc).isoformat(),))
        for control_name in EMERGENCY_CONTROL_LABELS:
            connection.execute(
                "INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES (?, '0', ?)",
                (control_name, datetime.now(timezone.utc).isoformat()),
            )
        connection.execute(
            """
            INSERT OR IGNORE INTO sync_jobs
                (id, enabled, interval_minutes, next_run_at, updated_at)
            VALUES (1, 0, 60, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )


initialize_database()


RATE_LIMIT_RULES = {
    "login": (("ip", 20, 900), ("account", 20, 900)),
    "google_auth": (("ip", 20, 900),),
    "github_auth": (("ip", 20, 900),),
    "login_2fa": (("ip", 10, 300), ("account", 5, 300), ("session", 5, 300)),
    "register": (("ip", 15, 3600), ("account", 3, 3600)),
    "forgot_password": (("ip", 10, 3600), ("account", 3, 3600)),
    "upload": (("ip", 100, 3600), ("session", 30, 3600)),
    "download": (("ip", 600, 900), ("session", 300, 900)),
    "bulk_download": (("ip", 40, 900), ("session", 10, 900)),
    "share_create": (("ip", 60, 3600), ("session", 20, 3600)),
    "public_share": (("ip", 300, 900),),
    "api": (("ip", 120, 300), ("session", 240, 300)),
    "admin": (("ip", 180, 300), ("session", 300, 300)),
}
RATE_LIMIT_DEFAULTS = (("ip", 600, 300), ("session", 900, 300))
RATE_LIMIT_HASH_KEY = app.secret_key.encode("utf-8") if isinstance(app.secret_key, str) else app.secret_key
_RATE_LIMIT_CLEANUP_LOCK = threading.Lock()
_RATE_LIMIT_LAST_CLEANUP = 0


def find_user(username):
    with database_connection() as connection:
        return connection.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with database_connection() as connection:
        return connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def request_ip():
    return (request.remote_addr or "unknown")[:64]


def rate_limit_identity(scope):
    if scope == "ip":
        return request_ip()
    if scope == "account":
        if request.endpoint == "login_2fa":
            return str(session.get("pending_2fa_user_id", "anonymous"))
        return request.form.get("username", "").strip().casefold()[:128] or "anonymous"
    if scope == "session":
        return session.get("device_token") or str(session.get("pending_2fa_user_id", "anonymous"))
    raise ValueError(f"Unsupported rate limit scope: {scope}")


def consume_rate_limit(endpoint, scope, identity, maximum, window_seconds):
    now = int(datetime.now(timezone.utc).timestamp())
    window_started_at = now - now % window_seconds
    bucket_value = f"{endpoint}\0{scope}\0{identity}\0{window_started_at}".encode("utf-8")
    bucket_key = hmac.new(RATE_LIMIT_HASH_KEY, bucket_value, hashlib.sha256).hexdigest()

    global _RATE_LIMIT_LAST_CLEANUP
    if now - _RATE_LIMIT_LAST_CLEANUP >= 3600:
        with _RATE_LIMIT_CLEANUP_LOCK:
            if now - _RATE_LIMIT_LAST_CLEANUP >= 3600:
                with database_connection() as connection:
                    connection.execute(
                        "DELETE FROM rate_limit_buckets WHERE window_started_at < ?",
                        (now - 86400,),
                    )
                _RATE_LIMIT_LAST_CLEANUP = now

    with database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT request_count, blocked_count FROM rate_limit_buckets WHERE bucket_key = ?",
            (bucket_key,),
        ).fetchone()
        request_count = (row["request_count"] if row else 0) + 1
        blocked_count = (row["blocked_count"] if row else 0) + int(request_count > maximum)
        connection.execute(
            """
            INSERT INTO rate_limit_buckets
                (bucket_key, endpoint, scope, window_started_at, request_count, blocked_count)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(bucket_key) DO UPDATE SET
                request_count = excluded.request_count,
                blocked_count = excluded.blocked_count
            """,
            (bucket_key, endpoint, scope, window_started_at, request_count, blocked_count),
        )
    return request_count <= maximum, max(1, window_seconds - (now - window_started_at)), bucket_key


def request_rate_limit():
    endpoint = request.endpoint or "unmatched"
    path = request.path
    if endpoint in {"login", "login_2fa", "register", "forgot_password"} and request.method != "POST":
        return None

    if endpoint in {"google_login_start", "google_callback"}:
        rule_name = "google_auth"
    elif endpoint in {"github_login_start", "github_callback"}:
        rule_name = "github_auth"
    elif endpoint in {"login", "login_2fa", "register", "forgot_password", "upload", "download", "bulk_download", "share_create", "public_share"}:
        rule_name = endpoint
    elif path.startswith("/api/"):
        rule_name = "api"
    elif path.startswith("/admin"):
        rule_name = "admin"
    else:
        rule_name = "default"

    policies = [
        (rule_name, policy)
        for policy in RATE_LIMIT_RULES.get(rule_name, RATE_LIMIT_DEFAULTS)
    ]
    if emergency_enabled("emergency_rate_limit"):
        policies = [
            (
                group,
                (scope, max(1, maximum // 4), window_seconds),
            )
            for group, (scope, maximum, window_seconds) in policies
        ]
    if rule_name != "default":
        policies.extend(("site", policy) for policy in RATE_LIMIT_DEFAULTS)

    retry_after = 0
    for bucket_group, (scope, maximum, window_seconds) in policies:
        identity = rate_limit_identity(scope)
        if scope == "session" and identity == "anonymous":
            continue
        allowed, retry, bucket_key = consume_rate_limit(
            bucket_group, scope, identity, maximum, window_seconds
        )
        if not allowed:
            retry_after = max(retry_after, retry)
            app.logger.warning(
                "rate_limit_exceeded endpoint=%s scope=%s bucket=%s",
                rule_name,
                scope,
                bucket_key[:16],
            )
            if scope == "ip":
                with database_connection() as connection:
                    bucket = connection.execute(
                        "SELECT blocked_count FROM rate_limit_buckets WHERE bucket_key = ?",
                        (bucket_key,),
                    ).fetchone()
                    if bucket and bucket["blocked_count"] >= 5:
                        create_security_alert(
                            connection,
                            "HIGH",
                            "request_rate_limit_burst",
                            None,
                            request_ip(),
                            f"At least {bucket['blocked_count']} requests were blocked "
                            f"for the {rule_name} limit within its active window.",
                            datetime.now(timezone.utc).isoformat(),
                        )

    if retry_after:
        return rate_limited_response(retry_after)
    return None


def rate_limited_response(retry_after):
    if request.is_json or request.path.startswith("/api/"):
        response = make_response(
            jsonify(
                error="too_many_requests",
                message="Too many requests. Please try again later.",
            ),
            429,
        )
    else:
        response = make_response(
            render_template_string(
                """<!doctype html><html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <title>Too Many Requests - Cloud Rdx</title>
                <style>body{margin:0;padding:12vh 24px;background:#f2f6f8;color:#17212b;font:16px Arial,sans-serif}
                main{max-width:560px;margin:auto;padding:36px;background:#fff;border:1px solid #d8e1e8;border-radius:8px}
                h1{margin-top:0}a{color:#087f73}</style></head><body><main><h1>Too many requests</h1>
                <p>Please wait a little while before trying again.</p><a href="{{ url_for('home') }}">Return to Cloud Rdx</a>
                </main></body></html>"""
            ),
            429,
        )
    response.headers["Retry-After"] = str(retry_after)
    response.headers["Cache-Control"] = "no-store"
    return response


def device_token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_security_alert(
    connection,
    severity,
    alert_type,
    username,
    ip_address,
    details,
    created_at,
    dedupe_minutes=15,
):
    dedupe_after = (
        datetime.fromisoformat(created_at)
        - timedelta(minutes=dedupe_minutes)
    ).isoformat()
    existing = connection.execute(
        """
        SELECT 1 FROM security_alerts
        WHERE alert_type = ? AND COALESCE(username, '') = COALESCE(?, '')
          AND COALESCE(ip_address, '') = COALESCE(?, '')
          AND status = 'open' AND created_at >= ?
        LIMIT 1
        """,
        (alert_type, username, ip_address, dedupe_after),
    ).fetchone()
    if existing:
        return False
    connection.execute(
        """
        INSERT INTO security_alerts
            (severity, alert_type, username, ip_address, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (severity, alert_type, username, ip_address, details[:1000], created_at),
    )
    return True


def record_login_attempt(username, success):
    attempted_at = datetime.now(timezone.utc).isoformat()
    settings = login_security_settings()
    with database_connection() as connection:
        connection.execute(
            "INSERT INTO login_attempts (username, ip_address, attempted_at, success) VALUES (?, ?, ?, ?)",
            (username[:128], request_ip(), attempted_at, int(success)),
        )
        if not success:
            cutoff = (
                datetime.now(timezone.utc)
                - timedelta(minutes=settings["login_window_minutes"])
            ).isoformat()
            failures = connection.execute(
                "SELECT COUNT(*) AS count FROM login_attempts WHERE username = ? COLLATE NOCASE AND ip_address = ? AND success = 0 AND attempted_at >= ?",
                (username[:128], request_ip(), cutoff),
            ).fetchone()["count"]
            if failures >= settings["login_max_attempts"]:
                create_security_alert(
                    connection,
                    "HIGH",
                    "brute_force_threshold",
                    username[:128],
                    request_ip(),
                    f"{failures} failed login attempts in "
                    f"{settings['login_window_minutes']} minutes",
                    attempted_at,
                )


def login_lockout_remaining(username):
    now = datetime.now(timezone.utc)
    settings = login_security_settings()
    history_cutoff = (now - timedelta(hours=24)).isoformat()
    with database_connection() as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS failures, MAX(attempted_at) AS latest_failure
            FROM login_attempts AS failures
            WHERE username = ? COLLATE NOCASE AND ip_address = ?
              AND success = 0 AND attempted_at >= ?
              AND attempted_at > COALESCE(
                  (SELECT MAX(successes.attempted_at)
                   FROM login_attempts AS successes
                   WHERE successes.username = failures.username COLLATE NOCASE
                     AND successes.ip_address = failures.ip_address
                     AND successes.success = 1
                     AND successes.attempted_at >= ?),
                  ?
              )
            """,
            (
                username[:128],
                request_ip(),
                history_cutoff,
                history_cutoff,
                history_cutoff,
            ),
        ).fetchone()
    attempt_threshold = settings["login_max_attempts"]
    consecutive_failures = int(row["failures"] or 0) if row else 0
    if consecutive_failures < attempt_threshold or not row["latest_failure"]:
        return 0
    try:
        latest_failure = datetime.fromisoformat(row["latest_failure"])
    except ValueError:
        return max(1, settings["login_lockout_minutes"] * 60)
    if latest_failure.tzinfo is None:
        latest_failure = latest_failure.replace(tzinfo=timezone.utc)
    escalation = max(0, (consecutive_failures - attempt_threshold) // attempt_threshold)
    duration_multiplier = min(8, 2**escalation)
    lockout_ends = latest_failure + timedelta(
        minutes=settings["login_lockout_minutes"] * duration_multiplier
    )
    return max(0, int((lockout_ends - now).total_seconds()))


def create_device_session(user_id):
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc).isoformat()
    user_agent = request.headers.get("User-Agent", "")[:300]
    label = (user_agent.split(" ", 1)[0] if user_agent else "Unknown device")[:80]
    with database_connection() as connection:
        connection.execute(
            "INSERT INTO device_sessions (user_id, session_token_hash, device_label, ip_address, user_agent, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, device_token_hash(token), label, request_ip(), user_agent, now, now),
        )
    return token


TRUSTED_DEVICE_COOKIE = "cloud_rdx_device"


def trusted_browser_device(user_id):
    device_token = request.cookies.get(TRUSTED_DEVICE_COOKIE, "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", device_token):
        device_token = secrets.token_urlsafe(32)
        existing = None
    else:
        with database_connection() as connection:
            existing = connection.execute(
                """
                SELECT id, status FROM trusted_devices
                WHERE user_id = ? AND device_token_hash = ?
                """,
                (user_id, device_token_hash(device_token)),
            ).fetchone()

    now = datetime.now(timezone.utc).isoformat()
    label = (
        request.headers.get("User-Agent", "").split(" ", 1)[0]
        or "Unknown device"
    )[:80]
    enforcing = emergency_enabled("block_new_devices")
    allowed = bool(existing and existing["status"] == "trusted")
    if not enforcing:
        allowed = True
    blocked = enforcing and not allowed
    with database_connection() as connection:
        if blocked:
            if not existing or existing["status"] != "rejected":
                connection.execute(
                    """
                    INSERT INTO trusted_devices
                        (user_id, device_token_hash, device_label, ip_address,
                         user_agent, status, created_at, last_seen_at)
                    VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
                    ON CONFLICT(user_id, device_token_hash) DO UPDATE SET
                        last_seen_at = excluded.last_seen_at,
                        ip_address = excluded.ip_address,
                        user_agent = excluded.user_agent
                    """,
                    (
                        user_id, device_token_hash(device_token), label,
                        request_ip(), request.headers.get("User-Agent", "")[:300],
                        now, now,
                    ),
                )
        elif enforcing:
            connection.execute(
                """
                UPDATE trusted_devices SET last_seen_at = ?, ip_address = ?
                WHERE id = ? AND user_id = ? AND status = 'trusted'
                """,
                (now, request_ip(), existing["id"], user_id),
            )
        elif not enforcing:
            connection.execute(
                """
                INSERT INTO trusted_devices
                    (user_id, device_token_hash, device_label, ip_address,
                     user_agent, status, created_at, last_seen_at, approved_at,
                     approved_by)
                VALUES (?, ?, ?, ?, ?, 'trusted', ?, ?, ?, ?)
                ON CONFLICT(user_id, device_token_hash) DO UPDATE SET
                    device_label = excluded.device_label,
                    ip_address = excluded.ip_address,
                    user_agent = excluded.user_agent,
                    status = 'trusted',
                    last_seen_at = excluded.last_seen_at,
                    approved_at = COALESCE(trusted_devices.approved_at, excluded.approved_at),
                    approved_by = COALESCE(trusted_devices.approved_by, excluded.approved_by)
                """,
                (
                    user_id, device_token_hash(device_token), label,
                    request_ip(), request.headers.get("User-Agent", "")[:300],
                    now, now, now, user_id,
                ),
            )
    if blocked:
        audit_event(
            "trusted_device_signin_blocked",
            "trusted_device",
            user_id,
            "Unapproved device attempted sign-in",
            status="denied",
            risk_level="HIGH",
            actor_id=None,
        )
    return device_token, allowed


def set_trusted_device_cookie(response, token):
    response.set_cookie(
        TRUSTED_DEVICE_COOKIE,
        token,
        max_age=60 * 60 * 24 * 365,
        httponly=True,
        secure=request.is_secure or app.config.get("SESSION_COOKIE_SECURE", False),
        samesite="Lax",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def trusted_device_login_denied(token):
    response = make_response(
        render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=github_signin_enabled(),
            github_oauth_configured=oauth_credentials_configured("github"),
            error=(
                "This device is not approved. An administrator must approve it "
                "before you can sign in."
            ),
        ),
        403,
    )
    return set_trusted_device_cookie(response, token)


def device_session_is_valid(user_id, token):
    if not token:
        return False
    with database_connection() as connection:
        row = connection.execute(
            "SELECT id FROM device_sessions WHERE user_id = ? AND session_token_hash = ? AND revoked_at IS NULL",
            (user_id, device_token_hash(token)),
        ).fetchone()
        if row:
            connection.execute("UPDATE device_sessions SET last_seen = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), row["id"]))
    return bool(row)


def is_admin():
    user = current_user()
    # The configured owner is the only account allowed to be an administrator.
    return bool(user and user["username"].lower() == ADMIN_USERNAME.lower())


def is_owner():
    user = current_user()
    return bool(user and user["username"].lower() == ADMIN_USERNAME.lower())


def require_owner():
    response = require_login()
    if response:
        return response
    if not is_owner():
        abort(403, "Only the server owner can manage administrator roles and permissions")
    return None


def user_folder():
    user = current_user()
    if not user:
        raise ValueError("Not authenticated")
    folder = SHARED_FOLDER / "users" / str(user["id"])
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def logged_in():
    return current_user() is not None


def safe_path(subpath=""):
    base = user_folder()
    target = (base / subpath).resolve()
    try:
        target.relative_to(base)
    except ValueError as exc:
        raise ValueError("Invalid path") from exc
    return target


def breadcrumbs(subpath):
    parts = [part for part in Path(subpath).parts if part not in (".", "")]
    result = []
    for index, name in enumerate(parts):
        path = "/".join(parts[: index + 1])
        result.append({"name": name, "url": url_for("files", subpath=path)})
    return result


def require_login():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if not device_session_is_valid(user["id"], session.get("device_token")):
        session.clear()
        flash("Your security session is no longer valid. Please sign in again.")
        return redirect(url_for("login"))
    if user["status"] != "active":
        session.clear()
        flash("This account is suspended. Contact an administrator.")
        return redirect(url_for("login"))
    last_seen = session.get("last_seen")
    now = datetime.now(timezone.utc)
    if last_seen:
        try:
            expired = now - datetime.fromisoformat(last_seen) > timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        except ValueError:
            expired = True
        if expired:
            session.clear()
            flash("Your session expired after being inactive.")
            return redirect(url_for("login"))
    timestamp = now.isoformat()
    session["last_seen"] = timestamp
    with database_connection() as connection:
        connection.execute("UPDATE users SET last_seen = ? WHERE id = ?", (timestamp, session["user_id"]))
    return None


def require_admin():
    response = require_login()
    if response:
        return response
    if not is_admin():
        abort(403)
    return None


def require_totp_available():
    if pyotp is None:
        abort(503, "Authenticator support is not installed")


def has_permission(permission):
    user = current_user()
    if not user:
        return False
    if user["username"].lower() == ADMIN_USERNAME.lower():
        return True
    with database_connection() as connection:
        row = connection.execute("""
            SELECT 1 FROM user_roles
            JOIN roles ON roles.id = user_roles.role_id
            JOIN role_permissions ON role_permissions.role_id = roles.id
            WHERE user_roles.user_id = ? AND role_permissions.permission = ?
            LIMIT 1
        """, (user["id"], permission)).fetchone()
    return bool(row)


def has_admin_access():
    return is_admin() or any(has_permission(permission) for permission in ("users.view", "users.manage", "storage.manage", "audit.view", "payments.review"))


def require_permission(permission):
    response = require_login()
    if response:
        return response
    if not has_permission(permission):
        abort(403, f"Missing administrator permission: {permission}")
    return None


def require_admin_access():
    response = require_login()
    if response:
        return response
    if not has_admin_access():
        abort(403)
    return None


def require_storage_user():
    response = require_login()
    if response:
        return response
    if has_admin_access():
        return redirect(url_for("admin_panel"))
    return None


def storage_permission(user_id, permission):
    if permission not in {"upload", "download"}:
        raise ValueError("Unsupported storage permission")
    with database_connection() as connection:
        row = connection.execute(
            "SELECT allow_upload, allow_download FROM storage_permissions WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    return not row or bool(row["allow_upload" if permission == "upload" else "allow_download"])


def require_storage_permission(permission):
    response = require_storage_user()
    if response:
        return response
    user = current_user()
    if not storage_permission(user["id"], permission):
        audit_event(f"{permission}_denied", "storage", user["id"], "permission disabled", status="denied")
        abort(403, f"Storage {permission} access is disabled for this account")
    require_storage_operation(permission)
    return None


def emergency_enabled(name):
    return policy_enabled(name, False)


def require_storage_operation(operation):
    read_only = emergency_enabled("global_read_only")
    blocked = False
    if operation == "upload":
        blocked = read_only or emergency_enabled("disable_uploads")
    elif operation in {"write", "edit"}:
        blocked = read_only or emergency_enabled("disable_editing")
    elif operation == "delete":
        blocked = read_only or emergency_enabled("disable_deletion")
    elif operation == "share":
        blocked = read_only or emergency_enabled("disable_file_sharing")
    elif operation == "download":
        blocked = emergency_enabled("disable_downloads")
    else:
        raise ValueError("Unsupported storage operation")
    if blocked:
        audit_event(
            f"emergency_{operation}_blocked",
            "storage",
            session.get("user_id"),
            "Emergency control blocked the operation",
            status="denied",
            risk_level="HIGH",
        )
        abort(503, f"Storage {operation} is temporarily disabled by the administrator")


def emergency_control_state(connection=None):
    if connection is None:
        with database_connection() as db:
            return emergency_control_state(db)
    rows = connection.execute(
        "SELECT name, value FROM policies WHERE name IN ({})".format(
            ",".join("?" for _ in EMERGENCY_CONTROL_LABELS)
        ),
        tuple(EMERGENCY_CONTROL_LABELS),
    ).fetchall()
    values = {row["name"]: row["value"] for row in rows}
    return {
        name: str(values.get(name, "0")).lower() in {"1", "true", "yes", "on"}
        for name in EMERGENCY_CONTROL_LABELS
    }


def write_emergency_event(
    connection,
    action,
    previous_state,
    new_state,
    reason="",
    affected_users=0,
    affected_user_ids=(),
    affected_services=(),
    result="success",
    incident_id=None,
):
    actor_id = session.get("user_id")
    now = datetime.now(timezone.utc).isoformat()
    previous_json = json.dumps(previous_state, sort_keys=True)
    new_json = json.dumps(new_state, sort_keys=True)
    user_ids_json = json.dumps(list(affected_user_ids)[:10000])
    services_json = json.dumps(list(affected_services))
    connection.execute(
        """
        INSERT INTO emergency_events
            (admin_id, incident_id, ip_address, action, previous_state, new_state,
             reason, affected_users, affected_user_ids, affected_services, result,
             created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            actor_id,
            incident_id,
            request_ip(),
            action[:120],
            previous_json,
            new_json,
            reason[:2000],
            max(0, int(affected_users)),
            user_ids_json,
            services_json,
            result[:40],
            now,
        ),
    )
    connection.execute(
        """
        INSERT INTO audit_events
            (actor_id, action, target_type, target_id, details, status, created_at,
             ip_address, risk_level, session_id)
        VALUES (?, ?, 'emergency', ?, ?, ?, ?, ?, 'HIGH', ?)
        """,
        (
            actor_id,
            f"emergency_{action}"[:120],
            str(incident_id) if incident_id is not None else "global",
            json.dumps({"reason": reason[:500], "affected_users": affected_users}),
            result[:40],
            now,
            request_ip(),
            session.get("device_token", "")[:16] or None,
        ),
    )
def policies_accepted(user_id):
    with database_connection() as connection:
        row = connection.execute("SELECT terms_accepted, privacy_accepted, cookies_accepted, disclaimer_accepted FROM policy_acceptances WHERE user_id = ?", (user_id,)).fetchone()
    return bool(row and all(row[column] for column in ("terms_accepted", "privacy_accepted", "cookies_accepted", "disclaimer_accepted")))


def policy_enabled(name, default=False):
    with database_connection() as connection:
        row = connection.execute("SELECT value FROM policies WHERE name = ?", (name,)).fetchone()
    return bool(row and str(row["value"]).lower() in {"1", "true", "yes", "on"}) if row else default


_OAUTH_CLIENT_LOCK = threading.RLock()
_OAUTH_PROVIDER_CONFIG = {
    "google": {
        "environment": (GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET),
        "name": "google",
        "settings": {
            "server_metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
            "client_kwargs": {"scope": "openid email profile"},
        },
    },
    "github": {
        "environment": (GITHUB_OAUTH_CLIENT_ID, GITHUB_OAUTH_CLIENT_SECRET),
        "name": "github",
        "settings": {
            "authorize_url": "https://github.com/login/oauth/authorize",
            "access_token_url": "https://github.com/login/oauth/access_token",
            "api_base_url": "https://api.github.com/",
            "client_kwargs": {"scope": "read:user user:email"},
        },
    },
}


def _oauth_credentials_cipher():
    if not FLASK_SECRET_KEY_CONFIGURED:
        raise RuntimeError(
            "Set a persistent FLASK_SECRET_KEY before storing OAuth credentials."
        )
    secret_key = (
        app.secret_key
        if isinstance(app.secret_key, bytes)
        else str(app.secret_key).encode("utf-8")
    )
    derived_key = hmac.new(
        secret_key, b"cloud-rdx/oauth-credentials/v1", hashlib.sha256
    ).digest()
    return Fernet(base64.urlsafe_b64encode(derived_key))


def oauth_provider_credentials(provider):
    provider_config = _OAUTH_PROVIDER_CONFIG.get(provider)
    if not provider_config:
        raise ValueError(f"Unsupported OAuth provider: {provider}")

    setting_name = f"{provider}_oauth_credentials"
    with database_connection() as connection:
        row = connection.execute(
            "SELECT value FROM policies WHERE name = ?", (setting_name,)
        ).fetchone()
    if row:
        try:
            payload = _oauth_credentials_cipher().decrypt(
                row["value"].encode("ascii")
            )
            credentials = json.loads(payload)
            if not isinstance(credentials, dict):
                raise ValueError("OAuth credential record is not an object")
            client_id = credentials.get("client_id", "")
            client_secret = credentials.get("client_secret", "")
            if isinstance(client_id, str) and isinstance(client_secret, str):
                return client_id, client_secret
        except (InvalidToken, UnicodeError, ValueError, RuntimeError, TypeError):
            app.logger.error(
                "%s OAuth credentials cannot be decrypted; check that "
                "FLASK_SECRET_KEY has not changed",
                provider,
            )
            return "", ""
        app.logger.error("%s OAuth credential record is invalid", provider)
        return "", ""
    return provider_config["environment"]


def oauth_credentials_configured(provider):
    client_id, client_secret = oauth_provider_credentials(provider)
    return bool(client_id and client_secret)


def oauth_credentials_admin_managed(provider):
    with database_connection() as connection:
        row = connection.execute(
            "SELECT 1 FROM policies WHERE name = ?",
            (f"{provider}_oauth_credentials",),
        ).fetchone()
    return row is not None


def oauth_provider_client(provider):
    provider_config = _OAUTH_PROVIDER_CONFIG.get(provider)
    if not provider_config:
        raise ValueError(f"Unsupported OAuth provider: {provider}")
    client_id, client_secret = oauth_provider_credentials(provider)
    if not client_id or not client_secret:
        return None

    if (client_id, client_secret) == provider_config["environment"]:
        return google if provider == "google" else github

    secret_key = (
        app.secret_key
        if isinstance(app.secret_key, bytes)
        else str(app.secret_key).encode("utf-8")
    )
    fingerprint = hmac.new(
        secret_key,
        f"{provider}\0{client_id}\0{client_secret}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:24]
    client_name = f"managed_{provider}_{fingerprint}"
    with _OAUTH_CLIENT_LOCK:
        client = oauth.register(
            name=client_name,
            client_id=client_id,
            client_secret=client_secret,
            **provider_config["settings"],
        )
        # Preserve the deterministic state key without caching the secret client.
        oauth._clients.pop(client_name, None)
        oauth._registry.pop(client_name, None)
    return client


def policy_integer(name, default, minimum, maximum):
    with database_connection() as connection:
        row = connection.execute("SELECT value FROM policies WHERE name = ?", (name,)).fetchone()
    try:
        value = int(row["value"]) if row else default
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def login_security_settings():
    return {
        "login_max_attempts": policy_integer(
            "login_max_attempts", LOGIN_MAX_ATTEMPTS, 1, 100
        ),
        "login_window_minutes": policy_integer(
            "login_window_minutes", LOGIN_WINDOW_MINUTES, 1, 1440
        ),
        "login_lockout_minutes": policy_integer(
            "login_lockout_minutes", LOGIN_LOCKOUT_MINUTES, 1, 1440
        ),
    }


def google_signin_enabled():
    return oauth_credentials_configured("google") and policy_enabled(
        "allow_google_signin", True
    )


def github_signin_enabled():
    return oauth_credentials_configured("github") and policy_enabled(
        "allow_github_signin", True
    )


def maintenance_enabled():
    with database_connection() as connection:
        row = connection.execute(
            "SELECT value, updated_at FROM policies WHERE name = 'maintenance_mode'"
        ).fetchone()
        if not row or str(row["value"]).lower() not in {"1", "true", "yes", "on"}:
            return False
        try:
            started_at = datetime.fromisoformat(row["updated_at"])
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            # An invalid activation timestamp must fail closed rather than
            # accidentally making the website available.
            return True
        if datetime.now(timezone.utc) - started_at >= timedelta(hours=MAINTENANCE_DURATION_HOURS):
            connection.execute(
                "UPDATE policies SET value = '0', updated_at = ? WHERE name = 'maintenance_mode'",
                (datetime.now(timezone.utc).isoformat(),),
            )
            return False
    return True


def admin_user_path(user_id, subpath=""):
    with database_connection() as connection:
        user = connection.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or user["is_admin"]:
        raise ValueError("User not found")
    base = (SHARED_FOLDER / "users" / str(user_id)).resolve()
    target = (base / subpath).resolve()
    try:
        target.relative_to(base)
    except ValueError as exc:
        raise ValueError("Invalid path") from exc
    return user, base, target


@app.before_request
def enforce_session_timeout():
    limited_response = request_rate_limit()
    if limited_response:
        return limited_response
    if (
        request.path.startswith("/api/")
        and request.endpoint != "payment_webhook"
        and emergency_enabled("disable_api_access")
    ):
        audit_event(
            "emergency_api_blocked",
            "api",
            request.endpoint or request.path,
            "Emergency API access control",
            status="denied",
            risk_level="HIGH",
            actor_id=session.get("user_id"),
        )
        return jsonify(
            error="service_unavailable",
            message="API access is temporarily disabled by the administrator.",
        ), 503
    exempt_endpoints = {
        "home",
        "login",
        "login_2fa",
        "register",
        "forgot_password",
        "google_login_start",
        "google_callback",
        "github_login_start",
        "github_callback",
        "login_assets",
        "background_video",
        "payment_webhook",
        "payment_qr",
        "static",
        "consent",
        "policy_page",
    }
    if maintenance_enabled():
        maintenance_exempt_endpoints = {
            "login",
            "login_2fa",
            "google_login_start",
            "google_callback",
            "github_login_start",
            "github_callback",
            "login_assets",
            "background_video",
            "payment_webhook",
            "payment_qr",
            "static",
        }
        user = current_user()
        owner_session = bool(user and user["username"].lower() == ADMIN_USERNAME.lower() and user["status"] == "active")
        if request.endpoint not in maintenance_exempt_endpoints and not owner_session:
            session.clear()
            return render_template_string(MAINTENANCE_PAGE), 503
    if (
        request.method == "POST"
        and (
            request.endpoint == "login_2fa"
            or request.endpoint not in exempt_endpoints
        )
    ):
        expected = session.get(CSRF_SESSION_KEY)
        supplied = request.form.get("csrf_token", "")
        if not expected or not supplied or not secrets.compare_digest(expected, supplied):
            abort(400, "Invalid or missing CSRF token")
    if request.endpoint not in exempt_endpoints:
        response = require_login()
        if response:
            return response
        user = current_user()
        if user and request.endpoint not in {"consent", "accept_policies", "policy_page"} and not policies_accepted(user["id"]):
            return redirect(url_for("consent"))
        if (
            user
            and emergency_enabled("force_password_reset")
            and user["must_change_password"]
            and request.endpoint not in {"profile", "change_password", "logout", "static"}
        ):
            return redirect(url_for("profile"))
        if (
            user
            and emergency_enabled("require_two_factor")
            and not user["totp_enabled"]
            and request.endpoint not in {"security_2fa_enroll", "logout", "static"}
        ):
            return redirect(url_for("security_2fa_enroll"))


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; object-src 'none'; "
        "frame-ancestors 'self'; form-action 'self'; "
        "img-src 'self' https: data: blob:; media-src 'self'; "
        "connect-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'",
    )
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.endpoint == "admin_settings":
        response.headers["Cache-Control"] = "no-store"
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


@app.context_processor
def inject_user():
    user = current_user()
    return {"username": user["username"] if user else "", "is_admin": bool(user and user["is_admin"]), "is_owner": is_owner(), "admin_access": has_admin_access() if user else False}


@app.route("/background-video")
def background_video():
    """Serve the supplied authentication background video."""
    video = RESOURCE_FOLDER / "Resources RDx" / "login page.mp4"
    return send_from_directory(video.parent, video.name, mimetype="video/mp4")


@app.route("/payment-qr")
def payment_qr():
    """Serve the configured payment QR image without exposing the asset folder."""
    qr = RESOURCE_FOLDER / "Resources RDx" / "WhatsApp Image 2026-09-16 at 12.34.01 PM.jpeg"
    if not qr.is_file():
        abort(404, "Payment QR is not configured")
    return send_from_directory(qr.parent, qr.name, mimetype="image/jpeg")


@app.route("/")
def home():
    if logged_in():
        return redirect(url_for("admin_panel" if has_admin_access() else "files"))
    return render_template_string(HOME_PAGE)


@app.route("/consent")
def consent():
    response = require_login()
    if response:
        return response
    return render_template_string(CONSENT_PAGE)


@app.route("/consent/accept", methods=["POST"])
def accept_policies():
    response = require_login()
    if response:
        return response
    if request.form.get("accept_all") != "on":
        return render_template_string(CONSENT_PAGE, error="You must accept all four policies before using RDx Cloud Storage."), 400
    now = datetime.now(timezone.utc).isoformat()
    with database_connection() as connection:
        connection.execute("""
            INSERT INTO policy_acceptances (user_id, terms_accepted, privacy_accepted, cookies_accepted, disclaimer_accepted, accepted_at)
            VALUES (?, 1, 1, 1, 1, ?)
            ON CONFLICT(user_id) DO UPDATE SET terms_accepted=1, privacy_accepted=1, cookies_accepted=1, disclaimer_accepted=1, accepted_at=excluded.accepted_at
        """, (session["user_id"], now))
    audit_event("accept_policies", "policy", session["user_id"], "terms, privacy, cookies, disclaimer")
    flash("Thank you. All policies were accepted.")
    if session.pop("show_profile_onboarding", False):
        return redirect(url_for("profile"))
    return redirect(url_for("admin_panel" if has_admin_access() else "files"))


@app.route("/policy/<policy_name>")
def policy_page(policy_name):
    policies = {
        "terms": {"title": "Terms and conditions", "summary": "These terms explain the acceptable use of RDx Cloud Storage and the responsibilities of account holders."},
        "privacy": {"title": "Privacy policy", "summary": "This policy explains how account, recovery, audit, and storage information is handled by this local storage service."},
        "cookies": {"title": "Cookie policy", "summary": "RDx Cloud Storage uses essential session cookies to keep you signed in and protect forms. It does not require advertising cookies."},
        "disclaimer": {"title": "Disclaimer", "summary": "The service is provided for authorized storage use. Keep independent backups of important files and do not rely on this service as your only copy."},
    }
    policy = policies.get(policy_name)
    if not policy:
        abort(404)
    return render_template_string(POLICY_PAGE, policy=policy, back_url=url_for("consent") if logged_in() else url_for("home"))


TOTP_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Security verification - Cloud Rdx</title><link rel="stylesheet" href="{{ url_for('static', filename='auth.css') }}"></head>
<body class="login-page"><main class="login-box"><div class="login-brand">RDx Cloud Storage-DB16</div><h1>Verify your sign-in</h1><p class="login-notice">Enter the six-digit code from your authenticator app.</p><form method="post" action="{{ url_for('login_2fa') }}"><div class="input-box"><input id="code" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder=" " required autofocus><label for="code">Authenticator code</label></div><button type="submit">Verify and continue</button></form>{% if error %}<p class="login-message" role="alert">{{ error }}</p>{% endif %}<p class="register-link"><a href="{{ url_for('login') }}">Cancel sign in</a></p></main></body></html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if logged_in():
        return redirect(url_for("admin_panel" if has_admin_access() else "files"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        lockout_remaining = login_lockout_remaining(username)
        if lockout_remaining:
            audit_event("login_throttled", "user", username, "too many recent failures", status="denied", actor_id=None)
            return rate_limited_response(lockout_remaining)
        user = find_user(username)
        password = request.form.get("password", "")
        owner_login_allowed = not maintenance_enabled() or bool(
            user and user["username"].lower() == ADMIN_USERNAME.lower()
        )
        if (
            owner_login_allowed
            and user
            and user["password_login_enabled"]
            and user["status"] == "active"
            and verify_password(user["password_hash"], password)
        ):
            record_login_attempt(username, True)
            if password_hash_needs_upgrade(user["password_hash"]):
                with database_connection() as connection:
                    connection.execute("UPDATE users SET password_hash = ?, password_login_enabled = 1 WHERE id = ?", (hash_password(password), user["id"]))
            if user["totp_enabled"] and (
                user["is_admin"] or emergency_enabled("require_two_factor")
            ):
                session.clear()
                session["pending_2fa_user_id"] = user["id"]
                session["pending_2fa_at"] = datetime.now(timezone.utc).isoformat()
                csrf_token()
                return redirect(url_for("login_2fa"))
            device_cookie, device_allowed = trusted_browser_device(user["id"])
            if not device_allowed:
                return trusted_device_login_denied(device_cookie)
            session.clear()
            timestamp = datetime.now(timezone.utc).isoformat()
            with database_connection() as connection:
                connection.execute(
                    "UPDATE users SET last_login_at = ? WHERE id = ?",
                    (timestamp, user["id"]),
                )
            session["user_id"] = user["id"]
            session["last_seen"] = timestamp
            session["device_token"] = create_device_session(user["id"])
            csrf_token()
            audit_event("login", "user", user["id"])
            if emergency_enabled("require_two_factor") and not user["totp_enabled"]:
                response = redirect(url_for("security_2fa_enroll"))
            else:
                response = redirect(url_for("admin_panel" if has_admin_access() else "files"))
            return set_trusted_device_cookie(response, device_cookie)
        record_login_attempt(username, False)
        if user and user["status"] != "active":
            audit_event("login_blocked", "user", user["id"], "account is suspended", status="denied", actor_id=None)
        return render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=github_signin_enabled(),
            github_oauth_configured=oauth_credentials_configured("github"),
            error="The username or password is not correct.",
        )
    return render_template_string(
        LOGIN_PAGE,
        google_login_enabled=google_signin_enabled(),
        google_oauth_configured=oauth_credentials_configured("google"),
        github_login_enabled=github_signin_enabled(),
        github_oauth_configured=oauth_credentials_configured("github"),
    )


def social_account_for_identity(
    provider,
    subject,
    email,
    full_name,
    allow_creation=True,
    provider_username=None,
    picture_url=None,
    provider_location=None,
):
    provider_columns = {
        "google": {
            "identity": "google_sub",
            "email": "google_email",
            "name": "google_profile_name",
            "username": "google_username",
            "picture": "google_picture",
        },
        "github": {
            "identity": "github_sub",
            "email": "github_email",
            "name": "github_profile_name",
            "username": "github_username",
            "picture": "github_picture",
        },
    }
    provider_fields = provider_columns.get(provider)
    if not provider_fields:
        raise ValueError(f"Unsupported social identity provider: {provider}")

    identity_column = provider_fields["identity"]
    provider_username = (
        provider_username.strip()[:255]
        if isinstance(provider_username, str) and provider_username.strip()
        else None
    )
    picture_url = safe_oauth_picture_url(picture_url, provider)
    provider_location = (
        provider_location.strip()[:160]
        if isinstance(provider_location, str) and provider_location.strip()
        else None
    )
    created = False
    linked = False
    with database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        user = connection.execute(
            f"SELECT * FROM users WHERE {identity_column} = ?", (subject,)
        ).fetchone()
        if not user:
            matches = connection.execute(
                "SELECT * FROM users WHERE lower(trim(email)) = ?",
                (email,),
            ).fetchall()
            if len(matches) > 1:
                return None, False, False, "That email matches multiple accounts. Contact support."
            if matches:
                user = matches[0]
                if user[identity_column] and user[identity_column] != subject:
                    return None, False, False, (
                        f"That account is already connected to another "
                        f"{provider.title()} identity."
                    )
                connection.execute(
                    f"""
                    UPDATE users
                    SET {identity_column} = ?,
                        full_name = COALESCE(NULLIF(full_name, ''), ?)
                    WHERE id = ?
                    """,
                    (subject, full_name, user["id"]),
                )
                linked = True
                user = connection.execute(
                    "SELECT * FROM users WHERE id = ?", (user["id"],)
                ).fetchone()
            else:
                if not allow_creation:
                    return None, False, False, (
                        f"New {provider.title()} accounts are unavailable during maintenance."
                    )
                if (
                    not policy_enabled("allow_registration", True)
                    or emergency_enabled("freeze_registrations")
                ):
                    return None, False, False, "New account registration is disabled."

                local_part = email.split("@", 1)[0]
                base_username = re.sub(r"[^A-Za-z0-9_-]", "", local_part)[:32]
                if len(base_username) < 3:
                    base_username = "clouduser"
                username = base_username
                suffix = 1
                while connection.execute(
                    "SELECT 1 FROM users WHERE username = ? COLLATE NOCASE",
                    (username,),
                ).fetchone():
                    tail = f"-{suffix}"
                    username = f"{base_username[:32 - len(tail)]}{tail}"
                    suffix += 1

                now = datetime.now(timezone.utc).isoformat()
                cursor = connection.execute(
                    f"""
                    INSERT INTO users
                        (username, password_hash, created_at, full_name, email,
                         {identity_column}, password_login_enabled)
                    VALUES (?, ?, ?, ?, ?, ?, 0)
                    """,
                    (
                        username,
                        hash_password(secrets.token_urlsafe(48)),
                        now,
                        full_name,
                        email,
                        subject,
                    ),
                )
                user_id = cursor.lastrowid
                connection.execute(
                    """
                    INSERT INTO storage_permissions
                        (user_id, allow_upload, allow_download, updated_at)
                    VALUES (?, 1, 1, ?)
                    """,
                    (user_id, now),
                )
                user = connection.execute(
                    "SELECT * FROM users WHERE id = ?", (user_id,)
                ).fetchone()
                created = True

        connection.execute(
            f"""
            UPDATE users
            SET {provider_fields["email"]} = ?,
                {provider_fields["name"]} = ?,
                {provider_fields["username"]} = COALESCE(?, {provider_fields["username"]}),
                {provider_fields["picture"]} = COALESCE(?, {provider_fields["picture"]}),
                location = COALESCE(NULLIF(location, ''), ?)
            WHERE id = ?
            """,
            (
                email,
                full_name[:160],
                provider_username,
                picture_url,
                provider_location,
                user["id"],
            ),
        )
        user = connection.execute(
            "SELECT * FROM users WHERE id = ?", (user["id"],)
        ).fetchone()
        if user["status"] != "active":
            return None, False, False, "This Cloud Rdx account is currently unavailable."

    if created:
        (SHARED_FOLDER / "users" / str(user["id"])).mkdir(
            parents=True, exist_ok=True
        )
    return user, created, linked, None


def safe_oauth_picture_url(value, provider):
    if not isinstance(value, str) or len(value) > 2048:
        return None
    try:
        parsed_url = urlsplit(value)
    except ValueError:
        return None
    hostname = parsed_url.hostname
    allowed_suffix = {
        "google": "googleusercontent.com",
        "github": "githubusercontent.com",
    }.get(provider)
    if (
        not allowed_suffix
        or parsed_url.scheme != "https"
        or not hostname
        or not (hostname == allowed_suffix or hostname.endswith(f".{allowed_suffix}"))
    ):
        return None
    return value


def complete_social_login(
    provider,
    subject,
    email,
    full_name,
    provider_username=None,
    picture_url=None,
    provider_location=None,
):
    maintenance_active = maintenance_enabled()
    user, created, linked, error = social_account_for_identity(
        provider,
        subject,
        email,
        full_name,
        allow_creation=(
            not maintenance_active
            and policy_enabled("allow_registration", True)
            and not emergency_enabled("freeze_registrations")
        ),
        provider_username=provider_username,
        picture_url=picture_url,
        provider_location=provider_location,
    )
    if error:
        if maintenance_active:
            return render_template_string(MAINTENANCE_PAGE), 503
        return render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=github_signin_enabled(),
            github_oauth_configured=oauth_credentials_configured("github"),
            error=error,
        ), 403

    if maintenance_active and user["username"].lower() != ADMIN_USERNAME.lower():
        return render_template_string(MAINTENANCE_PAGE), 503

    if created:
        audit_event(
            "account_created",
            "user",
            user["id"],
            f"provider={provider}",
            actor_id=None,
        )
    record_login_attempt(email, True)
    if user["totp_enabled"] and (
        user["is_admin"] or emergency_enabled("require_two_factor")
    ):
        session.clear()
        session["pending_2fa_user_id"] = user["id"]
        session["pending_2fa_at"] = datetime.now(timezone.utc).isoformat()
        csrf_token()
        audit_event(f"{provider}_login_2fa_required", "user", user["id"])
        return redirect(url_for("login_2fa"))

    device_cookie, device_allowed = trusted_browser_device(user["id"])
    if not device_allowed:
        session.clear()
        return trusted_device_login_denied(device_cookie)
    timestamp = datetime.now(timezone.utc).isoformat()
    with database_connection() as connection:
        connection.execute(
            "UPDATE users SET last_login_at = ? WHERE id = ?",
            (timestamp, user["id"]),
        )
    session.clear()
    session["user_id"] = user["id"]
    session["last_seen"] = timestamp
    session["device_token"] = create_device_session(user["id"])
    csrf_token()
    audit_action = (
        f"{provider}_account_created"
        if created
        else f"{provider}_account_linked"
        if linked
        else f"{provider}_login"
    )
    audit_event(audit_action, "user", user["id"], actor_id=user["id"])
    if emergency_enabled("require_two_factor") and not user["totp_enabled"]:
        response = redirect(url_for("security_2fa_enroll"))
        return set_trusted_device_cookie(response, device_cookie)
    if created:
        session["show_profile_onboarding"] = True
        flash(
            "Your account is ready. Add optional recovery and profile details, "
            "or return to storage to continue."
        )
        response = redirect(url_for("profile"))
    else:
        response = redirect(url_for("admin_panel" if has_admin_access() else "files"))
    return set_trusted_device_cookie(response, device_cookie)


@app.route("/auth/google")
def google_login_start():
    if logged_in():
        return redirect(url_for("admin_panel" if has_admin_access() else "files"))
    if not google_signin_enabled():
        error = (
            "Google sign-in is disabled by the site administrator."
            if oauth_credentials_configured("google")
            else "Google sign-in is not configured on this server."
        )
        return (
            render_template_string(
                LOGIN_PAGE,
                google_login_enabled=False,
                google_oauth_configured=oauth_credentials_configured("google"),
                github_login_enabled=github_signin_enabled(),
                github_oauth_configured=oauth_credentials_configured("github"),
                error=error,
            ),
            503,
        )
    redirect_uri = f"{APP_BASE_URL}{url_for('google_callback')}"
    client = oauth_provider_client("google")
    return client.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def google_callback():
    if not google_signin_enabled():
        error = (
            "Google sign-in is disabled by the site administrator."
            if oauth_credentials_configured("google")
            else "Google sign-in is not configured on this server."
        )
        return (
            render_template_string(
                LOGIN_PAGE,
                google_login_enabled=False,
                google_oauth_configured=oauth_credentials_configured("google"),
                github_login_enabled=github_signin_enabled(),
                github_oauth_configured=oauth_credentials_configured("github"),
                error=error,
            ),
            503,
        )
    try:
        client = oauth_provider_client("google")
        token = client.authorize_access_token()
    except (OAuthError, JoseError):
        app.logger.info("Google sign-in rejected an invalid OAuth response")
        return render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=github_signin_enabled(),
            github_oauth_configured=oauth_credentials_configured("github"),
            error="Google sign-in could not be verified. Please try again.",
        ), 400

    claims = token.get("userinfo")
    if not isinstance(claims, Mapping):
        return render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=github_signin_enabled(),
            github_oauth_configured=oauth_credentials_configured("github"),
            error="Google did not return a verified account. Please try again.",
        ), 400
    subject = claims.get("sub")
    email = claims.get("email")
    full_name = claims.get("name")
    if (
        not isinstance(subject, str)
        or not isinstance(email, str)
        or claims.get("email_verified") is not True
    ):
        return render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=github_signin_enabled(),
            github_oauth_configured=oauth_credentials_configured("github"),
            error="Google sign-in requires a verified email address.",
        ), 400

    subject = subject.strip()
    email = email.strip().lower()
    if not subject or len(subject) > 255 or "@" not in email or len(email) > 254:
        return render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=github_signin_enabled(),
            github_oauth_configured=oauth_credentials_configured("github"),
            error="Google sign-in returned invalid account details.",
        ), 400
    full_name = full_name.strip()[:160] if isinstance(full_name, str) else ""
    full_name = full_name or email.split("@", 1)[0]
    provider_username = claims.get("preferred_username")
    picture_url = claims.get("picture")
    return complete_social_login(
        "google",
        subject,
        email,
        full_name,
        provider_username=provider_username,
        picture_url=picture_url,
    )


@app.route("/auth/github")
def github_login_start():
    if logged_in():
        return redirect(url_for("admin_panel" if has_admin_access() else "files"))
    if not github_signin_enabled():
        error = (
            "GitHub sign-in is disabled by the site administrator."
            if oauth_credentials_configured("github")
            else "GitHub sign-in is not configured on this server."
        )
        return render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=False,
            github_oauth_configured=oauth_credentials_configured("github"),
            error=error,
        ), 503
    redirect_uri = f"{APP_BASE_URL}{url_for('github_callback')}"
    client = oauth_provider_client("github")
    return client.authorize_redirect(redirect_uri)


@app.route("/auth/github/callback")
def github_callback():
    if not github_signin_enabled():
        error = (
            "GitHub sign-in is disabled by the site administrator."
            if oauth_credentials_configured("github")
            else "GitHub sign-in is not configured on this server."
        )
        return render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=False,
            github_oauth_configured=oauth_credentials_configured("github"),
            error=error,
        ), 503
    try:
        client = oauth_provider_client("github")
        client.authorize_access_token()
        profile_response = client.get("user")
        if profile_response.status_code != 200:
            app.logger.warning(
                "GitHub profile lookup failed with status=%s",
                profile_response.status_code,
            )
            return github_auth_error(
                "GitHub could not verify your account. Please try again.", 502
            )
        profile = profile_response.json()
        if not isinstance(profile, Mapping):
            return github_auth_error("GitHub returned invalid account details.", 400)

        emails_response = client.get("user/emails")
        if emails_response.status_code != 200:
            app.logger.warning(
                "GitHub email lookup failed with status=%s",
                emails_response.status_code,
            )
            return github_auth_error(
                "GitHub could not verify your email address. Please try again.",
                502,
            )
        email_entries = emails_response.json()
    except OSError:
        app.logger.warning("GitHub sign-in could not reach the OAuth provider")
        return github_auth_error(
            "GitHub sign-in is temporarily unavailable. Please try again later.",
            502,
        )
    except (OAuthError, ValueError):
        app.logger.info("GitHub sign-in rejected an invalid OAuth response")
        return github_auth_error(
            "GitHub sign-in could not be verified. Please try again.", 400
        )

    github_id = profile.get("id")
    if isinstance(github_id, bool) or not isinstance(github_id, (int, str)):
        return github_auth_error("GitHub returned invalid account details.", 400)
    subject = str(github_id).strip()
    if not subject or len(subject) > 255 or not subject.isdigit():
        return github_auth_error("GitHub returned invalid account details.", 400)
    if not isinstance(email_entries, list):
        return github_auth_error(
            "GitHub did not return a verified email address.", 400
        )
    primary_email = next(
        (
            entry.get("email")
            for entry in email_entries
            if isinstance(entry, Mapping)
            and entry.get("primary") is True
            and entry.get("verified") is True
            and isinstance(entry.get("email"), str)
        ),
        None,
    )
    if not primary_email:
        return github_auth_error(
            "GitHub sign-in requires a verified primary email address.", 400
        )
    email = primary_email.strip().lower()
    if "@" not in email or len(email) > 254:
        return github_auth_error("GitHub returned invalid account details.", 400)
    full_name = profile.get("name")
    if not isinstance(full_name, str) or not full_name.strip():
        full_name = profile.get("login")
    if not isinstance(full_name, str) or not full_name.strip():
        full_name = email.split("@", 1)[0]
    return complete_social_login(
        "github",
        subject,
        email,
        full_name.strip()[:160],
        provider_username=profile.get("login"),
        picture_url=profile.get("avatar_url"),
        provider_location=profile.get("location"),
    )


def github_auth_error(message, status):
    return render_template_string(
        LOGIN_PAGE,
        google_login_enabled=google_signin_enabled(),
        google_oauth_configured=oauth_credentials_configured("google"),
        github_login_enabled=github_signin_enabled(),
        github_oauth_configured=oauth_credentials_configured("github"),
        error=message,
    ), status


@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("login"))
    try:
        issued = datetime.fromisoformat(session.get("pending_2fa_at", ""))
    except ValueError:
        issued = datetime.min.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - issued > timedelta(minutes=5):
        session.clear()
        return redirect(url_for("login"))
    user = current_user() if session.get("user_id") else None
    with database_connection() as connection:
        user = connection.execute(
            "SELECT * FROM users WHERE id = ? AND status = 'active'",
            (user_id,),
        ).fetchone()
    if (
        not user
        or pyotp is None
        or not user["totp_enabled"]
        or not (user["is_admin"] or emergency_enabled("require_two_factor"))
    ):
        session.clear()
        return render_template_string(TOTP_PAGE, error="Authenticator verification is unavailable. Contact the system administrator."), 503
    if request.method == "POST" and pyotp.TOTP(user["totp_secret"]).verify(request.form.get("code", "").strip(), valid_window=1):
        device_cookie, device_allowed = trusted_browser_device(user["id"])
        if not device_allowed:
            session.clear()
            return trusted_device_login_denied(device_cookie)
        timestamp = datetime.now(timezone.utc).isoformat()
        with database_connection() as connection:
            connection.execute(
                "UPDATE users SET last_login_at = ? WHERE id = ?",
                (timestamp, user["id"]),
            )
        session.clear()
        session["user_id"] = user["id"]
        session["last_seen"] = timestamp
        session["device_token"] = create_device_session(user["id"])
        csrf_token()
        audit_event("login_2fa", "user", user["id"])
        response = redirect(url_for("admin_panel" if has_admin_access() else "files"))
        return set_trusted_device_cookie(response, device_cookie)
    if request.method == "POST":
        record_login_attempt(user["username"], False)
        audit_event("login_2fa_failed", "user", user["id"], status="denied", actor_id=None)
        return render_template_string(TOTP_PAGE, error="That verification code is invalid or expired.")
    return render_template_string(TOTP_PAGE)


@app.route("/security/2fa/enroll", methods=["GET", "POST"])
def security_2fa_enroll():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if pyotp is None:
        abort(503, "Authenticator support is not installed")
    if user["totp_enabled"]:
        return redirect(url_for("admin_panel" if has_admin_access() else "files"))
    secret = session.get("totp_enroll_secret") or pyotp.random_base32()
    session["totp_enroll_secret"] = secret
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=user["email"] or user["username"],
        issuer_name="Cloud Rdx",
    )
    error = None
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if not re.fullmatch(r"\d{6}", code) or not pyotp.TOTP(secret).verify(
            code, valid_window=1
        ):
            error = "That verification code is invalid or expired."
        else:
            with database_connection() as connection:
                connection.execute(
                    "UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?",
                    (secret, user["id"]),
                )
            session.pop("totp_enroll_secret", None)
            audit_event("enroll_required_2fa", "user", user["id"], risk_level="HIGH")
            flash("Authenticator two-factor authentication is enabled.")
            return redirect(url_for("admin_panel" if has_admin_access() else "files"))
    return render_template_string(
        TOTP_SETUP_PAGE,
        secret=secret,
        provisioning_uri=provisioning_uri,
        error=error,
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if logged_in():
        return redirect(url_for("admin_panel" if has_admin_access() else "files"))
    if (
        not policy_enabled("allow_registration", True)
        or emergency_enabled("freeze_registrations")
    ):
        return render_template_string(REGISTER_PAGE, error="New registrations are currently disabled by an administrator."), 403
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        mobile = request.form.get("mobile", "").strip()
        date_of_birth = request.form.get("dob", "").strip()
        if not username or not username.replace("_", "").replace("-", "").isalnum() or not 3 <= len(username) <= 32:
            return render_template_string(REGISTER_PAGE, error="Use 3-32 letters, numbers, underscores, or hyphens.")
        if len(password) < 8:
            return render_template_string(REGISTER_PAGE, error="Password must be at least 8 characters.")
        if password != password_confirm:
            return render_template_string(REGISTER_PAGE, error="Passwords do not match.")
        if not full_name or not email or not mobile or not date_of_birth:
            return render_template_string(REGISTER_PAGE, error="All profile and recovery fields are required.")
        if find_user(username):
            return render_template_string(REGISTER_PAGE, error="That username is already taken.")
        with database_connection() as connection:
            cursor = connection.execute("INSERT INTO users (username, password_hash, created_at, full_name, email, mobile, date_of_birth) VALUES (?, ?, ?, ?, ?, ?, ?)", (username, hash_password(password), datetime.now(timezone.utc).isoformat(), full_name, email, mobile, date_of_birth))
            user_id = cursor.lastrowid
            connection.execute(
                "INSERT INTO storage_permissions (user_id, allow_upload, allow_download, updated_at) VALUES (?, 1, 1, ?)",
                (user_id, datetime.now(timezone.utc).isoformat()),
            )
        (SHARED_FOLDER / "users" / str(user_id)).mkdir(parents=True, exist_ok=True)
        audit_event("account_created", "user", user_id, "provider=password")
        flash("Account created. Sign in to access your private storage.")
        return redirect(url_for("login"))
    return render_template_string(REGISTER_PAGE)


@app.route("/profile", methods=["GET", "POST"])
def profile():
    response = require_login()
    if response:
        return response
    user = dict(current_user())
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        mobile = request.form.get("mobile", "").strip()
        date_of_birth = request.form.get("date_of_birth", "").strip()
        gender = request.form.get("gender", "").strip()
        location = request.form.get("location", "").strip()
        if not full_name or len(full_name) > 160:
            flash("Enter a full name of 1 to 160 characters.")
        elif len(mobile) > 32 or len(gender) > 80 or len(location) > 160:
            flash("One or more profile fields exceed their allowed length.")
        else:
            if date_of_birth:
                try:
                    parsed_birth_date = datetime.strptime(
                        date_of_birth, "%Y-%m-%d"
                    ).date()
                except ValueError:
                    parsed_birth_date = None
                if (
                    parsed_birth_date is None
                    or parsed_birth_date > datetime.now(timezone.utc).date()
                ):
                    flash("Enter a valid date of birth that is not in the future.")
                    return redirect(url_for("profile"))
            with database_connection() as connection:
                connection.execute(
                    """
                    UPDATE users
                    SET full_name = ?, mobile = ?, date_of_birth = ?,
                        gender = ?, location = ?
                    WHERE id = ?
                    """,
                    (
                        full_name,
                        mobile,
                        date_of_birth,
                        gender,
                        location,
                        user["id"],
                    ),
                )
            audit_event("profile_details_updated", "user", user["id"])
            flash("Your profile and recovery details were saved.")
            return redirect(url_for("profile"))

    user["profile_picture"] = user.get("google_picture") or user.get("github_picture")
    return render_template_string(
        PROFILE_PAGE,
        profile=user,
        can_edit_profile=True,
        back_url=url_for("admin_panel" if has_admin_access() else "files"),
    )


@app.route("/storage/plan")
def storage_plan():
    response = require_storage_user()
    if response:
        return response
    user = current_user()
    used = user_usage(user["id"])[1]
    quota = user_quota(user["id"])
    subscription = current_subscription(user["id"])
    percent = min(100, int(used * 100 / quota)) if quota else 0
    return render_template_string(
        USER_ALLOCATION_PAGE,
        plans=[dict(row) for row in plan_rows()],
        used=used,
        quota=quota,
        remaining=max(0, quota - used),
        percent=percent,
        subscription=subscription,
        qr_url=PAYMENT_QR_URL,
    )


@app.route("/storage/payment-request", methods=["POST"])
def manual_payment_request():
    response = require_storage_user()
    if response:
        return response
    try:
        plan_id = int(request.form.get("plan_id", "0"))
    except ValueError:
        abort(400, "Invalid storage plan")
    reference = request.form.get("transaction_reference", "").strip()
    if not reference or len(reference) > 120:
        flash("Enter a valid UPI transaction reference.")
        return redirect(url_for("storage_plan"))
    user = current_user()
    with database_connection() as connection:
        plan = connection.execute("SELECT * FROM storage_plans WHERE id = ? AND active = 1", (plan_id,)).fetchone()
        if not plan or not plan["price_paise"]:
            flash("That storage plan is not available for payment.")
            return redirect(url_for("storage_plan"))
        try:
            connection.execute("""
                INSERT INTO payment_requests
                (user_id, plan_id, transaction_reference, amount_paise, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (user["id"], plan["id"], reference, plan["price_paise"], datetime.now(timezone.utc).isoformat()))
        except sqlite3.IntegrityError:
            flash("That transaction reference has already been submitted.")
            return redirect(url_for("storage_plan"))
    audit_event("payment_request_submitted", "payment", reference, f"plan={plan['code']}")
    flash("Payment reference submitted. Storage will be updated after verification.")
    return redirect(url_for("storage_plan"))


@app.route("/api/storage/plans")
def api_storage_plans():
    response = require_login()
    if response:
        return jsonify({"error": "authentication_required"}), 401
    return jsonify({"plans": [dict(row) for row in plan_rows()]})


@app.route("/api/storage/usage")
def api_storage_usage():
    response = require_storage_user()
    if response:
        return jsonify({"error": "authentication_required"}), 401
    user = current_user()
    used = user_usage(user["id"])[1]
    quota = user_quota(user["id"])
    return jsonify({"used_bytes": used, "quota_bytes": quota, "remaining_bytes": max(0, quota - used), "percent": min(100, int(used * 100 / quota)) if quota else 0})


@app.route("/api/subscription")
def api_subscription():
    response = require_storage_user()
    if response:
        return jsonify({"error": "authentication_required"}), 401
    return jsonify(current_subscription(current_user()["id"]) or {"status": "free"})


@app.route("/api/storage/create-order", methods=["POST"])
def api_create_order():
    response = require_storage_user()
    if response:
        return jsonify({"error": "authentication_required"}), 401
    client = razorpay_client()
    if not client:
        return jsonify({"error": "razorpay_not_configured", "message": "Configure Razorpay credentials and provider plan IDs first."}), 503
    try:
        plan_id = int(request.json.get("plan_id", 0))
    except (TypeError, ValueError, AttributeError):
        return jsonify({"error": "invalid_plan"}), 400
    with database_connection() as connection:
        plan = connection.execute("SELECT * FROM storage_plans WHERE id = ? AND active = 1", (plan_id,)).fetchone()
    if not plan or not plan["provider_plan_id"]:
        return jsonify({"error": "provider_plan_not_configured"}), 400
    try:
        created = client.subscription.create({"plan_id": plan["provider_plan_id"], "total_count": 12, "customer_notify": 1})
    except Exception:
        app.logger.exception("Razorpay subscription creation failed")
        return jsonify({"error": "payment_provider_error"}), 502
    user = current_user()
    now = datetime.now(timezone.utc).isoformat()
    with database_connection() as connection:
        connection.execute("""
            INSERT INTO subscriptions (user_id, plan_id, provider, provider_subscription_id, status, quota_bytes, created_at, updated_at)
            VALUES (?, ?, 'razorpay', ?, 'pending', ?, ?, ?)
        """, (user["id"], plan["id"], created["id"], plan["quota_bytes"], now, now))
    return jsonify({"key_id": RAZORPAY_KEY_ID, "subscription_id": created["id"], "plan": dict(plan)})


@app.route("/api/storage/verify-payment", methods=["POST"])
def api_verify_payment():
    response = require_storage_user()
    if response:
        return jsonify({"error": "authentication_required"}), 401
    client = razorpay_client()
    data = request.get_json(silent=True) or {}
    required = {"razorpay_payment_id", "razorpay_subscription_id", "razorpay_signature"}
    if not client or not required.issubset(data):
        return jsonify({"error": "invalid_payment_request"}), 400
    user = current_user()
    with database_connection() as connection:
        subscription = connection.execute("SELECT * FROM subscriptions WHERE provider_subscription_id = ? AND user_id = ?", (data["razorpay_subscription_id"], user["id"])).fetchone()
    if not subscription:
        return jsonify({"error": "subscription_not_found"}), 404
    try:
        client.utility.verify_payment_signature({"razorpay_payment_id": data["razorpay_payment_id"], "razorpay_subscription_id": data["razorpay_subscription_id"], "razorpay_signature": data["razorpay_signature"]})
        remote = client.subscription.fetch(data["razorpay_subscription_id"])
    except Exception:
        return jsonify({"error": "payment_verification_failed"}), 400
    if remote.get("status") not in {"active", "authenticated"}:
        return jsonify({"error": "subscription_not_active"}), 400
    plan = activate_subscription(user["id"], subscription["plan_id"], "razorpay", data["razorpay_subscription_id"])
    audit_event("payment_verified", "subscription", data["razorpay_subscription_id"], f"payment={data['razorpay_payment_id']}")
    return jsonify({"status": "active", "plan": plan, "quota_bytes": plan["quota_bytes"]})


@app.route("/api/payment/webhook", methods=["POST"])
def payment_webhook():
    raw = request.get_data()
    signature = request.headers.get("X-Razorpay-Signature", "")
    event_id = request.headers.get("x-razorpay-event-id", "")
    if not RAZORPAY_WEBHOOK_SECRET or not signature or not event_id:
        return jsonify({"error": "webhook_not_configured"}), 503
    expected = hmac.new(RAZORPAY_WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return jsonify({"error": "invalid_signature"}), 400
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return jsonify({"error": "invalid_payload"}), 400
    event_type = payload.get("event", "unknown")
    with database_connection() as connection:
        inserted = connection.execute("INSERT OR IGNORE INTO webhook_events (event_id, provider, event_type, payload, processed_at) VALUES (?, 'razorpay', ?, ?, ?)", (event_id, event_type, raw.decode("utf-8"), datetime.now(timezone.utc).isoformat())).rowcount
    if not inserted:
        return jsonify({"status": "duplicate"}), 200
    entity = payload.get("payload", {}).get("subscription", {}).get("entity", {})
    provider_id = entity.get("id")
    if provider_id:
        with database_connection() as connection:
            subscription = connection.execute("SELECT user_id, plan_id FROM subscriptions WHERE provider_subscription_id = ?", (provider_id,)).fetchone()
        if subscription and event_type in {"subscription.activated", "subscription.authenticated", "subscription.charged"}:
            activate_subscription(subscription["user_id"], subscription["plan_id"], "razorpay", provider_id)
        elif subscription and event_type in {"subscription.halted", "subscription.cancelled", "subscription.completed", "payment.failed"}:
            with database_connection() as connection:
                connection.execute("UPDATE subscriptions SET status = ?, updated_at = ? WHERE provider_subscription_id = ?", ("failed" if event_type == "payment.failed" else "cancelled", datetime.now(timezone.utc).isoformat(), provider_id))
    return jsonify({"status": "processed"}), 200


@app.route("/admin/payments")
def admin_payments():
    response = require_permission("payments.review")
    if response:
        return response
    with database_connection() as connection:
        rows = connection.execute("""
            SELECT payment_requests.*, users.username, users.email,
                   storage_plans.name AS plan_name, storage_plans.quota_bytes
            FROM payment_requests
            JOIN users ON users.id = payment_requests.user_id
            JOIN storage_plans ON storage_plans.id = payment_requests.plan_id
            WHERE payment_requests.status = 'pending'
            ORDER BY payment_requests.created_at ASC
        """).fetchall()
    return render_template_string(ADMIN_PAYMENT_PAGE, requests=[dict(row) for row in rows])


@app.route("/admin/payments/<int:payment_id>/review", methods=["POST"])
def admin_review_payment(payment_id):
    response = require_permission("payments.review")
    if response:
        return response
    decision = request.form.get("decision", "").strip().lower()
    if decision not in {"approve", "reject"}:
        abort(400, "Invalid payment decision")
    now = datetime.now(timezone.utc).isoformat()
    with database_connection() as connection:
        payment = connection.execute("""
            SELECT payment_requests.*, storage_plans.quota_bytes, storage_plans.code
            FROM payment_requests JOIN storage_plans ON storage_plans.id = payment_requests.plan_id
            WHERE payment_requests.id = ?
        """, (payment_id,)).fetchone()
        if not payment or payment["status"] != "pending":
            flash("Payment is already reviewed or does not exist.")
            return redirect(url_for("admin_payments"))
        status = "approved" if decision == "approve" else "rejected"
        connection.execute("""
            UPDATE payment_requests SET status = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ? AND status = 'pending'
        """, (status, session["user_id"], now, payment_id))
        if decision == "approve":
            connection.execute("""
                INSERT INTO subscriptions (user_id, plan_id, provider, status, quota_bytes, created_at, updated_at)
                VALUES (?, ?, 'manual_qr', 'active', ?, ?, ?)
                ON CONFLICT(provider_subscription_id) DO NOTHING
            """, (payment["user_id"], payment["plan_id"], payment["quota_bytes"], now, now))
            connection.execute("""
                INSERT INTO quotas (user_id, quota_bytes, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET quota_bytes = excluded.quota_bytes, updated_at = excluded.updated_at
            """, (payment["user_id"], payment["quota_bytes"], now))
    audit_event("payment_approved" if decision == "approve" else "payment_rejected", "payment", payment_id, f"user={payment['user_id']}; plan={payment['code']}")
    flash("Payment approved and storage allocated." if decision == "approve" else "Payment rejected.")
    return redirect(url_for("admin_payments"))


@app.route("/profile/password", methods=["POST"])
def change_password():
    response = require_login()
    if response:
        return response
    user = current_user()
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    if not verify_password(user["password_hash"], current_password):
        flash("The current password is incorrect.")
    elif len(new_password) < 8:
        flash("The new password must be at least 8 characters.")
    elif new_password != confirm_password:
        flash("The new passwords do not match.")
    else:
        with database_connection() as connection:
            connection.execute(
                """
                UPDATE users
                SET password_hash = ?, password_login_enabled = 1,
                    must_change_password = 0
                WHERE id = ?
                """,
                (hash_password(new_password), user["id"]),
            )
        audit_event("change_password", "user", user["id"], risk_level="MEDIUM")
        flash("Your password was updated successfully.")
    return redirect(url_for("profile"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if logged_in():
        return redirect(url_for("admin_panel" if is_admin() else "files"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        mobile = request.form.get("mobile", "").strip()
        date_of_birth = request.form.get("dob", "").strip()
        user = find_user(username)
        if not user or user["is_admin"]:
            return render_template_string(FORGOT_PAGE, error="We could not create a recovery request for those details.")
        details_match = (
            email == (user["email"] or "").strip().lower()
            and mobile == (user["mobile"] or "").strip()
            and date_of_birth == (user["date_of_birth"] or "")
        )
        with database_connection() as connection:
            pending = connection.execute("SELECT id FROM password_requests WHERE user_id = ? AND status = 'pending'", (user["id"],)).fetchone()
            if pending:
                return render_template_string(FORGOT_PAGE, error="A recovery request is already waiting for administrator review.", message=None)
            if details_match:
                recovery_password = generate_recovery_password()
                connection.execute("UPDATE users SET password_hash = ?, password_login_enabled = 1 WHERE id = ?", (hash_password(recovery_password), user["id"]))
                connection.execute("INSERT INTO password_requests (user_id, email, mobile, date_of_birth, created_at, status, reviewed_at) VALUES (?, ?, ?, ?, ?, 'approved', ?)", (user["id"], email, mobile, date_of_birth, datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()))
            else:
                connection.execute("INSERT INTO password_requests (user_id, email, mobile, date_of_birth, created_at) VALUES (?, ?, ?, ?, ?)", (user["id"], email, mobile, date_of_birth, datetime.now(timezone.utc).isoformat()))
        if details_match:
            return render_template_string(FORGOT_PAGE, error=None, message=f"Your details matched. Your temporary password is: {recovery_password}")
        return render_template_string(FORGOT_PAGE, error=None, message="Request sent. An administrator must verify the details before resetting the password.")
    return render_template_string(FORGOT_PAGE)


def user_statistics(user_id):
    folder = SHARED_FOLDER / "users" / str(user_id)
    files = [path for path in folder.rglob("*") if path.is_file()] if folder.exists() else []
    return len(files), sum(path.stat().st_size for path in files)


@app.route("/admin/settings", methods=["GET", "POST"])
def admin_settings():
    response = require_owner()
    if response:
        return response
    if request.method == "POST":
        try:
            retention_days = max(1, min(3650, int(request.form.get("trash_retention_days", "30"))))
            login_max_attempts = int(request.form.get("login_max_attempts", ""))
            login_window_minutes = int(request.form.get("login_window_minutes", ""))
            login_lockout_minutes = int(request.form.get("login_lockout_minutes", ""))
        except ValueError:
            abort(400, "Enter valid whole-number values for retention and login protection.")
        if not 1 <= login_max_attempts <= 100:
            abort(400, "Failed attempts must be between 1 and 100.")
        if not 1 <= login_window_minutes <= 1440:
            abort(400, "The login failure window must be between 1 and 1440 minutes.")
        if not 1 <= login_lockout_minutes <= 1440:
            abort(400, "The lockout duration must be between 1 and 1440 minutes.")
        values = {
            "allow_registration": "1" if request.form.get("allow_registration") else "0",
            "allow_public_sharing": "1" if request.form.get("allow_public_sharing") else "0",
            "allow_google_signin": "1" if request.form.get("allow_google_signin") else "0",
            "allow_github_signin": "1" if request.form.get("allow_github_signin") else "0",
            "trash_retention_days": str(retention_days),
            "login_max_attempts": str(login_max_attempts),
            "login_window_minutes": str(login_window_minutes),
            "login_lockout_minutes": str(login_lockout_minutes),
        }
        if emergency_enabled("freeze_registrations"):
            values["allow_registration"] = "0"
        if emergency_enabled("disable_file_sharing"):
            values["allow_public_sharing"] = "0"
        credential_updates = {}
        for provider in ("google", "github"):
            client_id = request.form.get(
                f"{provider}_oauth_client_id", ""
            ).strip()
            client_secret = request.form.get(
                f"{provider}_oauth_client_secret", ""
            ).strip()
            clear_credentials = bool(
                request.form.get(f"clear_{provider}_oauth_credentials")
            )
            if len(client_id) > 512 or len(client_secret) > 4096:
                abort(400, f"{provider.title()} OAuth credentials are too long.")
            if clear_credentials:
                if client_secret:
                    abort(
                        400,
                        f"Clear or update {provider.title()} credentials, not both.",
                    )
                credential_updates[provider] = None
            elif client_id or client_secret:
                current_client_id, current_client_secret = (
                    oauth_provider_credentials(provider)
                )
                client_id = client_id or current_client_id
                client_secret = client_secret or current_client_secret
                if not client_id or not client_secret:
                    abort(
                        400,
                        f"Enter both the {provider.title()} OAuth Client ID and "
                        "Client Secret to configure sign-in.",
                    )
                try:
                    encrypted_credentials = _oauth_credentials_cipher().encrypt(
                        json.dumps(
                            {
                                "client_id": client_id,
                                "client_secret": client_secret,
                            },
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).decode("ascii")
                except RuntimeError as exc:
                    abort(503, str(exc))
                credential_updates[provider] = encrypted_credentials

        now = datetime.now(timezone.utc).isoformat()
        with database_connection() as connection:
            for name, value in values.items():
                connection.execute(
                    """
                    INSERT INTO policies (name, value, updated_at, updated_by)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(name) DO UPDATE SET
                        value = excluded.value,
                        updated_at = excluded.updated_at,
                        updated_by = excluded.updated_by
                    """,
                    (name, value, now, session["user_id"]),
                )
            for provider, encrypted_credentials in credential_updates.items():
                setting_name = f"{provider}_oauth_credentials"
                if encrypted_credentials is None:
                    connection.execute(
                        "DELETE FROM policies WHERE name = ?", (setting_name,)
                    )
                else:
                    connection.execute(
                        """
                        INSERT INTO policies (name, value, updated_at, updated_by)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(name) DO UPDATE SET
                            value = excluded.value,
                            updated_at = excluded.updated_at,
                            updated_by = excluded.updated_by
                        """,
                        (
                            setting_name,
                            encrypted_credentials,
                            now,
                            session["user_id"],
                        ),
                    )
        audit_event("update_website_security_settings", "settings", "policies", json.dumps(values, sort_keys=True))
        if credential_updates:
            audit_event(
                "update_oauth_credentials",
                "settings",
                "oauth",
                ",".join(sorted(credential_updates)),
            )
        flash("Website and login security settings updated.")
    with database_connection() as connection:
        rows = connection.execute(
            """
            SELECT name, value FROM policies
            WHERE name IN (
                'allow_registration', 'allow_public_sharing', 'trash_retention_days',
                'allow_google_signin', 'allow_github_signin', 'login_max_attempts',
                'login_window_minutes', 'login_lockout_minutes'
            )
            """
        ).fetchall()
    values = {row["name"]: row["value"] for row in rows}
    login_protection = login_security_settings()
    google_client_id, _ = oauth_provider_credentials("google")
    github_client_id, _ = oauth_provider_credentials("github")
    settings = {
        "allow_registration": values.get("allow_registration", "1") == "1",
        "allow_public_sharing": values.get("allow_public_sharing", "0") == "1",
        "allow_google_signin": values.get("allow_google_signin", "1") == "1",
        "allow_github_signin": values.get("allow_github_signin", "1") == "1",
        "google_oauth_configured": oauth_credentials_configured("google"),
        "github_oauth_configured": oauth_credentials_configured("github"),
        "google_oauth_admin_managed": oauth_credentials_admin_managed("google"),
        "github_oauth_admin_managed": oauth_credentials_admin_managed("github"),
        "google_oauth_client_id": google_client_id,
        "github_oauth_client_id": github_client_id,
        "trash_retention_days": values.get("trash_retention_days", "30"),
        **login_protection,
    }
    return render_template_string(ADMIN_SETTINGS_PAGE, settings=settings)


@app.route("/admin")
def admin_panel():
    response = require_admin_access()
    if response:
        return response
    admin_context = admin_console_context()
    can_view_recovery = admin_context["can_view_recovery"]
    cutoff = datetime.now(timezone.utc) - timedelta(days=INACTIVE_USER_DAYS)
    users = []
    with database_connection() as connection:
        total_users = connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        active_users = connection.execute("SELECT COUNT(*) AS count FROM users WHERE status = 'active'").fetchone()["count"]
        new_users = connection.execute("SELECT COUNT(*) AS count FROM users WHERE created_at >= ?", ((datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),)).fetchone()["count"]
        pending_reviews = connection.execute("SELECT (SELECT COUNT(*) FROM password_requests WHERE status = 'pending') + (SELECT COUNT(*) FROM payment_requests WHERE status = 'pending') AS count").fetchone()["count"]
        failed_logins = connection.execute("SELECT COUNT(*) AS count FROM login_attempts WHERE success = 0 AND attempted_at >= ?", ((datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),)).fetchone()["count"]
        open_alerts = connection.execute("SELECT COUNT(*) AS count FROM security_alerts WHERE status = 'open'").fetchone()["count"]
        recent_events = connection.execute("SELECT audit_events.*, users.username AS actor FROM audit_events LEFT JOIN users ON users.id = audit_events.actor_id ORDER BY audit_events.created_at DESC LIMIT 12").fetchall()
        provider_counts_row = connection.execute(
            """
            SELECT COUNT(*) AS total,
                SUM(CASE WHEN password_login_enabled = 1 THEN 1 ELSE 0 END) AS password,
                SUM(CASE WHEN google_sub IS NOT NULL THEN 1 ELSE 0 END) AS google,
                SUM(CASE WHEN github_sub IS NOT NULL THEN 1 ELSE 0 END) AS github
            FROM users
            """
        ).fetchone()
        provider_counts = {
            key: provider_counts_row[column] or 0
            for key, column in (
                ("all", "total"),
                ("password", "password"),
                ("google", "google"),
                ("github", "github"),
            )
        }
        account_type = request.args.get("account_type", "all")
        if account_type not in ADMIN_ACCOUNT_FILTERS:
            abort(400, "Invalid account type filter")
        rows = connection.execute(
            f"""
            SELECT id, username, created_at, last_seen, is_admin, status, email,
                password_login_enabled, google_sub, google_email,
                google_profile_name, google_username, google_picture,
                github_sub, github_email, github_profile_name,
                github_username, github_picture
            FROM users
            ORDER BY is_admin DESC, username COLLATE NOCASE
            """
        ).fetchall()
        recovery_rows = connection.execute("""
                 SELECT password_requests.id, users.username, users.email AS account_email,
                     users.mobile AS account_mobile, users.date_of_birth AS account_dob,
                     password_requests.email, password_requests.mobile, password_requests.date_of_birth,
                   password_requests.created_at
            FROM password_requests
            JOIN users ON users.id = password_requests.user_id
            WHERE password_requests.status = 'pending'
            ORDER BY password_requests.created_at ASC
        """).fetchall() if can_view_recovery else []
    total_files = 0
    total_bytes = 0
    for row in rows:
        try:
            inactive = not row["last_seen"] or datetime.fromisoformat(row["last_seen"]) < cutoff
        except ValueError:
            inactive = True
        files, bytes_used = user_statistics(row["id"])
        total_files += files
        total_bytes += bytes_used
        if (
            account_type == "password" and not row["password_login_enabled"]
            or account_type == "google" and not row["google_sub"]
            or account_type == "github" and not row["github_sub"]
        ):
            continue
        user = dict(row)
        auth_methods = []
        if user["password_login_enabled"]:
            auth_methods.append("Password")
        if user["google_sub"]:
            auth_methods.append("Google")
        if user["github_sub"]:
            auth_methods.append("GitHub")
        user.update(
            inactive=inactive,
            files=files,
            bytes=bytes_used,
            auth_methods=auth_methods or ["Unavailable"],
            picture_url=user["google_picture"] or user["github_picture"],
        )
        users.append(user)
    dashboard = {"total_users": total_users, "active_users": active_users, "new_users": new_users, "pending_reviews": pending_reviews, "inactive_users": total_users - active_users, "total_files": total_files, "total_bytes": total_bytes, "failed_logins": failed_logins, "open_alerts": open_alerts, "read_only": emergency_enabled("global_read_only"), "uploads_disabled": emergency_enabled("disable_uploads"), "downloads_disabled": emergency_enabled("disable_downloads"), "maintenance": emergency_enabled("maintenance_mode")}
    return render_template_string(
        ADMIN_PAGE,
        title=admin_context["admin_title"],
        users=users,
        current_user_id=session["user_id"],
        inactive_days=INACTIVE_USER_DAYS,
        recovery_requests=[dict(row) for row in recovery_rows],
        dashboard=dashboard,
        recent_events=[dict(row) for row in recent_events],
        provider_counts=provider_counts,
        account_type=account_type,
        **admin_context,
    )


@app.route("/admin/users/report.csv")
def admin_user_report():
    response = require_permission("users.view")
    if response:
        return response

    account_type = request.args.get("account_type", "all")
    if account_type not in ADMIN_ACCOUNT_FILTERS:
        abort(400, "Invalid account type filter")

    with database_connection() as connection:
        rows = connection.execute(
            f"""
            SELECT username, email, password_login_enabled,
                google_sub, google_email, google_profile_name, google_username,
                github_sub, github_email, github_profile_name, github_username,
                created_at, last_login_at, last_seen, status
            FROM users
            {ADMIN_ACCOUNT_FILTERS[account_type]}
            ORDER BY username COLLATE NOCASE
            """
        ).fetchall()

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        (
            "Cloud Rdx username",
            "Cloud Rdx email",
            "Sign-in methods",
            "Google profile",
            "Google email",
            "GitHub username",
            "GitHub email",
            "Created at",
            "Last login",
            "Last seen",
            "Status",
        )
    )
    for row in rows:
        methods = []
        if row["password_login_enabled"]:
            methods.append("Password")
        if row["google_sub"]:
            methods.append("Google")
        if row["github_sub"]:
            methods.append("GitHub")
        values = (
            row["username"],
            row["email"],
            " + ".join(methods) or "Unavailable",
            row["google_username"] or row["google_profile_name"],
            row["google_email"],
            row["github_username"] or row["github_profile_name"],
            row["github_email"],
            row["created_at"],
            row["last_login_at"],
            row["last_seen"],
            row["status"],
        )
        writer.writerow([spreadsheet_safe_cell(value) for value in values])

    report = make_response(output.getvalue())
    report.headers["Content-Type"] = "text/csv; charset=utf-8"
    report.headers["Content-Disposition"] = 'attachment; filename="cloud-rdx-users.csv"'
    report.headers["Cache-Control"] = "no-store"
    return report


@app.route("/admin/profit")
def admin_profit():
    response = require_owner()
    if response:
        return response
    cutoff = datetime.now(timezone.utc) - timedelta(days=INACTIVE_USER_DAYS)
    with database_connection() as connection:
        users = connection.execute(
            "SELECT id, status, created_at, last_seen FROM users WHERE username != ? COLLATE NOCASE",
            (ADMIN_USERNAME,),
        ).fetchall()
        payment_totals = connection.execute("""
            SELECT
                COALESCE(SUM(CASE WHEN status = 'approved' THEN amount_paise ELSE 0 END), 0) AS approved_paise,
                COALESCE(SUM(CASE WHEN status = 'pending' THEN amount_paise ELSE 0 END), 0) AS pending_paise,
                COALESCE(SUM(CASE WHEN status = 'rejected' THEN amount_paise ELSE 0 END), 0) AS rejected_paise,
                SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved_count,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_count,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected_count
            FROM payment_requests
        """).fetchone()
        active_subscriptions = connection.execute("""
            SELECT COUNT(*) AS count
            FROM subscriptions
            JOIN users ON users.id = subscriptions.user_id
            WHERE subscriptions.status = 'active' AND users.username != ? COLLATE NOCASE
        """, (ADMIN_USERNAME,)).fetchone()["count"]
        active_sessions = connection.execute("""
            SELECT COUNT(*) AS count FROM device_sessions
            JOIN users ON users.id = device_sessions.user_id
            WHERE device_sessions.revoked_at IS NULL AND users.username != ? COLLATE NOCASE
        """, (ADMIN_USERNAME,)).fetchone()["count"]
        plan_rows_for_summary = connection.execute("""
            SELECT storage_plans.name, storage_plans.price_paise,
                   COUNT(subscriptions.id) AS subscribers,
                   COALESCE(SUM(subscriptions.quota_bytes), 0) AS capacity
            FROM storage_plans
            LEFT JOIN subscriptions
              ON subscriptions.plan_id = storage_plans.id AND subscriptions.status = 'active'
            WHERE storage_plans.active = 1
            GROUP BY storage_plans.id
            ORDER BY storage_plans.quota_bytes
        """).fetchall()

    total_users = len(users)
    active_users = 0
    suspended_users = 0
    new_users = 0
    total_files = 0
    used_bytes = 0
    quota_bytes = 0
    for user in users:
        try:
            recently_seen = bool(user["last_seen"] and datetime.fromisoformat(user["last_seen"]) >= cutoff)
        except ValueError:
            recently_seen = False
        if user["status"] == "active" and recently_seen:
            active_users += 1
        if user["status"] == "suspended":
            suspended_users += 1
        try:
            if datetime.fromisoformat(user["created_at"]) >= datetime.now(timezone.utc) - timedelta(days=30):
                new_users += 1
        except (TypeError, ValueError):
            pass
        files, bytes_used = user_statistics(user["id"])
        total_files += files
        used_bytes += bytes_used
        quota_bytes += user_quota(user["id"])

    revenue = payment_totals["approved_paise"] / 100
    pending_revenue = payment_totals["pending_paise"] / 100
    rejected_revenue = payment_totals["rejected_paise"] / 100
    used_gb = used_bytes / (1024 ** 3)
    estimated_cost = used_gb * STORAGE_COST_PER_GB_INR
    capacity_percent = min(100, round(used_bytes * 100 / quota_bytes, 1)) if quota_bytes else 0
    plan_summary = [dict(row) for row in plan_rows_for_summary]
    monthly_plan_value = sum(row["price_paise"] * row["subscribers"] for row in plan_summary) / 100
    metrics = {
        "revenue": revenue,
        "estimated_cost": estimated_cost,
        "net_profit": revenue - estimated_cost,
        "pending_revenue": pending_revenue,
        "pending_payments": int(payment_totals["pending_count"] or 0),
        "approved_payments": int(payment_totals["approved_count"] or 0),
        "rejected_payments": int(payment_totals["rejected_count"] or 0),
        "rejected_revenue": rejected_revenue,
        "total_users": total_users,
        "active_users": active_users,
        "inactive_users": total_users - active_users,
        "suspended_users": suspended_users,
        "new_users": new_users,
        "active_sessions": active_sessions,
        "used_bytes": used_bytes,
        "quota_bytes": quota_bytes,
        "remaining_bytes": max(0, quota_bytes - used_bytes),
        "total_files": total_files,
        "average_usage": used_bytes / total_users if total_users else 0,
        "capacity_percent": capacity_percent,
        "active_subscriptions": active_subscriptions,
        "monthly_plan_value": monthly_plan_value,
        "cost_per_gb": STORAGE_COST_PER_GB_INR,
    }
    return render_template_string(
        ADMIN_PROFIT_PAGE,
        metrics=metrics,
        plan_summary=plan_summary,
        inactive_days=INACTIVE_USER_DAYS,
        owner_username=ADMIN_USERNAME,
    )


@app.route("/admin/intelligence")
def admin_intelligence():
    response = require_owner()
    if response:
        return response
    return render_template_string(
        ADMIN_INTELLIGENCE_PAGE,
        ranges=(
            ("24h", "24 hours"),
            ("7d", "7 days"),
            ("30d", "30 days"),
            ("180d", "6 months"),
            ("365d", "1 year"),
        ),
    )


@app.route("/api/admin/analytics/overview")
def admin_analytics_overview():
    response = require_owner()
    if response:
        return jsonify({"error": "administrator_required"}), 401
    cutoff_active = (
        datetime.now(timezone.utc) - timedelta(days=INACTIVE_USER_DAYS)
    ).isoformat()
    cutoff_login = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    with database_connection() as connection:
        users = connection.execute(
            """
            SELECT id, username, status, created_at, last_seen
            FROM users WHERE username != ? COLLATE NOCASE
            ORDER BY username COLLATE NOCASE
            """,
            (ADMIN_USERNAME,),
        ).fetchall()
        session_count = connection.execute(
            """
            SELECT COUNT(*) AS count FROM device_sessions
            JOIN users ON users.id = device_sessions.user_id
            WHERE device_sessions.revoked_at IS NULL
              AND users.username != ? COLLATE NOCASE
            """,
            (ADMIN_USERNAME,),
        ).fetchone()["count"]
        payment = connection.execute(
            """
            SELECT COALESCE(SUM(amount_paise), 0) AS amount,
                   COUNT(*) AS count
            FROM payment_requests WHERE status = 'approved'
            """
        ).fetchone()
        failed_logins = connection.execute(
            """
            SELECT COUNT(*) AS count FROM login_attempts
            WHERE success = 0 AND attempted_at >= ?
            """,
            (cutoff_login,),
        ).fetchone()["count"]
        open_alerts = connection.execute(
            "SELECT COUNT(*) AS count FROM security_alerts WHERE status = 'open'"
        ).fetchone()["count"]
        now_epoch = int(datetime.now(timezone.utc).timestamp())
        api_requests = connection.execute(
            """
            SELECT COALESCE(SUM(request_count), 0) AS count,
                   COALESCE(SUM(blocked_count), 0) AS blocked
            FROM rate_limit_buckets
            WHERE endpoint = 'api' AND window_started_at >= ?
            """,
            (now_epoch - 86400,),
        ).fetchone()

    categories = {
        "Images": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".heic"},
        "Videos": {".mp4", ".mov", ".avi", ".mkv", ".webm", ".m4v"},
        "Audio": {".mp3", ".wav", ".aac", ".flac", ".ogg", ".m4a"},
        "Documents": {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv"},
        "Archives": {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"},
        "Applications": {".exe", ".msi", ".apk", ".app", ".deb", ".rpm"},
    }
    category_totals = {
        name: {"category": name, "files": 0, "bytes": 0}
        for name in (*categories, "Other")
    }
    total_files = 0
    total_bytes = 0
    total_quota = 0
    active_users = 0
    top_storage = []
    for user in users:
        files = 0
        used = 0
        root = SHARED_FOLDER / "users" / str(user["id"])
        if root.exists():
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                try:
                    file_size = path.stat().st_size
                except OSError:
                    app.logger.warning("analytics_file_stat_failed path=%s", path.name)
                    continue
                files += 1
                used += file_size
                suffix = path.suffix.lower()
                category = next(
                    (name for name, extensions in categories.items() if suffix in extensions),
                    "Other",
                )
                category_totals[category]["files"] += 1
                category_totals[category]["bytes"] += file_size
        total_files += files
        total_bytes += used
        total_quota += user_quota(user["id"])
        if user["status"] == "active" and user["last_seen"] and user["last_seen"] >= cutoff_active:
            active_users += 1
        top_storage.append(
            {"username": user["username"], "files": files, "bytes": used}
        )
    top_storage.sort(key=lambda item: item["bytes"], reverse=True)
    storage_percent = (
        round(total_bytes * 100 / total_quota, 1) if total_quota else None
    )
    cost = (
        total_bytes / (1024**3) * STORAGE_COST_PER_GB_INR
        if os.getenv("STORAGE_COST_PER_GB_INR") is not None
        else None
    )
    try:
        disk_free = shutil.disk_usage(SHARED_FOLDER).free
    except OSError:
        app.logger.exception("analytics_host_disk_usage_failed")
        disk_free = None
    controls = emergency_control_state()
    active_control_count = sum(controls.values())
    if controls["maintenance_mode"]:
        status = "MAINTENANCE"
    elif controls["global_read_only"] and controls["disable_downloads"]:
        status = "LOCKDOWN"
    elif controls["enhanced_monitoring"] or open_alerts:
        status = "SECURITY ALERT"
    elif active_control_count:
        status = "RESTRICTED"
    else:
        status = "NORMAL"
    return jsonify(
        {
            "status": status,
            "users": {
                "total": len(users),
                "active": active_users,
                "inactive": max(0, len(users) - active_users),
                "top_storage": top_storage[:5],
            },
            "sessions": {"active": session_count},
            "storage": {
                "used_bytes": total_bytes,
                "quota_bytes": total_quota,
                "files": total_files,
                "remaining_bytes": max(0, total_quota - total_bytes),
                "utilization_percent": storage_percent,
                "categories": list(category_totals.values()),
            },
            "finance": {
                "collected_revenue": payment["amount"] / 100,
                "approved_payment_count": payment["count"],
                "estimated_storage_cost": cost,
                "estimated_net": None,
                "cost_basis": (
                    "configured_per_gb_estimate"
                    if cost is not None
                    else "unavailable"
                ),
            },
            "security": {
                "failed_logins_24h": failed_logins,
                "open_alerts": open_alerts,
                "api_requests_24h": int(api_requests["count"]),
                "blocked_api_requests_24h": int(api_requests["blocked"]),
            },
            "host": {"disk_free_bytes": disk_free},
            "data_availability": {
                "bandwidth": False,
                "geography": False,
                "cpu": False,
                "memory": False,
                "request_latency": False,
                "scheduled_backups": False,
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    )


@app.route("/api/admin/analytics/activity")
def admin_analytics_activity():
    response = require_owner()
    if response:
        return jsonify({"error": "administrator_required"}), 401
    range_key = request.args.get("range", "7d")
    range_days = {"24h": 1, "7d": 7, "30d": 30, "180d": 180, "365d": 365}
    if range_key not in range_days:
        return jsonify({"error": "invalid_range"}), 400
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=range_days[range_key])
    with database_connection() as connection:
        grouping = "substr(created_at, 1, 13)" if range_key == "24h" else "substr(created_at, 1, 10)"
        rows = connection.execute(
            f"""
            SELECT {grouping} AS bucket, COUNT(*) AS operations
            FROM audit_events
            WHERE created_at >= ?
              AND action IN ('upload', 'bulk_download', 'create_folder',
                             'rename', 'copy', 'move', 'delete',
                             'restore_from_trash', 'restore_own_trash',
                             'purge_trash', 'purge_own_trash', 'login',
                             'google_login', 'github_login')
            GROUP BY bucket ORDER BY bucket
            """,
            (cutoff.isoformat(),),
        ).fetchall()
    points = [
        {"time": row["bucket"], "operations": int(row["operations"])}
        for row in rows
    ]
    labels = {
        "24h": "24 hours",
        "7d": "7 days",
        "30d": "30 days",
        "180d": "6 months",
        "365d": "1 year",
    }
    return jsonify(
        {
            "range": range_key,
            "range_label": labels[range_key],
            "points": points,
            "total_operations": sum(point["operations"] for point in points),
            "source": "audit_events",
        }
    )


@app.route("/admin/manage")
def admin_manage():
    response = require_permission("users.manage")
    if response:
        return response
    cutoff = datetime.now(timezone.utc) - timedelta(days=INACTIVE_USER_DAYS)
    with database_connection() as connection:
        rows = connection.execute("SELECT id, username, status, is_admin FROM users ORDER BY username COLLATE NOCASE").fetchall()
        groups = connection.execute("""
            SELECT groups.id, groups.name, groups.description, COUNT(group_members.user_id) AS members
            FROM groups LEFT JOIN group_members ON group_members.group_id = groups.id
            GROUP BY groups.id ORDER BY groups.name COLLATE NOCASE
        """).fetchall()
        events = connection.execute("""
            SELECT audit_events.*, users.username AS actor
            FROM audit_events LEFT JOIN users ON users.id = audit_events.actor_id
            ORDER BY audit_events.created_at DESC LIMIT 100
        """).fetchall()
        role_rows = connection.execute("""
            SELECT user_roles.user_id, roles.name FROM user_roles JOIN roles ON roles.id = user_roles.role_id
        """).fetchall()
        roles = connection.execute("SELECT name, description FROM roles WHERE name != ? ORDER BY name", (ADMIN_ROLE,)).fetchall()
    roles_by_user = {}
    for row in role_rows:
        roles_by_user.setdefault(row["user_id"], []).append(row["name"])
    users = []
    for row in rows:
        files, bytes_used = user_usage(row["id"])
        quota = user_quota(row["id"])
        users.append({**dict(row), "files": files, "bytes": bytes_used, "quota_mb": quota // (1024 * 1024), "roles": roles_by_user.get(row["id"], [])})
    return render_template_string(
        ADMIN_MANAGEMENT_PAGE,
        users=users,
        groups=[dict(row) for row in groups],
        roles=[dict(row) for row in roles],
        events=[dict(row) for row in events],
        owner_username=ADMIN_USERNAME,
        is_owner=is_owner(),
    )


@app.route("/admin/permissions")
def admin_permissions():
    response = require_owner()
    if response:
        return response
    permission_catalog = (
        ("users.view", "View user accounts"),
        ("users.manage", "Activate, suspend, and manage users"),
        ("users.recovery", "Review password recovery requests"),
        ("storage.manage", "Manage storage quotas and files"),
        ("storage.recycle_bin", "Restore and purge recycle-bin items"),
        ("payments.review", "Review storage payments"),
        ("audit.view", "View audit activity"),
        ("storage.upload", "Upload files"),
        ("storage.download", "Download files"),
        ("storage.share", "Share files"),
        ("storage.delete", "Delete files"),
        ("storage.rename", "Rename files"),
        ("storage.create_folder", "Create folders"),
        ("security.manage", "Manage security controls"),
        ("settings.manage", "Manage system settings"),
    )
    with database_connection() as connection:
        rows = connection.execute("SELECT id, name, description FROM roles WHERE name != ? ORDER BY name", (ADMIN_ROLE,)).fetchall()
        assigned = connection.execute("SELECT role_id, permission FROM role_permissions").fetchall()
    assigned_by_role = {}
    for row in assigned:
        assigned_by_role.setdefault(row["role_id"], set()).add(row["permission"])
    roles = [{**dict(row), "permissions": assigned_by_role.get(row["id"], set())} for row in rows]
    permissions = [{"key": key, "label": label} for key, label in permission_catalog]
    return render_template_string(ADMIN_PERMISSIONS_PAGE, roles=roles, permissions=permissions)


@app.route("/admin/permissions/<int:role_id>", methods=["POST"])
def admin_role_permissions(role_id):
    response = require_owner()
    if response:
        return response
    allowed = {"users.view", "users.manage", "users.recovery", "storage.manage", "storage.recycle_bin", "payments.review", "audit.view", "storage.upload", "storage.download", "storage.share", "storage.delete", "storage.rename", "storage.create_folder", "security.manage", "settings.manage"}
    selected = set(request.form.getlist("permissions")) & allowed
    now = datetime.now(timezone.utc).isoformat()
    with database_connection() as connection:
        role = connection.execute("SELECT id, name FROM roles WHERE id = ? AND name != ?", (role_id, ADMIN_ROLE)).fetchone()
        if not role:
            abort(404, "Delegated role not found")
        connection.execute("DELETE FROM role_permissions WHERE role_id = ?", (role_id,))
        connection.executemany("INSERT INTO role_permissions (role_id, permission, assigned_at, assigned_by) VALUES (?, ?, ?, ?)", [(role_id, permission, now, session["user_id"]) for permission in sorted(selected)])
    audit_event("update_role_permissions", "role", role_id, f"role={role['name']}; permissions={','.join(sorted(selected))}")
    flash(f"Permissions updated for {role['name']}.")
    return redirect(url_for("admin_permissions"))


@app.route("/admin/roles/create", methods=["POST"])
def admin_role_create():
    response = require_owner()
    if response:
        return response
    name = request.form.get("name", "").strip().lower()
    description = request.form.get("description", "").strip()
    if not name or not re.fullmatch(r"[a-z0-9_-]{2,48}", name) or name == ADMIN_ROLE:
        flash("Role names must be 2-48 characters using letters, numbers, underscores, or hyphens.")
        return redirect(url_for("admin_permissions"))
    try:
        with database_connection() as connection:
            connection.execute("INSERT INTO roles (name, description) VALUES (?, ?)", (name, description[:160]))
    except sqlite3.IntegrityError:
        flash("That role already exists.")
    else:
        audit_event("create_role", "role", name, description)
        flash(f"Role {name} created.")
    return redirect(url_for("admin_permissions"))


ADMIN_SECURITY_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Security center - Cloud Rdx</title><link rel="stylesheet" href="{{ url_for('static', filename='admin-theme.css') }}"></head>
<body class="admin-theme"><main class="main"><header class="topbar"><div><p class="eyebrow">Cloud Rdx / security</p><h1>Security center</h1><p class="subtitle">Defensive monitoring based on authentication and audit telemetry.</p></div><a class="button" href="{{ url_for('admin_panel') }}">Dashboard</a></header>
{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}{% endwith %}
<section class="panel"><div class="panel-head"><h2>Open alerts</h2><p>Review suspicious activity without exposing passwords or credentials.</p></div><div class="table-responsive"><table><thead><tr><th>Severity</th><th>Type</th><th>Account / IP</th><th>Details</th><th>Created</th><th></th></tr></thead><tbody>{% for alert in alerts %}<tr><td>{{ alert.severity }}</td><td>{{ alert.alert_type }}</td><td>{{ alert.username or 'Unknown' }}<br>{{ alert.ip_address or 'Unknown' }}</td><td>{{ alert.details }}</td><td>{{ alert.created_at|prettydate }}</td><td><form method="post" action="{{ url_for('admin_security_alert_review', alert_id=alert.id) }}"><button type="submit">Mark reviewed</button></form></td></tr>{% else %}<tr><td colspan="6">No open security alerts.</td></tr>{% endfor %}</tbody></table></div></section>
<section class="panel"><div class="panel-head"><h2>Rate-limit events (last 24 hours)</h2><p>Aggregate counts only; client identifiers are stored as keyed hashes.</p></div><div class="table-responsive"><table><thead><tr><th>Endpoint group</th><th>Scope</th><th>Requests</th><th>Blocked</th><th>Latest window</th></tr></thead><tbody>{% for item in rate_limits %}<tr><td>{{ item.endpoint }}</td><td>{{ item.scope }}</td><td>{{ item.requests }}</td><td>{{ item.blocked }}</td><td>{{ item.last_event|prettydate }}</td></tr>{% else %}<tr><td colspan="5">No rate-limit events recorded.</td></tr>{% endfor %}</tbody></table></div></section>
</main></body></html>
"""


@app.route("/admin/security")
def admin_security():
    response = require_owner()
    if response:
        return response
    with database_connection() as connection:
        alerts = connection.execute("SELECT * FROM security_alerts WHERE status = 'open' ORDER BY created_at DESC LIMIT 250").fetchall()
        cutoff = int(datetime.now(timezone.utc).timestamp()) - 86400
        rate_limit_rows = connection.execute(
            """
            SELECT endpoint, scope, SUM(request_count) AS requests,
                   SUM(blocked_count) AS blocked, MAX(window_started_at) AS last_event
            FROM rate_limit_buckets
            WHERE blocked_count > 0 AND window_started_at >= ?
            GROUP BY endpoint, scope
            ORDER BY last_event DESC
            LIMIT 50
            """,
            (cutoff,),
        ).fetchall()
    rate_limits = [
        {
            **dict(row),
            "last_event": datetime.fromtimestamp(row["last_event"], timezone.utc).isoformat(),
        }
        for row in rate_limit_rows
    ]
    return render_template_string(
        ADMIN_SECURITY_PAGE, alerts=[dict(row) for row in alerts], rate_limits=rate_limits
    )


@app.route("/admin/security/alerts/<int:alert_id>/review", methods=["POST"])
def admin_security_alert_review(alert_id):
    response = require_owner()
    if response:
        return response
    with database_connection() as connection:
        result = connection.execute("UPDATE security_alerts SET status = 'reviewed', reviewed_by = ?, reviewed_at = ? WHERE id = ? AND status = 'open'", (session["user_id"], datetime.now(timezone.utc).isoformat(), alert_id))
    if not result.rowcount:
        abort(404, "Security alert not found")
    audit_event("review_security_alert", "security_alert", alert_id)
    flash("Security alert marked as reviewed.")
    return redirect(url_for("admin_security"))


ADMIN_EMERGENCY_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Emergency Control Centre - Cloud Rdx</title>
<link rel="stylesheet" href="{{ url_for('static', filename='admin-theme.css') }}">
<style>
.emergency{--ec-bg:#0b1220;--ec-panel:#111c2d;--ec-line:#24344d;--ec-text:#e7eef9;--ec-muted:#9aabc2;max-width:1500px;margin:0 auto;color:var(--ec-text)}
.emergency .topbar{margin-bottom:24px;background:#111c2d;border:1px solid var(--ec-line);border-radius:14px}
.emergency .eyebrow{color:#61d5c4}.emergency h1{color:#f4f7fb}.emergency .subtitle,.emergency .muted{color:var(--ec-muted)}
.emergency .panel,.emergency .card{margin-bottom:18px;color:var(--ec-text);background:var(--ec-panel);border:1px solid var(--ec-line);border-radius:14px;box-shadow:0 12px 32px #02061755}
.emergency .panel-head,.emergency .head{border-color:var(--ec-line)}.emergency .panel-head h2,.emergency .head h2{color:#f4f7fb}
.ec-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;padding:18px}
.ec-stat{padding:16px;background:#0d1727;border:1px solid #263750;border-radius:11px}.ec-stat small{display:block;color:var(--ec-muted);font-size:10px;letter-spacing:.08em;text-transform:uppercase}.ec-stat strong{display:block;margin-top:8px;font-size:22px}.ec-status{display:flex;align-items:center;gap:10px;padding:18px 22px;border-bottom:1px solid var(--ec-line)}
.ec-dot{width:11px;height:11px;flex:0 0 11px;background:#34d399;border-radius:50%;box-shadow:0 0 14px currentColor}.ec-dot.restricted{background:#fbbf24}.ec-dot.security{background:#fb923c}.ec-dot.lockdown,.ec-dot.maintenance{background:#fb7185}
.ec-presets{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;padding:18px}
.ec-preset{min-height:74px;color:#eff6ff!important;background:#17243a!important;border-color:#32445f!important;border-radius:10px!important;text-align:left}
.ec-preset:hover{background:#233653!important;transform:translateY(-2px)}.ec-preset.danger{background:#552338!important;border-color:#a13e5c!important}
.ec-controls{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;padding:18px}
.ec-control{display:flex;justify-content:space-between;align-items:center;gap:12px;min-height:84px;padding:14px;background:#0d1727;border:1px solid #263750;border-radius:10px}
.ec-control strong{display:block;font-size:13px}.ec-control small{display:block;margin-top:5px;color:var(--ec-muted);font:11px/1.4 Arial,sans-serif}
.ec-control input[type=checkbox]{width:20px;height:20px;flex:0 0 20px;accent-color:#fb7185}.ec-control input:disabled{opacity:.4}
.ec-control.unavailable{opacity:.72;border-style:dashed}
.ec-form-footer{display:flex;flex-wrap:wrap;gap:10px;align-items:end;padding:0 18px 18px}
.ec-form-footer label,.incident-form label{display:grid;gap:6px;color:var(--ec-muted);font-size:11px}.ec-form-footer input,.incident-form input,.incident-form select,.incident-form textarea,.ec-note{color:var(--ec-text)!important;background:#0b1423!important;border-color:#354962!important}
.incident-form{display:grid;grid-template-columns:1.2fr .7fr 1fr;gap:12px;padding:18px}.incident-form .wide{grid-column:1/-1}.incident-form textarea{min-height:80px;resize:vertical}
.ec-freeze-forms{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;padding:18px}
.ec-freeze-forms form{display:grid;gap:10px;padding:14px;background:#0d1727;border:1px solid #263750;border-radius:10px}
.ec-severity{font-weight:800}.sev-LOW{color:#34d399}.sev-MEDIUM{color:#fbbf24}.sev-HIGH{color:#fb923c}.sev-CRITICAL{color:#fb7185}
.ec-incidents{display:grid;gap:12px;padding:18px}.ec-incident{padding:16px;background:#0d1727;border:1px solid #263750;border-radius:11px}
.ec-incident-head{display:flex;justify-content:space-between;gap:12px;align-items:start}.ec-incident h3{margin:0 0 6px;font-size:15px}.ec-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}.ec-actions form{display:flex;gap:7px;align-items:center}
.ec-log-wrap{overflow:auto}.ec-log{min-width:860px}.ec-log td,.ec-log th{color:#dce6f5;border-color:#24344d}.ec-log th{background:#162339}.ec-log tr:hover td{background:#162339}
.ec-empty{padding:20px;color:var(--ec-muted);text-align:center}.ec-service-list{display:flex;flex-wrap:wrap;gap:9px}.ec-service-list label{display:flex;grid-auto-flow:column;align-items:center;gap:5px}
.ec-note{min-width:180px;padding:8px;border:1px solid;border-radius:6px}
.emergency dialog{width:min(520px,calc(100% - 28px));color:#e7eef9;background:#111c2d;border:1px solid #fb7185;border-radius:14px;box-shadow:0 20px 70px #000a}
.emergency dialog::backdrop{background:#020617c9;backdrop-filter:blur(3px)}.ec-dialog-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}
.emergency button.danger{background:#b42345!important;border-color:#d44965!important}.emergency :where(a,button,input,select,textarea):focus-visible{outline:3px solid #5eead4;outline-offset:3px}
@media(max-width:1000px){.ec-controls{grid-template-columns:repeat(2,minmax(0,1fr))}.ec-presets{grid-template-columns:repeat(3,minmax(0,1fr))}.ec-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:650px){.emergency{padding:0 6px}.emergency .topbar{display:grid;gap:12px;padding:16px}.ec-controls,.ec-grid,.ec-presets,.ec-freeze-forms{grid-template-columns:1fr}.incident-form{grid-template-columns:1fr}.incident-form .wide{grid-column:auto}.ec-incident-head{display:grid}.ec-form-footer{display:grid}.ec-form-footer>*{width:100%}}
@media(prefers-reduced-motion:reduce){.emergency *{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style></head>
<body class="admin-theme"><main class="main emergency">
<header class="topbar"><div><p class="eyebrow">CLOUD RDX / SECURITY OPERATIONS</p><h1>Emergency Control Centre</h1>
<p class="subtitle">Owner-only response controls, incident tracking, and a durable action ledger.</p></div>
<a class="button" href="{{ url_for('admin_panel') }}">Dashboard</a></header>
{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="flash" role="status">{{ message }}</div>{% endfor %}{% endwith %}
<section class="panel" aria-labelledby="system-status-heading">
<div class="ec-status"><span class="ec-dot {{ status_class }}" aria-hidden="true"></span><div><strong id="system-status-heading">SYSTEM STATUS · {{ system_status }}</strong><div class="muted">Last emergency action: {{ last_action or 'No emergency action recorded' }} · Admin: {{ last_admin or '—' }}</div></div></div>
<div class="ec-grid">
<article class="ec-stat"><small>Active controls</small><strong>{{ active_controls|length }}</strong></article>
<article class="ec-stat"><small>Affected user accounts</small><strong>{{ metrics.users }}</strong></article>
<article class="ec-stat"><small>Emergency-frozen accounts</small><strong>{{ metrics.frozen_accounts }}</strong></article>
<article class="ec-stat"><small>Active sessions</small><strong>{{ metrics.sessions }}</strong></article>
<article class="ec-stat"><small>Active incidents</small><strong>{{ metrics.incidents }}</strong></article>
<article class="ec-stat"><small>Blocked uploads</small><strong>{{ metrics.blocked_uploads }}</strong></article>
<article class="ec-stat"><small>Blocked downloads</small><strong>{{ metrics.blocked_downloads }}</strong></article>
<article class="ec-stat"><small>Blocked API requests</small><strong>{{ metrics.blocked_api }}</strong></article>
<article class="ec-stat"><small>Open security alerts</small><strong>{{ metrics.alerts }}</strong></article>
</div></section>

<section class="panel"><div class="panel-head"><h2>Emergency account freezes</h2><p>Freeze a single active account or eligible members of a group. Admin accounts and accounts already frozen/suspended are excluded. Restoring a freeze only reactivates accounts that were active before the freeze.</p></div>
<div class="ec-freeze-forms">
<form method="post" data-confirm="Freeze this user account? The user will be signed out and blocked from signing in until restored.">
<input type="hidden" name="action" value="freeze_accounts"><input type="hidden" name="scope" value="account">
<label>Account<select name="user_id" required><option value="">Select an active user</option>{% for target in freeze_targets %}<option value="{{ target.id }}">{{ target.username }}</option>{% endfor %}</select></label>
<label class="wide">Reason<input name="reason" maxlength="1000" required placeholder="Incident or security reason"></label>
<button class="danger" type="submit"{% if not freeze_targets %} disabled{% endif %}>Freeze account</button></form>
<form method="post" data-confirm="Freeze all eligible active non-admin members of this group?">
<input type="hidden" name="action" value="freeze_accounts"><input type="hidden" name="scope" value="group">
<label>Group<select name="group_id" required><option value="">Select a group</option>{% for group in freeze_groups %}<option value="{{ group.id }}">{{ group.name }} · {{ group.eligible_members }} eligible</option>{% endfor %}</select></label>
<label class="wide">Reason<input name="reason" maxlength="1000" required placeholder="Incident or security reason"></label>
<button class="danger" type="submit"{% if not freeze_groups %} disabled{% endif %}>Freeze group members</button></form>
</div>
<div class="ec-incidents">{% for freeze in freeze_batches %}<article class="ec-incident"><div class="ec-incident-head"><div><strong>{{ freeze.group_name or 'Individual account freeze' }}</strong><div class="muted">{{ freeze.account_count }} account(s) · {{ freeze.reason }} · {{ freeze.frozen_at[:19].replace('T',' ') }} UTC · {{ freeze.admin_name or 'Former administrator' }}</div></div>
<form method="post" data-confirm="Restore accounts in this freeze batch? Accounts that were already suspended before the freeze remain suspended."><input type="hidden" name="action" value="restore_account_freeze"><input type="hidden" name="freeze_batch_id" value="{{ freeze.freeze_batch_id }}"><button type="submit">Restore accounts</button></form></div></article>
{% else %}<div class="ec-empty">No emergency account freezes are active.</div>{% endfor %}</div></section>

<section class="panel"><div class="panel-head"><h2>Emergency presets</h2><p>Presets change only controls enforced by this application. Unavailable integrations remain visibly unavailable.</p></div>
<div class="ec-presets">{% for preset in presets %}<form method="post" data-confirm="Activate {{ preset }}?"{% if preset == 'FULL LOCKDOWN' %} data-confirm-phrase="CONFIRM LOCKDOWN"{% endif %}>
<input type="hidden" name="action" value="preset"><input type="hidden" name="preset" value="{{ preset }}">
<button class="ec-preset{% if preset == 'FULL LOCKDOWN' %} danger{% endif %}" type="submit"><strong>{{ preset }}</strong><br><small>{{ 'Restore normal app controls' if preset == 'NORMAL MODE' else 'Apply this incident profile' }}</small></button></form>{% endfor %}
<form method="post" data-confirm="Enable Maintenance Mode? Normal users will receive a maintenance page; owner access is retained.">
<input type="hidden" name="action" value="maintenance"><button class="ec-preset" type="submit"><strong>MAINTENANCE MODE</strong><br><small>Keep owner management available</small></button></form></div></section>

<section class="panel"><div class="panel-head"><h2>Access, file, and authentication controls</h2><p>Changes are persisted immediately after save and enforced server-side. Controls marked unavailable have no matching subsystem to protect.</p></div>
<form method="post" data-confirm="Save the selected emergency controls?"><input type="hidden" name="action" value="controls">
<div class="ec-controls">{% for name, item in controls.items() %}<label class="ec-control{% if not item.supported %} unavailable{% endif %}">
<span><strong>{{ item.label }}</strong><small>{{ item.description }}{% if not item.supported %} · NOT INTEGRATED{% endif %}</small></span>
<span><input type="hidden" name="{{ name }}" value="0"><input type="checkbox" name="{{ name }}" value="1" aria-label="{{ item.label }}" {% if item.enabled %}checked{% endif %}{% if not item.supported %} disabled{% endif %}></span>
</label>{% endfor %}</div>
<div class="ec-form-footer"><label for="control-reason">Reason (optional)<input id="control-reason" name="reason" maxlength="1000" placeholder="Incident or operational reason"></label><button type="submit">Save enforced controls</button></div></form></section>

<section class="panel"><div class="panel-head"><h2>Incident management</h2><p>Create and track response incidents. A restore never overwrites controls changed after the incident without explicit review.</p></div>
<form method="post" class="incident-form" id="incident-create-form" data-confirm="Create incident and activate the selected controls?">
<input type="hidden" name="action" value="create_incident">
<label>Incident title<input name="title" maxlength="160" required></label>
<label>Severity<select name="severity" required><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select></label>
<label>Preset<select name="preset" id="incident-preset" required>{% for preset in presets %}<option value="{{ preset }}"{% if preset == 'SECURITY MODE' %} selected{% endif %}>{{ preset }}</option>{% endfor %}</select></label>
<label class="wide">Reason / description<textarea name="description" maxlength="2000" required></textarea></label>
<div class="wide service-list" aria-label="Affected services">{% for service in services %}<label><input type="checkbox" name="services" value="{{ service }}"> {{ service|replace('_',' ')|title }}</label>{% endfor %}</div>
<div class="wide"><button class="danger" type="submit">Create incident & activate preset</button></div></form>
<div class="ec-incidents">{% for incident in incidents %}<article class="ec-incident"><div class="ec-incident-head"><div><h3>{{ incident.title }}</h3><span class="ec-severity sev-{{ incident.severity }}">{{ incident.severity }}</span> · {{ incident.status|upper }} · started {{ incident.started_at[:19].replace('T',' ') }} UTC · {{ incident.admin_name or 'Former administrator' }}</div><div class="muted">Affected services: {{ incident.services|join(', ') if incident.services else 'Not specified' }}</div></div>
<p class="muted">{{ incident.description }}</p>
{% if incident.status == 'active' %}<form method="post" class="ec-actions"><input type="hidden" name="action" value="incident_note"><input type="hidden" name="incident_id" value="{{ incident.id }}"><input class="ec-note" name="note" maxlength="1000" placeholder="Add incident note" required><button type="submit">Add note</button></form>
<div class="ec-actions"><form method="post"><input type="hidden" name="action" value="resolve_incident"><input type="hidden" name="incident_id" value="{{ incident.id }}"><button type="submit">Resolve incident</button></form>
<form method="post" data-confirm="Restore controls that still match the incident state? Controls changed since then will be left untouched."><input type="hidden" name="action" value="restore_incident"><input type="hidden" name="incident_id" value="{{ incident.id }}"><button type="submit">Restore previous state</button></form></div>
{% else %}<p class="muted">Resolved {{ incident.resolved_at[:19].replace('T',' ') if incident.resolved_at else '' }} UTC</p>{% endif %}
{% for note in incident.notes %}<p class="muted">• {{ note.created_at[:19].replace('T',' ') }} UTC — {{ note.admin_name or 'Former administrator' }}: {{ note.note }}</p>{% endfor %}</article>
{% else %}<div class="ec-empty">No incidents recorded.</div>{% endfor %}</div></section>

<section class="panel"><div class="panel-head"><h2>Emergency event log</h2><p>Append-only records of emergency changes, with actor, source IP, previous/new state, reason, affected users/services, outcome, and incident reference.</p><a href="{{ url_for('admin_audit') }}">View full audit log →</a></div>
<form method="get" class="ec-form-footer" aria-label="Filter emergency events">
<label>From<input type="date" name="date_from" value="{{ event_filters.date_from }}"></label>
<label>To<input type="date" name="date_to" value="{{ event_filters.date_to }}"></label>
<label>Administrator<input name="admin" maxlength="80" value="{{ event_filters.admin }}"></label>
<label>Action<input name="event_action" maxlength="120" value="{{ event_filters.action }}"></label>
<label>Severity<select name="severity"><option value="">Any</option>{% for severity in ['LOW','MEDIUM','HIGH','CRITICAL'] %}<option value="{{ severity }}"{% if event_filters.severity == severity %} selected{% endif %}>{{ severity }}</option>{% endfor %}</select></label>
<label>Incident ID<input type="number" min="1" name="incident" value="{{ event_filters.incident }}"></label>
<label>Affected user ID<input type="number" min="1" name="user" value="{{ event_filters.user }}"></label>
<label>IP address<input name="ip" maxlength="64" value="{{ event_filters.ip }}"></label>
<button type="submit">Filter events</button><a class="button" href="{{ url_for('admin_emergency') }}">Clear filters</a>
</form>
<div class="ec-log-wrap"><table class="ec-log"><thead><tr><th>Event</th><th>Timestamp</th><th>Administrator</th><th>IP</th><th>Action</th><th>Reason / affected</th><th>Result</th><th>Incident</th></tr></thead><tbody>
{% for event in events %}<tr><td>#{{ event.id }}</td><td>{{ event.created_at[:19].replace('T',' ') }} UTC</td><td>{{ event.admin_name or 'Former administrator' }}</td><td>{{ event.ip_address or 'Unknown' }}</td><td>{{ event.action }}</td><td>{{ event.reason or '—' }}<br><small>{{ event.affected_users }} users · {{ event.services|join(', ') }}</small></td><td>{{ event.result }}</td><td>{{ event.incident_id or '—' }}</td></tr>
{% else %}<tr><td colspan="8" class="ec-empty">No emergency events recorded.</td></tr>{% endfor %}</tbody></table></div></section>

<dialog id="emergency-confirm" aria-labelledby="confirm-title"><h2 id="confirm-title">Confirm emergency action</h2><p id="confirm-message"></p><label id="confirm-phrase-wrap" hidden>Type <strong id="confirm-phrase-text"></strong> to continue<input id="confirm-phrase-input" autocomplete="off"></label><div class="ec-dialog-actions"><button type="button" id="confirm-cancel">Cancel</button><button type="button" class="danger" id="confirm-proceed">Confirm action</button></div></dialog>
</main><script>
(() => {
 const dialog=document.getElementById('emergency-confirm'), message=document.getElementById('confirm-message');
 const phraseWrap=document.getElementById('confirm-phrase-wrap'), phraseInput=document.getElementById('confirm-phrase-input');
 const incidentPreset=document.getElementById('incident-preset');
 const incidentForm=document.getElementById('incident-create-form');
 const updateIncidentConfirmation=()=>{if(incidentPreset&&incidentForm){incidentForm.dataset.confirmPhrase=incidentPreset.value==='FULL LOCKDOWN'?'CONFIRM LOCKDOWN':''}};
 if(incidentPreset){incidentPreset.addEventListener('change',updateIncidentConfirmation);updateIncidentConfirmation()}
 let pending=null;
 document.querySelectorAll('form[data-confirm]').forEach(form=>form.addEventListener('submit',event=>{
   if(form.dataset.confirmed==='yes'){form.dataset.confirmed='';return}
   event.preventDefault(); pending=form; message.textContent=form.dataset.confirm;
   const phrase=form.dataset.confirmPhrase||''; phraseWrap.hidden=!phrase;
   document.getElementById('confirm-phrase-text').textContent=phrase; phraseInput.value='';
   dialog.showModal();
 }));
 document.getElementById('confirm-cancel').addEventListener('click',()=>dialog.close());
 document.getElementById('confirm-proceed').addEventListener('click',()=>{
   if(!pending)return;
   const required=pending.dataset.confirmPhrase||'';
   if(required&&phraseInput.value!==required){phraseInput.setCustomValidity('The confirmation text does not match.');phraseInput.reportValidity();phraseInput.setCustomValidity('');return}
   if(required){const input=document.createElement('input');input.type='hidden';input.name='confirmation_phrase';input.value=phraseInput.value;pending.appendChild(input)}
   pending.dataset.confirmed='yes';dialog.close();pending.requestSubmit();
 });
 dialog.addEventListener('close',()=>{pending=null});
})();
</script></body></html>
"""


@app.route("/admin/emergency", methods=["GET", "POST"])
def admin_emergency():
    response = require_owner()
    if response:
        return response
    enforced = {
        "global_read_only", "disable_uploads", "disable_downloads",
        "disable_deletion", "disable_editing", "disable_file_sharing",
        "revoke_active_share_links", "block_public_access",
        "disable_sync_automation", "block_new_devices",
        "freeze_registrations",
        "force_reauthentication", "force_password_reset", "require_two_factor",
        "disable_api_access", "enhanced_monitoring", "emergency_rate_limit",
        "maintenance_mode",
    }
    service_options = {
        "storage", "authentication", "sharing", "api", "backups", "database",
        "network",
    }
    if request.method == "POST":
        action = request.form.get("action", "")
        reason = request.form.get("reason", "").strip()
        preset_name = request.form.get("preset", "")
        if action in {"freeze_accounts", "restore_account_freeze"}:
            now = datetime.now(timezone.utc).isoformat()
            with database_connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = emergency_control_state(connection)
                affected_user_ids = []
                services = ["authentication"]
                if action == "freeze_accounts":
                    freeze_reason = request.form.get("reason", "").strip()
                    if not freeze_reason or len(freeze_reason) > 1000:
                        abort(400, "Enter a freeze reason of up to 1000 characters")
                    scope = request.form.get("scope", "")
                    group_id = None
                    if scope == "account":
                        try:
                            target_id = int(request.form.get("user_id", ""))
                        except ValueError:
                            abort(400, "Select a valid account")
                        targets = connection.execute(
                            """
                            SELECT id, status FROM users
                            WHERE id = ? AND is_admin = 0 AND status = 'active'
                              AND username != ? COLLATE NOCASE
                              AND NOT EXISTS (
                                  SELECT 1 FROM emergency_account_freezes f
                                  WHERE f.user_id = users.id
                              )
                            """,
                            (target_id, ADMIN_USERNAME),
                        ).fetchall()
                    elif scope == "group":
                        try:
                            group_id = int(request.form.get("group_id", ""))
                        except ValueError:
                            abort(400, "Select a valid group")
                        group = connection.execute(
                            "SELECT id FROM groups WHERE id = ?", (group_id,)
                        ).fetchone()
                        if not group:
                            abort(404, "Group not found")
                        targets = connection.execute(
                            """
                            SELECT users.id, users.status
                            FROM users
                            JOIN group_members ON group_members.user_id = users.id
                            WHERE group_members.group_id = ? AND users.is_admin = 0
                              AND users.status = 'active'
                              AND users.username != ? COLLATE NOCASE
                              AND NOT EXISTS (
                                  SELECT 1 FROM emergency_account_freezes f
                                  WHERE f.user_id = users.id
                              )
                            ORDER BY users.id
                            """,
                            (group_id, ADMIN_USERNAME),
                        ).fetchall()
                    else:
                        abort(400, "Select an account or group freeze scope")
                    if not targets:
                        abort(409, "No eligible active accounts were found to freeze")
                    batch_id = secrets.token_hex(16)
                    account_statuses = {}
                    for target in targets:
                        connection.execute(
                            """
                            INSERT INTO emergency_account_freezes
                                (user_id, group_id, previous_status, freeze_batch_id,
                                 reason, frozen_at, frozen_by)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                target["id"], group_id, target["status"], batch_id,
                                freeze_reason, now, session["user_id"],
                            ),
                        )
                        connection.execute(
                            "UPDATE users SET status = 'suspended', suspended_at = ? WHERE id = ?",
                            (now, target["id"]),
                        )
                        connection.execute(
                            """
                            UPDATE device_sessions SET revoked_at = ?
                            WHERE user_id = ? AND revoked_at IS NULL
                            """,
                            (now, target["id"]),
                        )
                        affected_user_ids.append(target["id"])
                        account_statuses[str(target["id"])] = {
                            "previous": target["status"],
                            "new": "suspended",
                        }
                    event_action = "freeze_accounts"
                    event_reason = freeze_reason
                else:
                    batch_id = request.form.get("freeze_batch_id", "").strip()
                    if not re.fullmatch(r"[0-9a-f]{32}", batch_id):
                        abort(400, "Invalid account-freeze batch")
                    frozen_accounts = connection.execute(
                        """
                        SELECT freezes.user_id, freezes.previous_status
                        FROM emergency_account_freezes AS freezes
                        JOIN users ON users.id = freezes.user_id
                        WHERE freezes.freeze_batch_id = ? AND users.is_admin = 0
                          AND users.username != ? COLLATE NOCASE
                        """,
                        (batch_id, ADMIN_USERNAME),
                    ).fetchall()
                    if not frozen_accounts:
                        abort(404, "Account-freeze batch not found")
                    account_statuses = {}
                    for frozen in frozen_accounts:
                        connection.execute(
                            """
                            UPDATE users SET status = ?, suspended_at = NULL
                            WHERE id = ? AND status = 'suspended'
                            """,
                            (frozen["previous_status"], frozen["user_id"]),
                        )
                        affected_user_ids.append(frozen["user_id"])
                        account_statuses[str(frozen["user_id"])] = {
                            "previous": "suspended",
                            "new": frozen["previous_status"],
                        }
                    connection.execute(
                        "DELETE FROM emergency_account_freezes WHERE freeze_batch_id = ?",
                        (batch_id,),
                    )
                    event_action = "restore_account_freeze"
                    event_reason = "Administrator restored accounts from emergency freeze"
                write_emergency_event(
                    connection,
                    event_action,
                    {
                        "controls": state,
                        "account_statuses": {
                            user_id: statuses["previous"]
                            for user_id, statuses in account_statuses.items()
                        },
                    },
                    {
                        "controls": state,
                        "account_statuses": {
                            user_id: statuses["new"]
                            for user_id, statuses in account_statuses.items()
                        },
                    },
                    event_reason,
                    len(affected_user_ids),
                    affected_user_ids,
                    services,
                )
            flash(
                f"{len(affected_user_ids)} account(s) "
                f"{'frozen' if action == 'freeze_accounts' else 'restored'}."
            )
            return redirect(url_for("admin_emergency"))
        if action in {"preset", "create_incident"}:
            if preset_name not in EMERGENCY_PRESETS:
                abort(400, "Invalid emergency preset")
            if preset_name == "FULL LOCKDOWN" and request.form.get("confirmation_phrase") != "CONFIRM LOCKDOWN":
                abort(400, "Type CONFIRM LOCKDOWN to activate the full-lockdown preset")
        now = datetime.now(timezone.utc).isoformat()
        with database_connection() as connection:
            previous = emergency_control_state(connection)
            desired = dict(previous)
            incident_id = None
            affected_services = []
            if action == "controls":
                for name in enforced:
                    desired[name] = request.form.getlist(name)[-1] == "1"
                reason = request.form.get("reason", "").strip()
            elif action == "maintenance":
                desired["maintenance_mode"] = not previous["maintenance_mode"]
                action = "controls"
                reason = "Maintenance mode toggle"
            elif action == "preset":
                preset_controls = {
                    name: value
                    for name, value in EMERGENCY_PRESETS[preset_name].items()
                    if name in enforced
                }
                desired = {**desired, **preset_controls}
                if preset_name == "NORMAL MODE":
                    for name in enforced:
                        desired[name] = False
                desired["maintenance_mode"] = False
                reason = reason or f"Activated {preset_name}"
            elif action == "create_incident":
                title = request.form.get("title", "").strip()
                description = request.form.get("description", "").strip()
                severity = request.form.get("severity", "").upper()
                affected_services = sorted(set(request.form.getlist("services")))
                if (
                    not title or len(title) > 160 or not description
                    or len(description) > 2000
                    or severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
                    or not set(affected_services).issubset(service_options)
                ):
                    abort(400, "Invalid incident details")
                selected_controls = {
                    name: value
                    for name, value in EMERGENCY_PRESETS[preset_name].items()
                    if name in enforced
                }
                if preset_name == "NORMAL MODE":
                    selected_controls = {name: False for name in enforced}
                desired = {**desired, **selected_controls}
                if preset_name == "FULL LOCKDOWN":
                    desired["maintenance_mode"] = False
                cursor = connection.execute(
                    """
                    INSERT INTO emergency_incidents
                        (title, severity, description, affected_services,
                         previous_state, emergency_state, started_at, created_by, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')
                    """,
                    (
                        title, severity, description, json.dumps(affected_services),
                        json.dumps(previous, sort_keys=True),
                        json.dumps(desired, sort_keys=True),
                        now, session["user_id"],
                    ),
                )
                incident_id = cursor.lastrowid
                reason = description
            elif action in {"incident_note", "resolve_incident", "restore_incident"}:
                try:
                    incident_id = int(request.form.get("incident_id", ""))
                except ValueError:
                    abort(400, "Invalid incident")
                incident = connection.execute(
                    "SELECT * FROM emergency_incidents WHERE id = ?",
                    (incident_id,),
                ).fetchone()
                if not incident:
                    abort(404, "Incident not found")
                services = json.loads(incident["affected_services"])
                if action == "incident_note":
                    note = request.form.get("note", "").strip()
                    if not note or len(note) > 1000:
                        abort(400, "Enter an incident note of up to 1000 characters")
                    connection.execute(
                        "INSERT INTO emergency_incident_notes (incident_id, admin_id, note, created_at) VALUES (?, ?, ?, ?)",
                        (incident_id, session["user_id"], note, now),
                    )
                    write_emergency_event(
                        connection, "incident_note", previous, previous, note,
                        affected_services=services, incident_id=incident_id,
                    )
                    flash("Incident note added.")
                    return redirect(url_for("admin_emergency"))
                if action == "resolve_incident":
                    connection.execute(
                        "UPDATE emergency_incidents SET status = 'resolved', resolved_at = ?, resolved_by = ? WHERE id = ? AND status = 'active'",
                        (now, session["user_id"], incident_id),
                    )
                    write_emergency_event(
                        connection, "resolve_incident", previous, previous,
                        affected_services=services, incident_id=incident_id,
                    )
                    flash("Incident resolved. Emergency controls remain as configured.")
                    return redirect(url_for("admin_emergency"))
                if incident["status"] != "active":
                    abort(409, "Only active incidents can restore a previous state")
                original = json.loads(incident["previous_state"])
                incident_state = json.loads(incident["emergency_state"])
                for name in enforced:
                    if previous.get(name) == incident_state.get(name):
                        desired[name] = bool(original.get(name, False))
                connection.execute(
                    "UPDATE emergency_incidents SET recovery_state = ? WHERE id = ?",
                    (json.dumps(desired, sort_keys=True), incident_id),
                )
                reason = "Selective incident rollback; controls changed after activation were preserved"
                affected_services = services
                action = "restore_incident"
            else:
                abort(400, "Invalid emergency action")

            if action in {"controls", "preset", "create_incident", "restore_incident"}:
                for name in enforced:
                    value = "1" if desired.get(name) else "0"
                    connection.execute(
                        """
                        INSERT INTO policies (name, value, updated_at, updated_by)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(name) DO UPDATE SET
                            value = excluded.value, updated_at = excluded.updated_at,
                            updated_by = excluded.updated_by
                        """,
                        (name, value, now, session["user_id"]),
                    )
                if desired.get("disable_file_sharing"):
                    connection.execute(
                        """
                        INSERT INTO policies (name, value, updated_at, updated_by)
                        VALUES ('allow_public_sharing', '0', ?, ?)
                        ON CONFLICT(name) DO UPDATE SET value='0',
                            updated_at=excluded.updated_at, updated_by=excluded.updated_by
                        """,
                        (now, session["user_id"]),
                    )
                if desired.get("force_password_reset") and not previous.get("force_password_reset"):
                    connection.execute(
                        """
                        UPDATE users SET must_change_password = 1
                        WHERE username != ? COLLATE NOCASE AND password_login_enabled = 1
                        """,
                        (ADMIN_USERNAME,),
                    )
                revoked_sessions = 0
                if desired.get("force_reauthentication") and not previous.get("force_reauthentication"):
                    current_token = session.get("device_token", "")
                    current_hash = device_token_hash(current_token) if current_token else ""
                    revoked = connection.execute(
                        """
                        UPDATE device_sessions SET revoked_at = ?
                        WHERE revoked_at IS NULL AND session_token_hash != ?
                        """,
                        (now, current_hash),
                    )
                    revoked_sessions = max(0, revoked.rowcount)
                affected_user_rows = connection.execute(
                    "SELECT id FROM users WHERE username != ? COLLATE NOCASE AND status = 'active' ORDER BY id",
                    (ADMIN_USERNAME,),
                ).fetchall()
                affected_user_ids = [row["id"] for row in affected_user_rows]
                affected_users = len(affected_user_ids)
                if action == "create_incident" and incident_id:
                    connection.execute(
                        "UPDATE emergency_incidents SET emergency_state = ? WHERE id = ?",
                        (json.dumps(desired, sort_keys=True), incident_id),
                    )
                if revoked_sessions:
                    reason += f"; revoked_sessions={revoked_sessions}"
                write_emergency_event(
                    connection,
                    action if action != "controls" else "update_controls",
                    previous,
                    desired,
                    reason,
                    affected_users,
                    affected_user_ids,
                    affected_services,
                    incident_id=incident_id,
                )
                flash(
                    f"Emergency action recorded. {affected_users} active user accounts "
                    "may be affected."
                )
        return redirect(url_for("admin_emergency"))

    now = datetime.now(timezone.utc)
    since_24h = (now - timedelta(hours=24)).isoformat()
    with database_connection() as connection:
        current = emergency_control_state(connection)
        metrics = {
            "users": connection.execute(
                "SELECT COUNT(*) AS count FROM users WHERE username != ? COLLATE NOCASE AND status = 'active'",
                (ADMIN_USERNAME,),
            ).fetchone()["count"],
            "frozen_accounts": connection.execute(
                "SELECT COUNT(*) AS count FROM emergency_account_freezes"
            ).fetchone()["count"],
            "sessions": connection.execute(
                "SELECT COUNT(*) AS count FROM device_sessions JOIN users ON users.id = device_sessions.user_id WHERE revoked_at IS NULL AND users.username != ? COLLATE NOCASE",
                (ADMIN_USERNAME,),
            ).fetchone()["count"],
            "incidents": connection.execute(
                "SELECT COUNT(*) AS count FROM emergency_incidents WHERE status = 'active'"
            ).fetchone()["count"],
            "blocked_uploads": connection.execute(
                "SELECT COUNT(*) AS count FROM audit_events WHERE action LIKE '%upload%blocked%' AND created_at >= ?",
                (since_24h,),
            ).fetchone()["count"],
            "blocked_downloads": connection.execute(
                "SELECT COUNT(*) AS count FROM audit_events WHERE action LIKE '%download%blocked%' AND created_at >= ?",
                (since_24h,),
            ).fetchone()["count"],
            "blocked_api": connection.execute(
                "SELECT COUNT(*) AS count FROM audit_events WHERE action LIKE '%api%blocked%' AND created_at >= ?",
                (since_24h,),
            ).fetchone()["count"],
            "alerts": connection.execute(
                "SELECT COUNT(*) AS count FROM security_alerts WHERE status = 'open'"
            ).fetchone()["count"],
        }
        incidents = connection.execute(
            """
            SELECT emergency_incidents.*, users.username AS admin_name
            FROM emergency_incidents
            LEFT JOIN users ON users.id = emergency_incidents.created_by
            ORDER BY CASE emergency_incidents.status WHEN 'active' THEN 0 ELSE 1 END,
                emergency_incidents.started_at DESC
            LIMIT 50
            """
        ).fetchall()
        freeze_targets = connection.execute(
            """
            SELECT users.id, users.username
            FROM users
            WHERE users.is_admin = 0 AND users.status = 'active'
              AND users.username != ? COLLATE NOCASE
              AND NOT EXISTS (
                  SELECT 1 FROM emergency_account_freezes freezes
                  WHERE freezes.user_id = users.id
              )
            ORDER BY users.username COLLATE NOCASE
            """,
            (ADMIN_USERNAME,),
        ).fetchall()
        freeze_groups = connection.execute(
            """
            SELECT groups.id, groups.name, COUNT(users.id) AS eligible_members
            FROM groups
            JOIN group_members ON group_members.group_id = groups.id
            JOIN users ON users.id = group_members.user_id
            WHERE users.is_admin = 0 AND users.status = 'active'
              AND users.username != ? COLLATE NOCASE
              AND NOT EXISTS (
                  SELECT 1 FROM emergency_account_freezes freezes
                  WHERE freezes.user_id = users.id
              )
            GROUP BY groups.id
            HAVING COUNT(users.id) > 0
            ORDER BY groups.name COLLATE NOCASE
            """,
            (ADMIN_USERNAME,),
        ).fetchall()
        freeze_batches = connection.execute(
            """
            SELECT freezes.freeze_batch_id, MIN(freezes.group_id) AS group_id,
                   COUNT(*) AS account_count, MIN(freezes.reason) AS reason,
                   MIN(freezes.frozen_at) AS frozen_at,
                   MIN(freezes.frozen_by) AS frozen_by,
                   groups.name AS group_name, users.username AS admin_name
            FROM emergency_account_freezes AS freezes
            LEFT JOIN groups ON groups.id = freezes.group_id
            LEFT JOIN users ON users.id = freezes.frozen_by
            GROUP BY freezes.freeze_batch_id
            ORDER BY frozen_at DESC
            """
        ).fetchall()
        event_filters = {
            "date_from": request.args.get("date_from", "").strip()[:10],
            "date_to": request.args.get("date_to", "").strip()[:10],
            "admin": request.args.get("admin", "").strip()[:80],
            "action": request.args.get("event_action", "").strip()[:120],
            "severity": request.args.get("severity", "").strip().upper()[:8],
            "incident": request.args.get("incident", "").strip()[:12],
            "user": request.args.get("user", "").strip()[:12],
            "ip": request.args.get("ip", "").strip()[:64],
        }
        clauses = []
        values = []
        for key, comparison in (("date_from", ">="), ("date_to", "<")):
            date_value = event_filters[key]
            if date_value:
                try:
                    parsed_date = datetime.strptime(date_value, "%Y-%m-%d")
                except ValueError:
                    abort(400, "Emergency event dates must use YYYY-MM-DD")
                boundary = parsed_date + (
                    timedelta(days=1) if key == "date_to" else timedelta()
                )
                clauses.append(f"emergency_events.created_at {comparison} ?")
                values.append(boundary.isoformat() if key == "date_to" else parsed_date.isoformat())
        if event_filters["admin"]:
            clauses.append("users.username LIKE ? COLLATE NOCASE")
            values.append(f"%{event_filters['admin']}%")
        if event_filters["action"]:
            clauses.append("emergency_events.action LIKE ?")
            values.append(f"%{event_filters['action']}%")
        if event_filters["severity"]:
            if event_filters["severity"] not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                abort(400, "Invalid event severity")
            clauses.append("incidents.severity = ?")
            values.append(event_filters["severity"])
        if event_filters["incident"]:
            try:
                incident_filter = int(event_filters["incident"])
            except ValueError:
                abort(400, "Incident filter must be a number")
            clauses.append("emergency_events.incident_id = ?")
            values.append(incident_filter)
        if event_filters["user"]:
            try:
                user_filter = int(event_filters["user"])
            except ValueError:
                abort(400, "User filter must be a number")
            clauses.append(
                "instr(',' || replace(replace(replace("
                "emergency_events.affected_user_ids, '[', ''), ']', ''), ' ', '') "
                "|| ',', ',' || ? || ',') > 0"
            )
            values.append(str(user_filter))
        if event_filters["ip"]:
            clauses.append("emergency_events.ip_address LIKE ?")
            values.append(f"%{event_filters['ip']}%")
        event_query = """
            SELECT emergency_events.*, users.username AS admin_name
            FROM emergency_events
            LEFT JOIN users ON users.id = emergency_events.admin_id
            LEFT JOIN emergency_incidents AS incidents
                ON incidents.id = emergency_events.incident_id
        """
        if clauses:
            event_query += " WHERE " + " AND ".join(clauses)
        event_query += " ORDER BY emergency_events.created_at DESC LIMIT 100"
        event_rows = connection.execute(event_query, values).fetchall()
        last_event = event_rows[0] if event_rows else None

    incident_items = []
    for row in incidents:
        item = dict(row)
        item["services"] = json.loads(item["affected_services"])
        with database_connection() as connection:
            item["notes"] = [
                dict(note)
                for note in connection.execute(
                    """
                    SELECT emergency_incident_notes.*, users.username AS admin_name
                    FROM emergency_incident_notes
                    LEFT JOIN users ON users.id = emergency_incident_notes.admin_id
                    WHERE incident_id = ? ORDER BY created_at
                    """,
                    (item["id"],),
                ).fetchall()
            ]
        incident_items.append(item)
    events = []
    for row in event_rows:
        item = dict(row)
        item["services"] = json.loads(item["affected_services"])
        try:
            item["reason"] = item["reason"] or ""
        except KeyError:
            item["reason"] = ""
        events.append(item)
    active_controls = [
        EMERGENCY_CONTROL_LABELS[name][0]
        for name, value in current.items()
        if value
    ]
    if current["maintenance_mode"]:
        system_status, status_class = "MAINTENANCE", "maintenance"
    elif current["global_read_only"] and current["disable_downloads"]:
        system_status, status_class = "LOCKDOWN", "lockdown"
    elif current["enhanced_monitoring"] or metrics["alerts"]:
        system_status, status_class = "SECURITY ALERT", "security"
    elif active_controls:
        system_status, status_class = "RESTRICTED", "restricted"
    else:
        system_status, status_class = "NORMAL", ""
    return render_template_string(
        ADMIN_EMERGENCY_PAGE,
        controls={
            name: {
                "label": label,
                "description": description,
                "enabled": current[name],
                "supported": name in enforced,
            }
            for name, (label, description) in EMERGENCY_CONTROL_LABELS.items()
        },
        presets=list(EMERGENCY_PRESETS),
        services=sorted(service_options),
        active_controls=active_controls,
        incidents=incident_items,
        freeze_targets=freeze_targets,
        freeze_groups=freeze_groups,
        freeze_batches=freeze_batches,
        events=events,
        event_filters=event_filters,
        metrics=metrics,
        system_status=system_status,
        status_class=status_class,
        last_action=last_event["action"] if last_event else None,
        last_admin=last_event["admin_name"] if last_event else None,
    )


@app.route("/admin/storage")
def admin_storage():
    response = require_permission("storage.manage")
    if response:
        return response
    users = []
    with database_connection() as connection:
        rows = connection.execute("SELECT id, username, status, is_admin FROM users WHERE is_admin = 0 ORDER BY username COLLATE NOCASE").fetchall()
    for row in rows:
        used = user_usage(row["id"])[1]
        quota = user_quota(row["id"])
        with database_connection() as connection:
            permissions = connection.execute("SELECT allow_upload, allow_download FROM storage_permissions WHERE user_id = ?", (row["id"],)).fetchone()
        users.append({**dict(row), "used": used, "quota": quota, "remaining": max(0, quota - used) if quota else 0, "quota_mb": quota // (1024 * 1024) if quota else 0, "allow_upload": not permissions or bool(permissions["allow_upload"]), "allow_download": not permissions or bool(permissions["allow_download"])})
    return render_template_string(ADMIN_STORAGE_PAGE, users=users)


@app.route("/admin/storage/<int:user_id>/quota", methods=["POST"])
def admin_storage_quota(user_id):
    response = require_permission("storage.manage")
    if response:
        return response
    try:
        quota_mb = int(request.form.get("quota_mb", "0"))
    except ValueError:
        quota_mb = -1
    if quota_mb < 0:
        flash("Quota must be zero or a positive number of megabytes.")
        return redirect(url_for("admin_storage"))
    with database_connection() as connection:
        user = connection.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user or user["is_admin"]:
            flash("That account is protected or does not exist.")
            return redirect(url_for("admin_storage"))
        now = datetime.now(timezone.utc).isoformat()
        connection.execute("""
            INSERT INTO quotas (user_id, quota_bytes, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET quota_bytes = excluded.quota_bytes, updated_at = excluded.updated_at
        """, (user_id, quota_mb * 1024 * 1024, now))
    audit_event("set_quota", "user", user_id, f"username={user['username']}; quota_mb={quota_mb}")
    flash(f"Storage quota updated for {user['username']}.")
    return redirect(url_for("admin_storage"))


@app.route("/admin/storage/<int:user_id>/permissions", methods=["POST"])
def admin_storage_permissions(user_id):
    response = require_permission("storage.manage")
    if response:
        return response
    allow_upload = int(bool(request.form.get("allow_upload")))
    allow_download = int(bool(request.form.get("allow_download")))
    now = datetime.now(timezone.utc).isoformat()
    with database_connection() as connection:
        user = connection.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user or user["is_admin"]:
            flash("That account is protected or does not exist.")
            return redirect(url_for("admin_storage"))
        connection.execute("""
            INSERT INTO storage_permissions (user_id, allow_upload, allow_download, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                allow_upload = excluded.allow_upload,
                allow_download = excluded.allow_download,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
        """, (user_id, allow_upload, allow_download, now, session["user_id"]))
    audit_event("update_storage_permissions", "user", user_id, f"username={user['username']}; upload={allow_upload}; download={allow_download}")
    flash(f"Storage access updated for {user['username']}.")
    return redirect(url_for("admin_storage"))


@app.route("/admin/audit")
def admin_audit():
    response = require_permission("audit.view")
    if response:
        return response
    action = request.args.get("action", "").strip()
    actor = request.args.get("actor", "").strip()
    status = request.args.get("status", "").strip()
    clauses = []
    values = []
    if action:
        clauses.append("audit_events.action LIKE ?")
        values.append(f"%{action}%")
    if actor:
        clauses.append("users.username LIKE ?")
        values.append(f"%{actor}%")
    if status in {"success", "denied"}:
        clauses.append("audit_events.status = ?")
        values.append(status)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with database_connection() as connection:
        events = connection.execute(f"""
            SELECT audit_events.*, users.username AS actor
            FROM audit_events LEFT JOIN users ON users.id = audit_events.actor_id
            {where}
            ORDER BY audit_events.created_at DESC LIMIT 250
        """, values).fetchall()
    grouped = {}
    for event in events:
        item = dict(event)
        username = item["actor"] or "System"
        grouped.setdefault(username, []).append(item)
    audit_groups = [{"username": username, "events": group_events} for username, group_events in grouped.items()]
    return render_template_string(ADMIN_AUDIT_PAGE, events=[dict(row) for row in events], audit_groups=audit_groups, filters={"action": action, "actor": actor, "status": status})


@app.route("/admin/users/<int:user_id>/status", methods=["POST"])
def admin_user_status(user_id):
    response = require_permission("users.manage")
    if response:
        return response
    status = request.form.get("status", "").strip().lower()
    if status not in {"active", "suspended"}:
        abort(400, "Invalid account status")
    if user_id == session["user_id"] and status != "active":
        flash("The active administrator cannot suspend itself.")
        return redirect(url_for("admin_manage"))
    with database_connection() as connection:
        if status == "active" and connection.execute(
            "SELECT 1 FROM emergency_account_freezes WHERE user_id = ?",
            (user_id,),
        ).fetchone():
            flash("Restore this account through the Emergency Control Centre.")
            return redirect(url_for("admin_manage"))
        result = connection.execute("UPDATE users SET status = ?, suspended_at = ? WHERE id = ? AND is_admin = 0", (status, datetime.now(timezone.utc).isoformat() if status == "suspended" else None, user_id))
    if result.rowcount:
        audit_event("suspend_user" if status == "suspended" else "activate_user", "user", user_id)
        flash(f"User account {status}.")
    else:
        flash("User not found or protected.")
    return redirect(url_for("admin_manage"))


@app.route("/admin/users/<int:user_id>/quota", methods=["POST"])
def admin_user_quota(user_id):
    response = require_permission("storage.manage")
    if response:
        return response
    try:
        quota_mb = int(request.form.get("quota_mb", "0"))
    except ValueError:
        quota_mb = -1
    if quota_mb < 0:
        flash("Quota must be zero or a positive number of megabytes.")
        return redirect(url_for("admin_manage"))
    with database_connection() as connection:
        user = connection.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if user:
            connection.execute("INSERT INTO quotas (user_id, quota_bytes, updated_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET quota_bytes=excluded.quota_bytes, updated_at=excluded.updated_at", (user_id, quota_mb * 1024 * 1024, datetime.now(timezone.utc).isoformat()))
    if not user:
        flash("User not found.")
    else:
        audit_event("set_quota", "user", user_id, f"quota_mb={quota_mb}")
        flash("Storage quota updated.")
    return redirect(url_for("admin_manage"))


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
def admin_user_role(user_id):
    response = require_permission("users.manage")
    if response:
        return response
    role_name = request.form.get("role_name", "").strip()
    if not role_name or role_name in {ADMIN_ROLE, "__system_admin__"}:
        flash("Choose a valid role.")
        return redirect(url_for("admin_manage"))
    normal_user = role_name == "__normal_user__"
    with database_connection() as connection:
        user = connection.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
        if user and user["username"].lower() == ADMIN_USERNAME.lower():
            flash("The server owner account cannot have its role changed.")
            return redirect(url_for("admin_manage"))
        role = None if normal_user else connection.execute("SELECT id FROM roles WHERE name = ? AND name != ?", (role_name, ADMIN_ROLE)).fetchone()
        protected = user and user["username"].lower() == ADMIN_USERNAME.lower()
        if user and role_name and (normal_user or role) and not protected and user_id != session["user_id"] and not user["is_admin"]:
            connection.execute("UPDATE users SET is_admin = 0 WHERE id = ?", (user_id,))
            connection.execute("DELETE FROM user_roles WHERE user_id = ?", (user_id,))
            if not normal_user:
                connection.execute("INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by) VALUES (?, ?, ?, ?)", (user_id, role["id"], datetime.now(timezone.utc).isoformat(), session["user_id"]))
    if not user or (not normal_user and not role) or protected or user_id == session["user_id"] or user["is_admin"]:
        flash("User or role not found; the owner is the only administrator and cannot be changed.")
    else:
        audit_event("set_user_role", "user", user_id, f"role={'normal_user' if normal_user else role_name}")
        flash(f"Role {'normal user' if normal_user else role_name} saved.")
    return redirect(url_for("admin_manage"))


@app.route("/admin/groups/create", methods=["POST"])
def admin_group_create():
    response = require_permission("users.manage")
    if response:
        return response
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    if not name or len(name) > 80:
        flash("Enter a group name up to 80 characters.")
        return redirect(url_for("admin_manage"))
    try:
        with database_connection() as connection:
            cursor = connection.execute("INSERT INTO groups (name, description, created_at) VALUES (?, ?, ?)", (name, description, datetime.now(timezone.utc).isoformat()))
        audit_event("create_group", "group", cursor.lastrowid, name)
        flash("Group created.")
    except sqlite3.IntegrityError:
        flash("That group already exists.")
    return redirect(url_for("admin_manage"))


@app.route("/admin/groups/<int:group_id>/members", methods=["POST"])
def admin_group_member(group_id):
    response = require_permission("users.manage")
    if response:
        return response
    try:
        user_id = int(request.form.get("user_id", "0"))
    except ValueError:
        abort(400, "Invalid user")
    with database_connection() as connection:
        group = connection.execute("SELECT id FROM groups WHERE id = ?", (group_id,)).fetchone()
        user = connection.execute("SELECT id FROM users WHERE id = ? AND status = 'active'", (user_id,)).fetchone()
        if group and user:
            connection.execute("INSERT OR IGNORE INTO group_members (group_id, user_id, assigned_at, assigned_by) VALUES (?, ?, ?, ?)", (group_id, user_id, datetime.now(timezone.utc).isoformat(), session["user_id"]))
    if not group or not user:
        flash("Group or active user not found.")
    else:
        audit_event("add_group_member", "group", group_id, f"user_id={user_id}")
        flash("User added to group.")
    return redirect(url_for("admin_manage"))


@app.route("/admin/users/<int:user_id>/profile")
def admin_user_profile(user_id):
    response = require_permission("users.view")
    if response:
        return response
    with database_connection() as connection:
        user = connection.execute(
            """
            SELECT id, username, full_name, email, mobile, date_of_birth,
                gender, location, created_at, last_login_at, last_seen,
                totp_enabled,
                google_sub, google_email, google_profile_name, google_username,
                google_picture, github_sub, github_email, github_profile_name,
                github_username, github_picture
            FROM users WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
    if not user:
        abort(404, "User not found")
    profile_data = dict(user)
    profile_data["profile_picture"] = (
        profile_data["google_picture"] or profile_data["github_picture"]
    )
    return render_template_string(
        PROFILE_PAGE,
        profile=profile_data,
        can_edit_profile=False,
        back_url=url_for("admin_panel"),
    )


@app.route("/admin/recovery/<int:request_id>/reset", methods=["POST"])
def admin_reset_password(request_id):
    response = require_permission("users.recovery")
    if response:
        return response
    with database_connection() as connection:
        recovery = connection.execute("""
            SELECT password_requests.id, password_requests.user_id,
                   password_requests.status, password_requests.email,
                   password_requests.mobile, password_requests.date_of_birth,
                   users.email AS account_email, users.mobile AS account_mobile,
                   users.date_of_birth AS account_dob
            FROM password_requests
            JOIN users ON users.id = password_requests.user_id
            WHERE password_requests.id = ? AND users.is_admin = 0
        """, (request_id,)).fetchone()
        if not recovery or recovery["status"] != "pending":
            abort(404, "Recovery request not found")
        if (recovery["email"].strip().lower() != (recovery["account_email"] or "").strip().lower()
                or recovery["mobile"].strip() != (recovery["account_mobile"] or "").strip()
                or recovery["date_of_birth"] != (recovery["account_dob"] or "")):
            connection.execute("UPDATE password_requests SET status = 'rejected', reviewed_at = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), request_id))
            flash("The recovery details did not match the registered account. Password was not changed.")
            return redirect(url_for("admin_panel"))
        recovery_password = generate_recovery_password()
        connection.execute("UPDATE users SET password_hash = ?, password_login_enabled = 1 WHERE id = ? AND is_admin = 0", (hash_password(recovery_password), recovery["user_id"]))
        connection.execute("UPDATE password_requests SET status = 'approved', reviewed_at = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), request_id))
    flash(f"Identity verified. Temporary password for the user: {recovery_password}")
    return redirect(url_for("admin_panel"))


ADMIN_FILES_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Admin read-only - Cloud Rdx</title><style>
body{margin:0;background:#f2f6f8;color:#17212b;font-family:'Segoe UI',Arial,sans-serif;background-image:linear-gradient(#d8e1e844 1px,transparent 1px),linear-gradient(90deg,#d8e1e844 1px,transparent 1px);background-size:32px 32px}.wrap{width:min(980px,calc(100% - 32px));margin:40px auto}.top{display:flex;justify-content:space-between;align-items:start;gap:20px;margin-bottom:25px}.eyebrow{margin:0 0 8px;color:#087f73;text-transform:uppercase;letter-spacing:.14em;font:700 11px Consolas,monospace}h1{margin:0;font-size:38px;letter-spacing:-.03em}.sub{margin:8px 0 0;color:#647483;font:13px Consolas,monospace}.back{color:#087f73;font:700 12px Consolas,monospace;text-decoration:none}.panel{overflow:hidden;background:#fff;border:1px solid #d8e1e8;border-radius:8px;box-shadow:0 12px 30px #19314214}.head{display:flex;justify-content:space-between;gap:15px;padding:18px 22px;border-bottom:1px solid #d8e1e8;font:13px Consolas,monospace}.head a{color:#087f73;text-decoration:none}.row{display:grid;grid-template-columns:40px minmax(0,1fr) 110px 90px;gap:12px;align-items:center;min-height:62px;padding:0 22px;border-bottom:1px solid #e8eef2;font:13px Consolas,monospace}.row:last-child{border:0}.icon{width:32px;height:32px;display:grid;place-items:center;border-radius:6px;background:#e5f5f2;color:#087f73}.icon.file{background:#fff3dc;color:#b06b0c}.row a{color:#087f73;text-decoration:none}.meta{color:#647483;font-size:11px}.download{justify-self:end;font-size:11px;font-weight:700}.empty{padding:60px;text-align:center;color:#647483;font:13px Consolas,monospace}@media(max-width:620px){.wrap{margin:24px auto}.top{display:block}.back{display:inline-block;margin-top:16px}.row{grid-template-columns:34px minmax(0,1fr) 68px;padding:0 14px}.meta{display:none}}
</style></head><body><main class="wrap"><header class="top"><div><p class="eyebrow">Admin read-only file inspection</p><h1>{{ username }}</h1><p class="sub">/users/{{ user_id }}{% if subpath %}/{{ subpath }}{% endif %}</p></div><a class="back" href="{{ url_for('admin_panel') }}">→ BACK TO ADMIN</a></header><section class="panel"><div class="head"><span>{% for crumb in breadcrumbs %}{% if not loop.first %} / {% endif %}<a href="{{ crumb.url }}">{{ crumb.name }}</a>{% endfor %}</span><span>READ ONLY</span></div>{% if parent is not none %}<div class="row"><div class="icon">^</div><a href="{{ url_for('admin_user_files', user_id=user_id, subpath=parent) }}">Parent directory</a><span class="meta">FOLDER</span><span></span></div>{% endif %}{% for item in items %}<div class="row"><div class="icon{% if not item.is_dir %} file{% endif %}">{% if item.is_dir %}[ ]{% else %}..{% endif %}</div>{% if item.is_dir %}<a href="{{ url_for('admin_user_files', user_id=user_id, subpath=item.path) }}">{{ item.name }}</a>{% else %}<span>{{ item.name }}</span>{% endif %}<span class="meta">{% if item.is_dir %}FOLDER{% else %}{{ item.size|filesize }}{% endif %}</span>{% if not item.is_dir %}<a class="download" href="{{ url_for('admin_user_download', user_id=user_id, subpath=item.path) }}">DOWNLOAD</a>{% else %}<span></span>{% endif %}</div>{% else %}<div class="empty">No files in this directory.</div>{% endfor %}</section></main></body></html>
"""


_flask_render_template_string = render_template_string


def csrf_token():
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def render_template_string(template, *args, **kwargs):
    """Render existing inline templates while adding CSRF fields to POST forms."""
    admin_markers = ("Role-based administration", "Admin panel - Cloud Rdx", "Control center", "Audit activity - Cloud Rdx", "Recycle bin - Cloud Rdx", "Admin read-only - Cloud Rdx", "Administration - Cloud Rdx", "Website settings - Cloud Rdx", "Payment verification - Cloud Rdx", "User storage quotas - Cloud Rdx", "Access control - Cloud Rdx", "Active sessions and devices", "Enable authenticator 2FA", "Authenticator 2FA enabled")
    admin_page = any(marker in template for marker in admin_markers)
    protected_page = not any(marker in template for marker in (*admin_markers, "Sign in - RDx Cloud Storage-DB16", "Create account - Cloud Rdx", "Password recovery", "Security verification - Cloud Rdx"))
    if "csrf_token" not in kwargs:
        kwargs["csrf_token"] = csrf_token()
    template = re.sub(
        r'<form(\s[^>]*method=["\']post["\'][^>]*)>',
        r'<form\1><input type="hidden" name="csrf_token" value="{{ csrf_token }}">',
        template,
        flags=re.IGNORECASE,
    )
    template = template.replace(
        "<head>",
        '<head><link rel="stylesheet" href="{{ url_for(\'static\', filename=\'admin-theme.css\') }}">',
        1,
    )
    if any(marker in template for marker in ("Create account - Cloud Rdx", "Password recovery")):
        template = template.replace(
            "admin-theme.css') }}\">",
            "admin-theme.css') }}\"><link rel=\"stylesheet\" href=\"{{ url_for('static', filename='auth.css') }}\">",
            1,
        )
    if admin_page:
        template = template.replace("<body>", '<body class="admin-theme">', 1)
    if admin_page and "admin-mobile-toggle" not in template:
        template = template.replace(
            "<body class=\"admin-theme\">",
            '<body class="admin-theme"><button class="admin-mobile-toggle" type="button" aria-label="Open admin navigation" aria-expanded="false">☰</button><button class="admin-mobile-backdrop" type="button" aria-label="Close admin navigation" tabindex="-1"></button>',
            1,
        )
        template = template.replace(
            "</body>",
            """<script>
(() => {
    const body = document.body;
    const rail = document.querySelector('.admin-theme .rail');
    const toggle = document.querySelector('.admin-mobile-toggle');
    const backdrop = document.querySelector('.admin-mobile-backdrop');
    if (!rail || !toggle || !backdrop) return;
    const setOpen = (open) => {
        rail.classList.toggle('admin-open', open);
        body.classList.toggle('admin-menu-open', open);
        toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        toggle.setAttribute('aria-label', open ? 'Close admin navigation' : 'Open admin navigation');
    };
    toggle.addEventListener('click', () => setOpen(!rail.classList.contains('admin-open')));
    backdrop.addEventListener('click', () => setOpen(false));
    rail.querySelectorAll('a').forEach((link) => link.addEventListener('click', () => setOpen(false)));
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape') setOpen(false); });
})();
</script></body>""",
            1,
        )
    if protected_page and "content-protection.js" not in template:
        template = template.replace(
            "</body>",
            '<script src="{{ url_for(\'static\', filename=\'content-protection.js\') }}" defer></script></body>',
            1,
        )
    return _flask_render_template_string(template, *args, **kwargs)


def audit_event(action, target_type, target_id=None, details="", status="success", actor_id=None, risk_level="LOW"):
    actor_id = actor_id if actor_id is not None else session.get("user_id")
    created_at = datetime.now(timezone.utc).isoformat()
    with database_connection() as connection:
        connection.execute(
            "INSERT INTO audit_events (actor_id, action, target_type, target_id, details, status, created_at, ip_address, risk_level, session_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (actor_id, action, target_type, str(target_id) if target_id is not None else None, details[:2000], status, created_at, request_ip(), risk_level, session.get("device_token", "")[:16] or None),
        )
        if actor_id is not None and status == "success":
            activity_windows = {
                "upload": (
                    ("upload",),
                    20,
                    "HIGH",
                    "unusual_upload_spike",
                    "More than 20 successful uploads were recorded for one account in five minutes.",
                ),
                "download": (
                    ("download", "bulk_download"),
                    40,
                    "HIGH",
                    "unusual_download_spike",
                    "More than 40 successful downloads were recorded for one account in five minutes.",
                ),
                "file_change": (
                    ("create_folder", "delete_to_trash", "copy_file", "move_file", "rename_file"),
                    30,
                    "MEDIUM",
                    "rapid_file_modifications",
                    "More than 30 successful file changes were recorded for one account in five minutes.",
                ),
            }
            if action == "upload":
                activity_type = "upload"
            elif action in {"download", "bulk_download"}:
                activity_type = "download"
            elif action in {
                "create_folder", "delete_to_trash", "restore_from_trash",
                "purge_trash", "restore_own_trash", "purge_own_trash",
            }:
                activity_type = "file_change"
            else:
                activity_type = None
            if activity_type:
                actions, threshold, severity, alert_type, alert_details = activity_windows[
                    activity_type
                ]
                cutoff = (
                    datetime.fromisoformat(created_at) - timedelta(minutes=5)
                ).isoformat()
                placeholders = ",".join("?" for _ in actions)
                count = connection.execute(
                    f"""
                    SELECT COUNT(*) AS count FROM audit_events
                    WHERE actor_id = ? AND status = 'success'
                      AND action IN ({placeholders}) AND created_at >= ?
                    """,
                    (actor_id, *actions, cutoff),
                ).fetchone()["count"]
                if count > threshold:
                    account = connection.execute(
                        "SELECT username FROM users WHERE id = ?", (actor_id,)
                    ).fetchone()
                    create_security_alert(
                        connection,
                        severity,
                        alert_type,
                        account["username"] if account else None,
                        request_ip(),
                        f"{alert_details} Observed: {count}.",
                        created_at,
                    )
        if action == "account_created":
            cutoff = (
                datetime.fromisoformat(created_at) - timedelta(minutes=10)
            ).isoformat()
            creations = connection.execute(
                """
                SELECT COUNT(*) AS count FROM audit_events
                WHERE action = 'account_created' AND ip_address = ?
                  AND created_at >= ?
                """,
                (request_ip(), cutoff),
            ).fetchone()["count"]
            if creations >= 10:
                create_security_alert(
                    connection,
                    "MEDIUM",
                    "unusual_account_creation_spike",
                    None,
                    request_ip(),
                    f"{creations} accounts were created from one IP within ten minutes.",
                    created_at,
                )


def user_usage(user_id):
    folder = SHARED_FOLDER / "users" / str(user_id)
    files = [path for path in folder.rglob("*") if path.is_file()] if folder.exists() else []
    return len(files), sum(path.stat().st_size for path in files)


def user_quota(user_id):
    with database_connection() as connection:
        row = connection.execute("SELECT quota_bytes FROM quotas WHERE user_id = ?", (user_id,)).fetchone()
        if row:
            return int(row["quota_bytes"])
        free = connection.execute("SELECT quota_bytes FROM storage_plans WHERE code = 'free' AND active = 1").fetchone()
    return int(free["quota_bytes"]) if free else 5 * 1024**3


def plan_rows():
    with database_connection() as connection:
        return connection.execute("SELECT * FROM storage_plans WHERE active = 1 ORDER BY quota_bytes").fetchall()


def current_subscription(user_id):
    with database_connection() as connection:
        row = connection.execute("""
            SELECT subscriptions.*, storage_plans.name AS plan_name
            FROM subscriptions JOIN storage_plans ON storage_plans.id = subscriptions.plan_id
            WHERE subscriptions.user_id = ? AND subscriptions.status IN ('pending', 'active')
            ORDER BY subscriptions.id DESC LIMIT 1
        """, (user_id,)).fetchone()
    return dict(row) if row else None


def razorpay_client():
    if not razorpay or not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        return None
    return razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))


def activate_subscription(user_id, plan_id, provider, provider_subscription_id=None):
    now = datetime.now(timezone.utc).isoformat()
    with database_connection() as connection:
        if provider_subscription_id:
            existing = connection.execute("SELECT plan_id FROM subscriptions WHERE provider_subscription_id = ?", (provider_subscription_id,)).fetchone()
            if existing:
                plan = connection.execute("SELECT * FROM storage_plans WHERE id = ?", (existing["plan_id"],)).fetchone()
                return dict(plan)
        plan = connection.execute("SELECT * FROM storage_plans WHERE id = ? AND active = 1", (plan_id,)).fetchone()
        if not plan:
            raise ValueError("Storage plan not found")
        connection.execute("UPDATE subscriptions SET status = 'replaced', updated_at = ? WHERE user_id = ? AND status = 'active'", (now, user_id))
        connection.execute("""
            INSERT INTO subscriptions (user_id, plan_id, provider, provider_subscription_id, status, quota_bytes, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
        """, (user_id, plan_id, provider, provider_subscription_id, plan["quota_bytes"], now, now))
        connection.execute("""
            INSERT INTO quotas (user_id, quota_bytes, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET quota_bytes = excluded.quota_bytes, updated_at = excluded.updated_at
        """, (user_id, plan["quota_bytes"], now))
    return dict(plan)


def quota_allows(user_id, additional_bytes):
    quota = user_quota(user_id)
    if quota <= 0:
        return True
    return user_usage(user_id)[1] + additional_bytes <= quota


def trash_item(user_id, target, deleted_by):
    base = SHARED_FOLDER / "users" / str(user_id)
    target = target.resolve()
    target.relative_to(base.resolve())
    trash_root = SHARED_FOLDER / ".trash" / str(user_id)
    trash_root.mkdir(parents=True, exist_ok=True)
    is_dir = target.is_dir()
    trash_path = trash_root / f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}_{secrets.token_hex(4)}_{target.name}"
    relative = target.relative_to(base).as_posix()
    shutil.move(str(target), str(trash_path))
    with database_connection() as connection:
        cursor = connection.execute(
            "INSERT INTO trash_items (user_id, original_path, trash_path, item_name, is_dir, deleted_by, deleted_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, relative, str(trash_path), target.name, int(is_dir), deleted_by, datetime.now(timezone.utc).isoformat()),
        )
    audit_event("delete_to_trash", "folder" if is_dir else "file", cursor.lastrowid, f"user={user_id}; path={relative}", actor_id=deleted_by)
    return cursor.lastrowid


@app.route("/admin/users/<int:user_id>/files/")
@app.route("/admin/users/<int:user_id>/files/<path:subpath>")
def admin_user_files(user_id, subpath=""):
    response = require_permission("storage.manage")
    if response:
        return response
    try:
        user, base, folder = admin_user_path(user_id, subpath)
    except ValueError:
        abort(404, "User or path not found")
    if not folder.is_dir():
        abort(404, "Folder not found")
    items = []
    for path in sorted(folder.iterdir(), key=lambda entry: (not entry.is_dir(), entry.name.lower())):
        items.append({"name": path.name, "path": path.relative_to(base).as_posix(), "is_dir": path.is_dir(), "size": path.stat().st_size if path.is_file() else 0})
    parent = Path(subpath).parent.as_posix() if subpath else None
    if parent == ".":
        parent = ""
    parts = [part for part in Path(subpath).parts if part not in (".", "")]
    crumbs = [{"name": name, "url": url_for("admin_user_files", user_id=user_id, subpath="/".join(parts[:index + 1]))} for index, name in enumerate(parts)]
    return render_template_string(ADMIN_FILES_PAGE, username=user["username"], user_id=user_id, subpath=subpath, parent=parent, breadcrumbs=crumbs, items=items)


@app.route("/admin/users/<int:user_id>/download/<path:subpath>")
def admin_user_download(user_id, subpath):
    response = require_permission("storage.manage")
    if response:
        return response
    try:
        user, base, target = admin_user_path(user_id, subpath)
    except ValueError:
        abort(404, "User or path not found")
    if not target.is_file():
        abort(404, "File not found")
    return send_from_directory(target.parent, target.name, as_attachment=True)


@app.route("/admin/users/<int:user_id>/password", methods=["POST"])
def admin_password(user_id):
    response = require_permission("users.manage")
    if response:
        return response
    password = request.form.get("password", "")
    if len(password) < 8:
        flash("Passwords must be at least 8 characters.")
    else:
        with database_connection() as connection:
            result = connection.execute("UPDATE users SET password_hash = ?, password_login_enabled = 1 WHERE id = ? AND is_admin = 0", (hash_password(password), user_id))
        flash("Password updated." if result.rowcount else "User not found or protected.")
    return redirect(url_for("admin_panel"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def admin_delete_user(user_id):
    response = require_permission("users.manage")
    if response:
        return response
    if user_id == session["user_id"]:
        flash("The active administrator account cannot remove itself.")
        return redirect(url_for("admin_panel"))
    with database_connection() as connection:
        user = connection.execute("SELECT id, username, is_admin, status FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        abort(404, "User not found")
    if user["is_admin"]:
        flash("Administrator accounts are protected from deletion.")
        return redirect(url_for("admin_panel"))
    folder = SHARED_FOLDER / "users" / str(user_id)
    if folder.exists() and any(folder.iterdir()):
        trash_item(user_id, folder, session["user_id"])
    with database_connection() as connection:
        connection.execute("UPDATE users SET status = 'suspended', suspended_at = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), user_id))
    audit_event("delete_user_to_trash", "user", user_id, f"username={user['username']}")
    flash(f"User {user['username']} was suspended and their storage moved to the recycle bin.")
    return redirect(url_for("admin_panel"))


@app.route("/admin/trash")
def admin_trash():
    response = require_permission("storage.recycle_bin")
    if response:
        return response
    with database_connection() as connection:
        items = connection.execute("""
            SELECT trash_items.*, users.username FROM trash_items
            JOIN users ON users.id = trash_items.user_id
            WHERE restored_at IS NULL AND purged_at IS NULL
            ORDER BY deleted_at DESC
        """).fetchall()
    return render_template_string(ADMIN_TRASH_PAGE, items=[dict(item) for item in items])


@app.route("/admin/trash/<int:trash_id>/restore", methods=["POST"])
def admin_restore_trash(trash_id):
    response = require_permission("storage.recycle_bin")
    if response:
        return response
    with database_connection() as connection:
        item = connection.execute("SELECT * FROM trash_items WHERE id = ? AND restored_at IS NULL AND purged_at IS NULL", (trash_id,)).fetchone()
    if not item:
        abort(404, "Trash item not found")
    base = SHARED_FOLDER / "users" / str(item["user_id"])
    destination = base / item["original_path"]
    source = Path(item["trash_path"])
    if not source.exists() or destination.exists():
        flash("Restore could not complete because the source is missing or the destination already exists.")
        return redirect(url_for("admin_trash"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(destination))
    with database_connection() as connection:
        connection.execute("UPDATE trash_items SET restored_at = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), trash_id))
    audit_event("restore_from_trash", "file" if not item["is_dir"] else "folder", trash_id, f"user={item['user_id']}; path={item['original_path']}")
    flash("Item restored successfully.")
    return redirect(url_for("admin_trash"))


@app.route("/admin/trash/<int:trash_id>/purge", methods=["POST"])
def admin_purge_trash(trash_id):
    response = require_permission("storage.recycle_bin")
    if response:
        return response
    with database_connection() as connection:
        item = connection.execute("SELECT * FROM trash_items WHERE id = ? AND restored_at IS NULL AND purged_at IS NULL", (trash_id,)).fetchone()
    if not item:
        abort(404, "Trash item not found")
    source = Path(item["trash_path"]).resolve()
    trash_root = (SHARED_FOLDER / ".trash" / str(item["user_id"])).resolve()
    try:
        source.relative_to(trash_root)
    except ValueError:
        abort(400, "Invalid trash path")
    if source.exists():
        if source.is_dir():
            shutil.rmtree(source)
        else:
            source.unlink()
    with database_connection() as connection:
        connection.execute("UPDATE trash_items SET purged_at = ? WHERE id = ? AND restored_at IS NULL AND purged_at IS NULL", (datetime.now(timezone.utc).isoformat(), trash_id))
    audit_event("purge_trash", "folder" if item["is_dir"] else "file", trash_id, f"user={item['user_id']}; path={item['original_path']}")
    flash("Item permanently deleted.")
    return redirect(url_for("admin_trash"))


@app.route("/admin/backup", methods=["POST"])
def admin_backup():
    """Create an explicit local snapshot; this is not a cloud-provider backup."""
    response = require_permission("storage.manage")
    if response:
        return response
    backup_root = SHARED_FOLDER / ".backups"
    backup_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = backup_root / f"cloud_rdx_{stamp}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as backup:
        for path in (SHARED_FOLDER / "users").rglob("*"):
            if path.is_file():
                backup.write(path, Path("users") / path.relative_to(SHARED_FOLDER / "users"))
        with database_connection() as connection:
            users = [dict(row) for row in connection.execute("SELECT id, username, status, created_at FROM users").fetchall()]
        backup.writestr("manifest.txt", "Cloud Rdx local snapshot\n" + "\n".join(f"{item['id']} {item['username']} {item['status']}" for item in users))
    audit_event("create_backup", "backup", archive.name, "local zip snapshot")
    flash(f"Local backup created: {archive.name}. Store a copy separately for disaster recovery.")
    return redirect(url_for("admin_manage"))


@app.route("/recycle-bin")
@app.route("/recycle-bin/")
def user_trash():
    response = require_storage_user()
    if response:
        return response
    with database_connection() as connection:
        items = connection.execute("SELECT * FROM trash_items WHERE user_id = ? AND restored_at IS NULL AND purged_at IS NULL ORDER BY deleted_at DESC", (session["user_id"],)).fetchall()
    return render_template_string(USER_TRASH_PAGE, items=[dict(item) for item in items])


def user_trash_item(trash_id):
    with database_connection() as connection:
        item = connection.execute("SELECT * FROM trash_items WHERE id = ? AND user_id = ? AND restored_at IS NULL AND purged_at IS NULL", (trash_id, session["user_id"])).fetchone()
    if not item:
        abort(404, "Recycle-bin item not found")
    trash_root = (SHARED_FOLDER / ".trash" / str(session["user_id"])).resolve()
    source = Path(item["trash_path"]).resolve()
    try:
        source.relative_to(trash_root)
    except ValueError:
        abort(400, "Invalid recycle-bin path")
    return item, trash_root, source


@app.route("/recycle-bin/<int:trash_id>/restore", methods=["POST"])
def restore_user_trash(trash_id):
    response = require_storage_user()
    if response:
        return response
    require_storage_operation("edit")
    item, trash_root, source = user_trash_item(trash_id)
    base = user_folder().resolve()
    destination = (base / item["original_path"]).resolve()
    try:
        destination.relative_to(base)
    except ValueError:
        abort(400, "Invalid restore path")
    if not source.exists() or destination.exists():
        flash("Restore could not complete because the source is missing or the destination already exists.")
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(destination))
        with database_connection() as connection:
            connection.execute("UPDATE trash_items SET restored_at = ? WHERE id = ? AND user_id = ?", (datetime.now(timezone.utc).isoformat(), trash_id, session["user_id"]))
        audit_event("restore_own_trash", "folder" if item["is_dir"] else "file", trash_id, f"path={item['original_path']}")
        flash(f"{item['item_name']} was restored.")
    return redirect(url_for("user_trash"))


@app.route("/recycle-bin/<int:trash_id>/purge", methods=["POST"])
def purge_user_trash(trash_id):
    response = require_storage_user()
    if response:
        return response
    require_storage_operation("delete")
    item, trash_root, source = user_trash_item(trash_id)
    if source.exists():
        shutil.rmtree(source) if source.is_dir() else source.unlink()
    with database_connection() as connection:
        connection.execute("UPDATE trash_items SET purged_at = ? WHERE id = ? AND user_id = ? AND restored_at IS NULL AND purged_at IS NULL", (datetime.now(timezone.utc).isoformat(), trash_id, session["user_id"]))
    audit_event("purge_own_trash", "folder" if item["is_dir"] else "file", trash_id, f"path={item['original_path']}")
    flash(f"{item['item_name']} was permanently deleted.")
    return redirect(url_for("user_trash"))


@app.route("/admin/security/2fa", methods=["GET", "POST"])
def admin_2fa():
    response = require_admin()
    if response:
        return response
    require_totp_available()
    user = current_user()
    if user["totp_enabled"]:
        return render_template_string("""<!doctype html><title>2FA security</title><link rel='stylesheet' href='{{ url_for('static', filename='admin-theme.css') }}'><body class='admin-theme'><main class='main'><h1>Authenticator 2FA enabled</h1><p>Your administrator account requires an authenticator code at sign-in.</p><a class='button' href='{{ url_for('admin_panel') }}'>Back to dashboard</a></main></body>""")
    secret = session.get("totp_setup_secret") or pyotp.random_base32()
    session["totp_setup_secret"] = secret
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if not pyotp.TOTP(secret).verify(code, valid_window=1):
            return render_template_string(TOTP_SETUP_PAGE, secret=secret, provisioning_uri=pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name="Cloud Rdx"), error="Enter a valid code from your authenticator app.")
        with database_connection() as connection:
            connection.execute("UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?", (secret, user["id"]))
        session.pop("totp_setup_secret", None)
        audit_event("enable_2fa", "user", user["id"])
        flash("Authenticator 2FA is now enabled for your administrator account.")
        return redirect(url_for("admin_panel"))
    return render_template_string(TOTP_SETUP_PAGE, secret=secret, provisioning_uri=pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name="Cloud Rdx"), error=None)


@app.route("/admin/security/sessions")
def admin_sessions():
    response = require_login()
    if response:
        return response
    with database_connection() as connection:
        sessions = connection.execute("SELECT id, device_label, ip_address, created_at, last_seen, revoked_at FROM device_sessions WHERE user_id = ? ORDER BY last_seen DESC", (session["user_id"],)).fetchall()
    return render_template_string(ADMIN_SESSIONS_PAGE, sessions=[dict(row) for row in sessions])


@app.route("/admin/security/sessions/<int:session_id>/revoke", methods=["POST"])
def revoke_admin_session(session_id):
    response = require_login()
    if response:
        return response
    with database_connection() as connection:
        result = connection.execute("UPDATE device_sessions SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL", (datetime.now(timezone.utc).isoformat(), session_id, session["user_id"]))
    if result.rowcount:
        audit_event("revoke_session", "device_session", session_id)
        flash("The selected device session was revoked.")
    return redirect(url_for("admin_sessions"))


TOTP_SETUP_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Enable 2FA</title><link rel="stylesheet" href="{{ url_for('static', filename='admin-theme.css') }}"></head><body class="admin-theme"><main class="main"><section class="panel" style="max-width:700px;margin:40px auto"><div class="panel-head"><h2>Enable authenticator 2FA</h2><p>Add this account to an authenticator app, then verify one generated code.</p></div><div style="padding:22px"><p><strong>Setup key</strong></p><p style="word-break:break-all;font-family:monospace">{{ secret }}</p><p><strong>Provisioning URI</strong></p><p style="word-break:break-all;font-family:monospace">{{ provisioning_uri }}</p>{% if error %}<p class="notice">{{ error }}</p>{% endif %}<form method="post"><label for="code">Six-digit authenticator code</label><input id="code" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required><button type="submit">Enable 2FA</button></form></div></section></main></body></html>
"""


ADMIN_SESSIONS_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sessions</title><link rel="stylesheet" href="{{ url_for('static', filename='admin-theme.css') }}"></head><body class="admin-theme"><main class="main"><section class="panel" style="margin:40px auto;max-width:900px"><div class="panel-head"><h2>Active sessions and devices</h2><p>Revoke any device you no longer recognize. The current session cannot be revoked from this page.</p></div><div class="table-responsive"><table><thead><tr><th>Device</th><th>IP</th><th>Created</th><th>Last seen</th><th>Status</th><th></th></tr></thead><tbody>{% for item in sessions %}<tr><td>{{ item.device_label }}</td><td>{{ item.ip_address or 'Unknown' }}</td><td>{{ item.created_at[:19].replace('T',' ') }}</td><td>{{ item.last_seen[:19].replace('T',' ') }}</td><td>{{ 'Revoked' if item.revoked_at else 'Active' }}</td><td>{% if not item.revoked_at %}<form method="post" action="{{ url_for('revoke_admin_session', session_id=item.id) }}"><button class="danger" type="submit">Revoke</button></form>{% endif %}</td></tr>{% else %}<tr><td colspan="6">No sessions recorded.</td></tr>{% endfor %}</tbody></table></div></section></main></body></html>
"""


@app.route("/logout")
def logout():
    token = session.get("device_token")
    if token:
        with database_connection() as connection:
            connection.execute("UPDATE device_sessions SET revoked_at = ? WHERE session_token_hash = ? AND revoked_at IS NULL", (datetime.now(timezone.utc).isoformat(), device_token_hash(token)))
    session.clear()
    return redirect(url_for("login"))


@app.route("/guide/cloud-storage")
def cloud_storage_guide():
    response = require_login()
    if response:
        return response
    return render_template_string(
        CLOUD_STORAGE_GUIDE_PAGE,
        back_url=url_for("admin_panel" if is_admin() else "files"),
    )


@app.route("/files/")
@app.route("/files/<path:subpath>")
def files(subpath=""):
    redirect_response = require_storage_user()
    if redirect_response:
        return redirect_response
    try:
        folder = safe_path(subpath)
    except ValueError:
        abort(400, "Invalid path")
    if not folder.is_dir():
        abort(404, "Folder not found")

    items = []
    total_size = 0
    for path in sorted(folder.iterdir(), key=lambda entry: (not entry.is_dir(), entry.name.lower())):
        item = {"name": path.name, "path": path.relative_to(folder).as_posix() if not subpath else (Path(subpath) / path.name).as_posix(), "is_dir": path.is_dir(), "size": 0}
        if path.is_file():
            item["size"] = path.stat().st_size
            total_size += item["size"]
        items.append(item)

    parent = Path(subpath).parent.as_posix() if subpath else None
    if parent == ".":
        parent = ""
    user = current_user()
    quota = user_quota(user["id"])
    used = user_usage(user["id"])[1]
    quota_percent = min(100, int(used * 100 / quota)) if quota else 0
    remaining_size = max(0, quota - used) if quota else 0
    return render_template_string(PAGE, title="My storage", items=items, subpath=subpath, parent=parent, breadcrumbs=breadcrumbs(subpath), item_count=len(items), total_size=used, quota=quota, remaining_size=remaining_size, quota_percent=quota_percent, allow_upload=storage_permission(user["id"], "upload"), allow_download=storage_permission(user["id"], "download"), allow_share=policy_enabled("allow_public_sharing", False) and not emergency_enabled("disable_file_sharing"), has_admin_access=has_admin_access(), admin_title=admin_console_context()["admin_title"])


@app.route("/download/<path:subpath>")
def download(subpath):
    redirect_response = require_storage_permission("download")
    if redirect_response:
        return redirect_response
    try:
        full = safe_path(subpath)
    except ValueError:
        abort(400, "Invalid path")
    if not full.is_file():
        abort(404, "File not found")
    audit_event(
        "download",
        "file",
        full.name,
        f"path={full.relative_to(user_folder()).as_posix()}; size={full.stat().st_size}",
    )
    return send_from_directory(full.parent, full.name, as_attachment=True)


@app.route("/downloads/bulk", methods=["POST"])
def bulk_download():
    redirect_response = require_storage_permission("download")
    if redirect_response:
        return redirect_response
    selected_paths = list(dict.fromkeys(request.form.getlist("paths")))
    if not selected_paths:
        abort(400, "Select at least one file")
    if len(selected_paths) > 100:
        abort(400, "You can download up to 100 files at a time")
    user = current_user()
    files_to_archive = []
    total_size = 0
    for relative_path in selected_paths:
        try:
            target = safe_path(relative_path)
        except ValueError:
            abort(400, "Invalid file selection")
        if not target.is_file():
            abort(400, "Bulk downloads support files only")
        size = target.stat().st_size
        total_size += size
        files_to_archive.append((target, relative_path))
    if total_size > MAX_UPLOAD_BYTES * 10:
        abort(400, "The selected files are too large for one archive")
    archive_fd, archive_name = tempfile.mkstemp(prefix="cloud_rdx_", suffix=".zip")
    os.close(archive_fd)
    archive_path = Path(archive_name)
    try:
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for target, relative_path in files_to_archive:
                archive.write(target, Path(relative_path).as_posix())
        audit_event("bulk_download", "archive", archive_path.name, f"count={len(files_to_archive)}; size={total_size}")
        response = send_file(archive_path, as_attachment=True, download_name="cloud_rdx_files.zip", mimetype="application/zip")
        response.call_on_close(lambda: archive_path.unlink(missing_ok=True))
        return response
    except Exception:
        archive_path.unlink(missing_ok=True)
        raise


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def install_file_without_overwrite(staged_path, destination):
    try:
        os.link(staged_path, destination)
    except FileExistsError:
        return False
    Path(staged_path).unlink()
    return True


@app.route("/upload/<path:subpath>", methods=["POST"])
@app.route("/upload/", methods=["POST"])
def upload(subpath=""):
    redirect_response = require_storage_permission("upload")
    if redirect_response:
        return redirect_response
    try:
        folder = safe_path(subpath)
    except ValueError:
        abort(400, "Invalid path")
    if not folder.is_dir():
        abort(404, "Folder not found")
    uploaded = request.files.get("file")
    filename = secure_filename(uploaded.filename) if uploaded else ""
    if not filename:
        flash("Choose a file before uploading.")
        return redirect(url_for("files", subpath=subpath))
    destination = folder / filename
    if destination.exists():
        flash("A file or folder with that name already exists. Rename it before uploading.")
        return redirect(url_for("files", subpath=subpath))
    uploaded.stream.seek(0, os.SEEK_END)
    upload_size = uploaded.stream.tell()
    uploaded.stream.seek(0)
    user = current_user()
    if not quota_allows(user["id"], upload_size):
        audit_event("upload_rejected_quota", "file", filename, f"size={upload_size}", status="denied")
        flash("Upload rejected because it would exceed your storage quota.")
        return redirect(url_for("files", subpath=subpath))
    staging_root = SHARED_FOLDER / ".quarantine" / ".staging"
    staging_root.mkdir(parents=True, exist_ok=True)
    descriptor, staging_name = tempfile.mkstemp(
        prefix="upload-", suffix=".scan", dir=staging_root
    )
    os.close(descriptor)
    staged_path = Path(staging_name)
    try:
        uploaded.save(staged_path)
    except Exception:
        staged_path.unlink(missing_ok=True)
        raise
    try:
        scan_status, detection = scan_with_clamav(staged_path)
    except MalwareScannerUnavailable:
        if os.getenv("CLAMD_REQUIRED", "0").strip().lower() in {
            "1", "true", "yes", "on"
        }:
            staged_path.unlink(missing_ok=True)
            audit_event(
                "upload_scan_unavailable",
                "file",
                filename,
                f"path={destination.relative_to(user_folder())}; size={upload_size}",
                status="denied",
                risk_level="HIGH",
            )
            abort(503, "Upload was not accepted because malware scanning is unavailable.")
        app.logger.warning(
            "ClamAV unavailable; accepting upload without malware scan "
            "(set CLAMD_REQUIRED=1 to reject unscanned uploads)"
        )
        audit_event(
            "upload_scan_unavailable",
            "file",
            filename,
            f"path={destination.relative_to(user_folder())}; size={upload_size}",
            status="warning",
            risk_level="HIGH",
        )
        scan_status, detection = "unscanned", None

    if scan_status == "infected":
        if not detection:
            staged_path.unlink(missing_ok=True)
            audit_event(
                "upload_scan_inconclusive",
                "file",
                filename,
                f"path={destination.relative_to(user_folder())}",
                status="denied",
                risk_level="HIGH",
            )
            abort(503, "Upload was not accepted because the scan result was inconclusive.")
        digest = file_sha256(staged_path)
        user_quarantine = SHARED_FOLDER / ".quarantine" / str(user["id"])
        user_quarantine.mkdir(parents=True, exist_ok=True)
        quarantine_path = user_quarantine / f"{secrets.token_hex(16)}.quarantine"
        os.replace(staged_path, quarantine_path)
        with database_connection() as connection:
            connection.execute(
                """
                INSERT INTO quarantined_files
                    (user_id, original_path, quarantine_path, sha256, detection,
                     created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user["id"],
                    Path(subpath, filename).as_posix(),
                    str(quarantine_path),
                    digest,
                    detection[:255],
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        audit_event(
            "malware_quarantined",
            "file",
            filename,
            f"path={Path(subpath, filename).as_posix()}; sha256={digest}; detection={detection[:180]}",
            status="denied",
            risk_level="CRITICAL",
        )
        flash("The file was isolated in quarantine because ClamAV detected malware.")
        return redirect(url_for("files", subpath=subpath))
    if scan_status not in {"clean", "unscanned"}:
        staged_path.unlink(missing_ok=True)
        audit_event(
            "upload_scan_inconclusive",
            "file",
            filename,
            f"path={destination.relative_to(user_folder())}",
            status="denied",
            risk_level="HIGH",
        )
        abort(503, "Upload was not accepted because the scan result was inconclusive.")
    if scan_status not in {"clean", "unscanned"}:
        staged_path.unlink(missing_ok=True)
        audit_event(
            "upload_scan_inconclusive",
            "file",
            filename,
            f"path={destination.relative_to(user_folder())}",
            status="denied",
            risk_level="HIGH",
        )
        abort(503, "Upload was not accepted because the scan result was inconclusive.")

    if not install_file_without_overwrite(staged_path, destination):
        staged_path.unlink(missing_ok=True)
        flash("A file or folder with that name already exists. Rename it before uploading.")
        return redirect(url_for("files", subpath=subpath))
    audit_event("upload", "file", filename, f"path={destination.relative_to(user_folder())}; size={upload_size}")
    flash(f"{filename} was added to your storage.")
    return redirect(url_for("files", subpath=subpath))


@app.route("/folder/<path:subpath>", methods=["POST"])
@app.route("/folder/", methods=["POST"])
def create_folder(subpath=""):
    redirect_response = require_storage_user()
    if redirect_response:
        return redirect_response
    require_storage_operation("edit")
    try:
        folder = safe_path(subpath)
    except ValueError:
        abort(400, "Invalid path")
    name = secure_filename(request.form.get("name", ""))
    if not name or name in {".", ".."}:
        flash("Enter a valid folder name.")
    elif (folder / name).exists():
        flash("That folder already exists.")
    else:
        (folder / name).mkdir()
        audit_event("create_folder", "folder", name, f"path={Path(subpath, name).as_posix()}")
        flash(f"Folder {name} created.")
    return redirect(url_for("files", subpath=subpath))


def storage_mutation(action, subpath, destination_name):
    user = current_user()
    require_storage_operation("edit")
    source = safe_path(subpath)
    if not source.exists() or source == user_folder():
        abort(404, "Item not found")
    name = secure_filename(destination_name)
    if not name or name in {".", ".."}:
        abort(400, "Invalid destination name")
    destination = source.parent / name
    destination = destination.resolve()
    destination.relative_to(user_folder().resolve())
    if destination.exists():
        abort(409, "Destination already exists")
    is_dir = source.is_dir()
    if action == "copy":
        shutil.copytree(source, destination) if is_dir else shutil.copy2(source, destination)
    elif action == "move":
        shutil.move(str(source), str(destination))
    elif action == "rename":
        source.rename(destination)
    else:
        abort(400, "Unsupported operation")
    audit_event(action, "folder" if is_dir else "file", subpath, f"destination={destination.relative_to(user_folder())}")
    return redirect(url_for("files", subpath=Path(subpath).parent.as_posix() if Path(subpath).parent.as_posix() != "." else ""))


@app.route("/rename/<path:subpath>", methods=["POST"])
def rename_item(subpath):
    response = require_storage_user()
    if response:
        return response
    return storage_mutation("rename", subpath, request.form.get("name", ""))


@app.route("/copy/<path:subpath>", methods=["POST"])
def copy_item(subpath):
    response = require_storage_user()
    if response:
        return response
    return storage_mutation("copy", subpath, request.form.get("name", ""))


@app.route("/move/<path:subpath>", methods=["POST"])
def move_item(subpath):
    response = require_storage_user()
    if response:
        return response
    return storage_mutation("move", subpath, request.form.get("name", ""))


@app.route("/delete/<path:subpath>", methods=["POST"])
def delete_item(subpath):
    redirect_response = require_storage_user()
    if redirect_response:
        return redirect_response
    require_storage_operation("delete")
    try:
        target = safe_path(subpath)
    except ValueError:
        abort(400, "Invalid path")
    if not target.exists() or target == user_folder():
        abort(404, "Item not found")
    user = current_user()
    trash_item(user["id"], target, user["id"])
    flash(f"{target.name} moved to the recycle bin. It can be restored by an administrator.")
    return redirect(url_for("files", subpath=Path(subpath).parent.as_posix() if Path(subpath).parent.as_posix() != "." else ""))


def run_desktop_application():
    """Run the Flask interface inside a native desktop window."""
    try:
        import webview
    except ImportError as error:
        raise RuntimeError(
            "The desktop runtime is not installed. Install dependencies with: pip install -r requirements.txt"
        ) from error

    SHARED_FOLDER.mkdir(parents=True, exist_ok=True)
    initialize_database()
    server = make_server("127.0.0.1", 0, app, threaded=True)
    server_thread = threading.Thread(target=server.serve_forever, name="cloud-rdx-server", daemon=True)
    server_thread.start()
    window = webview.create_window(
        "Cloud Rdx",
        f"http://127.0.0.1:{server.server_port}",
        width=1360,
        height=860,
        min_size=(980, 640),
        resizable=True,
        text_select=True,
    )
    window.events.closed += server.shutdown
    webview.start(debug=False)


def run_web_application():
    """Start the Flask application so it is reachable from a browser or host."""
    SHARED_FOLDER.mkdir(parents=True, exist_ok=True)
    initialize_database()
    print(f"Cloud Rdx is running at http://127.0.0.1:{PORT}", flush=True)
    if HOST not in {"127.0.0.1", "localhost"}:
        print(f"Network access is available at http://{HOST}:{PORT}", flush=True)
    app.run(host=HOST, port=PORT, debug=False, threaded=True, use_reloader=False)


if __name__ == "__main__":
    # Packaged desktop builds keep their native window. Running app.py directly
    # starts a normal web server, which is also the entrypoint used by hosts.
    if getattr(sys, "frozen", False) or os.getenv("CLOUD_RDX_DESKTOP", "").lower() in {"1", "true", "yes"}:
        run_desktop_application()
    else:
        run_web_application()
from datetime import datetime, timedelta, timezone
from collections.abc import Mapping
import base64
import csv
import io
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import sys
import tempfile
import threading
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken
from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from joserfc.errors import JoseError
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template_string,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.serving import make_server
from cloud_security_services import (
    MalwareScannerUnavailable,
    scan_with_clamav,
    upload_immutable_backup,
)

try:
    import pyotp
except ImportError:  # Optional during legacy upgrades; enabled when dependency is installed.
    pyotp = None

try:
    import razorpay  # type: ignore[import-not-found]
except ImportError:  # Optional until payment credentials and dependency are configured.
    razorpay = None


APP_FOLDER = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
RESOURCE_FOLDER = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
load_dotenv(APP_FOLDER / ".env", override=False)
app = Flask(__name__)

SHARED_FOLDER = Path(os.getenv("SHARED_FOLDER", APP_FOLDER / "storage")).resolve()
DATABASE = Path(os.getenv("FILE_SERVER_DATABASE", SHARED_FOLDER / "cloud_rdx.sqlite3")).resolve()
SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))
LOGIN_WINDOW_MINUTES = int(os.getenv("LOGIN_WINDOW_MINUTES", "15"))
LOGIN_MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOGIN_LOCKOUT_MINUTES = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))
TRUSTED_PROXY_HOPS = int(os.getenv("TRUSTED_PROXY_HOPS", "0"))
INACTIVE_USER_DAYS = int(os.getenv("INACTIVE_USER_DAYS", "30"))
MAINTENANCE_DURATION_HOURS = 6
EMERGENCY_CONTROL_LABELS = {
    "global_read_only": ("Global read-only mode", "Blocks all user file writes and changes."),
    "disable_uploads": ("Disable uploads", "Prevents new file uploads."),
    "disable_downloads": ("Disable downloads", "Prevents file downloads."),
    "disable_deletion": ("Disable file deletion", "Prevents moving files or folders to the recycle bin."),
    "disable_editing": ("Disable file editing", "Prevents folder creation, copy, move, and rename."),
    "disable_file_sharing": ("Disable file sharing", "Blocks new share links and public access to existing links."),
    "revoke_active_share_links": ("Revoke active share links", "Temporarily suspends every active public share link without deleting it."),
    "freeze_registrations": ("Freeze new account registration", "Blocks password and social-provider account creation."),
    "force_reauthentication": ("Force re-authentication", "Revokes all user sessions except the authorized administrator."),
    "force_password_reset": ("Force password reset", "Requires password users to change their password after sign-in."),
    "require_two_factor": ("Require two-factor authentication", "Requires users to enroll in authenticator-based 2FA."),
    "disable_api_access": ("Disable API access", "Blocks application API routes; payment webhooks remain available."),
    "disable_sync_automation": ("Disable sync/automation", "Pauses scheduled Azure sync jobs until the control is cleared."),
    "block_public_access": ("Block public access", "Blocks unauthenticated access to shared files."),
    "block_new_devices": ("Block new devices", "Only previously approved browser devices may sign in."),
    "enhanced_monitoring": ("Enhanced security monitoring", "Records additional security-relevant activity."),
    "emergency_rate_limit": ("Emergency rate-limit mode", "Applies stricter limits to API and file-transfer routes."),
    "backup_protection": ("Backup protection mode", "Backups are append-only in the current application."),
    "maintenance_mode": ("Maintenance mode", "Shows a maintenance page to users while retaining owner access."),
}
EMERGENCY_PRESETS = {
    "NORMAL MODE": {},
    "RESTRICTED MODE": {
        "disable_uploads": True,
        "disable_deletion": True,
        "disable_editing": True,
        "disable_file_sharing": True,
    },
    "SECURITY MODE": {
        "disable_uploads": True,
        "disable_downloads": True,
        "disable_deletion": True,
        "disable_file_sharing": True,
        "disable_api_access": True,
        "block_new_devices": True,
        "enhanced_monitoring": True,
    },
    "FULL LOCKDOWN": {
        "global_read_only": True,
        "disable_uploads": True,
        "disable_downloads": True,
        "disable_deletion": True,
        "disable_editing": True,
        "disable_file_sharing": True,
        "revoke_active_share_links": True,
        "freeze_registrations": True,
        "force_reauthentication": True,
        "disable_api_access": True,
        "block_public_access": True,
        "enhanced_monitoring": True,
    },
}
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_MB", "100")) * 1024 * 1024
PORT = int(os.getenv("PORT", "8000"))
HOST = os.getenv("HOST", os.getenv("APP_HOST", "0.0.0.0"))
GOOGLE_OAUTH_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip()
GOOGLE_OAUTH_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "").strip()
GITHUB_OAUTH_CLIENT_ID = os.getenv("GITHUB_OAUTH_CLIENT_ID", "").strip()
GITHUB_OAUTH_CLIENT_SECRET = os.getenv("GITHUB_OAUTH_CLIENT_SECRET", "").strip()
FLASK_SECRET_KEY_CONFIGURED = bool(os.getenv("FLASK_SECRET_KEY"))
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0") == "1",
)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
app.config["PREFERRED_URL_SCHEME"] = "https"
if TRUSTED_PROXY_HOPS < 0:
    raise ValueError("TRUSTED_PROXY_HOPS must be zero or greater")
if TRUSTED_PROXY_HOPS:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXY_HOPS, x_proto=TRUSTED_PROXY_HOPS)
oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=GOOGLE_OAUTH_CLIENT_ID,
    client_secret=GOOGLE_OAUTH_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)
github = oauth.register(
    name="github",
    client_id=GITHUB_OAUTH_CLIENT_ID,
    client_secret=GITHUB_OAUTH_CLIENT_SECRET,
    authorize_url="https://github.com/login/oauth/authorize",
    access_token_url="https://github.com/login/oauth/access_token",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "read:user user:email"},
)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admindivya")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
PAYMENT_QR_URL = os.getenv("PAYMENT_QR_URL", "/payment-qr")
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET", "")
RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "")
STORAGE_COST_PER_GB_INR = float(os.getenv("STORAGE_COST_PER_GB_INR", "0"))
RECOVERY_PASSWORD_CHARS = "RDxcloud.div@16"
ADMIN_ROLE = "system_admin"
OWNER_USERNAME = ADMIN_USERNAME
CSRF_SESSION_KEY = "csrf_token"
PASSWORD_HASHER = PasswordHasher()


PAGE = """
<!doctype html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }} - Cloud Rdx</title>
    <script src="{{ url_for('static', filename='cloud-dashboard.js') }}"></script>
    <style>
        :root {
            --ink: #17212b;
            --muted: #647483;
            --line: #d8e1e8;
            --paper: #f2f6f8;
            --panel: #ffffff;
            --mint: #dff5f1;
            --green: #087f73;
            --green-dark: #122b3a;
            --gold: #f0b44d;
            --shadow: 0 12px 30px rgba(25, 49, 66, .08);
        }
        * { box-sizing: border-box; }
        html { overflow-x: hidden; }
        body {
            margin: 0;
            color: var(--ink);
            background: var(--paper);
            font-family: 'Segoe UI', Arial, sans-serif;
            background-image: linear-gradient(rgba(216, 225, 232, .28) 1px, transparent 1px), linear-gradient(90deg, rgba(216, 225, 232, .28) 1px, transparent 1px);
            background-size: 32px 32px;
        }
        button, input { font: inherit; }
        button, a, label { -webkit-tap-highlight-color: transparent; }
        button, .upload-label, .download { min-height: 44px; }
        a { color: inherit; }
        .shell { min-height: 100vh; display: grid; grid-template-columns: 248px 1fr; }
        .rail {
            padding: 30px 22px;
            color: #eaf8ef;
            background: #122b3a;
            display: flex;
            flex-direction: column;
        }
        .brand { display: flex; align-items: center; gap: 12px; font: 700 14px Consolas, monospace; letter-spacing: .02em; }
        .brand-mark { width: 35px; height: 35px; display: grid; place-items: center; color: #122b3a; background: var(--gold); border-radius: 6px; font: 800 15px Consolas, monospace; }
        .rail-nav { margin-top: 70px; display: grid; gap: 10px; font-family: Arial, sans-serif; font-size: 14px; }
        .rail-link { display: flex; align-items: center; gap: 12px; padding: 12px 13px; color: #a9bfcd; text-decoration: none; border-radius: 6px; }
        .rail-link.active, .rail-link:hover { color: #fff; background: rgba(255,255,255,.11); }
        .rail-icon { width: 18px; text-align: center; font-size: 16px; }
        .rail-bottom { margin-top: auto; padding: 17px 14px; border-top: 1px solid rgba(255,255,255,.15); color: #a9cbb6; font: 12px/1.6 Arial, sans-serif; }
        .menu-toggle { display: none; margin-left: auto; padding: 9px 12px; color: #eaf8ef; background: transparent; border: 1px solid rgba(255,255,255,.3); border-radius: 7px; cursor: pointer; font-size: 20px; line-height: 1; }
        .menu-backdrop { display: none; }
        .main { padding: 36px clamp(22px, 5vw, 72px); min-width: 0; }
        .topbar { display: flex; justify-content: space-between; align-items: center; gap: 24px; margin-bottom: 43px; }
        .eyebrow { margin: 0 0 10px; color: var(--green); text-transform: uppercase; letter-spacing: .16em; font: 700 11px Arial, sans-serif; }
        h1, h2, p { margin-top: 0; }
        h1 { margin-bottom: 9px; font-size: clamp(30px, 4vw, 48px); line-height: 1; font-weight: 650; letter-spacing: -.03em; }
        .subtitle { margin-bottom: 0; color: var(--muted); font: 14px Arial, sans-serif; }
        .user-chip { display: flex; align-items: center; gap: 10px; padding: 8px 12px 8px 8px; color: var(--ink); background: var(--panel); border: 1px solid var(--line); border-radius: 999px; font: 13px Arial, sans-serif; white-space: nowrap; }
        .avatar { display: grid; place-items: center; width: 29px; height: 29px; color: #fff; background: var(--green); border-radius: 50%; font-weight: 700; }
        .layout { display: grid; grid-template-columns: minmax(0, 1fr) 285px; gap: 25px; align-items: start; }
        .panel { background: rgba(255,255,255,.94); border: 1px solid var(--line); border-radius: 8px; box-shadow: var(--shadow); }
        .browser { overflow: hidden; }
        .browser-head { display: flex; justify-content: space-between; align-items: center; padding: 18px 23px; border-bottom: 1px solid var(--line); gap: 14px; }
        .crumbs { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; font: 13px Consolas, monospace; }
        .crumbs a { color: var(--green); text-decoration: none; }
        .crumb-sep { color: #aab9b1; }
        .upload-label, .action-button { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 10px 14px; color: #fff; background: var(--green); border: 0; border-radius: 8px; cursor: pointer; font: 700 12px Arial, sans-serif; text-decoration: none; }
        .upload-label:hover, .action-button:hover { background: var(--green-dark); }
        .file-list { padding: 5px 23px 14px; }
        .file-row { display: grid; grid-template-columns: 24px 38px minmax(0, 1fr) 110px 100px; gap: 12px; align-items: center; min-height: 62px; border-bottom: 1px solid #e8eef2; font-family: Consolas, monospace; }
        .file-row:last-child { border-bottom: 0; }
        .file-icon { width: 34px; height: 34px; display: grid; place-items: center; border-radius: 6px; font-size: 15px; background: #e5f5f2; color: var(--green); }
        .file-icon.doc { color: #b06b0c; background: #fff3dc; }
        .file-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-size: 13px; }
        .file-name a { text-decoration: none; }
        .file-name a:hover { color: var(--green); }
        .file-meta { color: var(--muted); font-size: 11px; }
        .download { justify-self: end; color: var(--green); font-size: 12px; font-weight: 700; text-decoration: none; }
        .download:hover { text-decoration: underline; }
        .empty { padding: 65px 20px; color: var(--muted); text-align: center; font-family: Arial, sans-serif; }
        .empty strong { display: block; margin-bottom: 8px; color: var(--ink); font: 18px Georgia, serif; }
        .side { display: grid; gap: 17px; }
        .side-card { padding: 20px; }
        .side-card h2 { margin-bottom: 17px; font-size: 18px; font-weight: 500; }
        .storage-stat { display: flex; justify-content: space-between; margin-bottom: 10px; font: 12px Arial, sans-serif; }
        .storage-stat span:last-child { color: var(--green); font-weight: 700; }
        .meter { height: 8px; overflow: hidden; background: #e3ebef; border-radius: 3px; }
        .meter span { display: block; width: 100%; height: 100%; background: var(--gold); border-radius: inherit; }
        .storage-detail { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin: 16px 0 12px; }
        .storage-detail div { padding: 10px; background: #f7fafc; border: 1px solid var(--line); border-radius: 8px; }
        .storage-detail small { display: block; margin-bottom: 4px; color: var(--muted); font: 10px Arial, sans-serif; text-transform: uppercase; letter-spacing: .06em; }
        .storage-detail strong { color: var(--ink); font: 700 14px Consolas, monospace; }
        .storage-warning { margin: 12px 0 0; padding: 10px 12px; color: #875d0b; background: #fff5d9; border: 1px solid #f0d58c; border-radius: 7px; font: 12px/1.45 Arial, sans-serif; }
        .storage-warning.critical { color: #963d2c; background: #fff0ec; border-color: #efb7aa; }
        .file-row button.download { min-height: 36px; padding: 7px 10px; color: #fff; background: var(--green); border: 0; border-radius: 6px; cursor: pointer; font: 700 11px Arial, sans-serif; }
        .file-row button.download:hover { background: var(--green-dark); }
        .file-select { width: 16px; height: 16px; accent-color: var(--green); }
        .bulk-actions { display: flex; align-items: center; gap: 10px; padding: 12px 23px; background: #f7fafc; border-bottom: 1px solid var(--line); font: 12px Arial, sans-serif; }
        .bulk-actions button { padding: 8px 11px; color: #fff; background: var(--green); border: 0; border-radius: 6px; cursor: pointer; font-weight: 700; }
        .bulk-actions button:disabled { opacity: .45; cursor: not-allowed; }
        .upload-status { display: none; margin: 0 23px 16px; padding: 14px; background: #f7fafc; border: 1px solid var(--line); border-radius: 8px; font: 12px Arial, sans-serif; }
        .upload-status.visible { display: block; }
        .upload-status-head { display: flex; justify-content: space-between; gap: 12px; margin-bottom: 8px; }
        .upload-status progress { width: 100%; height: 9px; accent-color: var(--green); }
        .upload-status small { display: block; margin-top: 7px; color: var(--muted); }
        .cancel-upload { padding: 7px 10px; color: #963d2c; background: #fff0ec; border: 1px solid #efb7aa; border-radius: 6px; cursor: pointer; font-size: 11px; font-weight: 700; }
        .dropzone { padding: 22px 18px; text-align: center; background: var(--mint); border: 1px dashed #55aaa0; border-radius: 6px; }
        .dropzone-icon { margin-bottom: 9px; font-size: 22px; }
        .dropzone p { margin-bottom: 14px; color: #456c54; font: 12px/1.5 Arial, sans-serif; }
        .dropzone input { width: 100%; color: #456c54; font: 11px Arial, sans-serif; }
        .flash { margin: -25px 0 25px; padding: 12px 15px; color: #7a5311; background: #fff4d7; border: 1px solid #f3db9d; border-radius: 8px; font: 13px Arial, sans-serif; }
        .logout { color: #b9d7c3; text-decoration: none; }
        @media (max-width: 900px) { .shell { grid-template-columns: 72px 1fr; } .rail { padding: 22px 13px; } .brand span, .rail-link span:not(.rail-icon), .rail-bottom { display: none; } .rail-nav { margin-top: 45px; } .rail-link { justify-content: center; padding: 13px 8px; } .layout { grid-template-columns: 1fr; } .side { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
        @media (max-width: 620px) { .shell { display: block; } .rail { position: sticky; top: 0; z-index: 10; display: block; padding: 10px 15px; box-shadow: 0 3px 14px rgba(18,43,58,.2); } .brand { min-height: 42px; } .brand span { display: inline; } .menu-toggle { display: block; position: absolute; top: 10px; right: 15px; } .rail-nav { display: none; margin: 10px 0 0; padding-top: 8px; border-top: 1px solid rgba(255,255,255,.15); } .rail.open .rail-nav { display: grid; } .rail-link { justify-content: flex-start; min-height: 44px; padding: 10px 8px; } .rail-link span:not(.rail-icon) { display: inline; } .rail-bottom { display: none; } .main { padding: 22px 12px 32px; } .topbar { align-items: flex-start; margin-bottom: 25px; } .topbar h1 { font-size: 34px; } .user-chip { display: none; } .browser-head { align-items: stretch; flex-direction: column; padding: 15px; } .browser-head > div:last-child { display: grid !important; grid-template-columns: 1fr 1fr; } .upload-label { width: 100%; padding: 10px 8px; } .browser-head input[name=name] { width: 100% !important; } .file-list { padding: 5px 12px 12px; } .file-row { grid-template-columns: 22px 34px minmax(0, 1fr) auto; gap: 8px; min-height: 60px; } .file-meta { display: none; } .file-row > div:last-child, .file-row > form { grid-column: 4; grid-row: 1; } .file-row > div:last-child { display: flex; flex-wrap: wrap; gap: 4px; justify-content: flex-end; } .file-row > div:last-child > form { display: block; } .file-row .download { min-height: 40px; padding: 8px; } .bulk-actions { flex-wrap: wrap; padding: 12px 15px; } .bulk-actions button { flex: 1 1 100%; min-height: 44px; } .upload-status { margin-left: 15px; margin-right: 15px; } .side { grid-template-columns: 1fr; } .side-card { padding: 16px; } }
        @media (max-width: 900px) { .shell { display: block; } body.menu-open { overflow: hidden; } .mobile-menu-toggle { display: grid; place-items: center; position: fixed; top: 12px; left: 12px; z-index: 31; width: 48px; height: 48px; margin: 0; padding: 0; color: #fff; background: var(--green); border: 0; border-radius: 8px; box-shadow: 0 5px 16px rgba(18,43,58,.28); cursor: pointer; font-size: 22px; } .menu-backdrop { display: block; position: fixed; inset: 0; z-index: 19; width: 100%; height: 100%; padding: 0; border: 0; background: rgba(5,16,25,.58); opacity: 0; pointer-events: none; transition: opacity .28s ease; } body.menu-open .menu-backdrop { opacity: 1; pointer-events: auto; } .rail { position: fixed; inset: 0 auto 0 0; z-index: 20; display: flex; width: 50vw; max-width: 360px; min-width: 260px; height: 100dvh; padding: 22px 18px; overflow-y: auto; box-shadow: 12px 0 32px rgba(18,43,58,.34); transform: translate3d(-105%, 0, 0); transition: transform .28s cubic-bezier(.22,.61,.36,1); will-change: transform; } .rail.open { transform: translate3d(0, 0, 0); } .rail .brand span, .rail .rail-link span:not(.rail-icon) { display: inline; } .rail-nav { display: none; margin-top: 42px; } .rail.open .rail-nav { display: grid; } .rail-link { justify-content: flex-start; min-height: 48px; padding: 11px 10px; } .rail-bottom { display: block; } .main { width: 100%; margin: 0; padding-top: 78px; } }
        @media (max-width: 620px) { .rail.open .brand span, .rail.open .rail-link span:not(.rail-icon) { display: inline !important; } }
        @media (prefers-reduced-motion: reduce) { *, *::before, *::after { scroll-behavior: auto !important; transition-duration: .01ms !important; animation-duration: .01ms !important; } }
    </style>
    <link rel="stylesheet" href="{{ url_for('static', filename='cloud-dashboard.css') }}">
</head>
<body class="cloud-dashboard">
<div class="shell">
    <button class="menu-toggle mobile-menu-toggle" type="button" aria-label="Open navigation" aria-expanded="false">☰</button>
    <button class="menu-backdrop" type="button" aria-label="Close navigation" tabindex="-1"></button>
    <aside class="rail">
        <a class="brand" href="{{ url_for('files') }}"><span class="brand-mark">C</span><span>Cloud Rdx</span></a>
        <nav class="rail-nav" aria-label="Main navigation">
            <a class="rail-link active" href="{{ url_for('files') }}"><span class="rail-icon">[ ]</span><span>My storage</span></a>
            <a class="rail-link" href="{{ url_for('storage_plan') }}"><span class="rail-icon">$</span><span>Storage plan</span></a>
            <a class="rail-link" href="{{ url_for('profile') }}"><span class="rail-icon">@</span><span>My profile</span></a>
            <a class="rail-link" href="{{ url_for('cloud_storage_guide') }}"><span class="rail-icon">?</span><span>Storage guide</span></a>
            <a class="rail-link" href="{{ url_for('user_trash') }}"><span class="rail-icon">~</span><span>Recycle bin</span></a>
            {% if has_admin_access %}<a class="rail-link" href="{{ url_for('admin_panel') }}"><span class="rail-icon">#</span><span>{{ admin_title }}</span></a>{% endif %}
            <a class="rail-link" href="{{ url_for('logout') }}"><span class="rail-icon">&lt;</span><span>Sign out</span></a>
        </nav>
        <div class="rail-bottom">Private storage<br>Local and secure</div>
    </aside>
    <main class="main">
        <header class="topbar">
            <div><p class="eyebrow">Cloud Rdx / storage node</p><h1>My storage</h1><p class="subtitle">Private object workspace · session protected</p></div>
            <div class="topbar-actions">
                <button class="theme-toggle" id="theme-toggle" type="button" aria-label="Switch to light theme" aria-pressed="false"><span aria-hidden="true">◉</span><span id="theme-toggle-label">Dark mode</span></button>
                <div class="user-chip"><span class="avatar">{{ username[0]|upper }}</span><span>{{ username }}{% if is_admin %} · admin{% endif %} <b class="session-status">◌ signed in</b></span></div>
                <span id="theme-status" class="visually-hidden" role="status" aria-live="polite"></span>
            </div>
        </header>
        <nav class="quick-access" aria-label="Quick access">
            <a class="quick-link" href="{{ url_for('storage_plan') }}"><span class="quick-link-icon" aria-hidden="true">$</span><span><strong>Storage plan</strong><small>Manage your allocation</small></span><span class="quick-link-arrow" aria-hidden="true">→</span></a>
            <a class="quick-link" href="{{ url_for('profile') }}"><span class="quick-link-icon" aria-hidden="true">@</span><span><strong>My profile</strong><small>Account and password</small></span><span class="quick-link-arrow" aria-hidden="true">→</span></a>
            <a class="quick-link" href="{{ url_for('user_trash') }}"><span class="quick-link-icon" aria-hidden="true">🗑</span><span><strong>Recycle bin</strong><small>Review deleted items</small></span><span class="quick-link-arrow" aria-hidden="true">→</span></a>
        </nav>
        {% with messages = get_flashed_messages() %}{% for message in messages %}<div class="flash" role="status" aria-live="polite">{{ message }}</div>{% endfor %}{% endwith %}
        <div class="layout">
            <section class="panel browser">
                <div class="browser-head">
                    <div class="crumbs"><a href="{{ url_for('files') }}">Root</a>{% for crumb in breadcrumbs %}<span class="crumb-sep">/</span><a href="{{ crumb.url }}">{{ crumb.name }}</a>{% endfor %}</div>
                    <div style="display:flex;gap:8px;flex-wrap:wrap">{% if allow_share %}<a class="upload-label" href="{{ url_for('user_shares') }}">Manage links</a>{% endif %}{% if allow_upload %}<form method="post" action="{{ url_for('upload', subpath=subpath) }}" enctype="multipart/form-data"><label class="upload-label" for="top-file">+ Add file</label><input id="top-file" name="file" type="file" hidden></form>{% endif %}<form method="post" action="{{ url_for('create_folder', subpath=subpath) }}"><input name="name" placeholder="New folder" required style="padding:9px;border:1px solid var(--line);border-radius:8px;width:110px"><button class="upload-label" type="submit">+ Folder</button></form></div>
                </div>
                <div class="drive-tools">
                    <label class="drive-search"><span aria-hidden="true">⌕</span><input id="file-search" type="search" placeholder="Search in this folder" autocomplete="off"><span class="search-hint" aria-hidden="true">Search</span></label>
                    <div class="view-controls" role="group" aria-label="File layout">
                        <button class="view-button active" type="button" data-view="grid" aria-pressed="true" aria-label="Show files as cards">▦<span>Grid</span></button>
                        <button class="view-button" type="button" data-view="list" aria-pressed="false" aria-label="Show files as a list">☷<span>List</span></button>
                    </div>
                </div>
                <p class="visually-hidden" id="file-search-status" role="status" aria-live="polite" aria-atomic="true"></p>
                {% if allow_download %}<form id="bulk-download-form" method="post" action="{{ url_for('bulk_download') }}"></form><div class="bulk-actions"><label><input id="select-all-files" type="checkbox"> Select all</label><span id="selected-file-count">0 selected</span><button id="bulk-download-button" type="submit" form="bulk-download-form" disabled>Download selected</button></div>{% else %}<div class="flash" role="status" aria-live="polite">Downloads are disabled for this account. Contact an administrator to request access.</div>{% endif %}
                {% if allow_upload %}<div id="upload-status" class="upload-status" role="status" aria-live="polite"><div class="upload-status-head"><strong id="upload-status-title">Preparing upload…</strong><button id="cancel-upload" class="cancel-upload" type="button">Cancel</button></div><progress id="upload-progress" max="100" value="0"></progress><small id="upload-status-detail">Waiting to start.</small></div>{% endif %}
                <div class="file-list" id="file-list" data-view="grid">
                    {% if parent %}<div class="file-row" data-name="Parent folder" data-file-type="folder"><div></div><div class="file-icon">↑</div><div class="file-name"><a href="{{ url_for('files', subpath=parent) }}">Parent folder</a></div><div class="file-meta">Folder</div><div></div></div>{% endif %}
                    {% for item in items %}
                    <div class="file-row" data-name="{{ item.name|lower }}" data-file-type="{{ 'folder' if item.is_dir else 'file' }}"><div>{% if allow_download and not item.is_dir %}<input class="file-select" type="checkbox" name="paths" value="{{ item.path }}" form="bulk-download-form" aria-label="Select {{ item.name }}">{% endif %}</div><div class="file-icon{% if not item.is_dir %} doc{% endif %}" aria-hidden="true">{% if item.is_dir %}▰{% else %}..{% endif %}</div><div class="file-name">{% if item.is_dir %}<a href="{{ url_for('files', subpath=item.path) }}">{{ item.name }}</a>{% else %}{{ item.name }}{% endif %}</div><div class="file-meta">{% if item.is_dir %}Folder{% else %}{{ item.size|filesize }}{% endif %}</div>{% if item.is_dir %}<form method="post" action="{{ url_for('delete_item', subpath=item.path) }}" onsubmit="return confirm('Delete this folder and its contents?')"><button class="download" type="submit">Delete</button></form>{% else %}<div style="display:flex;gap:10px;justify-content:flex-end;align-items:center">{% if allow_download %}<a class="download" href="{{ url_for('download', subpath=item.path) }}">Download</a>{% endif %}{% if allow_share %}<form method="post" action="{{ url_for('share_create', subpath=item.path) }}" style="display:flex;gap:4px;align-items:center"><select name="expires_days" aria-label="Share link expiry" style="max-width:70px;padding:5px;border:1px solid var(--line);border-radius:5px"><option value="1">1 day</option><option value="7" selected>7 days</option><option value="30">30 days</option></select><button class="download" type="submit">Share</button></form>{% endif %}<form method="post" action="{{ url_for('delete_item', subpath=item.path) }}" onsubmit="return confirm('Delete this file?')"><button class="download" type="submit">Delete</button></form></div>{% endif %}</div>
                    {% else %}<div class="empty"><strong>This folder is empty</strong>Add a file to start building your storage.</div>{% endfor %}
                    <p class="empty search-empty" id="search-empty" hidden><strong>No matching files</strong>Try a different search term.</p>
                </div>
            </section>
            <aside class="side">
                <section class="panel side-card"><h2>Storage overview</h2><div class="storage-stat"><span>OBJECTS / {{ item_count }}</span><span>{{ total_size|filesize }}{% if quota %} / {{ quota|filesize }}{% else %} / UNLIMITED{% endif %}</span></div><div class="meter" {% if quota %}role="progressbar" aria-valuenow="{{ quota_percent }}" aria-valuemin="0" aria-valuemax="100" aria-label="Storage quota used"{% else %}aria-hidden="true"{% endif %}><span style="width:{{ quota_percent }}%"></span></div><div class="storage-detail"><div><small>Used</small><strong>{{ total_size|filesize }}</strong></div><div><small>Remaining</small><strong>{% if quota %}{{ remaining_size|filesize }}{% else %}Unlimited{% endif %}</strong></div></div><p style="margin:0;color:var(--muted);font:11px Consolas,monospace">STATUS: {% if quota and quota_percent >= 100 %}QUOTA REACHED{% elif quota and quota_percent >= 80 %}NEAR LIMIT{% elif quota %}AVAILABLE{% else %}UNMETERED{% endif %}</p>{% if quota and quota_percent >= 95 %}<p class="storage-warning critical">Storage is almost full. Delete files or upgrade your allocation.</p>{% elif quota and quota_percent >= 80 %}<p class="storage-warning">You have used most of your allocated storage.</p>{% endif %}</section>
                {% if allow_upload %}<section class="panel side-card"><h2>Quick upload</h2><form class="dropzone" method="post" action="{{ url_for('upload', subpath=subpath) }}" enctype="multipart/form-data"><div class="dropzone-icon">+</div><p>Choose a file to add it to this folder.</p><input name="file" type="file" required></form></section>{% endif %}
            </aside>
        </div>
    </main>
    <nav class="mobile-dock" aria-label="Mobile quick navigation">
        <a href="{{ url_for('files') }}" aria-current="page"><span aria-hidden="true">⌂</span><span>Drive</span></a>
        <a href="{{ url_for('storage_plan') }}"><span aria-hidden="true">⚑</span><span>Storage</span></a>
        <a href="{{ url_for('user_trash') }}"><span aria-hidden="true">🗑</span><span>Trash</span></a>
        <a href="{{ url_for('profile') }}"><span aria-hidden="true">◉</span><span>Profile</span></a>
    </nav>
</div>
<script>
(() => {
    const fileSearch = document.getElementById('file-search');
    const fileList = document.getElementById('file-list');
    const searchStatus = document.getElementById('file-search-status');
    const noSearchResults = document.getElementById('search-empty');
    const fileRows = Array.from(document.querySelectorAll('.file-row[data-name]'));
    if (fileSearch && fileList && searchStatus && noSearchResults) {
        const updateSearch = () => {
            const query = fileSearch.value.trim().toLocaleLowerCase();
            let visibleCount = 0;
            fileRows.forEach(row => {
                const visible = row.dataset.name.includes(query);
                row.hidden = !visible;
                if (visible) visibleCount += 1;
            });
            noSearchResults.hidden = !query || visibleCount > 0 || fileRows.length === 0;
            searchStatus.textContent = query
                ? `${visibleCount} of ${fileRows.length} items match ${fileSearch.value.trim()}.`
                : `${fileRows.length} items in this folder.`;
        };
        fileSearch.addEventListener('input', updateSearch);
        fileSearch.addEventListener('keydown', event => {
            if (event.key === 'Escape' && fileSearch.value) {
                fileSearch.value = '';
                updateSearch();
            }
        });
        updateSearch();
    }

    const fileView = document.getElementById('file-list');
    document.querySelectorAll('.view-button[data-view]').forEach(button => {
        button.addEventListener('click', () => {
            if (!fileView) return;
            const view = button.dataset.view;
            fileView.dataset.view = view;
            document.querySelectorAll('.view-button[data-view]').forEach(option => {
                const active = option === button;
                option.classList.toggle('active', active);
                option.setAttribute('aria-pressed', String(active));
            });
            const status = document.getElementById('file-search-status');
            if (status) status.textContent = `${view === 'grid' ? 'Card' : 'List'} layout selected.`;
        });
    });

    const rail = document.querySelector('.rail');
    const menuToggle = document.querySelector('.menu-toggle');
    const menuBackdrop = document.querySelector('.menu-backdrop');
    const setMenuState = open => {
        rail.classList.toggle('open', open);
        document.body.classList.toggle('menu-open', open);
        menuToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        menuToggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
    };
    menuToggle.addEventListener('click', () => {
        setMenuState(!rail.classList.contains('open'));
    });
    menuBackdrop.addEventListener('click', () => setMenuState(false));
    rail.querySelectorAll('.rail-link').forEach(link => link.addEventListener('click', () => {
        setMenuState(false);
    }));
    let activeRequest = null;
    const status = document.getElementById('upload-status');
    const title = document.getElementById('upload-status-title');
    const detail = document.getElementById('upload-status-detail');
    const progress = document.getElementById('upload-progress');
    const cancel = document.getElementById('cancel-upload');
    const selections = () => Array.from(document.querySelectorAll('.file-select'));
    const updateSelection = () => {
        const checked = selections().filter(input => input.checked).length;
        const count = document.getElementById('selected-file-count');
        const bulkButton = document.getElementById('bulk-download-button');
        if (count) count.textContent = `${checked} selected`;
        if (bulkButton) bulkButton.disabled = checked === 0;
        const all = selections();
        const selectAll = document.getElementById('select-all-files');
        if (selectAll) selectAll.checked = all.length > 0 && checked === all.length;
    };
    selections().forEach(input => input.addEventListener('change', updateSelection));
    const selectAll = document.getElementById('select-all-files');
    if (selectAll) selectAll.addEventListener('change', event => {
        selections().forEach(input => input.checked = event.target.checked);
        updateSelection();
    });
    const bulkForm = document.getElementById('bulk-download-form');
    if (bulkForm) bulkForm.addEventListener('submit', event => {
        if (!selections().some(input => input.checked)) event.preventDefault();
    });
    function formatSeconds(seconds) {
        if (!Number.isFinite(seconds) || seconds < 0) return 'calculating…';
        seconds = Math.ceil(seconds);
        return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    }
    function startUpload(form) {
        const input = form.querySelector('input[type=file]');
        if (!input.files.length) return;
        if (activeRequest) activeRequest.abort();
        const file = input.files[0], started = performance.now();
        let uploadFinishedAt = null;
        const xhr = new XMLHttpRequest();
        activeRequest = xhr;
        status.classList.add('visible'); progress.value = 0; cancel.disabled = false;
        title.textContent = `Uploading ${file.name}`;
        xhr.upload.onprogress = event => {
            if (!event.lengthComputable) { detail.textContent = 'Uploading…'; return; }
            const elapsed = (performance.now() - started) / 1000;
            const speed = event.loaded / Math.max(elapsed, 0.001);
            const remaining = (event.total - event.loaded) / Math.max(speed, 1);
            progress.value = event.loaded * 100 / event.total;
            if (event.loaded === event.total && !uploadFinishedAt) uploadFinishedAt = performance.now();
            detail.textContent = `${Math.round(progress.value)}% · ${formatSeconds(elapsed)} elapsed · about ${formatSeconds(remaining)} remaining`;
        };
        xhr.onreadystatechange = () => {
            if (xhr.readyState !== XMLHttpRequest.DONE) return;
            if (xhr.status >= 200 && xhr.status < 400) {
                const processedAt = performance.now();
                const uploadSeconds = ((uploadFinishedAt || processedAt) - started) / 1000;
                const processingSeconds = (processedAt - (uploadFinishedAt || started)) / 1000;
                title.textContent = 'Upload complete';
                detail.textContent = `Upload: ${formatSeconds(uploadSeconds)} · Processing: ${formatSeconds(processingSeconds)}`;
                cancel.disabled = true;
                window.setTimeout(() => window.location.reload(), 900);
            } else if (xhr.status !== 0) {
                title.textContent = 'Upload failed';
                detail.textContent = xhr.status === 503
                    ? 'The upload service is temporarily unavailable. Please try again shortly.'
                    : xhr.status === 403
                        ? 'Your account or a security policy does not currently allow uploads.'
                        : `The server rejected this upload (HTTP ${xhr.status}). Please try again.`;
                cancel.disabled = true;
            }
            activeRequest = null;
        };
        xhr.open('POST', form.action); xhr.send(new FormData(form));
    }
    document.querySelectorAll('form[action^="/upload/"]').forEach(form => {
        form.addEventListener('submit', event => { event.preventDefault(); startUpload(form); });
        form.querySelector('input[type=file]').addEventListener('change', () => startUpload(form));
    });
    if (cancel) cancel.addEventListener('click', () => {
        if (!activeRequest) return;
        activeRequest.abort(); activeRequest = null;
        title.textContent = 'Upload cancelled'; detail.textContent = 'The upload request was cancelled before completion.'; cancel.disabled = true;
    });
    updateSelection();
})();
</script>
</body>
</html>
"""


PAGE = PAGE.replace(
    '<nav class="rail-nav" aria-label="Main navigation">',
    '<nav class="rail-nav" aria-label="Main navigation"><a class="rail-link" href="{{ url_for(\'login\') }}"><span class="rail-icon">→</span><span>Sign in</span></a>',
)
PAGE = PAGE.replace("{% if is_admin %}<a class=\"rail-link\" href=\"{{ url_for('admin_panel') }}\">", "{% if admin_access %}<a class=\"rail-link\" href=\"{{ url_for('admin_panel') }}\">")


HOME_PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>RDx Cloud Storage</title>
    <style>
        :root { --ink:#17212b; --muted:#647483; --green:#087f73; --dark:#122b3a; --gold:#f0b44d; --paper:#f2f6f8; }
        * { box-sizing:border-box; }
        body.home-page { margin:0; min-height:100vh; color:#fff; background:#05060b; font-family:'Segoe UI',Arial,sans-serif; }
        .home-background-video, .home-video-overlay { position:fixed; inset:0; width:100%; height:100%; }
        .home-background-video { z-index:0; object-fit:cover; }
        .home-video-overlay { z-index:1; background:linear-gradient(135deg,rgba(2,7,22,.88),rgba(13,1,27,.72)); }
        .nav, .hero { position:relative; z-index:2; }
        .nav { display:flex; justify-content:space-between; align-items:center; gap:18px; padding:22px clamp(22px,6vw,82px); background:rgba(4,9,25,.58); border-bottom:1px solid rgba(255,255,255,.2); }
        .brand { display:flex; align-items:center; gap:10px; color:#fff; font:700 14px Consolas,monospace; text-shadow:0 2px 8px rgba(0,0,0,.7); }
        .mark { display:grid; place-items:center; width:38px; height:38px; color:var(--dark); background:var(--gold); border-radius:7px; font:800 16px Consolas,monospace; }
        .nav a { min-height:44px; display:inline-flex; align-items:center; color:#fff; font:700 13px Arial,sans-serif; text-decoration:none; }
        .hero { width:min(1050px,calc(100% - 36px)); margin:0 auto; padding:clamp(70px,12vw,145px) 0 90px; }
        .eyebrow { margin:0 0 14px; color:#8cecff; text-transform:uppercase; letter-spacing:.16em; font:700 11px Consolas,monospace; text-shadow:0 2px 8px rgba(0,0,0,.8); }
        h1 { max-width:760px; margin:0; color:#fff; font-size:clamp(42px,8vw,82px); line-height:.98; letter-spacing:-.06em; text-shadow:0 4px 18px rgba(0,0,0,.8); }
        .lead { max-width:610px; margin:25px 0 30px; color:#f1f7ff; font:18px/1.6 Arial,sans-serif; text-shadow:0 2px 10px rgba(0,0,0,.85); }
        .actions { display:flex; gap:12px; flex-wrap:wrap; }
        .button { display:inline-flex; padding:13px 18px; color:#fff !important; background:var(--green); border-radius:7px; font-weight:700 !important; }
        .button.secondary { color:#102033 !important; background:#f5fbff; border:1px solid #fff; }
        .features { display:grid; grid-template-columns:repeat(3,1fr); gap:16px; margin-top:70px; }
        .card { padding:22px; background:rgba(4,9,25,.62); border:1px solid rgba(255,255,255,.25); border-radius:16px; backdrop-filter:blur(8px); }
        .card h2 { margin:0 0 8px; color:#fff; font-size:18px; text-shadow:0 2px 8px rgba(0,0,0,.65); }
        .card p { margin:0; color:#e6f1fb; font:14px/1.55 Arial,sans-serif; text-shadow:0 2px 8px rgba(0,0,0,.7); }
        @media(max-width:700px) { .nav { padding:13px 18px; } .brand span:last-child { max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; } .hero { width:min(100% - 32px, 560px); padding-top:70px; padding-bottom:55px; } h1 { font-size:clamp(40px, 13vw, 62px); } .lead { font-size:16px; } .actions { display:grid; grid-template-columns:1fr; } .button { justify-content:center; min-height:48px; } .features { grid-template-columns:1fr; gap:12px; margin-top:48px; } .card { padding:18px; } }
        @media (prefers-reduced-motion: reduce), (max-width:700px) { .home-background-video { display:none; } }
    </style>
</head>
<body class="home-page">
    <video class="home-background-video" autoplay muted loop playsinline aria-hidden="true">
        <source src="{{ url_for('background_video') }}" type="video/mp4">
    </video>
    <div class="home-video-overlay" aria-hidden="true"></div>
    <nav class="nav" aria-label="Primary navigation"><div class="brand"><span class="mark">C</span><span>RDx Cloud Storage-DB16</span></div><a href="{{ url_for('login') }}">Sign in →</a></nav>
    <main class="hero"><p class="eyebrow">Private storage workspace</p><h1>Your files, organized and secure.</h1><p class="lead">Cloud Rdx gives you a simple private space to upload, organize, download, and manage your files from one place.</p><div class="actions"><a class="button" href="{{ url_for('login') }}">Sign in to storage</a><a class="button secondary" href="{{ url_for('register') }}">Create an account</a></div><section class="features"><article class="card"><h2>Private by default</h2><p>Your storage is protected by account access and secure password hashing.</p></article><article class="card"><h2>Simple organization</h2><p>Create folders, upload files, download items, and keep your workspace tidy.</p></article><article class="card"><h2>Recovery support</h2><p>Account recovery and administration tools help keep important data accessible.</p></article></section></main>
</body>
</html>
"""


CONSENT_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Policies and consent - RDx Cloud Storage</title><style>
body{margin:0;min-height:100vh;background:#f2f6f8;color:#17212b;font-family:'Segoe UI',Arial,sans-serif}.wrap{width:min(760px,calc(100% - 28px));margin:32px auto}.card{padding:28px;background:#fff;border:1px solid #d8e1e8;border-radius:12px;box-shadow:0 12px 30px #19314214}h1{margin:0 0 10px;font-size:clamp(28px,6vw,44px)}.lead{color:#647483;line-height:1.55}.notice{padding:12px 14px;margin:18px 0;color:#8b3d2d;background:#fff0ec;border:1px solid #efb7aa;border-radius:7px;font-size:13px}.policies{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:22px 0}.policy{padding:14px;color:#087f73;background:#f4fbfa;border:1px solid #b9e1dc;border-radius:8px;text-decoration:none;font-weight:700}.check{display:flex;align-items:flex-start;gap:10px;margin:20px 0;font-size:14px;line-height:1.5}.check input{width:20px;height:20px;flex:0 0 auto;accent-color:#087f73}.submit{width:100%;min-height:48px;color:#fff;background:#087f73;border:0;border-radius:8px;cursor:pointer;font-weight:700}@media(max-width:560px){.wrap{margin:16px auto}.card{padding:20px}.policies{grid-template-columns:1fr}}
</style></head><body><main class="wrap"><section class="card"><p style="color:#087f73;font-weight:700;letter-spacing:.12em;font-size:11px">RDx CLOUD STORAGE</p><h1>Before you continue</h1><p class="lead">To use RDx Cloud Storage, please read and accept all four policies. We ask once for this account; your choice is saved securely and will not be requested on every visit.</p>{% if error %}<div class="notice">{{ error }}</div>{% endif %}<div class="policies"><a class="policy" href="{{ url_for('policy_page', policy_name='terms') }}">Terms and conditions →</a><a class="policy" href="{{ url_for('policy_page', policy_name='privacy') }}">Privacy policy →</a><a class="policy" href="{{ url_for('policy_page', policy_name='cookies') }}">Cookie policy →</a><a class="policy" href="{{ url_for('policy_page', policy_name='disclaimer') }}">Disclaimer →</a></div><form method="post" action="{{ url_for('accept_policies') }}"><label class="check"><input type="checkbox" name="accept_all" required><span>I have read and agree to the Terms and Conditions, Privacy Policy, Cookie Policy, and Disclaimer.</span></label><button class="submit" type="submit">Accept all and continue</button></form></section></main></body></html>
"""


POLICY_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{ policy.title }} - RDx Cloud Storage</title><style>body{margin:0;background:#f2f6f8;color:#17212b;font-family:'Segoe UI',Arial,sans-serif}.wrap{width:min(800px,calc(100% - 28px));margin:30px auto}.card{padding:26px;background:#fff;border:1px solid #d8e1e8;border-radius:10px}h1{margin-top:0}p,li{line-height:1.65}.back{display:inline-block;margin-top:18px;color:#087f73;font-weight:700}</style></head><body><main class="wrap"><article class="card"><p style="color:#087f73;font-weight:700;letter-spacing:.1em;font-size:11px">RDx CLOUD STORAGE</p><h1>{{ policy.title }}</h1><p>{{ policy.summary }}</p><h2>Using this website</h2><p>By using RDx Cloud Storage, you agree to use the service lawfully, protect your account credentials, and respect other users and stored content.</p><h2>Your responsibilities</h2><ul><li>Keep your account information accurate and your password confidential.</li><li>Do not upload unlawful, harmful, or unauthorized content.</li><li>Review changes to these policies before continuing to use the service.</li></ul><a class="back" href="{{ back_url }}">→ Back to consent</a></article></main></body></html>
"""


LOGIN_PAGE = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign in - RDx Cloud Storage-DB16</title><style>
:root{--green:#105437;--mint:#d9f3e5;--ink:#16221f;--muted:#71817b}*{box-sizing:border-box}body{min-height:100vh;margin:0;display:grid;place-items:center;background:#f7faf7;color:var(--ink);font-family:Georgia,'Times New Roman',serif}.login{width:min(420px,calc(100% - 34px));padding:42px;background:#fff;border:1px solid #dfe8e2;border-radius:18px;box-shadow:0 18px 50px rgba(25,64,45,.08)}.mark{width:42px;height:42px;display:grid;place-items:center;margin-bottom:35px;color:var(--green);background:#f2be58;border-radius:12px 12px 12px 2px;font:bold 20px Arial}.eyebrow{margin:0 0 11px;color:#18794e;text-transform:uppercase;letter-spacing:.16em;font:700 11px Arial}h1{margin:0 0 10px;font-size:37px;font-weight:500;letter-spacing:-.03em}.intro{margin:0 0 30px;color:var(--muted);font:14px/1.5 Arial}.field{display:block;margin-bottom:9px;font:700 12px Arial}.password{width:100%;padding:13px 14px;border:1px solid #cbd9cf;border-radius:8px;outline:0;font:15px Arial}.password:focus{border-color:#18794e;box-shadow:0 0 0 3px var(--mint)}button{width:100%;margin-top:14px;padding:13px;border:0;border-radius:8px;color:#fff;background:var(--green);cursor:pointer;font:bold 13px Arial}button:hover{background:#18794e}.google-signin{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;min-height:46px;margin-top:18px;padding:12px;color:#263238;background:#fff;border:1px solid #cbd2d5;border-radius:8px;text-decoration:none;font:700 13px Arial;transition:background-color .16s,border-color .16s,box-shadow .16s}.google-signin:hover{background:#f8fafb;border-color:#9aa5aa;box-shadow:0 3px 10px #26323814}.google-mark{font:800 17px Arial;background:conic-gradient(from -45deg,#4285f4 0 25%,#34a853 25% 50%,#fbbc05 50% 75%,#ea4335 75%);background-clip:text;-webkit-text-fill-color:transparent}.login-divider{display:flex;align-items:center;gap:12px;margin:18px 0;color:#89938f;font:11px Arial;text-transform:uppercase}.login-divider:before,.login-divider:after{content:"";height:1px;flex:1;background:#e4eae6}.error{margin:16px 0 0;color:#9b4c2d;font:13px Arial}
</style></head><body><main class="login"><div class="mark">C</div><p class="eyebrow">Cloud Rdx Storage</p><h1>Welcome back</h1><p class="intro">Sign in to access your private local file space.</p>{% if google_login_enabled %}<a class="google-signin" href="{{ url_for('google_login_start') }}"><span class="google-mark" aria-hidden="true">G</span><span>Continue with Google</span></a><p style="font:11px/1.5 Arial;color:var(--muted);text-align:center;margin:8px 0 17px">New here? A standard Cloud Rdx account will be created.</p><div class="login-divider">or sign in with password</div>{% endif %}<form method="post"><label class="field" for="username">Username</label><input class="password" id="username" name="username" required autofocus><label class="field" for="password" style="margin-top:14px">Password</label><input class="password" id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Enter storage</button></form><p style="font:13px Arial;color:var(--muted);margin-top:20px"><a href="{{ url_for('forgot_password') }}" style="color:#18794e">Forgot password?</a></p><p style="font:13px Arial;color:var(--muted);margin-top:10px">New here? <a href="{{ url_for('register') }}" style="color:#18794e">Create an account</a></p>{% if error %}<p class="error" role="alert">{{ error }}</p>{% endif %}</main></body></html>
"""

LOGIN_PAGE = LOGIN_PAGE.replace(
    '<main class="login"><div class="mark">',
    '<main class="login"><nav style="display:flex;justify-content:flex-end;margin:-15px 0 28px;font:700 12px Arial" aria-label="Primary navigation"><a href="{{ url_for(\'login\') }}" style="color:#18794e;text-decoration:none">Home</a></nav><div class="mark">',
)
LOGIN_PAGE = LOGIN_PAGE.replace("url_for('login')", "url_for('home')", 1)


MAINTENANCE_PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Maintenance in progress - RDx Cloud Storage</title>
    <style>
        :root{--green:#105437;--gold:#f2be58;--ink:#16221f;--muted:#71817b}
        *{box-sizing:border-box}
        body{min-height:100vh;margin:0;display:grid;place-items:center;background:#f7faf7;color:var(--ink);font-family:Arial,sans-serif}
        .maintenance{width:min(560px,calc(100% - 34px));padding:42px;background:#fff;border:1px solid #dfe8e2;border-radius:18px;box-shadow:0 18px 50px rgba(25,64,45,.08);text-align:center}
        .mark{width:48px;height:48px;display:grid;place-items:center;margin:0 auto 28px;color:var(--green);background:var(--gold);border-radius:14px 14px 14px 3px;font:bold 21px Arial}
        .eyebrow{margin:0 0 12px;color:#18794e;text-transform:uppercase;letter-spacing:.16em;font-size:11px;font-weight:700}
        h1{margin:0 0 14px;font:500 36px Georgia,'Times New Roman',serif;letter-spacing:-.03em}
        .lead{margin:0 auto 12px;max-width:430px;color:var(--muted);font-size:15px;line-height:1.6}
        .notice{margin:24px 0;padding:14px;color:#76551a;background:#fff5d9;border:1px solid #f0d18a;border-radius:9px;font-size:13px}
        .mark-link{display:inline-block;text-decoration:none}
        .mark-link:focus-visible{outline:3px solid #18794e;outline-offset:5px;border-radius:16px}
    </style>
</head>
<body>
    <main class="maintenance">
        <a class="mark-link" href="{{ url_for('login', maintenance=1) }}" aria-label="Administrator sign in"><div class="mark">C</div></a>
        <p class="eyebrow">Cloud Rdx Storage</p>
        <h1>Website under maintenance</h1>
        <p class="lead">We are temporarily making improvements. Storage access and new sign-ins are paused while maintenance mode is active.</p>
        <div class="notice">Please visit again after 6 hours, or wait for the administrator to bring the website back online.</div>
    </main>
</body>
</html>
"""


REGISTER_PAGE = LOGIN_PAGE.replace(
    "Welcome back</h1><p class=\"intro\">Sign in to access your private local file space.</p><form method=\"post\"><label class=\"field\" for=\"username\">Username</label><input class=\"password\" id=\"username\" name=\"username\" required autofocus><label class=\"field\" for=\"password\" style=\"margin-top:14px\">Password</label><input class=\"password\" id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required><button type=\"submit\">Enter storage</button></form><p style=\"font:13px Arial;color:var(--muted);margin-top:20px\">New here? <a href=\"{{ url_for('register') }}\" style=\"color:#18794e\">Create an account</a></p>",
    "Create your space</h1><p class=\"intro\">Register for a private file space of your own.</p><form method=\"post\"><label class=\"field\" for=\"username\">Username</label><input class=\"password\" id=\"username\" name=\"username\" pattern=\"[A-Za-z0-9_-]{3,32}\" required autofocus><label class=\"field\" for=\"password\" style=\"margin-top:14px\">Password</label><input class=\"password\" id=\"password\" name=\"password\" type=\"password\" minlength=\"8\" required><button type=\"submit\">Create account</button></form><p style=\"font:13px Arial;color:var(--muted);margin-top:20px\">Already registered? <a href=\"{{ url_for('login') }}\" style=\"color:#18794e\">Sign in</a></p>",
)


REGISTER_PAGE = REGISTER_PAGE.replace(
    '<label class="field" for="password" style="margin-top:14px">Password</label><input class="password" id="password" name="password" type="password" minlength="8" required>',
    '<label class="field" for="full_name" style="margin-top:14px">Full name</label><input class="password" id="full_name" name="full_name" required><label class="field" for="email" style="margin-top:14px">Email address</label><input class="password" id="email" name="email" type="email" required><label class="field" for="mobile" style="margin-top:14px">Mobile number</label><input class="password" id="mobile" name="mobile" type="tel" required><label class="field" for="dob" style="margin-top:14px">Date of birth</label><input class="password" id="dob" name="dob" type="date" required><label class="field" for="password" style="margin-top:14px">Password</label><input class="password" id="password" name="password" type="password" minlength="8" required>',
)


REGISTER_PAGE = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Create account - Cloud Rdx</title><style>
:root{--ink:#17212b;--muted:#647483;--line:#d8e1e8;--paper:#f2f6f8;--panel:#fff;--green:#087f73;--dark:#122b3a;--gold:#f0b44d;--danger:#a34f3a}*{box-sizing:border-box}body{margin:0;min-height:100vh;color:var(--ink);background:var(--paper);font-family:'Segoe UI',Arial,sans-serif;background-image:linear-gradient(#d8e1e844 1px,transparent 1px),linear-gradient(90deg,#d8e1e844 1px,transparent 1px);background-size:32px 32px}.register-shell{width:min(880px,calc(100% - 32px));margin:34px auto 50px}.register-head{display:flex;justify-content:space-between;align-items:start;gap:24px;margin-bottom:24px}.brand{display:flex;align-items:center;gap:10px;color:var(--dark);font:700 13px Consolas,monospace}.mark{display:grid;place-items:center;width:38px;height:38px;color:var(--dark);background:var(--gold);border-radius:6px;font:800 16px Consolas,monospace}.eyebrow{margin:0 0 9px;color:var(--green);text-transform:uppercase;letter-spacing:.15em;font:700 11px Consolas,monospace}h1{margin:0;font-size:clamp(30px,5vw,46px);letter-spacing:-.04em}.intro{max-width:560px;margin:10px 0 0;color:var(--muted);font:14px/1.5 Arial}.signin{color:var(--green);font:700 12px Consolas,monospace;text-decoration:none;white-space:nowrap}.card{overflow:hidden;background:rgba(255,255,255,.96);border:1px solid var(--line);border-radius:8px;box-shadow:0 12px 30px #19314214}.section{padding:24px 28px;border-bottom:1px solid #e8eef2}.section-title{display:flex;align-items:baseline;gap:10px;margin-bottom:17px}.section-title h2{margin:0;font-size:18px;font-weight:650}.section-title span{color:var(--muted);font:11px Consolas,monospace}.grid{display:grid;grid-template-columns:1fr 1fr;gap:17px 20px}.field{display:block;color:var(--ink);font:700 11px Consolas,monospace}.input{display:block;width:100%;margin-top:7px;padding:12px 13px;color:var(--ink);background:#fbfdfe;border:1px solid #cbd8e0;border-radius:6px;outline:0;font:14px 'Segoe UI',Arial}.input:focus{border-color:var(--green);box-shadow:0 0 0 3px #dff5f1}.hint{margin:7px 0 0;color:var(--muted);font:11px/1.4 Arial}.privacy{margin:0;padding:16px 28px;color:#45616c;background:#edf8f7;font:12px/1.5 Arial}.privacy strong{color:var(--green)}.actions{display:flex;align-items:center;justify-content:space-between;gap:18px;padding:20px 28px;background:#f8fbfc}.submit{padding:12px 18px;color:#fff;background:var(--green);border:0;border-radius:6px;cursor:pointer;font:700 12px Consolas,monospace}.submit:hover{background:var(--dark)}.error{margin:0 0 18px;padding:12px 15px;color:var(--danger);background:#fff1ed;border:1px solid #e8c9c0;border-radius:6px;font:13px Arial}@media(max-width:620px){.register-shell{margin-top:22px}.register-head{display:block}.signin{display:inline-block;margin-top:17px}.section{padding:20px 17px}.grid{grid-template-columns:1fr}.privacy,.actions{padding-left:17px;padding-right:17px}.actions{align-items:stretch;flex-direction:column}.submit{width:100%}}
</style></head><body><main class="register-shell"><header class="register-head"><div><div class="brand"><span class="mark">C</span><span>Cloud Rdx / identity setup</span></div><p class="eyebrow" style="margin-top:29px">Private storage account</p><h1>Create your workspace</h1><p class="intro">Set up your secure file space. Your recovery details are stored privately and used only to verify account ownership.</p></div><a class="signin" href="{{ url_for('login') }}">ALREADY REGISTERED →</a></header>{% if error %}<p class="error">{{ error }}</p>{% endif %}<form class="card" method="post"><section class="section"><div class="section-title"><h2>Profile</h2><span>01 / IDENTITY</span></div><div class="grid"><label class="field">FULL NAME<input class="input" name="full_name" autocomplete="name" placeholder="Your name" required></label><label class="field">USERNAME<input class="input" name="username" pattern="[A-Za-z0-9_-]{3,32}" autocomplete="username" placeholder="3-32 characters" required></label><label class="field">EMAIL ADDRESS<input class="input" name="email" type="email" autocomplete="email" placeholder="you@example.com" required></label><label class="field">MOBILE NUMBER<input class="input" name="mobile" type="tel" autocomplete="tel" placeholder="+91 98765 43210" required></label></div></section><section class="section"><div class="section-title"><h2>Recovery details</h2><span>02 / PRIVATE VERIFICATION</span></div><div class="grid"><label class="field">DATE OF BIRTH<input class="input" name="dob" type="date" autocomplete="bday" required></label><div><p class="hint" style="margin-top:0">Your mobile number and date of birth help an administrator verify a recovery request. They are not shown to other users.</p></div></div></section><section class="section"><div class="section-title"><h2>Secure sign-in</h2><span>03 / CREDENTIALS</span></div><div class="grid"><label class="field">PASSWORD<input class="input" name="password" type="password" minlength="8" autocomplete="new-password" placeholder="At least 8 characters" required><span class="hint">Use a unique password with 8 or more characters.</span></label><label class="field">CONFIRM PASSWORD<input class="input" name="password_confirm" type="password" minlength="8" autocomplete="new-password" placeholder="Repeat your password" required></label></div></section><p class="privacy"><strong>Private by design.</strong> Your profile data is visible only from your own profile or to the administrator. Files remain inside your separate personal storage folder.</p><div class="actions"><span class="hint">Your details are stored for account access and recovery.</span><button class="submit" type="submit">CREATE SECURE ACCOUNT</button></div></form></main></body></html>
"""
REGISTER_PAGE = REGISTER_PAGE.replace('[A-Za-z0-9_-]', '[A-Za-z0-9_\\-]')


FORGOT_PAGE = LOGIN_PAGE.replace(
    '<h1>Welcome back</h1><p class="intro">Sign in to access your private local file space.</p><form method="post"><label class="field" for="username">Username</label><input class="password" id="username" name="username" required autofocus><label class="field" for="password" style="margin-top:14px">Password</label><input class="password" id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Enter storage</button></form><p style="font:13px Arial;color:var(--muted);margin-top:20px"><a href="{{ url_for(\'forgot_password\') }}" style="color:#18794e">Forgot password?</a></p><p style="font:13px Arial;color:var(--muted);margin-top:10px">New here? <a href="{{ url_for(\'register\') }}" style="color:#18794e">Create an account</a></p>',
    '<h1>Password recovery</h1><p class="intro">Submit your details. An administrator will verify your identity before resetting your password.</p><form method="post"><label class="field" for="username">Username</label><input class="password" id="username" name="username" required autofocus><label class="field" for="email" style="margin-top:14px">Email address</label><input class="password" id="email" name="email" type="email" required><label class="field" for="mobile" style="margin-top:14px">Mobile number</label><input class="password" id="mobile" name="mobile" type="tel" required><label class="field" for="dob" style="margin-top:14px">Date of birth</label><input class="password" id="dob" name="dob" type="date" required><button type="submit">Send recovery request</button></form><p style="font:13px Arial;color:var(--muted);margin-top:20px"><a href="{{ url_for(\'login\') }}" style="color:#18794e">Return to sign in</a></p>',
)
FORGOT_PAGE = FORGOT_PAGE.replace(
    "{% if error %}<p class=\"error\">{{ error }}</p>{% endif %}",
    "{% if error %}<p class=\"error\">{{ error }}</p>{% endif %}{% if message %}<p style=\"margin:16px 0 0;padding:12px 15px;color:#087f73;background:#edf8f7;border:1px solid #b9e1dc;border-radius:8px;font:13px Arial\">{{ message }}</p>{% endif %}",
)


# Use the attached animated login design only for sign-in. Registration and
# recovery keep their dedicated forms and existing validation behavior.
LOGIN_PAGE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in - RDx Cloud Storage-DB16</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='login.css') }}">
    <link rel="stylesheet" href="{{ url_for('static', filename='auth.css') }}">
</head>
<body class="login-page">
    <video class="login-background-video" autoplay muted loop playsinline aria-hidden="true">
        <source src="{{ url_for('background_video') }}" type="video/mp4">
    </video>
    <section aria-label="Cloud Rdx sign in">
        <main class="login-box">
            <div class="login-brand">RDx Cloud Storage-DB16</div>
            <h1>Welcome back</h1>
            {% with messages = get_flashed_messages() %}
                {% for message in messages %}<p class="login-notice">{{ message }}</p>{% endfor %}
            {% endwith %}
            {% if google_login_enabled or not google_oauth_configured or github_login_enabled or not github_oauth_configured %}
                <div class="provider-actions" aria-label="Social sign-in options">
            {% if google_login_enabled or not google_oauth_configured %}
                <a class="google-signin" href="{{ url_for('google_login_start') }}"
                   aria-label="Continue with Google or create an account" title="Google">
                    <svg class="provider-logo google-mark" viewBox="0 0 48 48" aria-hidden="true">
                        <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/>
                        <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.89c-.58 2.96-2.26 5.48-4.73 7.18l7.27 5.64c4.25-3.92 6.7-9.7 6.7-17.29z"/>
                        <path fill="#FBBC05" d="M10.53 28.59A14.4 14.4 0 0 1 9.75 24c0-1.59.27-3.13.76-4.59l-7.98-6.19A23.9 23.9 0 0 0 0 24c0 3.87.93 7.54 2.56 10.78l7.97-6.19z"/>
                        <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.91-5.8l-7.27-5.64c-2.02 1.35-4.6 2.14-8.64 2.14-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/>
                    </svg>
                </a>
            {% endif %}
            {% if github_login_enabled or not github_oauth_configured %}
                <a class="github-signin" href="{{ url_for('github_login_start') }}"
                   aria-label="Continue with GitHub or create an account" title="GitHub">
                    <svg class="provider-logo github-mark" viewBox="0 0 24 24" aria-hidden="true">
                        <path fill="currentColor" d="M12 .9a11.1 11.1 0 0 0-3.51 21.63c.56.1.76-.24.76-.54v-2.08c-3.1.67-3.76-1.32-3.76-1.32-.5-1.29-1.24-1.63-1.24-1.63-1.01-.69.08-.68.08-.68 1.12.08 1.71 1.15 1.71 1.15 1 1.71 2.62 1.22 3.26.93.1-.72.39-1.22.71-1.5-2.47-.28-5.07-1.23-5.07-5.48 0-1.21.43-2.2 1.15-2.97-.12-.28-.5-1.41.11-2.94 0 0 .94-.3 3.05 1.14a10.6 10.6 0 0 1 5.55 0c2.11-1.44 3.05-1.14 3.05-1.14.61 1.53.23 2.66.11 2.94.72.77 1.15 1.76 1.15 2.97 0 4.26-2.61 5.2-5.09 5.48.4.35.76 1.02.76 2.06v3.07c0 .3.2.65.77.54A11.1 11.1 0 0 0 12 .9z"/>
                    </svg>
                </a>
            {% endif %}
                </div>
            {% endif %}
            {% if google_login_enabled or github_login_enabled %}
                <p class="google-signup-note">Sign in or create an account with either provider.</p>
                <div class="login-divider" aria-hidden="true"><span>or use your password</span></div>
            {% else %}
                {% if google_oauth_configured or github_oauth_configured %}
                    <p class="google-signup-note google-setup-note" role="status">Social sign-in is disabled by the site administrator.</p>
                {% else %}
                    <p class="google-signup-note google-setup-note" role="status">Social sign-in is not configured on this server yet. Use password sign-in or ask the site administrator to configure OAuth.</p>
                {% endif %}
            {% endif %}
            <form method="post" action="{{ url_for('login') }}">
                <div class="input-box">
                    <span class="icon" aria-hidden="true">⚑</span>
                    <input id="username" name="username" type="text" autocomplete="username" placeholder=" " required autofocus>
                    <label for="username">Username</label>
                </div>
                <div class="input-box">
                    <button class="password-toggle" type="button" aria-label="Show password" aria-controls="password">
                        <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                            <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                            <circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="1.8"/>
                        </svg>
                    </button>
                    <input id="password" name="password" type="password" autocomplete="current-password" placeholder=" " required>
                    <label for="password">Password</label>
                </div>
                <div class="remember-forget">
                    <label><input type="checkbox" name="remember" disabled> Remember me</label>
                    <a href="{{ url_for('forgot_password') }}">Forgot password?</a>
                </div>
                <button type="submit">Sign in</button>
            </form>
            {% if error %}<p class="login-message" role="alert">{{ error }}</p>{% endif %}
            <div class="register-link">
                <p>Don't have an account? <a href="{{ url_for('register') }}">Create one</a></p>
                <p><a href="{{ url_for('home') }}">→ Back to home</a></p>
            </div>
        </main>
    </section>
    <script>
        const password = document.getElementById('password');
        const toggle = document.querySelector('.password-toggle');
        const eyeSvg = `
            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                <circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="1.8"/>
            </svg>`;
        const eyeOffSvg = `
            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                <path d="M3 3l18 18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                <path d="M10.6 10.6A2 2 0 0 1 13.4 13.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                <path d="M9.1 5.5A10.6 10.6 0 0 1 12 5c6.5 0 10 7 10 7a17.7 17.7 0 0 1-4.2 5.2M6.6 6.6A17.7 17.7 0 0 0 2 12s3.5 7 10 7a10.8 10.8 0 0 0 5.2-1.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>`;
        const setToggleState = () => {
            const visible = password.type === 'text';
            toggle.innerHTML = visible ? eyeOffSvg : eyeSvg;
            toggle.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
            toggle.setAttribute('title', visible ? 'Hide password' : 'Show password');
        };
        toggle.addEventListener('click', () => {
            password.type = password.type === 'text' ? 'password' : 'text';
            setToggleState();
        });
        setToggleState();
    </script>
</body>
</html>
"""


PROFILE_PAGE = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>My profile - Cloud Rdx</title><style>
:root{--ink:#17212b;--muted:#647483;--line:#d8e1e8;--paper:#f2f6f8;--panel:#fff;--green:#087f73;--dark:#122b3a;--gold:#f0b44d}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--paper);color:var(--ink);font-family:'Segoe UI',Arial,sans-serif;background-image:linear-gradient(#d8e1e844 1px,transparent 1px),linear-gradient(90deg,#d8e1e844 1px,transparent 1px);background-size:32px 32px}.wrap{width:min(760px,calc(100% - 32px));margin:44px auto}.top{display:flex;justify-content:space-between;align-items:start;margin-bottom:25px}.eyebrow{margin:0 0 9px;color:var(--green);text-transform:uppercase;letter-spacing:.15em;font:700 11px Consolas,monospace}h1{margin:0;font-size:40px;letter-spacing:-.03em}.sub{margin:9px 0 0;color:var(--muted);font:13px Consolas,monospace}.back{color:var(--green);font:700 12px Consolas,monospace;text-decoration:none}.panel{overflow:hidden;background:rgba(255,255,255,.96);border:1px solid var(--line);border-radius:8px;box-shadow:0 12px 30px #19314214}.head{padding:22px;border-bottom:1px solid var(--line)}.head h2{margin:0 0 5px;font-size:19px;font-weight:600}.head p{margin:0;color:var(--muted);font:12px Arial}.data{display:grid;grid-template-columns:1fr 1fr}.field{padding:19px 22px;border-bottom:1px solid #e8eef2}.field:nth-child(odd){border-right:1px solid #e8eef2}.label{display:block;margin-bottom:7px;color:var(--muted);font:700 10px Consolas,monospace;text-transform:uppercase;letter-spacing:.08em}.value{font:14px Consolas,monospace;overflow-wrap:anywhere}@media(max-width:580px){.wrap{margin:25px auto}.top{display:block}.back{display:inline-block;margin-top:17px}.data{display:block}.field:nth-child(odd){border-right:0}}
</style></head><body><main class="wrap"><header class="top"><div><p class="eyebrow">Private account record</p><h1>{{ profile.full_name }}</h1><p class="sub">/{{ profile.username }} · visible only to you and the administrator</p></div><a class="back" href="{{ back_url }}">→ BACK</a></header><section class="panel"><div class="head"><h2>Identity and recovery data</h2><p>This information is protected and used for account recovery verification.</p></div><div class="data"><div class="field"><span class="label">Username</span><span class="value">{{ profile.username }}</span></div><div class="field"><span class="label">Email address</span><span class="value">{{ profile.email }}</span></div><div class="field"><span class="label">Mobile number</span><span class="value">{{ profile.mobile }}</span></div><div class="field"><span class="label">Date of birth</span><span class="value">{{ profile.date_of_birth }}</span></div><div class="field"><span class="label">Account created</span><span class="value">{{ profile.created_at[:10] }}</span></div></div></section><section class="panel" style="margin-top:20px"><div class="head"><h2>Change password</h2><p>Update your password without administrator assistance.</p></div><form method="post" action="{{ url_for('change_password') }}" style="padding:22px"><label class="label" for="current_password">CURRENT PASSWORD</label><input id="current_password" name="current_password" type="password" required style="display:block;width:100%;margin:7px 0 14px;padding:12px;border:1px solid #cbd8e0;border-radius:6px"><label class="label" for="new_password">NEW PASSWORD</label><input id="new_password" name="new_password" type="password" minlength="8" required style="display:block;width:100%;margin:7px 0 14px;padding:12px;border:1px solid #cbd8e0;border-radius:6px"><label class="label" for="confirm_password">CONFIRM NEW PASSWORD</label><input id="confirm_password" name="confirm_password" type="password" minlength="8" required style="display:block;width:100%;margin:7px 0 14px;padding:12px;border:1px solid #cbd8e0;border-radius:6px"><button type="submit" style="padding:11px 15px;color:#fff;background:#087f73;border:0;border-radius:6px;cursor:pointer;font:700 12px Consolas,monospace">UPDATE PASSWORD</button></form></section></main></body></html>
"""
PROFILE_PAGE = PROFILE_PAGE.replace(
    '<header class="top">',
    '{% with messages = get_flashed_messages() %}{% for message in messages %}<p style="padding:12px 15px;color:#087f73;background:#edf8f7;border:1px solid #b9e1dc;border-radius:8px;font:13px Arial">{{ message }}</p>{% endfor %}{% endwith %}<header class="top">',
)
PROFILE_PAGE = PROFILE_PAGE.replace(
    "</style>",
    ".profile-form{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:22px}.profile-form label{display:block;color:var(--muted);font:700 10px Consolas,monospace;text-transform:uppercase;letter-spacing:.08em}.profile-form input{display:block;width:100%;margin-top:7px;padding:11px;border:1px solid var(--line);border-radius:6px;font:14px Arial}.profile-form .wide{grid-column:1/-1}.profile-note{padding:0 22px 18px;color:var(--muted);font:12px/1.5 Arial}.profile-picture{width:72px;height:72px;border-radius:50%;object-fit:cover}.profile-links{display:flex;gap:12px;flex-wrap:wrap;padding:16px 22px;font:13px Arial}.profile-links span{padding:8px 11px;background:#edf8f7;border-radius:999px}@media(max-width:580px){.profile-form{grid-template-columns:1fr}.profile-form .wide{grid-column:auto}}\\n</style>",
    1,
)
PROFILE_PAGE = PROFILE_PAGE.replace(
    '<section class="panel" style="margin-top:20px"><div class="head"><h2>Change password</h2>',
    """{% if can_edit_profile %}<section class="panel" style="margin-top:20px"><div class="head"><h2>Recovery and profile details</h2><p>Only provide details you are comfortable sharing. Phone and date of birth are used by the existing account-recovery verification flow.</p></div><form class="profile-form" method="post" action="{{ url_for('profile') }}"><label class="wide" for="profile-full-name">Full name<input id="profile-full-name" name="full_name" maxlength="160" value="{{ profile.full_name or '' }}" required autocomplete="name"></label><label for="profile-mobile">Phone number<input id="profile-mobile" name="mobile" type="tel" maxlength="32" value="{{ profile.mobile or '' }}" autocomplete="tel"></label><label for="profile-dob">Date of birth<input id="profile-dob" name="date_of_birth" type="date" value="{{ profile.date_of_birth or '' }}" autocomplete="bday"></label><label for="profile-gender">Gender (optional)<input id="profile-gender" name="gender" maxlength="80" value="{{ profile.gender or '' }}" autocomplete="off"></label><label for="profile-location">Location (optional)<input id="profile-location" name="location" maxlength="160" value="{{ profile.location or '' }}" autocomplete="address-level2"></label><button class="wide" type="submit" style="padding:11px 15px;color:#fff;background:#087f73;border:0;border-radius:6px;cursor:pointer;font:700 12px Consolas,monospace">SAVE PROFILE</button></form><p class="profile-note">Your OAuth provider password is never shared with Cloud Rdx. We do not ask for or store security-question answers. Keep recovery details current and use a unique Cloud Rdx password if you set one.</p></section>{% endif %}<section class="panel" style="margin-top:20px"><div class="head"><h2>Change password</h2>""",
    1,
)
PROFILE_PAGE = PROFILE_PAGE.replace(
    '<div class="field"><span class="label">Account created</span><span class="value">{{ profile.created_at[:10] }}</span></div>',
    '''<div class="field"><span class="label">Account created</span><span class="value">{{ profile.created_at[:10] }}</span></div><div class="field"><span class="label">Gender</span><span class="value">{{ profile.gender or 'Not provided' }}</span></div><div class="field"><span class="label">Location</span><span class="value">{{ profile.location or 'Not provided' }}</span></div><div class="field"><span class="label">Last login</span><span class="value">{{ profile.last_login_at|prettydate if profile.last_login_at else 'Not recorded' }}</span></div><div class="field"><span class="label">Last account activity</span><span class="value">{{ profile.last_seen|prettydate if profile.last_seen else 'Not recorded' }}</span></div><div class="field"><span class="label">Two-factor authentication</span><span class="value">{{ 'Enabled' if profile.totp_enabled else 'Not enabled' }}</span></div>''',
    1,
)
PROFILE_PAGE = PROFILE_PAGE.replace(
    '<h1>{{ profile.full_name }}</h1>',
    '{% if profile.profile_picture %}<img class="profile-picture" src="{{ profile.profile_picture }}" alt="Profile picture" referrerpolicy="no-referrer">{% endif %}<h1>{{ profile.full_name or profile.username }}</h1>',
    1,
)
PROFILE_PAGE = PROFILE_PAGE.replace(
    "<p>This information is protected and used for account recovery verification.</p>",
    "<p>Your profile is visible to you and authorized administrators. Phone number and date of birth are used for recovery verification.</p>",
    1,
)
PROFILE_PAGE = PROFILE_PAGE.replace(
    '</div></section>{% if can_edit_profile %}',
    '''</div>{% if profile.google_sub or profile.github_sub %}<div class="profile-links">{% if profile.google_sub %}<span>Google linked · {{ profile.google_username or profile.google_profile_name or 'Account' }} · {{ profile.google_email }}</span>{% endif %}{% if profile.github_sub %}<span>GitHub linked · {{ profile.github_username or profile.github_profile_name or 'Account' }} · {{ profile.github_email }}</span>{% endif %}</div>{% endif %}</section>{% if can_edit_profile %}''',
    1,
)
PROFILE_PAGE = PROFILE_PAGE.replace(
    '<section class="panel" style="margin-top:20px"><div class="head"><h2>Change password</h2>',
    '{% if can_edit_profile %}<section class="panel" style="margin-top:20px"><div class="head"><h2>Change password</h2>',
    1,
)
PROFILE_PAGE = PROFILE_PAGE.replace(
    "</form></section></main></body></html>",
    "</form></section>{% endif %}</main></body></html>",
    1,
)


USER_ALLOCATION_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Storage allocation - Cloud Rdx</title>
<style>body{margin:0;background:#f8f9fc;color:#3a3b45;font-family:Arial,sans-serif}.wrap{width:min(1040px,calc(100% - 32px));margin:32px auto}.top{display:flex;justify-content:space-between;gap:20px;align-items:start;margin-bottom:22px}.top a{color:#4e73df;font-weight:700;text-decoration:none}.panel{margin-bottom:20px;padding:22px;background:#fff;border:1px solid #e3e6f0;border-radius:8px;box-shadow:0 .15rem 1.2rem #3a3b4512}.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.stat{padding:16px;background:#f8f9fc;border-left:4px solid #4e73df}.stat small{display:block;color:#858796;font-size:11px;text-transform:uppercase}.stat strong{display:block;margin-top:8px;font-size:20px}.meter{height:12px;margin-top:20px;overflow:hidden;background:#eaecf4;border-radius:8px}.meter span{display:block;height:100%;background:#4e73df;border-radius:inherit}.plans{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.plan{padding:18px;border:1px solid #e3e6f0;border-radius:8px}.plan h3{margin:0 0 8px}.price{margin:12px 0;font-size:22px;font-weight:700}.button{padding:10px 13px;color:#fff;background:#4e73df;border:0;border-radius:5px;cursor:pointer;font-weight:700}.button:disabled{background:#b8bfce;cursor:not-allowed}.qr{max-width:220px;margin:10px 0;border:1px solid #e3e6f0}.notice{padding:12px 15px;margin-bottom:18px;color:#856404;background:#fff3cd;border:1px solid #ffeeba;border-radius:5px}.muted{color:#858796;font-size:13px}@media(max-width:800px){.summary,.plans{grid-template-columns:1fr 1fr}}@media(max-width:520px){.summary,.plans{grid-template-columns:1fr}.top{display:block}}</style></head><body><main class="wrap"><header class="top"><div><p class="muted">CLOUD RDX / STORAGE</p><h1>Storage allocation</h1><p class="muted">Monitor your personal quota and request an upgrade.</p></div><a href="{{ url_for('files') }}">→ BACK TO STORAGE</a></header>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="notice">{{ message }}</div>{% endfor %}{% endwith %}<section class="panel"><h2>My storage</h2><div class="summary"><div class="stat"><small>Used</small><strong>{{ used|filesize }}</strong></div><div class="stat"><small>Remaining</small><strong>{{ remaining|filesize }}</strong></div><div class="stat"><small>Allocation</small><strong>{{ quota|filesize }}</strong></div><div class="stat"><small>Status</small><strong>{{ subscription.status|upper if subscription else 'FREE' }}</strong></div></div><div class="meter" role="progressbar" aria-valuenow="{{ percent }}" aria-valuemin="0" aria-valuemax="100" aria-label="Storage allocation used"><span style="width:{{ percent }}%"></span></div><p class="muted">{{ percent }}% used · Current plan: {{ subscription.plan_name if subscription else 'Free Plan' }}</p></section><section class="panel"><h2>Upgrade storage</h2><p class="muted">Choose a plan. Payment requests are linked to your signed-in account and cannot change another user’s quota.</p><div class="plans">{% for plan in plans %}<article class="plan"><h3>{{ plan.name }}</h3><p>{{ plan.quota_bytes|filesize }} total storage</p><div class="price">₹{{ '%.2f'|format(plan.price_paise / 100) }}{% if plan.price_paise %}<small>/month</small>{% endif %}</div><form method="post" action="{{ url_for('manual_payment_request') }}"><input type="hidden" name="plan_id" value="{{ plan.id }}"><label class="visually-hidden" for="payment-reference-{{ plan.id }}">UPI transaction reference for {{ plan.name }}</label><input id="payment-reference-{{ plan.id }}" name="transaction_reference" required placeholder="UPI reference" style="width:100%;padding:9px;border:1px solid #d1d3e2;border-radius:5px"><button class="button" type="submit"{% if not plan.price_paise %} disabled{% endif %}>Submit payment reference</button></form></article>{% endfor %}</div><p class="muted">Scan the payment QR, then submit the transaction reference. Storage is activated after administrator verification.</p>{% if qr_url %}<img class="qr" src="{{ qr_url }}" alt="Payment QR code">{% else %}<p class="notice">Payment QR is not configured. Set PAYMENT_QR_URL before accepting manual payments.</p>{% endif %}</section></main></body></html>
"""


USER_PAGE_NAV = """
<nav class="account-nav" aria-label="Account navigation">
    <div class="account-nav-links">
        <a href="{{ url_for('files') }}" {% if request.endpoint == 'files' %}aria-current="page"{% endif %}><span aria-hidden="true">▦</span> My Drive</a>
        <a href="{{ url_for('storage_plan') }}" {% if request.endpoint == 'storage_plan' %}aria-current="page"{% endif %}><span aria-hidden="true">⚑</span> Storage plan</a>
        <a href="{{ url_for('profile') }}" {% if request.endpoint in ('profile', 'admin_user_profile') %}aria-current="page"{% endif %}><span aria-hidden="true">◉</span> My Profile</a>
        <a href="{{ url_for('user_trash') }}" {% if request.endpoint == 'user_trash' %}aria-current="page"{% endif %}><span aria-hidden="true">🗑</span> Recycle bin</a>
    </div>
    <div class="account-theme">
        <button class="account-theme-toggle" id="theme-toggle" type="button" aria-pressed="false" aria-label="Switch to light theme">
            <span aria-hidden="true">◉</span><span id="theme-toggle-label">Dark theme</span>
        </button>
        <span class="visually-hidden" id="theme-status" role="status" aria-live="polite"></span>
    </div>
</nav>
"""


def apply_user_page_theme(template):
    """Apply the shared account-page navigation, theme assets, and page class."""
    template = template.replace(
        "</head>",
        '<link rel="stylesheet" href="{{ url_for(\'static\', filename=\'cloud-account.css\') }}">'
        '<script src="{{ url_for(\'static\', filename=\'cloud-account.js\') }}" defer></script></head>',
        1,
    )
    template = template.replace('<html lang="en"', '<html lang="en" data-theme="dark"', 1)
    template = template.replace("<body>", '<body class="cloud-account-page">', 1)
    template = template.replace("</header>", "</header>" + USER_PAGE_NAV, 1)
    return template


PROFILE_PAGE = apply_user_page_theme(PROFILE_PAGE)
USER_ALLOCATION_PAGE = apply_user_page_theme(USER_ALLOCATION_PAGE)


ADMIN_PAYMENT_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Payment verification - Cloud Rdx</title></head><body class="admin-theme"><main class="main" style="width:auto"><header class="topbar"><div><p class="eyebrow">CLOUD RDX / BILLING</p><h1>Payment verification</h1><p class="subtitle">Review QR payment references and allocate storage to the verified account.</p></div><a href="{{ url_for('admin_panel') }}">→ ADMIN DASHBOARD</a></header>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}{% endwith %}<section class="panel"><div class="panel-head"><h2>Pending payment requests</h2><p>Approve only after checking the payment in your provider dashboard.</p></div><div class="table-responsive"><table><thead><tr><th>User</th><th>Plan</th><th>Amount</th><th>Reference</th><th>Submitted</th><th>Action</th></tr></thead><tbody>{% for item in requests %}<tr><td>{{ item.username }}<br><span class="muted">{{ item.email or 'No email' }}</span></td><td>{{ item.plan_name }}<br><span class="muted">{{ item.quota_bytes|filesize }}</span></td><td>₹{{ '%.2f'|format(item.amount_paise / 100) }}</td><td>{{ item.transaction_reference }}</td><td>{{ item.created_at|prettydate }}</td><td><form method="post" action="{{ url_for('admin_review_payment', payment_id=item.id) }}"><button class="button" name="decision" value="approve" type="submit">Approve</button> <button class="button danger" name="decision" value="reject" type="submit">Reject</button></form></td></tr>{% else %}<tr><td colspan="6">No pending payment requests.</td></tr>{% endfor %}</tbody></table></div></section></main></body></html>
"""


ADMIN_PROFIT_PAGE = """
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Profit and usage - Cloud Rdx</title>
<style>
:root{--ink:#16221f;--muted:#71817b;--line:#dfe8e2;--paper:#f7faf7;--panel:#fff;--green:#18794e;--dark:#105437;--gold:#f2be58;--red:#a34f3a;--blue:#356aa8}
*{box-sizing:border-box}body{margin:0;color:var(--ink);background:var(--paper);font-family:Arial,sans-serif}.wrap{width:min(1240px,calc(100% - 34px));margin:32px auto 50px}
.top{display:flex;justify-content:space-between;align-items:start;gap:22px;margin-bottom:25px}.eyebrow{margin:0 0 9px;color:var(--green);text-transform:uppercase;letter-spacing:.15em;font-size:11px;font-weight:700}h1{margin:0 0 8px;font:500 clamp(30px,4vw,46px) Georgia,serif;letter-spacing:-.03em}.subtitle,.muted{color:var(--muted);font-size:13px}.top a{color:var(--green);font-weight:700;text-decoration:none;white-space:nowrap}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;box-shadow:0 12px 30px #19314212}.card{padding:19px}.card small{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}.card strong{display:block;margin-top:9px;font:700 25px Consolas,monospace}.card .hint{display:block;margin-top:7px;color:var(--muted);font-size:11px}.positive{color:var(--green)}.negative{color:var(--red)}.blue{color:var(--blue)}
.panel{overflow:hidden;margin-bottom:20px}.head{padding:20px 22px;border-bottom:1px solid var(--line)}.head h2{margin:0 0 6px;font:500 20px Georgia,serif}.head p{margin:0;color:var(--muted);font-size:13px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--line)}.metric{padding:17px 20px;background:#fff}.metric span{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em}.metric b{display:block;margin-top:7px;font-size:18px}.table-wrap{overflow-x:auto}table{width:100%;min-width:680px;border-collapse:collapse;font-size:13px}th{padding:12px 18px;color:var(--muted);background:#f8fbf8;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.06em}td{padding:13px 18px;border-top:1px solid #edf2ee}.note{padding:14px 20px;color:#52675d;background:#f0f8f2;border-top:1px solid var(--line);font-size:12px;line-height:1.5}
@media(max-width:850px){.cards{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:560px){.wrap{width:min(100% - 24px,1240px);margin-top:22px}.top{display:block}.top a{display:inline-block;margin-top:16px}.cards,.grid{grid-template-columns:1fr}.card strong{font-size:22px}}
</style></head>
<body><main class="wrap"><header class="top"><div><p class="eyebrow">Cloud Rdx / owner analytics</p><h1>Profit and usage</h1><p class="subtitle">Private business, account, payment, and storage health overview for {{ owner_username }}.</p></div><a href="{{ url_for('admin_panel') }}">→ ADMIN DASHBOARD</a></header>
<section class="cards">
<article class="card"><small>Collected revenue</small><strong class="positive">₹{{ '%.2f'|format(metrics.revenue) }}</strong><span class="hint">Approved payments</span></article>
<article class="card"><small>Estimated operating cost</small><strong>₹{{ '%.2f'|format(metrics.estimated_cost) }}</strong><span class="hint">{{ '%.2f'|format(metrics.cost_per_gb) }} per used GB/month</span></article>
<article class="card"><small>Estimated net profit</small><strong class="{{ 'positive' if metrics.net_profit >= 0 else 'negative' }}">₹{{ '%.2f'|format(metrics.net_profit) }}</strong><span class="hint">Revenue minus estimated cost</span></article>
<article class="card"><small>Payment pipeline</small><strong class="blue">₹{{ '%.2f'|format(metrics.pending_revenue) }}</strong><span class="hint">{{ metrics.pending_payments }} pending requests</span></article>
</section>
<section class="panel"><div class="head"><h2>Users and activity</h2><p>Activity is based on the configured {{ inactive_days }}-day inactivity window and excludes the owner account.</p></div><div class="grid"><div class="metric"><span>Total users</span><b>{{ metrics.total_users }}</b></div><div class="metric"><span>Active users</span><b class="positive">{{ metrics.active_users }}</b></div><div class="metric"><span>Inactive users</span><b class="negative">{{ metrics.inactive_users }}</b></div><div class="metric"><span>Suspended users</span><b>{{ metrics.suspended_users }}</b></div><div class="metric"><span>New users (30 days)</span><b class="blue">{{ metrics.new_users }}</b></div><div class="metric"><span>Active sessions</span><b>{{ metrics.active_sessions }}</b></div></div></section>
<section class="panel"><div class="head"><h2>Data usage and capacity</h2><p>Usage is calculated from each account's private storage folder.</p></div><div class="grid"><div class="metric"><span>Data in use</span><b>{{ metrics.used_bytes|filesize }}</b></div><div class="metric"><span>Allocated capacity</span><b>{{ metrics.quota_bytes|filesize }}</b></div><div class="metric"><span>Capacity remaining</span><b>{{ metrics.remaining_bytes|filesize }}</b></div><div class="metric"><span>Stored files</span><b>{{ metrics.total_files }}</b></div><div class="metric"><span>Average usage / user</span><b>{{ metrics.average_usage|filesize }}</b></div><div class="metric"><span>Capacity utilization</span><b>{{ metrics.capacity_percent }}%</b></div></div><div class="note">Estimated cost is configurable with <code>STORAGE_COST_PER_GB_INR</code>; the default is ₹0 because no infrastructure cost has been configured.</div></section>
<section class="panel"><div class="head"><h2>Billing summary</h2><p>Payment request totals from the local billing records.</p></div><div class="grid"><div class="metric"><span>Approved requests</span><b class="positive">{{ metrics.approved_payments }}</b></div><div class="metric"><span>Pending requests</span><b>{{ metrics.pending_payments }}</b></div><div class="metric"><span>Rejected requests</span><b>{{ metrics.rejected_payments }}</b></div><div class="metric"><span>Rejected amount</span><b class="negative">₹{{ '%.2f'|format(metrics.rejected_revenue) }}</b></div><div class="metric"><span>Active subscriptions</span><b>{{ metrics.active_subscriptions }}</b></div><div class="metric"><span>Monthly recurring plan value</span><b>₹{{ '%.2f'|format(metrics.monthly_plan_value) }}</b></div></div></section>
<section class="panel"><div class="head"><h2>Plan distribution</h2><p>Current active subscriptions by storage plan.</p></div><div class="table-wrap"><table><thead><tr><th>Plan</th><th>Subscribers</th><th>Monthly price</th><th>Allocated capacity</th></tr></thead><tbody>{% for plan in plan_summary %}<tr><td>{{ plan.name }}</td><td>{{ plan.subscribers }}</td><td>₹{{ '%.2f'|format(plan.price_paise / 100) }}</td><td>{{ plan.capacity|filesize }}</td></tr>{% else %}<tr><td colspan="4">No active paid plans yet.</td></tr>{% endfor %}</tbody></table></div></section>
</main></body></html>
"""

ADMIN_INTELLIGENCE_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cloud Intelligence Center - Cloud Rdx</title>
<link rel="stylesheet" href="{{ url_for('static', filename='admin-theme.css') }}">
<style>
.intel{--bg:#08111f;--panel:#101d30;--line:#253954;--text:#e7effb;--muted:#9db0ca;max-width:1520px;margin:auto;color:var(--text)}
.intel .topbar{margin-bottom:20px;padding:20px;background:linear-gradient(115deg,#102039,#142b48);border:1px solid var(--line);border-radius:16px}
.intel .eyebrow{color:#5eead4}.intel h1{color:#f8fbff}.intel .subtitle,.intel .muted{color:var(--muted)}
.intel .panel,.intel .card{margin-bottom:16px;background:var(--panel);border:1px solid var(--line);border-radius:14px;box-shadow:0 16px 40px #02061755}
.intel .panel-head{border-color:var(--line)}.intel .panel-head h2{color:#f8fbff}.intel .panel-head p{color:var(--muted)}
.intel-actions{display:flex;align-items:center;justify-content:flex-end;flex-wrap:wrap;gap:8px}
.intel-actions a,.intel-actions button{min-height:40px;padding:9px 12px;color:#e6f3ff;background:#172943;border:1px solid #35516e;border-radius:9px;text-decoration:none;cursor:pointer}
.intel-actions button:hover,.intel-actions a:hover{background:#203958}
.intel-status{display:inline-flex;align-items:center;gap:7px;padding:7px 10px;border:1px solid #1d765f;border-radius:99px;background:#0f332e;font-size:11px;font-weight:700}
.intel-status:before{content:"";width:8px;height:8px;background:#34d399;border-radius:50%}
.intel-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:16px}
.intel-stat{position:relative;overflow:hidden;padding:17px;background:linear-gradient(145deg,#12233a,#0e1a2b);border:1px solid var(--line);border-radius:12px}
.intel-stat:after{content:"";position:absolute;right:-27px;top:-34px;width:84px;height:84px;border:1px solid #35d6c033;border-radius:50%;box-shadow:0 0 22px #35d6c018}
.intel-stat small{display:block;color:var(--muted);font-size:10px;letter-spacing:.09em;text-transform:uppercase}
.intel-stat strong{display:block;margin:9px 0 4px;color:#f8fbff;font:700 clamp(19px,2vw,27px) Consolas,monospace}
.intel-stat .tag{color:#70dfc8;font:10px Arial,sans-serif;text-transform:uppercase;letter-spacing:.07em}
.intel-layout{display:grid;grid-template-columns:1.2fr 1fr;gap:16px;align-items:stretch}
.intel-viz{min-height:320px;padding:14px 18px}
.intel-canvas{display:block;width:100%;height:230px}.intel-viz-label{display:flex;justify-content:space-between;gap:12px;color:var(--muted);font-size:11px}
.intel-category-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;padding:14px 18px}
.intel-category{padding:12px;background:#0b1728;border:1px solid #243851;border-radius:9px}
.intel-category b,.intel-category small{display:block}.intel-category small{margin-top:5px;color:var(--muted)}
.intel-empty{padding:18px;color:#b9c9dc;background:#0c1829;border:1px dashed #38506a;border-radius:10px}
.intel-table{overflow:auto}.intel table{width:100%;min-width:560px;border-collapse:collapse;font-size:12px}.intel th,.intel td{padding:11px 13px;color:var(--text);border-bottom:1px solid #253954;text-align:left}.intel th{color:var(--muted);background:#14243b;text-transform:uppercase;font-size:10px}
.intel-filter{display:flex;flex-wrap:wrap;gap:8px;padding:14px 18px}.intel-filter button{min-height:36px;padding:7px 10px;color:#cbd8eb;background:#102038;border:1px solid #304968;border-radius:8px;cursor:pointer}.intel-filter button[aria-pressed=true]{color:#08111f;background:#5eead4;border-color:#5eead4}
.intel-sphere-wrap{position:relative;display:grid;place-items:center;height:230px;overflow:hidden;background:radial-gradient(ellipse at center,#153a5070,transparent 66%)}
.intel-sphere{position:absolute;width:min(190px,55%);aspect-ratio:1;border:1px solid #46e0d188;border-radius:50%;background:radial-gradient(circle at 34% 30%,#68eadf65,#192b60a8 52%,#091423 72%);box-shadow:inset -18px -20px 36px #020617aa,0 0 34px #30d6c133;animation:orbit 18s linear infinite}
.intel-sphere:before,.intel-sphere:after{content:"";position:absolute;inset:14% -20%;border:1px solid #5eead477;border-radius:50%;transform:rotate(-23deg)}
.intel-sphere:after{inset:26% -26%;transform:rotate(55deg);border-color:#818cf866}
.intel-performance .intel-sphere{animation:none}.intel-globe{width:125px;height:125px;border:1px solid #818cf877;border-radius:50%;background:radial-gradient(circle at 35% 30%,#5eead455,#172554 65%,#091423);box-shadow:0 0 25px #818cf822}
@keyframes orbit{to{transform:rotate(360deg)}}
.intel :where(a,button,input,select):focus-visible{outline:3px solid #5eead4;outline-offset:3px}
.intel-fullscreen:fullscreen{overflow:auto;background:var(--bg);padding:14px}.intel-fullscreen:fullscreen .rail{display:none}.intel-fullscreen:fullscreen .main{width:100%;padding:10px 20px}
.intel-toast{position:fixed;right:18px;bottom:18px;z-index:8;padding:12px 16px;color:#08111f;background:#5eead4;border-radius:9px;box-shadow:0 10px 30px #0008}
@media(max-width:940px){.intel-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.intel-layout{grid-template-columns:1fr}}
@media(max-width:600px){.intel{padding:0 4px}.intel .topbar{display:grid;gap:12px;padding:15px}.intel-actions{justify-content:flex-start}.intel-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.intel-stat{padding:13px}.intel-category-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.intel-viz{min-height:285px;padding:12px}.intel-canvas{height:190px}}
@media(prefers-reduced-motion:reduce){.intel *, .intel *:before,.intel *:after{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
</style></head><body class="admin-theme"><div class="shell intel-fullscreen" id="intel-dashboard">
<aside class="rail"><a class="brand" href="{{ url_for('admin_panel') }}"><span class="brand-mark">C</span><span>Cloud Rdx</span></a><nav class="rail-nav" aria-label="Command center">
<a class="rail-link active" href="{{ url_for('admin_intelligence') }}"><span class="rail-icon">◌</span><span>Intelligence</span></a>
<a class="rail-link" href="{{ url_for('admin_profit') }}"><span class="rail-icon">₹</span><span>Profit & usage</span></a>
<a class="rail-link" href="{{ url_for('admin_emergency') }}"><span class="rail-icon">⚙</span><span>Security response</span></a>
<a class="rail-link" href="{{ url_for('admin_audit') }}"><span class="rail-icon">≪</span><span>Audit log</span></a>
<a class="rail-link" href="{{ url_for('admin_storage') }}"><span class="rail-icon">◇</span><span>Storage</span></a>
<a class="rail-link" href="{{ url_for('admin_panel') }}"><span class="rail-icon">⌂</span><span>Admin dashboard</span></a></nav></aside>
<main class="main intel"><header class="topbar"><div><p class="eyebrow">CLOUD INFRASTRUCTURE / INTELLIGENCE</p><h1>Cloud Intelligence Center</h1><p class="subtitle">Aggregated operational data from the application database and private storage.</p></div>
<div class="intel-actions"><span class="intel-status" id="system-status">CHECKING</span><span class="muted" id="last-updated">Not refreshed</span><button type="button" id="refresh-data">Refresh analytics</button><button type="button" id="performance-toggle" aria-pressed="false">Performance mode</button><button type="button" id="fullscreen-toggle">Fullscreen</button></div></header>
<section class="intel-grid" aria-live="polite">
<article class="intel-stat"><small>Registered users</small><strong id="total-users">—</strong><span class="tag">Actual database count</span></article>
<article class="intel-stat"><small>Active sessions</small><strong id="active-sessions">—</strong><span class="tag">Actual session records</span></article>
<article class="intel-stat"><small>Storage in use</small><strong id="storage-used">—</strong><span class="tag">Measured from user files</span></article>
<article class="intel-stat"><small>Allocated capacity</small><strong id="storage-quota">—</strong><span class="tag">Account quota total</span></article>
<article class="intel-stat"><small>Collected revenue</small><strong id="revenue">—</strong><span class="tag">Approved payments · actual</span></article>
<article class="intel-stat"><small>Estimated storage cost</small><strong id="cost">Data unavailable</strong><span class="tag">Only when cost rate configured</span></article>
<article class="intel-stat"><small>Failed logins · 24h</small><strong id="failed-logins">—</strong><span class="tag">Recorded attempts</span></article>
<article class="intel-stat"><small>Open security alerts</small><strong id="open-alerts">—</strong><span class="tag">Actual alert queue</span></article>
</section>
<div class="intel-layout">
<section class="panel"><div class="panel-head"><h2>Storage galaxy</h2><p>Core size and usage ring are driven by measured storage. No estimated capacity is substituted for missing data.</p></div>
<div class="intel-viz"><div class="intel-sphere-wrap"><div class="intel-sphere" aria-hidden="true"></div><canvas class="intel-canvas" id="storage-ring" role="img" aria-label="Storage usage ring. Exact values are shown below."></canvas></div>
<div class="intel-viz-label"><span id="storage-caption">Loading measured storage…</span><span id="storage-percent">—</span></div></div></section>
<section class="panel"><div class="panel-head"><h2>Profit planet</h2><p>Actual approved payment total and explicitly estimated costs. No projection is shown.</p></div>
<div class="intel-viz"><div class="intel-sphere-wrap"><div class="intel-sphere" aria-hidden="true"></div></div>
<div class="intel-viz-label"><span id="profit-caption">Collected revenue: loading</span><span id="profit-detail">Estimated net: —</span></div>
<div class="intel-empty" id="finance-note">Operating expenses and profit margin are unavailable unless the deployment configures its cost model.</div></div></section></div>
<section class="panel"><div class="panel-head"><h2>Usage mountain · audited file activity</h2><p>Counts include activity written to the audit log only. This application does not currently collect bandwidth or geographic telemetry.</p></div>
<div class="intel-filter" role="group" aria-label="Activity range">{% for value,label in ranges %}<button type="button" data-range="{{ value }}" aria-pressed="{{ 'true' if value == '7d' else 'false' }}">{{ label }}</button>{% endfor %}</div>
<div class="intel-viz"><canvas class="intel-canvas" id="activity-chart" role="img" aria-label="Audited file activity chart."></canvas><div class="intel-viz-label"><span id="activity-caption">Loading activity…</span><span>Historical sample from audit_events</span></div></div></section>
<div class="intel-layout">
<section class="panel"><div class="panel-head"><h2>Storage distribution</h2><p>Aggregated from actual files by file type.</p></div><div class="intel-category-grid" id="storage-categories"><div class="intel-empty">Loading file categories…</div></div></section>
<section class="panel"><div class="panel-head"><h2>Platform signals</h2><p>Measurements the current deployment can verify.</p></div><div class="ec-grid">
<article class="ec-stat"><small>Host disk free</small><strong id="disk-free">Data unavailable</strong></article>
<article class="ec-stat"><small>CPU / memory / network</small><strong>Data unavailable</strong></article>
<article class="ec-stat"><small>Bandwidth totals</small><strong>Data unavailable</strong></article>
<article class="ec-stat"><small>Regional activity</small><strong>Data unavailable</strong></article>
</div><p class="muted" style="padding:0 18px 16px">CPU, RAM, bandwidth, geography, scheduled backups, and real-time request rates require telemetry sources not present in this application.</p></section></div>
<section class="panel"><div class="panel-head"><h2>Top storage accounts</h2><p>Owner-only, aggregated storage usage; no profile, email, or location data is exposed here.</p></div><div class="intel-table"><table><thead><tr><th>Account</th><th>Stored files</th><th>Storage used</th></tr></thead><tbody id="top-users"><tr><td colspan="3">Loading…</td></tr></tbody></table></div></section>
</main></div><div id="intel-toast" class="intel-toast" role="status" hidden></div>
<script>
(() => {
 const api="{{ url_for('admin_analytics_overview') }}", activityApi="{{ url_for('admin_analytics_activity') }}";
 const $=id=>document.getElementById(id), fmtBytes=n=>{if(n===null||n===undefined)return'Data unavailable';const units=['B','KB','MB','GB','TB'];let i=0,v=Number(n);while(v>=1024&&i<units.length-1){v/=1024;i++}return`${v.toFixed(i?1:0)} ${units[i]}`};
 const fmtMoney=n=>n===null||n===undefined?'Data unavailable':`₹${Number(n).toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2})}`;
 const toast=(text)=>{const el=$('intel-toast');el.textContent=text;el.hidden=false;setTimeout(()=>el.hidden=true,3200)};
 let overview=null, range='7d';
 function drawRing(){const c=$('storage-ring'),ctx=c.getContext('2d'),dpr=window.devicePixelRatio||1,r=c.getBoundingClientRect();c.width=r.width*dpr;c.height=r.height*dpr;ctx.scale(dpr,dpr);const x=r.width/2,y=r.height/2,rad=Math.min(r.width,r.height)*.39;ctx.lineWidth=12;ctx.strokeStyle='#203752';ctx.beginPath();ctx.arc(x,y,rad,0,Math.PI*2);ctx.stroke();if(!overview)return;const p=overview.storage.utilization_percent;if(p===null)return;ctx.strokeStyle='#5eead4';ctx.lineCap='round';ctx.shadowColor='#5eead4';ctx.shadowBlur=14;ctx.beginPath();ctx.arc(x,y,rad,-Math.PI/2,-Math.PI/2+Math.PI*2*Math.min(100,p)/100);ctx.stroke();ctx.shadowBlur=0}
 function drawActivity(data){const c=$('activity-chart'),ctx=c.getContext('2d'),dpr=window.devicePixelRatio||1,r=c.getBoundingClientRect();c.width=r.width*dpr;c.height=r.height*dpr;ctx.scale(dpr,dpr);ctx.clearRect(0,0,r.width,r.height);const points=data.points||[],pad=22,w=r.width-pad*2,h=r.height-pad*2;ctx.strokeStyle='#263c56';ctx.lineWidth=1;for(let i=0;i<4;i++){const y=pad+h*i/3;ctx.beginPath();ctx.moveTo(pad,y);ctx.lineTo(pad+w,y);ctx.stroke()}if(!points.length)return;const vals=points.map(p=>p.operations),max=Math.max(1,...vals),step=w/Math.max(points.length-1,1);ctx.beginPath();points.forEach((p,i)=>{const x=pad+i*step,y=pad+h-(p.operations/max*h);i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.lineTo(pad+w,pad+h);ctx.lineTo(pad,pad+h);ctx.closePath();const g=ctx.createLinearGradient(0,pad,0,pad+h);g.addColorStop(0,'#5eead466');g.addColorStop(1,'#5eead400');ctx.fillStyle=g;ctx.fill();ctx.beginPath();points.forEach((p,i)=>{const x=pad+i*step,y=pad+h-(p.operations/max*h);i?ctx.lineTo(x,y):ctx.moveTo(x,y)});ctx.strokeStyle='#5eead4';ctx.lineWidth=2;ctx.stroke()}
 function populate(o){overview=o;$('total-users').textContent=o.users.total.toLocaleString();$('active-sessions').textContent=o.sessions.active.toLocaleString();$('storage-used').textContent=fmtBytes(o.storage.used_bytes);$('storage-quota').textContent=fmtBytes(o.storage.quota_bytes);$('storage-caption').textContent=`${fmtBytes(o.storage.used_bytes)} used / ${fmtBytes(o.storage.quota_bytes)} allocated`;$('storage-percent').textContent=o.storage.utilization_percent===null?'—':`${o.storage.utilization_percent}% used`;$('revenue').textContent=fmtMoney(o.finance.collected_revenue);$('cost').textContent=fmtMoney(o.finance.estimated_storage_cost);$('failed-logins').textContent=o.security.failed_logins_24h.toLocaleString();$('open-alerts').textContent=o.security.open_alerts.toLocaleString();$('profit-caption').textContent=`Collected: ${fmtMoney(o.finance.collected_revenue)}`;$('profit-detail').textContent=o.finance.estimated_net===null?'Net: Data unavailable':`Estimated net: ${fmtMoney(o.finance.estimated_net)}`;$('disk-free').textContent=fmtBytes(o.host.disk_free_bytes);$('system-status').textContent=o.status;$('last-updated').textContent=`Updated ${new Date().toLocaleTimeString()}`;
 const cat=$('storage-categories');cat.replaceChildren();if(!o.storage.categories.length){cat.innerHTML='<div class="intel-empty">No files recorded.</div>'}else{o.storage.categories.forEach(item=>{const el=document.createElement('div');el.className='intel-category';el.innerHTML=`<b>${item.category}</b><small>${item.files.toLocaleString()} files · ${fmtBytes(item.bytes)}</small>`;cat.appendChild(el)})}
 const tb=$('top-users');tb.replaceChildren();if(!o.users.top_storage.length){tb.innerHTML='<tr><td colspan="3">No user storage data.</td></tr>'}else{o.users.top_storage.forEach(item=>{const tr=document.createElement('tr');[item.username,item.files.toLocaleString(),fmtBytes(item.bytes)].forEach(value=>{const td=document.createElement('td');td.textContent=value;tr.appendChild(td)});tb.appendChild(tr)})}
 drawRing()}
 async function loadActivity(){const response=await fetch(`${activityApi}?range=${encodeURIComponent(range)}`,{credentials:'same-origin',headers:{Accept:'application/json'}});if(!response.ok)throw new Error('Activity analytics could not be loaded.');const data=await response.json();drawActivity(data);$('activity-caption').textContent=`${data.total_operations.toLocaleString()} audited operations · ${data.range_label}`}
 async function refresh(){try{const response=await fetch(api,{credentials:'same-origin',headers:{Accept:'application/json'}});if(!response.ok)throw new Error('Analytics could not be loaded.');populate(await response.json());await loadActivity()}catch(error){toast(error.message||'Analytics refresh failed.');$('system-status').textContent='UNAVAILABLE'}}
 $('refresh-data').addEventListener('click',refresh);document.querySelectorAll('[data-range]').forEach(button=>button.addEventListener('click',()=>{range=button.dataset.range;document.querySelectorAll('[data-range]').forEach(b=>b.setAttribute('aria-pressed',String(b===button)));loadActivity().catch(e=>toast(e.message))}));
 const dashboard=$('intel-dashboard'),mode=$('performance-toggle');try{if(localStorage.getItem('cloud-rdx-performance-mode')==='true'){dashboard.classList.add('intel-performance');mode.setAttribute('aria-pressed','true')}}catch{}
 mode.addEventListener('click',()=>{const on=!dashboard.classList.contains('intel-performance');dashboard.classList.toggle('intel-performance',on);mode.setAttribute('aria-pressed',String(on));try{localStorage.setItem('cloud-rdx-performance-mode',String(on))}catch{}});
 $('fullscreen-toggle').addEventListener('click',async()=>{try{if(!document.fullscreenElement)await dashboard.requestFullscreen();else await document.exitFullscreen()}catch{toast('Fullscreen is not available in this browser or was denied.')}});
 window.addEventListener('resize',()=>{if(overview)drawRing();loadActivity().catch(()=>{})},{passive:true});
 refresh();
})();
</script></body></html>
"""


ADMIN_STORAGE_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>User storage quotas - Cloud Rdx</title><style>
body{margin:0;background:#f8f9fc;color:#3a3b45;font-family:Arial,sans-serif}.wrap{width:min(1180px,calc(100% - 32px));margin:32px auto}.top{display:flex;justify-content:space-between;align-items:start;gap:18px;margin-bottom:24px}.top a{color:#4e73df;font-weight:700;text-decoration:none}.panel{overflow:hidden;background:#fff;border:1px solid #e3e6f0;border-radius:8px;box-shadow:0 .15rem 1.2rem #3a3b4512}.head{padding:20px 22px;border-bottom:1px solid #e3e6f0}.head h1{margin:0 0 7px;font-size:28px}.head p{margin:0;color:#858796;font-size:13px}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:760px;font-size:13px}th{padding:13px 18px;color:#6e707e;background:#f8f9fc;text-align:left;font-size:11px;text-transform:uppercase}td{padding:15px 18px;border-top:1px solid #eaecf4;vertical-align:middle}.muted{color:#858796;font-size:12px}.quota-form{display:flex;gap:7px;align-items:center}.quota-form input{width:110px;padding:8px;border:1px solid #d1d3e2;border-radius:4px}.button{padding:8px 11px;color:#fff;background:#4e73df;border:1px solid #4e73df;border-radius:4px;cursor:pointer;font-weight:700}.notice{margin-bottom:18px;padding:12px 15px;color:#856404;background:#fff3cd;border:1px solid #ffeeba;border-radius:5px}@media(max-width:700px){.top{display:block}.top a{display:inline-block;margin-top:14px}}
</style></head><body><main class="wrap"><header class="top"><div><p class="muted">CLOUD RDX / ADMINISTRATION</p><h1>User storage quotas</h1><p class="muted">Review storage usage, quotas, and per-user upload/download access.</p></div><a href="{{ url_for('admin_panel') }}">→ ADMIN DASHBOARD</a></header>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="notice">{{ message }}</div>{% endfor %}{% endwith %}<section class="panel"><div class="head"><h1>Storage allocation and access by user</h1><p>Each change applies only to the selected user and is recorded in the audit trail.</p></div><div class="table-wrap"><table><thead><tr><th>User ID</th><th>Username</th><th>Total Storage Used</th><th>Allocated Quota</th><th>Remaining Quota</th><th>Set Quota</th><th>Storage access</th></tr></thead><tbody>{% for item in users %}<tr><td>{{ item.id }}</td><td><strong>{{ item.username }}</strong><br><span class="muted">{{ item.status }}</span></td><td>{{ item.used|filesize }}</td><td>{% if item.quota %}{{ item.quota|filesize }}{% else %}Unlimited{% endif %}</td><td>{% if item.quota %}{{ item.remaining|filesize }}{% else %}Unlimited{% endif %}</td><td><form class="quota-form" method="post" action="{{ url_for('admin_storage_quota', user_id=item.id) }}"><input type="number" name="quota_mb" min="0" value="{{ item.quota_mb }}" required><span class="muted">MB</span><button class="button" type="submit">Save</button></form></td><td><form method="post" action="{{ url_for('admin_storage_permissions', user_id=item.id) }}"><label><input type="checkbox" name="allow_upload"{% if item.allow_upload %} checked{% endif %}> Upload</label><br><label><input type="checkbox" name="allow_download"{% if item.allow_download %} checked{% endif %}> Download</label><br><button class="button" type="submit">Save access</button></form></td></tr>{% else %}<tr><td colspan="7">No non-administrator users found.</td></tr>{% endfor %}</tbody></table></div></section></main></body></html>
"""


ADMIN_PERMISSIONS_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access control - Cloud Rdx</title>
<style>
:root{--ink:#14231e;--muted:#71817b;--line:#dfe9e2;--paper:#f4f8f5;--panel:#fff;--green:#18794e;--dark:#105437;--gold:#f2be58;--shadow:0 16px 40px rgba(25,64,45,.09)}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font-family:Arial,sans-serif}.shell{min-height:100vh;display:grid;grid-template-columns:230px 1fr}.rail{padding:28px 18px;color:#eaf8ef;background:var(--dark);display:flex;flex-direction:column}.brand{display:flex;align-items:center;gap:10px;color:#fff;text-decoration:none;font-weight:700}.brand-mark{width:34px;height:34px;display:grid;place-items:center;color:var(--dark);background:var(--gold);border-radius:10px 10px 10px 2px;font-weight:800}.rail-nav{margin-top:55px;display:grid;gap:7px}.rail-link{padding:11px 12px;color:#b9d7c3;text-decoration:none;border-radius:9px;font-size:13px}.rail-link:hover,.rail-link.active{color:#fff;background:#ffffff1c}.rail-bottom{margin-top:auto;padding:15px 12px;border-top:1px solid #ffffff26;color:#a9cbb6;font-size:11px;line-height:1.6}.main{padding:38px clamp(20px,5vw,70px);max-width:1500px}.topbar{display:flex;justify-content:space-between;gap:20px;align-items:start;margin-bottom:28px}.eyebrow{margin:0 0 9px;color:var(--green);text-transform:uppercase;letter-spacing:.14em;font-size:11px;font-weight:700}.topbar h1{margin:0 0 8px;font:500 clamp(30px,4vw,46px) Georgia,serif;letter-spacing:-.03em}.subtitle{margin:0;color:var(--muted);font-size:14px;line-height:1.6}.actions{display:flex;gap:9px;flex-wrap:wrap}.button{display:inline-block;padding:10px 14px;color:#fff;background:var(--green);border:0;border-radius:8px;cursor:pointer;text-decoration:none;font-weight:700;font-size:12px}.button.secondary{color:var(--green);background:#e4f1e8}.flash{padding:12px 15px;margin-bottom:18px;color:#72500d;background:#fff4d7;border:1px solid #f1d79a;border-radius:9px;font-size:13px}.intro{display:grid;grid-template-columns:1.4fr 1fr;gap:18px;margin-bottom:20px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:15px;box-shadow:var(--shadow);overflow:hidden}.intro-card{padding:22px}.intro-card h2{margin:0 0 8px;font:500 23px Georgia,serif}.intro-card p{margin:0;color:var(--muted);font-size:13px;line-height:1.6}.stat-list{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.stat{padding:16px;background:#f7fbf8;border:1px solid var(--line);border-radius:10px}.stat b{display:block;font-size:20px;color:var(--green)}.stat span{color:var(--muted);font-size:11px}.head{padding:21px 23px;border-bottom:1px solid var(--line)}.head h2{margin:0 0 5px;font:500 21px Georgia,serif}.head p{margin:0;color:var(--muted);font-size:13px}.role-create{display:grid;grid-template-columns:1fr 2fr auto;gap:10px;padding:20px 23px}.input{width:100%;padding:11px 12px;border:1px solid #cbd9cf;border-radius:8px;background:#fff;font:13px Arial}.roles{display:grid;gap:16px;padding:18px}.role-card{border:1px solid var(--line);border-radius:12px;overflow:hidden}.role-head{display:flex;justify-content:space-between;gap:12px;align-items:start;padding:17px 18px;background:#f8fbf9}.role-head h3{margin:0 0 4px;font-size:16px}.role-head p{margin:0;color:var(--muted);font-size:12px}.permission-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:9px;padding:17px 18px}.permission{display:flex;gap:9px;align-items:center;padding:10px;background:#f7faf8;border:1px solid #e4ede7;border-radius:8px;color:#35463e;font-size:12px}.permission input{accent-color:var(--green)}.role-save{padding:0 18px 17px;text-align:right}@media(max-width:800px){.shell{display:block}.rail{padding:18px}.rail-nav{margin-top:22px;display:flex;overflow:auto}.rail-link{white-space:nowrap}.main{padding:25px 16px}.topbar,.intro{display:block}.actions{margin-top:16px}.intro-card{margin-bottom:12px}.role-create{grid-template-columns:1fr}.role-save{text-align:left}}
</style></head><body><div class="shell"><aside class="rail"><a class="brand" href="{{ url_for('files') }}"><span class="brand-mark">C</span><span>Cloud Rdx</span></a><nav class="rail-nav"><a class="rail-link" href="{{ url_for('admin_panel') }}">Dashboard</a><a class="rail-link" href="{{ url_for('admin_manage') }}">Administration</a><a class="rail-link active" href="{{ url_for('admin_permissions') }}">Access control</a><a class="rail-link" href="{{ url_for('admin_security') }}">Security center</a><a class="rail-link" href="{{ url_for('logout') }}">Sign out</a></nav><div class="rail-bottom">Owner-only security controls<br>Every permission change is audited</div></aside><main class="main"><header class="topbar"><div><p class="eyebrow">Cloud Rdx / governance</p><h1>Access control</h1><p class="subtitle">Design delegated roles and apply least-privilege permissions from one focused workspace.</p></div><div class="actions"><a class="button secondary" href="{{ url_for('admin_manage') }}">Administration</a><a class="button" href="{{ url_for('admin_panel') }}">Dashboard</a></div></header>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}{% endwith %}<section class="intro"><div class="panel intro-card"><h2>Permission governance</h2><p>The owner is the only administrator. Delegated roles let other users perform specific tasks without granting full administrator access. Role changes are separate from account status and storage quota operations.</p></div><div class="stat-list"><div class="stat"><b>{{ roles|length }}</b><span>Delegated roles</span></div><div class="stat"><b>{{ permissions|length }}</b><span>Available permissions</span></div></div></section><section class="panel" style="margin-bottom:20px"><div class="head"><h2>Create a custom role</h2><p>Use a clear name and configure its permissions immediately after creation.</p></div><form class="role-create" method="post" action="{{ url_for('admin_role_create') }}"><input class="input" name="name" required maxlength="48" pattern="[A-Za-z0-9_-]+" placeholder="role_name"><input class="input" name="description" maxlength="160" placeholder="What can this role do?"><button class="button" type="submit">Create role</button></form></section><section class="panel"><div class="head"><h2>Delegated roles</h2><p>Each role is independent. Save only the permissions this role needs.</p></div><div class="roles">{% for role in roles %}<form class="role-card" method="post" action="{{ url_for('admin_role_permissions', role_id=role.id) }}"><div class="role-head"><div><h3>{{ role.name|replace('_',' ')|title }}</h3><p>{{ role.description or 'No description provided.' }}</p></div><span class="stat"><span>Role permissions</span></span></div><div class="permission-grid">{% for permission in permissions %}<label class="permission"><input type="checkbox" name="permissions" value="{{ permission.key }}"{% if permission.key in role.permissions %} checked{% endif %}> <span>{{ permission.label }}</span></label>{% endfor %}</div><div class="role-save"><button class="button" type="submit">Save permissions</button></div></form>{% else %}<div class="intro-card"><p>No delegated roles exist yet. Create one above to begin.</p></div>{% endfor %}</div></section></main></div></body></html>
"""


ADMIN_PAGE = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{ admin_title }} - Cloud Rdx</title>
<style>
:root{--ink:#16221f;--muted:#71817b;--line:#dfe8e2;--paper:#f7faf7;--panel:#fff;--green:#18794e;--dark:#105437;--gold:#f2be58;--red:#a34f3a;--shadow:0 18px 50px rgba(25,64,45,.08)}*{box-sizing:border-box}body{margin:0;color:var(--ink);background:var(--paper);font-family:Georgia,'Times New Roman',serif}.shell{min-height:100vh;display:grid;grid-template-columns:248px 1fr}.rail{padding:30px 22px;color:#eaf8ef;background:var(--dark);display:flex;flex-direction:column}.brand{display:flex;align-items:center;gap:12px;color:#fff;text-decoration:none;font-weight:700}.brand-mark{width:35px;height:35px;display:grid;place-items:center;color:var(--dark);background:var(--gold);border-radius:10px 10px 10px 2px;font:bold 16px Arial}.rail-nav{margin-top:70px;display:grid;gap:10px;font:14px Arial}.rail-link{display:flex;gap:12px;padding:12px 13px;color:#b9d7c3;text-decoration:none;border-radius:10px}.rail-link:hover,.rail-link.active{color:#fff;background:#ffffff1c}.rail-bottom{margin-top:auto;padding:17px 14px;border-top:1px solid #ffffff26;color:#a9cbb6;font:12px/1.6 Arial}.main{padding:36px clamp(22px,5vw,72px)}.topbar{display:flex;justify-content:space-between;gap:20px;align-items:start;margin-bottom:35px}.eyebrow{margin:0 0 10px;color:var(--green);text-transform:uppercase;letter-spacing:.16em;font:700 11px Arial}h1{margin:0 0 9px;font-size:clamp(30px,4vw,48px);font-weight:500;letter-spacing:-.03em}.subtitle{margin:0;color:var(--muted);font:14px Arial}.user-chip{display:flex;align-items:center;gap:10px;padding:8px 12px 8px 8px;background:#fff;border:1px solid var(--line);border-radius:999px;font:13px Arial}.avatar{display:grid;place-items:center;width:29px;height:29px;color:#fff;background:var(--green);border-radius:50%;font-weight:700}.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow);overflow:hidden}.panel-head{padding:23px;border-bottom:1px solid var(--line)}.panel-head h2{margin:0 0 6px;font-size:20px;font-weight:500}.panel-head p{margin:0;color:var(--muted);font:13px Arial}.flash{margin:0 0 20px;padding:12px 15px;color:#7a5311;background:#fff4d7;border:1px solid #f3db9d;border-radius:8px;font:13px Arial}.user-row{display:grid;grid-template-columns:minmax(120px,1fr) 145px 150px 270px;gap:18px;align-items:center;padding:17px 23px;border-bottom:1px solid #edf2ee;font-family:Arial}.user-row:last-child{border-bottom:0}.user-name{font-size:14px;font-weight:700}.user-name small{display:block;margin-top:5px;color:var(--muted);font-size:11px;font-weight:400}.status{font-size:12px;color:var(--green)}.status.stale{color:var(--red);font-weight:700}.user-form{display:flex;gap:7px}.user-form input{min-width:0;width:130px;padding:9px;border:1px solid var(--line);border-radius:7px;font:12px Arial}.button{padding:9px 11px;border:0;border-radius:7px;background:var(--green);color:#fff;cursor:pointer;font:bold 11px Arial}.button:hover{background:var(--dark)}.button.danger{background:#fff;color:var(--red);border:1px solid #e8c9c0}.button.danger:hover{background:#fff1ed}.empty{padding:50px;text-align:center;color:var(--muted);font:14px Arial}@media(max-width:900px){.shell{grid-template-columns:72px 1fr}.rail{padding:22px 13px}.brand span,.rail-link span:not(.rail-icon),.rail-bottom{display:none}.rail-nav{margin-top:45px}.rail-link{justify-content:center}.user-row{grid-template-columns:1fr 1fr}.user-form{grid-column:1/-1}}@media(max-width:620px){.main{padding:25px 15px}.topbar{flex-direction:column}.user-row{grid-template-columns:1fr}.user-form{grid-column:auto;flex-wrap:wrap}.user-form input{flex:1}.panel{border-radius:12px}}
</style></head><body><div class="shell"><aside class="rail"><a class="brand" href="{{ url_for('files') }}"><span class="brand-mark">C</span><span>Cloud Rdx</span></a><nav class="rail-nav"><a class="rail-link" href="{{ url_for('files') }}"><span class="rail-icon">[ ]</span><span>My storage</span></a><a class="rail-link active" href="{{ url_for('admin_panel') }}"><span class="rail-icon">#</span><span>{{ admin_title }}</span></a>{% if is_owner %}<a class="rail-link" href="{{ url_for('admin_settings') }}"><span class="rail-icon">⚙</span><span>Website &amp; security settings</span></a><a class="rail-link" href="{{ url_for('admin_security') }}"><span class="rail-icon">!</span><span>Security center</span></a><a class="rail-link" href="{{ url_for('admin_emergency') }}"><span class="rail-icon">!</span><span>Emergency controls</span></a>{% endif %}{% if can_manage_users %}<a class="rail-link" href="{{ url_for('admin_manage') }}"><span class="rail-icon">+</span><span>User administration</span></a>{% endif %}{% if can_manage_storage %}<a class="rail-link" href="{{ url_for('admin_storage') }}"><span class="rail-icon">$</span><span>Storage administration</span></a>{% endif %}{% if can_review_payments %}<a class="rail-link" href="{{ url_for('admin_payments') }}"><span class="rail-icon">₹</span><span>Payment administration</span></a>{% endif %}{% if can_view_audit %}<a class="rail-link" href="{{ url_for('admin_audit') }}"><span class="rail-icon">=</span><span>Audit administration</span></a>{% endif %}<a class="rail-link" href="{{ url_for('logout') }}"><span class="rail-icon">&lt;</span><span>Sign out</span></a></nav><div class="rail-bottom">{{ admin_role_label }}<br>Restricted permissions</div></aside><main class="main"><header class="topbar"><div><p class="eyebrow">Role-based administration</p><h1>{{ admin_title }}</h1><p class="subtitle">{{ admin_description }}</p></div><div class="user-chip"><span class="avatar">{{ username[0]|upper }}</span><span>{{ username }} · {{ admin_role_label }}</span></div></header>{% with messages = get_flashed_messages() %}{% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}{% endwith %}<section class="panel"><div class="panel-head"><h2>Accounts</h2><p>Inactive means no recorded activity for {{ inactive_days }} days. Only inactive non-admin accounts can be removed.</p></div>{% for item in users %}<div class="user-row"><div class="user-name">{{ item.username }}{% if item.is_admin %}<small>Administrator account</small>{% else %}<small>Joined {{ item.created_at|dateonly }}</small>{% endif %}</div><div class="status{% if item.inactive %} stale{% endif %}">{% if item.inactive %}Inactive{% else %}Active{% endif %}<small style="display:block;color:var(--muted);margin-top:4px">{{ item.last_seen|prettydate }}</small></div><div style="font:12px Arial;color:var(--muted)">{{ item.files }} files · {{ item.bytes|filesize }}</div>{% if not item.is_admin %}<div class="user-form"><form method="post" action="{{ url_for('admin_password', user_id=item.id) }}"><input name="password" type="password" minlength="8" placeholder="New password" required><button class="button" type="submit">Change password</button></form>{% if item.inactive %}<form method="post" action="{{ url_for('admin_delete_user', user_id=item.id) }}" onsubmit="return confirm('Remove this inactive user and all their files?')"><button class="button danger" type="submit">Remove user</button></form>{% endif %}</div>{% else %}<div style="font:12px Arial;color:var(--muted)">Protected account</div>{% endif %}</div>{% else %}<div class="empty">No accounts found.</div>{% endfor %}</section></main></div></body></html>
"""


ADMIN_PAGE = ADMIN_PAGE.replace(
    "{{ item.username }}",
    "<a href=\"{{ url_for('admin_user_files', user_id=item.id) }}\">{{ item.username }}</a> <a href=\"{{ url_for('admin_user_profile', user_id=item.id) }}\" style=\"font-size:10px\">[profile]</a>",
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<section class="panel"><div class="panel-head"><h2>Accounts</h2>',
    '<section class="admin-stat-grid"><article class="panel admin-stat"><span class="admin-stat-label">Total users</span><strong class="admin-stat-value">{{ dashboard.total_users }}</strong></article><article class="panel admin-stat success"><span class="admin-stat-label">Active users</span><strong class="admin-stat-value">{{ dashboard.active_users }}</strong></article><article class="panel admin-stat info"><span class="admin-stat-label">Files / storage</span><strong class="admin-stat-value">{{ dashboard.total_files }} / {{ dashboard.total_bytes|filesize }}</strong></article><article class="panel admin-stat warning"><span class="admin-stat-label">Security alerts</span><strong class="admin-stat-value">{{ dashboard.open_alerts }}</strong></article></section><section class="panel" style="margin-bottom:20px"><div class="panel-head"><h2>System health</h2><p>Live operational indicators from the application database and storage roots.</p></div><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;padding:18px;font:12px Arial"><div><b>API</b><br><span class="status">ONLINE</span></div><div><b>Database</b><br><span class="status">ONLINE</span></div><div><b>Storage</b><br><span class="status">{{ dashboard.total_bytes|filesize }} used</span></div><div><b>Failed logins / 24h</b><br><span class="status{% if dashboard.failed_logins %} stale{% endif %}">{{ dashboard.failed_logins }}</span></div><div><b>Emergency mode</b><br><span class="status{% if dashboard.read_only or dashboard.maintenance %} stale{% endif %}">{% if dashboard.read_only or dashboard.maintenance %}RESTRICTED{% else %}NORMAL{% endif %}</span></div></div></section><section class="panel"><div class="panel-head"><h2>Accounts</h2>',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<section class="admin-stat-grid">',
    """<section class="dashboard-welcome" data-dashboard-user="{{ session.get('user_id', 'admin') }}" aria-label="Admin dashboard shortcuts">
    <div class="dashboard-welcome-copy">
        <p class="dashboard-kicker">Your workspace at a glance</p>
        <h2>Welcome back, {{ username }}.</h2>
        <p>Choose a tool to jump straight into the work that needs your attention.</p>
    </div>
    <nav class="dashboard-quick-links" aria-label="Frequently used admin tools">
        {% if is_owner %}<a class="dashboard-quick-link security" href="{{ url_for('admin_security') }}"><span class="quick-icon" aria-hidden="true">!</span><span><strong>Security center</strong><small>Alerts and rate limits</small></span><span class="quick-arrow" aria-hidden="true">→</span></a>{% endif %}
        {% if can_manage_users %}<a class="dashboard-quick-link users" href="{{ url_for('admin_manage') }}"><span class="quick-icon" aria-hidden="true">+</span><span><strong>User administration</strong><small>Accounts and access</small></span><span class="quick-arrow" aria-hidden="true">→</span></a>{% endif %}
        {% if can_manage_storage %}<a class="dashboard-quick-link storage" href="{{ url_for('admin_storage') }}"><span class="quick-icon" aria-hidden="true">◇</span><span><strong>Storage quotas</strong><small>Usage and permissions</small></span><span class="quick-arrow" aria-hidden="true">→</span></a>{% endif %}
        {% if can_review_payments %}<a class="dashboard-quick-link payments" href="{{ url_for('admin_payments') }}"><span class="quick-icon" aria-hidden="true">₹</span><span><strong>Payments</strong><small>Review requests</small></span><span class="quick-arrow" aria-hidden="true">→</span></a>{% endif %}
        {% if can_view_audit %}<a class="dashboard-quick-link audit" href="{{ url_for('admin_audit') }}"><span class="quick-icon" aria-hidden="true">≡</span><span><strong>Audit activity</strong><small>Recent changes</small></span><span class="quick-arrow" aria-hidden="true">→</span></a>{% endif %}
    </nav>
    <div class="dashboard-personalize">
        <button class="dashboard-customize-button" id="dashboard-customize" type="button" aria-expanded="false" aria-controls="dashboard-preferences">Customize dashboard</button>
        <div class="dashboard-preferences" id="dashboard-preferences" hidden>
            <p>Show dashboard cards</p>
            <label><input type="checkbox" data-widget-toggle="users" checked> Total users</label>
            <label><input type="checkbox" data-widget-toggle="active-users" checked> Active users</label>
            <label><input type="checkbox" data-widget-toggle="storage" checked> Files and storage</label>
            <label><input type="checkbox" data-widget-toggle="alerts" checked> Security alerts</label>
            <label><input type="checkbox" data-widget-toggle="health" checked> System health</label>
            <button class="dashboard-reset-button" id="dashboard-reset" type="button">Reset to default</button>
            <span class="dashboard-preference-status" id="dashboard-preference-status" role="status" aria-live="polite"></span>
        </div>
    </div>
</section><section class="admin-stat-grid">""",
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<article class="panel admin-stat">',
    '<article class="panel admin-stat" data-dashboard-widget="users">',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<article class="panel admin-stat success">',
    '<article class="panel admin-stat success" data-dashboard-widget="active-users">',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<article class="panel admin-stat info">',
    '<article class="panel admin-stat info" data-dashboard-widget="storage">',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<article class="panel admin-stat warning">',
    '<article class="panel admin-stat warning" data-dashboard-widget="alerts">',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<section class="panel" style="margin-bottom:20px"><div class="panel-head"><h2>System health</h2>',
    '<section class="panel dashboard-health" data-dashboard-widget="health" style="margin-bottom:20px"><div class="panel-head"><h2>System health</h2>',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    "</body></html>",
    '<script src="{{ url_for(\'static\', filename=\'admin-dashboard.js\') }}" defer></script></body></html>',
    1,
)


ADMIN_SETTINGS_PAGE = """
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Website settings - Cloud Rdx</title><link rel="stylesheet" href="{{ url_for('static', filename='admin-theme.css') }}">
<style>
.settings-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,360px),1fr));gap:18px;max-width:1100px}.settings-card{overflow:hidden}.settings-form{padding:22px;display:grid;gap:16px}.setting-row{display:grid;gap:7px;font-size:14px;font-weight:700}.setting-row input[type=number]{max-width:220px;padding:10px 12px;border:1px solid #cbd9cf;border-radius:8px;font:14px Arial}.setting-help{margin:0;color:var(--admin-muted);font-size:12px;line-height:1.55}.setting-toggle{display:flex;gap:11px;align-items:flex-start;padding:13px;background:#f5faf6;border:1px solid var(--admin-line);border-radius:10px;font-size:13px;line-height:1.5}.setting-toggle input{width:18px;height:18px;margin:1px 0 0;accent-color:var(--admin-green)}.oauth-status{padding:11px 13px;border-radius:9px;background:#eef8f1;color:#185a37;font-size:13px;line-height:1.5}.oauth-status.offline{background:#fff4d7;color:#72500d}.settings-actions{display:flex;flex-wrap:wrap;gap:10px;align-items:center}.settings-actions .secondary{display:inline-block;padding:10px 13px;border-radius:8px;background:#e4f1e8;color:var(--admin-blue);font-size:12px;font-weight:700;text-decoration:none}.settings-full{grid-column:1/-1}
</style></head><body class="admin-theme"><main class="main">
<header class="topbar"><div><p class="eyebrow">System configuration</p><h1>Website settings</h1><p class="subtitle">Manage sign-up, Google and GitHub sign-in, login protection, sharing, and retention.</p></div><div class="settings-actions"><a class="button secondary" href="{{ url_for('admin_security') }}">Security reports</a><a class="button" href="{{ url_for('admin_panel') }}">Back to dashboard</a></div></header>
{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="flash" role="status">{{ message }}</div>{% endfor %}{% endwith %}
<form method="post"><div class="settings-grid">
<section class="panel settings-card"><div class="panel-head"><h2>Account access</h2><p>Choose which account creation and sharing options are available to site visitors.</p></div><div class="settings-form">
<label class="setting-toggle"><input type="checkbox" name="allow_registration"{% if settings.allow_registration %} checked{% endif %}><span><strong>Allow new account registration</strong><br><span class="setting-help">Controls password sign-up and whether new Google users can create accounts.</span></span></label>
<label class="setting-toggle"><input type="checkbox" name="allow_google_signin"{% if settings.allow_google_signin %} checked{% endif %}><span><strong>Allow Google sign-in</strong><br><span class="setting-help">When disabled, the Google login and sign-up buttons cannot start authentication. Existing linked accounts are not removed.</span></span></label>
<div class="oauth-status{% if not settings.google_oauth_configured %} offline{% endif %}"><strong>Google OAuth configuration:</strong> {% if settings.google_oauth_configured %}{% if settings.google_oauth_admin_managed %}Credentials are saved encrypted in admin settings.{% else %}Credentials are loaded from the server environment.{% endif %} The client secret is never displayed.{% else %}Credentials are not configured. Add them below or provide GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET in the server environment.{% endif %}</div>
<label class="setting-row" for="google-client-id">Google OAuth Client ID<input id="google-client-id" name="google_oauth_client_id" type="text" maxlength="512" autocomplete="off" placeholder="Leave blank to keep the current Client ID"><span class="setting-help">Current Client ID: {{ settings.google_oauth_client_id or 'not configured' }}. Client IDs are not secret.</span></label>
<label class="setting-row" for="google-client-secret">Google OAuth Client Secret<input id="google-client-secret" name="google_oauth_client_secret" type="password" maxlength="4096" autocomplete="new-password" placeholder="{% if settings.google_oauth_configured %}Saved; leave blank to keep current secret{% else %}Paste Google OAuth Client Secret{% endif %}"><span class="setting-help">Stored encrypted and never shown again. Requires a persistent FLASK_SECRET_KEY.</span></label>
<label class="setting-toggle"><input type="checkbox" name="clear_google_oauth_credentials"><span><strong>Remove admin-managed Google credentials</strong><br><span class="setting-help">Environment credentials, if present, remain active as a fallback.</span></span></label>
<label class="setting-toggle"><input type="checkbox" name="allow_github_signin"{% if settings.allow_github_signin %} checked{% endif %}><span><strong>Allow GitHub sign-in</strong><br><span class="setting-help">When disabled, GitHub login and sign-up cannot start authentication. Existing linked accounts are not removed.</span></span></label>
<div class="oauth-status{% if not settings.github_oauth_configured %} offline{% endif %}"><strong>GitHub OAuth configuration:</strong> {% if settings.github_oauth_configured %}{% if settings.github_oauth_admin_managed %}Credentials are saved encrypted in admin settings.{% else %}Credentials are loaded from the server environment.{% endif %} The client secret is never displayed.{% else %}Credentials are not configured. Add them below or provide GITHUB_OAUTH_CLIENT_ID and GITHUB_OAUTH_CLIENT_SECRET in the server environment.{% endif %}</div>
<label class="setting-row" for="github-client-id">GitHub OAuth Client ID<input id="github-client-id" name="github_oauth_client_id" type="text" maxlength="512" autocomplete="off" placeholder="Leave blank to keep the current Client ID"><span class="setting-help">Current Client ID: {{ settings.github_oauth_client_id or 'not configured' }}. Client IDs are not secret.</span></label>
<label class="setting-row" for="github-client-secret">GitHub OAuth Client Secret<input id="github-client-secret" name="github_oauth_client_secret" type="password" maxlength="4096" autocomplete="new-password" placeholder="{% if settings.github_oauth_configured %}Saved; leave blank to keep current secret{% else %}Paste GitHub OAuth App Client Secret{% endif %}"><span class="setting-help">Stored encrypted and never shown again. Requires a persistent FLASK_SECRET_KEY.</span></label>
<label class="setting-toggle"><input type="checkbox" name="clear_github_oauth_credentials"><span><strong>Remove admin-managed GitHub credentials</strong><br><span class="setting-help">Environment credentials, if present, remain active as a fallback.</span></span></label>
<label class="setting-toggle"><input type="checkbox" name="allow_public_sharing"{% if settings.allow_public_sharing %} checked{% endif %}><span><strong>Allow public sharing</strong><br><span class="setting-help">Enable or disable public file sharing across the site.</span></span></label>
<label class="setting-row" for="trash-retention">Recycle-bin retention (days)<input id="trash-retention" name="trash_retention_days" type="number" min="1" max="3650" value="{{ settings.trash_retention_days }}" required><span class="setting-help">Deleted files are automatically retained for this duration.</span></label>
</div></section>
<section class="panel settings-card"><div class="panel-head"><h2>Login protection</h2><p>Adjust when repeated failed passwords trigger progressively longer lockouts.</p></div><div class="settings-form">
<label class="setting-row" for="login-max-attempts">Failed attempts before lockout<input id="login-max-attempts" name="login_max_attempts" type="number" min="1" max="100" value="{{ settings.login_max_attempts }}" required><span class="setting-help">Applies per account and source address. Further retries return HTTP 429 with a Retry-After header.</span></label>
<label class="setting-row" for="login-window">Failure counting window (minutes)<input id="login-window" name="login_window_minutes" type="number" min="1" max="1440" value="{{ settings.login_window_minutes }}" required></label>
<label class="setting-row" for="login-lockout">Initial lockout duration (minutes)<input id="login-lockout" name="login_lockout_minutes" type="number" min="1" max="1440" value="{{ settings.login_lockout_minutes }}" required><span class="setting-help">Repeat lockouts increase progressively, up to eight times this duration.</span></label>
<div class="settings-actions"><button class="button" type="submit">Save website and security settings</button><a class="secondary" href="{{ url_for('admin_security') }}">Review security activity →</a></div>
</div></section></div></form></main></body></html>
"""


ADMIN_MANAGEMENT_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Administration - Cloud Rdx</title>
<style>body{margin:0;background:#f2f6f8;color:#17212b;font-family:Arial,sans-serif}.wrap{width:min(1180px,calc(100% - 32px));margin:32px auto}.top{display:flex;justify-content:space-between;gap:18px;align-items:start;margin-bottom:24px}.top a{color:#087f73;font-weight:700;text-decoration:none}.panel{margin-bottom:22px;overflow:hidden;background:#fff;border:1px solid #d8e1e8;border-radius:10px;box-shadow:0 12px 30px #19314214}.head{padding:19px 22px;border-bottom:1px solid #d8e1e8}.head h2{margin:0 0 5px;font-size:19px}.head p{margin:0;color:#647483;font-size:13px}.row{display:grid;grid-template-columns:1.2fr 1fr 1fr 1.5fr;gap:12px;align-items:center;padding:14px 22px;border-bottom:1px solid #edf1f3;font-size:13px}.row:last-child{border:0}.muted{color:#647483;font-size:12px}.form{display:flex;gap:7px;flex-wrap:wrap}.input{min-width:0;padding:8px;border:1px solid #cbd8e0;border-radius:6px}.button{padding:8px 10px;color:#fff;background:#087f73;border:0;border-radius:6px;cursor:pointer;font-weight:700}.danger{background:#a34f3a}.notice{padding:12px 15px;background:#fff4d7;border:1px solid #f3db9d;color:#7a5311;border-radius:7px;margin-bottom:18px}@media(max-width:800px){.row{grid-template-columns:1fr}.wrap{margin:22px auto}}</style></head><body><main class="wrap"><header class="top"><div><p class="muted">CLOUD RDX / ADMINISTRATION</p><h1>Control center</h1><p class="muted">Sensitive actions are audited. Deletes move data to recoverable trash first.</p></div><div><a href="{{ url_for('admin_panel') }}">→ ADMIN DASHBOARD</a><form method="post" action="{{ url_for('admin_backup') }}" style="margin-top:12px"><button class="button" type="submit">Create local backup</button></form></div></header>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="notice">{{ message }}</div>{% endfor %}{% endwith %}
<section class="panel"><div class="head"><h2>Accounts and lifecycle</h2><p>Manage account status and storage quotas here. The owner is the only administrator; delegated roles define exactly what other users can do.</p></div>{% for item in users %}<div class="row"><div><strong>{{ item.username }}</strong><div class="muted">{{ item.files }} files · {{ item.bytes|filesize }} used · {{ item.status }}</div></div><div class="muted">{% if item.is_admin %}Administrator{% elif item.roles %}{{ item.roles|join(', ') }}{% else %}Normal user{% endif %}</div><form class="form" method="post" action="{{ url_for('admin_user_status', user_id=item.id) }}"><input class="input" type="hidden" name="status" value="{{ 'suspended' if item.status == 'active' else 'active' }}"><button class="button{% if item.status == 'active' %} danger{% endif %}" type="submit">{{ 'Suspend' if item.status == 'active' else 'Activate' }}</button></form><form class="form" method="post" action="{{ url_for('admin_user_quota', user_id=item.id) }}"><input class="input" name="quota_mb" type="number" min="0" value="{{ item.quota_mb }}" placeholder="Quota MB"><button class="button" type="submit">Save quota</button></form>{% if is_owner and item.username|lower != owner_username|lower %}<form class="form" method="post" action="{{ url_for('admin_user_role', user_id=item.id) }}"><select class="input" name="role_name"><option value="__normal_user__"{% if not item.is_admin and not item.roles %} selected{% endif %}>Normal user - no delegated access</option>{% for role in roles %}<option value="{{ role.name }}" title="{{ role.description }}">{{ role.name|replace('_', ' ')|title }} - {{ role.description }}</option>{% endfor %}</select><button class="button" type="submit">Save role</button></form>{% elif item.username|lower == owner_username|lower %}<span class="muted">Protected owner account</span>{% else %}<span class="muted">Owner-managed role</span>{% endif %}</div>{% endfor %}</section>
<section class="panel"><div class="head"><h2>Groups</h2><p>Create teams and assign users explicitly.</p></div><div class="row"><form class="form" method="post" action="{{ url_for('admin_group_create') }}"><input class="input" name="name" required placeholder="Group name"><input class="input" name="description" placeholder="Description"><button class="button" type="submit">Create group</button></form></div>{% for group in groups %}<div class="row"><div><strong>{{ group.name }}</strong><div class="muted">{{ group.description }}</div></div><div class="muted">{{ group.members }} members</div><form class="form" method="post" action="{{ url_for('admin_group_member', group_id=group.id) }}"><select class="input" name="user_id" required>{% for item in users if item.status == 'active' %}<option value="{{ item.id }}">{{ item.username }}</option>{% endfor %}</select><button class="button" type="submit">Add member</button></form><span></span></div>{% endfor %}</section>
<section class="panel"><div class="head"><h2>Audit trail</h2><p>Recent administrative and security-sensitive activity.</p></div>{% for event in events %}<div class="row"><div><strong>{{ event.action }}</strong><div class="muted">{{ event.created_at|prettydate }}</div></div><div>{{ event.actor or 'System' }}</div><div>{{ event.target_type }} {{ event.target_id or '' }}</div><div class="muted">{{ event.details }}</div></div>{% else %}<div class="row">No events recorded yet.</div>{% endfor %}</section></main></body></html>
"""

# Keep Control Center focused on account status and delegated roles. Storage
# quotas and audit activity have dedicated admin pages.
ADMIN_MANAGEMENT_PAGE = re.sub(
    r'<section class="panel"><div class="head"><h2>Groups</h2>.*?</section>',
    '',
    ADMIN_MANAGEMENT_PAGE,
    flags=re.DOTALL,
)
ADMIN_MANAGEMENT_PAGE = ADMIN_MANAGEMENT_PAGE.replace(
    '<a href="{{ url_for(\'admin_panel\') }}">→ ADMIN DASHBOARD</a>',
    '<a href="{{ url_for(\'admin_panel\') }}">→ ADMIN DASHBOARD</a>{% if is_owner %} <a href="{{ url_for(\'admin_permissions\') }}">ACCESS CONTROL →</a>{% endif %}',
)
ADMIN_MANAGEMENT_PAGE = re.sub(
    r'<section class="panel"><div class="head"><h2>Audit trail</h2>.*?</section>',
    '',
    ADMIN_MANAGEMENT_PAGE,
    flags=re.DOTALL,
)
ADMIN_MANAGEMENT_PAGE = re.sub(
    r'<form class="form" method="post" action="{{ url_for\(\'admin_user_quota\'.*?</form>',
    '',
    ADMIN_MANAGEMENT_PAGE,
    flags=re.DOTALL,
)
ADMIN_MANAGEMENT_PAGE = re.sub(
    r'<form class="form" method="post" action="{{ url_for\(\'admin_user_status\'.*?</form>',
    '{% if not item.is_admin %}<form class="form" method="post" action="{{ url_for(\'admin_user_status\', user_id=item.id) }}"><input class="input" type="hidden" name="status" value="{{ \'suspended\' if item.status == \'active\' else \'active\' }}"><button class="button{% if item.status == \'active\' %} danger{% endif %}" type="submit">{{ \'Suspend\' if item.status == \'active\' else \'Activate\' }}</button></form>{% else %}<span class="muted">Administrator account protected</span>{% endif %}',
    ADMIN_MANAGEMENT_PAGE,
    flags=re.DOTALL,
)


ADMIN_AUDIT_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Audit activity - Cloud Rdx</title>
<style>body{margin:0;background:#f8f9fc;color:#3a3b45;font-family:Arial,sans-serif}.wrap{width:min(1180px,calc(100% - 36px));margin:28px auto}.top{display:flex;justify-content:space-between;align-items:start;margin-bottom:22px}.top a{color:#4e73df;font-weight:700;text-decoration:none}.card{background:#fff;border:1px solid #e3e6f0;border-radius:6px;box-shadow:0 .15rem 1.75rem #3a3b4515}.head{padding:20px 22px;border-bottom:1px solid #e3e6f0}.head h1{margin:0 0 6px;font-size:27px}.head p{margin:0;color:#858796;font-size:13px}.filters{display:flex;gap:8px;flex-wrap:wrap;padding:16px 22px;border-bottom:1px solid #e3e6f0}.filters input,.filters select{padding:9px;border:1px solid #d1d3e2;border-radius:4px}.filters button{padding:9px 14px;color:#fff;background:#4e73df;border:0;border-radius:4px;font-weight:700}.table-wrap{overflow:auto}table{width:100%;min-width:760px;border-collapse:collapse;font-size:13px}th{padding:12px;color:#6e707e;background:#f8f9fc;text-align:left;font-size:10px;text-transform:uppercase}td{padding:12px;border-top:1px solid #eaecf4;vertical-align:top}.muted{color:#858796;font-size:11px}.badge{display:inline-block;padding:4px 7px;border-radius:10px;font-size:10px;font-weight:700}.success{color:#0f684c;background:#d7f8ec}.denied{color:#8c2f27;background:#fbdcd9}@media(max-width:620px){.top{display:block}.top a{display:inline-block;margin-top:14px}}</style></head><body><main class="wrap"><header class="top"><div><p class="muted">CLOUD RDX / SECURITY</p><h1>Audit activity</h1><p class="muted">Review administrative actions, file activity, and security events.</p></div><a href="{{ url_for('admin_manage') }}">→ BACK TO CONTROLS</a></header><section class="card"><form class="filters" method="get"><input name="action" value="{{ filters.action }}" placeholder="Action"><input name="actor" value="{{ filters.actor }}" placeholder="Actor"><select name="status"><option value="">All statuses</option><option value="success"{% if filters.status == 'success' %} selected{% endif %}>Success</option><option value="denied"{% if filters.status == 'denied' %} selected{% endif %}>Denied</option></select><button type="submit">Filter activity</button></form><div class="table-wrap"><table><thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Target</th><th>Details</th><th>Status</th></tr></thead><tbody>{% for event in events %}<tr><td class="muted">{{ event.created_at|prettydate }}</td><td><strong>{{ event.action }}</strong></td><td>{{ event.actor or 'System' }}</td><td>{{ event.target_type }} {{ event.target_id or '' }}</td><td class="muted">{{ event.details }}</td><td><span class="badge {{ 'success' if event.status == 'success' else 'denied' }}">{{ event.status|upper }}</span></td></tr>{% else %}<tr><td colspan="6">No matching activity.</td></tr>{% endfor %}</tbody></table></div></section></main></body></html>
"""


ADMIN_AUDIT_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Audit activity - Cloud Rdx</title>
<style>body{margin:0;background:#f8f9fc;color:#3a3b45;font-family:Arial,sans-serif}.wrap{width:min(1180px,calc(100% - 36px));margin:28px auto}.top{display:flex;justify-content:space-between;align-items:start;margin-bottom:22px}.top a{color:#4e73df;font-weight:700;text-decoration:none}.card{background:#fff;border:1px solid #e3e6f0;border-radius:6px;box-shadow:0 .15rem 1.75rem #3a3b4515}.filters{display:flex;gap:8px;flex-wrap:wrap;padding:16px 22px;border-bottom:1px solid #e3e6f0}.filters input,.filters select{padding:9px;border:1px solid #d1d3e2;border-radius:4px}.filters button{padding:9px 14px;color:#fff;background:#4e73df;border:0;border-radius:4px;font-weight:700}.user-group{margin:18px 22px;border:1px solid #e3e6f0;border-radius:6px;overflow:hidden}.user-heading{padding:12px 15px;color:#224abe;background:#f0f4ff;font-weight:700}.table-wrap{overflow:auto}table{width:100%;min-width:700px;border-collapse:collapse;font-size:13px}th{padding:12px;color:#6e707e;background:#f8f9fc;text-align:left;font-size:10px;text-transform:uppercase}td{padding:12px;border-top:1px solid #eaecf4;vertical-align:top}.muted{color:#858796;font-size:11px}.badge{display:inline-block;padding:4px 7px;border-radius:10px;font-size:10px;font-weight:700}.success{color:#0f684c;background:#d7f8ec}.denied{color:#8c2f27;background:#fbdcd9}@media(max-width:620px){.top{display:block}.top a{display:inline-block;margin-top:14px}.user-group{margin-left:12px;margin-right:12px}}</style></head><body><main class="wrap"><header class="top"><div><p class="muted">CLOUD RDX / SECURITY</p><h1>Audit activity by username</h1><p class="muted">Review security and storage actions grouped by the account that performed them.</p></div><a href="{{ url_for('admin_manage') }}">→ BACK TO CONTROLS</a></header><section class="card"><form class="filters" method="get"><input name="action" value="{{ filters.action }}" placeholder="Action"><input name="actor" value="{{ filters.actor }}" placeholder="Username"><select name="status"><option value="">All statuses</option><option value="success"{% if filters.status == 'success' %} selected{% endif %}>Success</option><option value="denied"{% if filters.status == 'denied' %} selected{% endif %}>Denied</option></select><button type="submit">Filter activity</button></form>{% for group in audit_groups %}<section class="user-group"><div class="user-heading">Username: {{ group.username }} · {{ group.events|length }} event{% if group.events|length != 1 %}s{% endif %}</div><div class="table-wrap"><table><thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Details</th><th>Status</th></tr></thead><tbody>{% for event in group.events %}<tr><td class="muted">{{ event.created_at|prettydate }}</td><td><strong>{{ event.action }}</strong></td><td>{{ event.target_type }} {{ event.target_id or '' }}</td><td class="muted">{{ event.details }}</td><td><span class="badge {{ 'success' if event.status == 'success' else 'denied' }}">{{ event.status|upper }}</span></td></tr>{% endfor %}</tbody></table></div></section>{% else %}<p style="padding:22px">No matching activity.</p>{% endfor %}</section></main></body></html>
"""


ADMIN_TRASH_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Recycle bin - Cloud Rdx</title></head><body class="admin-theme"><div class="shell"><aside class="rail"><a class="brand" href="{{ url_for('admin_panel') }}"><span class="brand-mark">C</span><span>Cloud Rdx</span></a><nav class="rail-nav"><a class="rail-link" href="{{ url_for('admin_panel') }}"><span class="rail-icon">#</span><span>Dashboard</span></a><a class="rail-link" href="{{ url_for('admin_manage') }}"><span class="rail-icon">+</span><span>Controls</span></a><a class="rail-link active" href="{{ url_for('admin_trash') }}"><span class="rail-icon">~</span><span>Recycle bin</span></a><a class="rail-link" href="{{ url_for('admin_audit') }}"><span class="rail-icon">≡</span><span>Audit activity</span></a><a class="rail-link" href="{{ url_for('cloud_storage_guide') }}"><span class="rail-icon">?</span><span>Storage guide</span></a><a class="rail-link" href="{{ url_for('logout') }}"><span class="rail-icon">&lt;</span><span>Sign out</span></a></nav><div class="rail-bottom">Administrator console<br>Recoverable deletion enabled</div></aside><main class="main"><header class="topbar"><div><p class="eyebrow">Cloud Rdx / recovery</p><h1>Recycle bin</h1><p class="subtitle">Deleted items remain recoverable until an administrator restores them.</p></div><div class="user-chip"><span class="avatar">{{ username[0]|upper }}</span><span>{{ username }} · admin</span></div></header>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}{% endwith %}<section class="panel"><div class="panel-head"><h2>Recoverable items</h2><p>Permanent purge is intentionally unavailable until a separate audited workflow is implemented.</p></div><div class="table-responsive"><table><thead><tr><th>User</th><th>Item</th><th>Type</th><th>Original path</th><th>Deleted at</th><th>Action</th></tr></thead><tbody>{% for item in items %}<tr><td><strong>{{ item.username }}</strong></td><td>{{ item.item_name }}</td><td><span class="badge badge-info">{{ 'Folder' if item.is_dir else 'File' }}</span></td><td>{{ item.original_path }}</td><td class="muted">{{ item.deleted_at|prettydate }}</td><td><form method="post" action="{{ url_for('admin_restore_trash', trash_id=item.id) }}"><button class="button" type="submit">Restore</button></form></td></tr>{% else %}<tr><td colspan="6" class="muted">Recycle bin is empty.</td></tr>{% endfor %}</tbody></table></div></section></main></div></body></html>
"""


USER_TRASH_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Recycle bin - RDx Cloud Storage</title><style>body{margin:0;background:#f2f6f8;color:#17212b;font-family:'Segoe UI',Arial,sans-serif}.wrap{width:min(980px,calc(100% - 28px));margin:28px auto}.top{display:flex;justify-content:space-between;gap:18px;align-items:start;margin-bottom:22px}.top a{color:#087f73;font-weight:700;text-decoration:none}.panel{overflow:hidden;background:#fff;border:1px solid #d8e1e8;border-radius:10px;box-shadow:0 12px 30px #19314214}.head{padding:20px 22px;border-bottom:1px solid #d8e1e8}.head h1{margin:0 0 7px}.head p,.muted{color:#647483;font-size:13px}.table-wrap{overflow:auto}table{width:100%;min-width:680px;border-collapse:collapse}th{padding:12px 16px;background:#f7fafc;color:#647483;text-align:left;font-size:11px;text-transform:uppercase}td{padding:13px 16px;border-top:1px solid #e8eef2}.actions{display:flex;gap:7px;flex-wrap:wrap}button{min-height:38px;padding:8px 11px;color:#fff;background:#087f73;border:0;border-radius:6px;cursor:pointer;font-weight:700}button.danger{background:#a34f3a}.notice{margin-bottom:16px;padding:12px 14px;color:#7a5311;background:#fff4d7;border:1px solid #f3db9d;border-radius:7px}@media(max-width:620px){.top{display:block}.top a{display:inline-block;margin-top:14px}.head{padding:17px}}
</style></head><body><main class="wrap"><header class="top"><div><p class="muted">RDx CLOUD STORAGE / RECOVERY</p><h1>Recycle bin</h1><p class="muted">Deleted files stay here until you restore or permanently delete them.</p></div><a href="{{ url_for('files') }}">→ BACK TO STORAGE</a></header>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="notice">{{ message }}</div>{% endfor %}{% endwith %}<section class="panel"><div class="head"><h1>Your deleted items</h1><p>Only your deleted files and folders are shown.</p></div><div class="table-wrap"><table><thead><tr><th>Item</th><th>Type</th><th>Original location</th><th>Deleted</th><th>Actions</th></tr></thead><tbody>{% for item in items %}<tr><td>{{ item.item_name }}</td><td>{{ 'Folder' if item.is_dir else 'File' }}</td><td>{{ item.original_path }}</td><td>{{ item.deleted_at[:19].replace('T',' ') }}</td><td><div class="actions"><form method="post" action="{{ url_for('restore_user_trash', trash_id=item.id) }}"><button type="submit">Restore</button></form><form method="post" action="{{ url_for('purge_user_trash', trash_id=item.id) }}" onsubmit="return confirm('Permanently delete this item?')"><button class="danger" type="submit">Delete forever</button></form></div></td></tr>{% else %}<tr><td colspan="5" class="muted">Your recycle bin is empty.</td></tr>{% endfor %}</tbody></table></div></section></main></body></html>
"""


USER_TRASH_PAGE = apply_user_page_theme(USER_TRASH_PAGE)


# Recycle bin shows all users' deleted items and supports restore or permanent deletion.
ADMIN_TRASH_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Recycle bin - Cloud Rdx</title><style>body{margin:0;background:#f8f9fc;color:#3a3b45;font-family:Arial,sans-serif}.wrap{width:min(1180px,calc(100% - 32px));margin:32px auto}.top{display:flex;justify-content:space-between;align-items:start;gap:18px;margin-bottom:24px}.top a{color:#4e73df;font-weight:700;text-decoration:none}.panel{overflow:hidden;background:#fff;border:1px solid #e3e6f0;border-radius:8px;box-shadow:0 .15rem 1.2rem #3a3b4512}.head{padding:20px 22px;border-bottom:1px solid #e3e6f0}.head h1{margin:0 0 7px;font-size:28px}.head p{margin:0;color:#858796;font-size:13px}.notice{margin-bottom:18px;padding:12px 15px;color:#856404;background:#fff3cd;border:1px solid #ffeeba;border-radius:5px}.table-wrap{overflow-x:auto}table{width:100%;min-width:850px;border-collapse:collapse;font-size:13px}th{padding:13px 18px;color:#6e707e;background:#f8f9fc;text-align:left;font-size:11px;text-transform:uppercase}td{padding:15px 18px;border-top:1px solid #eaecf4;vertical-align:middle}.muted{color:#858796;font-size:12px}.button{padding:8px 11px;color:#fff;background:#4e73df;border:1px solid #4e73df;border-radius:4px;cursor:pointer;font-weight:700}.danger{background:#e74a3b;border-color:#e74a3b}.actions{display:flex;gap:7px;flex-wrap:wrap}@media(max-width:700px){.top{display:block}.top a{display:inline-block;margin-top:14px}}</style></head><body><main class="wrap"><header class="top"><div><p class="muted">CLOUD RDX / RECOVERY</p><h1>Recycle bin</h1><p class="muted">Deleted files and folders from every user. Restore items or permanently delete them.</p></div><a href="{{ url_for('admin_panel') }}">→ ADMIN DASHBOARD</a></header>{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="notice">{{ message }}</div>{% endfor %}{% endwith %}<section class="panel"><div class="head"><h1>Deleted items by user</h1><p>Permanent deletion cannot be undone. Verify the user and path before acting.</p></div><div class="table-wrap"><table><thead><tr><th>User</th><th>Item</th><th>Type</th><th>Original path</th><th>Deleted at</th><th>Actions</th></tr></thead><tbody>{% for item in items %}<tr><td><strong>{{ item.username }}</strong><br><span class="muted">User ID {{ item.user_id }}</span></td><td>{{ item.item_name }}</td><td>{{ 'Folder' if item.is_dir else 'File' }}</td><td>{{ item.original_path }}</td><td>{{ item.deleted_at|prettydate }}</td><td><div class="actions"><form method="post" action="{{ url_for('admin_restore_trash', trash_id=item.id) }}"><button class="button" type="submit">Restore</button></form><form method="post" action="{{ url_for('admin_purge_trash', trash_id=item.id) }}" onsubmit="return confirm('Permanently delete this item? This cannot be undone.')"><button class="button danger" type="submit">Permanently delete</button></form></div></td></tr>{% else %}<tr><td colspan="6">No deleted items in the recycle bin.</td></tr>{% endfor %}</tbody></table></div></section></main></body></html>
"""


CLOUD_STORAGE_GUIDE_PAGE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cloud storage guide - Cloud Rdx</title>
<style>
:root{--ink:#17212b;--muted:#647483;--line:#d8e1e8;--paper:#f2f6f8;--panel:#fff;--green:#087f73;--dark:#122b3a;--gold:#f0b44d;--mint:#e5f5f2}*{box-sizing:border-box}body{margin:0;color:var(--ink);background:var(--paper);font-family:'Segoe UI',Arial,sans-serif;background-image:linear-gradient(#d8e1e844 1px,transparent 1px),linear-gradient(90deg,#d8e1e844 1px,transparent 1px);background-size:32px 32px}.wrap{width:min(1120px,calc(100% - 32px));margin:32px auto 60px}.top{display:flex;justify-content:space-between;gap:24px;align-items:start;margin-bottom:25px}.brand{display:flex;align-items:center;gap:10px;color:var(--dark);font:700 13px Consolas,monospace}.mark{display:grid;place-items:center;width:38px;height:38px;color:var(--dark);background:var(--gold);border-radius:7px;font:800 16px Consolas,monospace}.back{color:var(--green);font:700 12px Consolas,monospace;text-decoration:none}.eyebrow{margin:27px 0 9px;color:var(--green);text-transform:uppercase;letter-spacing:.15em;font:700 11px Consolas,monospace}h1{margin:0;font-size:clamp(32px,5vw,56px);letter-spacing:-.04em;line-height:1.02}.lead{max-width:780px;color:var(--muted);font-size:17px;line-height:1.6}.panel{margin-top:18px;padding:25px 28px;background:rgba(255,255,255,.96);border:1px solid var(--line);border-radius:10px;box-shadow:0 12px 30px #19314214}h2{margin:0 0 12px;font-size:24px}h3{margin:20px 0 7px;color:var(--green);font-size:17px}p,li{line-height:1.6}li{margin:5px 0}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}.card{padding:17px;background:#f8fbfc;border:1px solid var(--line);border-radius:8px}.card h3{margin-top:0}.note{padding:14px 16px;background:var(--mint);border-left:4px solid var(--green);border-radius:5px}.flow{display:grid;grid-template-columns:repeat(5,1fr);gap:9px}.step{padding:14px 12px;background:var(--dark);color:#fff;border-radius:7px;font-size:13px}.step b{display:block;color:var(--gold);margin-bottom:7px}.table-wrap{overflow-x:auto}table{width:100%;min-width:760px;border-collapse:collapse;font-size:13px}th,td{padding:12px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}th{color:#fff;background:var(--dark)}tr:nth-child(even){background:#f8fbfc}.small{color:var(--muted);font-size:13px}@media(max-width:720px){.top{display:block}.back{display:inline-block;margin-top:18px}.grid{grid-template-columns:1fr}.flow{grid-template-columns:1fr}}
</style>
</head>
<body><main class="wrap"><header class="top"><div><div class="brand"><span class="mark">C</span><span>Cloud Rdx / learning center</span></div><p class="eyebrow">Beginner guide</p><h1>Understanding cloud storage</h1><p class="lead">Cloud storage lets you keep files on internet-connected servers instead of only on one computer. You can access those files from a browser, phone, or desktop app, as long as you have permission and an internet connection.</p></div><a class="back" href="{{ back_url }}">→ BACK TO STORAGE</a></header>
<section class="panel"><h2>1. What is cloud storage?</h2><p>Think of cloud storage as a secure online filing cabinet. A provider stores your data in data centers, while an application shows you folders and files. “Cloud” does not mean the files float in the air: they are stored on physical computers managed by the provider.</p><p>Compared with saving only to a laptop, cloud storage makes access, sharing, synchronization, backup, and recovery easier. The provider normally handles servers, disks, availability, and some security controls.</p></section>
<section class="panel"><h2>2. Main actions</h2><div class="grid"><div class="card"><h3>Upload and download</h3><p><b>Upload</b> sends a file from your device to online storage. <b>Download</b> copies it back to your device for viewing or offline use.</p></div><div class="card"><h3>Create, rename, move, and copy</h3><p>Folders organize files. Rename gives an item a clearer name. Move changes its folder. Copy creates another independent copy.</p></div><div class="card"><h3>Delete and restore</h3><p>Delete usually moves an item to a recycle bin first. Restore brings it back. Permanent deletion may be restricted or delayed by a retention policy.</p></div><div class="card"><h3>Share and collaborate</h3><p>Sharing grants selected people access through an account or link. Collaboration lets several people comment or edit, depending on their permission.</p></div><div class="card"><h3>Sync across devices</h3><p>A desktop or mobile app watches a folder and keeps approved changes aligned between devices. Conflicts can happen if two devices edit the same file at once.</p></div><div class="card"><h3>Backup and restore data</h3><p>Backup keeps a separate copy so data can be recovered after accidental deletion, device failure, or an attack. Restore returns a backup copy to active storage.</p></div></div></section>
<section class="panel"><h2>3. Common cloud-storage functions</h2><ul><li><b>File management:</b> folders, names, uploads, downloads, moves, copies, and deletion.</li><li><b>Data synchronization:</b> changes are shared between web, desktop, and mobile clients.</li><li><b>Data backup:</b> scheduled or manual copies protect against loss.</li><li><b>Sharing and collaboration:</b> links, invitations, comments, editing, and team folders.</li><li><b>Access control:</b> owners choose who can view, comment, edit, or administer content.</li><li><b>Version history:</b> earlier versions can be inspected or restored after an unwanted edit.</li><li><b>Search and organization:</b> names, types, owners, dates, labels, and full-text search help find files.</li><li><b>Encryption and security:</b> encryption, sign-in protection, audit logs, malware checks, and recovery controls protect data.</li></ul></section>
<section class="panel"><h2>4. User experience (UX)</h2><div class="grid"><div class="card"><h3>Upload and access</h3><p>A user opens the web app or desktop folder, chooses <b>Upload</b>, selects a file, and sees progress. After completion, the file appears in the chosen folder and can be opened, downloaded, or shared from another device.</p></div><div class="card"><h3>Organize folders</h3><p>Users create folders by project, year, or team. Breadcrumbs show where they are. Good names such as <i>Invoices / 2026 / March</i> are easier to search than names such as <i>New folder (7)</i>.</p></div><div class="card"><h3>Sharing and permissions</h3><p>The owner chooses people or a link, then selects a level such as viewer, commenter, or editor. A viewer cannot change content; an editor can. Sensitive links should expire or be revoked when no longer needed.</p></div><div class="card"><h3>Recovery</h3><p>Deleted files normally appear in a trash area. Version history lets a user compare or restore an earlier version. Retention periods differ by service and plan, so users should not treat trash as a permanent backup.</p></div><div class="card"><h3>Web, desktop, and mobile</h3><p><b>Web:</b> works from a browser without installation. <b>Desktop:</b> shows synced files in the normal file explorer and may support offline work. <b>Mobile:</b> provides previews, camera uploads, sharing, and offline favorites.</p></div><div class="card"><h3>What makes good UX?</h3><p>Clear progress, understandable permission labels, search, breadcrumbs, undo, visible storage limits, conflict warnings, and plain-language error messages reduce mistakes.</p></div></div></section>
<section class="panel"><h2>5. Real-world examples</h2><ul><li><b>Google Drive:</b> people create Docs, Sheets, or folders, share them as viewers/commenters/editors, and use Drive for web, desktop, and mobile access.</li><li><b>Microsoft OneDrive:</b> integrates with Windows and Microsoft 365. A file can be edited in Word, synchronized, shared, and recovered through version history or the recycle bin.</li><li><b>Dropbox:</b> focuses on synchronized folders, link sharing, collaboration, and file recovery features.</li><li><b>Amazon S3:</b> is primarily a developer and infrastructure service. Applications store objects in buckets using APIs, IAM permissions, lifecycle rules, versioning, and storage classes. It is not normally a consumer folder interface by itself.</li></ul></section>
<section class="panel"><h2>6. User-facing functions vs backend infrastructure</h2><div class="grid"><div class="card"><h3>User-facing</h3><p>These are the visible actions: upload, download, folders, search, sharing, comments, permissions, trash, version restore, and sync status. They answer: <i>“What can I do?”</i></p></div><div class="card"><h3>Backend/cloud infrastructure</h3><p>These are the systems underneath: object storage, databases, identity services, encryption-key management, replication, data-center networking, monitoring, billing, lifecycle tiers, APIs, and disaster recovery. They answer: <i>“How does the service operate reliably?”</i></p></div></div><p class="note"><b>Example:</b> “Download report.pdf” is user-facing. Behind it, the service authenticates the user, checks an access policy, locates replicated data, decrypts it when authorized, logs the event, and streams bytes over HTTPS.</p></section>
<section class="panel"><h2>7. Simple upload-to-download workflow</h2><div class="flow"><div class="step"><b>1 · Upload</b>The user selects a file. The client sends bytes securely.</div><div class="step"><b>2 · Store</b>The service checks size and permission, saves the file, and records metadata.</div><div class="step"><b>3 · Share</b>The owner invites a person or creates a restricted link.</div><div class="step"><b>4 · Edit</b>The recipient edits if allowed. Sync and version history record the change.</div><div class="step"><b>5 · Download</b>A permitted user requests the file; the service checks access and streams it.</div></div></section>
<section class="panel"><h2>8. Security features and best practices</h2><div class="grid"><div class="card"><h3>Common features</h3><ul><li>Encryption in transit with HTTPS and encryption at rest.</li><li>Strong passwords, multi-factor authentication, and single sign-on.</li><li>Role-based permissions and least privilege.</li><li>Share-link expiration, passwords, download limits, and revocation.</li><li>Version history, recycle bins, backups, retention policies, and audit logs.</li><li>Alerts for unusual downloads, sign-ins, or sharing.</li></ul></div><div class="card"><h3>Good habits</h3><ul><li>Use a unique password and enable MFA.</li><li>Share with named people instead of “anyone with the link” when possible.</li><li>Give viewer access unless editing is necessary.</li><li>Review shared links and remove old collaborators.</li><li>Keep important files backed up in a separate location.</li><li>Do not upload secrets or regulated data without checking policy.</li><li>Verify the recipient before sending confidential files.</li></ul></div></div></section>
<section class="panel"><h2>9. Quick reference table</h2><div class="table-wrap"><table><thead><tr><th>Action</th><th>Function</th><th>User experience</th><th>Example</th></tr></thead><tbody><tr><td>Upload</td><td>Send local data to storage</td><td>Choose a file and watch progress</td><td>Upload a travel receipt to Drive</td></tr><tr><td>Download</td><td>Copy stored data to a device</td><td>Click Download or mark offline</td><td>Download a report from OneDrive</td></tr><tr><td>Folder</td><td>Organize related files</td><td>Create a folder and use breadcrumbs</td><td>Dropbox / Projects / Website</td></tr><tr><td>Share</td><td>Grant controlled access</td><td>Invite a person and choose viewer/editor</td><td>Share a presentation for comments</td></tr><tr><td>Sync</td><td>Keep approved copies aligned</td><td>Edit on laptop and see the update on mobile</td><td>OneDrive Windows folder</td></tr><tr><td>Version/restore</td><td>Recover an earlier or deleted copy</td><td>Open history or recycle bin and restore</td><td>Recover yesterday’s spreadsheet</td></tr><tr><td>Backup</td><td>Keep a separate recovery copy</td><td>Run a schedule or snapshot</td><td>Archive application data to Amazon S3</td></tr></tbody></table></div></section>
<p class="small">Cloud storage behavior varies by provider, account plan, administrator policy, file type, and region. Always check the service’s current retention, sharing, and recovery rules.</p></main></body></html>
"""
ADMIN_PAGE = ADMIN_PAGE.replace(
    "Manage accounts without opening their private files.",
    "Manage accounts and inspect user files in read-only mode.",
).replace(
    "Only inactive non-admin accounts can be removed.",
    "Any account except the active administrator can be removed.",
).replace(
    "{% if not item.is_admin %}",
    "{% if item.id != current_user_id %}",
).replace(
    "{% if item.inactive %}<form method=\"post\" action=\"{{ url_for('admin_delete_user', user_id=item.id) }}\" onsubmit=\"return confirm('Remove this inactive user and all their files?')\"><button class=\"button danger\" type=\"submit\">Remove user</button></form>{% endif %}",
    "<form method=\"post\" action=\"{{ url_for('admin_delete_user', user_id=item.id) }}\" onsubmit=\"return confirm('Remove this user and all their files?')\"><button class=\"button danger\" type=\"submit\">Remove user</button></form>",
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<a class="rail-link active" href="{{ url_for(\'admin_panel\') }}"><span class="rail-icon">#</span><span>{{ admin_title }}</span></a>',
    '<a class="rail-link active" href="{{ url_for(\'admin_panel\') }}"><span class="rail-icon">#</span><span>{{ admin_title }}</span></a>{% if is_owner %}<a class="rail-link" href="{{ url_for(\'admin_intelligence\') }}"><span class="rail-icon">◌</span><span>Cloud Intelligence</span></a><a class="rail-link" href="{{ url_for(\'admin_profit\') }}"><span class="rail-icon">₹</span><span>Profit and usage</span></a>{% endif %}',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<a class="rail-link active" href="{{ url_for(\'admin_panel\') }}"><span class="rail-icon">#</span><span>Admin panel</span></a>',
    '<a class="rail-link active" href="{{ url_for(\'admin_panel\') }}"><span class="rail-icon">#</span><span>Admin panel</span></a>{% if is_owner %}<a class="rail-link" href="{{ url_for(\'admin_intelligence\') }}"><span class="rail-icon">◌</span><span>Cloud Intelligence</span></a><a class="rail-link" href="{{ url_for(\'admin_profit\') }}"><span class="rail-icon">₹</span><span>Profit and usage</span></a>{% endif %}<a class="rail-link" href="{{ url_for(\'admin_manage\') }}"><span class="rail-icon">+</span><span>Controls</span></a><a class="rail-link" href="{{ url_for(\'admin_permissions\') }}"><span class="rail-icon">*</span><span>Access control</span></a><a class="rail-link" href="{{ url_for(\'admin_storage\') }}"><span class="rail-icon">%</span><span>Storage quotas</span></a><a class="rail-link" href="{{ url_for(\'admin_payments\') }}"><span class="rail-icon">$</span><span>Payment verification</span></a><a class="rail-link" href="{{ url_for(\'admin_audit\') }}"><span class="rail-icon">≡</span><span>Audit activity</span></a><a class="rail-link" href="{{ url_for(\'admin_settings\') }}"><span class="rail-icon">⚙</span><span>Website settings</span></a><a class="rail-link" href="{{ url_for(\'admin_trash\') }}"><span class="rail-icon">~</span><span>Recycle bin</span></a><a class="rail-link" href="{{ url_for(\'cloud_storage_guide\') }}"><span class="rail-icon">?</span><span>Storage guide</span></a>',
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    "</style>",
    ".config-section{margin-top:24px}.config-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;padding:20px 23px}.config-card{display:flex;flex-direction:column;gap:9px;padding:18px;background:#f8fbf8;border:1px solid var(--line);border-left:4px solid var(--green);border-radius:10px}.config-card h3{margin:0;color:var(--ink);font:700 16px Arial,sans-serif}.config-card p{margin:0;color:var(--muted);font:13px/1.5 Arial,sans-serif}.config-card .help{display:inline-grid;place-items:center;width:19px;height:19px;margin-left:5px;color:#fff;background:var(--green);border-radius:50%;font:700 12px Arial;cursor:help}.config-card a{align-self:flex-start;margin-top:auto;padding:9px 12px;color:#fff;background:var(--green);border-radius:6px;font:700 11px Arial,sans-serif;text-decoration:none}.config-card a:hover{background:var(--dark)}@media(max-width:700px){.config-grid{grid-template-columns:1fr;padding:16px}.config-card a{min-height:40px;display:inline-flex;align-items:center}} </style>",
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<section class="panel" style="margin-top:24px"><div class="panel-head"><h2>Password recovery requests</h2>',
    '''<section class="panel config-section"><div class="panel-head"><h2>Administration configuration</h2><p>Each area is separated so changes are easier to understand, review, and audit. Hover or focus the <b title="Help">?</b> icon for guidance.</p></div><div class="config-grid"><article class="config-card"><h3>User accounts <span class="help" title="Activate, suspend, remove users, change passwords, and review account profiles.">?</span></h3><p>Manage account status, credentials, profiles, groups, and delegated roles.</p><a href="{{ url_for('admin_manage') }}">Open user management →</a></article><article class="config-card"><h3>Access control <span class="help" title="Choose which permissions each delegated role receives.">?</span></h3><p>Configure role permissions for user, storage, recovery, payment, and audit administration.</p><a href="{{ url_for('admin_permissions') }}">Configure permissions →</a></article><article class="config-card"><h3>Storage quotas <span class="help" title="Set storage limits in megabytes. Zero means unlimited.">?</span></h3><p>Review usage and customize each user’s allocated storage quota.</p><a href="{{ url_for('admin_storage') }}">Manage quotas →</a></article><article class="config-card"><h3>Payments and plans <span class="help" title="Approve or reject payment references before allocating storage.">?</span></h3><p>Review payment requests and apply storage-plan allocations.</p><a href="{{ url_for('admin_payments') }}">Review payments →</a></article><article class="config-card"><h3>Audit activity <span class="help" title="Audit records are read-only evidence of security and administration actions.">?</span></h3><p>Filter and review actions performed by administrators and users.</p><a href="{{ url_for('admin_audit') }}">View audit activity →</a></article><article class="config-card"><h3>Recycle bin <span class="help" title="Restore deleted items or permanently purge them after checking the original path.">?</span></h3><p>Recover or permanently remove deleted user files and folders.</p><a href="{{ url_for('admin_trash') }}">Open recycle bin →</a></article></div></section><section class="panel" style="margin-top:24px"><div class="panel-head"><h2>Password recovery requests</h2>''',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    "</section></main>",
    """{% if can_view_recovery %}<section class=\"panel\" style=\"margin-top:24px\"><div class=\"panel-head\"><h2>Password recovery requests</h2><p>Compare the request details with the registered account record before resetting.</p></div>{% for item in recovery_requests %}<div class=\"user-row\"><div class=\"user-name\">{{ item.username }}<small>{{ item.email }} · registered {{ item.account_email }}</small></div><div class=\"status\">{{ item.created_at|prettydate }}</div><div style=\"font:12px Arial;color:var(--muted)\">Request DOB: {{ item.date_of_birth }}<br>Account DOB: {{ item.account_dob }}<br>Request mobile: {{ item.mobile }}<br>Account mobile: {{ item.account_mobile }}</div><div class=\"user-form\"><form method=\"post\" action=\"{{ url_for('admin_reset_password', request_id=item.id) }}\"><button class=\"button\" type=\"submit\" onclick=\"return confirm('I verified the DOB and mobile number. Reset to the default password?')\">Verify & reset</button></form></div></div>{% else %}<div class=\"empty\">No pending recovery requests.</div>{% endfor %}</section>{% endif %}</main>""",
)
ADMIN_CONFIG_HUB = '''<section class="panel config-section"><div class="panel-head"><h2>Administration configuration</h2><p>Each area is separated so changes are easier to understand, review, and audit. Hover or focus a <b title="Help">?</b> icon for guidance.</p></div><div class="config-grid"><article class="config-card"><h3>User accounts <span class="help" title="Activate, suspend, remove users, change passwords, and review profiles.">?</span></h3><p>Manage account status, credentials, profiles, groups, and delegated roles.</p><a href="{{ url_for('admin_manage') }}">Open user management →</a></article><article class="config-card"><h3>Access control <span class="help" title="Choose permissions for delegated administrator roles.">?</span></h3><p>Configure role permissions for user, storage, recovery, payment, and audit administration.</p><a href="{{ url_for('admin_permissions') }}">Configure permissions →</a></article><article class="config-card"><h3>Storage quotas <span class="help" title="Set limits in megabytes. Zero means unlimited.">?</span></h3><p>Review usage and customize each user’s allocated storage quota.</p><a href="{{ url_for('admin_storage') }}">Manage quotas →</a></article><article class="config-card"><h3>Payments and plans <span class="help" title="Approve or reject payment references before allocating storage.">?</span></h3><p>Review payment requests and apply storage-plan allocations.</p><a href="{{ url_for('admin_payments') }}">Review payments →</a></article><article class="config-card"><h3>Audit activity <span class="help" title="Audit records are read-only evidence of administration activity.">?</span></h3><p>Filter and review actions performed by administrators and users.</p><a href="{{ url_for('admin_audit') }}">View audit activity →</a></article><article class="config-card"><h3>Recycle bin <span class="help" title="Restore deleted items or permanently purge them after checking the path.">?</span></h3><p>Recover or permanently remove deleted user files and folders.</p><a href="{{ url_for('admin_trash') }}">Open recycle bin →</a></article></div></section>'''
ADMIN_CONFIG_HUB = ADMIN_CONFIG_HUB.replace(
    '<article class="config-card"><h3>User accounts',
    '{% if can_manage_users %}<article class="config-card"><h3>User accounts',
).replace(
    '</a></article><article class="config-card"><h3>Access control',
    '</a></article>{% endif %}<article class="config-card"><h3>Access control',
).replace(
    '<article class="config-card"><h3>Access control',
    '{% if is_owner %}<article class="config-card"><h3>Access control',
).replace(
    '</a></article><article class="config-card"><h3>Storage quotas',
    '</a></article>{% endif %}<article class="config-card"><h3>Storage quotas',
).replace(
    '<article class="config-card"><h3>Storage quotas',
    '{% if can_manage_storage %}<article class="config-card"><h3>Storage quotas',
).replace(
    '</a></article><article class="config-card"><h3>Payments and plans',
    '</a></article>{% endif %}<article class="config-card"><h3>Payments and plans',
).replace(
    '<article class="config-card"><h3>Payments and plans',
    '{% if can_review_payments %}<article class="config-card"><h3>Payments and plans',
).replace(
    '</a></article><article class="config-card"><h3>Audit activity',
    '</a></article>{% endif %}<article class="config-card"><h3>Audit activity',
).replace(
    '<article class="config-card"><h3>Audit activity',
    '{% if can_view_audit %}<article class="config-card"><h3>Audit activity',
).replace(
    '</a></article><article class="config-card"><h3>Recycle bin',
    '</a></article>{% endif %}<article class="config-card"><h3>Recycle bin',
).replace(
    '<article class="config-card"><h3>Recycle bin',
    '{% if can_manage_storage %}<article class="config-card"><h3>Recycle bin',
).replace(
    '</a></article></div></section>',
    '</a></article>{% endif %}</div></section>',
)
ADMIN_CONFIG_HUB = ADMIN_CONFIG_HUB.replace(
    '</div></section>',
    '''{% if is_owner %}<article class="config-card"><h3>Website and security settings</h3><p>Control Google sign-in, new account registration, login lockout thresholds, and retention.</p><a href="{{ url_for('admin_settings') }}">Manage site settings →</a></article><article class="config-card"><h3>Security center</h3><p>Review open security alerts and aggregate rate-limit events without exposing client identifiers.</p><a href="{{ url_for('admin_security') }}">Review security activity →</a></article>{% endif %}</div></section>''',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<section class="panel" style="margin-top:24px"><div class="panel-head"><h2>Password recovery requests</h2>',
    ADMIN_CONFIG_HUB + '<section class="panel" style="margin-top:24px"><div class="panel-head"><h2>Password recovery requests</h2>',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<section class="panel"><div class="panel-head"><h2>Accounts</h2>',
    '{% if can_manage_users %}<section class="panel"><div class="panel-head"><h2>Accounts</h2>',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(ADMIN_CONFIG_HUB, '{% endif %}' + ADMIN_CONFIG_HUB, 1)
ADMIN_PAGE = ADMIN_PAGE.replace(
    "</style>",
    """.account-filter{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:16px 23px;border-bottom:1px solid var(--line);font:13px Arial}.account-filter select{padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:#fff;color:var(--ink)}.provider-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:0 0 18px}.provider-stat{padding:16px;border:1px solid var(--line);border-radius:12px;background:#fff;box-shadow:var(--shadow);font:13px Arial}.provider-stat strong{display:block;margin-top:7px;color:var(--green);font-size:22px}.user-row{grid-template-columns:minmax(120px,1fr) minmax(210px,1.3fr) 130px 145px minmax(230px,1fr)}.account-meta{display:flex;gap:10px;align-items:center;min-width:0;font:12px/1.5 Arial;color:var(--muted)}.account-meta img{width:38px;height:38px;flex:0 0 38px;border-radius:50%;object-fit:cover}.account-meta small{display:block;overflow-wrap:anywhere}.account-meta strong{color:var(--ink);font-size:12px}@media(max-width:900px){.provider-summary{grid-template-columns:repeat(2,minmax(0,1fr))}.user-row{grid-template-columns:repeat(2,minmax(0,1fr))}.account-meta,.user-form{grid-column:1/-1}}@media(max-width:620px){.user-row{grid-template-columns:1fr}.account-meta,.user-form{grid-column:auto}}@media(max-width:520px){.provider-summary{grid-template-columns:1fr}}</style>""",
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<section class="panel"><div class="panel-head"><h2>Accounts</h2>',
    """<section class="provider-summary" aria-label="Sign-in method report"><article class="provider-stat">Password sign-in<strong>{{ provider_counts.password }}</strong></article><article class="provider-stat">Google accounts<strong>{{ provider_counts.google }}</strong></article><article class="provider-stat">GitHub accounts<strong>{{ provider_counts.github }}</strong></article><article class="provider-stat">All accounts<strong>{{ provider_counts.all }}</strong></article></section><section class="panel"><div class="account-filter"><label for="account-type">Filter accounts by sign-in</label><select id="account-type" name="account_type" form="account-filter-form"><option value="all"{% if account_type == 'all' %} selected{% endif %}>All sign-in types</option><option value="password"{% if account_type == 'password' %} selected{% endif %}>Password</option><option value="google"{% if account_type == 'google' %} selected{% endif %}>Google</option><option value="github"{% if account_type == 'github' %} selected{% endif %}>GitHub</option></select><form id="account-filter-form" method="get"><button class="button" type="submit">Apply filter</button></form><a class="button" href="{{ url_for('admin_user_report', account_type=account_type) }}">Download CSV report</a></div><div class="panel-head"><h2>Accounts</h2>""",
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '</div><div class="status{% if item.inactive %} stale{% endif %}">',
    '''</div><div class="account-meta">{% if item.picture_url %}<img src="{{ item.picture_url }}" alt="" loading="lazy" referrerpolicy="no-referrer">{% endif %}<div><strong>{{ item.email or 'No email' }}</strong><small>Sign-in: {{ item.auth_methods|join(' + ') }}</small>{% if item.google_sub %}<small>Google · {{ item.google_username or item.google_profile_name or 'Account' }} · {{ item.google_email }}</small>{% endif %}{% if item.github_sub %}<small>GitHub · {{ item.github_username or item.github_profile_name or 'Account' }} · {{ item.github_email }}</small>{% endif %}</div></div><div class="status{% if item.inactive %} stale{% endif %}">''',
    1,
)
ADMIN_PAGE = ADMIN_PAGE.replace(
    '<form id="account-filter-form" method="get">',
    '<form id="account-filter-form" action="{{ url_for(\'admin_panel\') }}" method="get">',
    1,
)


ADMIN_ACCOUNT_FILTERS = {
    "all": "",
    "password": "WHERE password_login_enabled = 1",
    "google": "WHERE google_sub IS NOT NULL",
    "github": "WHERE github_sub IS NOT NULL",
}


def spreadsheet_safe_cell(value):
    text = "" if value is None else str(value)
    if text.lstrip(" \t\r\n")[:1] in ("=", "+", "-", "@"):
        return "'" + text
    return text


def admin_console_context():
    user = current_user()
    owner = bool(user and user["username"].lower() == ADMIN_USERNAME.lower())
    permissions = set()
    role_names = []
    if not owner and user:
        with database_connection() as connection:
            rows = connection.execute("""
                SELECT roles.name, roles.description, role_permissions.permission
                FROM user_roles
                JOIN roles ON roles.id = user_roles.role_id
                LEFT JOIN role_permissions ON role_permissions.role_id = roles.id
                WHERE user_roles.user_id = ? AND roles.name != ?
            """, (user["id"], ADMIN_ROLE)).fetchall()
        role_names = sorted({row["name"] for row in rows})
        permissions = {row["permission"] for row in rows if row["permission"]}
    if owner:
        role_label = "Owner administrator"
        title = "Owner administration"
        description = "Full system administration. Permission governance is owner-only."
    elif role_names:
        role_label = ", ".join(name.replace("_", " ").title() for name in role_names)
        title = f"{role_label} console"
        description = "This console contains only the functions granted to your delegated role."
    else:
        role_label = "Restricted administrator"
        title = "Restricted administration"
        description = "No delegated administration permissions are assigned to this account."
    return {
        "admin_title": title,
        "admin_role_label": role_label,
        "admin_description": description,
        "is_owner": owner,
        "has_admin_access": owner or bool(permissions),
        "can_manage_users": owner or "users.manage" in permissions,
        "can_manage_storage": owner or "storage.manage" in permissions,
        "can_review_payments": owner or "payments.review" in permissions,
        "can_view_audit": owner or "audit.view" in permissions,
        "can_view_recovery": owner or "users.recovery" in permissions,
    }


def format_size(value):
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


def generate_recovery_password():
    return "".join(secrets.SystemRandom().sample(RECOVERY_PASSWORD_CHARS, len(RECOVERY_PASSWORD_CHARS)))


def hash_password(password):
    """Create a salted, one-way Argon2id password hash."""
    return PASSWORD_HASHER.hash(password)


def verify_password(password_hash, password):
    """Verify Argon2id hashes and support one-time migration of old hashes."""
    try:
        PASSWORD_HASHER.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False
    except (InvalidHashError, VerificationError):
        # Existing installations may contain Werkzeug hashes. They are still
        # verified safely, then replaced with Argon2id after a successful login.
        return check_password_hash(password_hash, password)


def password_hash_needs_upgrade(password_hash):
    return not password_hash.startswith("$argon2")


app.jinja_env.filters["filesize"] = format_size


@app.template_filter("dateonly")
def date_only(value):
    return value[:10] if value else "Unknown"


@app.template_filter("prettydate")
def pretty_date(value):
    if not value:
        return "Never signed in"
    try:
        return datetime.fromisoformat(value).astimezone().strftime("Last seen %d %b %Y, %H:%M")
    except ValueError:
        return "Unknown activity"


def database_connection():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    with database_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_seen TEXT,
                is_admin INTEGER NOT NULL DEFAULT 0,
                full_name TEXT,
                email TEXT,
                mobile TEXT,
                date_of_birth TEXT,
                last_login_at TEXT,
                password_login_enabled INTEGER NOT NULL DEFAULT 1
            )
        """)
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
        if "last_seen" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN last_seen TEXT")
        if "is_admin" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        if "status" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active'")
        if "suspended_at" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN suspended_at TEXT")
        for column in (
            "full_name", "email", "mobile", "date_of_birth", "google_sub",
            "google_email", "google_profile_name", "google_username",
            "google_picture", "github_email", "github_username", "github_picture",
            "github_profile_name", "gender", "location",
        ):
            if column not in columns:
                connection.execute(f"ALTER TABLE users ADD COLUMN {column} TEXT")
        if "password_login_enabled" not in columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN password_login_enabled "
                "INTEGER NOT NULL DEFAULT 1"
            )
        if "last_login_at" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN last_login_at TEXT")
        if "github_sub" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN github_sub TEXT")
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub "
            "ON users(google_sub) WHERE google_sub IS NOT NULL"
        )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_github_sub "
            "ON users(github_sub) WHERE github_sub IS NOT NULL"
        )
        for column, definition in (("totp_secret", "TEXT"), ("totp_enabled", "INTEGER NOT NULL DEFAULT 0"), ("must_change_password", "INTEGER NOT NULL DEFAULT 0")):
            if column not in columns:
                connection.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS device_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token_hash TEXT NOT NULL UNIQUE,
                device_label TEXT NOT NULL DEFAULT 'Unknown device',
                ip_address TEXT,
                user_agent TEXT,
                created_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                revoked_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_device_sessions_user ON device_sessions(user_id, revoked_at)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS trusted_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_token_hash TEXT NOT NULL,
                device_label TEXT NOT NULL DEFAULT 'Unknown device',
                ip_address TEXT,
                user_agent TEXT,
                status TEXT NOT NULL CHECK(status IN ('pending', 'trusted', 'rejected')),
                created_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                approved_at TEXT,
                approved_by INTEGER,
                UNIQUE(user_id, device_token_hash),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (approved_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_trusted_devices_status "
            "ON trusted_devices(status, created_at DESC)"
        )
        connection.execute("""
            CREATE TABLE IF NOT EXISTS share_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                relative_path TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                last_accessed_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_share_links_user "
            "ON share_links(user_id, created_at DESC)"
        )
        connection.execute("""
            CREATE TABLE IF NOT EXISTS quarantined_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL UNIQUE,
                sha256 TEXT NOT NULL,
                detection TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'quarantined'
                    CHECK(status IN ('quarantined', 'released')),
                created_at TEXT NOT NULL,
                reviewed_at TEXT,
                reviewed_by INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_quarantined_files_status "
            "ON quarantined_files(status, created_at DESC)"
        )
        connection.execute("""
            CREATE TABLE IF NOT EXISTS sync_jobs (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                enabled INTEGER NOT NULL DEFAULT 0,
                interval_minutes INTEGER NOT NULL DEFAULT 60,
                next_run_at TEXT NOT NULL,
                last_run_at TEXT,
                updated_at TEXT NOT NULL,
                updated_by INTEGER,
                FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS sync_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                uploaded_count INTEGER NOT NULL DEFAULT 0,
                unchanged_count INTEGER NOT NULL DEFAULT 0,
                unstable_count INTEGER NOT NULL DEFAULT 0,
                summary TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (job_id) REFERENCES sync_jobs(id) ON DELETE CASCADE
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_sync_runs_started "
            "ON sync_runs(started_at DESC)"
        )
        connection.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip_address TEXT,
                attempted_at TEXT NOT NULL,
                success INTEGER NOT NULL DEFAULT 0
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_lookup ON login_attempts(username, ip_address, attempted_at)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS rate_limit_buckets (
                bucket_key TEXT PRIMARY KEY,
                endpoint TEXT NOT NULL,
                scope TEXT NOT NULL,
                window_started_at INTEGER NOT NULL,
                request_count INTEGER NOT NULL,
                blocked_count INTEGER NOT NULL DEFAULT 0
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_recent ON rate_limit_buckets(window_started_at, blocked_count)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                severity TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                username TEXT,
                ip_address TEXT,
                details TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                reviewed_by INTEGER,
                reviewed_at TEXT,
                FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_security_alerts_status ON security_alerts(status, created_at DESC)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS password_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                mobile TEXT NOT NULL,
                date_of_birth TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                reviewed_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT ''
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS user_roles (
                user_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                assigned_at TEXT NOT NULL,
                assigned_by INTEGER,
                PRIMARY KEY (user_id, role_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS role_permissions (
                role_id INTEGER NOT NULL,
                permission TEXT NOT NULL,
                assigned_at TEXT NOT NULL,
                assigned_by INTEGER,
                PRIMARY KEY (role_id, permission),
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                assigned_at TEXT NOT NULL,
                assigned_by INTEGER,
                PRIMARY KEY (group_id, user_id),
                FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS quotas (
                user_id INTEGER PRIMARY KEY,
                quota_bytes INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS storage_permissions (
                user_id INTEGER PRIMARY KEY,
                allow_upload INTEGER NOT NULL DEFAULT 1,
                allow_download INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT NOT NULL,
                updated_by INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            INSERT OR IGNORE INTO storage_permissions (user_id, allow_upload, allow_download, updated_at)
            SELECT id, 1, 1, ?
            FROM users
        """, (datetime.now(timezone.utc).isoformat(),))
        connection.execute("""
            CREATE TABLE IF NOT EXISTS storage_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                quota_bytes INTEGER NOT NULL,
                price_paise INTEGER NOT NULL DEFAULT 0,
                currency TEXT NOT NULL DEFAULT 'INR',
                billing_period TEXT NOT NULL DEFAULT 'monthly',
                provider_plan_id TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plan_id INTEGER NOT NULL,
                provider TEXT NOT NULL DEFAULT 'manual',
                provider_subscription_id TEXT UNIQUE,
                status TEXT NOT NULL DEFAULT 'pending',
                quota_bytes INTEGER NOT NULL,
                current_period_end TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (plan_id) REFERENCES storage_plans(id)
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS payment_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plan_id INTEGER NOT NULL,
                provider TEXT NOT NULL DEFAULT 'manual_qr',
                transaction_reference TEXT NOT NULL UNIQUE,
                amount_paise INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                proof_path TEXT,
                reviewed_by INTEGER,
                reviewed_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (plan_id) REFERENCES storage_plans(id),
                FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("CREATE INDEX IF NOT EXISTS idx_payment_requests_status ON payment_requests(status, created_at)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON subscriptions(user_id, status)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS webhook_events (
                event_id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                processed_at TEXT NOT NULL
            )
        """)
        now = datetime.now(timezone.utc).isoformat()
        plans = (
            ("free", "Free Plan", 5 * 1024**3, 0),
            ("100gb", "100 GB Plan", 100 * 1024**3, 9900),
            ("500gb", "500 GB Plan", 500 * 1024**3, 19900),
            ("1tb", "1 TB Plan", 1024 * 1024**3, 39900),
        )
        for code, name, quota_bytes, price_paise in plans:
            connection.execute("""
                INSERT OR IGNORE INTO storage_plans
                (code, name, quota_bytes, price_paise, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (code, name, quota_bytes, price_paise, now, now))
        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT,
                details TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'success',
                created_at TEXT NOT NULL,
                FOREIGN KEY (actor_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        audit_columns = {row["name"] for row in connection.execute("PRAGMA table_info(audit_events)")}
        for column, definition in (("ip_address", "TEXT"), ("risk_level", "TEXT NOT NULL DEFAULT 'LOW'"), ("session_id", "TEXT")):
            if column not in audit_columns:
                connection.execute(f"ALTER TABLE audit_events ADD COLUMN {column} {definition}")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events(created_at DESC)")
        connection.execute("""
            CREATE TABLE IF NOT EXISTS trash_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                original_path TEXT NOT NULL,
                trash_path TEXT NOT NULL UNIQUE,
                item_name TEXT NOT NULL,
                is_dir INTEGER NOT NULL DEFAULT 0,
                deleted_by INTEGER,
                deleted_at TEXT NOT NULL,
                restored_at TEXT,
                purged_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (deleted_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS policy_acceptances (
                user_id INTEGER PRIMARY KEY,
                terms_accepted INTEGER NOT NULL DEFAULT 0,
                privacy_accepted INTEGER NOT NULL DEFAULT 0,
                cookies_accepted INTEGER NOT NULL DEFAULT 0,
                disclaimer_accepted INTEGER NOT NULL DEFAULT 0,
                accepted_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS policies (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by INTEGER,
                FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS emergency_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                affected_services TEXT NOT NULL DEFAULT '[]',
                previous_state TEXT NOT NULL,
                emergency_state TEXT NOT NULL,
                recovery_state TEXT,
                started_at TEXT NOT NULL,
                resolved_at TEXT,
                created_by INTEGER,
                resolved_by INTEGER,
                status TEXT NOT NULL DEFAULT 'active',
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (resolved_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS emergency_incident_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER NOT NULL,
                admin_id INTEGER,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE CASCADE,
                FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS emergency_account_freezes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                group_id INTEGER,
                previous_status TEXT NOT NULL,
                freeze_batch_id TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                frozen_at TEXT NOT NULL,
                frozen_by INTEGER,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE SET NULL,
                FOREIGN KEY (frozen_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_emergency_account_freezes_batch "
            "ON emergency_account_freezes(freeze_batch_id)"
        )
        connection.execute("""
            CREATE TABLE IF NOT EXISTS emergency_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER,
                incident_id INTEGER,
                ip_address TEXT,
                action TEXT NOT NULL,
                previous_state TEXT NOT NULL DEFAULT '{}',
                new_state TEXT NOT NULL DEFAULT '{}',
                reason TEXT NOT NULL DEFAULT '',
                affected_users INTEGER NOT NULL DEFAULT 0,
                affected_user_ids TEXT NOT NULL DEFAULT '[]',
                affected_services TEXT NOT NULL DEFAULT '[]',
                result TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (incident_id) REFERENCES emergency_incidents(id) ON DELETE SET NULL
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_emergency_events_created "
            "ON emergency_events(created_at DESC)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_emergency_incidents_status "
            "ON emergency_incidents(status, started_at DESC)"
        )
        emergency_event_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(emergency_events)")
        }
        if "affected_user_ids" not in emergency_event_columns:
            connection.execute(
                "ALTER TABLE emergency_events ADD COLUMN affected_user_ids TEXT NOT NULL DEFAULT '[]'"
            )
        role_descriptions = {
            "system_admin": "Full administration with protected account safeguards.",
            "user_admin": "Manage user accounts and recovery requests.",
            "storage_admin": "Manage quotas and storage operations.",
            "auditor": "Read-only access to reports and audit events.",
        }
        for role_name, description in role_descriptions.items():
            connection.execute("INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)", (role_name, description))
        permission_defaults = {
            "user_admin": ("users.view", "users.manage", "users.recovery"),
            "storage_admin": ("storage.manage", "storage.recycle_bin", "payments.review"),
            "auditor": ("audit.view",),
        }
        for role_name, permissions in permission_defaults.items():
            role = connection.execute("SELECT id FROM roles WHERE name = ?", (role_name,)).fetchone()
            for permission in permissions:
                connection.execute("INSERT OR IGNORE INTO role_permissions (role_id, permission, assigned_at) VALUES (?, ?, ?)", (role["id"], permission, datetime.now(timezone.utc).isoformat()))
        connection.execute("UPDATE users SET is_admin = 0 WHERE username != ? COLLATE NOCASE", (ADMIN_USERNAME,))
        admin = connection.execute("SELECT id FROM users WHERE username = ? COLLATE NOCASE", (ADMIN_USERNAME,)).fetchone()
        if not admin:
            initial_password = ADMIN_PASSWORD or secrets.token_urlsafe(18)
            connection.execute("INSERT INTO users (username, password_hash, created_at, last_seen, is_admin, full_name, email, status) VALUES (?, ?, ?, ?, 1, ?, ?, 'active')", (ADMIN_USERNAME, hash_password(initial_password), datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat(), "Cloud Rdx Administrator", ""))
            print(f"Initial administrator password: {initial_password}")
        else:
            connection.execute("UPDATE users SET is_admin = 1, status = 'active' WHERE id = ?", (admin["id"],))
        admin = connection.execute("SELECT id FROM users WHERE username = ? COLLATE NOCASE", (ADMIN_USERNAME,)).fetchone()
        system_role = connection.execute("SELECT id FROM roles WHERE name = ?", (ADMIN_ROLE,)).fetchone()
        connection.execute("INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_at) VALUES (?, ?, ?)", (admin["id"], system_role["id"], datetime.now(timezone.utc).isoformat()))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('allow_registration', '1', ?)", (datetime.now(timezone.utc).isoformat(),))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('allow_public_sharing', '0', ?)", (datetime.now(timezone.utc).isoformat(),))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('trash_retention_days', '30', ?)", (datetime.now(timezone.utc).isoformat(),))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('allow_google_signin', '1', ?)", (datetime.now(timezone.utc).isoformat(),))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('allow_github_signin', '1', ?)", (datetime.now(timezone.utc).isoformat(),))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('login_window_minutes', ?, ?)", (str(LOGIN_WINDOW_MINUTES), datetime.now(timezone.utc).isoformat()))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('login_max_attempts', ?, ?)", (str(LOGIN_MAX_ATTEMPTS), datetime.now(timezone.utc).isoformat()))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('login_lockout_minutes', ?, ?)", (str(LOGIN_LOCKOUT_MINUTES), datetime.now(timezone.utc).isoformat()))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('global_read_only', '0', ?)", (datetime.now(timezone.utc).isoformat(),))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('disable_uploads', '0', ?)", (datetime.now(timezone.utc).isoformat(),))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('disable_downloads', '0', ?)", (datetime.now(timezone.utc).isoformat(),))
        connection.execute("INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES ('maintenance_mode', '0', ?)", (datetime.now(timezone.utc).isoformat(),))
        for control_name in EMERGENCY_CONTROL_LABELS:
            connection.execute(
                "INSERT OR IGNORE INTO policies (name, value, updated_at) VALUES (?, '0', ?)",
                (control_name, datetime.now(timezone.utc).isoformat()),
            )
        connection.execute(
            """
            INSERT OR IGNORE INTO sync_jobs
                (id, enabled, interval_minutes, next_run_at, updated_at)
            VALUES (1, 0, 60, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )


initialize_database()


RATE_LIMIT_RULES = {
    "login": (("ip", 20, 900), ("account", 20, 900)),
    "google_auth": (("ip", 20, 900),),
    "github_auth": (("ip", 20, 900),),
    "login_2fa": (("ip", 10, 300), ("account", 5, 300), ("session", 5, 300)),
    "register": (("ip", 15, 3600), ("account", 3, 3600)),
    "forgot_password": (("ip", 10, 3600), ("account", 3, 3600)),
    "upload": (("ip", 100, 3600), ("session", 30, 3600)),
    "download": (("ip", 600, 900), ("session", 300, 900)),
    "bulk_download": (("ip", 40, 900), ("session", 10, 900)),
    "share_create": (("ip", 60, 3600), ("session", 20, 3600)),
    "public_share": (("ip", 300, 900),),
    "api": (("ip", 120, 300), ("session", 240, 300)),
    "admin": (("ip", 180, 300), ("session", 300, 300)),
}
RATE_LIMIT_DEFAULTS = (("ip", 600, 300), ("session", 900, 300))
RATE_LIMIT_HASH_KEY = app.secret_key.encode("utf-8") if isinstance(app.secret_key, str) else app.secret_key
_RATE_LIMIT_CLEANUP_LOCK = threading.Lock()
_RATE_LIMIT_LAST_CLEANUP = 0


def find_user(username):
    with database_connection() as connection:
        return connection.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    with database_connection() as connection:
        return connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def request_ip():
    return (request.remote_addr or "unknown")[:64]


def rate_limit_identity(scope):
    if scope == "ip":
        return request_ip()
    if scope == "account":
        if request.endpoint == "login_2fa":
            return str(session.get("pending_2fa_user_id", "anonymous"))
        return request.form.get("username", "").strip().casefold()[:128] or "anonymous"
    if scope == "session":
        return session.get("device_token") or str(session.get("pending_2fa_user_id", "anonymous"))
    raise ValueError(f"Unsupported rate limit scope: {scope}")


def consume_rate_limit(endpoint, scope, identity, maximum, window_seconds):
    now = int(datetime.now(timezone.utc).timestamp())
    window_started_at = now - now % window_seconds
    bucket_value = f"{endpoint}\0{scope}\0{identity}\0{window_started_at}".encode("utf-8")
    bucket_key = hmac.new(RATE_LIMIT_HASH_KEY, bucket_value, hashlib.sha256).hexdigest()

    global _RATE_LIMIT_LAST_CLEANUP
    if now - _RATE_LIMIT_LAST_CLEANUP >= 3600:
        with _RATE_LIMIT_CLEANUP_LOCK:
            if now - _RATE_LIMIT_LAST_CLEANUP >= 3600:
                with database_connection() as connection:
                    connection.execute(
                        "DELETE FROM rate_limit_buckets WHERE window_started_at < ?",
                        (now - 86400,),
                    )
                _RATE_LIMIT_LAST_CLEANUP = now

    with database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT request_count, blocked_count FROM rate_limit_buckets WHERE bucket_key = ?",
            (bucket_key,),
        ).fetchone()
        request_count = (row["request_count"] if row else 0) + 1
        blocked_count = (row["blocked_count"] if row else 0) + int(request_count > maximum)
        connection.execute(
            """
            INSERT INTO rate_limit_buckets
                (bucket_key, endpoint, scope, window_started_at, request_count, blocked_count)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(bucket_key) DO UPDATE SET
                request_count = excluded.request_count,
                blocked_count = excluded.blocked_count
            """,
            (bucket_key, endpoint, scope, window_started_at, request_count, blocked_count),
        )
    return request_count <= maximum, max(1, window_seconds - (now - window_started_at)), bucket_key


def request_rate_limit():
    endpoint = request.endpoint or "unmatched"
    path = request.path
    if endpoint in {"login", "login_2fa", "register", "forgot_password"} and request.method != "POST":
        return None

    if endpoint in {"google_login_start", "google_callback"}:
        rule_name = "google_auth"
    elif endpoint in {"github_login_start", "github_callback"}:
        rule_name = "github_auth"
    elif endpoint in {"login", "login_2fa", "register", "forgot_password", "upload", "download", "bulk_download", "share_create", "public_share"}:
        rule_name = endpoint
    elif path.startswith("/api/"):
        rule_name = "api"
    elif path.startswith("/admin"):
        rule_name = "admin"
    else:
        rule_name = "default"

    policies = [
        (rule_name, policy)
        for policy in RATE_LIMIT_RULES.get(rule_name, RATE_LIMIT_DEFAULTS)
    ]
    if emergency_enabled("emergency_rate_limit"):
        policies = [
            (
                group,
                (scope, max(1, maximum // 4), window_seconds),
            )
            for group, (scope, maximum, window_seconds) in policies
        ]
    if rule_name != "default":
        policies.extend(("site", policy) for policy in RATE_LIMIT_DEFAULTS)

    retry_after = 0
    for bucket_group, (scope, maximum, window_seconds) in policies:
        identity = rate_limit_identity(scope)
        if scope == "session" and identity == "anonymous":
            continue
        allowed, retry, bucket_key = consume_rate_limit(
            bucket_group, scope, identity, maximum, window_seconds
        )
        if not allowed:
            retry_after = max(retry_after, retry)
            app.logger.warning(
                "rate_limit_exceeded endpoint=%s scope=%s bucket=%s",
                rule_name,
                scope,
                bucket_key[:16],
            )
            if scope == "ip":
                with database_connection() as connection:
                    bucket = connection.execute(
                        "SELECT blocked_count FROM rate_limit_buckets WHERE bucket_key = ?",
                        (bucket_key,),
                    ).fetchone()
                    if bucket and bucket["blocked_count"] >= 5:
                        create_security_alert(
                            connection,
                            "HIGH",
                            "request_rate_limit_burst",
                            None,
                            request_ip(),
                            f"At least {bucket['blocked_count']} requests were blocked "
                            f"for the {rule_name} limit within its active window.",
                            datetime.now(timezone.utc).isoformat(),
                        )

    if retry_after:
        return rate_limited_response(retry_after)
    return None


def rate_limited_response(retry_after):
    if request.is_json or request.path.startswith("/api/"):
        response = make_response(
            jsonify(
                error="too_many_requests",
                message="Too many requests. Please try again later.",
            ),
            429,
        )
    else:
        response = make_response(
            render_template_string(
                """<!doctype html><html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <title>Too Many Requests - Cloud Rdx</title>
                <style>body{margin:0;padding:12vh 24px;background:#f2f6f8;color:#17212b;font:16px Arial,sans-serif}
                main{max-width:560px;margin:auto;padding:36px;background:#fff;border:1px solid #d8e1e8;border-radius:8px}
                h1{margin-top:0}a{color:#087f73}</style></head><body><main><h1>Too many requests</h1>
                <p>Please wait a little while before trying again.</p><a href="{{ url_for('home') }}">Return to Cloud Rdx</a>
                </main></body></html>"""
            ),
            429,
        )
    response.headers["Retry-After"] = str(retry_after)
    response.headers["Cache-Control"] = "no-store"
    return response


def device_token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_security_alert(
    connection,
    severity,
    alert_type,
    username,
    ip_address,
    details,
    created_at,
    dedupe_minutes=15,
):
    dedupe_after = (
        datetime.fromisoformat(created_at)
        - timedelta(minutes=dedupe_minutes)
    ).isoformat()
    existing = connection.execute(
        """
        SELECT 1 FROM security_alerts
        WHERE alert_type = ? AND COALESCE(username, '') = COALESCE(?, '')
          AND COALESCE(ip_address, '') = COALESCE(?, '')
          AND status = 'open' AND created_at >= ?
        LIMIT 1
        """,
        (alert_type, username, ip_address, dedupe_after),
    ).fetchone()
    if existing:
        return False
    connection.execute(
        """
        INSERT INTO security_alerts
            (severity, alert_type, username, ip_address, details, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (severity, alert_type, username, ip_address, details[:1000], created_at),
    )
    return True


def record_login_attempt(username, success):
    attempted_at = datetime.now(timezone.utc).isoformat()
    settings = login_security_settings()
    with database_connection() as connection:
        connection.execute(
            "INSERT INTO login_attempts (username, ip_address, attempted_at, success) VALUES (?, ?, ?, ?)",
            (username[:128], request_ip(), attempted_at, int(success)),
        )
        if not success:
            cutoff = (
                datetime.now(timezone.utc)
                - timedelta(minutes=settings["login_window_minutes"])
            ).isoformat()
            failures = connection.execute(
                "SELECT COUNT(*) AS count FROM login_attempts WHERE username = ? COLLATE NOCASE AND ip_address = ? AND success = 0 AND attempted_at >= ?",
                (username[:128], request_ip(), cutoff),
            ).fetchone()["count"]
            if failures >= settings["login_max_attempts"]:
                create_security_alert(
                    connection,
                    "HIGH",
                    "brute_force_threshold",
                    username[:128],
                    request_ip(),
                    f"{failures} failed login attempts in "
                    f"{settings['login_window_minutes']} minutes",
                    attempted_at,
                )


def login_lockout_remaining(username):
    now = datetime.now(timezone.utc)
    settings = login_security_settings()
    history_cutoff = (now - timedelta(hours=24)).isoformat()
    with database_connection() as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS failures, MAX(attempted_at) AS latest_failure
            FROM login_attempts AS failures
            WHERE username = ? COLLATE NOCASE AND ip_address = ?
              AND success = 0 AND attempted_at >= ?
              AND attempted_at > COALESCE(
                  (SELECT MAX(successes.attempted_at)
                   FROM login_attempts AS successes
                   WHERE successes.username = failures.username COLLATE NOCASE
                     AND successes.ip_address = failures.ip_address
                     AND successes.success = 1
                     AND successes.attempted_at >= ?),
                  ?
              )
            """,
            (
                username[:128],
                request_ip(),
                history_cutoff,
                history_cutoff,
                history_cutoff,
            ),
        ).fetchone()
    attempt_threshold = settings["login_max_attempts"]
    consecutive_failures = int(row["failures"] or 0) if row else 0
    if consecutive_failures < attempt_threshold or not row["latest_failure"]:
        return 0
    try:
        latest_failure = datetime.fromisoformat(row["latest_failure"])
    except ValueError:
        return max(1, settings["login_lockout_minutes"] * 60)
    if latest_failure.tzinfo is None:
        latest_failure = latest_failure.replace(tzinfo=timezone.utc)
    escalation = max(0, (consecutive_failures - attempt_threshold) // attempt_threshold)
    duration_multiplier = min(8, 2**escalation)
    lockout_ends = latest_failure + timedelta(
        minutes=settings["login_lockout_minutes"] * duration_multiplier
    )
    return max(0, int((lockout_ends - now).total_seconds()))


def create_device_session(user_id):
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc).isoformat()
    user_agent = request.headers.get("User-Agent", "")[:300]
    label = (user_agent.split(" ", 1)[0] if user_agent else "Unknown device")[:80]
    with database_connection() as connection:
        connection.execute(
            "INSERT INTO device_sessions (user_id, session_token_hash, device_label, ip_address, user_agent, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, device_token_hash(token), label, request_ip(), user_agent, now, now),
        )
    return token


TRUSTED_DEVICE_COOKIE = "cloud_rdx_device"


def trusted_browser_device(user_id):
    device_token = request.cookies.get(TRUSTED_DEVICE_COOKIE, "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", device_token):
        device_token = secrets.token_urlsafe(32)
        existing = None
    else:
        with database_connection() as connection:
            existing = connection.execute(
                """
                SELECT id, status FROM trusted_devices
                WHERE user_id = ? AND device_token_hash = ?
                """,
                (user_id, device_token_hash(device_token)),
            ).fetchone()

    now = datetime.now(timezone.utc).isoformat()
    label = (
        request.headers.get("User-Agent", "").split(" ", 1)[0]
        or "Unknown device"
    )[:80]
    enforcing = emergency_enabled("block_new_devices")
    allowed = bool(existing and existing["status"] == "trusted")
    if not enforcing:
        allowed = True
    blocked = enforcing and not allowed
    with database_connection() as connection:
        if blocked:
            if not existing or existing["status"] != "rejected":
                connection.execute(
                    """
                    INSERT INTO trusted_devices
                        (user_id, device_token_hash, device_label, ip_address,
                         user_agent, status, created_at, last_seen_at)
                    VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
                    ON CONFLICT(user_id, device_token_hash) DO UPDATE SET
                        last_seen_at = excluded.last_seen_at,
                        ip_address = excluded.ip_address,
                        user_agent = excluded.user_agent
                    """,
                    (
                        user_id, device_token_hash(device_token), label,
                        request_ip(), request.headers.get("User-Agent", "")[:300],
                        now, now,
                    ),
                )
        elif enforcing:
            connection.execute(
                """
                UPDATE trusted_devices SET last_seen_at = ?, ip_address = ?
                WHERE id = ? AND user_id = ? AND status = 'trusted'
                """,
                (now, request_ip(), existing["id"], user_id),
            )
        elif not enforcing:
            connection.execute(
                """
                INSERT INTO trusted_devices
                    (user_id, device_token_hash, device_label, ip_address,
                     user_agent, status, created_at, last_seen_at, approved_at,
                     approved_by)
                VALUES (?, ?, ?, ?, ?, 'trusted', ?, ?, ?, ?)
                ON CONFLICT(user_id, device_token_hash) DO UPDATE SET
                    device_label = excluded.device_label,
                    ip_address = excluded.ip_address,
                    user_agent = excluded.user_agent,
                    status = 'trusted',
                    last_seen_at = excluded.last_seen_at,
                    approved_at = COALESCE(trusted_devices.approved_at, excluded.approved_at),
                    approved_by = COALESCE(trusted_devices.approved_by, excluded.approved_by)
                """,
                (
                    user_id, device_token_hash(device_token), label,
                    request_ip(), request.headers.get("User-Agent", "")[:300],
                    now, now, now, user_id,
                ),
            )
    if blocked:
        audit_event(
            "trusted_device_signin_blocked",
            "trusted_device",
            user_id,
            "Unapproved device attempted sign-in",
            status="denied",
            risk_level="HIGH",
            actor_id=None,
        )
    return device_token, allowed


def set_trusted_device_cookie(response, token):
    response.set_cookie(
        TRUSTED_DEVICE_COOKIE,
        token,
        max_age=60 * 60 * 24 * 365,
        httponly=True,
        secure=request.is_secure or app.config.get("SESSION_COOKIE_SECURE", False),
        samesite="Lax",
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def trusted_device_login_denied(token):
    response = make_response(
        render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=github_signin_enabled(),
            github_oauth_configured=oauth_credentials_configured("github"),
            error=(
                "This device is not approved. An administrator must approve it "
                "before you can sign in."
            ),
        ),
        403,
    )
    return set_trusted_device_cookie(response, token)


def device_session_is_valid(user_id, token):
    if not token:
        return False
    with database_connection() as connection:
        row = connection.execute(
            "SELECT id FROM device_sessions WHERE user_id = ? AND session_token_hash = ? AND revoked_at IS NULL",
            (user_id, device_token_hash(token)),
        ).fetchone()
        if row:
            connection.execute("UPDATE device_sessions SET last_seen = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), row["id"]))
    return bool(row)


def is_admin():
    user = current_user()
    # The configured owner is the only account allowed to be an administrator.
    return bool(user and user["username"].lower() == ADMIN_USERNAME.lower())


def is_owner():
    user = current_user()
    return bool(user and user["username"].lower() == ADMIN_USERNAME.lower())


def require_owner():
    response = require_login()
    if response:
        return response
    if not is_owner():
        abort(403, "Only the server owner can manage administrator roles and permissions")
    return None


def user_folder():
    user = current_user()
    if not user:
        raise ValueError("Not authenticated")
    folder = SHARED_FOLDER / "users" / str(user["id"])
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def logged_in():
    return current_user() is not None


def safe_path(subpath=""):
    base = user_folder()
    target = (base / subpath).resolve()
    try:
        target.relative_to(base)
    except ValueError as exc:
        raise ValueError("Invalid path") from exc
    return target


def breadcrumbs(subpath):
    parts = [part for part in Path(subpath).parts if part not in (".", "")]
    result = []
    for index, name in enumerate(parts):
        path = "/".join(parts[: index + 1])
        result.append({"name": name, "url": url_for("files", subpath=path)})
    return result


def require_login():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if not device_session_is_valid(user["id"], session.get("device_token")):
        session.clear()
        flash("Your security session is no longer valid. Please sign in again.")
        return redirect(url_for("login"))
    if user["status"] != "active":
        session.clear()
        flash("This account is suspended. Contact an administrator.")
        return redirect(url_for("login"))
    last_seen = session.get("last_seen")
    now = datetime.now(timezone.utc)
    if last_seen:
        try:
            expired = now - datetime.fromisoformat(last_seen) > timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        except ValueError:
            expired = True
        if expired:
            session.clear()
            flash("Your session expired after being inactive.")
            return redirect(url_for("login"))
    timestamp = now.isoformat()
    session["last_seen"] = timestamp
    with database_connection() as connection:
        connection.execute("UPDATE users SET last_seen = ? WHERE id = ?", (timestamp, session["user_id"]))
    return None


def require_admin():
    response = require_login()
    if response:
        return response
    if not is_admin():
        abort(403)
    return None


def require_totp_available():
    if pyotp is None:
        abort(503, "Authenticator support is not installed")


def has_permission(permission):
    user = current_user()
    if not user:
        return False
    if user["username"].lower() == ADMIN_USERNAME.lower():
        return True
    with database_connection() as connection:
        row = connection.execute("""
            SELECT 1 FROM user_roles
            JOIN roles ON roles.id = user_roles.role_id
            JOIN role_permissions ON role_permissions.role_id = roles.id
            WHERE user_roles.user_id = ? AND role_permissions.permission = ?
            LIMIT 1
        """, (user["id"], permission)).fetchone()
    return bool(row)


def has_admin_access():
    return is_admin() or any(has_permission(permission) for permission in ("users.view", "users.manage", "storage.manage", "audit.view", "payments.review"))


def require_permission(permission):
    response = require_login()
    if response:
        return response
    if not has_permission(permission):
        abort(403, f"Missing administrator permission: {permission}")
    return None


def require_admin_access():
    response = require_login()
    if response:
        return response
    if not has_admin_access():
        abort(403)
    return None


def require_storage_user():
    response = require_login()
    if response:
        return response
    if has_admin_access():
        return redirect(url_for("admin_panel"))
    return None


def storage_permission(user_id, permission):
    if permission not in {"upload", "download"}:
        raise ValueError("Unsupported storage permission")
    with database_connection() as connection:
        row = connection.execute(
            "SELECT allow_upload, allow_download FROM storage_permissions WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    return not row or bool(row["allow_upload" if permission == "upload" else "allow_download"])


def require_storage_permission(permission):
    response = require_storage_user()
    if response:
        return response
    user = current_user()
    if not storage_permission(user["id"], permission):
        audit_event(f"{permission}_denied", "storage", user["id"], "permission disabled", status="denied")
        abort(403, f"Storage {permission} access is disabled for this account")
    require_storage_operation(permission)
    return None


def emergency_enabled(name):
    return policy_enabled(name, False)


def require_storage_operation(operation):
    read_only = emergency_enabled("global_read_only")
    blocked = False
    if operation == "upload":
        blocked = read_only or emergency_enabled("disable_uploads")
    elif operation in {"write", "edit"}:
        blocked = read_only or emergency_enabled("disable_editing")
    elif operation == "delete":
        blocked = read_only or emergency_enabled("disable_deletion")
    elif operation == "share":
        blocked = read_only or emergency_enabled("disable_file_sharing")
    elif operation == "download":
        blocked = emergency_enabled("disable_downloads")
    else:
        raise ValueError("Unsupported storage operation")
    if blocked:
        audit_event(
            f"emergency_{operation}_blocked",
            "storage",
            session.get("user_id"),
            "Emergency control blocked the operation",
            status="denied",
            risk_level="HIGH",
        )
        abort(503, f"Storage {operation} is temporarily disabled by the administrator")


def emergency_control_state(connection=None):
    if connection is None:
        with database_connection() as db:
            return emergency_control_state(db)
    rows = connection.execute(
        "SELECT name, value FROM policies WHERE name IN ({})".format(
            ",".join("?" for _ in EMERGENCY_CONTROL_LABELS)
        ),
        tuple(EMERGENCY_CONTROL_LABELS),
    ).fetchall()
    values = {row["name"]: row["value"] for row in rows}
    return {
        name: str(values.get(name, "0")).lower() in {"1", "true", "yes", "on"}
        for name in EMERGENCY_CONTROL_LABELS
    }


def write_emergency_event(
    connection,
    action,
    previous_state,
    new_state,
    reason="",
    affected_users=0,
    affected_user_ids=(),
    affected_services=(),
    result="success",
    incident_id=None,
):
    actor_id = session.get("user_id")
    now = datetime.now(timezone.utc).isoformat()
    previous_json = json.dumps(previous_state, sort_keys=True)
    new_json = json.dumps(new_state, sort_keys=True)
    user_ids_json = json.dumps(list(affected_user_ids)[:10000])
    services_json = json.dumps(list(affected_services))
    connection.execute(
        """
        INSERT INTO emergency_events
            (admin_id, incident_id, ip_address, action, previous_state, new_state,
             reason, affected_users, affected_user_ids, affected_services, result,
             created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            actor_id,
            incident_id,
            request_ip(),
            action[:120],
            previous_json,
            new_json,
            reason[:2000],
            max(0, int(affected_users)),
            user_ids_json,
            services_json,
            result[:40],
            now,
        ),
    )
    connection.execute(
        """
        INSERT INTO audit_events
            (actor_id, action, target_type, target_id, details, status, created_at,
             ip_address, risk_level, session_id)
        VALUES (?, ?, 'emergency', ?, ?, ?, ?, ?, 'HIGH', ?)
        """,
        (
            actor_id,
            f"emergency_{action}"[:120],
            str(incident_id) if incident_id is not None else "global",
            json.dumps({"reason": reason[:500], "affected_users": affected_users}),
            result[:40],
            now,
            request_ip(),
            session.get("device_token", "")[:16] or None,
        ),
    )
def policies_accepted(user_id):
    with database_connection() as connection:
        row = connection.execute("SELECT terms_accepted, privacy_accepted, cookies_accepted, disclaimer_accepted FROM policy_acceptances WHERE user_id = ?", (user_id,)).fetchone()
    return bool(row and all(row[column] for column in ("terms_accepted", "privacy_accepted", "cookies_accepted", "disclaimer_accepted")))


def policy_enabled(name, default=False):
    with database_connection() as connection:
        row = connection.execute("SELECT value FROM policies WHERE name = ?", (name,)).fetchone()
    return bool(row and str(row["value"]).lower() in {"1", "true", "yes", "on"}) if row else default


_OAUTH_CLIENT_LOCK = threading.RLock()
_OAUTH_PROVIDER_CONFIG = {
    "google": {
        "environment": (GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET),
        "name": "google",
        "settings": {
            "server_metadata_url": "https://accounts.google.com/.well-known/openid-configuration",
            "client_kwargs": {"scope": "openid email profile"},
        },
    },
    "github": {
        "environment": (GITHUB_OAUTH_CLIENT_ID, GITHUB_OAUTH_CLIENT_SECRET),
        "name": "github",
        "settings": {
            "authorize_url": "https://github.com/login/oauth/authorize",
            "access_token_url": "https://github.com/login/oauth/access_token",
            "api_base_url": "https://api.github.com/",
            "client_kwargs": {"scope": "read:user user:email"},
        },
    },
}


def _oauth_credentials_cipher():
    if not FLASK_SECRET_KEY_CONFIGURED:
        raise RuntimeError(
            "Set a persistent FLASK_SECRET_KEY before storing OAuth credentials."
        )
    secret_key = (
        app.secret_key
        if isinstance(app.secret_key, bytes)
        else str(app.secret_key).encode("utf-8")
    )
    derived_key = hmac.new(
        secret_key, b"cloud-rdx/oauth-credentials/v1", hashlib.sha256
    ).digest()
    return Fernet(base64.urlsafe_b64encode(derived_key))


def oauth_provider_credentials(provider):
    provider_config = _OAUTH_PROVIDER_CONFIG.get(provider)
    if not provider_config:
        raise ValueError(f"Unsupported OAuth provider: {provider}")

    setting_name = f"{provider}_oauth_credentials"
    with database_connection() as connection:
        row = connection.execute(
            "SELECT value FROM policies WHERE name = ?", (setting_name,)
        ).fetchone()
    if row:
        try:
            payload = _oauth_credentials_cipher().decrypt(
                row["value"].encode("ascii")
            )
            credentials = json.loads(payload)
            if not isinstance(credentials, dict):
                raise ValueError("OAuth credential record is not an object")
            client_id = credentials.get("client_id", "")
            client_secret = credentials.get("client_secret", "")
            if isinstance(client_id, str) and isinstance(client_secret, str):
                return client_id, client_secret
        except (InvalidToken, UnicodeError, ValueError, RuntimeError, TypeError):
            app.logger.error(
                "%s OAuth credentials cannot be decrypted; check that "
                "FLASK_SECRET_KEY has not changed",
                provider,
            )
            return "", ""
        app.logger.error("%s OAuth credential record is invalid", provider)
        return "", ""
    return provider_config["environment"]


def oauth_credentials_configured(provider):
    client_id, client_secret = oauth_provider_credentials(provider)
    return bool(client_id and client_secret)


def oauth_credentials_admin_managed(provider):
    with database_connection() as connection:
        row = connection.execute(
            "SELECT 1 FROM policies WHERE name = ?",
            (f"{provider}_oauth_credentials",),
        ).fetchone()
    return row is not None


def oauth_provider_client(provider):
    provider_config = _OAUTH_PROVIDER_CONFIG.get(provider)
    if not provider_config:
        raise ValueError(f"Unsupported OAuth provider: {provider}")
    client_id, client_secret = oauth_provider_credentials(provider)
    if not client_id or not client_secret:
        return None

    if (client_id, client_secret) == provider_config["environment"]:
        return google if provider == "google" else github

    secret_key = (
        app.secret_key
        if isinstance(app.secret_key, bytes)
        else str(app.secret_key).encode("utf-8")
    )
    fingerprint = hmac.new(
        secret_key,
        f"{provider}\0{client_id}\0{client_secret}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:24]
    client_name = f"managed_{provider}_{fingerprint}"
    with _OAUTH_CLIENT_LOCK:
        client = oauth.register(
            name=client_name,
            client_id=client_id,
            client_secret=client_secret,
            **provider_config["settings"],
        )
        # Preserve the deterministic state key without caching the secret client.
        oauth._clients.pop(client_name, None)
        oauth._registry.pop(client_name, None)
    return client


def policy_integer(name, default, minimum, maximum):
    with database_connection() as connection:
        row = connection.execute("SELECT value FROM policies WHERE name = ?", (name,)).fetchone()
    try:
        value = int(row["value"]) if row else default
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


def login_security_settings():
    return {
        "login_max_attempts": policy_integer(
            "login_max_attempts", LOGIN_MAX_ATTEMPTS, 1, 100
        ),
        "login_window_minutes": policy_integer(
            "login_window_minutes", LOGIN_WINDOW_MINUTES, 1, 1440
        ),
        "login_lockout_minutes": policy_integer(
            "login_lockout_minutes", LOGIN_LOCKOUT_MINUTES, 1, 1440
        ),
    }


def google_signin_enabled():
    return oauth_credentials_configured("google") and policy_enabled(
        "allow_google_signin", True
    )


def github_signin_enabled():
    return oauth_credentials_configured("github") and policy_enabled(
        "allow_github_signin", True
    )


def maintenance_enabled():
    with database_connection() as connection:
        row = connection.execute(
            "SELECT value, updated_at FROM policies WHERE name = 'maintenance_mode'"
        ).fetchone()
        if not row or str(row["value"]).lower() not in {"1", "true", "yes", "on"}:
            return False
        try:
            started_at = datetime.fromisoformat(row["updated_at"])
            if started_at.tzinfo is None:
                started_at = started_at.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            # An invalid activation timestamp must fail closed rather than
            # accidentally making the website available.
            return True
        if datetime.now(timezone.utc) - started_at >= timedelta(hours=MAINTENANCE_DURATION_HOURS):
            connection.execute(
                "UPDATE policies SET value = '0', updated_at = ? WHERE name = 'maintenance_mode'",
                (datetime.now(timezone.utc).isoformat(),),
            )
            return False
    return True


def admin_user_path(user_id, subpath=""):
    with database_connection() as connection:
        user = connection.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user or user["is_admin"]:
        raise ValueError("User not found")
    base = (SHARED_FOLDER / "users" / str(user_id)).resolve()
    target = (base / subpath).resolve()
    try:
        target.relative_to(base)
    except ValueError as exc:
        raise ValueError("Invalid path") from exc
    return user, base, target


@app.before_request
def enforce_session_timeout():
    limited_response = request_rate_limit()
    if limited_response:
        return limited_response
    if (
        request.path.startswith("/api/")
        and request.endpoint != "payment_webhook"
        and emergency_enabled("disable_api_access")
    ):
        audit_event(
            "emergency_api_blocked",
            "api",
            request.endpoint or request.path,
            "Emergency API access control",
            status="denied",
            risk_level="HIGH",
            actor_id=session.get("user_id"),
        )
        return jsonify(
            error="service_unavailable",
            message="API access is temporarily disabled by the administrator.",
        ), 503
    exempt_endpoints = {
        "home",
        "login",
        "login_2fa",
        "register",
        "forgot_password",
        "google_login_start",
        "google_callback",
        "github_login_start",
        "github_callback",
        "login_assets",
        "background_video",
        "payment_webhook",
        "payment_qr",
        "static",
        "consent",
        "policy_page",
    }
    if maintenance_enabled():
        maintenance_exempt_endpoints = {
            "login",
            "login_2fa",
            "google_login_start",
            "google_callback",
            "github_login_start",
            "github_callback",
            "login_assets",
            "background_video",
            "payment_webhook",
            "payment_qr",
            "static",
        }
        user = current_user()
        owner_session = bool(user and user["username"].lower() == ADMIN_USERNAME.lower() and user["status"] == "active")
        if request.endpoint not in maintenance_exempt_endpoints and not owner_session:
            session.clear()
            return render_template_string(MAINTENANCE_PAGE), 503
    if (
        request.method == "POST"
        and (
            request.endpoint == "login_2fa"
            or request.endpoint not in exempt_endpoints
        )
    ):
        expected = session.get(CSRF_SESSION_KEY)
        supplied = request.form.get("csrf_token", "")
        if not expected or not supplied or not secrets.compare_digest(expected, supplied):
            abort(400, "Invalid or missing CSRF token")
    if request.endpoint not in exempt_endpoints:
        response = require_login()
        if response:
            return response
        user = current_user()
        if user and request.endpoint not in {"consent", "accept_policies", "policy_page"} and not policies_accepted(user["id"]):
            return redirect(url_for("consent"))
        if (
            user
            and emergency_enabled("force_password_reset")
            and user["must_change_password"]
            and request.endpoint not in {"profile", "change_password", "logout", "static"}
        ):
            return redirect(url_for("profile"))
        if (
            user
            and emergency_enabled("require_two_factor")
            and not user["totp_enabled"]
            and request.endpoint not in {"security_2fa_enroll", "logout", "static"}
        ):
            return redirect(url_for("security_2fa_enroll"))


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; object-src 'none'; "
        "frame-ancestors 'self'; form-action 'self'; "
        "img-src 'self' https: data: blob:; media-src 'self'; "
        "connect-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'",
    )
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.endpoint == "admin_settings":
        response.headers["Cache-Control"] = "no-store"
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


@app.context_processor
def inject_user():
    user = current_user()
    return {"username": user["username"] if user else "", "is_admin": bool(user and user["is_admin"]), "is_owner": is_owner(), "admin_access": has_admin_access() if user else False}


@app.route("/login-assets/<path:filename>")
def login_assets(filename):
    """Serve the supplied login background without exposing other files."""
    assets = RESOURCE_FOLDER / "Animated-attractive-Login-Page-main"
    return send_from_directory(assets, filename)


@app.route("/background-video")
def background_video():
    """Serve the supplied authentication background video."""
    video = RESOURCE_FOLDER / "Resources RDx" / "login page.mp4"
    return send_from_directory(video.parent, video.name, mimetype="video/mp4")


@app.route("/payment-qr")
def payment_qr():
    """Serve the configured payment QR image without exposing the asset folder."""
    qr = RESOURCE_FOLDER / "Resources RDx" / "WhatsApp Image 2026-09-16 at 12.34.01 PM.jpeg"
    if not qr.is_file():
        abort(404, "Payment QR is not configured")
    return send_from_directory(qr.parent, qr.name, mimetype="image/jpeg")


@app.route("/")
def home():
    if logged_in():
        return redirect(url_for("admin_panel" if has_admin_access() else "files"))
    return render_template_string(HOME_PAGE)


@app.route("/consent")
def consent():
    response = require_login()
    if response:
        return response
    return render_template_string(CONSENT_PAGE)


@app.route("/consent/accept", methods=["POST"])
def accept_policies():
    response = require_login()
    if response:
        return response
    if request.form.get("accept_all") != "on":
        return render_template_string(CONSENT_PAGE, error="You must accept all four policies before using RDx Cloud Storage."), 400
    now = datetime.now(timezone.utc).isoformat()
    with database_connection() as connection:
        connection.execute("""
            INSERT INTO policy_acceptances (user_id, terms_accepted, privacy_accepted, cookies_accepted, disclaimer_accepted, accepted_at)
            VALUES (?, 1, 1, 1, 1, ?)
            ON CONFLICT(user_id) DO UPDATE SET terms_accepted=1, privacy_accepted=1, cookies_accepted=1, disclaimer_accepted=1, accepted_at=excluded.accepted_at
        """, (session["user_id"], now))
    audit_event("accept_policies", "policy", session["user_id"], "terms, privacy, cookies, disclaimer")
    flash("Thank you. All policies were accepted.")
    if session.pop("show_profile_onboarding", False):
        return redirect(url_for("profile"))
    return redirect(url_for("admin_panel" if has_admin_access() else "files"))


@app.route("/policy/<policy_name>")
def policy_page(policy_name):
    policies = {
        "terms": {"title": "Terms and conditions", "summary": "These terms explain the acceptable use of RDx Cloud Storage and the responsibilities of account holders."},
        "privacy": {"title": "Privacy policy", "summary": "This policy explains how account, recovery, audit, and storage information is handled by this local storage service."},
        "cookies": {"title": "Cookie policy", "summary": "RDx Cloud Storage uses essential session cookies to keep you signed in and protect forms. It does not require advertising cookies."},
        "disclaimer": {"title": "Disclaimer", "summary": "The service is provided for authorized storage use. Keep independent backups of important files and do not rely on this service as your only copy."},
    }
    policy = policies.get(policy_name)
    if not policy:
        abort(404)
    return render_template_string(POLICY_PAGE, policy=policy, back_url=url_for("consent") if logged_in() else url_for("home"))


TOTP_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Security verification - Cloud Rdx</title><link rel="stylesheet" href="{{ url_for('static', filename='auth.css') }}"></head>
<body class="login-page"><main class="login-box"><div class="login-brand">RDx Cloud Storage-DB16</div><h1>Verify your sign-in</h1><p class="login-notice">Enter the six-digit code from your authenticator app.</p><form method="post" action="{{ url_for('login_2fa') }}"><div class="input-box"><input id="code" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder=" " required autofocus><label for="code">Authenticator code</label></div><button type="submit">Verify and continue</button></form>{% if error %}<p class="login-message" role="alert">{{ error }}</p>{% endif %}<p class="register-link"><a href="{{ url_for('login') }}">Cancel sign in</a></p></main></body></html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if logged_in():
        return redirect(url_for("admin_panel" if has_admin_access() else "files"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        lockout_remaining = login_lockout_remaining(username)
        if lockout_remaining:
            audit_event("login_throttled", "user", username, "too many recent failures", status="denied", actor_id=None)
            return rate_limited_response(lockout_remaining)
        user = find_user(username)
        password = request.form.get("password", "")
        owner_login_allowed = not maintenance_enabled() or bool(
            user and user["username"].lower() == ADMIN_USERNAME.lower()
        )
        if (
            owner_login_allowed
            and user
            and user["password_login_enabled"]
            and user["status"] == "active"
            and verify_password(user["password_hash"], password)
        ):
            record_login_attempt(username, True)
            if password_hash_needs_upgrade(user["password_hash"]):
                with database_connection() as connection:
                    connection.execute("UPDATE users SET password_hash = ?, password_login_enabled = 1 WHERE id = ?", (hash_password(password), user["id"]))
            if user["totp_enabled"] and (
                user["is_admin"] or emergency_enabled("require_two_factor")
            ):
                session.clear()
                session["pending_2fa_user_id"] = user["id"]
                session["pending_2fa_at"] = datetime.now(timezone.utc).isoformat()
                csrf_token()
                return redirect(url_for("login_2fa"))
            device_cookie, device_allowed = trusted_browser_device(user["id"])
            if not device_allowed:
                return trusted_device_login_denied(device_cookie)
            session.clear()
            timestamp = datetime.now(timezone.utc).isoformat()
            with database_connection() as connection:
                connection.execute(
                    "UPDATE users SET last_login_at = ? WHERE id = ?",
                    (timestamp, user["id"]),
                )
            session["user_id"] = user["id"]
            session["last_seen"] = timestamp
            session["device_token"] = create_device_session(user["id"])
            csrf_token()
            audit_event("login", "user", user["id"])
            if emergency_enabled("require_two_factor") and not user["totp_enabled"]:
                response = redirect(url_for("security_2fa_enroll"))
            else:
                response = redirect(url_for("admin_panel" if has_admin_access() else "files"))
            return set_trusted_device_cookie(response, device_cookie)
        record_login_attempt(username, False)
        if user and user["status"] != "active":
            audit_event("login_blocked", "user", user["id"], "account is suspended", status="denied", actor_id=None)
        return render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=github_signin_enabled(),
            github_oauth_configured=oauth_credentials_configured("github"),
            error="The username or password is not correct.",
        )
    return render_template_string(
        LOGIN_PAGE,
        google_login_enabled=google_signin_enabled(),
        google_oauth_configured=oauth_credentials_configured("google"),
        github_login_enabled=github_signin_enabled(),
        github_oauth_configured=oauth_credentials_configured("github"),
    )


def social_account_for_identity(
    provider,
    subject,
    email,
    full_name,
    allow_creation=True,
    provider_username=None,
    picture_url=None,
    provider_location=None,
):
    provider_columns = {
        "google": {
            "identity": "google_sub",
            "email": "google_email",
            "name": "google_profile_name",
            "username": "google_username",
            "picture": "google_picture",
        },
        "github": {
            "identity": "github_sub",
            "email": "github_email",
            "name": "github_profile_name",
            "username": "github_username",
            "picture": "github_picture",
        },
    }
    provider_fields = provider_columns.get(provider)
    if not provider_fields:
        raise ValueError(f"Unsupported social identity provider: {provider}")

    identity_column = provider_fields["identity"]
    provider_username = (
        provider_username.strip()[:255]
        if isinstance(provider_username, str) and provider_username.strip()
        else None
    )
    picture_url = safe_oauth_picture_url(picture_url, provider)
    provider_location = (
        provider_location.strip()[:160]
        if isinstance(provider_location, str) and provider_location.strip()
        else None
    )
    created = False
    linked = False
    with database_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        user = connection.execute(
            f"SELECT * FROM users WHERE {identity_column} = ?", (subject,)
        ).fetchone()
        if not user:
            matches = connection.execute(
                "SELECT * FROM users WHERE lower(trim(email)) = ?",
                (email,),
            ).fetchall()
            if len(matches) > 1:
                return None, False, False, "That email matches multiple accounts. Contact support."
            if matches:
                user = matches[0]
                if user[identity_column] and user[identity_column] != subject:
                    return None, False, False, (
                        f"That account is already connected to another "
                        f"{provider.title()} identity."
                    )
                connection.execute(
                    f"""
                    UPDATE users
                    SET {identity_column} = ?,
                        full_name = COALESCE(NULLIF(full_name, ''), ?)
                    WHERE id = ?
                    """,
                    (subject, full_name, user["id"]),
                )
                linked = True
                user = connection.execute(
                    "SELECT * FROM users WHERE id = ?", (user["id"],)
                ).fetchone()
            else:
                if not allow_creation:
                    return None, False, False, (
                        f"New {provider.title()} accounts are unavailable during maintenance."
                    )
                if (
                    not policy_enabled("allow_registration", True)
                    or emergency_enabled("freeze_registrations")
                ):
                    return None, False, False, "New account registration is disabled."

                local_part = email.split("@", 1)[0]
                base_username = re.sub(r"[^A-Za-z0-9_-]", "", local_part)[:32]
                if len(base_username) < 3:
                    base_username = "clouduser"
                username = base_username
                suffix = 1
                while connection.execute(
                    "SELECT 1 FROM users WHERE username = ? COLLATE NOCASE",
                    (username,),
                ).fetchone():
                    tail = f"-{suffix}"
                    username = f"{base_username[:32 - len(tail)]}{tail}"
                    suffix += 1

                now = datetime.now(timezone.utc).isoformat()
                cursor = connection.execute(
                    f"""
                    INSERT INTO users
                        (username, password_hash, created_at, full_name, email,
                         {identity_column}, password_login_enabled)
                    VALUES (?, ?, ?, ?, ?, ?, 0)
                    """,
                    (
                        username,
                        hash_password(secrets.token_urlsafe(48)),
                        now,
                        full_name,
                        email,
                        subject,
                    ),
                )
                user_id = cursor.lastrowid
                connection.execute(
                    """
                    INSERT INTO storage_permissions
                        (user_id, allow_upload, allow_download, updated_at)
                    VALUES (?, 1, 1, ?)
                    """,
                    (user_id, now),
                )
                user = connection.execute(
                    "SELECT * FROM users WHERE id = ?", (user_id,)
                ).fetchone()
                created = True

        connection.execute(
            f"""
            UPDATE users
            SET {provider_fields["email"]} = ?,
                {provider_fields["name"]} = ?,
                {provider_fields["username"]} = COALESCE(?, {provider_fields["username"]}),
                {provider_fields["picture"]} = COALESCE(?, {provider_fields["picture"]}),
                location = COALESCE(NULLIF(location, ''), ?)
            WHERE id = ?
            """,
            (
                email,
                full_name[:160],
                provider_username,
                picture_url,
                provider_location,
                user["id"],
            ),
        )
        user = connection.execute(
            "SELECT * FROM users WHERE id = ?", (user["id"],)
        ).fetchone()
        if user["status"] != "active":
            return None, False, False, "This Cloud Rdx account is currently unavailable."

    if created:
        (SHARED_FOLDER / "users" / str(user["id"])).mkdir(
            parents=True, exist_ok=True
        )
    return user, created, linked, None


def safe_oauth_picture_url(value, provider):
    if not isinstance(value, str) or len(value) > 2048:
        return None
    try:
        parsed_url = urlsplit(value)
    except ValueError:
        return None
    hostname = parsed_url.hostname
    allowed_suffix = {
        "google": "googleusercontent.com",
        "github": "githubusercontent.com",
    }.get(provider)
    if (
        not allowed_suffix
        or parsed_url.scheme != "https"
        or not hostname
        or not (hostname == allowed_suffix or hostname.endswith(f".{allowed_suffix}"))
    ):
        return None
    return value


def complete_social_login(
    provider,
    subject,
    email,
    full_name,
    provider_username=None,
    picture_url=None,
    provider_location=None,
):
    maintenance_active = maintenance_enabled()
    user, created, linked, error = social_account_for_identity(
        provider,
        subject,
        email,
        full_name,
        allow_creation=(
            not maintenance_active
            and policy_enabled("allow_registration", True)
            and not emergency_enabled("freeze_registrations")
        ),
        provider_username=provider_username,
        picture_url=picture_url,
        provider_location=provider_location,
    )
    if error:
        if maintenance_active:
            return render_template_string(MAINTENANCE_PAGE), 503
        return render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=github_signin_enabled(),
            github_oauth_configured=oauth_credentials_configured("github"),
            error=error,
        ), 403

    if maintenance_active and user["username"].lower() != ADMIN_USERNAME.lower():
        return render_template_string(MAINTENANCE_PAGE), 503

    if created:
        audit_event(
            "account_created",
            "user",
            user["id"],
            f"provider={provider}",
            actor_id=None,
        )
    record_login_attempt(email, True)
    if user["totp_enabled"] and (
        user["is_admin"] or emergency_enabled("require_two_factor")
    ):
        session.clear()
        session["pending_2fa_user_id"] = user["id"]
        session["pending_2fa_at"] = datetime.now(timezone.utc).isoformat()
        csrf_token()
        audit_event(f"{provider}_login_2fa_required", "user", user["id"])
        return redirect(url_for("login_2fa"))

    device_cookie, device_allowed = trusted_browser_device(user["id"])
    if not device_allowed:
        session.clear()
        return trusted_device_login_denied(device_cookie)
    timestamp = datetime.now(timezone.utc).isoformat()
    with database_connection() as connection:
        connection.execute(
            "UPDATE users SET last_login_at = ? WHERE id = ?",
            (timestamp, user["id"]),
        )
    session.clear()
    session["user_id"] = user["id"]
    session["last_seen"] = timestamp
    session["device_token"] = create_device_session(user["id"])
    csrf_token()
    audit_action = (
        f"{provider}_account_created"
        if created
        else f"{provider}_account_linked"
        if linked
        else f"{provider}_login"
    )
    audit_event(audit_action, "user", user["id"], actor_id=user["id"])
    if emergency_enabled("require_two_factor") and not user["totp_enabled"]:
        response = redirect(url_for("security_2fa_enroll"))
        return set_trusted_device_cookie(response, device_cookie)
    if created:
        session["show_profile_onboarding"] = True
        flash(
            "Your account is ready. Add optional recovery and profile details, "
            "or return to storage to continue."
        )
        response = redirect(url_for("profile"))
    else:
        response = redirect(url_for("admin_panel" if has_admin_access() else "files"))
    return set_trusted_device_cookie(response, device_cookie)


@app.route("/auth/google")
def google_login_start():
    if logged_in():
        return redirect(url_for("admin_panel" if has_admin_access() else "files"))
    if not google_signin_enabled():
        error = (
            "Google sign-in is disabled by the site administrator."
            if oauth_credentials_configured("google")
            else "Google sign-in is not configured on this server."
        )
        return (
            render_template_string(
                LOGIN_PAGE,
                google_login_enabled=False,
                google_oauth_configured=oauth_credentials_configured("google"),
                github_login_enabled=github_signin_enabled(),
                github_oauth_configured=oauth_credentials_configured("github"),
                error=error,
            ),
            503,
        )
    redirect_uri = f"{APP_BASE_URL}{url_for('google_callback')}"
    client = oauth_provider_client("google")
    return client.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def google_callback():
    if not google_signin_enabled():
        error = (
            "Google sign-in is disabled by the site administrator."
            if oauth_credentials_configured("google")
            else "Google sign-in is not configured on this server."
        )
        return (
            render_template_string(
                LOGIN_PAGE,
                google_login_enabled=False,
                google_oauth_configured=oauth_credentials_configured("google"),
                github_login_enabled=github_signin_enabled(),
                github_oauth_configured=oauth_credentials_configured("github"),
                error=error,
            ),
            503,
        )
    try:
        client = oauth_provider_client("google")
        token = client.authorize_access_token()
    except (OAuthError, JoseError):
        app.logger.info("Google sign-in rejected an invalid OAuth response")
        return render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=github_signin_enabled(),
            github_oauth_configured=oauth_credentials_configured("github"),
            error="Google sign-in could not be verified. Please try again.",
        ), 400

    claims = token.get("userinfo")
    if not isinstance(claims, Mapping):
        return render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=github_signin_enabled(),
            github_oauth_configured=oauth_credentials_configured("github"),
            error="Google did not return a verified account. Please try again.",
        ), 400
    subject = claims.get("sub")
    email = claims.get("email")
    full_name = claims.get("name")
    if (
        not isinstance(subject, str)
        or not isinstance(email, str)
        or claims.get("email_verified") is not True
    ):
        return render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=github_signin_enabled(),
            github_oauth_configured=oauth_credentials_configured("github"),
            error="Google sign-in requires a verified email address.",
        ), 400

    subject = subject.strip()
    email = email.strip().lower()
    if not subject or len(subject) > 255 or "@" not in email or len(email) > 254:
        return render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=github_signin_enabled(),
            github_oauth_configured=oauth_credentials_configured("github"),
            error="Google sign-in returned invalid account details.",
        ), 400
    full_name = full_name.strip()[:160] if isinstance(full_name, str) else ""
    full_name = full_name or email.split("@", 1)[0]
    provider_username = claims.get("preferred_username")
    picture_url = claims.get("picture")
    return complete_social_login(
        "google",
        subject,
        email,
        full_name,
        provider_username=provider_username,
        picture_url=picture_url,
    )


@app.route("/auth/github")
def github_login_start():
    if logged_in():
        return redirect(url_for("admin_panel" if has_admin_access() else "files"))
    if not github_signin_enabled():
        error = (
            "GitHub sign-in is disabled by the site administrator."
            if oauth_credentials_configured("github")
            else "GitHub sign-in is not configured on this server."
        )
        return render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=False,
            github_oauth_configured=oauth_credentials_configured("github"),
            error=error,
        ), 503
    redirect_uri = f"{APP_BASE_URL}{url_for('github_callback')}"
    client = oauth_provider_client("github")
    return client.authorize_redirect(redirect_uri)


@app.route("/auth/github/callback")
def github_callback():
    if not github_signin_enabled():
        error = (
            "GitHub sign-in is disabled by the site administrator."
            if oauth_credentials_configured("github")
            else "GitHub sign-in is not configured on this server."
        )
        return render_template_string(
            LOGIN_PAGE,
            google_login_enabled=google_signin_enabled(),
            google_oauth_configured=oauth_credentials_configured("google"),
            github_login_enabled=False,
            github_oauth_configured=oauth_credentials_configured("github"),
            error=error,
        ), 503
    try:
        client = oauth_provider_client("github")
        client.authorize_access_token()
        profile_response = client.get("user")
        if profile_response.status_code != 200:
            app.logger.warning(
                "GitHub profile lookup failed with status=%s",
                profile_response.status_code,
            )
            return github_auth_error(
                "GitHub could not verify your account. Please try again.", 502
            )
        profile = profile_response.json()
        if not isinstance(profile, Mapping):
            return github_auth_error("GitHub returned invalid account details.", 400)

        emails_response = client.get("user/emails")
        if emails_response.status_code != 200:
            app.logger.warning(
                "GitHub email lookup failed with status=%s",
                emails_response.status_code,
            )
            return github_auth_error(
                "GitHub could not verify your email address. Please try again.",
                502,
            )
        email_entries = emails_response.json()
    except OSError:
        app.logger.warning("GitHub sign-in could not reach the OAuth provider")
        return github_auth_error(
            "GitHub sign-in is temporarily unavailable. Please try again later.",
            502,
        )
    except (OAuthError, ValueError):
        app.logger.info("GitHub sign-in rejected an invalid OAuth response")
        return github_auth_error(
            "GitHub sign-in could not be verified. Please try again.", 400
        )

    github_id = profile.get("id")
    if isinstance(github_id, bool) or not isinstance(github_id, (int, str)):
        return github_auth_error("GitHub returned invalid account details.", 400)
    subject = str(github_id).strip()
    if not subject or len(subject) > 255 or not subject.isdigit():
        return github_auth_error("GitHub returned invalid account details.", 400)
    if not isinstance(email_entries, list):
        return github_auth_error(
            "GitHub did not return a verified email address.", 400
        )
    primary_email = next(
        (
            entry.get("email")
            for entry in email_entries
            if isinstance(entry, Mapping)
            and entry.get("primary") is True
            and entry.get("verified") is True
            and isinstance(entry.get("email"), str)
        ),
        None,
    )
    if not primary_email:
        return github_auth_error(
            "GitHub sign-in requires a verified primary email address.", 400
        )
    email = primary_email.strip().lower()
    if "@" not in email or len(email) > 254:
        return github_auth_error("GitHub returned invalid account details.", 400)
    full_name = profile.get("name")
    if not isinstance(full_name, str) or not full_name.strip():
        full_name = profile.get("login")
    if not isinstance(full_name, str) or not full_name.strip():
        full_name = email.split("@", 1)[0]
    return complete_social_login(
        "github",
        subject,
        email,
        full_name.strip()[:160],
        provider_username=profile.get("login"),
        picture_url=profile.get("avatar_url"),
        provider_location=profile.get("location"),
    )


def github_auth_error(message, status):
    return render_template_string(
        LOGIN_PAGE,
        google_login_enabled=google_signin_enabled(),
        google_oauth_configured=oauth_credentials_configured("google"),
        github_login_enabled=github_signin_enabled(),
        github_oauth_configured=oauth_credentials_configured("github"),
        error=message,
    ), status


@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("login"))
    try:
        issued = datetime.fromisoformat(session.get("pending_2fa_at", ""))
    except ValueError:
        issued = datetime.min.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - issued > timedelta(minutes=5):
        session.clear()
        return redirect(url_for("login"))
    user = current_user() if session.get("user_id") else None
    with database_connection() as connection:
        user = connection.execute(
            "SELECT * FROM users WHERE id = ? AND status = 'active'",
            (user_id,),
        ).fetchone()
    if (
        not user
        or pyotp is None
        or not user["totp_enabled"]
        or not (user["is_admin"] or emergency_enabled("require_two_factor"))
    ):
        session.clear()
        return render_template_string(TOTP_PAGE, error="Authenticator verification is unavailable. Contact the system administrator."), 503
    if request.method == "POST" and pyotp.TOTP(user["totp_secret"]).verify(request.form.get("code", "").strip(), valid_window=1):
        device_cookie, device_allowed = trusted_browser_device(user["id"])
        if not device_allowed:
            session.clear()
            return trusted_device_login_denied(device_cookie)
        timestamp = datetime.now(timezone.utc).isoformat()
        with database_connection() as connection:
            connection.execute(
                "UPDATE users SET last_login_at = ? WHERE id = ?",
                (timestamp, user["id"]),
            )
        session.clear()
        session["user_id"] = user["id"]
        session["last_seen"] = timestamp
        session["device_token"] = create_device_session(user["id"])
        csrf_token()
        audit_event("login_2fa", "user", user["id"])
        response = redirect(url_for("admin_panel" if has_admin_access() else "files"))
        return set_trusted_device_cookie(response, device_cookie)
    if request.method == "POST":
        record_login_attempt(user["username"], False)
        audit_event("login_2fa_failed", "user", user["id"], status="denied", actor_id=None)
        return render_template_string(TOTP_PAGE, error="That verification code is invalid or expired.")
    return render_template_string(TOTP_PAGE)


@app.route("/security/2fa/enroll", methods=["GET", "POST"])
def security_2fa_enroll():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if pyotp is None:
        abort(503, "Authenticator support is not installed")
    if user["totp_enabled"]:
        return redirect(url_for("admin_panel" if has_admin_access() else "files"))
    secret = session.get("totp_enroll_secret") or pyotp.random_base32()
    session["totp_enroll_secret"] = secret
    provisioning_uri = pyotp.TOTP(secret).provisioning_uri(
        name=user["email"] or user["username"],
        issuer_name="Cloud Rdx",
    )
    error = None
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if not re.fullmatch(r"\d{6}", code) or not pyotp.TOTP(secret).verify(
            code, valid_window=1
        ):
            error = "That verification code is invalid or expired."
        else:
            with database_connection() as connection:
                connection.execute(
                    "UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?",
                    (secret, user["id"]),
                )
            session.pop("totp_enroll_secret", None)
            audit_event("enroll_required_2fa", "user", user["id"], risk_level="HIGH")
            flash("Authenticator two-factor authentication is enabled.")
            return redirect(url_for("admin_panel" if has_admin_access() else "files"))
    return render_template_string(
        TOTP_SETUP_PAGE,
        secret=secret,
        provisioning_uri=provisioning_uri,
        error=error,
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if logged_in():
        return redirect(url_for("admin_panel" if has_admin_access() else "files"))
    if (
        not policy_enabled("allow_registration", True)
        or emergency_enabled("freeze_registrations")
    ):
        return render_template_string(REGISTER_PAGE, error="New registrations are currently disabled by an administrator."), 403
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        mobile = request.form.get("mobile", "").strip()
        date_of_birth = request.form.get("dob", "").strip()
        if not username or not username.replace("_", "").replace("-", "").isalnum() or not 3 <= len(username) <= 32:
            return render_template_string(REGISTER_PAGE, error="Use 3-32 letters, numbers, underscores, or hyphens.")
        if len(password) < 8:
            return render_template_string(REGISTER_PAGE, error="Password must be at least 8 characters.")
        if password != password_confirm:
            return render_template_string(REGISTER_PAGE, error="Passwords do not match.")
        if not full_name or not email or not mobile or not date_of_birth:
            return render_template_string(REGISTER_PAGE, error="All profile and recovery fields are required.")
        if find_user(username):
            return render_template_string(REGISTER_PAGE, error="That username is already taken.")
        with database_connection() as connection:
            cursor = connection.execute("INSERT INTO users (username, password_hash, created_at, full_name, email, mobile, date_of_birth) VALUES (?, ?, ?, ?, ?, ?, ?)", (username, hash_password(password), datetime.now(timezone.utc).isoformat(), full_name, email, mobile, date_of_birth))
            user_id = cursor.lastrowid
            connection.execute(
                "INSERT INTO storage_permissions (user_id, allow_upload, allow_download, updated_at) VALUES (?, 1, 1, ?)",
                (user_id, datetime.now(timezone.utc).isoformat()),
            )
        (SHARED_FOLDER / "users" / str(user_id)).mkdir(parents=True, exist_ok=True)
        audit_event("account_created", "user", user_id, "provider=password")
        flash("Account created. Sign in to access your private storage.")
        return redirect(url_for("login"))
    return render_template_string(REGISTER_PAGE)


@app.route("/profile", methods=["GET", "POST"])
def profile():
    response = require_login()
    if response:
        return response
    user = dict(current_user())
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        mobile = request.form.get("mobile", "").strip()
        date_of_birth = request.form.get("date_of_birth", "").strip()
        gender = request.form.get("gender", "").strip()
        location = request.form.get("location", "").strip()
        if not full_name or len(full_name) > 160:
            flash("Enter a full name of 1 to 160 characters.")
        elif len(mobile) > 32 or len(gender) > 80 or len(location) > 160:
            flash("One or more profile fields exceed their allowed length.")
        else:
            if date_of_birth:
                try:
                    parsed_birth_date = datetime.strptime(
                        date_of_birth, "%Y-%m-%d"
                    ).date()
                except ValueError:
                    parsed_birth_date = None
                if (
                    parsed_birth_date is None
                    or parsed_birth_date > datetime.now(timezone.utc).date()
                ):
                    flash("Enter a valid date of birth that is not in the future.")
                    return redirect(url_for("profile"))
            with database_connection() as connection:
                connection.execute(
                    """
                    UPDATE users
                    SET full_name = ?, mobile = ?, date_of_birth = ?,
                        gender = ?, location = ?
                    WHERE id = ?
                    """,
                    (
                        full_name,
                        mobile,
                        date_of_birth,
                        gender,
                        location,
                        user["id"],
                    ),
                )
            audit_event("profile_details_updated", "user", user["id"])
            flash("Your profile and recovery details were saved.")
            return redirect(url_for("profile"))

    user["profile_picture"] = user.get("google_picture") or user.get("github_picture")
    return render_template_string(
        PROFILE_PAGE,
        profile=user,
        can_edit_profile=True,
        back_url=url_for("admin_panel" if has_admin_access() else "files"),
    )


@app.route("/storage/plan")
def storage_plan():
    response = require_storage_user()
    if response:
        return response
    user = current_user()
    used = user_usage(user["id"])[1]
    quota = user_quota(user["id"])
    subscription = current_subscription(user["id"])
    percent = min(100, int(used * 100 / quota)) if quota else 0
    return render_template_string(
        USER_ALLOCATION_PAGE,
        plans=[dict(row) for row in plan_rows()],
        used=used,
        quota=quota,
        remaining=max(0, quota - used),
        percent=percent,
        subscription=subscription,
        qr_url=PAYMENT_QR_URL,
    )


@app.route("/storage/payment-request", methods=["POST"])
def manual_payment_request():
    response = require_storage_user()
    if response:
        return response
    try:
        plan_id = int(request.form.get("plan_id", "0"))
    except ValueError:
        abort(400, "Invalid storage plan")
    reference = request.form.get("transaction_reference", "").strip()
    if not reference or len(reference) > 120:
        flash("Enter a valid UPI transaction reference.")
        return redirect(url_for("storage_plan"))
    user = current_user()
    with database_connection() as connection:
        plan = connection.execute("SELECT * FROM storage_plans WHERE id = ? AND active = 1", (plan_id,)).fetchone()
        if not plan or not plan["price_paise"]:
            flash("That storage plan is not available for payment.")
            return redirect(url_for("storage_plan"))
        try:
            connection.execute("""
                INSERT INTO payment_requests
                (user_id, plan_id, transaction_reference, amount_paise, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (user["id"], plan["id"], reference, plan["price_paise"], datetime.now(timezone.utc).isoformat()))
        except sqlite3.IntegrityError:
            flash("That transaction reference has already been submitted.")
            return redirect(url_for("storage_plan"))
    audit_event("payment_request_submitted", "payment", reference, f"plan={plan['code']}")
    flash("Payment reference submitted. Storage will be updated after verification.")
    return redirect(url_for("storage_plan"))


@app.route("/api/storage/plans")
def api_storage_plans():
    response = require_login()
    if response:
        return jsonify({"error": "authentication_required"}), 401
    return jsonify({"plans": [dict(row) for row in plan_rows()]})


@app.route("/api/storage/usage")
def api_storage_usage():
    response = require_storage_user()
    if response:
        return jsonify({"error": "authentication_required"}), 401
    user = current_user()
    used = user_usage(user["id"])[1]
    quota = user_quota(user["id"])
    return jsonify({"used_bytes": used, "quota_bytes": quota, "remaining_bytes": max(0, quota - used), "percent": min(100, int(used * 100 / quota)) if quota else 0})


@app.route("/api/subscription")
def api_subscription():
    response = require_storage_user()
    if response:
        return jsonify({"error": "authentication_required"}), 401
    return jsonify(current_subscription(current_user()["id"]) or {"status": "free"})


@app.route("/api/storage/create-order", methods=["POST"])
def api_create_order():
    response = require_storage_user()
    if response:
        return jsonify({"error": "authentication_required"}), 401
    client = razorpay_client()
    if not client:
        return jsonify({"error": "razorpay_not_configured", "message": "Configure Razorpay credentials and provider plan IDs first."}), 503
    try:
        plan_id = int(request.json.get("plan_id", 0))
    except (TypeError, ValueError, AttributeError):
        return jsonify({"error": "invalid_plan"}), 400
    with database_connection() as connection:
        plan = connection.execute("SELECT * FROM storage_plans WHERE id = ? AND active = 1", (plan_id,)).fetchone()
    if not plan or not plan["provider_plan_id"]:
        return jsonify({"error": "provider_plan_not_configured"}), 400
    try:
        created = client.subscription.create({"plan_id": plan["provider_plan_id"], "total_count": 12, "customer_notify": 1})
    except Exception:
        app.logger.exception("Razorpay subscription creation failed")
        return jsonify({"error": "payment_provider_error"}), 502
    user = current_user()
    now = datetime.now(timezone.utc).isoformat()
    with database_connection() as connection:
        connection.execute("""
            INSERT INTO subscriptions (user_id, plan_id, provider, provider_subscription_id, status, quota_bytes, created_at, updated_at)
            VALUES (?, ?, 'razorpay', ?, 'pending', ?, ?, ?)
        """, (user["id"], plan["id"], created["id"], plan["quota_bytes"], now, now))
    return jsonify({"key_id": RAZORPAY_KEY_ID, "subscription_id": created["id"], "plan": dict(plan)})


@app.route("/api/storage/verify-payment", methods=["POST"])
def api_verify_payment():
    response = require_storage_user()
    if response:
        return jsonify({"error": "authentication_required"}), 401
    client = razorpay_client()
    data = request.get_json(silent=True) or {}
    required = {"razorpay_payment_id", "razorpay_subscription_id", "razorpay_signature"}
    if not client or not required.issubset(data):
        return jsonify({"error": "invalid_payment_request"}), 400
    user = current_user()
    with database_connection() as connection:
        subscription = connection.execute("SELECT * FROM subscriptions WHERE provider_subscription_id = ? AND user_id = ?", (data["razorpay_subscription_id"], user["id"])).fetchone()
    if not subscription:
        return jsonify({"error": "subscription_not_found"}), 404
    try:
        client.utility.verify_payment_signature({"razorpay_payment_id": data["razorpay_payment_id"], "razorpay_subscription_id": data["razorpay_subscription_id"], "razorpay_signature": data["razorpay_signature"]})
        remote = client.subscription.fetch(data["razorpay_subscription_id"])
    except Exception:
        return jsonify({"error": "payment_verification_failed"}), 400
    if remote.get("status") not in {"active", "authenticated"}:
        return jsonify({"error": "subscription_not_active"}), 400
    plan = activate_subscription(user["id"], subscription["plan_id"], "razorpay", data["razorpay_subscription_id"])
    audit_event("payment_verified", "subscription", data["razorpay_subscription_id"], f"payment={data['razorpay_payment_id']}")
    return jsonify({"status": "active", "plan": plan, "quota_bytes": plan["quota_bytes"]})


@app.route("/api/payment/webhook", methods=["POST"])
def payment_webhook():
    raw = request.get_data()
    signature = request.headers.get("X-Razorpay-Signature", "")
    event_id = request.headers.get("x-razorpay-event-id", "")
    if not RAZORPAY_WEBHOOK_SECRET or not signature or not event_id:
        return jsonify({"error": "webhook_not_configured"}), 503
    expected = hmac.new(RAZORPAY_WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return jsonify({"error": "invalid_signature"}), 400
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return jsonify({"error": "invalid_payload"}), 400
    event_type = payload.get("event", "unknown")
    with database_connection() as connection:
        inserted = connection.execute("INSERT OR IGNORE INTO webhook_events (event_id, provider, event_type, payload, processed_at) VALUES (?, 'razorpay', ?, ?, ?)", (event_id, event_type, raw.decode("utf-8"), datetime.now(timezone.utc).isoformat())).rowcount
    if not inserted:
        return jsonify({"status": "duplicate"}), 200
    entity = payload.get("payload", {}).get("subscription", {}).get("entity", {})
    provider_id = entity.get("id")
    if provider_id:
        with database_connection() as connection:
            subscription = connection.execute("SELECT user_id, plan_id FROM subscriptions WHERE provider_subscription_id = ?", (provider_id,)).fetchone()
        if subscription and event_type in {"subscription.activated", "subscription.authenticated", "subscription.charged"}:
            activate_subscription(subscription["user_id"], subscription["plan_id"], "razorpay", provider_id)
        elif subscription and event_type in {"subscription.halted", "subscription.cancelled", "subscription.completed", "payment.failed"}:
            with database_connection() as connection:
                connection.execute("UPDATE subscriptions SET status = ?, updated_at = ? WHERE provider_subscription_id = ?", ("failed" if event_type == "payment.failed" else "cancelled", datetime.now(timezone.utc).isoformat(), provider_id))
    return jsonify({"status": "processed"}), 200


@app.route("/admin/payments")
def admin_payments():
    response = require_permission("payments.review")
    if response:
        return response
    with database_connection() as connection:
        rows = connection.execute("""
            SELECT payment_requests.*, users.username, users.email,
                   storage_plans.name AS plan_name, storage_plans.quota_bytes
            FROM payment_requests
            JOIN users ON users.id = payment_requests.user_id
            JOIN storage_plans ON storage_plans.id = payment_requests.plan_id
            WHERE payment_requests.status = 'pending'
            ORDER BY payment_requests.created_at ASC
        """).fetchall()
    return render_template_string(ADMIN_PAYMENT_PAGE, requests=[dict(row) for row in rows])


@app.route("/admin/payments/<int:payment_id>/review", methods=["POST"])
def admin_review_payment(payment_id):
    response = require_permission("payments.review")
    if response:
        return response
    decision = request.form.get("decision", "").strip().lower()
    if decision not in {"approve", "reject"}:
        abort(400, "Invalid payment decision")
    now = datetime.now(timezone.utc).isoformat()
    with database_connection() as connection:
        payment = connection.execute("""
            SELECT payment_requests.*, storage_plans.quota_bytes, storage_plans.code
            FROM payment_requests JOIN storage_plans ON storage_plans.id = payment_requests.plan_id
            WHERE payment_requests.id = ?
        """, (payment_id,)).fetchone()
        if not payment or payment["status"] != "pending":
            flash("Payment is already reviewed or does not exist.")
            return redirect(url_for("admin_payments"))
        status = "approved" if decision == "approve" else "rejected"
        connection.execute("""
            UPDATE payment_requests SET status = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ? AND status = 'pending'
        """, (status, session["user_id"], now, payment_id))
        if decision == "approve":
            connection.execute("""
                INSERT INTO subscriptions (user_id, plan_id, provider, status, quota_bytes, created_at, updated_at)
                VALUES (?, ?, 'manual_qr', 'active', ?, ?, ?)
                ON CONFLICT(provider_subscription_id) DO NOTHING
            """, (payment["user_id"], payment["plan_id"], payment["quota_bytes"], now, now))
            connection.execute("""
                INSERT INTO quotas (user_id, quota_bytes, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET quota_bytes = excluded.quota_bytes, updated_at = excluded.updated_at
            """, (payment["user_id"], payment["quota_bytes"], now))
    audit_event("payment_approved" if decision == "approve" else "payment_rejected", "payment", payment_id, f"user={payment['user_id']}; plan={payment['code']}")
    flash("Payment approved and storage allocated." if decision == "approve" else "Payment rejected.")
    return redirect(url_for("admin_payments"))


@app.route("/profile/password", methods=["POST"])
def change_password():
    response = require_login()
    if response:
        return response
    user = current_user()
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    if not verify_password(user["password_hash"], current_password):
        flash("The current password is incorrect.")
    elif len(new_password) < 8:
        flash("The new password must be at least 8 characters.")
    elif new_password != confirm_password:
        flash("The new passwords do not match.")
    else:
        with database_connection() as connection:
            connection.execute(
                """
                UPDATE users
                SET password_hash = ?, password_login_enabled = 1,
                    must_change_password = 0
                WHERE id = ?
                """,
                (hash_password(new_password), user["id"]),
            )
        audit_event("change_password", "user", user["id"], risk_level="MEDIUM")
        flash("Your password was updated successfully.")
    return redirect(url_for("profile"))


def user_statistics(user_id):
    folder = SHARED_FOLDER / "users" / str(user_id)
    files = [path for path in folder.rglob("*") if path.is_file()] if folder.exists() else []
    return len(files), sum(path.stat().st_size for path in files)


@app.route("/admin/settings", methods=["GET", "POST"])
def admin_settings():
    response = require_owner()
    if response:
        return response
    if request.method == "POST":
        try:
            retention_days = max(1, min(3650, int(request.form.get("trash_retention_days", "30"))))
            login_max_attempts = int(request.form.get("login_max_attempts", ""))
            login_window_minutes = int(request.form.get("login_window_minutes", ""))
            login_lockout_minutes = int(request.form.get("login_lockout_minutes", ""))
        except ValueError:
            abort(400, "Enter valid whole-number values for retention and login protection.")
        if not 1 <= login_max_attempts <= 100:
            abort(400, "Failed attempts must be between 1 and 100.")
        if not 1 <= login_window_minutes <= 1440:
            abort(400, "The login failure window must be between 1 and 1440 minutes.")
        if not 1 <= login_lockout_minutes <= 1440:
            abort(400, "The lockout duration must be between 1 and 1440 minutes.")
        values = {
            "allow_registration": "1" if request.form.get("allow_registration") else "0",
            "allow_public_sharing": "1" if request.form.get("allow_public_sharing") else "0",
            "allow_google_signin": "1" if request.form.get("allow_google_signin") else "0",
            "allow_github_signin": "1" if request.form.get("allow_github_signin") else "0",
            "trash_retention_days": str(retention_days),
            "login_max_attempts": str(login_max_attempts),
            "login_window_minutes": str(login_window_minutes),
            "login_lockout_minutes": str(login_lockout_minutes),
        }
        if emergency_enabled("freeze_registrations"):
            values["allow_registration"] = "0"
        if emergency_enabled("disable_file_sharing"):
            values["allow_public_sharing"] = "0"
        credential_updates = {}
        for provider in ("google", "github"):
            client_id = request.form.get(
                f"{provider}_oauth_client_id", ""
            ).strip()
            client_secret = request.form.get(
                f"{provider}_oauth_client_secret", ""
            ).strip()
            clear_credentials = bool(
                request.form.get(f"clear_{provider}_oauth_credentials")
            )
            if len(client_id) > 512 or len(client_secret) > 4096:
                abort(400, f"{provider.title()} OAuth credentials are too long.")
            if clear_credentials:
                if client_secret:
                    abort(
                        400,
                        f"Clear or update {provider.title()} credentials, not both.",
                    )
                credential_updates[provider] = None
            elif client_id or client_secret:
                current_client_id, current_client_secret = (
                    oauth_provider_credentials(provider)
                )
                client_id = client_id or current_client_id
                client_secret = client_secret or current_client_secret
                if not client_id or not client_secret:
                    abort(
                        400,
                        f"Enter both the {provider.title()} OAuth Client ID and "
                        "Client Secret to configure sign-in.",
                    )
                try:
                    encrypted_credentials = _oauth_credentials_cipher().encrypt(
                        json.dumps(
                            {
                                "client_id": client_id,
                                "client_secret": client_secret,
                            },
                            separators=(",", ":"),
                        ).encode("utf-8")
                    ).decode("ascii")
                except RuntimeError as exc:
                    abort(503, str(exc))
                credential_updates[provider] = encrypted_credentials

        now = datetime.now(timezone.utc).isoformat()
        with database_connection() as connection:
            for name, value in values.items():
                connection.execute(
                    """
                    INSERT INTO policies (name, value, updated_at, updated_by)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(name) DO UPDATE SET
                        value = excluded.value,
                        updated_at = excluded.updated_at,
                        updated_by = excluded.updated_by
                    """,
                    (name, value, now, session["user_id"]),
                )
            for provider, encrypted_credentials in credential_updates.items():
                setting_name = f"{provider}_oauth_credentials"
                if encrypted_credentials is None:
                    connection.execute(
                        "DELETE FROM policies WHERE name = ?", (setting_name,)
                    )
                else:
                    connection.execute(
                        """
                        INSERT INTO policies (name, value, updated_at, updated_by)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(name) DO UPDATE SET
                            value = excluded.value,
                            updated_at = excluded.updated_at,
                            updated_by = excluded.updated_by
                        """,
                        (
                            setting_name,
                            encrypted_credentials,
                            now,
                            session["user_id"],
                        ),
                    )
        audit_event("update_website_security_settings", "settings", "policies", json.dumps(values, sort_keys=True))
        if credential_updates:
            audit_event(
                "update_oauth_credentials",
                "settings",
                "oauth",
                ",".join(sorted(credential_updates)),
            )
        flash("Website and login security settings updated.")
    with database_connection() as connection:
        rows = connection.execute(
            """
            SELECT name, value FROM policies
            WHERE name IN (
                'allow_registration', 'allow_public_sharing', 'trash_retention_days',
                'allow_google_signin', 'allow_github_signin', 'login_max_attempts',
                'login_window_minutes', 'login_lockout_minutes'
            )
            """
        ).fetchall()
    values = {row["name"]: row["value"] for row in rows}
    login_protection = login_security_settings()
    google_client_id, _ = oauth_provider_credentials("google")
    github_client_id, _ = oauth_provider_credentials("github")
    settings = {
        "allow_registration": values.get("allow_registration", "1") == "1",
        "allow_public_sharing": values.get("allow_public_sharing", "0") == "1",
        "allow_google_signin": values.get("allow_google_signin", "1") == "1",
        "allow_github_signin": values.get("allow_github_signin", "1") == "1",
        "google_oauth_configured": oauth_credentials_configured("google"),
        "github_oauth_configured": oauth_credentials_configured("github"),
        "google_oauth_admin_managed": oauth_credentials_admin_managed("google"),
        "github_oauth_admin_managed": oauth_credentials_admin_managed("github"),
        "google_oauth_client_id": google_client_id,
        "github_oauth_client_id": github_client_id,
        "trash_retention_days": values.get("trash_retention_days", "30"),
        **login_protection,
    }
    return render_template_string(ADMIN_SETTINGS_PAGE, settings=settings)


@app.route("/admin")
def admin_panel():
    response = require_admin_access()
    if response:
        return response
    admin_context = admin_console_context()
    can_view_recovery = admin_context["can_view_recovery"]
    cutoff = datetime.now(timezone.utc) - timedelta(days=INACTIVE_USER_DAYS)
    users = []
    with database_connection() as connection:
        total_users = connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        active_users = connection.execute("SELECT COUNT(*) AS count FROM users WHERE status = 'active'").fetchone()["count"]
        new_users = connection.execute("SELECT COUNT(*) AS count FROM users WHERE created_at >= ?", ((datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),)).fetchone()["count"]
        pending_reviews = connection.execute("SELECT (SELECT COUNT(*) FROM password_requests WHERE status = 'pending') + (SELECT COUNT(*) FROM payment_requests WHERE status = 'pending') AS count").fetchone()["count"]
        failed_logins = connection.execute("SELECT COUNT(*) AS count FROM login_attempts WHERE success = 0 AND attempted_at >= ?", ((datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),)).fetchone()["count"]
        open_alerts = connection.execute("SELECT COUNT(*) AS count FROM security_alerts WHERE status = 'open'").fetchone()["count"]
        recent_events = connection.execute("SELECT audit_events.*, users.username AS actor FROM audit_events LEFT JOIN users ON users.id = audit_events.actor_id ORDER BY audit_events.created_at DESC LIMIT 12").fetchall()
        provider_counts_row = connection.execute(
            """
            SELECT COUNT(*) AS total,
                SUM(CASE WHEN password_login_enabled = 1 THEN 1 ELSE 0 END) AS password,
                SUM(CASE WHEN google_sub IS NOT NULL THEN 1 ELSE 0 END) AS google,
                SUM(CASE WHEN github_sub IS NOT NULL THEN 1 ELSE 0 END) AS github
            FROM users
            """
        ).fetchone()
        provider_counts = {
            key: provider_counts_row[column] or 0
            for key, column in (
                ("all", "total"),
                ("password", "password"),
                ("google", "google"),
                ("github", "github"),
            )
        }
        account_type = request.args.get("account_type", "all")
        if account_type not in ADMIN_ACCOUNT_FILTERS:
            abort(400, "Invalid account type filter")
        rows = connection.execute(
            f"""
            SELECT id, username, created_at, last_seen, is_admin, status, email,
                password_login_enabled, google_sub, google_email,
                google_profile_name, google_username, google_picture,
                github_sub, github_email, github_profile_name,
                github_username, github_picture
            FROM users
            ORDER BY is_admin DESC, username COLLATE NOCASE
            """
        ).fetchall()
        recovery_rows = connection.execute("""
                 SELECT password_requests.id, users.username, users.email AS account_email,
                     users.mobile AS account_mobile, users.date_of_birth AS account_dob,
                     password_requests.email, password_requests.mobile, password_requests.date_of_birth,
                   password_requests.created_at
            FROM password_requests
            JOIN users ON users.id = password_requests.user_id
            WHERE password_requests.status = 'pending'
            ORDER BY password_requests.created_at ASC
        """).fetchall() if can_view_recovery else []
    total_files = 0
    total_bytes = 0
    for row in rows:
        try:
            inactive = not row["last_seen"] or datetime.fromisoformat(row["last_seen"]) < cutoff
        except ValueError:
            inactive = True
        files, bytes_used = user_statistics(row["id"])
        total_files += files
        total_bytes += bytes_used
        if (
            account_type == "password" and not row["password_login_enabled"]
            or account_type == "google" and not row["google_sub"]
            or account_type == "github" and not row["github_sub"]
        ):
            continue
        user = dict(row)
        auth_methods = []
        if user["password_login_enabled"]:
            auth_methods.append("Password")
        if user["google_sub"]:
            auth_methods.append("Google")
        if user["github_sub"]:
            auth_methods.append("GitHub")
        user.update(
            inactive=inactive,
            files=files,
            bytes=bytes_used,
            auth_methods=auth_methods or ["Unavailable"],
            picture_url=user["google_picture"] or user["github_picture"],
        )
        users.append(user)
    dashboard = {"total_users": total_users, "active_users": active_users, "new_users": new_users, "pending_reviews": pending_reviews, "inactive_users": total_users - active_users, "total_files": total_files, "total_bytes": total_bytes, "failed_logins": failed_logins, "open_alerts": open_alerts, "read_only": emergency_enabled("global_read_only"), "uploads_disabled": emergency_enabled("disable_uploads"), "downloads_disabled": emergency_enabled("disable_downloads"), "maintenance": emergency_enabled("maintenance_mode")}
    return render_template_string(
        ADMIN_PAGE,
        title=admin_context["admin_title"],
        users=users,
        current_user_id=session["user_id"],
        inactive_days=INACTIVE_USER_DAYS,
        recovery_requests=[dict(row) for row in recovery_rows],
        dashboard=dashboard,
        recent_events=[dict(row) for row in recent_events],
        provider_counts=provider_counts,
        account_type=account_type,
        **admin_context,
    )


@app.route("/admin/users/report.csv")
def admin_user_report():
    response = require_permission("users.view")
    if response:
        return response

    account_type = request.args.get("account_type", "all")
    if account_type not in ADMIN_ACCOUNT_FILTERS:
        abort(400, "Invalid account type filter")

    with database_connection() as connection:
        rows = connection.execute(
            f"""
            SELECT username, email, password_login_enabled,
                google_sub, google_email, google_profile_name, google_username,
                github_sub, github_email, github_profile_name, github_username,
                created_at, last_login_at, last_seen, status
            FROM users
            {ADMIN_ACCOUNT_FILTERS[account_type]}
            ORDER BY username COLLATE NOCASE
            """
        ).fetchall()

    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(
        (
            "Cloud Rdx username",
            "Cloud Rdx email",
            "Sign-in methods",
            "Google profile",
            "Google email",
            "GitHub username",
            "GitHub email",
            "Created at",
            "Last login",
            "Last seen",
            "Status",
        )
    )
    for row in rows:
        methods = []
        if row["password_login_enabled"]:
            methods.append("Password")
        if row["google_sub"]:
            methods.append("Google")
        if row["github_sub"]:
            methods.append("GitHub")
        values = (
            row["username"],
            row["email"],
            " + ".join(methods) or "Unavailable",
            row["google_username"] or row["google_profile_name"],
            row["google_email"],
            row["github_username"] or row["github_profile_name"],
            row["github_email"],
            row["created_at"],
            row["last_login_at"],
            row["last_seen"],
            row["status"],
        )
        writer.writerow([spreadsheet_safe_cell(value) for value in values])

    report = make_response(output.getvalue())
    report.headers["Content-Type"] = "text/csv; charset=utf-8"
    report.headers["Content-Disposition"] = 'attachment; filename="cloud-rdx-users.csv"'
    report.headers["Cache-Control"] = "no-store"
    return report


@app.route("/admin/profit")
def admin_profit():
    response = require_owner()
    if response:
        return response
    cutoff = datetime.now(timezone.utc) - timedelta(days=INACTIVE_USER_DAYS)
    with database_connection() as connection:
        users = connection.execute(
            "SELECT id, status, created_at, last_seen FROM users WHERE username != ? COLLATE NOCASE",
            (ADMIN_USERNAME,),
        ).fetchall()
        payment_totals = connection.execute("""
            SELECT
                COALESCE(SUM(CASE WHEN status = 'approved' THEN amount_paise ELSE 0 END), 0) AS approved_paise,
                COALESCE(SUM(CASE WHEN status = 'pending' THEN amount_paise ELSE 0 END), 0) AS pending_paise,
                COALESCE(SUM(CASE WHEN status = 'rejected' THEN amount_paise ELSE 0 END), 0) AS rejected_paise,
                SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved_count,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_count,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected_count
            FROM payment_requests
        """).fetchone()
        active_subscriptions = connection.execute("""
            SELECT COUNT(*) AS count
            FROM subscriptions
            JOIN users ON users.id = subscriptions.user_id
            WHERE subscriptions.status = 'active' AND users.username != ? COLLATE NOCASE
        """, (ADMIN_USERNAME,)).fetchone()["count"]
        active_sessions = connection.execute("""
            SELECT COUNT(*) AS count FROM device_sessions
            JOIN users ON users.id = device_sessions.user_id
            WHERE device_sessions.revoked_at IS NULL AND users.username != ? COLLATE NOCASE
        """, (ADMIN_USERNAME,)).fetchone()["count"]
        plan_rows_for_summary = connection.execute("""
            SELECT storage_plans.name, storage_plans.price_paise,
                   COUNT(subscriptions.id) AS subscribers,
                   COALESCE(SUM(subscriptions.quota_bytes), 0) AS capacity
            FROM storage_plans
            LEFT JOIN subscriptions
              ON subscriptions.plan_id = storage_plans.id AND subscriptions.status = 'active'
            WHERE storage_plans.active = 1
            GROUP BY storage_plans.id
            ORDER BY storage_plans.quota_bytes
        """).fetchall()

    total_users = len(users)
    active_users = 0
    suspended_users = 0
    new_users = 0
    total_files = 0
    used_bytes = 0
    quota_bytes = 0
    for user in users:
        try:
            recently_seen = bool(user["last_seen"] and datetime.fromisoformat(user["last_seen"]) >= cutoff)
        except ValueError:
            recently_seen = False
        if user["status"] == "active" and recently_seen:
            active_users += 1
        if user["status"] == "suspended":
            suspended_users += 1
        try:
            if datetime.fromisoformat(user["created_at"]) >= datetime.now(timezone.utc) - timedelta(days=30):
                new_users += 1
        except (TypeError, ValueError):
            pass
        files, bytes_used = user_statistics(user["id"])
        total_files += files
        used_bytes += bytes_used
        quota_bytes += user_quota(user["id"])

    revenue = payment_totals["approved_paise"] / 100
    pending_revenue = payment_totals["pending_paise"] / 100
    rejected_revenue = payment_totals["rejected_paise"] / 100
    used_gb = used_bytes / (1024 ** 3)
    estimated_cost = used_gb * STORAGE_COST_PER_GB_INR
    capacity_percent = min(100, round(used_bytes * 100 / quota_bytes, 1)) if quota_bytes else 0
    plan_summary = [dict(row) for row in plan_rows_for_summary]
    monthly_plan_value = sum(row["price_paise"] * row["subscribers"] for row in plan_summary) / 100
    metrics = {
        "revenue": revenue,
        "estimated_cost": estimated_cost,
        "net_profit": revenue - estimated_cost,
        "pending_revenue": pending_revenue,
        "pending_payments": int(payment_totals["pending_count"] or 0),
        "approved_payments": int(payment_totals["approved_count"] or 0),
        "rejected_payments": int(payment_totals["rejected_count"] or 0),
        "rejected_revenue": rejected_revenue,
        "total_users": total_users,
        "active_users": active_users,
        "inactive_users": total_users - active_users,
        "suspended_users": suspended_users,
        "new_users": new_users,
        "active_sessions": active_sessions,
        "used_bytes": used_bytes,
        "quota_bytes": quota_bytes,
        "remaining_bytes": max(0, quota_bytes - used_bytes),
        "total_files": total_files,
        "average_usage": used_bytes / total_users if total_users else 0,
        "capacity_percent": capacity_percent,
        "active_subscriptions": active_subscriptions,
        "monthly_plan_value": monthly_plan_value,
        "cost_per_gb": STORAGE_COST_PER_GB_INR,
    }
    return render_template_string(
        ADMIN_PROFIT_PAGE,
        metrics=metrics,
        plan_summary=plan_summary,
        inactive_days=INACTIVE_USER_DAYS,
        owner_username=ADMIN_USERNAME,
    )


@app.route("/admin/intelligence")
def admin_intelligence():
    response = require_owner()
    if response:
        return response
    return render_template_string(
        ADMIN_INTELLIGENCE_PAGE,
        ranges=(
            ("24h", "24 hours"),
            ("7d", "7 days"),
            ("30d", "30 days"),
            ("180d", "6 months"),
            ("365d", "1 year"),
        ),
    )


@app.route("/api/admin/analytics/overview")
def admin_analytics_overview():
    response = require_owner()
    if response:
        return jsonify({"error": "administrator_required"}), 401
    cutoff_active = (
        datetime.now(timezone.utc) - timedelta(days=INACTIVE_USER_DAYS)
    ).isoformat()
    cutoff_login = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    with database_connection() as connection:
        users = connection.execute(
            """
            SELECT id, username, status, created_at, last_seen
            FROM users WHERE username != ? COLLATE NOCASE
            ORDER BY username COLLATE NOCASE
            """,
            (ADMIN_USERNAME,),
        ).fetchall()
        session_count = connection.execute(
            """
            SELECT COUNT(*) AS count FROM device_sessions
            JOIN users ON users.id = device_sessions.user_id
            WHERE device_sessions.revoked_at IS NULL
              AND users.username != ? COLLATE NOCASE
            """,
            (ADMIN_USERNAME,),
        ).fetchone()["count"]
        payment = connection.execute(
            """
            SELECT COALESCE(SUM(amount_paise), 0) AS amount,
                   COUNT(*) AS count
            FROM payment_requests WHERE status = 'approved'
            """
        ).fetchone()
        failed_logins = connection.execute(
            """
            SELECT COUNT(*) AS count FROM login_attempts
            WHERE success = 0 AND attempted_at >= ?
            """,
            (cutoff_login,),
        ).fetchone()["count"]
        open_alerts = connection.execute(
            "SELECT COUNT(*) AS count FROM security_alerts WHERE status = 'open'"
        ).fetchone()["count"]
        now_epoch = int(datetime.now(timezone.utc).timestamp())
        api_requests = connection.execute(
            """
            SELECT COALESCE(SUM(request_count), 0) AS count,
                   COALESCE(SUM(blocked_count), 0) AS blocked
            FROM rate_limit_buckets
            WHERE endpoint = 'api' AND window_started_at >= ?
            """,
            (now_epoch - 86400,),
        ).fetchone()

    categories = {
        "Images": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".heic"},
        "Videos": {".mp4", ".mov", ".avi", ".mkv", ".webm", ".m4v"},
        "Audio": {".mp3", ".wav", ".aac", ".flac", ".ogg", ".m4a"},
        "Documents": {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv"},
        "Archives": {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"},
        "Applications": {".exe", ".msi", ".apk", ".app", ".deb", ".rpm"},
    }
    category_totals = {
        name: {"category": name, "files": 0, "bytes": 0}
        for name in (*categories, "Other")
    }
    total_files = 0
    total_bytes = 0
    total_quota = 0
    active_users = 0
    top_storage = []
    for user in users:
        files = 0
        used = 0
        root = SHARED_FOLDER / "users" / str(user["id"])
        if root.exists():
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                try:
                    file_size = path.stat().st_size
                except OSError:
                    app.logger.warning("analytics_file_stat_failed path=%s", path.name)
                    continue
                files += 1
                used += file_size
                suffix = path.suffix.lower()
                category = next(
                    (name for name, extensions in categories.items() if suffix in extensions),
                    "Other",
                )
                category_totals[category]["files"] += 1
                category_totals[category]["bytes"] += file_size
        total_files += files
        total_bytes += used
        total_quota += user_quota(user["id"])
        if user["status"] == "active" and user["last_seen"] and user["last_seen"] >= cutoff_active:
            active_users += 1
        top_storage.append(
            {"username": user["username"], "files": files, "bytes": used}
        )
    top_storage.sort(key=lambda item: item["bytes"], reverse=True)
    storage_percent = (
        round(total_bytes * 100 / total_quota, 1) if total_quota else None
    )
    cost = (
        total_bytes / (1024**3) * STORAGE_COST_PER_GB_INR
        if os.getenv("STORAGE_COST_PER_GB_INR") is not None
        else None
    )
    try:
        disk_free = shutil.disk_usage(SHARED_FOLDER).free
    except OSError:
        app.logger.exception("analytics_host_disk_usage_failed")
        disk_free = None
    controls = emergency_control_state()
    active_control_count = sum(controls.values())
    if controls["maintenance_mode"]:
        status = "MAINTENANCE"
    elif controls["global_read_only"] and controls["disable_downloads"]:
        status = "LOCKDOWN"
    elif controls["enhanced_monitoring"] or open_alerts:
        status = "SECURITY ALERT"
    elif active_control_count:
        status = "RESTRICTED"
    else:
        status = "NORMAL"
    return jsonify(
        {
            "status": status,
            "users": {
                "total": len(users),
                "active": active_users,
                "inactive": max(0, len(users) - active_users),
                "top_storage": top_storage[:5],
            },
            "sessions": {"active": session_count},
            "storage": {
                "used_bytes": total_bytes,
                "quota_bytes": total_quota,
                "files": total_files,
                "remaining_bytes": max(0, total_quota - total_bytes),
                "utilization_percent": storage_percent,
                "categories": list(category_totals.values()),
            },
            "finance": {
                "collected_revenue": payment["amount"] / 100,
                "approved_payment_count": payment["count"],
                "estimated_storage_cost": cost,
                "estimated_net": None,
                "cost_basis": (
                    "configured_per_gb_estimate"
                    if cost is not None
                    else "unavailable"
                ),
            },
            "security": {
                "failed_logins_24h": failed_logins,
                "open_alerts": open_alerts,
                "api_requests_24h": int(api_requests["count"]),
                "blocked_api_requests_24h": int(api_requests["blocked"]),
            },
            "host": {"disk_free_bytes": disk_free},
            "data_availability": {
                "bandwidth": False,
                "geography": False,
                "cpu": False,
                "memory": False,
                "request_latency": False,
                "scheduled_backups": False,
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    )


@app.route("/api/admin/analytics/activity")
def admin_analytics_activity():
    response = require_owner()
    if response:
        return jsonify({"error": "administrator_required"}), 401
    range_key = request.args.get("range", "7d")
    range_days = {"24h": 1, "7d": 7, "30d": 30, "180d": 180, "365d": 365}
    if range_key not in range_days:
        return jsonify({"error": "invalid_range"}), 400
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=range_days[range_key])
    with database_connection() as connection:
        grouping = "substr(created_at, 1, 13)" if range_key == "24h" else "substr(created_at, 1, 10)"
        rows = connection.execute(
            f"""
            SELECT {grouping} AS bucket, COUNT(*) AS operations
            FROM audit_events
            WHERE created_at >= ?
              AND action IN ('upload', 'bulk_download', 'create_folder',
                             'rename', 'copy', 'move', 'delete',
                             'restore_from_trash', 'restore_own_trash',
                             'purge_trash', 'purge_own_trash', 'login',
                             'google_login', 'github_login')
            GROUP BY bucket ORDER BY bucket
            """,
            (cutoff.isoformat(),),
        ).fetchall()
    points = [
        {"time": row["bucket"], "operations": int(row["operations"])}
        for row in rows
    ]
    labels = {
        "24h": "24 hours",
        "7d": "7 days",
        "30d": "30 days",
        "180d": "6 months",
        "365d": "1 year",
    }
    return jsonify(
        {
            "range": range_key,
            "range_label": labels[range_key],
            "points": points,
            "total_operations": sum(point["operations"] for point in points),
            "source": "audit_events",
        }
    )


@app.route("/admin/manage")
def admin_manage():
    response = require_permission("users.manage")
    if response:
        return response
    cutoff = datetime.now(timezone.utc) - timedelta(days=INACTIVE_USER_DAYS)
    with database_connection() as connection:
        rows = connection.execute("SELECT id, username, status, is_admin FROM users ORDER BY username COLLATE NOCASE").fetchall()
        groups = connection.execute("""
            SELECT groups.id, groups.name, groups.description, COUNT(group_members.user_id) AS members
            FROM groups LEFT JOIN group_members ON group_members.group_id = groups.id
            GROUP BY groups.id ORDER BY groups.name COLLATE NOCASE
        """).fetchall()
        events = connection.execute("""
            SELECT audit_events.*, users.username AS actor
            FROM audit_events LEFT JOIN users ON users.id = audit_events.actor_id
            ORDER BY audit_events.created_at DESC LIMIT 100
        """).fetchall()
        role_rows = connection.execute("""
            SELECT user_roles.user_id, roles.name FROM user_roles JOIN roles ON roles.id = user_roles.role_id
        """).fetchall()
        roles = connection.execute("SELECT name, description FROM roles WHERE name != ? ORDER BY name", (ADMIN_ROLE,)).fetchall()
    roles_by_user = {}
    for row in role_rows:
        roles_by_user.setdefault(row["user_id"], []).append(row["name"])
    users = []
    for row in rows:
        files, bytes_used = user_usage(row["id"])
        quota = user_quota(row["id"])
        users.append({**dict(row), "files": files, "bytes": bytes_used, "quota_mb": quota // (1024 * 1024), "roles": roles_by_user.get(row["id"], [])})
    return render_template_string(
        ADMIN_MANAGEMENT_PAGE,
        users=users,
        groups=[dict(row) for row in groups],
        roles=[dict(row) for row in roles],
        events=[dict(row) for row in events],
        owner_username=ADMIN_USERNAME,
        is_owner=is_owner(),
    )


@app.route("/admin/permissions")
def admin_permissions():
    response = require_owner()
    if response:
        return response
    permission_catalog = (
        ("users.view", "View user accounts"),
        ("users.manage", "Activate, suspend, and manage users"),
        ("users.recovery", "Review password recovery requests"),
        ("storage.manage", "Manage storage quotas and files"),
        ("storage.recycle_bin", "Restore and purge recycle-bin items"),
        ("payments.review", "Review storage payments"),
        ("audit.view", "View audit activity"),
        ("storage.upload", "Upload files"),
        ("storage.download", "Download files"),
        ("storage.share", "Share files"),
        ("storage.delete", "Delete files"),
        ("storage.rename", "Rename files"),
        ("storage.create_folder", "Create folders"),
        ("security.manage", "Manage security controls"),
        ("settings.manage", "Manage system settings"),
    )
    with database_connection() as connection:
        rows = connection.execute("SELECT id, name, description FROM roles WHERE name != ? ORDER BY name", (ADMIN_ROLE,)).fetchall()
        assigned = connection.execute("SELECT role_id, permission FROM role_permissions").fetchall()
    assigned_by_role = {}
    for row in assigned:
        assigned_by_role.setdefault(row["role_id"], set()).add(row["permission"])
    roles = [{**dict(row), "permissions": assigned_by_role.get(row["id"], set())} for row in rows]
    permissions = [{"key": key, "label": label} for key, label in permission_catalog]
    return render_template_string(ADMIN_PERMISSIONS_PAGE, roles=roles, permissions=permissions)


@app.route("/admin/permissions/<int:role_id>", methods=["POST"])
def admin_role_permissions(role_id):
    response = require_owner()
    if response:
        return response
    allowed = {"users.view", "users.manage", "users.recovery", "storage.manage", "storage.recycle_bin", "payments.review", "audit.view", "storage.upload", "storage.download", "storage.share", "storage.delete", "storage.rename", "storage.create_folder", "security.manage", "settings.manage"}
    selected = set(request.form.getlist("permissions")) & allowed
    now = datetime.now(timezone.utc).isoformat()
    with database_connection() as connection:
        role = connection.execute("SELECT id, name FROM roles WHERE id = ? AND name != ?", (role_id, ADMIN_ROLE)).fetchone()
        if not role:
            abort(404, "Delegated role not found")
        connection.execute("DELETE FROM role_permissions WHERE role_id = ?", (role_id,))
        connection.executemany("INSERT INTO role_permissions (role_id, permission, assigned_at, assigned_by) VALUES (?, ?, ?, ?)", [(role_id, permission, now, session["user_id"]) for permission in sorted(selected)])
    audit_event("update_role_permissions", "role", role_id, f"role={role['name']}; permissions={','.join(sorted(selected))}")
    flash(f"Permissions updated for {role['name']}.")
    return redirect(url_for("admin_permissions"))


@app.route("/admin/roles/create", methods=["POST"])
def admin_role_create():
    response = require_owner()
    if response:
        return response
    name = request.form.get("name", "").strip().lower()
    description = request.form.get("description", "").strip()
    if not name or not re.fullmatch(r"[a-z0-9_-]{2,48}", name) or name == ADMIN_ROLE:
        flash("Role names must be 2-48 characters using letters, numbers, underscores, or hyphens.")
        return redirect(url_for("admin_permissions"))
    try:
        with database_connection() as connection:
            connection.execute("INSERT INTO roles (name, description) VALUES (?, ?)", (name, description[:160]))
    except sqlite3.IntegrityError:
        flash("That role already exists.")
    else:
        audit_event("create_role", "role", name, description)
        flash(f"Role {name} created.")
    return redirect(url_for("admin_permissions"))


ADMIN_SECURITY_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Security center - Cloud Rdx</title><link rel="stylesheet" href="{{ url_for('static', filename='admin-theme.css') }}"></head>
<body class="admin-theme"><main class="main"><header class="topbar"><div><p class="eyebrow">Cloud Rdx / security</p><h1>Security center</h1><p class="subtitle">Defensive monitoring based on authentication and audit telemetry.</p></div><a class="button" href="{{ url_for('admin_panel') }}">Dashboard</a></header>
{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="flash">{{ message }}</div>{% endfor %}{% endwith %}
<section class="panel"><div class="panel-head"><h2>Open alerts</h2><p>Review suspicious activity without exposing passwords or credentials.</p></div><div class="table-responsive"><table><thead><tr><th>Severity</th><th>Type</th><th>Account / IP</th><th>Details</th><th>Created</th><th></th></tr></thead><tbody>{% for alert in alerts %}<tr><td>{{ alert.severity }}</td><td>{{ alert.alert_type }}</td><td>{{ alert.username or 'Unknown' }}<br>{{ alert.ip_address or 'Unknown' }}</td><td>{{ alert.details }}</td><td>{{ alert.created_at|prettydate }}</td><td><form method="post" action="{{ url_for('admin_security_alert_review', alert_id=alert.id) }}"><button type="submit">Mark reviewed</button></form></td></tr>{% else %}<tr><td colspan="6">No open security alerts.</td></tr>{% endfor %}</tbody></table></div></section>
<section class="panel"><div class="panel-head"><h2>Rate-limit events (last 24 hours)</h2><p>Aggregate counts only; client identifiers are stored as keyed hashes.</p></div><div class="table-responsive"><table><thead><tr><th>Endpoint group</th><th>Scope</th><th>Requests</th><th>Blocked</th><th>Latest window</th></tr></thead><tbody>{% for item in rate_limits %}<tr><td>{{ item.endpoint }}</td><td>{{ item.scope }}</td><td>{{ item.requests }}</td><td>{{ item.blocked }}</td><td>{{ item.last_event|prettydate }}</td></tr>{% else %}<tr><td colspan="5">No rate-limit events recorded.</td></tr>{% endfor %}</tbody></table></div></section>
</main></body></html>
"""


@app.route("/admin/security")
def admin_security():
    response = require_owner()
    if response:
        return response
    with database_connection() as connection:
        alerts = connection.execute("SELECT * FROM security_alerts WHERE status = 'open' ORDER BY created_at DESC LIMIT 250").fetchall()
        cutoff = int(datetime.now(timezone.utc).timestamp()) - 86400
        rate_limit_rows = connection.execute(
            """
            SELECT endpoint, scope, SUM(request_count) AS requests,
                   SUM(blocked_count) AS blocked, MAX(window_started_at) AS last_event
            FROM rate_limit_buckets
            WHERE blocked_count > 0 AND window_started_at >= ?
            GROUP BY endpoint, scope
            ORDER BY last_event DESC
            LIMIT 50
            """,
            (cutoff,),
        ).fetchall()
    rate_limits = [
        {
            **dict(row),
            "last_event": datetime.fromtimestamp(row["last_event"], timezone.utc).isoformat(),
        }
        for row in rate_limit_rows
    ]
    return render_template_string(
        ADMIN_SECURITY_PAGE, alerts=[dict(row) for row in alerts], rate_limits=rate_limits
    )


@app.route("/admin/security/alerts/<int:alert_id>/review", methods=["POST"])
def admin_security_alert_review(alert_id):
    response = require_owner()
    if response:
        return response
    with database_connection() as connection:
        result = connection.execute("UPDATE security_alerts SET status = 'reviewed', reviewed_by = ?, reviewed_at = ? WHERE id = ? AND status = 'open'", (session["user_id"], datetime.now(timezone.utc).isoformat(), alert_id))
    if not result.rowcount:
        abort(404, "Security alert not found")
    audit_event("review_security_alert", "security_alert", alert_id)
    flash("Security alert marked as reviewed.")
    return redirect(url_for("admin_security"))


ADMIN_EMERGENCY_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Emergency Control Centre - Cloud Rdx</title>
<link rel="stylesheet" href="{{ url_for('static', filename='admin-theme.css') }}">
<style>
.emergency{--ec-bg:#0b1220;--ec-panel:#111c2d;--ec-line:#24344d;--ec-text:#e7eef9;--ec-muted:#9aabc2;max-width:1500px;margin:0 auto;color:var(--ec-text)}
.emergency .topbar{margin-bottom:24px;background:#111c2d;border:1px solid var(--ec-line);border-radius:14px}
.emergency .eyebrow{color:#61d5c4}.emergency h1{color:#f4f7fb}.emergency .subtitle,.emergency .muted{color:var(--ec-muted)}
.emergency .panel,.emergency .card{margin-bottom:18px;color:var(--ec-text);background:var(--ec-panel);border:1px solid var(--ec-line);border-radius:14px;box-shadow:0 12px 32px #02061755}
.emergency .panel-head,.emergency .head{border-color:var(--ec-line)}.emergency .panel-head h2,.emergency .head h2{color:#f4f7fb}
.ec-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;padding:18px}
.ec-stat{padding:16px;background:#0d1727;border:1px solid #263750;border-radius:11px}.ec-stat small{display:block;color:var(--ec-muted);font-size:10px;letter-spacing:.08em;text-transform:uppercase}.ec-stat strong{display:block;margin-top:8px;font-size:22px}.ec-status{display:flex;align-items:center;gap:10px;padding:18px 22px;border-bottom:1px solid var(--ec-line)}
.ec-dot{width:11px;height:11px;flex:0 0 11px;background:#34d399;border-radius:50%;box-shadow:0 0 14px currentColor}.ec-dot.restricted{background:#fbbf24}.ec-dot.security{background:#fb923c}.ec-dot.lockdown,.ec-dot.maintenance{background:#fb7185}
.ec-presets{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;padding:18px}
.ec-preset{min-height:74px;color:#eff6ff!important;background:#17243a!important;border-color:#32445f!important;border-radius:10px!important;text-align:left}
.ec-preset:hover{background:#233653!important;transform:translateY(-2px)}.ec-preset.danger{background:#552338!important;border-color:#a13e5c!important}
.ec-controls{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;padding:18px}
.ec-control{display:flex;justify-content:space-between;align-items:center;gap:12px;min-height:84px;padding:14px;background:#0d1727;border:1px solid #263750;border-radius:10px}
.ec-control strong{display:block;font-size:13px}.ec-control small{display:block;margin-top:5px;color:var(--ec-muted);font:11px/1.4 Arial,sans-serif}
.ec-control input[type=checkbox]{width:20px;height:20px;flex:0 0 20px;accent-color:#fb7185}.ec-control input:disabled{opacity:.4}
.ec-control.unavailable{opacity:.72;border-style:dashed}
.ec-form-footer{display:flex;flex-wrap:wrap;gap:10px;align-items:end;padding:0 18px 18px}
.ec-form-footer label,.incident-form label{display:grid;gap:6px;color:var(--ec-muted);font-size:11px}.ec-form-footer input,.incident-form input,.incident-form select,.incident-form textarea,.ec-note{color:var(--ec-text)!important;background:#0b1423!important;border-color:#354962!important}
.incident-form{display:grid;grid-template-columns:1.2fr .7fr 1fr;gap:12px;padding:18px}.incident-form .wide{grid-column:1/-1}.incident-form textarea{min-height:80px;resize:vertical}
.ec-freeze-forms{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;padding:18px}
.ec-freeze-forms form{display:grid;gap:10px;padding:14px;background:#0d1727;border:1px solid #263750;border-radius:10px}
.ec-severity{font-weight:800}.sev-LOW{color:#34d399}.sev-MEDIUM{color:#fbbf24}.sev-HIGH{color:#fb923c}.sev-CRITICAL{color:#fb7185}
.ec-incidents{display:grid;gap:12px;padding:18px}.ec-incident{padding:16px;background:#0d1727;border:1px solid #263750;border-radius:11px}
.ec-incident-head{display:flex;justify-content:space-between;gap:12px;align-items:start}.ec-incident h3{margin:0 0 6px;font-size:15px}.ec-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}.ec-actions form{display:flex;gap:7px;align-items:center}
.ec-log-wrap{overflow:auto}.ec-log{min-width:860px}.ec-log td,.ec-log th{color:#dce6f5;border-color:#24344d}.ec-log th{background:#162339}.ec-log tr:hover td{background:#162339}
.ec-empty{padding:20px;color:var(--ec-muted);text-align:center}.ec-service-list{display:flex;flex-wrap:wrap;gap:9px}.ec-service-list label{display:flex;grid-auto-flow:column;align-items:center;gap:5px}
.ec-note{min-width:180px;padding:8px;border:1px solid;border-radius:6px}
.emergency dialog{width:min(520px,calc(100% - 28px));color:#e7eef9;background:#111c2d;border:1px solid #fb7185;border-radius:14px;box-shadow:0 20px 70px #000a}
.emergency dialog::backdrop{background:#020617c9;backdrop-filter:blur(3px)}.ec-dialog-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}
.emergency button.danger{background:#b42345!important;border-color:#d44965!important}.emergency :where(a,button,input,select,textarea):focus-visible{outline:3px solid #5eead4;outline-offset:3px}
@media(max-width:1000px){.ec-controls{grid-template-columns:repeat(2,minmax(0,1fr))}.ec-presets{grid-template-columns:repeat(3,minmax(0,1fr))}.ec-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:650px){.emergency{padding:0 6px}.emergency .topbar{display:grid;gap:12px;padding:16px}.ec-controls,.ec-grid,.ec-presets,.ec-freeze-forms{grid-template-columns:1fr}.incident-form{grid-template-columns:1fr}.incident-form .wide{grid-column:auto}.ec-incident-head{display:grid}.ec-form-footer{display:grid}.ec-form-footer>*{width:100%}}
@media(prefers-reduced-motion:reduce){.emergency *{scroll-behavior:auto!important;transition:none!important;animation:none!important}}
</style></head>
<body class="admin-theme"><main class="main emergency">
<header class="topbar"><div><p class="eyebrow">CLOUD RDX / SECURITY OPERATIONS</p><h1>Emergency Control Centre</h1>
<p class="subtitle">Owner-only response controls, incident tracking, and a durable action ledger.</p></div>
<a class="button" href="{{ url_for('admin_panel') }}">Dashboard</a></header>
{% with messages=get_flashed_messages() %}{% for message in messages %}<div class="flash" role="status">{{ message }}</div>{% endfor %}{% endwith %}
<section class="panel" aria-labelledby="system-status-heading">
<div class="ec-status"><span class="ec-dot {{ status_class }}" aria-hidden="true"></span><div><strong id="system-status-heading">SYSTEM STATUS · {{ system_status }}</strong><div class="muted">Last emergency action: {{ last_action or 'No emergency action recorded' }} · Admin: {{ last_admin or '—' }}</div></div></div>
<div class="ec-grid">
<article class="ec-stat"><small>Active controls</small><strong>{{ active_controls|length }}</strong></article>
<article class="ec-stat"><small>Affected user accounts</small><strong>{{ metrics.users }}</strong></article>
<article class="ec-stat"><small>Emergency-frozen accounts</small><strong>{{ metrics.frozen_accounts }}</strong></article>
<article class="ec-stat"><small>Active sessions</small><strong>{{ metrics.sessions }}</strong></article>
<article class="ec-stat"><small>Active incidents</small><strong>{{ metrics.incidents }}</strong></article>
<article class="ec-stat"><small>Blocked uploads</small><strong>{{ metrics.blocked_uploads }}</strong></article>
<article class="ec-stat"><small>Blocked downloads</small><strong>{{ metrics.blocked_downloads }}</strong></article>
<article class="ec-stat"><small>Blocked API requests</small><strong>{{ metrics.blocked_api }}</strong></article>
<article class="ec-stat"><small>Open security alerts</small><strong>{{ metrics.alerts }}</strong></article>
</div></section>

<section class="panel"><div class="panel-head"><h2>Emergency account freezes</h2><p>Freeze a single active account or eligible members of a group. Admin accounts and accounts already frozen/suspended are excluded. Restoring a freeze only reactivates accounts that were active before the freeze.</p></div>
<div class="ec-freeze-forms">
<form method="post" data-confirm="Freeze this user account? The user will be signed out and blocked from signing in until restored.">
<input type="hidden" name="action" value="freeze_accounts"><input type="hidden" name="scope" value="account">
<label>Account<select name="user_id" required><option value="">Select an active user</option>{% for target in freeze_targets %}<option value="{{ target.id }}">{{ target.username }}</option>{% endfor %}</select></label>
<label class="wide">Reason<input name="reason" maxlength="1000" required placeholder="Incident or security reason"></label>
<button class="danger" type="submit"{% if not freeze_targets %} disabled{% endif %}>Freeze account</button></form>
<form method="post" data-confirm="Freeze all eligible active non-admin members of this group?">
<input type="hidden" name="action" value="freeze_accounts"><input type="hidden" name="scope" value="group">
<label>Group<select name="group_id" required><option value="">Select a group</option>{% for group in freeze_groups %}<option value="{{ group.id }}">{{ group.name }} · {{ group.eligible_members }} eligible</option>{% endfor %}</select></label>
<label class="wide">Reason<input name="reason" maxlength="1000" required placeholder="Incident or security reason"></label>
<button class="danger" type="submit"{% if not freeze_groups %} disabled{% endif %}>Freeze group members</button></form>
</div>
<div class="ec-incidents">{% for freeze in freeze_batches %}<article class="ec-incident"><div class="ec-incident-head"><div><strong>{{ freeze.group_name or 'Individual account freeze' }}</strong><div class="muted">{{ freeze.account_count }} account(s) · {{ freeze.reason }} · {{ freeze.frozen_at[:19].replace('T',' ') }} UTC · {{ freeze.admin_name or 'Former administrator' }}</div></div>
<form method="post" data-confirm="Restore accounts in this freeze batch? Accounts that were already suspended before the freeze remain suspended."><input type="hidden" name="action" value="restore_account_freeze"><input type="hidden" name="freeze_batch_id" value="{{ freeze.freeze_batch_id }}"><button type="submit">Restore accounts</button></form></div></article>
{% else %}<div class="ec-empty">No emergency account freezes are active.</div>{% endfor %}</div></section>

<section class="panel"><div class="panel-head"><h2>Emergency presets</h2><p>Presets change only controls enforced by this application. Unavailable integrations remain visibly unavailable.</p></div>
<div class="ec-presets">{% for preset in presets %}<form method="post" data-confirm="Activate {{ preset }}?"{% if preset == 'FULL LOCKDOWN' %} data-confirm-phrase="CONFIRM LOCKDOWN"{% endif %}>
<input type="hidden" name="action" value="preset"><input type="hidden" name="preset" value="{{ preset }}">
<button class="ec-preset{% if preset == 'FULL LOCKDOWN' %} danger{% endif %}" type="submit"><strong>{{ preset }}</strong><br><small>{{ 'Restore normal app controls' if preset == 'NORMAL MODE' else 'Apply this incident profile' }}</small></button></form>{% endfor %}
<form method="post" data-confirm="Enable Maintenance Mode? Normal users will receive a maintenance page; owner access is retained.">
<input type="hidden" name="action" value="maintenance"><button class="ec-preset" type="submit"><strong>MAINTENANCE MODE</strong><br><small>Keep owner management available</small></button></form></div></section>

<section class="panel"><div class="panel-head"><h2>Access, file, and authentication controls</h2><p>Changes are persisted immediately after save and enforced server-side. Controls marked unavailable have no matching subsystem to protect.</p></div>
<form method="post" data-confirm="Save the selected emergency controls?"><input type="hidden" name="action" value="controls">
<div class="ec-controls">{% for name, item in controls.items() %}<label class="ec-control{% if not item.supported %} unavailable{% endif %}">
<span><strong>{{ item.label }}</strong><small>{{ item.description }}{% if not item.supported %} · NOT INTEGRATED{% endif %}</small></span>
<span><input type="hidden" name="{{ name }}" value="0"><input type="checkbox" name="{{ name }}" value="1" aria-label="{{ item.label }}" {% if item.enabled %}checked{% endif %}{% if not item.supported %} disabled{% endif %}></span>
</label>{% endfor %}</div>
<div class="ec-form-footer"><label for="control-reason">Reason (optional)<input id="control-reason" name="reason" maxlength="1000" placeholder="Incident or operational reason"></label><button type="submit">Save enforced controls</button></div></form></section>

<section class="panel"><div class="panel-head"><h2>Incident management</h2><p>Create and track response incidents. A restore never overwrites controls changed after the incident without explicit review.</p></div>
<form method="post" class="incident-form" id="incident-create-form" data-confirm="Create incident and activate the selected controls?">
<input type="hidden" name="action" value="create_incident">
<label>Incident title<input name="title" maxlength="160" required></label>
<label>Severity<select name="severity" required><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select></label>
<label>Preset<select name="preset" id="incident-preset" required>{% for preset in presets %}<option value="{{ preset }}"{% if preset == 'SECURITY MODE' %} selected{% endif %}>{{ preset }}</option>{% endfor %}</select></label>
<label class="wide">Reason / description<textarea name="description" maxlength="2000" required></textarea></label>
<div class="wide service-list" aria-label="Affected services">{% for service in services %}<label><input type="checkbox" name="services" value="{{ service }}"> {{ service|replace('_',' ')|title }}</label>{% endfor %}</div>
<div class="wide"><button class="danger" type="submit">Create incident & activate preset</button></div></form>
<div class="ec-incidents">{% for incident in incidents %}<article class="ec-incident"><div class="ec-incident-head"><div><h3>{{ incident.title }}</h3><span class="ec-severity sev-{{ incident.severity }}">{{ incident.severity }}</span> · {{ incident.status|upper }} · started {{ incident.started_at[:19].replace('T',' ') }} UTC · {{ incident.admin_name or 'Former administrator' }}</div><div class="muted">Affected services: {{ incident.services|join(', ') if incident.services else 'Not specified' }}</div></div>
<p class="muted">{{ incident.description }}</p>
{% if incident.status == 'active' %}<form method="post" class="ec-actions"><input type="hidden" name="action" value="incident_note"><input type="hidden" name="incident_id" value="{{ incident.id }}"><input class="ec-note" name="note" maxlength="1000" placeholder="Add incident note" required><button type="submit">Add note</button></form>
<div class="ec-actions"><form method="post"><input type="hidden" name="action" value="resolve_incident"><input type="hidden" name="incident_id" value="{{ incident.id }}"><button type="submit">Resolve incident</button></form>
<form method="post" data-confirm="Restore controls that still match the incident state? Controls changed since then will be left untouched."><input type="hidden" name="action" value="restore_incident"><input type="hidden" name="incident_id" value="{{ incident.id }}"><button type="submit">Restore previous state</button></form></div>
{% else %}<p class="muted">Resolved {{ incident.resolved_at[:19].replace('T',' ') if incident.resolved_at else '' }} UTC</p>{% endif %}
{% for note in incident.notes %}<p class="muted">• {{ note.created_at[:19].replace('T',' ') }} UTC — {{ note.admin_name or 'Former administrator' }}: {{ note.note }}</p>{% endfor %}</article>
{% else %}<div class="ec-empty">No incidents recorded.</div>{% endfor %}</div></section>

<section class="panel"><div class="panel-head"><h2>Emergency event log</h2><p>Append-only records of emergency changes, with actor, source IP, previous/new state, reason, affected users/services, outcome, and incident reference.</p><a href="{{ url_for('admin_audit') }}">View full audit log →</a></div>
<form method="get" class="ec-form-footer" aria-label="Filter emergency events">
<label>From<input type="date" name="date_from" value="{{ event_filters.date_from }}"></label>
<label>To<input type="date" name="date_to" value="{{ event_filters.date_to }}"></label>
<label>Administrator<input name="admin" maxlength="80" value="{{ event_filters.admin }}"></label>
<label>Action<input name="event_action" maxlength="120" value="{{ event_filters.action }}"></label>
<label>Severity<select name="severity"><option value="">Any</option>{% for severity in ['LOW','MEDIUM','HIGH','CRITICAL'] %}<option value="{{ severity }}"{% if event_filters.severity == severity %} selected{% endif %}>{{ severity }}</option>{% endfor %}</select></label>
<label>Incident ID<input type="number" min="1" name="incident" value="{{ event_filters.incident }}"></label>
<label>Affected user ID<input type="number" min="1" name="user" value="{{ event_filters.user }}"></label>
<label>IP address<input name="ip" maxlength="64" value="{{ event_filters.ip }}"></label>
<button type="submit">Filter events</button><a class="button" href="{{ url_for('admin_emergency') }}">Clear filters</a>
</form>
<div class="ec-log-wrap"><table class="ec-log"><thead><tr><th>Event</th><th>Timestamp</th><th>Administrator</th><th>IP</th><th>Action</th><th>Reason / affected</th><th>Result</th><th>Incident</th></tr></thead><tbody>
{% for event in events %}<tr><td>#{{ event.id }}</td><td>{{ event.created_at[:19].replace('T',' ') }} UTC</td><td>{{ event.admin_name or 'Former administrator' }}</td><td>{{ event.ip_address or 'Unknown' }}</td><td>{{ event.action }}</td><td>{{ event.reason or '—' }}<br><small>{{ event.affected_users }} users · {{ event.services|join(', ') }}</small></td><td>{{ event.result }}</td><td>{{ event.incident_id or '—' }}</td></tr>
{% else %}<tr><td colspan="8" class="ec-empty">No emergency events recorded.</td></tr>{% endfor %}</tbody></table></div></section>

<dialog id="emergency-confirm" aria-labelledby="confirm-title"><h2 id="confirm-title">Confirm emergency action</h2><p id="confirm-message"></p><label id="confirm-phrase-wrap" hidden>Type <strong id="confirm-phrase-text"></strong> to continue<input id="confirm-phrase-input" autocomplete="off"></label><div class="ec-dialog-actions"><button type="button" id="confirm-cancel">Cancel</button><button type="button" class="danger" id="confirm-proceed">Confirm action</button></div></dialog>
</main><script>
(() => {
 const dialog=document.getElementById('emergency-confirm'), message=document.getElementById('confirm-message');
 const phraseWrap=document.getElementById('confirm-phrase-wrap'), phraseInput=document.getElementById('confirm-phrase-input');
 const incidentPreset=document.getElementById('incident-preset');
 const incidentForm=document.getElementById('incident-create-form');
 const updateIncidentConfirmation=()=>{if(incidentPreset&&incidentForm){incidentForm.dataset.confirmPhrase=incidentPreset.value==='FULL LOCKDOWN'?'CONFIRM LOCKDOWN':''}};
 if(incidentPreset){incidentPreset.addEventListener('change',updateIncidentConfirmation);updateIncidentConfirmation()}
 let pending=null;
 document.querySelectorAll('form[data-confirm]').forEach(form=>form.addEventListener('submit',event=>{
   if(form.dataset.confirmed==='yes'){form.dataset.confirmed='';return}
   event.preventDefault(); pending=form; message.textContent=form.dataset.confirm;
   const phrase=form.dataset.confirmPhrase||''; phraseWrap.hidden=!phrase;
   document.getElementById('confirm-phrase-text').textContent=phrase; phraseInput.value='';
   dialog.showModal();
 }));
 document.getElementById('confirm-cancel').addEventListener('click',()=>dialog.close());
 document.getElementById('confirm-proceed').addEventListener('click',()=>{
   if(!pending)return;
   const required=pending.dataset.confirmPhrase||'';
   if(required&&phraseInput.value!==required){phraseInput.setCustomValidity('The confirmation text does not match.');phraseInput.reportValidity();phraseInput.setCustomValidity('');return}
   if(required){const input=document.createElement('input');input.type='hidden';input.name='confirmation_phrase';input.value=phraseInput.value;pending.appendChild(input)}
   pending.dataset.confirmed='yes';dialog.close();pending.requestSubmit();
 });
 dialog.addEventListener('close',()=>{pending=null});
})();
</script></body></html>
"""


@app.route("/admin/emergency", methods=["GET", "POST"])
def admin_emergency():
    response = require_owner()
    if response:
        return response
    enforced = {
        "global_read_only", "disable_uploads", "disable_downloads",
        "disable_deletion", "disable_editing", "disable_file_sharing",
        "revoke_active_share_links", "block_public_access",
        "disable_sync_automation", "block_new_devices",
        "freeze_registrations",
        "force_reauthentication", "force_password_reset", "require_two_factor",
        "disable_api_access", "enhanced_monitoring", "emergency_rate_limit",
        "maintenance_mode",
    }
    service_options = {
        "storage", "authentication", "sharing", "api", "backups", "database",
        "network",
    }
    if request.method == "POST":
        action = request.form.get("action", "")
        reason = request.form.get("reason", "").strip()
        preset_name = request.form.get("preset", "")
        if action in {"freeze_accounts", "restore_account_freeze"}:
            now = datetime.now(timezone.utc).isoformat()
            with database_connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                state = emergency_control_state(connection)
                affected_user_ids = []
                services = ["authentication"]
                if action == "freeze_accounts":
                    freeze_reason = request.form.get("reason", "").strip()
                    if not freeze_reason or len(freeze_reason) > 1000:
                        abort(400, "Enter a freeze reason of up to 1000 characters")
                    scope = request.form.get("scope", "")
                    group_id = None
                    if scope == "account":
                        try:
                            target_id = int(request.form.get("user_id", ""))
                        except ValueError:
                            abort(400, "Select a valid account")
                        targets = connection.execute(
                            """
                            SELECT id, status FROM users
                            WHERE id = ? AND is_admin = 0 AND status = 'active'
                              AND username != ? COLLATE NOCASE
                              AND NOT EXISTS (
                                  SELECT 1 FROM emergency_account_freezes f
                                  WHERE f.user_id = users.id
                              )
                            """,
                            (target_id, ADMIN_USERNAME),
                        ).fetchall()
                    elif scope == "group":
                        try:
                            group_id = int(request.form.get("group_id", ""))
                        except ValueError:
                            abort(400, "Select a valid group")
                        group = connection.execute(
                            "SELECT id FROM groups WHERE id = ?", (group_id,)
                        ).fetchone()
                        if not group:
                            abort(404, "Group not found")
                        targets = connection.execute(
                            """
                            SELECT users.id, users.status
                            FROM users
                            JOIN group_members ON group_members.user_id = users.id
                            WHERE group_members.group_id = ? AND users.is_admin = 0
                              AND users.status = 'active'
                              AND users.username != ? COLLATE NOCASE
                              AND NOT EXISTS (
                                  SELECT 1 FROM emergency_account_freezes f
                                  WHERE f.user_id = users.id
                              )
                            ORDER BY users.id
                            """,
                            (group_id, ADMIN_USERNAME),
                        ).fetchall()
                    else:
                        abort(400, "Select an account or group freeze scope")
                    if not targets:
                        abort(409, "No eligible active accounts were found to freeze")
                    batch_id = secrets.token_hex(16)
                    account_statuses = {}
                    for target in targets:
                        connection.execute(
                            """
                            INSERT INTO emergency_account_freezes
                                (user_id, group_id, previous_status, freeze_batch_id,
                                 reason, frozen_at, frozen_by)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                target["id"], group_id, target["status"], batch_id,
                                freeze_reason, now, session["user_id"],
                            ),
                        )
                        connection.execute(
                            "UPDATE users SET status = 'suspended', suspended_at = ? WHERE id = ?",
                            (now, target["id"]),
                        )
                        connection.execute(
                            """
                            UPDATE device_sessions SET revoked_at = ?
                            WHERE user_id = ? AND revoked_at IS NULL
                            """,
                            (now, target["id"]),
                        )
                        affected_user_ids.append(target["id"])
                        account_statuses[str(target["id"])] = {
                            "previous": target["status"],
                            "new": "suspended",
                        }
                    event_action = "freeze_accounts"
                    event_reason = freeze_reason
                else:
                    batch_id = request.form.get("freeze_batch_id", "").strip()
                    if not re.fullmatch(r"[0-9a-f]{32}", batch_id):
                        abort(400, "Invalid account-freeze batch")
                    frozen_accounts = connection.execute(
                        """
                        SELECT freezes.user_id, freezes.previous_status
                        FROM emergency_account_freezes AS freezes
                        JOIN users ON users.id = freezes.user_id
                        WHERE freezes.freeze_batch_id = ? AND users.is_admin = 0
                          AND users.username != ? COLLATE NOCASE
                        """,
                        (batch_id, ADMIN_USERNAME),
                    ).fetchall()
                    if not frozen_accounts:
                        abort(404, "Account-freeze batch not found")
                    account_statuses = {}
                    for frozen in frozen_accounts:
                        connection.execute(
                            """
                            UPDATE users SET status = ?, suspended_at = NULL
                            WHERE id = ? AND status = 'suspended'
                            """,
                            (frozen["previous_status"], frozen["user_id"]),
                        )
                        affected_user_ids.append(frozen["user_id"])
                        account_statuses[str(frozen["user_id"])] = {
                            "previous": "suspended",
                            "new": frozen["previous_status"],
                        }
                    connection.execute(
                        "DELETE FROM emergency_account_freezes WHERE freeze_batch_id = ?",
                        (batch_id,),
                    )
                    event_action = "restore_account_freeze"
                    event_reason = "Administrator restored accounts from emergency freeze"
                write_emergency_event(
                    connection,
                    event_action,
                    {
                        "controls": state,
                        "account_statuses": {
                            user_id: statuses["previous"]
                            for user_id, statuses in account_statuses.items()
                        },
                    },
                    {
                        "controls": state,
                        "account_statuses": {
                            user_id: statuses["new"]
                            for user_id, statuses in account_statuses.items()
                        },
                    },
                    event_reason,
                    len(affected_user_ids),
                    affected_user_ids,
                    services,
                )
            flash(
                f"{len(affected_user_ids)} account(s) "
                f"{'frozen' if action == 'freeze_accounts' else 'restored'}."
            )
            return redirect(url_for("admin_emergency"))
        if action in {"preset", "create_incident"}:
            if preset_name not in EMERGENCY_PRESETS:
                abort(400, "Invalid emergency preset")
            if preset_name == "FULL LOCKDOWN" and request.form.get("confirmation_phrase") != "CONFIRM LOCKDOWN":
                abort(400, "Type CONFIRM LOCKDOWN to activate the full-lockdown preset")
        now = datetime.now(timezone.utc).isoformat()
        with database_connection() as connection:
            previous = emergency_control_state(connection)
            desired = dict(previous)
            incident_id = None
            affected_services = []
            if action == "controls":
                for name in enforced:
                    desired[name] = request.form.getlist(name)[-1] == "1"
                reason = request.form.get("reason", "").strip()
            elif action == "maintenance":
                desired["maintenance_mode"] = not previous["maintenance_mode"]
                action = "controls"
                reason = "Maintenance mode toggle"
            elif action == "preset":
                preset_controls = {
                    name: value
                    for name, value in EMERGENCY_PRESETS[preset_name].items()
                    if name in enforced
                }
                desired = {**desired, **preset_controls}
                if preset_name == "NORMAL MODE":
                    for name in enforced:
                        desired[name] = False
                desired["maintenance_mode"] = False
                reason = reason or f"Activated {preset_name}"
            elif action == "create_incident":
                title = request.form.get("title", "").strip()
                description = request.form.get("description", "").strip()
                severity = request.form.get("severity", "").upper()
                affected_services = sorted(set(request.form.getlist("services")))
                if (
                    not title or len(title) > 160 or not description
                    or len(description) > 2000
                    or severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
                    or not set(affected_services).issubset(service_options)
                ):
                    abort(400, "Invalid incident details")
                selected_controls = {
                    name: value
                    for name, value in EMERGENCY_PRESETS[preset_name].items()
                    if name in enforced
                }
                if preset_name == "NORMAL MODE":
                    selected_controls = {name: False for name in enforced}
                desired = {**desired, **selected_controls}
                if preset_name == "FULL LOCKDOWN":
                    desired["maintenance_mode"] = False
                cursor = connection.execute(
                    """
                    INSERT INTO emergency_incidents
                        (title, severity, description, affected_services,
                         previous_state, emergency_state, started_at, created_by, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')
                    """,
                    (
                        title, severity, description, json.dumps(affected_services),
                        json.dumps(previous, sort_keys=True),
                        json.dumps(desired, sort_keys=True),
                        now, session["user_id"],
                    ),
                )
                incident_id = cursor.lastrowid
                reason = description
            elif action in {"incident_note", "resolve_incident", "restore_incident"}:
                try:
                    incident_id = int(request.form.get("incident_id", ""))
                except ValueError:
                    abort(400, "Invalid incident")
                incident = connection.execute(
                    "SELECT * FROM emergency_incidents WHERE id = ?",
                    (incident_id,),
                ).fetchone()
                if not incident:
                    abort(404, "Incident not found")
                services = json.loads(incident["affected_services"])
                if action == "incident_note":
                    note = request.form.get("note", "").strip()
                    if not note or len(note) > 1000:
                        abort(400, "Enter an incident note of up to 1000 characters")
                    connection.execute(
                        "INSERT INTO emergency_incident_notes (incident_id, admin_id, note, created_at) VALUES (?, ?, ?, ?)",
                        (incident_id, session["user_id"], note, now),
                    )
                    write_emergency_event(
                        connection, "incident_note", previous, previous, note,
                        affected_services=services, incident_id=incident_id,
                    )
                    flash("Incident note added.")
                    return redirect(url_for("admin_emergency"))
                if action == "resolve_incident":
                    connection.execute(
                        "UPDATE emergency_incidents SET status = 'resolved', resolved_at = ?, resolved_by = ? WHERE id = ? AND status = 'active'",
                        (now, session["user_id"], incident_id),
                    )
                    write_emergency_event(
                        connection, "resolve_incident", previous, previous,
                        affected_services=services, incident_id=incident_id,
                    )
                    flash("Incident resolved. Emergency controls remain as configured.")
                    return redirect(url_for("admin_emergency"))
                if incident["status"] != "active":
                    abort(409, "Only active incidents can restore a previous state")
                original = json.loads(incident["previous_state"])
                incident_state = json.loads(incident["emergency_state"])
                for name in enforced:
                    if previous.get(name) == incident_state.get(name):
                        desired[name] = bool(original.get(name, False))
                connection.execute(
                    "UPDATE emergency_incidents SET recovery_state = ? WHERE id = ?",
                    (json.dumps(desired, sort_keys=True), incident_id),
                )
                reason = "Selective incident rollback; controls changed after activation were preserved"
                affected_services = services
                action = "restore_incident"
            else:
                abort(400, "Invalid emergency action")

            if action in {"controls", "preset", "create_incident", "restore_incident"}:
                for name in enforced:
                    value = "1" if desired.get(name) else "0"
                    connection.execute(
                        """
                        INSERT INTO policies (name, value, updated_at, updated_by)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(name) DO UPDATE SET
                            value = excluded.value, updated_at = excluded.updated_at,
                            updated_by = excluded.updated_by
                        """,
                        (name, value, now, session["user_id"]),
                    )
                if desired.get("disable_file_sharing"):
                    connection.execute(
                        """
                        INSERT INTO policies (name, value, updated_at, updated_by)
                        VALUES ('allow_public_sharing', '0', ?, ?)
                        ON CONFLICT(name) DO UPDATE SET value='0',
                            updated_at=excluded.updated_at, updated_by=excluded.updated_by
                        """,
                        (now, session["user_id"]),
                    )
                if desired.get("force_password_reset") and not previous.get("force_password_reset"):
                    connection.execute(
                        """
                        UPDATE users SET must_change_password = 1
                        WHERE username != ? COLLATE NOCASE AND password_login_enabled = 1
                        """,
                        (ADMIN_USERNAME,),
                    )
                revoked_sessions = 0
                if desired.get("force_reauthentication") and not previous.get("force_reauthentication"):
                    current_token = session.get("device_token", "")
                    current_hash = device_token_hash(current_token) if current_token else ""
                    revoked = connection.execute(
                        """
                        UPDATE device_sessions SET revoked_at = ?
                        WHERE revoked_at IS NULL AND session_token_hash != ?
                        """,
                        (now, current_hash),
                    )
                    revoked_sessions = max(0, revoked.rowcount)
                affected_user_rows = connection.execute(
                    "SELECT id FROM users WHERE username != ? COLLATE NOCASE AND status = 'active' ORDER BY id",
                    (ADMIN_USERNAME,),
                ).fetchall()
                affected_user_ids = [row["id"] for row in affected_user_rows]
                affected_users = len(affected_user_ids)
                if action == "create_incident" and incident_id:
                    connection.execute(
                        "UPDATE emergency_incidents SET emergency_state = ? WHERE id = ?",
                        (json.dumps(desired, sort_keys=True), incident_id),
                    )
                if revoked_sessions:
                    reason += f"; revoked_sessions={revoked_sessions}"
                write_emergency_event(
                    connection,
                    action if action != "controls" else "update_controls",
                    previous,
                    desired,
                    reason,
                    affected_users,
                    affected_user_ids,
                    affected_services,
                    incident_id=incident_id,
                )
                flash(
                    f"Emergency action recorded. {affected_users} active user accounts "
                    "may be affected."
                )
        return redirect(url_for("admin_emergency"))

    now = datetime.now(timezone.utc)
    since_24h = (now - timedelta(hours=24)).isoformat()
    with database_connection() as connection:
        current = emergency_control_state(connection)
        metrics = {
            "users": connection.execute(
                "SELECT COUNT(*) AS count FROM users WHERE username != ? COLLATE NOCASE AND status = 'active'",
                (ADMIN_USERNAME,),
            ).fetchone()["count"],
            "frozen_accounts": connection.execute(
                "SELECT COUNT(*) AS count FROM emergency_account_freezes"
            ).fetchone()["count"],
            "sessions": connection.execute(
                "SELECT COUNT(*) AS count FROM device_sessions JOIN users ON users.id = device_sessions.user_id WHERE revoked_at IS NULL AND users.username != ? COLLATE NOCASE",
                (ADMIN_USERNAME,),
            ).fetchone()["count"],
            "incidents": connection.execute(
                "SELECT COUNT(*) AS count FROM emergency_incidents WHERE status = 'active'"
            ).fetchone()["count"],
            "blocked_uploads": connection.execute(
                "SELECT COUNT(*) AS count FROM audit_events WHERE action LIKE '%upload%blocked%' AND created_at >= ?",
                (since_24h,),
            ).fetchone()["count"],
            "blocked_downloads": connection.execute(
                "SELECT COUNT(*) AS count FROM audit_events WHERE action LIKE '%download%blocked%' AND created_at >= ?",
                (since_24h,),
            ).fetchone()["count"],
            "blocked_api": connection.execute(
                "SELECT COUNT(*) AS count FROM audit_events WHERE action LIKE '%api%blocked%' AND created_at >= ?",
                (since_24h,),
            ).fetchone()["count"],
            "alerts": connection.execute(
                "SELECT COUNT(*) AS count FROM security_alerts WHERE status = 'open'"
            ).fetchone()["count"],
        }
        incidents = connection.execute(
            """
            SELECT emergency_incidents.*, users.username AS admin_name
            FROM emergency_incidents
            LEFT JOIN users ON users.id = emergency_incidents.created_by
            ORDER BY CASE emergency_incidents.status WHEN 'active' THEN 0 ELSE 1 END,
                emergency_incidents.started_at DESC
            LIMIT 50
            """
        ).fetchall()
        freeze_targets = connection.execute(
            """
            SELECT users.id, users.username
            FROM users
            WHERE users.is_admin = 0 AND users.status = 'active'
              AND users.username != ? COLLATE NOCASE
              AND NOT EXISTS (
                  SELECT 1 FROM emergency_account_freezes freezes
                  WHERE freezes.user_id = users.id
              )
            ORDER BY users.username COLLATE NOCASE
            """,
            (ADMIN_USERNAME,),
        ).fetchall()
        freeze_groups = connection.execute(
            """
            SELECT groups.id, groups.name, COUNT(users.id) AS eligible_members
            FROM groups
            JOIN group_members ON group_members.group_id = groups.id
            JOIN users ON users.id = group_members.user_id
            WHERE users.is_admin = 0 AND users.status = 'active'
              AND users.username != ? COLLATE NOCASE
              AND NOT EXISTS (
                  SELECT 1 FROM emergency_account_freezes freezes
                  WHERE freezes.user_id = users.id
              )
            GROUP BY groups.id
            HAVING COUNT(users.id) > 0
            ORDER BY groups.name COLLATE NOCASE
            """,
            (ADMIN_USERNAME,),
        ).fetchall()
        freeze_batches = connection.execute(
            """
            SELECT freezes.freeze_batch_id, MIN(freezes.group_id) AS group_id,
                   COUNT(*) AS account_count, MIN(freezes.reason) AS reason,
                   MIN(freezes.frozen_at) AS frozen_at,
                   MIN(freezes.frozen_by) AS frozen_by,
                   groups.name AS group_name, users.username AS admin_name
            FROM emergency_account_freezes AS freezes
            LEFT JOIN groups ON groups.id = freezes.group_id
            LEFT JOIN users ON users.id = freezes.frozen_by
            GROUP BY freezes.freeze_batch_id
            ORDER BY frozen_at DESC
            """
        ).fetchall()
        event_filters = {
            "date_from": request.args.get("date_from", "").strip()[:10],
            "date_to": request.args.get("date_to", "").strip()[:10],
            "admin": request.args.get("admin", "").strip()[:80],
            "action": request.args.get("event_action", "").strip()[:120],
            "severity": request.args.get("severity", "").strip().upper()[:8],
            "incident": request.args.get("incident", "").strip()[:12],
            "user": request.args.get("user", "").strip()[:12],
            "ip": request.args.get("ip", "").strip()[:64],
        }
        clauses = []
        values = []
        for key, comparison in (("date_from", ">="), ("date_to", "<")):
            date_value = event_filters[key]
            if date_value:
                try:
                    parsed_date = datetime.strptime(date_value, "%Y-%m-%d")
                except ValueError:
                    abort(400, "Emergency event dates must use YYYY-MM-DD")
                boundary = parsed_date + (
                    timedelta(days=1) if key == "date_to" else timedelta()
                )
                clauses.append(f"emergency_events.created_at {comparison} ?")
                values.append(boundary.isoformat() if key == "date_to" else parsed_date.isoformat())
        if event_filters["admin"]:
            clauses.append("users.username LIKE ? COLLATE NOCASE")
            values.append(f"%{event_filters['admin']}%")
        if event_filters["action"]:
            clauses.append("emergency_events.action LIKE ?")
            values.append(f"%{event_filters['action']}%")
        if event_filters["severity"]:
            if event_filters["severity"] not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                abort(400, "Invalid event severity")
            clauses.append("incidents.severity = ?")
            values.append(event_filters["severity"])
        if event_filters["incident"]:
            try:
                incident_filter = int(event_filters["incident"])
            except ValueError:
                abort(400, "Incident filter must be a number")
            clauses.append("emergency_events.incident_id = ?")
            values.append(incident_filter)
        if event_filters["user"]:
            try:
                user_filter = int(event_filters["user"])
            except ValueError:
                abort(400, "User filter must be a number")
            clauses.append(
                "instr(',' || replace(replace(replace("
                "emergency_events.affected_user_ids, '[', ''), ']', ''), ' ', '') "
                "|| ',', ',' || ? || ',') > 0"
            )
            values.append(str(user_filter))
        if event_filters["ip"]:
            clauses.append("emergency_events.ip_address LIKE ?")
            values.append(f"%{event_filters['ip']}%")
        event_query = """
            SELECT emergency_events.*, users.username AS admin_name
            FROM emergency_events
            LEFT JOIN users ON users.id = emergency_events.admin_id
            LEFT JOIN emergency_incidents AS incidents
                ON incidents.id = emergency_events.incident_id
        """
        if clauses:
            event_query += " WHERE " + " AND ".join(clauses)
        event_query += " ORDER BY emergency_events.created_at DESC LIMIT 100"
        event_rows = connection.execute(event_query, values).fetchall()
        last_event = event_rows[0] if event_rows else None

    incident_items = []
    for row in incidents:
        item = dict(row)
        item["services"] = json.loads(item["affected_services"])
        with database_connection() as connection:
            item["notes"] = [
                dict(note)
                for note in connection.execute(
                    """
                    SELECT emergency_incident_notes.*, users.username AS admin_name
                    FROM emergency_incident_notes
                    LEFT JOIN users ON users.id = emergency_incident_notes.admin_id
                    WHERE incident_id = ? ORDER BY created_at
                    """,
                    (item["id"],),
                ).fetchall()
            ]
        incident_items.append(item)
    events = []
    for row in event_rows:
        item = dict(row)
        item["services"] = json.loads(item["affected_services"])
        try:
            item["reason"] = item["reason"] or ""
        except KeyError:
            item["reason"] = ""
        events.append(item)
    active_controls = [
        EMERGENCY_CONTROL_LABELS[name][0]
        for name, value in current.items()
        if value
    ]
    if current["maintenance_mode"]:
        system_status, status_class = "MAINTENANCE", "maintenance"
    elif current["global_read_only"] and current["disable_downloads"]:
        system_status, status_class = "LOCKDOWN", "lockdown"
    elif current["enhanced_monitoring"] or metrics["alerts"]:
        system_status, status_class = "SECURITY ALERT", "security"
    elif active_controls:
        system_status, status_class = "RESTRICTED", "restricted"
    else:
        system_status, status_class = "NORMAL", ""
    return render_template_string(
        ADMIN_EMERGENCY_PAGE,
        controls={
            name: {
                "label": label,
                "description": description,
                "enabled": current[name],
                "supported": name in enforced,
            }
            for name, (label, description) in EMERGENCY_CONTROL_LABELS.items()
        },
        presets=list(EMERGENCY_PRESETS),
        services=sorted(service_options),
        active_controls=active_controls,
        incidents=incident_items,
        freeze_targets=freeze_targets,
        freeze_groups=freeze_groups,
        freeze_batches=freeze_batches,
        events=events,
        event_filters=event_filters,
        metrics=metrics,
        system_status=system_status,
        status_class=status_class,
        last_action=last_event["action"] if last_event else None,
        last_admin=last_event["admin_name"] if last_event else None,
    )


@app.route("/admin/storage")
def admin_storage():
    response = require_permission("storage.manage")
    if response:
        return response
    users = []
    with database_connection() as connection:
        rows = connection.execute("SELECT id, username, status, is_admin FROM users WHERE is_admin = 0 ORDER BY username COLLATE NOCASE").fetchall()
    for row in rows:
        used = user_usage(row["id"])[1]
        quota = user_quota(row["id"])
        with database_connection() as connection:
            permissions = connection.execute("SELECT allow_upload, allow_download FROM storage_permissions WHERE user_id = ?", (row["id"],)).fetchone()
        users.append({**dict(row), "used": used, "quota": quota, "remaining": max(0, quota - used) if quota else 0, "quota_mb": quota // (1024 * 1024) if quota else 0, "allow_upload": not permissions or bool(permissions["allow_upload"]), "allow_download": not permissions or bool(permissions["allow_download"])})
    return render_template_string(ADMIN_STORAGE_PAGE, users=users)


@app.route("/admin/storage/<int:user_id>/quota", methods=["POST"])
def admin_storage_quota(user_id):
    response = require_permission("storage.manage")
    if response:
        return response
    try:
        quota_mb = int(request.form.get("quota_mb", "0"))
    except ValueError:
        quota_mb = -1
    if quota_mb < 0:
        flash("Quota must be zero or a positive number of megabytes.")
        return redirect(url_for("admin_storage"))
    with database_connection() as connection:
        user = connection.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user or user["is_admin"]:
            flash("That account is protected or does not exist.")
            return redirect(url_for("admin_storage"))
        now = datetime.now(timezone.utc).isoformat()
        connection.execute("""
            INSERT INTO quotas (user_id, quota_bytes, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET quota_bytes = excluded.quota_bytes, updated_at = excluded.updated_at
        """, (user_id, quota_mb * 1024 * 1024, now))
    audit_event("set_quota", "user", user_id, f"username={user['username']}; quota_mb={quota_mb}")
    flash(f"Storage quota updated for {user['username']}.")
    return redirect(url_for("admin_storage"))


@app.route("/admin/storage/<int:user_id>/permissions", methods=["POST"])
def admin_storage_permissions(user_id):
    response = require_permission("storage.manage")
    if response:
        return response
    allow_upload = int(bool(request.form.get("allow_upload")))
    allow_download = int(bool(request.form.get("allow_download")))
    now = datetime.now(timezone.utc).isoformat()
    with database_connection() as connection:
        user = connection.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user or user["is_admin"]:
            flash("That account is protected or does not exist.")
            return redirect(url_for("admin_storage"))
        connection.execute("""
            INSERT INTO storage_permissions (user_id, allow_upload, allow_download, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                allow_upload = excluded.allow_upload,
                allow_download = excluded.allow_download,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
        """, (user_id, allow_upload, allow_download, now, session["user_id"]))
    audit_event("update_storage_permissions", "user", user_id, f"username={user['username']}; upload={allow_upload}; download={allow_download}")
    flash(f"Storage access updated for {user['username']}.")
    return redirect(url_for("admin_storage"))


@app.route("/admin/audit")
def admin_audit():
    response = require_permission("audit.view")
    if response:
        return response
    action = request.args.get("action", "").strip()
    actor = request.args.get("actor", "").strip()
    status = request.args.get("status", "").strip()
    clauses = []
    values = []
    if action:
        clauses.append("audit_events.action LIKE ?")
        values.append(f"%{action}%")
    if actor:
        clauses.append("users.username LIKE ?")
        values.append(f"%{actor}%")
    if status in {"success", "denied"}:
        clauses.append("audit_events.status = ?")
        values.append(status)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with database_connection() as connection:
        events = connection.execute(f"""
            SELECT audit_events.*, users.username AS actor
            FROM audit_events LEFT JOIN users ON users.id = audit_events.actor_id
            {where}
            ORDER BY audit_events.created_at DESC LIMIT 250
        """, values).fetchall()
    grouped = {}
    for event in events:
        item = dict(event)
        username = item["actor"] or "System"
        grouped.setdefault(username, []).append(item)
    audit_groups = [{"username": username, "events": group_events} for username, group_events in grouped.items()]
    return render_template_string(ADMIN_AUDIT_PAGE, events=[dict(row) for row in events], audit_groups=audit_groups, filters={"action": action, "actor": actor, "status": status})


@app.route("/admin/users/<int:user_id>/status", methods=["POST"])
def admin_user_status(user_id):
    response = require_permission("users.manage")
    if response:
        return response
    status = request.form.get("status", "").strip().lower()
    if status not in {"active", "suspended"}:
        abort(400, "Invalid account status")
    if user_id == session["user_id"] and status != "active":
        flash("The active administrator cannot suspend itself.")
        return redirect(url_for("admin_manage"))
    with database_connection() as connection:
        if status == "active" and connection.execute(
            "SELECT 1 FROM emergency_account_freezes WHERE user_id = ?",
            (user_id,),
        ).fetchone():
            flash("Restore this account through the Emergency Control Centre.")
            return redirect(url_for("admin_manage"))
        result = connection.execute("UPDATE users SET status = ?, suspended_at = ? WHERE id = ? AND is_admin = 0", (status, datetime.now(timezone.utc).isoformat() if status == "suspended" else None, user_id))
    if result.rowcount:
        audit_event("suspend_user" if status == "suspended" else "activate_user", "user", user_id)
        flash(f"User account {status}.")
    else:
        flash("User not found or protected.")
    return redirect(url_for("admin_manage"))


@app.route("/admin/users/<int:user_id>/quota", methods=["POST"])
def admin_user_quota(user_id):
    response = require_permission("storage.manage")
    if response:
        return response
    try:
        quota_mb = int(request.form.get("quota_mb", "0"))
    except ValueError:
        quota_mb = -1
    if quota_mb < 0:
        flash("Quota must be zero or a positive number of megabytes.")
        return redirect(url_for("admin_manage"))
    with database_connection() as connection:
        user = connection.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        if user:
            connection.execute("INSERT INTO quotas (user_id, quota_bytes, updated_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET quota_bytes=excluded.quota_bytes, updated_at=excluded.updated_at", (user_id, quota_mb * 1024 * 1024, datetime.now(timezone.utc).isoformat()))
    if not user:
        flash("User not found.")
    else:
        audit_event("set_quota", "user", user_id, f"quota_mb={quota_mb}")
        flash("Storage quota updated.")
    return redirect(url_for("admin_manage"))


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
def admin_user_role(user_id):
    response = require_permission("users.manage")
    if response:
        return response
    role_name = request.form.get("role_name", "").strip()
    if not role_name or role_name in {ADMIN_ROLE, "__system_admin__"}:
        flash("Choose a valid role.")
        return redirect(url_for("admin_manage"))
    normal_user = role_name == "__normal_user__"
    with database_connection() as connection:
        user = connection.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
        if user and user["username"].lower() == ADMIN_USERNAME.lower():
            flash("The server owner account cannot have its role changed.")
            return redirect(url_for("admin_manage"))
        role = None if normal_user else connection.execute("SELECT id FROM roles WHERE name = ? AND name != ?", (role_name, ADMIN_ROLE)).fetchone()
        protected = user and user["username"].lower() == ADMIN_USERNAME.lower()
        if user and role_name and (normal_user or role) and not protected and user_id != session["user_id"] and not user["is_admin"]:
            connection.execute("UPDATE users SET is_admin = 0 WHERE id = ?", (user_id,))
            connection.execute("DELETE FROM user_roles WHERE user_id = ?", (user_id,))
            if not normal_user:
                connection.execute("INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by) VALUES (?, ?, ?, ?)", (user_id, role["id"], datetime.now(timezone.utc).isoformat(), session["user_id"]))
    if not user or (not normal_user and not role) or protected or user_id == session["user_id"] or user["is_admin"]:
        flash("User or role not found; the owner is the only administrator and cannot be changed.")
    else:
        audit_event("set_user_role", "user", user_id, f"role={'normal_user' if normal_user else role_name}")
        flash(f"Role {'normal user' if normal_user else role_name} saved.")
    return redirect(url_for("admin_manage"))


@app.route("/admin/groups/create", methods=["POST"])
def admin_group_create():
    response = require_permission("users.manage")
    if response:
        return response
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    if not name or len(name) > 80:
        flash("Enter a group name up to 80 characters.")
        return redirect(url_for("admin_manage"))
    try:
        with database_connection() as connection:
            cursor = connection.execute("INSERT INTO groups (name, description, created_at) VALUES (?, ?, ?)", (name, description, datetime.now(timezone.utc).isoformat()))
        audit_event("create_group", "group", cursor.lastrowid, name)
        flash("Group created.")
    except sqlite3.IntegrityError:
        flash("That group already exists.")
    return redirect(url_for("admin_manage"))


@app.route("/admin/groups/<int:group_id>/members", methods=["POST"])
def admin_group_member(group_id):
    response = require_permission("users.manage")
    if response:
        return response
    try:
        user_id = int(request.form.get("user_id", "0"))
    except ValueError:
        abort(400, "Invalid user")
    with database_connection() as connection:
        group = connection.execute("SELECT id FROM groups WHERE id = ?", (group_id,)).fetchone()
        user = connection.execute("SELECT id FROM users WHERE id = ? AND status = 'active'", (user_id,)).fetchone()
        if group and user:
            connection.execute("INSERT OR IGNORE INTO group_members (group_id, user_id, assigned_at, assigned_by) VALUES (?, ?, ?, ?)", (group_id, user_id, datetime.now(timezone.utc).isoformat(), session["user_id"]))
    if not group or not user:
        flash("Group or active user not found.")
    else:
        audit_event("add_group_member", "group", group_id, f"user_id={user_id}")
        flash("User added to group.")
    return redirect(url_for("admin_manage"))


@app.route("/admin/users/<int:user_id>/profile")
def admin_user_profile(user_id):
    response = require_permission("users.view")
    if response:
        return response
    with database_connection() as connection:
        user = connection.execute(
            """
            SELECT id, username, full_name, email, mobile, date_of_birth,
                gender, location, created_at, last_login_at, last_seen,
                totp_enabled,
                google_sub, google_email, google_profile_name, google_username,
                google_picture, github_sub, github_email, github_profile_name,
                github_username, github_picture
            FROM users WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
    if not user:
        abort(404, "User not found")
    profile_data = dict(user)
    profile_data["profile_picture"] = (
        profile_data["google_picture"] or profile_data["github_picture"]
    )
    return render_template_string(
        PROFILE_PAGE,
        profile=profile_data,
        can_edit_profile=False,
        back_url=url_for("admin_panel"),
    )


@app.route("/admin/recovery/<int:request_id>/reset", methods=["POST"])
def admin_reset_password(request_id):
    response = require_permission("users.recovery")
    if response:
        return response
    with database_connection() as connection:
        recovery = connection.execute("""
            SELECT password_requests.id, password_requests.user_id,
                   password_requests.status, password_requests.email,
                   password_requests.mobile, password_requests.date_of_birth,
                   users.email AS account_email, users.mobile AS account_mobile,
                   users.date_of_birth AS account_dob
            FROM password_requests
            JOIN users ON users.id = password_requests.user_id
            WHERE password_requests.id = ? AND users.is_admin = 0
        """, (request_id,)).fetchone()
        if not recovery or recovery["status"] != "pending":
            abort(404, "Recovery request not found")
        if (recovery["email"].strip().lower() != (recovery["account_email"] or "").strip().lower()
                or recovery["mobile"].strip() != (recovery["account_mobile"] or "").strip()
                or recovery["date_of_birth"] != (recovery["account_dob"] or "")):
            connection.execute("UPDATE password_requests SET status = 'rejected', reviewed_at = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), request_id))
            flash("The recovery details did not match the registered account. Password was not changed.")
            return redirect(url_for("admin_panel"))
        recovery_password = generate_recovery_password()
        connection.execute("UPDATE users SET password_hash = ?, password_login_enabled = 1 WHERE id = ? AND is_admin = 0", (hash_password(recovery_password), recovery["user_id"]))
        connection.execute("UPDATE password_requests SET status = 'approved', reviewed_at = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), request_id))
    flash(f"Identity verified. Temporary password for the user: {recovery_password}")
    return redirect(url_for("admin_panel"))


ADMIN_FILES_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Admin read-only - Cloud Rdx</title><style>
body{margin:0;background:#f2f6f8;color:#17212b;font-family:'Segoe UI',Arial,sans-serif;background-image:linear-gradient(#d8e1e844 1px,transparent 1px),linear-gradient(90deg,#d8e1e844 1px,transparent 1px);background-size:32px 32px}.wrap{width:min(980px,calc(100% - 32px));margin:40px auto}.top{display:flex;justify-content:space-between;align-items:start;gap:20px;margin-bottom:25px}.eyebrow{margin:0 0 8px;color:#087f73;text-transform:uppercase;letter-spacing:.14em;font:700 11px Consolas,monospace}h1{margin:0;font-size:38px;letter-spacing:-.03em}.sub{margin:8px 0 0;color:#647483;font:13px Consolas,monospace}.back{color:#087f73;font:700 12px Consolas,monospace;text-decoration:none}.panel{overflow:hidden;background:#fff;border:1px solid #d8e1e8;border-radius:8px;box-shadow:0 12px 30px #19314214}.head{display:flex;justify-content:space-between;gap:15px;padding:18px 22px;border-bottom:1px solid #d8e1e8;font:13px Consolas,monospace}.head a{color:#087f73;text-decoration:none}.row{display:grid;grid-template-columns:40px minmax(0,1fr) 110px 90px;gap:12px;align-items:center;min-height:62px;padding:0 22px;border-bottom:1px solid #e8eef2;font:13px Consolas,monospace}.row:last-child{border:0}.icon{width:32px;height:32px;display:grid;place-items:center;border-radius:6px;background:#e5f5f2;color:#087f73}.icon.file{background:#fff3dc;color:#b06b0c}.row a{color:#087f73;text-decoration:none}.meta{color:#647483;font-size:11px}.download{justify-self:end;font-size:11px;font-weight:700}.empty{padding:60px;text-align:center;color:#647483;font:13px Consolas,monospace}@media(max-width:620px){.wrap{margin:24px auto}.top{display:block}.back{display:inline-block;margin-top:16px}.row{grid-template-columns:34px minmax(0,1fr) 68px;padding:0 14px}.meta{display:none}}
</style></head><body><main class="wrap"><header class="top"><div><p class="eyebrow">Admin read-only file inspection</p><h1>{{ username }}</h1><p class="sub">/users/{{ user_id }}{% if subpath %}/{{ subpath }}{% endif %}</p></div><a class="back" href="{{ url_for('admin_panel') }}">→ BACK TO ADMIN</a></header><section class="panel"><div class="head"><span>{% for crumb in breadcrumbs %}{% if not loop.first %} / {% endif %}<a href="{{ crumb.url }}">{{ crumb.name }}</a>{% endfor %}</span><span>READ ONLY</span></div>{% if parent is not none %}<div class="row"><div class="icon">^</div><a href="{{ url_for('admin_user_files', user_id=user_id, subpath=parent) }}">Parent directory</a><span class="meta">FOLDER</span><span></span></div>{% endif %}{% for item in items %}<div class="row"><div class="icon{% if not item.is_dir %} file{% endif %}">{% if item.is_dir %}[ ]{% else %}..{% endif %}</div>{% if item.is_dir %}<a href="{{ url_for('admin_user_files', user_id=user_id, subpath=item.path) }}">{{ item.name }}</a>{% else %}<span>{{ item.name }}</span>{% endif %}<span class="meta">{% if item.is_dir %}FOLDER{% else %}{{ item.size|filesize }}{% endif %}</span>{% if not item.is_dir %}<a class="download" href="{{ url_for('admin_user_download', user_id=user_id, subpath=item.path) }}">DOWNLOAD</a>{% else %}<span></span>{% endif %}</div>{% else %}<div class="empty">No files in this directory.</div>{% endfor %}</section></main></body></html>
"""


_flask_render_template_string = render_template_string


def csrf_token():
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def render_template_string(template, *args, **kwargs):
    """Render existing inline templates while adding CSRF fields to POST forms."""
    admin_markers = ("Role-based administration", "Admin panel - Cloud Rdx", "Control center", "Audit activity - Cloud Rdx", "Recycle bin - Cloud Rdx", "Admin read-only - Cloud Rdx", "Administration - Cloud Rdx", "Website settings - Cloud Rdx", "Payment verification - Cloud Rdx", "User storage quotas - Cloud Rdx", "Access control - Cloud Rdx", "Active sessions and devices", "Enable authenticator 2FA", "Authenticator 2FA enabled")
    admin_page = any(marker in template for marker in admin_markers)
    protected_page = not any(marker in template for marker in (*admin_markers, "Sign in - RDx Cloud Storage-DB16", "Create account - Cloud Rdx", "Password recovery", "Security verification - Cloud Rdx"))
    if "csrf_token" not in kwargs:
        kwargs["csrf_token"] = csrf_token()
    template = re.sub(
        r'<form(\s[^>]*method=["\']post["\'][^>]*)>',
        r'<form\1><input type="hidden" name="csrf_token" value="{{ csrf_token }}">',
        template,
        flags=re.IGNORECASE,
    )
    template = template.replace(
        "<head>",
        '<head><link rel="stylesheet" href="{{ url_for(\'static\', filename=\'admin-theme.css\') }}">',
        1,
    )
    if any(marker in template for marker in ("Create account - Cloud Rdx", "Password recovery")):
        template = template.replace(
            "admin-theme.css') }}\">",
            "admin-theme.css') }}\"><link rel=\"stylesheet\" href=\"{{ url_for('static', filename='auth.css') }}\">",
            1,
        )
    if admin_page:
        template = template.replace("<body>", '<body class="admin-theme">', 1)
    if admin_page and "admin-mobile-toggle" not in template:
        template = template.replace(
            "<body class=\"admin-theme\">",
            '<body class="admin-theme"><button class="admin-mobile-toggle" type="button" aria-label="Open admin navigation" aria-expanded="false">☰</button><button class="admin-mobile-backdrop" type="button" aria-label="Close admin navigation" tabindex="-1"></button>',
            1,
        )
        template = template.replace(
            "</body>",
            """<script>
(() => {
    const body = document.body;
    const rail = document.querySelector('.admin-theme .rail');
    const toggle = document.querySelector('.admin-mobile-toggle');
    const backdrop = document.querySelector('.admin-mobile-backdrop');
    if (!rail || !toggle || !backdrop) return;
    const setOpen = (open) => {
        rail.classList.toggle('admin-open', open);
        body.classList.toggle('admin-menu-open', open);
        toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        toggle.setAttribute('aria-label', open ? 'Close admin navigation' : 'Open admin navigation');
    };
    toggle.addEventListener('click', () => setOpen(!rail.classList.contains('admin-open')));
    backdrop.addEventListener('click', () => setOpen(false));
    rail.querySelectorAll('a').forEach((link) => link.addEventListener('click', () => setOpen(false)));
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape') setOpen(false); });
})();
</script></body>""",
            1,
        )
    if protected_page and "content-protection.js" not in template:
        template = template.replace(
            "</body>",
            '<script src="{{ url_for(\'static\', filename=\'content-protection.js\') }}" defer></script></body>',
            1,
        )
    return _flask_render_template_string(template, *args, **kwargs)


def audit_event(action, target_type, target_id=None, details="", status="success", actor_id=None, risk_level="LOW"):
    actor_id = actor_id if actor_id is not None else session.get("user_id")
    created_at = datetime.now(timezone.utc).isoformat()
    with database_connection() as connection:
        connection.execute(
            "INSERT INTO audit_events (actor_id, action, target_type, target_id, details, status, created_at, ip_address, risk_level, session_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (actor_id, action, target_type, str(target_id) if target_id is not None else None, details[:2000], status, created_at, request_ip(), risk_level, session.get("device_token", "")[:16] or None),
        )
        if actor_id is not None and status == "success":
            activity_windows = {
                "upload": (
                    ("upload",),
                    20,
                    "HIGH",
                    "unusual_upload_spike",
                    "More than 20 successful uploads were recorded for one account in five minutes.",
                ),
                "download": (
                    ("download", "bulk_download"),
                    40,
                    "HIGH",
                    "unusual_download_spike",
                    "More than 40 successful downloads were recorded for one account in five minutes.",
                ),
                "file_change": (
                    ("create_folder", "delete_to_trash", "copy_file", "move_file", "rename_file"),
                    30,
                    "MEDIUM",
                    "rapid_file_modifications",
                    "More than 30 successful file changes were recorded for one account in five minutes.",
                ),
            }
            if action == "upload":
                activity_type = "upload"
            elif action in {"download", "bulk_download"}:
                activity_type = "download"
            elif action in {
                "create_folder", "delete_to_trash", "restore_from_trash",
                "purge_trash", "restore_own_trash", "purge_own_trash",
            }:
                activity_type = "file_change"
            else:
                activity_type = None
            if activity_type:
                actions, threshold, severity, alert_type, alert_details = activity_windows[
                    activity_type
                ]
                cutoff = (
                    datetime.fromisoformat(created_at) - timedelta(minutes=5)
                ).isoformat()
                placeholders = ",".join("?" for _ in actions)
                count = connection.execute(
                    f"""
                    SELECT COUNT(*) AS count FROM audit_events
                    WHERE actor_id = ? AND status = 'success'
                      AND action IN ({placeholders}) AND created_at >= ?
                    """,
                    (actor_id, *actions, cutoff),
                ).fetchone()["count"]
                if count > threshold:
                    account = connection.execute(
                        "SELECT username FROM users WHERE id = ?", (actor_id,)
                    ).fetchone()
                    create_security_alert(
                        connection,
                        severity,
                        alert_type,
                        account["username"] if account else None,
                        request_ip(),
                        f"{alert_details} Observed: {count}.",
                        created_at,
                    )
        if action == "account_created":
            cutoff = (
                datetime.fromisoformat(created_at) - timedelta(minutes=10)
            ).isoformat()
            creations = connection.execute(
                """
                SELECT COUNT(*) AS count FROM audit_events
                WHERE action = 'account_created' AND ip_address = ?
                  AND created_at >= ?
                """,
                (request_ip(), cutoff),
            ).fetchone()["count"]
            if creations >= 10:
                create_security_alert(
                    connection,
                    "MEDIUM",
                    "unusual_account_creation_spike",
                    None,
                    request_ip(),
                    f"{creations} accounts were created from one IP within ten minutes.",
                    created_at,
                )


def user_usage(user_id):
    folder = SHARED_FOLDER / "users" / str(user_id)
    files = [path for path in folder.rglob("*") if path.is_file()] if folder.exists() else []
    return len(files), sum(path.stat().st_size for path in files)


def user_quota(user_id):
    with database_connection() as connection:
        row = connection.execute("SELECT quota_bytes FROM quotas WHERE user_id = ?", (user_id,)).fetchone()
        if row:
            return int(row["quota_bytes"])
        free = connection.execute("SELECT quota_bytes FROM storage_plans WHERE code = 'free' AND active = 1").fetchone()
    return int(free["quota_bytes"]) if free else 5 * 1024**3


def plan_rows():
    with database_connection() as connection:
        return connection.execute("SELECT * FROM storage_plans WHERE active = 1 ORDER BY quota_bytes").fetchall()


def current_subscription(user_id):
    with database_connection() as connection:
        row = connection.execute("""
            SELECT subscriptions.*, storage_plans.name AS plan_name
            FROM subscriptions JOIN storage_plans ON storage_plans.id = subscriptions.plan_id
            WHERE subscriptions.user_id = ? AND subscriptions.status IN ('pending', 'active')
            ORDER BY subscriptions.id DESC LIMIT 1
        """, (user_id,)).fetchone()
    return dict(row) if row else None


def razorpay_client():
    if not razorpay or not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        return None
    return razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))


def activate_subscription(user_id, plan_id, provider, provider_subscription_id=None):
    now = datetime.now(timezone.utc).isoformat()
    with database_connection() as connection:
        if provider_subscription_id:
            existing = connection.execute("SELECT plan_id FROM subscriptions WHERE provider_subscription_id = ?", (provider_subscription_id,)).fetchone()
            if existing:
                plan = connection.execute("SELECT * FROM storage_plans WHERE id = ?", (existing["plan_id"],)).fetchone()
                return dict(plan)
        plan = connection.execute("SELECT * FROM storage_plans WHERE id = ? AND active = 1", (plan_id,)).fetchone()
        if not plan:
            raise ValueError("Storage plan not found")
        connection.execute("UPDATE subscriptions SET status = 'replaced', updated_at = ? WHERE user_id = ? AND status = 'active'", (now, user_id))
        connection.execute("""
            INSERT INTO subscriptions (user_id, plan_id, provider, provider_subscription_id, status, quota_bytes, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
        """, (user_id, plan_id, provider, provider_subscription_id, plan["quota_bytes"], now, now))
        connection.execute("""
            INSERT INTO quotas (user_id, quota_bytes, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET quota_bytes = excluded.quota_bytes, updated_at = excluded.updated_at
        """, (user_id, plan["quota_bytes"], now))
    return dict(plan)


def quota_allows(user_id, additional_bytes):
    quota = user_quota(user_id)
    if quota <= 0:
        return True
    return user_usage(user_id)[1] + additional_bytes <= quota


def trash_item(user_id, target, deleted_by):
    base = SHARED_FOLDER / "users" / str(user_id)
    target = target.resolve()
    target.relative_to(base.resolve())
    trash_root = SHARED_FOLDER / ".trash" / str(user_id)
    trash_root.mkdir(parents=True, exist_ok=True)
    is_dir = target.is_dir()
    trash_path = trash_root / f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}_{secrets.token_hex(4)}_{target.name}"
    relative = target.relative_to(base).as_posix()
    shutil.move(str(target), str(trash_path))
    with database_connection() as connection:
        cursor = connection.execute(
            "INSERT INTO trash_items (user_id, original_path, trash_path, item_name, is_dir, deleted_by, deleted_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, relative, str(trash_path), target.name, int(is_dir), deleted_by, datetime.now(timezone.utc).isoformat()),
        )
    audit_event("delete_to_trash", "folder" if is_dir else "file", cursor.lastrowid, f"user={user_id}; path={relative}", actor_id=deleted_by)
    return cursor.lastrowid


@app.route("/admin/users/<int:user_id>/files/")
@app.route("/admin/users/<int:user_id>/files/<path:subpath>")
def admin_user_files(user_id, subpath=""):
    response = require_permission("storage.manage")
    if response:
        return response
    try:
        user, base, folder = admin_user_path(user_id, subpath)
    except ValueError:
        abort(404, "User or path not found")
    if not folder.is_dir():
        abort(404, "Folder not found")
    items = []
    for path in sorted(folder.iterdir(), key=lambda entry: (not entry.is_dir(), entry.name.lower())):
        items.append({"name": path.name, "path": path.relative_to(base).as_posix(), "is_dir": path.is_dir(), "size": path.stat().st_size if path.is_file() else 0})
    parent = Path(subpath).parent.as_posix() if subpath else None
    if parent == ".":
        parent = ""
    parts = [part for part in Path(subpath).parts if part not in (".", "")]
    crumbs = [{"name": name, "url": url_for("admin_user_files", user_id=user_id, subpath="/".join(parts[:index + 1]))} for index, name in enumerate(parts)]
    return render_template_string(ADMIN_FILES_PAGE, username=user["username"], user_id=user_id, subpath=subpath, parent=parent, breadcrumbs=crumbs, items=items)


@app.route("/admin/users/<int:user_id>/download/<path:subpath>")
def admin_user_download(user_id, subpath):
    response = require_permission("storage.manage")
    if response:
        return response
    try:
        user, base, target = admin_user_path(user_id, subpath)
    except ValueError:
        abort(404, "User or path not found")
    if not target.is_file():
        abort(404, "File not found")
    return send_from_directory(target.parent, target.name, as_attachment=True)


@app.route("/admin/users/<int:user_id>/password", methods=["POST"])
def admin_password(user_id):
    response = require_permission("users.manage")
    if response:
        return response
    password = request.form.get("password", "")
    if len(password) < 8:
        flash("Passwords must be at least 8 characters.")
    else:
        with database_connection() as connection:
            result = connection.execute("UPDATE users SET password_hash = ?, password_login_enabled = 1 WHERE id = ? AND is_admin = 0", (hash_password(password), user_id))
        flash("Password updated." if result.rowcount else "User not found or protected.")
    return redirect(url_for("admin_panel"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def admin_delete_user(user_id):
    response = require_permission("users.manage")
    if response:
        return response
    if user_id == session["user_id"]:
        flash("The active administrator account cannot remove itself.")
        return redirect(url_for("admin_panel"))
    with database_connection() as connection:
        user = connection.execute("SELECT id, username, is_admin, status FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        abort(404, "User not found")
    if user["is_admin"]:
        flash("Administrator accounts are protected from deletion.")
        return redirect(url_for("admin_panel"))
    folder = SHARED_FOLDER / "users" / str(user_id)
    if folder.exists() and any(folder.iterdir()):
        trash_item(user_id, folder, session["user_id"])
    with database_connection() as connection:
        connection.execute("UPDATE users SET status = 'suspended', suspended_at = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), user_id))
    audit_event("delete_user_to_trash", "user", user_id, f"username={user['username']}")
    flash(f"User {user['username']} was suspended and their storage moved to the recycle bin.")
    return redirect(url_for("admin_panel"))


@app.route("/admin/trash")
def admin_trash():
    response = require_permission("storage.recycle_bin")
    if response:
        return response
    with database_connection() as connection:
        items = connection.execute("""
            SELECT trash_items.*, users.username FROM trash_items
            JOIN users ON users.id = trash_items.user_id
            WHERE restored_at IS NULL AND purged_at IS NULL
            ORDER BY deleted_at DESC
        """).fetchall()
    return render_template_string(ADMIN_TRASH_PAGE, items=[dict(item) for item in items])


@app.route("/admin/trash/<int:trash_id>/restore", methods=["POST"])
def admin_restore_trash(trash_id):
    response = require_permission("storage.recycle_bin")
    if response:
        return response
    with database_connection() as connection:
        item = connection.execute("SELECT * FROM trash_items WHERE id = ? AND restored_at IS NULL AND purged_at IS NULL", (trash_id,)).fetchone()
    if not item:
        abort(404, "Trash item not found")
    base = SHARED_FOLDER / "users" / str(item["user_id"])
    destination = base / item["original_path"]
    source = Path(item["trash_path"])
    if not source.exists() or destination.exists():
        flash("Restore could not complete because the source is missing or the destination already exists.")
        return redirect(url_for("admin_trash"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(destination))
    with database_connection() as connection:
        connection.execute("UPDATE trash_items SET restored_at = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), trash_id))
    audit_event("restore_from_trash", "file" if not item["is_dir"] else "folder", trash_id, f"user={item['user_id']}; path={item['original_path']}")
    flash("Item restored successfully.")
    return redirect(url_for("admin_trash"))


@app.route("/admin/trash/<int:trash_id>/purge", methods=["POST"])
def admin_purge_trash(trash_id):
    response = require_permission("storage.recycle_bin")
    if response:
        return response
    with database_connection() as connection:
        item = connection.execute("SELECT * FROM trash_items WHERE id = ? AND restored_at IS NULL AND purged_at IS NULL", (trash_id,)).fetchone()
    if not item:
        abort(404, "Trash item not found")
    source = Path(item["trash_path"]).resolve()
    trash_root = (SHARED_FOLDER / ".trash" / str(item["user_id"])).resolve()
    try:
        source.relative_to(trash_root)
    except ValueError:
        abort(400, "Invalid trash path")
    if source.exists():
        if source.is_dir():
            shutil.rmtree(source)
        else:
            source.unlink()
    with database_connection() as connection:
        connection.execute("UPDATE trash_items SET purged_at = ? WHERE id = ? AND restored_at IS NULL AND purged_at IS NULL", (datetime.now(timezone.utc).isoformat(), trash_id))
    audit_event("purge_trash", "folder" if item["is_dir"] else "file", trash_id, f"user={item['user_id']}; path={item['original_path']}")
    flash("Item permanently deleted.")
    return redirect(url_for("admin_trash"))


@app.route("/admin/backup", methods=["POST"])
def admin_backup():
    """Create an explicit local snapshot; this is not a cloud-provider backup."""
    response = require_permission("storage.manage")
    if response:
        return response
    backup_root = SHARED_FOLDER / ".backups"
    backup_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = backup_root / f"cloud_rdx_{stamp}.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as backup:
        for path in (SHARED_FOLDER / "users").rglob("*"):
            if path.is_file():
                backup.write(path, Path("users") / path.relative_to(SHARED_FOLDER / "users"))
        with database_connection() as connection:
            users = [dict(row) for row in connection.execute("SELECT id, username, status, created_at FROM users").fetchall()]
        backup.writestr("manifest.txt", "Cloud Rdx local snapshot\n" + "\n".join(f"{item['id']} {item['username']} {item['status']}" for item in users))
    audit_event("create_backup", "backup", archive.name, "local zip snapshot")
    flash(f"Local backup created: {archive.name}. Store a copy separately for disaster recovery.")
    return redirect(url_for("admin_manage"))


@app.route("/recycle-bin")
@app.route("/recycle-bin/")
def user_trash():
    response = require_storage_user()
    if response:
        return response
    with database_connection() as connection:
        items = connection.execute("SELECT * FROM trash_items WHERE user_id = ? AND restored_at IS NULL AND purged_at IS NULL ORDER BY deleted_at DESC", (session["user_id"],)).fetchall()
    return render_template_string(USER_TRASH_PAGE, items=[dict(item) for item in items])


def user_trash_item(trash_id):
    with database_connection() as connection:
        item = connection.execute("SELECT * FROM trash_items WHERE id = ? AND user_id = ? AND restored_at IS NULL AND purged_at IS NULL", (trash_id, session["user_id"])).fetchone()
    if not item:
        abort(404, "Recycle-bin item not found")
    trash_root = (SHARED_FOLDER / ".trash" / str(session["user_id"])).resolve()
    source = Path(item["trash_path"]).resolve()
    try:
        source.relative_to(trash_root)
    except ValueError:
        abort(400, "Invalid recycle-bin path")
    return item, trash_root, source


@app.route("/recycle-bin/<int:trash_id>/restore", methods=["POST"])
def restore_user_trash(trash_id):
    response = require_storage_user()
    if response:
        return response
    require_storage_operation("edit")
    item, trash_root, source = user_trash_item(trash_id)
    base = user_folder().resolve()
    destination = (base / item["original_path"]).resolve()
    try:
        destination.relative_to(base)
    except ValueError:
        abort(400, "Invalid restore path")
    if not source.exists() or destination.exists():
        flash("Restore could not complete because the source is missing or the destination already exists.")
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(destination))
        with database_connection() as connection:
            connection.execute("UPDATE trash_items SET restored_at = ? WHERE id = ? AND user_id = ?", (datetime.now(timezone.utc).isoformat(), trash_id, session["user_id"]))
        audit_event("restore_own_trash", "folder" if item["is_dir"] else "file", trash_id, f"path={item['original_path']}")
        flash(f"{item['item_name']} was restored.")
    return redirect(url_for("user_trash"))


@app.route("/recycle-bin/<int:trash_id>/purge", methods=["POST"])
def purge_user_trash(trash_id):
    response = require_storage_user()
    if response:
        return response
    require_storage_operation("delete")
    item, trash_root, source = user_trash_item(trash_id)
    if source.exists():
        shutil.rmtree(source) if source.is_dir() else source.unlink()
    with database_connection() as connection:
        connection.execute("UPDATE trash_items SET purged_at = ? WHERE id = ? AND user_id = ? AND restored_at IS NULL AND purged_at IS NULL", (datetime.now(timezone.utc).isoformat(), trash_id, session["user_id"]))
    audit_event("purge_own_trash", "folder" if item["is_dir"] else "file", trash_id, f"path={item['original_path']}")
    flash(f"{item['item_name']} was permanently deleted.")
    return redirect(url_for("user_trash"))


@app.route("/admin/security/2fa", methods=["GET", "POST"])
def admin_2fa():
    response = require_admin()
    if response:
        return response
    require_totp_available()
    user = current_user()
    if user["totp_enabled"]:
        return render_template_string("""<!doctype html><title>2FA security</title><link rel='stylesheet' href='{{ url_for('static', filename='admin-theme.css') }}'><body class='admin-theme'><main class='main'><h1>Authenticator 2FA enabled</h1><p>Your administrator account requires an authenticator code at sign-in.</p><a class='button' href='{{ url_for('admin_panel') }}'>Back to dashboard</a></main></body>""")
    secret = session.get("totp_setup_secret") or pyotp.random_base32()
    session["totp_setup_secret"] = secret
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if not pyotp.TOTP(secret).verify(code, valid_window=1):
            return render_template_string(TOTP_SETUP_PAGE, secret=secret, provisioning_uri=pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name="Cloud Rdx"), error="Enter a valid code from your authenticator app.")
        with database_connection() as connection:
            connection.execute("UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?", (secret, user["id"]))
        session.pop("totp_setup_secret", None)
        audit_event("enable_2fa", "user", user["id"])
        flash("Authenticator 2FA is now enabled for your administrator account.")
        return redirect(url_for("admin_panel"))
    return render_template_string(TOTP_SETUP_PAGE, secret=secret, provisioning_uri=pyotp.TOTP(secret).provisioning_uri(name=user["username"], issuer_name="Cloud Rdx"), error=None)


@app.route("/admin/security/sessions")
def admin_sessions():
    response = require_login()
    if response:
        return response
    with database_connection() as connection:
        sessions = connection.execute("SELECT id, device_label, ip_address, created_at, last_seen, revoked_at FROM device_sessions WHERE user_id = ? ORDER BY last_seen DESC", (session["user_id"],)).fetchall()
    return render_template_string(ADMIN_SESSIONS_PAGE, sessions=[dict(row) for row in sessions])


@app.route("/admin/security/sessions/<int:session_id>/revoke", methods=["POST"])
def revoke_admin_session(session_id):
    response = require_login()
    if response:
        return response
    with database_connection() as connection:
        result = connection.execute("UPDATE device_sessions SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL", (datetime.now(timezone.utc).isoformat(), session_id, session["user_id"]))
    if result.rowcount:
        audit_event("revoke_session", "device_session", session_id)
        flash("The selected device session was revoked.")
    return redirect(url_for("admin_sessions"))


TOTP_SETUP_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Enable 2FA</title><link rel="stylesheet" href="{{ url_for('static', filename='admin-theme.css') }}"></head><body class="admin-theme"><main class="main"><section class="panel" style="max-width:700px;margin:40px auto"><div class="panel-head"><h2>Enable authenticator 2FA</h2><p>Add this account to an authenticator app, then verify one generated code.</p></div><div style="padding:22px"><p><strong>Setup key</strong></p><p style="word-break:break-all;font-family:monospace">{{ secret }}</p><p><strong>Provisioning URI</strong></p><p style="word-break:break-all;font-family:monospace">{{ provisioning_uri }}</p>{% if error %}<p class="notice">{{ error }}</p>{% endif %}<form method="post"><label for="code">Six-digit authenticator code</label><input id="code" name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required><button type="submit">Enable 2FA</button></form></div></section></main></body></html>
"""


ADMIN_SESSIONS_PAGE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sessions</title><link rel="stylesheet" href="{{ url_for('static', filename='admin-theme.css') }}"></head><body class="admin-theme"><main class="main"><section class="panel" style="margin:40px auto;max-width:900px"><div class="panel-head"><h2>Active sessions and devices</h2><p>Revoke any device you no longer recognize. The current session cannot be revoked from this page.</p></div><div class="table-responsive"><table><thead><tr><th>Device</th><th>IP</th><th>Created</th><th>Last seen</th><th>Status</th><th></th></tr></thead><tbody>{% for item in sessions %}<tr><td>{{ item.device_label }}</td><td>{{ item.ip_address or 'Unknown' }}</td><td>{{ item.created_at[:19].replace('T',' ') }}</td><td>{{ item.last_seen[:19].replace('T',' ') }}</td><td>{{ 'Revoked' if item.revoked_at else 'Active' }}</td><td>{% if not item.revoked_at %}<form method="post" action="{{ url_for('revoke_admin_session', session_id=item.id) }}"><button class="danger" type="submit">Revoke</button></form>{% endif %}</td></tr>{% else %}<tr><td colspan="6">No sessions recorded.</td></tr>{% endfor %}</tbody></table></div></section></main></body></html>
"""


@app.route("/logout")
def logout():
    token = session.get("device_token")
    if token:
        with database_connection() as connection:
            connection.execute("UPDATE device_sessions SET revoked_at = ? WHERE session_token_hash = ? AND revoked_at IS NULL", (datetime.now(timezone.utc).isoformat(), device_token_hash(token)))
    session.clear()
    return redirect(url_for("login"))


@app.route("/guide/cloud-storage")
def cloud_storage_guide():
    response = require_login()
    if response:
        return response
    return render_template_string(
        CLOUD_STORAGE_GUIDE_PAGE,
        back_url=url_for("admin_panel" if is_admin() else "files"),
    )


@app.route("/files/")
@app.route("/files/<path:subpath>")
def files(subpath=""):
    redirect_response = require_storage_user()
    if redirect_response:
        return redirect_response
    try:
        folder = safe_path(subpath)
    except ValueError:
        abort(400, "Invalid path")
    if not folder.is_dir():
        abort(404, "Folder not found")

    items = []
    total_size = 0
    for path in sorted(folder.iterdir(), key=lambda entry: (not entry.is_dir(), entry.name.lower())):
        item = {"name": path.name, "path": path.relative_to(folder).as_posix() if not subpath else (Path(subpath) / path.name).as_posix(), "is_dir": path.is_dir(), "size": 0}
        if path.is_file():
            item["size"] = path.stat().st_size
            total_size += item["size"]
        items.append(item)

    parent = Path(subpath).parent.as_posix() if subpath else None
    if parent == ".":
        parent = ""
    user = current_user()
    quota = user_quota(user["id"])
    used = user_usage(user["id"])[1]
    quota_percent = min(100, int(used * 100 / quota)) if quota else 0
    remaining_size = max(0, quota - used) if quota else 0
    return render_template_string(PAGE, title="My storage", items=items, subpath=subpath, parent=parent, breadcrumbs=breadcrumbs(subpath), item_count=len(items), total_size=used, quota=quota, remaining_size=remaining_size, quota_percent=quota_percent, allow_upload=storage_permission(user["id"], "upload"), allow_download=storage_permission(user["id"], "download"), allow_share=policy_enabled("allow_public_sharing", False) and not emergency_enabled("disable_file_sharing"), has_admin_access=has_admin_access(), admin_title=admin_console_context()["admin_title"])


@app.route("/download/<path:subpath>")
def download(subpath):
    redirect_response = require_storage_permission("download")
    if redirect_response:
        return redirect_response
    try:
        full = safe_path(subpath)
    except ValueError:
        abort(400, "Invalid path")
    if not full.is_file():
        abort(404, "File not found")
    audit_event(
        "download",
        "file",
        full.name,
        f"path={full.relative_to(user_folder()).as_posix()}; size={full.stat().st_size}",
    )
    return send_from_directory(full.parent, full.name, as_attachment=True)


@app.route("/downloads/bulk", methods=["POST"])
def bulk_download():
    redirect_response = require_storage_permission("download")
    if redirect_response:
        return redirect_response
    selected_paths = list(dict.fromkeys(request.form.getlist("paths")))
    if not selected_paths:
        abort(400, "Select at least one file")
    if len(selected_paths) > 100:
        abort(400, "You can download up to 100 files at a time")
    user = current_user()
    files_to_archive = []
    total_size = 0
    for relative_path in selected_paths:
        try:
            target = safe_path(relative_path)
        except ValueError:
            abort(400, "Invalid file selection")
        if not target.is_file():
            abort(400, "Bulk downloads support files only")
        size = target.stat().st_size
        total_size += size
        files_to_archive.append((target, relative_path))
    if total_size > MAX_UPLOAD_BYTES * 10:
        abort(400, "The selected files are too large for one archive")
    archive_fd, archive_name = tempfile.mkstemp(prefix="cloud_rdx_", suffix=".zip")
    os.close(archive_fd)
    archive_path = Path(archive_name)
    try:
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for target, relative_path in files_to_archive:
                archive.write(target, Path(relative_path).as_posix())
        audit_event("bulk_download", "archive", archive_path.name, f"count={len(files_to_archive)}; size={total_size}")
        response = send_file(archive_path, as_attachment=True, download_name="cloud_rdx_files.zip", mimetype="application/zip")
        response.call_on_close(lambda: archive_path.unlink(missing_ok=True))
        return response
    except Exception:
        archive_path.unlink(missing_ok=True)
        raise


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def install_file_without_overwrite(staged_path, destination):
    try:
        os.link(staged_path, destination)
    except FileExistsError:
        return False
    Path(staged_path).unlink()
    return True


@app.route("/upload/<path:subpath>", methods=["POST"])
@app.route("/upload/", methods=["POST"])
def upload(subpath=""):
    redirect_response = require_storage_permission("upload")
    if redirect_response:
        return redirect_response
    try:
        folder = safe_path(subpath)
    except ValueError:
        abort(400, "Invalid path")
    if not folder.is_dir():
        abort(404, "Folder not found")
    uploaded = request.files.get("file")
    filename = secure_filename(uploaded.filename) if uploaded else ""
    if not filename:
        flash("Choose a file before uploading.")
        return redirect(url_for("files", subpath=subpath))
    destination = folder / filename
    if destination.exists():
        flash("A file or folder with that name already exists. Rename it before uploading.")
        return redirect(url_for("files", subpath=subpath))
    uploaded.stream.seek(0, os.SEEK_END)
    upload_size = uploaded.stream.tell()
    uploaded.stream.seek(0)
    user = current_user()
    if not quota_allows(user["id"], upload_size):
        audit_event("upload_rejected_quota", "file", filename, f"size={upload_size}", status="denied")
        flash("Upload rejected because it would exceed your storage quota.")
        return redirect(url_for("files", subpath=subpath))
    staging_root = SHARED_FOLDER / ".quarantine" / ".staging"
    staging_root.mkdir(parents=True, exist_ok=True)
    descriptor, staging_name = tempfile.mkstemp(
        prefix="upload-", suffix=".scan", dir=staging_root
    )
    os.close(descriptor)
    staged_path = Path(staging_name)
    try:
        uploaded.save(staged_path)
    except Exception:
        staged_path.unlink(missing_ok=True)
        raise
    try:
        scan_status, detection = scan_with_clamav(staged_path)
    except MalwareScannerUnavailable:
        if os.getenv("CLAMD_REQUIRED", "0").strip().lower() in {
            "1", "true", "yes", "on"
        }:
            staged_path.unlink(missing_ok=True)
            audit_event(
                "upload_scan_unavailable",
                "file",
                filename,
                f"path={destination.relative_to(user_folder())}; size={upload_size}",
                status="denied",
                risk_level="HIGH",
            )
            abort(503, "Upload was not accepted because malware scanning is unavailable.")
        app.logger.warning(
            "ClamAV unavailable; accepting upload without malware scan "
            "(set CLAMD_REQUIRED=1 to reject unscanned uploads)"
        )
        audit_event(
            "upload_scan_unavailable",
            "file",
            filename,
            f"path={destination.relative_to(user_folder())}; size={upload_size}",
            status="warning",
            risk_level="HIGH",
        )
        scan_status, detection = "unscanned", None

    if scan_status == "infected":
        if not detection:
            staged_path.unlink(missing_ok=True)
            audit_event(
                "upload_scan_inconclusive",
                "file",
                filename,
                f"path={destination.relative_to(user_folder())}",
                status="denied",
                risk_level="HIGH",
            )
            abort(503, "Upload was not accepted because the scan result was inconclusive.")
        digest = file_sha256(staged_path)
        user_quarantine = SHARED_FOLDER / ".quarantine" / str(user["id"])
        user_quarantine.mkdir(parents=True, exist_ok=True)
        quarantine_path = user_quarantine / f"{secrets.token_hex(16)}.quarantine"
        os.replace(staged_path, quarantine_path)
        with database_connection() as connection:
            connection.execute(
                """
                INSERT INTO quarantined_files
                    (user_id, original_path, quarantine_path, sha256, detection,
                     created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user["id"],
                    Path(subpath, filename).as_posix(),
                    str(quarantine_path),
                    digest,
                    detection[:255],
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        audit_event(
            "malware_quarantined",
            "file",
            filename,
            f"path={Path(subpath, filename).as_posix()}; sha256={digest}; detection={detection[:180]}",
            status="denied",
            risk_level="CRITICAL",
        )
        flash("The file was isolated in quarantine because ClamAV detected malware.")
        return redirect(url_for("files", subpath=subpath))
    if scan_status not in {"clean", "unscanned"}:
        staged_path.unlink(missing_ok=True)
        audit_event(
            "upload_scan_inconclusive",
            "file",
            filename,
            f"path={destination.relative_to(user_folder())}",
            status="denied",
            risk_level="HIGH",
        )
        abort(503, "Upload was not accepted because the scan result was inconclusive.")
    if scan_status not in {"clean", "unscanned"}:
        staged_path.unlink(missing_ok=True)
        audit_event(
            "upload_scan_inconclusive",
            "file",
            filename,
            f"path={destination.relative_to(user_folder())}",
            status="denied",
            risk_level="HIGH",
        )
        abort(503, "Upload was not accepted because the scan result was inconclusive.")

    if not install_file_without_overwrite(staged_path, destination):
        staged_path.unlink(missing_ok=True)
        flash("A file or folder with that name already exists. Rename it before uploading.")
        return redirect(url_for("files", subpath=subpath))
    audit_event("upload", "file", filename, f"path={destination.relative_to(user_folder())}; size={upload_size}")
    flash(f"{filename} was added to your storage.")
    return redirect(url_for("files", subpath=subpath))


@app.route("/folder/<path:subpath>", methods=["POST"])
@app.route("/folder/", methods=["POST"])
def create_folder(subpath=""):
    redirect_response = require_storage_user()
    if redirect_response:
        return redirect_response
    require_storage_operation("edit")
    try:
        folder = safe_path(subpath)
    except ValueError:
        abort(400, "Invalid path")
    name = secure_filename(request.form.get("name", ""))
    if not name or name in {".", ".."}:
        flash("Enter a valid folder name.")
    elif (folder / name).exists():
        flash("That folder already exists.")
    else:
        (folder / name).mkdir()
        audit_event("create_folder", "folder", name, f"path={Path(subpath, name).as_posix()}")
        flash(f"Folder {name} created.")
    return redirect(url_for("files", subpath=subpath))


def storage_mutation(action, subpath, destination_name):
    user = current_user()
    require_storage_operation("edit")
    source = safe_path(subpath)
    if not source.exists() or source == user_folder():
        abort(404, "Item not found")
    name = secure_filename(destination_name)
    if not name or name in {".", ".."}:
        abort(400, "Invalid destination name")
    destination = source.parent / name
    destination = destination.resolve()
    destination.relative_to(user_folder().resolve())
    if destination.exists():
        abort(409, "Destination already exists")
    is_dir = source.is_dir()
    if action == "copy":
        shutil.copytree(source, destination) if is_dir else shutil.copy2(source, destination)
    elif action == "move":
        shutil.move(str(source), str(destination))
    elif action == "rename":
        source.rename(destination)
    else:
        abort(400, "Unsupported operation")
    audit_event(action, "folder" if is_dir else "file", subpath, f"destination={destination.relative_to(user_folder())}")
    return redirect(url_for("files", subpath=Path(subpath).parent.as_posix() if Path(subpath).parent.as_posix() != "." else ""))


@app.route("/rename/<path:subpath>", methods=["POST"])
def rename_item(subpath):
    response = require_storage_user()
    if response:
        return response
    return storage_mutation("rename", subpath, request.form.get("name", ""))


@app.route("/copy/<path:subpath>", methods=["POST"])
def copy_item(subpath):
    response = require_storage_user()
    if response:
        return response
    return storage_mutation("copy", subpath, request.form.get("name", ""))


@app.route("/move/<path:subpath>", methods=["POST"])
def move_item(subpath):
    response = require_storage_user()
    if response:
        return response
    return storage_mutation("move", subpath, request.form.get("name", ""))


@app.route("/delete/<path:subpath>", methods=["POST"])
def delete_item(subpath):
    redirect_response = require_storage_user()
    if redirect_response:
        return redirect_response
    require_storage_operation("delete")
    try:
        target = safe_path(subpath)
    except ValueError:
        abort(400, "Invalid path")
    if not target.exists() or target == user_folder():
        abort(404, "Item not found")
    user = current_user()
    trash_item(user["id"], target, user["id"])
    flash(f"{target.name} moved to the recycle bin. It can be restored by an administrator.")
    return redirect(url_for("files", subpath=Path(subpath).parent.as_posix() if Path(subpath).parent.as_posix() != "." else ""))


def run_desktop_application():
    """Run the Flask interface inside a native desktop window."""
    try:
        import webview
    except ImportError as error:
        raise RuntimeError(
            "The desktop runtime is not installed. Install dependencies with: pip install -r requirements.txt"
        ) from error

    SHARED_FOLDER.mkdir(parents=True, exist_ok=True)
    initialize_database()
    server = make_server("127.0.0.1", 0, app, threaded=True)
    server_thread = threading.Thread(target=server.serve_forever, name="cloud-rdx-server", daemon=True)
    server_thread.start()
    window = webview.create_window(
        "Cloud Rdx",
        f"http://127.0.0.1:{server.server_port}",
        width=1360,
        height=860,
        min_size=(980, 640),
        resizable=True,
        text_select=True,
    )
    window.events.closed += server.shutdown
    webview.start(debug=False)


def run_web_application():
    """Start the Flask application so it is reachable from a browser or host."""
    SHARED_FOLDER.mkdir(parents=True, exist_ok=True)
    initialize_database()
    print(f"Cloud Rdx is running at http://127.0.0.1:{PORT}", flush=True)
    if HOST not in {"127.0.0.1", "localhost"}:
        print(f"Network access is available at http://{HOST}:{PORT}", flush=True)
    app.run(host=HOST, port=PORT, debug=False, threaded=True, use_reloader=False)


if __name__ == "__main__":
    # Packaged desktop builds keep their native window. Running app.py directly
    # starts a normal web server, which is also the entrypoint used by hosts.
    if getattr(sys, "frozen", False) or os.getenv("CLOUD_RDX_DESKTOP", "").lower() in {"1", "true", "yes"}:
        run_desktop_application()
    else:
        run_web_application()




