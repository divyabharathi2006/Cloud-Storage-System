import os
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from io import BytesIO, StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from werkzeug.exceptions import HTTPException


_test_storage = tempfile.TemporaryDirectory(prefix="cloud-rdx-security-tests-")
_test_root = Path(_test_storage.name)
os.environ["SHARED_FOLDER"] = str(_test_root / "storage")
os.environ["FILE_SERVER_DATABASE"] = str(_test_root / "cloud_rdx_test.sqlite3")
os.environ["FLASK_SECRET_KEY"] = "test-only-rate-limit-secret"
os.environ["ADMIN_USERNAME"] = "test-admin"
os.environ["ADMIN_PASSWORD"] = "test-only-admin-password"
os.environ["GOOGLE_OAUTH_CLIENT_ID"] = "test-google-client-id"
os.environ["GOOGLE_OAUTH_CLIENT_SECRET"] = "test-google-client-secret"
os.environ["GITHUB_OAUTH_CLIENT_ID"] = "test-github-client-id"
os.environ["GITHUB_OAUTH_CLIENT_SECRET"] = "test-github-client-secret"
os.environ["APP_BASE_URL"] = "http://127.0.0.1:8000"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

with redirect_stdout(StringIO()):
    import app as cloud_app  # noqa: E402

_original_database_connection = cloud_app.database_connection


@contextmanager
def _closed_test_database_connection():
    connection = _original_database_connection()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


cloud_app.database_connection = _closed_test_database_connection


class RateLimitSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cloud_app.app.config.update(TESTING=True)

    def setUp(self):
        with cloud_app.database_connection() as connection:
            connection.execute("DELETE FROM rate_limit_buckets")
            connection.execute("DELETE FROM login_attempts")
            connection.execute("DELETE FROM security_alerts")
            connection.execute("DELETE FROM device_sessions")
            connection.execute("DELETE FROM policy_acceptances")
            connection.execute("DELETE FROM emergency_events")
            connection.execute("DELETE FROM emergency_incident_notes")
            connection.execute("DELETE FROM emergency_incidents")
            connection.executemany(
                "DELETE FROM policies WHERE name = ?",
                [(name,) for name in cloud_app.EMERGENCY_CONTROL_LABELS],
            )
        cloud_app._RATE_LIMIT_LAST_CLEANUP = 0
        self.client = cloud_app.app.test_client()

    def sign_in_owner(self, client=None):
        client = client or self.client
        now = cloud_app.datetime.now(cloud_app.timezone.utc).isoformat()
        token = "test-admin-settings-device-token"
        with cloud_app.database_connection() as connection:
            admin = connection.execute(
                "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
                (cloud_app.ADMIN_USERNAME,),
            ).fetchone()
            connection.execute(
                """
                INSERT INTO device_sessions
                    (user_id, session_token_hash, device_label, created_at, last_seen)
                VALUES (?, ?, 'Settings test device', ?, ?)
                """,
                (admin["id"], cloud_app.device_token_hash(token), now, now),
            )
            connection.execute(
                """
                INSERT OR REPLACE INTO policy_acceptances
                    (user_id, terms_accepted, privacy_accepted, cookies_accepted,
                     disclaimer_accepted, accepted_at)
                VALUES (?, 1, 1, 1, 1, ?)
                """,
                (admin["id"], now),
            )
        with client.session_transaction() as signed_session:
            signed_session["user_id"] = admin["id"]
            signed_session["device_token"] = token
            signed_session["last_seen"] = now
            signed_session["csrf_token"] = "test-admin-settings-csrf"
        return admin["id"]

    def sign_in_user(self, user_id, client=None):
        client = client or self.client
        now = cloud_app.datetime.now(cloud_app.timezone.utc).isoformat()
        token = "test-profile-device-token"
        with cloud_app.database_connection() as connection:
            connection.execute(
                """
                INSERT INTO device_sessions
                    (user_id, session_token_hash, device_label, created_at, last_seen)
                VALUES (?, ?, 'Profile test device', ?, ?)
                """,
                (user_id, cloud_app.device_token_hash(token), now, now),
            )
            connection.execute(
                """
                INSERT OR REPLACE INTO policy_acceptances
                    (user_id, terms_accepted, privacy_accepted, cookies_accepted,
                     disclaimer_accepted, accepted_at)
                VALUES (?, 1, 1, 1, 1, ?)
                """,
                (user_id, now),
            )
        with client.session_transaction() as signed_session:
            signed_session["user_id"] = user_id
            signed_session["device_token"] = token
            signed_session["last_seen"] = now
            signed_session["csrf_token"] = "test-profile-csrf"

    def test_login_account_limit_returns_429_across_source_ips(self):
        for index in range(20):
            response = self.client.post(
                "/login",
                data={"username": "victim-account", "password": "incorrect"},
                environ_base={"REMOTE_ADDR": f"192.0.{index // 254}.{index % 254 + 1}"},
            )
            self.assertEqual(response.status_code, 200)

        response = self.client.post(
            "/login",
            data={"username": "VICTIM-ACCOUNT", "password": "incorrect"},
            environ_base={"REMOTE_ADDR": "192.0.1.99"},
        )

        self.assertEqual(response.status_code, 429)
        self.assertGreater(int(response.headers["Retry-After"]), 0)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertIn(b"Too many requests", response.data)
        self.assertNotIn(b"victim-account", response.data)

    def test_upload_and_download_work_when_optional_clamav_is_unavailable(self):
        now = cloud_app.datetime.now(cloud_app.timezone.utc).isoformat()
        with cloud_app.database_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users
                    (username, password_hash, created_at, status, is_admin)
                VALUES (?, ?, ?, 'active', 0)
                """,
                (
                    "file-transfer-test-user",
                    cloud_app.hash_password("test-only-password"),
                    now,
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

        self.sign_in_user(user_id)
        with (
            patch.dict(os.environ, {"CLAMD_REQUIRED": "0"}),
            patch.object(
                cloud_app,
                "scan_with_clamav",
                side_effect=cloud_app.MalwareScannerUnavailable(
                    "ClamAV is not configured in this test"
                ),
            ),
        ):
            uploaded = self.client.post(
                "/upload/",
                data={
                    "csrf_token": "test-profile-csrf",
                    "file": (BytesIO(b"transfer works"), "transfer.txt"),
                },
                content_type="multipart/form-data",
                environ_base={"REMOTE_ADDR": "192.0.2.135"},
            )

        self.assertEqual(uploaded.status_code, 302, uploaded.get_data(as_text=True))
        stored = (
            cloud_app.SHARED_FOLDER / "users" / str(user_id) / "transfer.txt"
        )
        self.assertEqual(stored.read_text(encoding="utf-8"), "transfer works")
        downloaded = self.client.get(
            "/download/transfer.txt",
            environ_base={"REMOTE_ADDR": "192.0.2.135"},
        )
        self.assertEqual(downloaded.status_code, 200)
        self.assertEqual(downloaded.data, b"transfer works")

    def test_successful_password_login_records_login_separately_from_activity(self):
        now = cloud_app.datetime.now(cloud_app.timezone.utc).isoformat()
        with cloud_app.database_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users
                    (username, password_hash, created_at, full_name, email,
                     password_login_enabled)
                VALUES (?, ?, ?, ?, ?, 1)
                """,
                (
                    "last-login-test-user",
                    cloud_app.hash_password("test-only-password"),
                    now,
                    "Last Login Test",
                    "last-login-test@example.net",
                ),
            )
            user_id = cursor.lastrowid
            connection.execute(
                """
                INSERT INTO policy_acceptances
                    (user_id, terms_accepted, privacy_accepted, cookies_accepted,
                     disclaimer_accepted, accepted_at)
                VALUES (?, 1, 1, 1, 1, ?)
                """,
                (user_id, now),
            )

        response = self.client.post(
            "/login",
            data={
                "username": "last-login-test-user",
                "password": "test-only-password",
            },
            environ_base={"REMOTE_ADDR": "192.0.2.130"},
        )

        self.assertEqual(response.status_code, 302)
        with cloud_app.database_connection() as connection:
            after_login = connection.execute(
                "SELECT last_login_at, last_seen FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        login_at = after_login["last_login_at"]
        self.assertIsNotNone(login_at)
        self.assertIsNone(after_login["last_seen"])

        profile = self.client.get(
            "/profile", environ_base={"REMOTE_ADDR": "192.0.2.130"}
        )
        self.assertEqual(profile.status_code, 200)
        self.assertIn(b"Last login", profile.data)
        self.assertIn(b"Last account activity", profile.data)
        with cloud_app.database_connection() as connection:
            after_profile_visit = connection.execute(
                "SELECT last_login_at, last_seen FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        self.assertEqual(after_profile_visit["last_login_at"], login_at)
        self.assertIsNotNone(after_profile_visit["last_seen"])
        self.assertGreaterEqual(
            cloud_app.datetime.fromisoformat(after_profile_visit["last_seen"]),
            cloud_app.datetime.fromisoformat(login_at),
        )

    def test_login_ip_limit_returns_429_across_account_names(self):
        for index in range(20):
            response = self.client.post(
                "/login",
                data={"username": f"account-{index}", "password": "incorrect"},
                environ_base={"REMOTE_ADDR": "198.51.100.24"},
            )
            self.assertEqual(response.status_code, 200)

        response = self.client.post(
            "/login",
            data={"username": "another-account", "password": "incorrect"},
            environ_base={"REMOTE_ADDR": "198.51.100.24"},
        )

        self.assertEqual(response.status_code, 429)

    def test_repeated_failed_login_gets_429_and_lockout_retry_time(self):
        for _ in range(5):
            response = self.client.post(
                "/login",
                data={"username": "same-account", "password": "incorrect"},
                environ_base={"REMOTE_ADDR": "203.0.113.67"},
            )
            self.assertEqual(response.status_code, 200)

        response = self.client.post(
            "/login",
            data={"username": "same-account", "password": "incorrect"},
            environ_base={"REMOTE_ADDR": "203.0.113.67"},
        )

        self.assertEqual(response.status_code, 429)
        self.assertGreater(int(response.headers["Retry-After"]), 0)

    def test_login_cooldown_escalates_and_success_resets_failure_streak(self):
        now = cloud_app.datetime.now(cloud_app.timezone.utc)
        with cloud_app.database_connection() as connection:
            for seconds_ago in range(10, 0, -1):
                connection.execute(
                    """
                    INSERT INTO login_attempts
                        (username, ip_address, attempted_at, success)
                    VALUES (?, ?, ?, 0)
                    """,
                    (
                        "backoff-user",
                        "203.0.113.81",
                        (now - cloud_app.timedelta(seconds=seconds_ago)).isoformat(),
                    ),
                )

        with cloud_app.app.test_request_context(
            "/login", environ_base={"REMOTE_ADDR": "203.0.113.81"}
        ):
            remaining = cloud_app.login_lockout_remaining("backoff-user")
        self.assertGreater(remaining, cloud_app.LOGIN_LOCKOUT_MINUTES * 60)

        with cloud_app.database_connection() as connection:
            connection.execute(
                """
                INSERT INTO login_attempts (username, ip_address, attempted_at, success)
                VALUES (?, ?, ?, 1)
                """,
                ("backoff-user", "203.0.113.81", now.isoformat()),
            )
        with cloud_app.app.test_request_context(
            "/login", environ_base={"REMOTE_ADDR": "203.0.113.81"}
        ):
            self.assertEqual(cloud_app.login_lockout_remaining("backoff-user"), 0)

    def test_rate_limit_storage_does_not_contain_raw_account_or_ip(self):
        self.client.post(
            "/login",
            data={"username": "private-account-name", "password": "incorrect"},
            environ_base={"REMOTE_ADDR": "203.0.113.45"},
        )

        with cloud_app.database_connection() as connection:
            keys = [
                row["bucket_key"]
                for row in connection.execute(
                    "SELECT bucket_key FROM rate_limit_buckets"
                )
            ]

        self.assertTrue(keys)
        self.assertTrue(all("private-account-name" not in key for key in keys))
        self.assertTrue(all("203.0.113.45" not in key for key in keys))

    def test_api_rate_limit_uses_generic_json_429_response(self):
        original_rule = cloud_app.RATE_LIMIT_RULES["api"]
        cloud_app.RATE_LIMIT_RULES["api"] = (("ip", 1, 300), ("session", 2, 300))
        try:
            first_response = self.client.get(
                "/api/storage/plans",
                environ_base={"REMOTE_ADDR": "198.51.100.28"},
            )
            response = self.client.get(
                "/api/storage/plans",
                environ_base={"REMOTE_ADDR": "198.51.100.28"},
            )
        finally:
            cloud_app.RATE_LIMIT_RULES["api"] = original_rule

        self.assertEqual(first_response.status_code, 302)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json["error"], "too_many_requests")
        self.assertGreater(int(response.headers["Retry-After"]), 0)

    def test_forwarded_for_is_not_trusted_by_default(self):
        with cloud_app.app.test_request_context(
            "/login",
            environ_base={"REMOTE_ADDR": "192.0.2.45"},
            headers={"X-Forwarded-For": "203.0.113.1"},
        ):
            self.assertEqual(cloud_app.request_ip(), "192.0.2.45")

    def test_security_headers_are_present_on_auth_pages(self):
        response = self.client.get(
            "/login", environ_base={"REMOTE_ADDR": "192.0.2.71"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        policy = response.headers["Content-Security-Policy"]
        self.assertIn("frame-ancestors 'self'", policy)
        self.assertNotIn("unsafe-eval", policy)
        self.assertEqual(
            response.headers["Referrer-Policy"], "strict-origin-when-cross-origin"
        )

    def test_admin_security_center_shows_aggregate_limit_events(self):
        with cloud_app.app.test_request_context(
            "/", environ_base={"REMOTE_ADDR": "192.0.2.88"}
        ):
            cloud_app.consume_rate_limit("test-group", "ip", "test-client", 0, 300)

        now = cloud_app.datetime.now(cloud_app.timezone.utc).isoformat()
        token = "test-admin-device-token"
        with cloud_app.database_connection() as connection:
            admin = connection.execute(
                "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
                (cloud_app.ADMIN_USERNAME,),
            ).fetchone()
            connection.execute(
                """
                INSERT INTO device_sessions
                    (user_id, session_token_hash, device_label, created_at, last_seen)
                VALUES (?, ?, 'Test device', ?, ?)
                """,
                (
                    admin["id"],
                    cloud_app.device_token_hash(token),
                    now,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO policy_acceptances
                    (user_id, terms_accepted, privacy_accepted, cookies_accepted,
                     disclaimer_accepted, accepted_at)
                VALUES (?, 1, 1, 1, 1, ?)
                """,
                (admin["id"], now),
            )
        with self.client.session_transaction() as signed_session:
            signed_session["user_id"] = admin["id"]
            signed_session["device_token"] = token
            signed_session["last_seen"] = now

        response = self.client.get(
            "/admin/security", environ_base={"REMOTE_ADDR": "192.0.2.88"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Rate-limit events", response.data)
        self.assertIn(b"test-group", response.data)

    def test_emergency_dashboard_is_owner_only(self):
        now = cloud_app.datetime.now(cloud_app.timezone.utc).isoformat()
        with cloud_app.database_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (username, password_hash, created_at, status, is_admin)
                VALUES (?, ?, ?, 'active', 0)
                """,
                ("emergency-viewer", cloud_app.hash_password("test-only-password"), now),
            )
            user_id = cursor.lastrowid

        self.sign_in_user(user_id)
        self.assertEqual(self.client.get("/admin/emergency").status_code, 403)
        self.assertEqual(self.client.get("/admin/intelligence").status_code, 403)
        self.assertEqual(
            self.client.get("/api/admin/analytics/overview").status_code, 403
        )

    def test_emergency_full_lockdown_requires_phrase_and_records_event(self):
        admin_id = self.sign_in_owner()
        csrf_token = "test-admin-settings-csrf"
        base_data = {
            "csrf_token": csrf_token,
            "action": "preset",
            "preset": "FULL LOCKDOWN",
            "reason": "Incident test",
        }

        response = self.client.post("/admin/emergency", data=base_data)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(cloud_app.emergency_enabled("global_read_only"))

        response = self.client.post(
            "/admin/emergency",
            data={**base_data, "confirmation_phrase": "CONFIRM LOCKDOWN"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(cloud_app.emergency_enabled("global_read_only"))
        self.assertTrue(cloud_app.emergency_enabled("disable_uploads"))
        with cloud_app.database_connection() as connection:
            event = connection.execute(
                "SELECT * FROM emergency_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertIsNotNone(event)
        self.assertEqual(event["admin_id"], admin_id)
        self.assertEqual(event["action"], "preset")
        self.assertEqual(event["result"], "success")
        self.assertEqual(event["reason"], "Incident test")
        affected_user_ids = cloud_app.json.loads(event["affected_user_ids"])
        self.assertEqual(event["affected_users"], len(affected_user_ids))
        self.assertNotIn(admin_id, affected_user_ids)

    def test_global_read_only_does_not_block_downloads(self):
        with patch.object(
            cloud_app,
            "emergency_enabled",
            side_effect=lambda name: name == "global_read_only",
        ):
            with cloud_app.app.test_request_context("/"):
                cloud_app.require_storage_operation("download")
                with self.assertRaises(HTTPException) as error:
                    cloud_app.require_storage_operation("upload")

        self.assertEqual(error.exception.code, 503)

    def test_registration_freeze_blocks_new_social_accounts(self):
        with cloud_app.database_connection() as connection:
            connection.execute(
                """
                INSERT INTO policies (name, value, updated_at)
                VALUES ('freeze_registrations', '1', ?)
                ON CONFLICT(name) DO UPDATE SET value='1'
                """,
                (cloud_app.datetime.now(cloud_app.timezone.utc).isoformat(),),
            )

        user, created, linked, error = cloud_app.social_account_for_identity(
            "google",
            "registration-freeze-test-subject",
            "registration-freeze-test@example.net",
            "Registration Freeze Test",
        )

        self.assertIsNone(user)
        self.assertFalse(created)
        self.assertFalse(linked)
        self.assertEqual(error, "New account registration is disabled.")
        with cloud_app.database_connection() as connection:
            self.assertIsNone(
                connection.execute(
                    "SELECT id FROM users WHERE email = ?",
                    ("registration-freeze-test@example.net",),
                ).fetchone()
            )

    def test_emergency_api_disable_blocks_owner_api_requests(self):
        self.sign_in_owner()
        with cloud_app.database_connection() as connection:
            connection.execute(
                """
                INSERT INTO policies (name, value, updated_at)
                VALUES ('disable_api_access', '1', ?)
                ON CONFLICT(name) DO UPDATE SET value='1'
                """,
                (cloud_app.datetime.now(cloud_app.timezone.utc).isoformat(),),
            )

        response = self.client.get(
            "/api/admin/analytics/overview",
            environ_base={"REMOTE_ADDR": "192.0.2.145"},
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json["error"], "service_unavailable")

    def test_emergency_group_freeze_and_restore_preserves_user_status(self):
        admin_id = self.sign_in_owner()
        now = cloud_app.datetime.now(cloud_app.timezone.utc).isoformat()
        with cloud_app.database_connection() as connection:
            group_cursor = connection.execute(
                "INSERT INTO groups (name, description, created_at) VALUES (?, '', ?)",
                ("emergency-freeze-test-group", now),
            )
            user_ids = []
            for username in ("freeze-group-user-a", "freeze-group-user-b"):
                user_cursor = connection.execute(
                    """
                    INSERT INTO users (username, password_hash, created_at, status)
                    VALUES (?, ?, ?, 'active')
                    """,
                    (username, cloud_app.hash_password("test-only-password"), now),
                )
                user_ids.append(user_cursor.lastrowid)
                device_token = f"freeze-session-token-{user_cursor.lastrowid}"
                connection.execute(
                    """
                    INSERT INTO device_sessions
                        (user_id, session_token_hash, device_label, created_at, last_seen)
                    VALUES (?, ?, 'Freeze test device', ?, ?)
                    """,
                    (
                        user_cursor.lastrowid,
                        cloud_app.device_token_hash(device_token),
                        now,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO group_members (group_id, user_id, assigned_at, assigned_by)
                    VALUES (?, ?, ?, ?)
                    """,
                    (group_cursor.lastrowid, user_cursor.lastrowid, now, admin_id),
                )

        response = self.client.post(
            "/admin/emergency",
            data={
                "csrf_token": "test-admin-settings-csrf",
                "action": "freeze_accounts",
                "scope": "group",
                "group_id": group_cursor.lastrowid,
                "reason": "Security incident test",
            },
        )
        self.assertEqual(response.status_code, 302)
        with cloud_app.database_connection() as connection:
            frozen = connection.execute(
                "SELECT freeze_batch_id FROM emergency_account_freezes WHERE user_id = ?",
                (user_ids[0],),
            ).fetchone()
            self.assertIsNotNone(frozen)
            statuses = connection.execute(
                "SELECT id, status FROM users WHERE id IN (?, ?)",
                user_ids,
            ).fetchall()
            self.assertEqual({row["status"] for row in statuses}, {"suspended"})
            session_count = connection.execute(
                """
                SELECT COUNT(*) AS count FROM device_sessions
                WHERE user_id IN (?, ?) AND revoked_at IS NOT NULL
                """,
                user_ids,
            ).fetchone()["count"]
            self.assertEqual(session_count, 2)

        response = self.client.post(
            "/admin/emergency",
            data={
                "csrf_token": "test-admin-settings-csrf",
                "action": "restore_account_freeze",
                "freeze_batch_id": frozen["freeze_batch_id"],
            },
        )
        self.assertEqual(response.status_code, 302)
        with cloud_app.database_connection() as connection:
            statuses = connection.execute(
                "SELECT id, status FROM users WHERE id IN (?, ?)",
                user_ids,
            ).fetchall()
            self.assertEqual({row["status"] for row in statuses}, {"active"})
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) AS count FROM emergency_account_freezes"
                ).fetchone()["count"],
                0,
            )
            event = connection.execute(
                "SELECT previous_state, new_state FROM emergency_events "
                "WHERE action = 'restore_account_freeze' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        previous_state = cloud_app.json.loads(event["previous_state"])
        new_state = cloud_app.json.loads(event["new_state"])
        self.assertEqual(
            set(previous_state["account_statuses"].values()), {"suspended"}
        )
        self.assertEqual(set(new_state["account_statuses"].values()), {"active"})

    def test_request_rate_limit_burst_creates_one_deduplicated_alert(self):
        with patch.dict(
            cloud_app.RATE_LIMIT_RULES,
            {"api": (("ip", 1, 300),)},
        ):
            with cloud_app.app.test_request_context(
                "/api/test",
                environ_base={"REMOTE_ADDR": "192.0.2.156"},
            ):
                self.assertIsNone(cloud_app.request_rate_limit())
                for _ in range(6):
                    self.assertIsNotNone(cloud_app.request_rate_limit())

        with cloud_app.database_connection() as connection:
            alerts = connection.execute(
                """
                SELECT COUNT(*) AS count FROM security_alerts
                WHERE alert_type = 'request_rate_limit_burst'
                  AND ip_address = '192.0.2.156'
                """
            ).fetchone()["count"]
        self.assertEqual(alerts, 1)

    def test_upload_spike_creates_security_alert(self):
        now = cloud_app.datetime.now(cloud_app.timezone.utc).isoformat()
        with cloud_app.database_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (username, password_hash, created_at)
                VALUES (?, ?, ?)
                """,
                (
                    "upload-spike-test-user",
                    cloud_app.hash_password("test-only-password"),
                    now,
                ),
            )
            user_id = cursor.lastrowid

        with cloud_app.app.test_request_context(
            "/files",
            environ_base={"REMOTE_ADDR": "192.0.2.157"},
        ):
            for index in range(21):
                cloud_app.audit_event(
                    "upload",
                    "file",
                    f"test-{index}.txt",
                    actor_id=user_id,
                )

        with cloud_app.database_connection() as connection:
            alert = connection.execute(
                """
                SELECT * FROM security_alerts
                WHERE alert_type = 'unusual_upload_spike'
                  AND username = 'upload-spike-test-user'
                """
            ).fetchone()
        self.assertIsNotNone(alert)
        self.assertIn("Observed: 21", alert["details"])

    def test_successful_download_is_audited_for_monitoring(self):
        now = cloud_app.datetime.now(cloud_app.timezone.utc).isoformat()
        with cloud_app.database_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (username, password_hash, created_at)
                VALUES (?, ?, ?)
                """,
                (
                    "download-audit-test-user",
                    cloud_app.hash_password("test-only-password"),
                    now,
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
        user_folder = cloud_app.SHARED_FOLDER / "users" / str(user_id)
        user_folder.mkdir(parents=True, exist_ok=True)
        (user_folder / "monitoring-test.txt").write_text("test file", encoding="utf-8")
        self.sign_in_user(user_id)

        response = self.client.get(
            "/download/monitoring-test.txt",
            environ_base={"REMOTE_ADDR": "192.0.2.159"},
        )

        self.assertEqual(response.status_code, 200)
        with cloud_app.database_connection() as connection:
            event = connection.execute(
                """
                SELECT action, actor_id, details FROM audit_events
                WHERE action = 'download' AND actor_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (user_id,),
            ).fetchone()
        self.assertIsNotNone(event)
        self.assertIn("monitoring-test.txt", event["details"])

    def test_account_creation_spike_creates_security_alert(self):
        with cloud_app.app.test_request_context(
            "/register",
            environ_base={"REMOTE_ADDR": "192.0.2.158"},
        ):
            for index in range(10):
                cloud_app.audit_event(
                    "account_created",
                    "user",
                    index + 100,
                    "provider=test",
                    actor_id=None,
                )

        with cloud_app.database_connection() as connection:
            alert = connection.execute(
                """
                SELECT * FROM security_alerts
                WHERE alert_type = 'unusual_account_creation_spike'
                  AND ip_address = '192.0.2.158'
                """
            ).fetchone()
        self.assertIsNotNone(alert)
        self.assertIn("10 accounts", alert["details"])

    def test_incident_restore_preserves_controls_changed_after_activation(self):
        self.sign_in_owner()
        incident_data = {
            "csrf_token": "test-admin-settings-csrf",
            "action": "create_incident",
            "title": "Selective restore test",
            "severity": "HIGH",
            "description": "Verify later control changes are preserved.",
            "preset": "SECURITY MODE",
            "services": ["storage", "api"],
        }
        response = self.client.post("/admin/emergency", data=incident_data)
        self.assertEqual(response.status_code, 302)
        with cloud_app.database_connection() as connection:
            incident = connection.execute(
                "SELECT * FROM emergency_incidents ORDER BY id DESC LIMIT 1"
            ).fetchone()
            connection.execute(
                """
                UPDATE policies SET value = '0'
                WHERE name = 'disable_uploads'
                """
            )

        filtered_log = self.client.get(
            f"/admin/emergency?severity=HIGH&event_action=create_incident&incident={incident['id']}"
        )
        self.assertEqual(filtered_log.status_code, 200)
        self.assertIn(b"create_incident", filtered_log.data)

        response = self.client.post(
            "/admin/emergency",
            data={
                "csrf_token": "test-admin-settings-csrf",
                "action": "restore_incident",
                "incident_id": incident["id"],
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(cloud_app.emergency_enabled("disable_uploads"))
        self.assertFalse(cloud_app.emergency_enabled("disable_downloads"))
        with cloud_app.database_connection() as connection:
            restored = connection.execute(
                "SELECT recovery_state FROM emergency_incidents WHERE id = ?",
                (incident["id"],),
            ).fetchone()
        self.assertIsNotNone(restored["recovery_state"])

    def test_admin_settings_manage_google_and_login_protection(self):
        self.sign_in_owner()
        response = self.client.get(
            "/admin/settings", environ_base={"REMOTE_ADDR": "192.0.2.87"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Google OAuth configuration:", response.data)
        self.assertIn(b"Allow Google sign-in", response.data)
        self.assertIn(b"GitHub OAuth configuration:", response.data)
        self.assertIn(b"Allow GitHub sign-in", response.data)
        self.assertIn(b'name="google_oauth_client_id"', response.data)
        self.assertIn(b'name="google_oauth_client_secret"', response.data)
        self.assertIn(b'name="github_oauth_client_id"', response.data)
        self.assertIn(b'name="github_oauth_client_secret"', response.data)
        self.assertIn(b"Login protection", response.data)
        self.assertIn(b'name="login_max_attempts"', response.data)
        self.assertIn(b"Security reports", response.data)
        self.assertNotIn(b"test-google-client-secret", response.data)

        with cloud_app.database_connection() as connection:
            previous_settings = {
                row["name"]: row["value"]
                for row in connection.execute(
                    """
                    SELECT name, value FROM policies
                    WHERE name IN (
                        'allow_google_signin', 'allow_github_signin',
                        'login_max_attempts',
                        'login_window_minutes', 'login_lockout_minutes'
                    )
                    """
                )
            }
        try:
            response = self.client.post(
                "/admin/settings",
                data={
                    "csrf_token": "test-admin-settings-csrf",
                    "allow_registration": "on",
                    "trash_retention_days": "30",
                    "login_max_attempts": "2",
                    "login_window_minutes": "7",
                    "login_lockout_minutes": "3",
                },
                environ_base={"REMOTE_ADDR": "192.0.2.87"},
            )
            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Website and login security settings updated.", response.data)
            self.assertFalse(
                cloud_app.oauth_credentials_admin_managed("google")
            )
            self.assertFalse(
                cloud_app.oauth_credentials_admin_managed("github")
            )
            self.assertEqual(
                cloud_app.login_security_settings(),
                {
                    "login_max_attempts": 2,
                    "login_window_minutes": 7,
                    "login_lockout_minutes": 3,
                },
            )
            self.assertEqual(
                cloud_app.app.test_client().get(
                    "/auth/google",
                    environ_base={"REMOTE_ADDR": "192.0.2.87"},
                ).status_code,
                503,
            )
            self.assertEqual(
                cloud_app.app.test_client().get(
                    "/auth/github",
                    environ_base={"REMOTE_ADDR": "192.0.2.87"},
                ).status_code,
                503,
            )
            disabled_login = cloud_app.app.test_client().get(
                "/login", environ_base={"REMOTE_ADDR": "192.0.2.87"}
            )
            self.assertIn(b"disabled by the site administrator", disabled_login.data)
            self.assertNotIn(b'href="/auth/google"', disabled_login.data)
            anonymous = cloud_app.app.test_client()
            first = anonymous.post(
                "/login",
                data={"username": "settings-lockout-test", "password": "bad"},
                environ_base={"REMOTE_ADDR": "192.0.2.86"},
            )
            second = anonymous.post(
                "/login",
                data={"username": "settings-lockout-test", "password": "bad"},
                environ_base={"REMOTE_ADDR": "192.0.2.86"},
            )
            blocked = anonymous.post(
                "/login",
                data={"username": "settings-lockout-test", "password": "bad"},
                environ_base={"REMOTE_ADDR": "192.0.2.86"},
            )
            self.assertEqual((first.status_code, second.status_code), (200, 200))
            self.assertEqual(blocked.status_code, 429)
        finally:
            with cloud_app.database_connection() as connection:
                for name, value in previous_settings.items():
                    connection.execute(
                        "UPDATE policies SET value = ? WHERE name = ?",
                        (value, name),
                    )

    def test_owner_can_store_encrypted_oauth_credentials_and_clear_them(self):
        self.sign_in_owner()
        policy_names = (
            "allow_registration",
            "allow_public_sharing",
            "allow_google_signin",
            "allow_github_signin",
            "trash_retention_days",
            "login_max_attempts",
            "login_window_minutes",
            "login_lockout_minutes",
            "google_oauth_credentials",
        )
        placeholders = ",".join("?" for _ in policy_names)
        with cloud_app.database_connection() as connection:
            previous = {
                row["name"]: dict(row)
                for row in connection.execute(
                    f"SELECT * FROM policies WHERE name IN ({placeholders})",
                    policy_names,
                )
            }

        client_id = "admin-managed-google-client"
        client_secret = "private-google-client-secret"
        common_settings = {
            "csrf_token": "test-admin-settings-csrf",
            "allow_registration": "on",
            "allow_google_signin": "on",
            "allow_github_signin": "on",
            "allow_public_sharing": "on",
            "trash_retention_days": "30",
            "login_max_attempts": "5",
            "login_window_minutes": "15",
            "login_lockout_minutes": "15",
        }
        try:
            response = self.client.post(
                "/admin/settings",
                data={
                    **common_settings,
                    "google_oauth_client_id": client_id,
                    "google_oauth_client_secret": client_secret,
                },
                environ_base={"REMOTE_ADDR": "192.0.2.74"},
            )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertIn(b"Credentials are saved encrypted in admin settings", response.data)
            self.assertIn(client_id.encode(), response.data)
            self.assertNotIn(client_secret.encode(), response.data)
            with cloud_app.database_connection() as connection:
                stored = connection.execute(
                    "SELECT value FROM policies WHERE name = ?",
                    ("google_oauth_credentials",),
                ).fetchone()["value"]
            self.assertNotIn(client_secret, stored)
            self.assertEqual(
                cloud_app.oauth_provider_credentials("google"),
                (client_id, client_secret),
            )
            configured_client = cloud_app.oauth_provider_client("google")
            self.assertEqual(configured_client.client_id, client_id)
            self.assertEqual(configured_client.client_secret, client_secret)
            with (
                patch.object(
                    cloud_app,
                    "oauth_provider_client",
                    return_value=configured_client,
                ),
                patch.object(
                    configured_client,
                    "authorize_redirect",
                    return_value=cloud_app.redirect("/oauth-provider-mock"),
                ) as authorize_redirect,
            ):
                response = cloud_app.app.test_client().get(
                    "/auth/google",
                    environ_base={"REMOTE_ADDR": "192.0.2.73"},
                )
            self.assertEqual(response.status_code, 302)
            authorize_redirect.assert_called_once_with(
                "http://127.0.0.1:8000/auth/google/callback"
            )

            response = self.client.post(
                "/admin/settings",
                data={
                    **common_settings,
                    "clear_google_oauth_credentials": "on",
                    "google_oauth_client_id": client_id,
                },
                environ_base={"REMOTE_ADDR": "192.0.2.74"},
            )
            self.assertEqual(response.status_code, 200)
            self.assertFalse(
                cloud_app.oauth_credentials_admin_managed("google")
            )
            self.assertEqual(
                cloud_app.oauth_provider_credentials("google"),
                (
                    cloud_app.GOOGLE_OAUTH_CLIENT_ID,
                    cloud_app.GOOGLE_OAUTH_CLIENT_SECRET,
                ),
            )
        finally:
            with cloud_app.database_connection() as connection:
                connection.execute(
                    f"DELETE FROM policies WHERE name IN ({placeholders})",
                    policy_names,
                )
                for row in previous.values():
                    connection.execute(
                        """
                        INSERT INTO policies (name, value, updated_at, updated_by)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            row["name"],
                            row["value"],
                            row["updated_at"],
                            row["updated_by"],
                        ),
                    )

    def test_delegated_admin_cannot_manage_website_security_settings(self):
        now = cloud_app.datetime.now(cloud_app.timezone.utc).isoformat()
        with cloud_app.database_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (username, password_hash, created_at, status, is_admin)
                VALUES (?, ?, ?, 'active', 0)
                """,
                (
                    "settings-delegate",
                    cloud_app.hash_password("test-only-password"),
                    now,
                ),
            )
            user_id = cursor.lastrowid
            role_id = connection.execute(
                "SELECT id FROM roles WHERE name = 'auditor'"
            ).fetchone()["id"]
            connection.execute(
                "INSERT INTO user_roles (user_id, role_id, assigned_at) VALUES (?, ?, ?)",
                (user_id, role_id, now),
            )
            token = "test-settings-delegate-device-token"
            connection.execute(
                """
                INSERT INTO device_sessions
                    (user_id, session_token_hash, device_label, created_at, last_seen)
                VALUES (?, ?, 'Delegate test device', ?, ?)
                """,
                (user_id, cloud_app.device_token_hash(token), now, now),
            )
            connection.execute(
                """
                INSERT INTO policy_acceptances
                    (user_id, terms_accepted, privacy_accepted, cookies_accepted,
                     disclaimer_accepted, accepted_at)
                VALUES (?, 1, 1, 1, 1, ?)
                """,
                (user_id, now),
            )
        with self.client.session_transaction() as signed_session:
            signed_session["user_id"] = user_id
            signed_session["device_token"] = token
            signed_session["last_seen"] = now

        response = self.client.get(
            "/admin/settings", environ_base={"REMOTE_ADDR": "192.0.2.85"}
        )

        self.assertEqual(response.status_code, 403)

    def test_admin_dashboard_has_quick_actions_customization_and_theme_script(self):
        now = cloud_app.datetime.now(cloud_app.timezone.utc).isoformat()
        token = "test-admin-dashboard-device-token"
        with cloud_app.database_connection() as connection:
            admin = connection.execute(
                "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
                (cloud_app.ADMIN_USERNAME,),
            ).fetchone()
            connection.execute(
                """
                INSERT INTO device_sessions
                    (user_id, session_token_hash, device_label, created_at, last_seen)
                VALUES (?, ?, 'Dashboard test device', ?, ?)
                """,
                (admin["id"], cloud_app.device_token_hash(token), now, now),
            )
            connection.execute(
                """
                INSERT INTO policy_acceptances
                    (user_id, terms_accepted, privacy_accepted, cookies_accepted,
                     disclaimer_accepted, accepted_at)
                VALUES (?, 1, 1, 1, 1, ?)
                """,
                (admin["id"], now),
            )
        with self.client.session_transaction() as signed_session:
            signed_session["user_id"] = admin["id"]
            signed_session["device_token"] = token
            signed_session["last_seen"] = now

        response = self.client.get(
            "/admin", environ_base={"REMOTE_ADDR": "192.0.2.89"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Welcome back", response.data)
        self.assertIn(b"Security center", response.data)
        self.assertIn(b"Website &amp; security settings", response.data)
        self.assertIn(b"Manage site settings", response.data)
        self.assertIn(b"User administration", response.data)
        self.assertIn(b'id="dashboard-customize"', response.data)
        self.assertIn(b'data-dashboard-widget="health"', response.data)
        self.assertIn(b"admin-dashboard.js", response.data)

        script_response = self.client.get("/static/admin-dashboard.js")
        try:
            self.assertEqual(script_response.status_code, 200)
            self.assertIn(b"localStorage.setItem", script_response.data)
            self.assertIn(b"restored to its default layout", script_response.data)
        finally:
            script_response.close()

    def test_storage_dashboard_has_theme_control_and_real_quick_access(self):
        now = cloud_app.datetime.now(cloud_app.timezone.utc).isoformat()
        token = "test-storage-dashboard-device-token"
        with cloud_app.database_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users
                    (username, password_hash, created_at, full_name, email, mobile, date_of_birth)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "storage-dashboard-user",
                    cloud_app.hash_password("test-only-password"),
                    now,
                    "Storage Dashboard User",
                    "storage-dashboard@example.com",
                    "+15550001000",
                    "1990-01-01",
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
            connection.execute(
                """
                INSERT INTO device_sessions
                    (user_id, session_token_hash, device_label, created_at, last_seen)
                VALUES (?, ?, 'Dashboard test device', ?, ?)
                """,
                (user_id, cloud_app.device_token_hash(token), now, now),
            )
            connection.execute(
                """
                INSERT INTO policy_acceptances
                    (user_id, terms_accepted, privacy_accepted, cookies_accepted,
                     disclaimer_accepted, accepted_at)
                VALUES (?, 1, 1, 1, 1, ?)
                """,
                (user_id, now),
            )
        (cloud_app.SHARED_FOLDER / "users" / str(user_id)).mkdir(
            parents=True, exist_ok=True
        )
        with self.client.session_transaction() as signed_session:
            signed_session["user_id"] = user_id
            signed_session["device_token"] = token
            signed_session["last_seen"] = now

        response = self.client.get(
            "/files/", environ_base={"REMOTE_ADDR": "192.0.2.92"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'data-theme="dark"', response.data)
        self.assertIn(b'id="theme-toggle"', response.data)
        self.assertIn(b'aria-label="Quick access"', response.data)
        self.assertIn(b"Storage plan", response.data)
        self.assertIn(b"My profile", response.data)
        self.assertIn(b"Recycle bin", response.data)
        self.assertIn(b"OBJECTS / 0", response.data)
        self.assertIn(b"Search in this folder", response.data)
        self.assertIn(b'aria-label="Show files as cards"', response.data)
        self.assertIn(b'aria-label="Show files as a list"', response.data)
        self.assertIn(b"Mobile quick navigation", response.data)
        self.assertIn(b"file-search-status", response.data)
        self.assertIn(b"role=\"status\"", response.data)
        self.assertNotIn(b"Ask NOVA", response.data)

        css_response = self.client.get("/static/cloud-dashboard.css")
        try:
            self.assertEqual(css_response.status_code, 200)
            self.assertIn(b':root[data-theme="light"]', css_response.data)
            self.assertIn(b'.file-list[data-view="list"]', css_response.data)
            self.assertIn(b'safe-area-inset-bottom', css_response.data)
            self.assertIn(b':focus-visible', css_response.data)
            self.assertIn(b"prefers-reduced-motion", css_response.data)
        finally:
            css_response.close()

        script_response = self.client.get("/static/cloud-dashboard.js")
        try:
            self.assertEqual(script_response.status_code, 200)
            self.assertIn(b"localStorage.setItem", script_response.data)
            self.assertIn(b"could not save the preference", script_response.data)
        finally:
            script_response.close()

    def test_user_account_pages_share_theme_navigation_and_accessible_controls(self):
        now = cloud_app.datetime.now(cloud_app.timezone.utc).isoformat()
        with cloud_app.database_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users
                    (username, password_hash, created_at, full_name, email)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "shared-theme-user",
                    cloud_app.hash_password("test-only-password"),
                    now,
                    "Shared Theme User",
                    "shared-theme@example.net",
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
        self.sign_in_user(user_id)

        for path, active_label in (
            ("/storage/plan", b"Storage plan"),
            ("/profile", b"My Profile"),
            ("/recycle-bin", b"Recycle bin"),
        ):
            with self.subTest(path=path):
                response = self.client.get(
                    path, environ_base={"REMOTE_ADDR": "192.0.2.111"}
                )
                self.assertEqual(response.status_code, 200)
                self.assertIn(b"cloud-account.css", response.data)
                self.assertIn(b"cloud-account.js", response.data)
                self.assertIn(b"Account navigation", response.data)
                self.assertIn(b"Switch to light theme", response.data)
                self.assertIn(b'aria-current="page"', response.data)
                self.assertIn(active_label, response.data)

        plan_page = self.client.get(
            "/storage/plan", environ_base={"REMOTE_ADDR": "192.0.2.111"}
        )
        self.assertIn(b'role="progressbar"', plan_page.data)
        self.assertIn(b"UPI transaction reference for", plan_page.data)
        trash_page = self.client.get(
            "/recycle-bin", environ_base={"REMOTE_ADDR": "192.0.2.111"}
        )
        self.assertIn(b"Your deleted items", trash_page.data)

        css_response = self.client.get("/static/cloud-account.css")
        try:
            self.assertEqual(css_response.status_code, 200)
            self.assertIn(b"prefers-reduced-motion", css_response.data)
            self.assertIn(b":focus-visible", css_response.data)
            self.assertIn(b"@keyframes account-panel-enter", css_response.data)
        finally:
            css_response.close()
        script_response = self.client.get("/static/cloud-account.js")
        try:
            self.assertEqual(script_response.status_code, 200)
            self.assertIn(b"localStorage.setItem", script_response.data)
            self.assertIn(b"aria-pressed", script_response.data)
        finally:
            script_response.close()

    def test_login_page_offers_google_login_when_configured(self):
        response = self.client.get(
            "/login", environ_base={"REMOTE_ADDR": "192.0.2.90"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'aria-label="Continue with Google or create an account"', response.data)
        self.assertIn(b'aria-label="Continue with GitHub or create an account"', response.data)
        self.assertEqual(response.data.count(b'href="/auth/google"'), 1)
        self.assertEqual(response.data.count(b'href="/auth/github"'), 1)
        self.assertEqual(response.data.count(b'class="provider-logo'), 2)
        self.assertNotIn(b"Sign up with Google", response.data)
        self.assertNotIn(b"Sign up with GitHub", response.data)

    def test_github_login_start_uses_configured_callback_url(self):
        with patch.object(
            cloud_app.github,
            "authorize_redirect",
            return_value=cloud_app.redirect("/github-provider-mock"),
        ) as authorize_redirect:
            response = self.client.get(
                "/auth/github", environ_base={"REMOTE_ADDR": "192.0.2.83"}
            )

        self.assertEqual(response.status_code, 302)
        authorize_redirect.assert_called_once_with(
            "http://127.0.0.1:8000/auth/github/callback"
        )

    def test_github_callback_creates_account_using_verified_primary_email(self):
        profile = {
            "id": 123456,
            "login": "octo-cloud",
            "name": None,
            "avatar_url": "https://avatars.githubusercontent.com/u/123456?v=4",
            "location": "Octo City",
        }
        emails = [
            {"email": "unverified@example.com", "primary": True, "verified": False},
            {
                "email": "octo@example.com",
                "primary": True,
                "verified": True,
            },
        ]
        with (
            patch.object(cloud_app.github, "authorize_access_token"),
            patch.object(
                cloud_app.github,
                "get",
                side_effect=[
                    SimpleNamespace(status_code=200, json=lambda: profile),
                    SimpleNamespace(status_code=200, json=lambda: emails),
                ],
            ),
        ):
            response = self.client.get(
                "/auth/github/callback",
                environ_base={"REMOTE_ADDR": "192.0.2.82"},
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/profile")
        with cloud_app.database_connection() as connection:
            user = connection.execute(
                "SELECT * FROM users WHERE github_sub = ?", ("123456",)
            ).fetchone()
            permission = connection.execute(
                "SELECT * FROM storage_permissions WHERE user_id = ?",
                (user["id"],),
            ).fetchone()
        self.assertIsNotNone(user)
        self.assertFalse(user["is_admin"])
        self.assertEqual(user["username"], "octo")
        self.assertEqual(user["email"], "octo@example.com")
        self.assertEqual(user["full_name"], "octo-cloud")
        self.assertEqual(user["github_email"], "octo@example.com")
        self.assertEqual(user["github_username"], "octo-cloud")
        self.assertEqual(
            user["github_picture"],
            "https://avatars.githubusercontent.com/u/123456?v=4",
        )
        self.assertEqual(user["location"], "Octo City")
        self.assertEqual(user["password_login_enabled"], 0)
        self.assertEqual(permission["allow_upload"], 1)
        self.assertEqual(permission["allow_download"], 1)
        with self.client.session_transaction() as signed_session:
            self.assertEqual(signed_session["user_id"], user["id"])

    def test_admin_can_filter_and_export_social_account_details(self):
        self.assertIsNone(
            cloud_app.safe_oauth_picture_url(
                "https://attacker.example/avatar.png", "github"
            )
        )
        self.assertEqual(
            cloud_app.spreadsheet_safe_cell(" =HYPERLINK('x')"),
            "' =HYPERLINK('x')",
        )
        user, created, linked, error = cloud_app.social_account_for_identity(
            "github",
            "admin-report-github-subject",
            "rdx-report-oauth@example.net",
            "RDX Report User",
            provider_username="rdx-report-github",
            picture_url="https://avatars.githubusercontent.com/u/42",
        )
        self.assertTrue(created)
        self.assertFalse(linked)
        self.assertIsNone(error)
        user, created, linked, error = cloud_app.social_account_for_identity(
            "google",
            "admin-report-google-subject",
            "rdx-report-oauth@example.net",
            "RDX Report Google",
            provider_username="rdx-report-google",
            picture_url="https://lh3.googleusercontent.com/a/report",
        )
        self.assertFalse(created)
        self.assertTrue(linked)
        self.assertIsNone(error)
        self.assertEqual(user["google_email"], "rdx-report-oauth@example.net")
        self.assertEqual(
            user["github_picture"],
            "https://avatars.githubusercontent.com/u/42",
        )
        self.assertEqual(
            user["google_picture"],
            "https://lh3.googleusercontent.com/a/report",
        )

        self.sign_in_owner()
        response = self.client.get(
            "/admin?account_type=github",
            environ_base={"REMOTE_ADDR": "192.0.2.82"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"rdx-report-github", response.data)
        self.assertIn(b"rdx-report-oauth@example.net", response.data)
        self.assertIn(b"lh3.googleusercontent.com/a/report", response.data)
        self.assertIn(b"Sign-in: Google + GitHub", response.data)
        self.assertIn(b'action="/admin"', response.data)

        report = self.client.get(
            "/admin/users/report.csv?account_type=github",
            environ_base={"REMOTE_ADDR": "192.0.2.82"},
        )
        self.assertEqual(report.status_code, 200)
        self.assertIn("text/csv", report.headers["Content-Type"])
        self.assertIn("attachment;", report.headers["Content-Disposition"])
        self.assertIn(b"rdx-report-github", report.data)
        self.assertIn(b"GitHub", report.data)
        self.assertIn(b"Last login", report.data)
        self.assertIn(b"Last seen", report.data)
        self.assertNotIn(b"password_hash", report.data)
        self.assertNotIn(b"admin-report-github-subject", report.data)

        password_filter = self.client.get(
            "/admin?account_type=password",
            environ_base={"REMOTE_ADDR": "192.0.2.82"},
        )
        self.assertEqual(password_filter.status_code, 200)
        self.assertNotIn(b"rdx-report-github", password_filter.data)

    def test_oauth_user_can_update_recovery_profile_and_view_account_security(self):
        user, created, linked, error = cloud_app.social_account_for_identity(
            "google",
            "profile-recovery-google-subject",
            "profile.recovery.unique@example.net",
            "Profile Recovery",
            provider_username="profile-recovery",
            picture_url="https://lh3.googleusercontent.com/a/profile-recovery",
        )
        self.assertTrue(created)
        self.assertFalse(linked)
        self.assertIsNone(error)
        user_id = user["id"]
        self.sign_in_user(user_id)
        try:
            page = self.client.get(
                "/profile", environ_base={"REMOTE_ADDR": "192.0.2.66"}
            )
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"Recovery and profile details", page.data)
            self.assertIn(b"Phone number", page.data)
            self.assertIn(b"Gender (optional)", page.data)
            self.assertIn(b"Location (optional)", page.data)
            self.assertIn(b"Google linked", page.data)
            self.assertIn(b"Profile picture", page.data)
            self.assertIn(b"Two-factor authentication", page.data)
            self.assertIn(b"We do not ask for or store security-question answers", page.data)

            saved = self.client.post(
                "/profile",
                data={
                    "csrf_token": "test-profile-csrf",
                    "full_name": "Updated Recovery Name",
                    "mobile": "+1 555 010 2000",
                    "date_of_birth": "1992-04-15",
                    "gender": "Prefer not to say",
                    "location": "North District",
                },
                environ_base={"REMOTE_ADDR": "192.0.2.66"},
            )
            self.assertEqual(saved.status_code, 302)
            with cloud_app.database_connection() as connection:
                updated = connection.execute(
                    """
                    SELECT full_name, email, mobile, date_of_birth, gender,
                        location, google_email, password_login_enabled
                    FROM users WHERE id = ?
                    """,
                    (user_id,),
                ).fetchone()
            self.assertEqual(updated["full_name"], "Updated Recovery Name")
            self.assertEqual(updated["email"], "profile.recovery.unique@example.net")
            self.assertEqual(updated["mobile"], "+1 555 010 2000")
            self.assertEqual(updated["date_of_birth"], "1992-04-15")
            self.assertEqual(updated["gender"], "Prefer not to say")
            self.assertEqual(updated["location"], "North District")
            self.assertEqual(
                updated["google_email"], "profile.recovery.unique@example.net"
            )
            self.assertEqual(updated["password_login_enabled"], 0)

            invalid = self.client.post(
                "/profile",
                data={
                    "csrf_token": "test-profile-csrf",
                    "full_name": "Invalid Date",
                    "date_of_birth": "2999-01-01",
                },
                environ_base={"REMOTE_ADDR": "192.0.2.66"},
            )
            self.assertEqual(invalid.status_code, 302)
            with cloud_app.database_connection() as connection:
                unchanged = connection.execute(
                    "SELECT full_name, date_of_birth FROM users WHERE id = ?",
                    (user_id,),
                ).fetchone()
            self.assertEqual(unchanged["full_name"], "Updated Recovery Name")
            self.assertEqual(unchanged["date_of_birth"], "1992-04-15")
        finally:
            with cloud_app.database_connection() as connection:
                connection.execute("DELETE FROM users WHERE id = ?", (user_id,))

    def test_github_callback_rejects_account_without_verified_primary_email(self):
        with (
            patch.object(cloud_app.github, "authorize_access_token"),
            patch.object(
                cloud_app.github,
                "get",
                side_effect=[
                    SimpleNamespace(
                        status_code=200,
                        json=lambda: {
                            "id": 98765,
                            "login": "no-verified-email",
                            "name": "No Email",
                        },
                    ),
                    SimpleNamespace(
                        status_code=200,
                        json=lambda: [
                            {
                                "email": "unverified@example.com",
                                "primary": True,
                                "verified": False,
                            }
                        ],
                    ),
                ],
            ),
        ):
            response = self.client.get(
                "/auth/github/callback",
                environ_base={"REMOTE_ADDR": "192.0.2.81"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn(b"verified primary email", response.data)
        with cloud_app.database_connection() as connection:
            user = connection.execute(
                "SELECT id FROM users WHERE github_sub = ?", ("98765",)
            ).fetchone()
        self.assertIsNone(user)

    def test_github_callback_links_verified_email_to_existing_account(self):
        now = cloud_app.datetime.now(cloud_app.timezone.utc).isoformat()
        with cloud_app.database_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users
                    (username, password_hash, created_at, status, email, full_name)
                VALUES (?, ?, ?, 'active', ?, ?)
                """,
                (
                    "github-link-user",
                    cloud_app.hash_password("test-only-password"),
                    now,
                    "link@example.com",
                    "Existing Account",
                ),
            )
            user_id = cursor.lastrowid
        with (
            patch.object(cloud_app.github, "authorize_access_token"),
            patch.object(
                cloud_app.github,
                "get",
                side_effect=[
                    SimpleNamespace(
                        status_code=200,
                        json=lambda: {
                            "id": 24680,
                            "login": "link-user",
                            "name": "GitHub Name",
                        },
                    ),
                    SimpleNamespace(
                        status_code=200,
                        json=lambda: [
                            {
                                "email": "link@example.com",
                                "primary": True,
                                "verified": True,
                            }
                        ],
                    ),
                ],
            ),
        ):
            response = self.client.get(
                "/auth/github/callback",
                environ_base={"REMOTE_ADDR": "192.0.2.80"},
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/files/")
        with cloud_app.database_connection() as connection:
            user = connection.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM users WHERE lower(email) = ?",
                    ("link@example.com",),
                ).fetchone()[0],
                1,
            )
        self.assertEqual(user["github_sub"], "24680")
        with self.client.session_transaction() as signed_session:
            self.assertEqual(signed_session["user_id"], user_id)

    def test_github_callback_handles_provider_network_failure(self):
        with patch.object(
            cloud_app.github,
            "authorize_access_token",
            side_effect=OSError("network details are not shown to users"),
        ):
            response = self.client.get(
                "/auth/github/callback",
                environ_base={"REMOTE_ADDR": "192.0.2.79"},
            )

        self.assertEqual(response.status_code, 502)
        self.assertIn(b"temporarily unavailable", response.data)

    def test_login_page_keeps_provider_buttons_visible_when_oauth_is_unconfigured(self):
        with (
            patch.object(
                cloud_app, "oauth_provider_credentials", return_value=("", "")
            ),
        ):
            response = self.client.get(
                "/login", environ_base={"REMOTE_ADDR": "192.0.2.93"}
            )
            google_response = self.client.get(
                "/auth/google", environ_base={"REMOTE_ADDR": "192.0.2.94"}
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'aria-label="Continue with Google or create an account"', response.data)
        self.assertIn(b'aria-label="Continue with GitHub or create an account"', response.data)
        self.assertIn(b"not configured on this server yet", response.data)
        self.assertEqual(response.data.count(b'href="/auth/google"'), 1)
        self.assertEqual(response.data.count(b'href="/auth/github"'), 1)
        self.assertEqual(google_response.status_code, 503)
        self.assertIn(b"Google sign-in is not configured on this server.", google_response.data)

    def test_google_callback_creates_non_admin_account_with_storage_access(self):
        claims = {
            "sub": "google-sub-new-user",
            "email": "new.google.user@example.com",
            "email_verified": True,
            "name": "New Google User",
            "preferred_username": "google-user-name",
            "picture": "https://lh3.googleusercontent.com/a/google-user",
        }
        with patch.object(
            cloud_app.google,
            "authorize_access_token",
            return_value={"userinfo": claims},
        ):
            response = self.client.get(
                "/auth/google/callback",
                environ_base={"REMOTE_ADDR": "192.0.2.91"},
            )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/profile")
        with cloud_app.database_connection() as connection:
            user = connection.execute(
                "SELECT * FROM users WHERE google_sub = ?",
                (claims["sub"],),
            ).fetchone()
            permission = connection.execute(
                "SELECT * FROM storage_permissions WHERE user_id = ?",
                (user["id"],),
            ).fetchone()
        self.assertIsNotNone(user)
        self.assertFalse(user["is_admin"])
        self.assertEqual(user["username"], "newgoogleuser")
        self.assertEqual(user["email"], claims["email"])
        self.assertEqual(user["full_name"], claims["name"])
        self.assertEqual(user["google_email"], claims["email"])
        self.assertEqual(user["google_profile_name"], claims["name"])
        self.assertEqual(user["google_username"], claims["preferred_username"])
        self.assertEqual(user["google_picture"], claims["picture"])
        self.assertEqual(permission["allow_upload"], 1)
        self.assertEqual(permission["allow_download"], 1)
        with self.client.session_transaction() as signed_session:
            self.assertEqual(signed_session["user_id"], user["id"])
            self.assertTrue(signed_session["show_profile_onboarding"])

        consent_page = self.client.get(
            "/profile", environ_base={"REMOTE_ADDR": "192.0.2.91"}
        )
        self.assertEqual(consent_page.status_code, 302)
        self.assertEqual(consent_page.headers["Location"], "/consent")
        with self.client.session_transaction() as signed_session:
            csrf = signed_session["csrf_token"]
        accepted = self.client.post(
            "/consent/accept",
            data={"csrf_token": csrf, "accept_all": "on"},
            environ_base={"REMOTE_ADDR": "192.0.2.91"},
        )
        self.assertEqual(accepted.status_code, 302)
        self.assertEqual(accepted.headers["Location"], "/profile")
        profile_page = self.client.get(
            "/profile", environ_base={"REMOTE_ADDR": "192.0.2.91"}
        )
        self.assertEqual(profile_page.status_code, 200)
        self.assertIn(b"Recovery and profile details", profile_page.data)

    def test_google_callback_links_only_one_verified_email_match(self):
        now = cloud_app.datetime.now(cloud_app.timezone.utc).isoformat()
        with cloud_app.database_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (username, password_hash, created_at, email)
                VALUES (?, ?, ?, ?)
                """,
                (
                    "existing-google-user",
                    cloud_app.hash_password("existing-user-password"),
                    now,
                    "existing@example.com",
                ),
            )
            user_id = cursor.lastrowid
        claims = {
            "sub": "google-sub-existing-user",
            "email": "existing@example.com",
            "email_verified": True,
            "name": "Google User",
        }
        with patch.object(
            cloud_app.google,
            "authorize_access_token",
            return_value={"userinfo": claims},
        ):
            response = self.client.get(
                "/auth/google/callback",
                environ_base={"REMOTE_ADDR": "192.0.2.92"},
            )

        self.assertEqual(response.status_code, 302)
        with cloud_app.database_connection() as connection:
            user = connection.execute(
                "SELECT username, google_sub FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        self.assertEqual(user["username"], "existing-google-user")
        self.assertEqual(user["google_sub"], claims["sub"])
        with self.client.session_transaction() as signed_session:
            self.assertEqual(signed_session["user_id"], user_id)

    def test_google_callback_rejects_unverified_email(self):
        claims = {
            "sub": "google-sub-unverified",
            "email": "unverified@example.com",
            "email_verified": False,
            "name": "Unverified User",
        }
        with patch.object(
            cloud_app.google,
            "authorize_access_token",
            return_value={"userinfo": claims},
        ):
            response = self.client.get(
                "/auth/google/callback",
                environ_base={"REMOTE_ADDR": "192.0.2.94"},
            )

        self.assertEqual(response.status_code, 400)
        with cloud_app.database_connection() as connection:
            user = connection.execute(
                "SELECT id FROM users WHERE google_sub = ?",
                (claims["sub"],),
            ).fetchone()
        self.assertIsNone(user)

    def test_google_callback_respects_registration_disabled(self):
        claims = {
            "sub": "google-sub-registration-disabled",
            "email": "registration.disabled@example.com",
            "email_verified": True,
            "name": "Registration Disabled",
        }
        with (
            patch.object(
                cloud_app.google,
                "authorize_access_token",
                return_value={"userinfo": claims},
            ),
            patch.object(
                cloud_app,
                "policy_enabled",
                side_effect=lambda name, default=False: (
                    False if name == "allow_registration" else default
                ),
            ),
        ):
            response = self.client.get(
                "/auth/google/callback",
                environ_base={"REMOTE_ADDR": "192.0.2.95"},
            )

        self.assertEqual(response.status_code, 403)
        with cloud_app.database_connection() as connection:
            user = connection.execute(
                "SELECT id FROM users WHERE google_sub = ?",
                (claims["sub"],),
            ).fetchone()
        self.assertIsNone(user)

    def test_google_callback_does_not_create_account_during_maintenance(self):
        claims = {
            "sub": "google-sub-maintenance",
            "email": "maintenance@example.com",
            "email_verified": True,
            "name": "Maintenance User",
        }
        with (
            patch.object(
                cloud_app.google,
                "authorize_access_token",
                return_value={"userinfo": claims},
            ),
            patch.object(cloud_app, "maintenance_enabled", return_value=True),
        ):
            response = self.client.get(
                "/auth/google/callback",
                environ_base={"REMOTE_ADDR": "192.0.2.96"},
            )

        self.assertEqual(response.status_code, 503)
        with cloud_app.database_connection() as connection:
            user = connection.execute(
                "SELECT id FROM users WHERE google_sub = ?",
                (claims["sub"],),
            ).fetchone()
        self.assertIsNone(user)

    def test_google_admin_login_still_requires_authenticator_verification(self):
        token = "google-sub-admin-mfa-test"
        with cloud_app.database_connection() as connection:
            admin = connection.execute(
                "SELECT id, google_sub, totp_secret, totp_enabled FROM users "
                "WHERE username = ? COLLATE NOCASE",
                (cloud_app.ADMIN_USERNAME,),
            ).fetchone()
            connection.execute(
                "UPDATE users SET google_sub = ?, totp_secret = ?, totp_enabled = 1 "
                "WHERE id = ?",
                (token, "JBSWY3DPEHPK3PXP", admin["id"]),
            )
        claims = {
            "sub": token,
            "email": "test-admin@example.com",
            "email_verified": True,
            "name": "Cloud Rdx Administrator",
        }
        try:
            with patch.object(
                cloud_app.google,
                "authorize_access_token",
                return_value={"userinfo": claims},
            ):
                response = self.client.get(
                    "/auth/google/callback",
                    environ_base={"REMOTE_ADDR": "192.0.2.97"},
                )
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.headers["Location"], "/login/2fa")
            with self.client.session_transaction() as signed_session:
                self.assertEqual(
                    signed_session["pending_2fa_user_id"], admin["id"]
                )
                self.assertNotIn("user_id", signed_session)
        finally:
            with cloud_app.database_connection() as connection:
                connection.execute(
                    "UPDATE users SET google_sub = ?, totp_secret = ?, "
                    "totp_enabled = ? WHERE id = ?",
                    (
                        admin["google_sub"],
                        admin["totp_secret"],
                        admin["totp_enabled"],
                        admin["id"],
                    ),
                )

    def test_google_login_start_uses_configured_callback_url(self):
        with patch.object(
            cloud_app.google,
            "authorize_redirect",
            return_value=cloud_app.redirect("/oauth-provider-mock"),
        ) as authorize_redirect:
            response = self.client.get(
                "/auth/google", environ_base={"REMOTE_ADDR": "192.0.2.93"}
            )

        self.assertEqual(response.status_code, 302)
        authorize_redirect.assert_called_once_with(
            "http://127.0.0.1:8000/auth/google/callback"
        )


def tearDownModule():
    import gc

    gc.collect()
    _test_storage.cleanup()


if __name__ == "__main__":
    unittest.main()

