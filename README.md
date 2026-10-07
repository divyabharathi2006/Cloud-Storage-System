# Cloud Rdx

Cloud Rdx is a Python/Flask file-storage application with account management, a browser-based file manager, and administrator controls. It stores files on the application host by default, with optional integrations for OAuth sign-in, upload scanning, payments, and Azure Blob Storage. Windows packaging is provided both for a hosted-site desktop client and for a bundled standalone application.

> **Important:** Cloud Rdx is application software, not a managed cloud-storage service. Review [`SECURITY.md`](SECURITY.md) before exposing it to a network or using it with real data. The documented controls are not a security certification.

## Key features

- User registration, password sign-in, profile management, optional authenticator-based two-factor authentication, and optional Google/GitHub OAuth.
- File uploads, downloads, folder creation and management, bulk downloads, storage quotas, and a recycle bin.
- Administrator user, role, permission, quota, payment-review, audit, security-alert, and emergency-control pages.
- SQLite-backed accounts, policies, audit/security records, and subscription data; user files are stored separately on the local filesystem.
- Optional ClamAV upload scanning, Razorpay subscription/payment handling, and Azure Blob sync/backup utilities.
- Windows hosted-site desktop client, standalone desktop application, and installer build scripts.

Optional integrations require their respective services, credentials, and configuration; installing `requirements.txt` alone does not configure them.

## Latest version highlights

This version includes the current Cloud Rdx feature set and the latest improvements added to the application.

### Recent product improvements

- Refined the authentication flow with a modern sign-in experience, improved password-entry UX, password visibility toggle, better registration and recovery guidance, and clearer error feedback.
- Added a complete profile and recovery workflow so users can update personal details, review recovery information, and change passwords without administrator intervention.
- Improved security hardening with rate limiting, login lockouts, session protections, audit logging, and security alerting for suspicious activity.
- Expanded the admin surface with dashboard analytics, user management, permissions controls, emergency controls, and account-level configuration.
- Added policy/consent handling for the required terms, privacy, cookie, and disclaimer reminders before continued use.
- Improved the file browser with folder browsing, bulk downloads, shared-link management, recycle-bin support, and a cleaner user workflow.
- Added support for optional Google and GitHub OAuth sign-in while keeping password-based access available.
- Added backup and sync support for local backup creation and optional Azure Blob sync workflows.
- Strengthened hardening with security headers and static-file controls to reduce common web-application risks.
- Improved packaging support for the Windows desktop and standalone application targets.

### Current capabilities

- Private local file storage with per-user directories, quotas, and recovery-safe account handling.
- Administrator-led controls for user access, storage limits, emergency policy changes, and data recovery actions.
- Payment and subscription integration for account upgrades and storage plans.
- Local file scanning and optional ClamAV-based malicious-file defense during upload.
- Azure sync and backup helpers for organizations that want local-to-cloud workflows and retention-aware backup patterns.

### Deployment notes

- Cloud Rdx is designed for self-hosted or private deployment and is not a managed SaaS platform.
- Use the guidance in [`SECURITY.md`](SECURITY.md) before exposing the app to the internet or a shared network.
- Optional services such as Google/GitHub OAuth, ClamAV, Razorpay, and Azure storage require their own credentials and configuration.
## Technologies

- **Python**, **Flask**, **Werkzeug**, and **SQLite** for the web application and persistence.
- **Authlib** for Google OpenID Connect and GitHub OAuth.
- **argon2-cffi** for password hashing, **cryptography** for cryptographic operations, and **python-dotenv** for local environment configuration.
- **pywebview** for the Windows desktop windows; **PyInstaller** is used by the build scripts but is installed separately.
- **Razorpay Python SDK** for optional subscription/payment flows.
- Optional external services: ClamAV; Azure Identity and Blob Storage SDKs (not currently included in `requirements.txt`).
- **Python `unittest`** for the current test suite.

## Architecture and repository layout

The main Flask application is `app.py`. It owns browser routes, JSON endpoints, authentication, policy checks, and SQLite initialization. `cloud_security_services.py` contains optional ClamAV and Azure storage operations. `automation_worker.py` is a separate process for polling due local-to-Azure sync jobs. The web UI uses Flask-rendered HTML and files under `static/`.

```text
app.py                              Flask application, routes, and database setup
automation_worker.py                Scheduled local-to-Azure sync worker
cloud_security_services.py          ClamAV and Azure storage helpers
requirements.txt                    Python application dependencies
static/                             Application CSS and JavaScript
storage/                            Local database, uploads, trash, and backups
tests/                               Automated tests
desktop/                             Hosted-site Windows desktop client
desktop-application/                Bundled standalone Windows application
installer/                           Windows installer build
SECURITY.md                          Security controls and deployment limitations
```

Runtime `storage/` data and generated build output are ignored by `.gitignore`. Check that no private data has already been committed before publishing.

## Requirements

- Python 3 and pip (the repository does not declare a specific minimum Python version).
- Windows PowerShell for the included Windows build scripts.
- Optional, depending on enabled features: Google/GitHub OAuth applications; a ClamAV daemon; Razorpay credentials; or Azure Storage and credentials supported by `DefaultAzureCredential`.

## Installation and local setup

Run commands from the repository root.

### 1. Create and activate a virtual environment

**Windows PowerShell:**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS/Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The Azure SDK packages used by the optional worker are dynamically imported and are not in `requirements.txt`. Install them separately only if enabling Azure storage functionality:

```bash
python -m pip install azure-identity azure-storage-blob
```

### 3. Configure local settings and run

Set a local secret key and initial administrator password before first startup. These example values are placeholders, not production secrets.

**Windows PowerShell:**

```powershell
$env:FLASK_SECRET_KEY = "replace-with-a-long-random-local-secret"
$env:ADMIN_PASSWORD = "choose-a-strong-local-admin-password"
python app.py
```

**macOS/Linux:**

```bash
export FLASK_SECRET_KEY='replace-with-a-long-random-local-secret'
export ADMIN_PASSWORD='choose-a-strong-local-admin-password'
python app.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The default administrator username is `admindivya`; change it with `ADMIN_USERNAME`. `HOST` and `PORT` control the bind address and port.

On first startup, the application creates the initial administrator. If `ADMIN_PASSWORD` is unset, it generates and prints a password to the server console. Set a password before first startup and protect console output. Subsequent starts do not reset the existing administrator's password.

For local development, settings may be placed in a private root `.env` file; `.env` files are ignored by Git. Never commit real credentials or secrets.

## Configuration

These are the main environment variables read by the application and optional integrations. Defaults are for local/basic operation, not production recommendations. See [`SECURITY.md`](SECURITY.md) for additional deployment guidance.

| Variable | Purpose | Default |
|---|---|---|
| `FLASK_SECRET_KEY` | Persistent signing key for sessions and key-derived protected values. | Random per process if unset; development fallback only |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | Initial administrator credentials. | `admindivya` / generated and printed if unset |
| `HOST` / `PORT` | Flask development-server bind address and port. | `0.0.0.0` / `8000` |
| `SHARED_FOLDER` | Root for local application storage and per-user files. | `storage/` beside the application |
| `FILE_SERVER_DATABASE` | SQLite database file. | `cloud_rdx.sqlite3` inside `SHARED_FOLDER` |
| `SESSION_TIMEOUT_MINUTES` | Idle session timeout. | `30` |
| `SESSION_COOKIE_SECURE` | Set to `1` when requests use HTTPS. | `0` for local development |
| `TRUSTED_PROXY_HOPS` | Number of trusted reverse-proxy hops for forwarded headers. | `0` |
| `MAX_UPLOAD_MB` | Maximum accepted upload size in MiB. | `100` |
| `LOGIN_WINDOW_MINUTES`, `LOGIN_MAX_ATTEMPTS`, `LOGIN_LOCKOUT_MINUTES` | Login failure/lockout defaults for new installations. | `15`, `5`, `15` |
| `APP_BASE_URL` | Base URL for OAuth callback construction. | `http://localhost:8000` |
| `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET` | Optional Google sign-in credentials. | Unset |
| `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET` | Optional GitHub sign-in credentials. | Unset |
| `CLAMD_HOST`, `CLAMD_PORT`, `CLAMD_TIMEOUT_SECONDS` | ClamAV daemon connection settings. | `127.0.0.1`, `3310`, `15` seconds |
| `CLAMD_REQUIRED` | Set to `1` to reject uploads when ClamAV is unavailable. | `0` |
| `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET` | Optional Razorpay integration credentials. | Unset |
| `PAYMENT_QR_URL` | Payment QR route/path used by the payment page. | `/payment-qr` |
| `CLOUD_RDX_AZURE_ACCOUNT_URL` | HTTPS Azure Blob account endpoint. | Unset |
| `CLOUD_RDX_SYNC_CONTAINER` | Azure container used by the sync worker. | `cloud-rdx-sync` |
| `CLOUD_RDX_SYNC_POLL_SECONDS` | Worker idle polling interval, clamped to 5â€“300 seconds. | `15` |
| `CLOUD_RDX_BACKUP_RETENTION_DAYS` | Minimum locked immutability retention required by the Azure backup helper. | `90` |

Google and GitHub callback URLs are `${APP_BASE_URL}/auth/google/callback` and `${APP_BASE_URL}/auth/github/callback`. Register the exact callback URL with each provider. For a public deployment, use the public HTTPS URL and store client secrets in a secret manager or private environment settings. Some provider credentials can also be managed from owner-only website settings.

### Optional Azure sync worker

`automation_worker.py` polls the SQLite sync-job table and processes due local-to-Azure Blob sync jobs. Start it separately from the web application:

```bash
python automation_worker.py
```

The default sync job is disabled; configure and enable a job before expecting files to sync. Azure authentication uses `DefaultAzureCredential`. Verify Azure permissions, container setup, and retention requirements before use. The project also contains an immutable-backup helper that requires an Azure container with a locked immutability policy; the local admin backup action is separate and is not an Azure backup.

## Routes and API

The application uses Flask routes rather than a separately versioned API service. These are representative entry points; some routes require an authenticated user or an administrator permission.

### Browser routes

| Route | Purpose |
|---|---|
| `/` | Home and signed-in landing page |
| `/login`, `/register`, `/logout` | Account access |
| `/auth/google`, `/auth/google/callback`, `/auth/github`, `/auth/github/callback` | Optional provider sign-in start and callback routes |
| `/login/2fa`, `/security/2fa/enroll` | Authenticator verification and enrollment |
| `/profile` | User profile |
| `/files/` | User file browser |
| `/upload/`, `/download/<path>` | File transfer |
| `/downloads/bulk` | Bulk file download |
| `/recycle-bin` | User recycle bin |
| `/storage/plan` | Storage plans and payment options |
| `/admin`, `/admin/manage`, `/admin/storage` | Administration and storage management |
| `/admin/security`, `/admin/audit`, `/admin/emergency` | Security, audit, and emergency controls |

### JSON and webhook endpoints

| Method and route | Purpose / access |
|---|---|
| `GET /api/storage/plans` | Storage plans; requires sign-in |
| `GET /api/storage/usage` | Current user's storage usage; requires sign-in |
| `GET /api/subscription` | Current user's subscription; requires sign-in |
| `POST /api/storage/create-order` | Create a configured Razorpay subscription order; requires sign-in and Razorpay setup |
| `POST /api/storage/verify-payment` | Verify a Razorpay payment; requires sign-in and Razorpay setup |
| `POST /api/payment/webhook` | Razorpay webhook; validates the configured webhook signature |
| `GET /api/admin/analytics/overview` | Owner-only aggregate analytics |
| `GET /api/admin/analytics/activity` | Owner-only audit activity series; supports `range=24h`, `7d`, `30d`, `180d`, or `365d` |

There is no OpenAPI/Swagger specification in the repository. Use the route implementation in `app.py` as the source of truth for request/response details.

## Database and file storage

- The application uses SQLite. By default, the database is `storage/cloud_rdx.sqlite3`; `FILE_SERVER_DATABASE` can override its path.
- User files are kept below `SHARED_FOLDER/users/<user-id>/`. Trash and local ZIP snapshots are stored under `.trash/` and `.backups/` within `SHARED_FOLDER`.
- Database tables are initialized and updated by the application at startup. Back up the database before deploying updates and protect both the database and file storage with operating-system permissions and encrypted storage where appropriate.
- The admin â€œCreate local backupâ€ action archives user files and a manifest; it does **not** include the SQLite database and is not an off-host disaster-recovery backup. Keep separate database and file backups and test restoration.
- Tests configure temporary storage and a temporary database so test data is isolated from normal application data.

## Screenshots

No application screenshots are currently included. Add reviewed screenshots under a documentation or image folder and link them here when available. Existing image files are application/theme assets, not documented screenshots of the running UI.

## Tests

Run the current test suite from the repository root:

```bash
python -m unittest discover -s tests -v
```

The focused tests cover security and file-transfer behavior using temporary local test data. See [`SECURITY.md`](SECURITY.md) for the current test coverage and its limitations.

## Windows desktop builds

The repository has two different desktop targets:

- **Hosted-site client** (`desktop/`): opens an already-running Cloud Rdx website in a native window. It does not run Flask or store uploaded user files locally. Follow [`desktop/README.txt`](desktop/README.txt). Install PyInstaller separately and provide the hosted URL:

  ```powershell
  python -m pip install pyinstaller
  powershell -ExecutionPolicy Bypass -File .\desktop\build.ps1 -ServerUrl "https://your-hosted-domain.example"
  ```

- **Standalone application** (`desktop-application/`): bundles the Flask app and runs it locally in a native window. Its database and files are stored beside the executable by default. Follow [`desktop-application/README.txt`](desktop-application/README.txt):

  ```powershell
  python -m pip install pyinstaller
  powershell -ExecutionPolicy Bypass -File .\desktop-application\build.ps1
  ```

- **Installer** (`installer/`): packages the standalone application for Windows. See [`installer/README.txt`](installer/README.txt).

Build outputs are written to the relevant `dist/` directories and are ignored by Git.

## Deployment and security

`python app.py` starts Flask's built-in development server; it is for local development and must not be exposed directly as a production server. The repository does not include a production WSGI server or a complete deployment/hosting configuration. For a production deployment, select and configure a production WSGI server and reverse proxy appropriate to your host.

Before handling real data:

- Set a long, cryptographically random, persistent `FLASK_SECRET_KEY` and a strong `ADMIN_PASSWORD` before the first startup. Do not rely on the generated secret fallback in production.
- Serve only through correctly configured HTTPS and set `SESSION_COOKIE_SECURE=1`.
- Keep debug mode disabled, restrict direct access to the application process, and configure `TRUSTED_PROXY_HOPS` only for a verified trusted proxy chain.
- Restrict access to the database, uploaded files, backups, and logs. Back up the database and files separately and test restoration.
- Use an edge WAF/rate limits for public deployments. Flask-level rate limits do not replace volumetric DDoS protection; SQLite rate-limit state is not suitable for multi-host high availability.
- Configure and monitor ClamAV if uploads must be scanned; `CLAMD_REQUIRED=1` rejects uploads when scanning is unavailable.
- Review the recovery-flow and other known limitations in [`SECURITY.md`](SECURITY.md) before production use.

The application includes controls such as Argon2 password hashes, CSRF checks for browser POSTs, per-request rate limiting, session/device checks, and security headers. These do not eliminate the need for a complete security review. Full details, limitations, and incident guidance are in [`SECURITY.md`](SECURITY.md).

## Troubleshooting

- **Missing Python module:** Activate `.venv` and run `python -m pip install -r requirements.txt` again. Azure worker imports are optional and require the two Azure SDK packages listed above.
- **Initial password is unknown:** Check the server console from the first startup if `ADMIN_PASSWORD` was unset. Set `ADMIN_PASSWORD` before the database creates its initial administrator; it does not reset an existing password.
- **Port is already in use:** Set `PORT` to an available port and open that port locally.
- **OAuth callback error:** Ensure the provider's registered callback exactly matches `APP_BASE_URL` plus the callback path, and that the configured client credentials belong to that OAuth application.
- **Uploads report a scanner issue:** Check ClamAV availability at `CLAMD_HOST`/`CLAMD_PORT`. Without `CLAMD_REQUIRED=1`, an unavailable scanner does not block ordinary uploads; with it enabled, uploads are rejected when scanning is unavailable.
- **Razorpay endpoints report not configured:** Set the required Razorpay keys and configure the provider plan IDs/settings before creating orders.
- **Azure sync does not run:** Confirm the Azure SDK packages and credentials are available, `CLOUD_RDX_AZURE_ACCOUNT_URL` is an HTTPS Blob endpoint, the target container is accessible, the sync job is enabled, and the worker process is running.
- **Desktop build fails:** Install project requirements and PyInstaller in the active environment. The hosted-site client build also requires a valid `-ServerUrl`.

## Potential future improvements

These are follow-up recommendations, not claims of existing functionality:

- Replace the current recovery flow with email-delivered, single-use password-reset tokens.
- Move inline scripts/styles out of templates or use per-response CSP nonces to reduce reliance on `unsafe-inline`.
- Use a transactional shared rate-limit store for multi-host deployments.
- Add production deployment configuration and broader integration/security test coverage.

The first three items are also reflected in the known limitations and recommendations in [`SECURITY.md`](SECURITY.md).

## Author

Author or maintainer details are not specified in the project files. Add the appropriate name and profile links before publishing this as a portfolio project.

## License

No root `LICENSE` file is present. The project's reuse and redistribution terms are therefore not stated here; add a license file and update this section before inviting public reuse.
# Cloud Rdx

Cloud Rdx is a Python/Flask file-storage application with account management, a browser-based file manager, and administrator controls. It stores files on the application host by default, with optional integrations for OAuth sign-in, upload scanning, payments, and Azure Blob Storage. Windows packaging is provided both for a hosted-site desktop client and for a bundled standalone application.

> **Important:** Cloud Rdx is application software, not a managed cloud-storage service. Review [`SECURITY.md`](SECURITY.md) before exposing it to a network or using it with real data. The documented controls are not a security certification.

## Key features

- User registration, password sign-in, profile management, optional authenticator-based two-factor authentication, and optional Google/GitHub OAuth.
- File uploads, downloads, folder creation and management, bulk downloads, storage quotas, and a recycle bin.
- Administrator user, role, permission, quota, payment-review, audit, security-alert, and emergency-control pages.
- SQLite-backed accounts, policies, audit/security records, and subscription data; user files are stored separately on the local filesystem.
- Optional ClamAV upload scanning, Razorpay subscription/payment handling, and Azure Blob sync/backup utilities.
- Windows hosted-site desktop client, standalone desktop application, and installer build scripts.

Optional integrations require their respective services, credentials, and configuration; installing `requirements.txt` alone does not configure them.

## Technologies

- **Python**, **Flask**, **Werkzeug**, and **SQLite** for the web application and persistence.
- **Authlib** for Google OpenID Connect and GitHub OAuth.
- **argon2-cffi** for password hashing, **cryptography** for cryptographic operations, and **python-dotenv** for local environment configuration.
- **pywebview** for the Windows desktop windows; **PyInstaller** is used by the build scripts but is installed separately.
- **Razorpay Python SDK** for optional subscription/payment flows.
- Optional external services: ClamAV; Azure Identity and Blob Storage SDKs (not currently included in `requirements.txt`).
- **Python `unittest`** for the current test suite.

## Architecture and repository layout

The main Flask application is `app.py`. It owns browser routes, JSON endpoints, authentication, policy checks, and SQLite initialization. `cloud_security_services.py` contains optional ClamAV and Azure storage operations. `automation_worker.py` is a separate process for polling due local-to-Azure sync jobs. The web UI uses Flask-rendered HTML and files under `static/`.

```text
app.py                              Flask application, routes, and database setup
automation_worker.py                Scheduled local-to-Azure sync worker
cloud_security_services.py          ClamAV and Azure storage helpers
requirements.txt                    Python application dependencies
static/                             Application CSS and JavaScript
storage/                            Local database, uploads, trash, and backups
tests/                               Automated tests
desktop/                             Hosted-site Windows desktop client
desktop-application/                Bundled standalone Windows application
installer/                           Windows installer build
SECURITY.md                          Security controls and deployment limitations
```

Runtime `storage/` data and generated build output are ignored by `.gitignore`. Check that no private data has already been committed before publishing.

## Requirements

- Python 3 and pip (the repository does not declare a specific minimum Python version).
- Windows PowerShell for the included Windows build scripts.
- Optional, depending on enabled features: Google/GitHub OAuth applications; a ClamAV daemon; Razorpay credentials; or Azure Storage and credentials supported by `DefaultAzureCredential`.

## Installation and local setup

Run commands from the repository root.

### 1. Create and activate a virtual environment

**Windows PowerShell:**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**macOS/Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The Azure SDK packages used by the optional worker are dynamically imported and are not in `requirements.txt`. Install them separately only if enabling Azure storage functionality:

```bash
python -m pip install azure-identity azure-storage-blob
```

### 3. Configure local settings and run

Set a local secret key and initial administrator password before first startup. These example values are placeholders, not production secrets.

**Windows PowerShell:**

```powershell
$env:FLASK_SECRET_KEY = "replace-with-a-long-random-local-secret"
$env:ADMIN_PASSWORD = "choose-a-strong-local-admin-password"
python app.py
```

**macOS/Linux:**

```bash
export FLASK_SECRET_KEY='replace-with-a-long-random-local-secret'
export ADMIN_PASSWORD='choose-a-strong-local-admin-password'
python app.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The default administrator username is `admindivya`; change it with `ADMIN_USERNAME`. `HOST` and `PORT` control the bind address and port.

On first startup, the application creates the initial administrator. If `ADMIN_PASSWORD` is unset, it generates and prints a password to the server console. Set a password before first startup and protect console output. Subsequent starts do not reset the existing administrator's password.

For local development, settings may be placed in a private root `.env` file; `.env` files are ignored by Git. Never commit real credentials or secrets.

## Configuration

These are the main environment variables read by the application and optional integrations. Defaults are for local/basic operation, not production recommendations. See [`SECURITY.md`](SECURITY.md) for additional deployment guidance.

| Variable | Purpose | Default |
|---|---|---|
| `FLASK_SECRET_KEY` | Persistent signing key for sessions and key-derived protected values. | Random per process if unset; development fallback only |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | Initial administrator credentials. | `admindivya` / generated and printed if unset |
| `HOST` / `PORT` | Flask development-server bind address and port. | `0.0.0.0` / `8000` |
| `SHARED_FOLDER` | Root for local application storage and per-user files. | `storage/` beside the application |
| `FILE_SERVER_DATABASE` | SQLite database file. | `cloud_rdx.sqlite3` inside `SHARED_FOLDER` |
| `SESSION_TIMEOUT_MINUTES` | Idle session timeout. | `30` |
| `SESSION_COOKIE_SECURE` | Set to `1` when requests use HTTPS. | `0` for local development |
| `TRUSTED_PROXY_HOPS` | Number of trusted reverse-proxy hops for forwarded headers. | `0` |
| `MAX_UPLOAD_MB` | Maximum accepted upload size in MiB. | `100` |
| `LOGIN_WINDOW_MINUTES`, `LOGIN_MAX_ATTEMPTS`, `LOGIN_LOCKOUT_MINUTES` | Login failure/lockout defaults for new installations. | `15`, `5`, `15` |
| `APP_BASE_URL` | Base URL for OAuth callback construction. | `http://localhost:8000` |
| `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET` | Optional Google sign-in credentials. | Unset |
| `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET` | Optional GitHub sign-in credentials. | Unset |
| `CLAMD_HOST`, `CLAMD_PORT`, `CLAMD_TIMEOUT_SECONDS` | ClamAV daemon connection settings. | `127.0.0.1`, `3310`, `15` seconds |
| `CLAMD_REQUIRED` | Set to `1` to reject uploads when ClamAV is unavailable. | `0` |
| `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET` | Optional Razorpay integration credentials. | Unset |
| `PAYMENT_QR_URL` | Payment QR route/path used by the payment page. | `/payment-qr` |
| `CLOUD_RDX_AZURE_ACCOUNT_URL` | HTTPS Azure Blob account endpoint. | Unset |
| `CLOUD_RDX_SYNC_CONTAINER` | Azure container used by the sync worker. | `cloud-rdx-sync` |
| `CLOUD_RDX_SYNC_POLL_SECONDS` | Worker idle polling interval, clamped to 5â€“300 seconds. | `15` |
| `CLOUD_RDX_BACKUP_RETENTION_DAYS` | Minimum locked immutability retention required by the Azure backup helper. | `90` |

Google and GitHub callback URLs are `${APP_BASE_URL}/auth/google/callback` and `${APP_BASE_URL}/auth/github/callback`. Register the exact callback URL with each provider. For a public deployment, use the public HTTPS URL and store client secrets in a secret manager or private environment settings. Some provider credentials can also be managed from owner-only website settings.

### Optional Azure sync worker

`automation_worker.py` polls the SQLite sync-job table and processes due local-to-Azure Blob sync jobs. Start it separately from the web application:

```bash
python automation_worker.py
```

The default sync job is disabled; configure and enable a job before expecting files to sync. Azure authentication uses `DefaultAzureCredential`. Verify Azure permissions, container setup, and retention requirements before use. The project also contains an immutable-backup helper that requires an Azure container with a locked immutability policy; the local admin backup action is separate and is not an Azure backup.

## Routes and API

The application uses Flask routes rather than a separately versioned API service. These are representative entry points; some routes require an authenticated user or an administrator permission.

### Browser routes

| Route | Purpose |
|---|---|
| `/` | Home and signed-in landing page |
| `/login`, `/register`, `/logout` | Account access |
| `/auth/google`, `/auth/google/callback`, `/auth/github`, `/auth/github/callback` | Optional provider sign-in start and callback routes |
| `/login/2fa`, `/security/2fa/enroll` | Authenticator verification and enrollment |
| `/profile` | User profile |
| `/files/` | User file browser |
| `/upload/`, `/download/<path>` | File transfer |
| `/downloads/bulk` | Bulk file download |
| `/recycle-bin` | User recycle bin |
| `/storage/plan` | Storage plans and payment options |
| `/admin`, `/admin/manage`, `/admin/storage` | Administration and storage management |
| `/admin/security`, `/admin/audit`, `/admin/emergency` | Security, audit, and emergency controls |

### JSON and webhook endpoints

| Method and route | Purpose / access |
|---|---|
| `GET /api/storage/plans` | Storage plans; requires sign-in |
| `GET /api/storage/usage` | Current user's storage usage; requires sign-in |
| `GET /api/subscription` | Current user's subscription; requires sign-in |
| `POST /api/storage/create-order` | Create a configured Razorpay subscription order; requires sign-in and Razorpay setup |
| `POST /api/storage/verify-payment` | Verify a Razorpay payment; requires sign-in and Razorpay setup |
| `POST /api/payment/webhook` | Razorpay webhook; validates the configured webhook signature |
| `GET /api/admin/analytics/overview` | Owner-only aggregate analytics |
| `GET /api/admin/analytics/activity` | Owner-only audit activity series; supports `range=24h`, `7d`, `30d`, `180d`, or `365d` |

There is no OpenAPI/Swagger specification in the repository. Use the route implementation in `app.py` as the source of truth for request/response details.

## Database and file storage

- The application uses SQLite. By default, the database is `storage/cloud_rdx.sqlite3`; `FILE_SERVER_DATABASE` can override its path.
- User files are kept below `SHARED_FOLDER/users/<user-id>/`. Trash and local ZIP snapshots are stored under `.trash/` and `.backups/` within `SHARED_FOLDER`.
- Database tables are initialized and updated by the application at startup. Back up the database before deploying updates and protect both the database and file storage with operating-system permissions and encrypted storage where appropriate.
- The admin â€œCreate local backupâ€ action archives user files and a manifest; it does **not** include the SQLite database and is not an off-host disaster-recovery backup. Keep separate database and file backups and test restoration.
- Tests configure temporary storage and a temporary database so test data is isolated from normal application data.

## Screenshots

No application screenshots are currently included. Add reviewed screenshots under a documentation or image folder and link them here when available. Existing image files are application/theme assets, not documented screenshots of the running UI.

## Tests

Run the current test suite from the repository root:

```bash
python -m unittest discover -s tests -v
```

The focused tests cover security and file-transfer behavior using temporary local test data. See [`SECURITY.md`](SECURITY.md) for the current test coverage and its limitations.

## Windows desktop builds

The repository has two different desktop targets:

- **Hosted-site client** (`desktop/`): opens an already-running Cloud Rdx website in a native window. It does not run Flask or store uploaded user files locally. Follow [`desktop/README.txt`](desktop/README.txt). Install PyInstaller separately and provide the hosted URL:

  ```powershell
  python -m pip install pyinstaller
  powershell -ExecutionPolicy Bypass -File .\desktop\build.ps1 -ServerUrl "https://your-hosted-domain.example"
  ```

- **Standalone application** (`desktop-application/`): bundles the Flask app and runs it locally in a native window. Its database and files are stored beside the executable by default. Follow [`desktop-application/README.txt`](desktop-application/README.txt):

  ```powershell
  python -m pip install pyinstaller
  powershell -ExecutionPolicy Bypass -File .\desktop-application\build.ps1
  ```

- **Installer** (`installer/`): packages the standalone application for Windows. See [`installer/README.txt`](installer/README.txt).

Build outputs are written to the relevant `dist/` directories and are ignored by Git.

## Deployment and security

`python app.py` starts Flask's built-in development server; it is for local development and must not be exposed directly as a production server. The repository does not include a production WSGI server or a complete deployment/hosting configuration. For a production deployment, select and configure a production WSGI server and reverse proxy appropriate to your host.

Before handling real data:

- Set a long, cryptographically random, persistent `FLASK_SECRET_KEY` and a strong `ADMIN_PASSWORD` before the first startup. Do not rely on the generated secret fallback in production.
- Serve only through correctly configured HTTPS and set `SESSION_COOKIE_SECURE=1`.
- Keep debug mode disabled, restrict direct access to the application process, and configure `TRUSTED_PROXY_HOPS` only for a verified trusted proxy chain.
- Restrict access to the database, uploaded files, backups, and logs. Back up the database and files separately and test restoration.
- Use an edge WAF/rate limits for public deployments. Flask-level rate limits do not replace volumetric DDoS protection; SQLite rate-limit state is not suitable for multi-host high availability.
- Configure and monitor ClamAV if uploads must be scanned; `CLAMD_REQUIRED=1` rejects uploads when scanning is unavailable.
- Review the recovery-flow and other known limitations in [`SECURITY.md`](SECURITY.md) before production use.

The application includes controls such as Argon2 password hashes, CSRF checks for browser POSTs, per-request rate limiting, session/device checks, and security headers. These do not eliminate the need for a complete security review. Full details, limitations, and incident guidance are in [`SECURITY.md`](SECURITY.md).

## Troubleshooting

- **Missing Python module:** Activate `.venv` and run `python -m pip install -r requirements.txt` again. Azure worker imports are optional and require the two Azure SDK packages listed above.
- **Initial password is unknown:** Check the server console from the first startup if `ADMIN_PASSWORD` was unset. Set `ADMIN_PASSWORD` before the database creates its initial administrator; it does not reset an existing password.
- **Port is already in use:** Set `PORT` to an available port and open that port locally.
- **OAuth callback error:** Ensure the provider's registered callback exactly matches `APP_BASE_URL` plus the callback path, and that the configured client credentials belong to that OAuth application.
- **Uploads report a scanner issue:** Check ClamAV availability at `CLAMD_HOST`/`CLAMD_PORT`. Without `CLAMD_REQUIRED=1`, an unavailable scanner does not block ordinary uploads; with it enabled, uploads are rejected when scanning is unavailable.
- **Razorpay endpoints report not configured:** Set the required Razorpay keys and configure the provider plan IDs/settings before creating orders.
- **Azure sync does not run:** Confirm the Azure SDK packages and credentials are available, `CLOUD_RDX_AZURE_ACCOUNT_URL` is an HTTPS Blob endpoint, the target container is accessible, the sync job is enabled, and the worker process is running.
- **Desktop build fails:** Install project requirements and PyInstaller in the active environment. The hosted-site client build also requires a valid `-ServerUrl`.

## Potential future improvements

These are follow-up recommendations, not claims of existing functionality:

- Replace the current recovery flow with email-delivered, single-use password-reset tokens.
- Move inline scripts/styles out of templates or use per-response CSP nonces to reduce reliance on `unsafe-inline`.
- Use a transactional shared rate-limit store for multi-host deployments.
- Add production deployment configuration and broader integration/security test coverage.

The first three items are also reflected in the known limitations and recommendations in [`SECURITY.md`](SECURITY.md).

## Author

Author or maintainer details are not specified in the project files. Add the appropriate name and profile links before publishing this as a portfolio project.

## License

No root `LICENSE` file is present. The project's reuse and redistribution terms are therefore not stated here; add a license file and update this section before inviting public reuse.








