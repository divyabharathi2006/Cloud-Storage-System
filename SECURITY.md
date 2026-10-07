# Cloud Rdx security

This document describes security controls present in the Flask application and
deployment responsibilities. It is not a certification that the service is
secure against every threat.

## Security architecture and controls

- The application uses Argon2 password hashes and verifies current account
  status during authentication.
- Login failures are recorded in SQLite and checked per account and source IP.
  After the configured threshold, the account/source pair is temporarily
  cooled down.
- Persistent request limits are enforced per IP, account, session, endpoint
  group, and method-specific operation. Current defaults are:
  - Login: 20 per account and 20 per IP per 15 minutes. The existing
    failed-password cooldown applies after 5 consecutive failures for an
    account/source-IP pair, then doubles for each additional group of 5 failures
    (capped at 8 times the configured base). A successful login resets that
    failure streak.
  - Google OAuth start and callback: 20 per IP per 15 minutes.
  - Authenticator verification: 5 per pending account/session per 5 minutes.
  - Registration: 3 per account and 15 per IP per hour.
  - Password recovery: 3 per account and 10 per IP per hour.
  - Uploads: 30 per session and 100 per IP per hour.
  - Downloads: 300 per session and 600 per IP per 15 minutes; bulk downloads
    are limited to 10 per session and 40 per IP per 15 minutes.
  - API requests: 120 per IP and 240 per session per 5 minutes.
  - Admin endpoints: 180 per IP and 300 per session per 5 minutes.
  - Other traffic: 600 per IP and 900 per session per 5 minutes.
- A rejected request receives HTTP 429 and a `Retry-After` header. JSON clients
  receive a generic JSON error; browser clients receive a generic page.
- Rate-limit identifiers are HMAC-hashed using the Flask secret key before
  storage. The admin Security Center displays aggregate blocked counts, not
  those identifiers.
- Security response headers include CSP, `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy`. HSTS is added
  only when Flask considers the request HTTPS.
- Forwarded client-IP headers are ignored by default. `TRUSTED_PROXY_HOPS`
  enables Werkzeug `ProxyFix` only when the app is isolated behind the exact
  number of trusted proxies configured.
- Existing application controls also include CSRF checks for browser POSTs,
  persistent device-session revocation checks, role checks, path containment
  for user storage, upload-size/quota checks, and parameterized SQLite queries.
- Uploads are staged outside each user's visible folder and scanned through
  the ClamAV daemon when available; confirmed detections are isolated in a
  private quarantine area. ClamAV being unavailable does not block ordinary
  uploads by default, but is logged as an elevated-risk event. Set
  `CLAMD_REQUIRED=1` to reject uploads whenever ClamAV is unavailable. This
  default preserves file-transfer availability; deployments should operate
  ClamAV and enable the required mode if unscanned uploads are unacceptable.
- The owner-only Emergency Control Centre persists supported controls in the
  existing policy table. Server-side guards enforce upload/download, deletion,
  editing, registration, API access, mandatory 2FA, forced password changes,
  session revocation, and emergency rate-limit policies. Full Lockdown requires
  the exact confirmation phrase `CONFIRM LOCKDOWN`; browser POST actions also
  require the existing CSRF token.
- The emergency account-freeze workflow can suspend one non-admin account or
  eligible active non-admin members of a group. It records each prior status;
  it also revokes their active device sessions. Restoration only reactivates
  accounts that were active before the freeze; revoked sessions stay revoked
  and users must sign in again. Ordinary account administration cannot
  reactivate an account while its emergency freeze record is active.
- Emergency incidents, notes, and event records use additive SQLite tables.
  Events record the administrator, source IP, action, prior/new control state,
  reason, affected user IDs/count, affected services, result, timestamp, and
  incident reference. Emergency event history supports date, administrator,
  action, severity, incident, affected-user-ID, and IP filters. The owner-only
  Cloud Intelligence Center exposes aggregate analytics endpoints.
- Automatic alerts are generated for repeated failed logins, request buckets
  with at least five blocked requests, more than 20 successful uploads or 40
  downloads per account in five minutes, more than 30 audited file changes
  per account in five minutes, and 10 or more account creations from one IP
  within ten minutes. Duplicate open alerts for the same identity and alert
  type are suppressed for 15 minutes.
- Optional Google sign-in uses OpenID Connect with Authlib, validates the
  provider's verified-email claim, and keeps the stable Google subject in a
  unique database column. New Google accounts are ordinary non-admin accounts;
  registration settings, account status, policy consent, login auditing,
  device sessions, rate limits, and administrator two-factor verification
  continue to apply. A unique verified email can link to one existing account;
  ambiguous or already-linked identities are rejected.
- Optional GitHub sign-in uses OAuth with the minimum `read:user user:email`
  scopes. It requires a verified primary email from GitHub's email API, stores
  GitHub's stable account ID in a unique database column, and applies the same
  account creation/linking safeguards and session protections as Google sign-in.
  Provider credentials can be configured through the owner-only Website
  settings or server environment; the client secret is encrypted at rest and
  never shown in the admin panel.
- The administrator account list shows linked sign-in methods and provider-
  supplied profile names, verified provider email addresses, and approved
  provider-hosted profile images. Administrators with user-view permission can
  filter accounts by sign-in method and download an activity/account-type CSV
  report containing account creation, last-login, and last-activity timestamps.
  Last login is updated only after successful authentication (including any
  required two-factor challenge); last activity is updated as the user accesses
  the site. OAuth does not
  disclose a user's Google or GitHub password to Cloud Rdx; the app neither
  requests nor stores provider passwords. OAuth-only accounts cannot use
  password sign-in unless an administrator or account recovery flow explicitly
  sets a Cloud Rdx password.
- Users can review and update their own name, phone, date of birth, and optional
  gender/location from their profile. Phone and date of birth are optional
  profile fields, but the current recovery-verification flow requires matching
  phone and date of birth. Profile updates are CSRF-protected and audited
  without recording the field values. The profile also shows provider-linked
  account metadata, account creation/last-login/last-activity timestamps, and whether
  two-factor authentication is enabled. Cloud Rdx does not collect security
  question answers or OAuth provider passwords.
  Google/GitHub profile locations are used only when returned by the provider
  and the user has not already supplied a location. These profile fields are
  stored in the application database; protect the database file and its
  backups with operating-system access controls and encrypted storage.

## Database migration

On startup, the app uses additive schema changes to add the
`rate_limit_buckets` table and index, nullable provider identity/profile/login timestamp columns, optional gender/location profile
fields, the `password_login_enabled` flag, and unique partial indexes for linked Google
and GitHub identities, emergency incident/note/event tables and indexes, plus
the emergency policy keys and emergency account-freeze table/index. Existing
accounts and records are not rewritten or deleted. The limiter stores endpoint/scope,
window/count metadata, and keyed hashes; old counter rows are pruned after a
day. Back up the SQLite database before deploying any application update.

## Environment and deployment requirements

- Set `FLASK_SECRET_KEY` to a long, cryptographically random, persistent secret.
  Do not use the generated development fallback in a multi-worker or production
  deployment; changing the key also changes rate-limit hashes and invalidates
  Flask sessions and makes admin-stored OAuth credentials undecryptable.
- Set `SESSION_COOKIE_SECURE=1` when HTTPS is in place. The current `.env`
  example keeps it disabled for local development.
- To enable Google sign-in, create an OAuth 2.0 Web application client in
  Google Cloud Console, configure the consent screen, then set
  `GOOGLE_OAUTH_CLIENT_ID` and `GOOGLE_OAUTH_CLIENT_SECRET` from a secret
  manager or a private `.env` file beside `app.py` (or beside
  `CloudRdxComplete.exe` for the desktop build). Add the exact redirect URI
  `${APP_BASE_URL}/auth/google/callback` to the client. Use the public HTTPS
  application URL for `APP_BASE_URL` in production; localhost HTTP is suitable
  only for local development. The Google buttons remain visible when OAuth is
  unconfigured and the login page displays a setup notice.
- To enable GitHub sign-in, create a GitHub OAuth App, set
  `GITHUB_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_SECRET` in the server secret
  manager or private `.env` file, or enter both values in owner-only Website
  settings. Admin-entered values are encrypted with a key derived from the
  persistent `FLASK_SECRET_KEY`; blank fields preserve existing credentials,
  and the clear option removes only admin-managed values. Environment values
  remain the fallback. Register
  `${APP_BASE_URL}/auth/github/callback` as its callback URL. Use the public
  HTTPS URL in production. The owner can independently disable GitHub sign-in
  from Website settings without deleting linked accounts.
- Google credentials can also be entered or cleared in owner-only Website
  settings. Configure the exact Google callback URI above. Do not enter user
  access tokens; these fields are for OAuth app client credentials.
- Keep `TRUSTED_PROXY_HOPS=0` unless direct access to the app is blocked and the
  only ingress is through the specified trusted proxy chain. Configure the
  proxy to overwrite forwarded headers rather than append attacker-provided
  values.
- Keep debug mode disabled. Terminate TLS at a correctly configured proxy or
  web server and enable HSTS only after HTTPS is verified end to end.
- Use a WAF/CDN, edge request limits, and DDoS protection for public
  deployments. Flask-level limits cannot absorb volumetric attacks.
- SQLite rate limits are shared across processes only when all workers use the
  same local database. For multiple hosts or high availability, use a
  transactional shared limiter such as Redis and retain edge/WAF limits.
- Existing related settings include `LOGIN_WINDOW_MINUTES`,
  `LOGIN_MAX_ATTEMPTS`, `LOGIN_LOCKOUT_MINUTES`, `SESSION_TIMEOUT_MINUTES`,
  `MAX_UPLOAD_MB`, `FILE_SERVER_DATABASE`, and `SHARED_FOLDER`. Keep login
  values positive and choose session/upload limits for the deployment. The
  owner-only Website settings page can adjust login failure thresholds,
  lockout durations, Google sign-in availability, and site registration
  policies; these choices are stored in the application database and audited.
  The login environment values seed new installations and remain available as
  defaults.
- Authlib is required for Google OpenID Connect. Install the pinned project
  dependencies from `requirements.txt`.

### Production deployment checklist

- [ ] Serve only through HTTPS; set `SESSION_COOKIE_SECURE=1`.
- [ ] Configure a persistent secret in a secret manager and set
  `FLASK_SECRET_KEY` before starting the service.
- [ ] If Google sign-in is enabled, keep its client secret in a secret manager
  and allow only the exact production HTTPS callback URI in Google Cloud.
- [ ] Keep Flask debug mode disabled and restrict direct access to the app
  server.
- [ ] Set `TRUSTED_PROXY_HOPS` only for a verified, private proxy chain.
- [ ] Back up the database before deploying the additive schema update.
- [ ] Configure WAF/CDN, edge limits, network controls, log retention, and
  protected backups.
- [ ] Complete the recovery-flow redesign and verify session revocation,
  authorization, upload, and restore behavior for the deployed configuration.
- [ ] Run the local security tests and a deployment-appropriate security
  assessment.

## Security testing

The focused tests use a temporary SQLite database and only harmless local test
requests. Run them from the project root with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The tests cover account/IP login ceilings, HTTP 429 and retry behavior, privacy
of stored rate-limit keys, default handling of forwarded IP headers, security
headers, Google OAuth redirects, account creation, verified-email linking,
owner-only emergency access, full-lockdown confirmation/auditing, emergency API
blocking, registration freeze, selective incident rollback, and storage
read-only semantics, group account freeze/restoration, and automatic
login/request/file/account-creation alert creation.

## Incident response

1. Restrict ingress at the WAF/reverse proxy and preserve relevant access and
   application logs.
2. Review the admin Security Center and audit events; do not export credentials
   or session tokens.
3. Disable compromised users and revoke their device sessions.
4. Rotate `FLASK_SECRET_KEY` and payment/provider credentials if compromised;
   rotating the Flask key invalidates active signed sessions.
5. Restore affected data from separately protected backups and validate the
   restore before returning service to users.

## Known limitations and remaining recommendations

- The recovery flow currently has no email-delivery-backed, single-use reset
  token workflow. It relies on account recovery details and requires a separate
  security redesign before public deployment.
- CSP allows inline scripts and styles to preserve existing templates. Move
  inline code to static files or use per-response nonces before tightening it.
- `SESSION_COOKIE_SECURE` is opt-in for local development; production must set
  it to `1` and serve only HTTPS.
- This change does not add antivirus scanning, encrypted backups, a WAF/CDN,
  SIEM forwarding, or network segmentation; configure these at the appropriate
  infrastructure layer.
- Emergency controls for share-link revocation, sync/automation, public file
  access, trusted-device admission, malware quarantine, and backup immutability
  are shown as unsupported because the corresponding application subsystems do
  not exist. They are not enforced by setting their policy flags. Emergency
  analytics are based on the application's SQLite records and local storage
  scan; they do not provide host CPU/RAM telemetry, forecasts, or 3D/WebGL
  visualizations. Automatic alert coverage uses available login, rate-limit,
  and successful file-operation records. Sharing anomalies and external
  network/host telemetry are unavailable, so no alert is generated for those
  signals.
- Review initial administrator provisioning: the existing first-run behavior
  can print a generated initial password to the server console. Supply a
  strong `ADMIN_PASSWORD` through a secret manager before first startup and
  restrict console/log access.
- Review password changes, reset, MFA-secret encryption, every admin/API
  authorization path, and database backup handling before production. The
  focused tests in this update are not a substitute for a complete security
  test suite or penetration test.

## Audit summary for this change

| Severity | Finding |
|---|---|
| Critical | No critical issue was confirmed within the rate-limiting change. |
| High | The existing recovery flow does not use emailed, single-use reset tokens; it needs redesign before public deployment. |
| High | The Flask secret fallback is process-random and session cookies are not secure by default; production configuration is required. |
| Medium | Existing inline scripts/styles require CSP `unsafe-inline`, reducing CSP's XSS protection. |
| Medium | SQLite limits are not suitable for multi-host deployments and do not replace WAF/CDN DDoS controls. |
| Low | Rate limits are fixed defaults in application code; tune after observing legitimate production traffic. |
# Cloud Rdx security

This document describes security controls present in the Flask application and
deployment responsibilities. It is not a certification that the service is
secure against every threat.

## Security architecture and controls

- The application uses Argon2 password hashes and verifies current account
  status during authentication.
- Login failures are recorded in SQLite and checked per account and source IP.
  After the configured threshold, the account/source pair is temporarily
  cooled down.
- Persistent request limits are enforced per IP, account, session, endpoint
  group, and method-specific operation. Current defaults are:
  - Login: 20 per account and 20 per IP per 15 minutes. The existing
    failed-password cooldown applies after 5 consecutive failures for an
    account/source-IP pair, then doubles for each additional group of 5 failures
    (capped at 8 times the configured base). A successful login resets that
    failure streak.
  - Google OAuth start and callback: 20 per IP per 15 minutes.
  - Authenticator verification: 5 per pending account/session per 5 minutes.
  - Registration: 3 per account and 15 per IP per hour.
  - Password recovery: 3 per account and 10 per IP per hour.
  - Uploads: 30 per session and 100 per IP per hour.
  - Downloads: 300 per session and 600 per IP per 15 minutes; bulk downloads
    are limited to 10 per session and 40 per IP per 15 minutes.
  - API requests: 120 per IP and 240 per session per 5 minutes.
  - Admin endpoints: 180 per IP and 300 per session per 5 minutes.
  - Other traffic: 600 per IP and 900 per session per 5 minutes.
- A rejected request receives HTTP 429 and a `Retry-After` header. JSON clients
  receive a generic JSON error; browser clients receive a generic page.
- Rate-limit identifiers are HMAC-hashed using the Flask secret key before
  storage. The admin Security Center displays aggregate blocked counts, not
  those identifiers.
- Security response headers include CSP, `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy`. HSTS is added
  only when Flask considers the request HTTPS.
- Forwarded client-IP headers are ignored by default. `TRUSTED_PROXY_HOPS`
  enables Werkzeug `ProxyFix` only when the app is isolated behind the exact
  number of trusted proxies configured.
- Existing application controls also include CSRF checks for browser POSTs,
  persistent device-session revocation checks, role checks, path containment
  for user storage, upload-size/quota checks, and parameterized SQLite queries.
- Uploads are staged outside each user's visible folder and scanned through
  the ClamAV daemon when available; confirmed detections are isolated in a
  private quarantine area. ClamAV being unavailable does not block ordinary
  uploads by default, but is logged as an elevated-risk event. Set
  `CLAMD_REQUIRED=1` to reject uploads whenever ClamAV is unavailable. This
  default preserves file-transfer availability; deployments should operate
  ClamAV and enable the required mode if unscanned uploads are unacceptable.
- The owner-only Emergency Control Centre persists supported controls in the
  existing policy table. Server-side guards enforce upload/download, deletion,
  editing, registration, API access, mandatory 2FA, forced password changes,
  session revocation, and emergency rate-limit policies. Full Lockdown requires
  the exact confirmation phrase `CONFIRM LOCKDOWN`; browser POST actions also
  require the existing CSRF token.
- The emergency account-freeze workflow can suspend one non-admin account or
  eligible active non-admin members of a group. It records each prior status;
  it also revokes their active device sessions. Restoration only reactivates
  accounts that were active before the freeze; revoked sessions stay revoked
  and users must sign in again. Ordinary account administration cannot
  reactivate an account while its emergency freeze record is active.
- Emergency incidents, notes, and event records use additive SQLite tables.
  Events record the administrator, source IP, action, prior/new control state,
  reason, affected user IDs/count, affected services, result, timestamp, and
  incident reference. Emergency event history supports date, administrator,
  action, severity, incident, affected-user-ID, and IP filters. The owner-only
  Cloud Intelligence Center exposes aggregate analytics endpoints.
- Automatic alerts are generated for repeated failed logins, request buckets
  with at least five blocked requests, more than 20 successful uploads or 40
  downloads per account in five minutes, more than 30 audited file changes
  per account in five minutes, and 10 or more account creations from one IP
  within ten minutes. Duplicate open alerts for the same identity and alert
  type are suppressed for 15 minutes.
- Optional Google sign-in uses OpenID Connect with Authlib, validates the
  provider's verified-email claim, and keeps the stable Google subject in a
  unique database column. New Google accounts are ordinary non-admin accounts;
  registration settings, account status, policy consent, login auditing,
  device sessions, rate limits, and administrator two-factor verification
  continue to apply. A unique verified email can link to one existing account;
  ambiguous or already-linked identities are rejected.
- Optional GitHub sign-in uses OAuth with the minimum `read:user user:email`
  scopes. It requires a verified primary email from GitHub's email API, stores
  GitHub's stable account ID in a unique database column, and applies the same
  account creation/linking safeguards and session protections as Google sign-in.
  Provider credentials can be configured through the owner-only Website
  settings or server environment; the client secret is encrypted at rest and
  never shown in the admin panel.
- The administrator account list shows linked sign-in methods and provider-
  supplied profile names, verified provider email addresses, and approved
  provider-hosted profile images. Administrators with user-view permission can
  filter accounts by sign-in method and download an activity/account-type CSV
  report containing account creation, last-login, and last-activity timestamps.
  Last login is updated only after successful authentication (including any
  required two-factor challenge); last activity is updated as the user accesses
  the site. OAuth does not
  disclose a user's Google or GitHub password to Cloud Rdx; the app neither
  requests nor stores provider passwords. OAuth-only accounts cannot use
  password sign-in unless an administrator or account recovery flow explicitly
  sets a Cloud Rdx password.
- Users can review and update their own name, phone, date of birth, and optional
  gender/location from their profile. Phone and date of birth are optional
  profile fields, but the current recovery-verification flow requires matching
  phone and date of birth. Profile updates are CSRF-protected and audited
  without recording the field values. The profile also shows provider-linked
  account metadata, account creation/last-login/last-activity timestamps, and whether
  two-factor authentication is enabled. Cloud Rdx does not collect security
  question answers or OAuth provider passwords.
  Google/GitHub profile locations are used only when returned by the provider
  and the user has not already supplied a location. These profile fields are
  stored in the application database; protect the database file and its
  backups with operating-system access controls and encrypted storage.

## Database migration

On startup, the app uses additive schema changes to add the
`rate_limit_buckets` table and index, nullable provider identity/profile/login timestamp columns, optional gender/location profile
fields, the `password_login_enabled` flag, and unique partial indexes for linked Google
and GitHub identities, emergency incident/note/event tables and indexes, plus
the emergency policy keys and emergency account-freeze table/index. Existing
accounts and records are not rewritten or deleted. The limiter stores endpoint/scope,
window/count metadata, and keyed hashes; old counter rows are pruned after a
day. Back up the SQLite database before deploying any application update.

## Environment and deployment requirements

- Set `FLASK_SECRET_KEY` to a long, cryptographically random, persistent secret.
  Do not use the generated development fallback in a multi-worker or production
  deployment; changing the key also changes rate-limit hashes and invalidates
  Flask sessions and makes admin-stored OAuth credentials undecryptable.
- Set `SESSION_COOKIE_SECURE=1` when HTTPS is in place. The current `.env`
  example keeps it disabled for local development.
- To enable Google sign-in, create an OAuth 2.0 Web application client in
  Google Cloud Console, configure the consent screen, then set
  `GOOGLE_OAUTH_CLIENT_ID` and `GOOGLE_OAUTH_CLIENT_SECRET` from a secret
  manager or a private `.env` file beside `app.py` (or beside
  `CloudRdxComplete.exe` for the desktop build). Add the exact redirect URI
  `${APP_BASE_URL}/auth/google/callback` to the client. Use the public HTTPS
  application URL for `APP_BASE_URL` in production; localhost HTTP is suitable
  only for local development. The Google buttons remain visible when OAuth is
  unconfigured and the login page displays a setup notice.
- To enable GitHub sign-in, create a GitHub OAuth App, set
  `GITHUB_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_SECRET` in the server secret
  manager or private `.env` file, or enter both values in owner-only Website
  settings. Admin-entered values are encrypted with a key derived from the
  persistent `FLASK_SECRET_KEY`; blank fields preserve existing credentials,
  and the clear option removes only admin-managed values. Environment values
  remain the fallback. Register
  `${APP_BASE_URL}/auth/github/callback` as its callback URL. Use the public
  HTTPS URL in production. The owner can independently disable GitHub sign-in
  from Website settings without deleting linked accounts.
- Google credentials can also be entered or cleared in owner-only Website
  settings. Configure the exact Google callback URI above. Do not enter user
  access tokens; these fields are for OAuth app client credentials.
- Keep `TRUSTED_PROXY_HOPS=0` unless direct access to the app is blocked and the
  only ingress is through the specified trusted proxy chain. Configure the
  proxy to overwrite forwarded headers rather than append attacker-provided
  values.
- Keep debug mode disabled. Terminate TLS at a correctly configured proxy or
  web server and enable HSTS only after HTTPS is verified end to end.
- Use a WAF/CDN, edge request limits, and DDoS protection for public
  deployments. Flask-level limits cannot absorb volumetric attacks.
- SQLite rate limits are shared across processes only when all workers use the
  same local database. For multiple hosts or high availability, use a
  transactional shared limiter such as Redis and retain edge/WAF limits.
- Existing related settings include `LOGIN_WINDOW_MINUTES`,
  `LOGIN_MAX_ATTEMPTS`, `LOGIN_LOCKOUT_MINUTES`, `SESSION_TIMEOUT_MINUTES`,
  `MAX_UPLOAD_MB`, `FILE_SERVER_DATABASE`, and `SHARED_FOLDER`. Keep login
  values positive and choose session/upload limits for the deployment. The
  owner-only Website settings page can adjust login failure thresholds,
  lockout durations, Google sign-in availability, and site registration
  policies; these choices are stored in the application database and audited.
  The login environment values seed new installations and remain available as
  defaults.
- Authlib is required for Google OpenID Connect. Install the pinned project
  dependencies from `requirements.txt`.

### Production deployment checklist

- [ ] Serve only through HTTPS; set `SESSION_COOKIE_SECURE=1`.
- [ ] Configure a persistent secret in a secret manager and set
  `FLASK_SECRET_KEY` before starting the service.
- [ ] If Google sign-in is enabled, keep its client secret in a secret manager
  and allow only the exact production HTTPS callback URI in Google Cloud.
- [ ] Keep Flask debug mode disabled and restrict direct access to the app
  server.
- [ ] Set `TRUSTED_PROXY_HOPS` only for a verified, private proxy chain.
- [ ] Back up the database before deploying the additive schema update.
- [ ] Configure WAF/CDN, edge limits, network controls, log retention, and
  protected backups.
- [ ] Complete the recovery-flow redesign and verify session revocation,
  authorization, upload, and restore behavior for the deployed configuration.
- [ ] Run the local security tests and a deployment-appropriate security
  assessment.

## Security testing

The focused tests use a temporary SQLite database and only harmless local test
requests. Run them from the project root with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The tests cover account/IP login ceilings, HTTP 429 and retry behavior, privacy
of stored rate-limit keys, default handling of forwarded IP headers, security
headers, Google OAuth redirects, account creation, verified-email linking,
owner-only emergency access, full-lockdown confirmation/auditing, emergency API
blocking, registration freeze, selective incident rollback, and storage
read-only semantics, group account freeze/restoration, and automatic
login/request/file/account-creation alert creation.

## Incident response

1. Restrict ingress at the WAF/reverse proxy and preserve relevant access and
   application logs.
2. Review the admin Security Center and audit events; do not export credentials
   or session tokens.
3. Disable compromised users and revoke their device sessions.
4. Rotate `FLASK_SECRET_KEY` and payment/provider credentials if compromised;
   rotating the Flask key invalidates active signed sessions.
5. Restore affected data from separately protected backups and validate the
   restore before returning service to users.

## Known limitations and remaining recommendations

- The recovery flow currently has no email-delivery-backed, single-use reset
  token workflow. It relies on account recovery details and requires a separate
  security redesign before public deployment.
- CSP allows inline scripts and styles to preserve existing templates. Move
  inline code to static files or use per-response nonces before tightening it.
- `SESSION_COOKIE_SECURE` is opt-in for local development; production must set
  it to `1` and serve only HTTPS.
- This change does not add antivirus scanning, encrypted backups, a WAF/CDN,
  SIEM forwarding, or network segmentation; configure these at the appropriate
  infrastructure layer.
- Emergency controls for share-link revocation, sync/automation, public file
  access, trusted-device admission, malware quarantine, and backup immutability
  are shown as unsupported because the corresponding application subsystems do
  not exist. They are not enforced by setting their policy flags. Emergency
  analytics are based on the application's SQLite records and local storage
  scan; they do not provide host CPU/RAM telemetry, forecasts, or 3D/WebGL
  visualizations. Automatic alert coverage uses available login, rate-limit,
  and successful file-operation records. Sharing anomalies and external
  network/host telemetry are unavailable, so no alert is generated for those
  signals.
- Review initial administrator provisioning: the existing first-run behavior
  can print a generated initial password to the server console. Supply a
  strong `ADMIN_PASSWORD` through a secret manager before first startup and
  restrict console/log access.
- Review password changes, reset, MFA-secret encryption, every admin/API
  authorization path, and database backup handling before production. The
  focused tests in this update are not a substitute for a complete security
  test suite or penetration test.

## Audit summary for this change

| Severity | Finding |
|---|---|
| Critical | No critical issue was confirmed within the rate-limiting change. |
| High | The existing recovery flow does not use emailed, single-use reset tokens; it needs redesign before public deployment. |
| High | The Flask secret fallback is process-random and session cookies are not secure by default; production configuration is required. |
| Medium | Existing inline scripts/styles require CSP `unsafe-inline`, reducing CSP's XSS protection. |
| Medium | SQLite limits are not suitable for multi-host deployments and do not replace WAF/CDN DDoS controls. |
| Low | Rate limits are fixed defaults in application code; tune after observing legitimate production traffic. |
