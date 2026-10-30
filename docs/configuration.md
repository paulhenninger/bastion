# Configuration

Everything is set by environment variable (or `.env` with Docker Compose).
Defaults are chosen to be safe; the only values you **must** set are the two
secrets.

## Required

| Variable | Description |
|---|---|
| `JWT_SECRET` | Base64, ≥ 256 bits. Signs access tokens. `openssl rand -base64 32`. The app refuses to start without it. Rotating it is harmless: clients silently refresh. |
| `DATA_ENCRYPTION_KEY` | Base64, exactly 256 bits. AES-GCM key for TOTP secrets at rest. `openssl rand -base64 32` — a **different** value from `JWT_SECRET`. **Back it up separately from the database.** |
| `APP_BASE_URL` | How users open the app, e.g. `https://app.example.com`. Emailed links, the passkey origin/RP ID and the cookie `Secure` flag all derive from it. |

## Application

| Variable | Default | Description |
|---|---|---|
| `APP_NAME` | `Bastion` | Shown in emails, the authenticator-app entry and passkey prompts. |
| `BOOTSTRAP_ADMIN_EMAIL` | — | First administrator: promoted once this address signs up and verifies, only while no admin exists. |
| `SPRING_PROFILES_ACTIVE` | — | `prod` switches logs to structured JSON (ECS). |
| `LOG_FORMAT` | `ecs` (prod) | Structured log format under `prod`: `ecs`, `logstash` or `gelf`. |
| `SERVER_PORT` | `8080` | API port. |
| `MANAGEMENT_PORT` | `9091` | Health and Prometheus. **Never expose publicly.** |

## Sessions

| Variable | Default | Description |
|---|---|---|
| `ACCESS_TOKEN_MINUTES` | `15` | Access-token lifetime. Short on purpose. |
| `SESSION_IDLE_DAYS` | `14` | A session that doesn't refresh for this long ends. |
| `SESSION_MAX_DAYS` | `30` | A session ends this long after sign-in, however active. |
| `REAUTH_MINUTES` | `10` | How long a re-authentication unlocks sensitive actions. |
| `NEW_SIGN_IN_ALERTS` | `true` | Email the owner on sign-in from an unrecognised device/network. |

## Security

| Variable | Default | Description |
|---|---|---|
| `TRUST_FORWARDED_FOR` | `false` | Use the first `X-Forwarded-For` hop as the client IP. Enable **only** behind a proxy that *resets* the header (the bundled nginx does). Otherwise clients can spoof their rate-limit key. |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated origins allowed to call the API with credentials. In production the SPA is same-origin and this can stay narrow. |
| `ADMIN_REQUIRES_MFA` | `true` | Admin API requires a session signed in with two factors. |
| `AUDIT_RETENTION_DAYS` | `180` | Security events older than this are purged (they contain IPs and emails). |
| `MAX_REQUEST_BYTES` | `65536` | Largest request body the API will read. |

## Passwords

| Variable | Default | Description |
|---|---|---|
| `PASSWORD_MIN_LENGTH` | `12` | NIST SP 800-63B-4 asks for 15 where the password is the only factor; raise it if most users won't enable MFA. |
| `PASSWORD_MAX_LENGTH` | `128` | Upper bound keeps hashing cost predictable. |
| `PASSWORD_BREACH_CHECK` | `true` | Refuse passwords found in Have I Been Pwned (k-anonymity; fails open). |

## Signup

| Variable | Default | Description |
|---|---|---|
| `SIGNUPS_OPEN` | `true` | Initial state of the admin "new accounts" switch. |
| `SIGNUP_BLOCK_DISPOSABLE` | `true` | Refuse known throwaway-mail domains. |
| `SIGNUP_CHECK_MX` | `true` | Refuse domains with no mail exchanger (fails open on DNS errors). Set `false` in dev — `example.com` has none. |
| `PURGE_UNVERIFIED_DAYS` | `7` | Unverified accounts older than this are deleted nightly. |
| `VERIFICATION_TOKEN_HOURS` | `24` | Verification link lifetime. |
| `RESET_TOKEN_MINUTES` | `30` | Password-reset link lifetime. |
| `EMAIL_CHANGE_TOKEN_HOURS` | `24` | Email-change confirmation lifetime. |
| `TURNSTILE_SITE_KEY` / `TURNSTILE_SECRET_KEY` | — | Cloudflare Turnstile CAPTCHA on signup, forgot-password and resend-verification. Both or neither. |

## Passkeys

| Variable | Default | Description |
|---|---|---|
| `PASSKEY_RP_ID` | host of `APP_BASE_URL` | WebAuthn relying-party id. Set to the registrable parent (e.g. `example.com`) to share passkeys across subdomains. **Changing it later invalidates every registered passkey.** |
| `PASSKEY_EXTRA_ORIGINS` | — | Additional allowed origins, comma-separated. |

## Database

| Variable | Default | Description |
|---|---|---|
| `DB_HOST` / `DB_PORT` / `DB_NAME` | `localhost` / `3306` / `bastion` | MySQL 9.7 LTS (8.4 LTS also works). |
| `DB_USER` / `DB_PASS` | `bastion` / `bastion` | Use a dedicated user with rights on this schema only. |
| `DB_PARAMS` | — | Appended to the JDBC URL. Production: `&sslMode=VERIFY_IDENTITY`. |
| `DB_POOL_SIZE` | `20` | Hikari pool size. |

## Mail

| Variable | Default | Description |
|---|---|---|
| `MAIL_HOST` / `MAIL_PORT` | `localhost` / `1025` | SMTP relay (dev default: Mailpit). |
| `MAIL_USER` / `MAIL_PASS` | — | Relay credentials. |
| `MAIL_SMTP_AUTH` / `MAIL_STARTTLS` | `false` | Set both `true` for any real relay; STARTTLS is then *required*, not opportunistic. |
| `MAIL_FROM` | `Bastion <no-reply@bastion.local>` | A sender your relay is authorised for (SPF/DKIM/DMARC). |
| `MAIL_*_TIMEOUT_MS` | `10000` | Connect/read/write timeouts. |

## Executors

| Variable | Default | Description |
|---|---|---|
| `ASYNC_POOL_SIZE` | `4` | Threads for mail and audit writes. |
| `ASYNC_QUEUE_CAPACITY` | `1000` | Bounded queue; a flood can't grow it without limit. |
| `SCHEDULER_POOL_SIZE` | `4` | Scheduled purges. |
