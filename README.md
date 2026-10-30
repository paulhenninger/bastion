# ⬢ Bastion

**Production-grade authentication for Spring Boot 4 + React — the security
plumbing every SaaS needs, done carefully, documented honestly and tested
end to end, so you can start on the product.**

Bastion is an MIT-licensed starter kit: a Spring Boot 4.1 (Java 25) backend and
a React 19 + Vite + TypeScript SPA implementing account creation, sign-in,
two-factor authentication, passkeys, password recovery, session management,
administration, audit logging and monitoring.

> **On "unhackable":** nothing is. What Bastion offers instead is defence in
> depth, safe defaults, and a [security model](docs/security-model.md) that lists
> every threat it addresses, the control, the test that proves it — and the
> risks that remain yours. Found a hole? See [SECURITY.md](SECURITY.md).

## Features

**Sign-in**
- Email + password, with **TOTP two-factor** (any authenticator app) and
  single-use **recovery codes**
- **Passkeys** (WebAuthn): phishing-resistant, passwordless, biometric/PIN required
- Passwords hashed with **Argon2id**; legacy BCrypt hashes upgraded transparently
- New passwords checked against **Have I Been Pwned** (k-anonymity — the password
  never leaves the server); sign-ins with a breached password prompt a change
- Throttling per IP *and* per account, race-free; soft lockout, with **device
  cookies** so an attacker spending an account's budget can't lock its owner out

**Account lifecycle**
- Signup with email verification that **defeats account pre-hijacking**
- Strict address validation, disposable-domain and MX checks, optional
  Cloudflare Turnstile CAPTCHA
- Password reset that never bypasses 2FA and ends every session
- Verified email change (confirmed by the new inbox, old inbox notified)
- Self-service account deletion and **data export** (GDPR Art. 15/20)
- **Enumeration-safe** everywhere: same reply and same timing whether or not
  an account exists

**Sessions**
- 15-minute access tokens held **in memory only**; rotating refresh tokens in an
  `HttpOnly`, `SameSite=Strict`, path-scoped cookie
- **Theft detection**: a replayed refresh token revokes every session
- **Immediate revocation**: sign-out, lock, password reset and demotion take
  effect on the very next request
- Idle *and* absolute session lifetimes
- "Where you're signed in" list with per-device sign-out
- **Sudo mode**: sensitive changes require re-authentication (password + code,
  or a passkey) within the last 10 minutes
- Email alerts for new-device sign-ins and every credential change

**Administration**
- User search, detail view, role changes, lock/unlock, sign-out-everywhere,
  2FA reset, deletion
- Admin area **requires a two-factor session**; every mutation requires sudo
- No default credentials: the first admin is bootstrapped from a verified email
- Runtime switch to close new signups

**Logging & monitoring**
- Security event log for every sign-in, failure and credential change — viewable
  by admins (searchable) and by each user for their own account
- Structured JSON logs (ECS) with request ids; a dedicated `bastion.audit`
  logger for your SIEM
- Prometheus metrics and health probes on a private management port, with
  [suggested alerts](docs/operations.md#metrics-and-alerts)

**Hardening**
- Strict CSP (no inline script), HSTS, `X-Frame-Options`, COOP/CORP,
  `Permissions-Policy`, `no-referrer`
- Request body cap, uniform JSON errors (no stack traces, no 500s for bad input)
- TOTP secrets encrypted at rest (AES-256-GCM); every token stored hashed
- Refuses to start a real deployment on development settings (http, published
  database passwords, a shared key)

**Containers & supply chain**
- Every container non-root, **read-only**, all capabilities dropped,
  `no-new-privileges`, memory/PID-capped; segmented networks (the web container
  can't reach the database, only the app reaches the internet)
- MySQL with TLS required and **two logins**: the app can only read and write
  rows; migrations run as a separate owner; root can't sign in over the network
- Base images and GitHub Actions pinned by digest/SHA; Trivy (images + npm),
  gitleaks, and a CI smoke test that proves all of the above on the running stack

**Quality**
- 80 backend tests: full flows through MockMvc, real WebAuthn ceremonies against
  an emulated authenticator, RFC 6238 test vectors, and the real Flyway migrations
  on real MySQL (Testcontainers)
- CI: tests, SpotBugs + find-sec-bugs, CodeQL, dependency review, `npm audit`,
  Trivy, gitleaks, a hardened-stack smoke test,
  Dependabot

## Quickstart

Prerequisites: Docker, a JDK is *not* needed (Gradle downloads Java 25), Node 26 LTS.

```bash
# 1. Secrets
cp .env.example .env
# Fill JWT_SECRET and DATA_ENCRYPTION_KEY — two different values from:
openssl rand -base64 32

# 2a. Everything in containers  →  http://localhost:8081
#     (set APP_BASE_URL and CORS_ORIGINS to http://localhost:8081 in .env)
docker compose --profile full up -d --build

# 2b. …or databases in containers, app with hot reload  →  http://localhost:5173
docker compose up -d                      # MySQL + Mailpit
set -a; . ./.env; set +a; ./gradlew bootRun
cd frontend && npm install && npm run dev
```

Sign up as `admin@example.com` (the `BOOTSTRAP_ADMIN_EMAIL` in `.env.example`),
open **Mailpit at http://localhost:8025**, click the link, and enter your
password: you're signed in as the administrator. The admin area asks you to add
two-factor authentication or a passkey first — that's on purpose.

## Documentation

| Document | What's in it |
|---|---|
| [docs/security-model.md](docs/security-model.md) | Threats, controls, the tests that prove them, residual risks |
| [docs/configuration.md](docs/configuration.md) | Every environment variable |
| [docs/api.md](docs/api.md) | Every endpoint, error codes, rate limits |
| [docs/operations.md](docs/operations.md) | Production checklist, monitoring & alerts, logging, key rotation, incident response, scaling |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Building, testing, conventions |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Project layout

```
src/main/java/dev/bastion/
  auth/         signup, verification, sign-in, recovery, email change, account service
  session/      sessions, refresh-token rotation, sudo-mode re-authentication
  mfa/          TOTP (RFC 6238), recovery codes, sign-in challenges
  passkey/      WebAuthn registration, sign-in, re-authentication (webauthn4j)
  user/         the signed-in user's endpoints
  admin/        user management, settings, first-admin bootstrap, admin-MFA gate
  audit/        security event log (DB + bastion.audit logger + metrics)
  email/        messages, async delivery, per-recipient cap, address checks
  security/     JWT, filters, rate limits, attempt budgets, encryption, password policy
  config/       Spring Security, typed AppProperties
  maintenance/  nightly purges
src/main/resources/db/migration/   Flyway (MySQL)
frontend/src/
  api/          fetch client (silent refresh, sudo retry), auth calls, WebAuthn helpers
  auth/         AuthContext, re-authentication dialog
  pages/        sign-in, signup, verify, recovery, account & security, admin
frontend/nginx/ production nginx config and security headers
```

## Make it yours

1. **Rename**: search-and-replace `dev.bastion` / `bastion` / `Bastion`, set
   `APP_NAME`, rename the cookie (`AuthController.REFRESH_COOKIE`), retitle
   `index.html`, swap the CSS tokens at the top of `frontend/src/styles.css`.
2. **Build your product** in `DashboardPage` and new backend packages beside
   `auth/`. New endpoints are authenticated by default; take the caller with
   `@AuthenticationPrincipal AuthPrincipal me`, and call `reauth.require(me)`
   before anything a session thief would want to do.
3. **Ship it**: follow the [production checklist](docs/operations.md#production-checklist).

## License

MIT — see [LICENSE](LICENSE). Use it for anything, commercial or not; keep the
copyright notice. No warranty: you are responsible for reviewing security
software before you rely on it.
