# Changelog

## Unreleased

- **A deployment refuses to run as a powerful database login**
  (`DatabaseLoginCheck`). Once `APP_BASE_URL` names a real host, the app asks
  MySQL what `DB_USER` may do and refuses to start if it holds a global
  privilege, anything beyond SELECT/INSERT/UPDATE/DELETE on its database, the
  right to grant, or an active role. CI already proved this for the Compose
  stack; now a hand-configured deployment can't run as the owner or root.
  **Upgrading:** a deployment on one login must apply `db/roles.sql` and set
  `DB_USER=bastion_app` and `SPRING_FLYWAY_USER=bastion_owner` first.
- **Dependabot now covers the Java dependencies.** GitHub cannot parse a
  Gradle build, so the dependency graph held only npm packages and no backend
  advisory could ever raise an alert. `dependency-submission.yml` submits the
  resolved runtime classpath from `main` (and weekly).
- **Java 25.0.5** (Temurin, the October 2026 security update) in both stages
  of the backend image (was 25.0.4.1).

## 2.1.0 — 2026-10-30

### Runtime versions (all on current long-term-support lines)

- **MySQL 9.7 LTS** (was 8.4) in Compose and in the real-database migration
  test. An existing 8.4 data volume upgrades in place on first start (LTS → next
  LTS is a supported path); it cannot be downgraded afterwards, so back it up
  first.
- **Node 26 LTS** for the SPA build in CI as well as the image (CI was on 24).
- Spring Boot 4.1.2, Gradle 9.8.2 (wrapper now verifies the distribution's
  SHA-256), React 19.3.1, React Router 7.18.5, Vite 8.3.5. Java stays on 25 LTS.
- CI fails if `build.gradle`, the Dockerfiles, Compose and the MySQL test
  disagree on a runtime version, and if the real-MySQL test was skipped.
- Every GitHub Action is pinned to a commit SHA; checkouts no longer keep the
  token. Dependabot never proposes a non-LTS Java, Node or MySQL major.

### Container and supply-chain hardening

- **Every container** runs as a non-root user on a read-only root filesystem
  with all Linux capabilities dropped, `no-new-privileges`, memory and PID
  limits and rotated logs. Networks are segmented: the web container can't
  reach the database, and only the app can reach the internet.
- **Two database logins** (`db/roles.sql`, applied by a `db-roles` Compose
  service): the app runs as `bastion_app` (rows only) and migrates as
  `bastion_owner` via `SPRING_FLYWAY_USER`/`SPRING_FLYWAY_PASSWORD`. MySQL
  requires TLS, root signs in only from inside its container, `local_infile`
  and the X protocol are off.
- **The app refuses to start a real deployment on development settings**
  (`DeploymentSafetyCheck`): an `http://` base URL, an empty or published
  database password, or `JWT_SECRET` equal to `DATA_ENCRYPTION_KEY`.
- Images: base images pinned by digest and upgraded at build; Alpine JRE with
  a layered Spring Boot app; health checks in both images; nginx runs without
  its start-up scripts (read-only safe), logs paths without query strings,
  believes `X-Forwarded-For` only from proxies listed in `trusted-proxies.conf`,
  and sends HSTS.
- CI (`security.yml`, also daily): gitleaks over the whole history, Trivy on
  both images and the npm lockfile, then the stack is started and
  `scripts/verify-stack.sh` proves every control above holds.
- Dependabot now proposes base-image updates (they are digest-pinned, so it's
  the only way they move).

### Scaffolding

- `scripts/rename-project.sh <name> <package> "<Display Name>"` renames the
  whole template in one pass (package, classes, cookies, CSRF header, metrics,
  audit logger, database and logins, images, UI) and leaves migrations alone.
- `docs/scaffolding.md`: from an empty folder to a deployed product — rename,
  customize, build features safely, trim, deploy, take upstream fixes.
- `docs/ai-customization-prompt.md`: a prompt for an AI coding assistant that
  interviews you, then does the above and verifies it. `AGENTS.md`/`CLAUDE.md`
  carry the rules into every later session.

### Upgrading from 2.0

- `.env`: set `DB_USER=bastion_app`, `DB_PASS`, `SPRING_FLYWAY_USER=bastion_owner`,
  `SPRING_FLYWAY_PASSWORD` (see `.env.example`). The Compose service is now
  `db` (was `mysql`). For an existing dev volume, `docker compose up` creates
  the two logins; or start fresh with `docker compose down -v`.
- Production: run `db/roles.sql` as an administrator and switch the app to the
  two logins. If `APP_BASE_URL` is a real host, the app now refuses to start on
  the settings listed above — fix them rather than setting
  `ALLOW_DEVELOPMENT_SETTINGS`.
- nginx: `default.conf` is replaced by a full `nginx.conf`. Behind a load
  balancer, mount a `trusted-proxies.conf` listing it.

## 2.0.1 — 2026-10-21

Fixes from a full black-box security and usability verification of 2.0.0
(a live attack suite against the Docker stack and a browser walkthrough).

### Fixed

- **Signing in with a recovery code failed on MySQL** (500): the session's
  `auth_method` column was too short for `PASSWORD_RECOVERY_CODE`. Migration
  `V3` widens it, and a new MySQL test checks every enum against its column.
- **Security events raised in signed-in requests were missing from JSON logs**
  (`prod` profile): the audit logger's `userId` field collided with the MDC's.
  The field is now `subjectUserId` — update SIEM queries that used `userId`.
- **Two tabs refreshing at once signed the user out**: the refused stale token's
  reply cleared the cookie the other tab had just received.
- **An attacker could keep an account's owner from signing in** by spending its
  sign-in budget every 15 minutes. Browsers that have signed in before now carry
  a device cookie and keep a budget of their own.
- Signups refused as invalid (e.g. a breached password) used up the hourly
  signup limit; only accepted signups count now (attempts are capped at 30/hour).
- After a pre-hijacking attempt, the account kept the attacker's display name;
  verification now applies the name from the signup that was proven.
- Admin user search treated `%` and `_` as wildcards.

## 2.0.0 — 2026-10-21

A security-focused major release. **Upgrading signs every user out once** and
requires a new `DATA_ENCRYPTION_KEY` — see
[docs/operations.md](docs/operations.md#upgrading-from-1x).

### Security fixes (1.x was affected)

- **Account pre-hijacking.** Someone who registered a victim's address before
  them could end up with the account once the victim verified. Verification now
  requires the password chosen at signup and applies the one proven.
- **Single-use tokens could be used twice** under concurrent requests;
  **a refresh token could fork into two sessions**. Consumption is now atomic
  (conditional updates, row locks).
- **Access tokens survived logout, password change and lock** for up to 15
  minutes. Every request now checks the session.
- **Tokens in URL query strings** could leak through proxy logs and `Referer`.
  Emailed links now use the URL fragment.
- **Timing differences** on signup and forgot-password revealed which addresses
  had accounts. Work is now equalised or asynchronous.
- **Passwords over 72 bytes** caused a 500 (BCrypt). Now Argon2id.
- **Malformed requests** returned 500, and **unbounded request bodies** could
  exhaust memory. Now 4xx, and a 64 KiB cap.
- **A dev admin password was printed to the log** whenever the `prod` profile
  wasn't set, as was Spring Boot's generated default password. Both are gone.
- **Change-password had no attempt limit**, so a stolen access token could
  brute-force the password. Re-authentication is now budgeted per account.
- The Docker build failed on Windows checkouts (CRLF in `gradlew`).

### Added

- TOTP two-factor authentication with recovery codes; TOTP secrets encrypted
  at rest (AES-256-GCM)
- Passkeys (WebAuthn) for passwordless sign-in and re-authentication
- Sessions list with per-device sign-out; idle and absolute session lifetimes
- Sudo mode (step-up re-authentication) for sensitive changes
- Breached-password check (Have I Been Pwned, k-anonymity)
- Per-account login throttling, per-account code budgets, per-recipient mail cap
- Disposable-domain, TLD and MX checks on new addresses; optional Turnstile CAPTCHA
- Verified email change; account deletion; personal data export
- Security event log (admin viewer + per-user activity) and `bastion.audit` logger
- Security notification emails and new-device sign-in alerts
- Admin: search, user detail, sign-out-everywhere, 2FA reset, signups switch;
  admin API requires a two-factor session; every mutation requires sudo
- First admin via `BOOTSTRAP_ADMIN_EMAIL` (no default credentials)
- Actuator health probes and Prometheus metrics on a private management port
- Structured JSON logging (`prod` profile), `X-Request-Id` correlation
- Strict CSP and full browser security header set; non-root containers
- Test suite grown from 15 to 68 tests, including real WebAuthn ceremonies and
  migrations on real MySQL
- CI: CodeQL, SpotBugs + find-sec-bugs, dependency review, `npm audit`
- Documentation: security model, configuration, API, operations, security policy

### Changed

- Passwords hashed with Argon2id (BCrypt upgraded at next sign-in); minimum length 12
- Refresh cookie is `SameSite=Strict`; refresh and logout require `X-Bastion-Client`
- `POST /auth/verify-email` replaces `GET` and takes `{token, password}`
- Password change keeps the current session and ends the others
- Timestamps are `DATETIME(6)` in UTC (no 2038 limit)
- `REFRESH_TOKEN_DAYS` replaced by `SESSION_IDLE_DAYS` / `SESSION_MAX_DAYS`
- `/profile` is now `/account`

### Removed

- The seeded development admin account

## 1.0.0 — 2026-08-08

Initial release.

- Spring Boot 4.1 (Spring Framework 7) / Java 25 backend; React 19 + Vite 8 +
  TypeScript SPA
- Sessions: 15-min HS256 access tokens (in-memory in the SPA) + rotating
  opaque refresh tokens (HttpOnly cookie, SHA-256 at rest)
- Refresh-token theft detection with a two-tab grace window
- Signup with email verification; password reset via emailed single-use link;
  change password
- Enumeration-safe signup/recovery flows; constant-shape login
- USER/ADMIN roles, paginated admin user management
- Per-IP auth rate limiting; Flyway schema; Mailpit; Docker Compose; CI
