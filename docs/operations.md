# Operations

Running Bastion in production: the checklist, monitoring, logging, keys,
backups and scaling.

## Production checklist

- [ ] **Secrets**: `JWT_SECRET` and `DATA_ENCRYPTION_KEY` are distinct, random
      (`openssl rand -base64 32`) and come from a secrets manager — never from a
      file in the image or the repository.
- [ ] **`DATA_ENCRYPTION_KEY` is backed up separately** from database backups.
- [ ] **HTTPS everywhere.** `APP_BASE_URL` starts with `https://` (this makes the
      refresh cookie `Secure`). HSTS is set at the TLS terminator:
      `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
- [ ] **Reverse proxy resets `X-Forwarded-For`** (`proxy_set_header X-Forwarded-For $remote_addr;`,
      never `$proxy_add_x_forwarded_for` at the outermost proxy) and
      `TRUST_FORWARDED_FOR=true`. If there is a second proxy in front (a CDN or
      load balancer), make the *outermost* one reset it.
- [ ] **Management port (9091) is private** — reachable by Prometheus and the
      orchestrator only, never through the public proxy.
- [ ] **Database**: TLS (`DB_PARAMS=&sslMode=VERIFY_IDENTITY`), encrypted
      backups, and two logins from [`db/roles.sql`](../db/roles.sql): the app
      runs as `bastion_app` (rows only) and migrates as `bastion_owner`
      (`SPRING_FLYWAY_USER`/`SPRING_FLYWAY_PASSWORD`). Never run the app as root.
- [ ] **No development settings.** The app refuses to start when `APP_BASE_URL`
      names a real host but the URL is `http://`, a database password is one of the
      published defaults, or the two keys are equal (`DeploymentSafetyCheck`).
      `ALLOW_DEVELOPMENT_SETTINGS` must be unset.
- [ ] **Containers run as Compose runs them**: read-only root filesystem with a
      `/tmp` tmpfs, `cap_drop: ALL`, `no-new-privileges`, memory and PID limits,
      and the database on a network the web container can't reach. Run
      [`scripts/verify-stack.sh`](../scripts/verify-stack.sh) against your stack.
- [ ] **Trusted proxies**: behind a load balancer, mount a
      `trusted-proxies.conf` naming only its address into the web container
      (see that file), so per-IP limits see real clients.
- [ ] **Mail**: a real relay with `MAIL_SMTP_AUTH=true` and `MAIL_STARTTLS=true`;
      SPF, DKIM and DMARC (`p=reject` once verified) on the sending domain.
- [ ] `SPRING_PROFILES_ACTIVE=prod` (structured JSON logs).
- [ ] `BOOTSTRAP_ADMIN_EMAIL` set to an address you control; after the first
      admin exists it is inert, and you can remove it.
- [ ] First admin enrolls TOTP or a passkey immediately (the admin area requires it).
- [ ] Consider `TURNSTILE_*` if you expect signup abuse, and
      `PASSWORD_MIN_LENGTH=15` if most users won't use MFA.
- [ ] Single instance, or rate limiting moved to a shared store (see *Scaling*).
- [ ] GitHub private vulnerability reporting enabled on your fork, and
      Dependabot alerts on.

## Deployment shape

```
Internet ──TLS──▶ edge proxy / load balancer  (HSTS, resets X-Forwarded-For)
                     │
                     ▼
                 web (nginx, :8080)  ── SPA + security headers + /api proxy
                     │
                     ▼
                 app (Spring Boot, :8080)   ── :9091 management (private)
                     │
                     ▼
                 MySQL 9.7 LTS (TLS)        SMTP relay (STARTTLS)
```

## Container hardening

`docker-compose.yml` is the reference for how the images must run; CI starts it
and runs [`scripts/verify-stack.sh`](../scripts/verify-stack.sh), which fails
unless every item below holds.

| Control | Where |
|---|---|
| Base images pinned by version **and digest**; Alpine packages upgraded at build; Dependabot proposes new pins | Both Dockerfiles, `.github/dependabot.yml` |
| Fixable HIGH/CRITICAL vulnerabilities in OS packages, jars or npm lockfile fail the build (Trivy), daily as well as per PR | `.github/workflows/security.yml`, `.trivyignore` |
| No secret anywhere in git history (gitleaks) | same, `.gitleaks.toml` |
| Every container: non-root user, read-only root filesystem, `cap_drop: ALL`, `no-new-privileges`, memory + PID limits, rotated logs | `x-hardened` in Compose |
| Network segmentation: web ↔ app ↔ db on `internal` networks; only the app has a route out; web can't reach the database | Compose `networks:` |
| MySQL: TLS required, root only from inside its container, `local_infile` off, X protocol off, no DNS-based accounts | Compose `db.command` |
| Two database logins: app = rows only, owner = DDL for migrations | `db/roles.sql` |
| Access log without query strings; `X-Forwarded-For` believed only from listed proxies; HSTS; `/healthz` | `frontend/nginx/` |
| Health checks in both images (`/actuator/health/liveness`, `/healthz`) | Dockerfiles |
| Layered Spring Boot image, JVM exits on OOM so the orchestrator restarts it | `Dockerfile` |

Docker Desktop (Windows/macOS) ignores `enable_ip_masquerade: false`, so locally
the database and web containers can still reach the internet; on Linux (and in
CI) they cannot.

## Health checks

| Endpoint (management port) | Use |
|---|---|
| `/actuator/health/liveness` | Restart the container if failing |
| `/actuator/health/readiness` | Route traffic only when passing |
| `/actuator/health` | Combined; details are never exposed |

## Metrics and alerts

Prometheus scrapes `http://app:9091/actuator/prometheus`. Bastion-specific series:

| Metric | Meaning |
|---|---|
| `bastion_security_events_total{type}` | Every security event, by type (see below) |
| `bastion_ratelimit_rejected_total{rule}` | Requests refused by a per-IP limit |
| `bastion_mail_sent_total`, `bastion_mail_failures_total` | Mail delivery |
| `http_server_requests_seconds_*` | Latency and status per endpoint (standard) |
| `hikaricp_*`, `jvm_*` | Pool and JVM health (standard) |

Suggested alerts (PromQL):

```promql
# Any refresh-token reuse: a session token was very likely stolen.
increase(bastion_security_events_total{type="REFRESH_TOKEN_REUSE"}[5m]) > 0

# Credential stuffing / spraying in progress.
sum(rate(bastion_security_events_total{type=~"SIGN_IN_FAILED|SIGN_IN_BLOCKED"}[5m])) > 1

# Second-factor grinding.
increase(bastion_security_events_total{type="MFA_FAILED"}[15m]) > 20

# Admin actions — page someone if this is unexpected at 3 a.m.
increase(bastion_security_events_total{type=~"ADMIN_.*"}[5m]) > 0

# Mail is failing: users can't verify or recover accounts.
increase(bastion_mail_failures_total[15m]) > 0
```

## Logging

With `SPRING_PROFILES_ACTIVE=prod`, logs are one JSON object per line (ECS). Every
line inside a request carries `requestId` (also returned to the client as
`X-Request-Id`) and, once authenticated, `userId`.

Security events are additionally written to the logger **`bastion.audit`** as
`security_event` lines with `event`, `subjectUserId` (the account the event is
about), `actorId` and `ip` fields — ship
that logger to your SIEM. The same events are stored in the `security_events`
table for the admin viewer and each user's activity page, and purged after
`AUDIT_RETENTION_DAYS`.

What is never logged: passwords, tokens of any kind, TOTP secrets or codes,
recovery codes. Email addresses appear only in security events (needed to
investigate an account) — treat those logs as personal data.

## Key rotation

**`JWT_SECRET`** — replace and restart. Outstanding access tokens stop
validating; clients refresh with their cookie. Nobody is signed out. Device
cookies (sign-in throttling) are signed with a key derived from it, so every
browser counts as new until it next signs in.

**`DATA_ENCRYPTION_KEY`** — set the new key, move the old one to
`DATA_ENCRYPTION_PREVIOUS_KEYS`, restart. Old secrets stay readable and are
re-encrypted under the new key the next time each user enters a code. Keep the
old key until no `totp_secret` starts with `v1:<old key id>:`
(`SELECT COUNT(*) FROM users WHERE totp_secret LIKE 'v1:<id>:%'`), then drop it.

**Database / mail credentials** — standard rotation; restart the app.

## Backups and restore

Back up MySQL (encrypted, off-site) and `DATA_ENCRYPTION_KEY` (separately).
After restoring an older backup, consider rotating `JWT_SECRET` and revoking all
sessions (`UPDATE user_sessions SET revoked_at = NOW() WHERE revoked_at IS NULL`)
— refresh tokens issued after the backup no longer exist anyway.

## Incident response

- **A user reports account compromise** — Admin → Users → the user: review the
  security events and sessions; *Sign out* (revokes every session), *Lock* if
  needed, have them reset their password, and *Reset 2FA* only after verifying
  their identity out of band.
- **Suspected database leak** — rotate `DATA_ENCRYPTION_KEY` and `JWT_SECRET`,
  revoke all sessions (SQL above), force password resets if you have reason to
  believe hashes will be cracked (Argon2id makes that slow, not impossible), and
  notify users as your jurisdiction requires.
- **Abuse wave** — Admin → Settings → close signups; enable Turnstile.

## Scaling out

Everything is stateless against the database **except** the in-memory counters
in `WindowCounter` (rate limits, login/attempt budgets, the per-recipient mail
cap). With several instances each counts separately, multiplying every limit by
the instance count. Before scaling out, back `WindowCounter` with Redis
(`INCR key` + `EXPIRE key window` gives identical semantics), or pin auth traffic
to one instance.

The per-request session lookup is a single indexed primary-key query. If it
shows up in profiles, cache resolved sessions for a few seconds — never for the
access-token lifetime, or revocation stops being immediate.

## Upgrading from 1.x

The `V2__security_hardening` migration runs automatically. Users keep their
accounts and passwords (BCrypt hashes are upgraded to Argon2id at next sign-in),
but **everyone is signed out once**: 1.x refresh tokens predate session tracking.
New required setting: `DATA_ENCRYPTION_KEY`. The seeded dev admin
(`admin@bastion.local`) no longer exists — use `BOOTSTRAP_ADMIN_EMAIL`.
