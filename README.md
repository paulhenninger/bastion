# ⬢ Bastion

**Production-grade auth for Spring Boot 4 + React — the two weeks of security
plumbing every SaaS needs, done right, so you can start on the product.**

Bastion is an MIT-licensed starter kit: a complete, tested Spring Boot 4.1
(Java 25, Spring Framework 7) backend and React 19 + Vite 8 + TypeScript SPA
implementing the auth stack that is easy to get subtly wrong and expensive to
get wrong subtly. Every dependency is on its current major.

## What's inside

**Sessions done properly**
- Short-lived HS256 access tokens (15 min) held **in memory only** — never
  localStorage, so XSS can't exfiltrate a long-lived credential
- Rotating opaque refresh tokens in an **HttpOnly, SameSite=Lax cookie** scoped
  to the auth path, stored server-side as SHA-256 hashes only
- **Token-theft detection**: replaying a consumed refresh token revokes every
  session the user has — while a benign two-tab refresh race is tolerated
- Single-flight silent refresh in the SPA client: any number of concurrent 401s
  produce exactly one refresh call, then retry

**Account lifecycle**
- Signup → email verification (single-use, hashed, expiring tokens) → login
- Password reset via emailed single-use link; a reset revokes every session
- Change password (revokes all sessions + notification email)
- **Enumeration-safe by construction**: signup, forgot-password and
  resend-verification reply identically whether or not the address is
  registered, and login runs one BCrypt comparison whether or not the user
  exists (no timing oracle)

**Admin**
- `USER`/`ADMIN` roles; role is re-read from the DB on every request, so a
  demotion takes effect immediately, not at JWT expiry
- Paginated user management UI: promote/demote, lock/unlock (lock ≠ unverified,
  and locking revokes all sessions), delete
- Self-targeting refused server-side — no self-demote/lock/delete lockouts
- Admin tree answers 403 (not 401) so the SPA never mistakes "not allowed"
  for "session expired"

**Operational sanity**
- Flyway-managed schema, Hibernate in `validate`-only mode
- Per-IP rate limiting on auth endpoints with a hard memory bound
- SMTP timeouts set explicitly (Jakarta Mail defaults to *infinite*)
- Nightly purge of expired token rows
- Fails fast at startup on a missing/weak JWT secret
- Docker Compose dev stack with MySQL + Mailpit (local mail catcher — watch
  every email at http://localhost:8025 without sending anything)
- GitHub Actions CI: backend tests + frontend type-check/build

**Tests that earn their keep** — 15 tests covering the full signup → verify →
login → refresh-rotation → theft-detection → reset flow end-to-end through
MockMvc, including the enumeration-safety and single-use-token guarantees.

## Quickstart

```bash
# 1. Databases + mail catcher
docker compose up -d

# 2. Secrets
cp .env.example .env
# set JWT_SECRET (openssl rand -base64 32) and load the file into your shell

# 3. Backend  →  http://localhost:8080
# (no JDK 25 install needed — the Gradle toolchain auto-downloads it)
./gradlew bootRun

# 4. Frontend  →  http://localhost:5173
cd frontend
npm install
npm run dev
```

Sign up at http://localhost:5173, open http://localhost:8025 (Mailpit), click
the verification link — you're in. A dev admin account is seeded at startup
(credentials in the backend log; disabled under the `prod` profile).

Full containerized stack instead: `docker compose --profile full up -d --build`
→ app at http://localhost:8081 (set `APP_BASE_URL`/`CORS_ORIGINS` accordingly).

## API

Base path `/api/v1`.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/signup` | No | Register; sends verification email |
| GET | `/auth/verify-email?token=` | No | Verify email; returns session |
| POST | `/auth/resend-verification` | No | Re-send link (generic reply) |
| POST | `/auth/login` | No | Login; JWT + refresh cookie |
| POST | `/auth/refresh` | Cookie | Rotate refresh token; new JWT |
| POST | `/auth/logout` | Cookie | Revoke this session |
| POST | `/auth/forgot-password` | No | Email a reset link (generic reply) |
| POST | `/auth/reset-password` | No | Set new password; revokes all sessions |
| GET / PUT | `/users/me` | Bearer | Get / update profile |
| POST | `/users/me/change-password` | Bearer | Change password; revokes all sessions |
| GET | `/admin/users?page=&size=` | Admin | Paginated user list |
| PUT | `/admin/users/{id}/role` | Admin | Promote / demote |
| PUT | `/admin/users/{id}/locked` | Admin | Lock / unlock (lock revokes sessions) |
| DELETE | `/admin/users/{id}` | Admin | Delete account |

## Project layout

```
src/main/java/dev/bastion/
  auth/         signup, login, tokens, rotation, recovery
  user/         profile + change-password
  admin/        user management + dev admin seed
  security/     JWT, auth filter, rate limiting, token hashing
  email/        SMTP (async, timeout-bounded)
  config/       SecurityConfig, typed AppProperties
  maintenance/  nightly token purge
frontend/src/
  api/          fetch client (silent refresh), auth calls
  auth/         AuthContext (boot-time session resume)
  components/   NavBar, route guards
  pages/        login, signup, verify, forgot/reset, dashboard, profile, admin
```

## Make it yours

1. **Rename**: search-and-replace `dev.bastion` / `bastion` / `Bastion`, rename
   the cookie in `AuthController.REFRESH_COOKIE`, retitle `index.html`, and swap
   the CSS tokens at the top of `frontend/src/styles.css`.
2. **Build your product** in `DashboardPage` and new backend packages beside
   `auth/` — the security plumbing doesn't need touching.
3. **Going to production**: set a strong `JWT_SECRET` and DB credentials, run
   with `SPRING_PROFILES_ACTIVE=prod` (disables the seeded admin), point
   `MAIL_*` at a real relay (SES/Postmark/Mailgun), put nginx in front (the
   included `frontend/nginx.conf` resets `X-Forwarded-For` correctly — keep
   that behavior), serve HTTPS (the refresh cookie flips to `Secure`
   automatically when `APP_BASE_URL` is https), and add a CSP.

## Design decisions worth knowing about

- **Why hash tokens at rest?** A leaked database must not contain usable
  sessions, verification links or reset links. Only SHA-256 hashes are stored;
  the raw value exists in the cookie/email alone.
- **Why re-read the user per request?** Locks and demotions must take effect
  now. The cost is one indexed primary-key read; cache later if you must.
- **Why a 60-second reuse grace?** Two tabs refreshing simultaneously is
  normal; a replay minutes later is theft. The grace window separates them.
- **Why `flushAutomatically`/`clearAutomatically` on `revokeAllForUser`?**
  Bulk JPQL updates bypass the persistence context; without them, an entity
  already loaded in the same transaction still looks unrevoked afterwards —
  a bug our own integration tests caught.
- **Single-instance assumption**: the rate limiter is in-process memory.
  Scaling to multiple instances means moving it to Redis; everything else is
  already stateless against the shared database.

## License

MIT — see [LICENSE](LICENSE). Use it for anything, commercial or not; keep the
copyright notice. No warranty: security software is your responsibility to
review before you ship it.
