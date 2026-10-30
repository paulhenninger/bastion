# Starting a new project from Bastion

Bastion is meant to be copied, not depended on: you take the whole repository,
rename it, and build your product inside it. This guide covers that path from
an empty folder to a deployable app, and what to keep intact along the way.

Prefer to have an AI coding assistant do it? Give it
[ai-customization-prompt.md](ai-customization-prompt.md): it interviews you,
then runs the steps below and checks its own work.

## 1. Get a copy with your own history

```bash
# GitHub: "Use this template" on the repository page, or:
git clone --depth 1 https://github.com/paulhenninger/bastion.git acme
cd acme
rm -rf .git && git init -b main && git add -A && git commit -m "Start from Bastion 2.1.0"
```

Keep a way back to upstream fixes (optional, recommended — see §8):

```bash
git remote add bastion https://github.com/paulhenninger/bastion.git
```

## 2. Rename it — one command

```bash
sh scripts/rename-project.sh acme com.example.acme "Acme"
```

| Argument | Rules | Becomes |
|---|---|---|
| `acme` | `[a-z][a-z0-9_]*` | database, both DB logins (`acme_app`, `acme_owner`), cookies (`acme_refresh`, `acme_device`), metrics (`acme_security_events_total`), the audit logger (`acme.audit`), image and Gradle project names |
| `com.example.acme` | a Java package | the package (sources are moved), Gradle `group` = `com.example` |
| `"Acme"` | free text | page title, nav bar, emails, the authenticator-app label, passkey prompt, docs |

It also renames `BastionApplication` → `AcmeApplication` and the CSRF header
`X-Bastion-Client` → `X-Acme-Client`, sets the version to `0.1.0`, starts a
fresh `CHANGELOG.md`, and deletes itself. It never touches the Flyway
migrations (their checksums must not change), `LICENSE`, or these two docs.

Then prove nothing broke:

```bash
./gradlew build                              # every test, incl. real MySQL via Docker
(cd frontend && npm install && npm run build)
git grep -in bastion                         # only credits and migration comments should remain
git add -A && git commit -m "Rename to Acme"
```

## 3. What to change by hand

| What | Where | Notes |
|---|---|---|
| Copyright | `LICENSE` | Add your line; keep Bastion's (MIT requires the notice). |
| Brand colours | `frontend/src/styles.css` `:root` tokens | All UI colour comes from these variables. |
| Logo / nav text | `frontend/src/components/NavBar.tsx` | The `⬢` glyph is a placeholder. |
| Favicon | `frontend/index.html` (+ a new `frontend/public/`) | None ships. |
| Email wording | `src/main/java/<pkg>/email/EmailService.java` | Plain-text by design; keep links to `APP_BASE_URL`. |
| Security contact | `SECURITY.md` | Point at **your** reporting channel. |
| README | `README.md` | Rewrite for your product; keep the docs table. |
| Third-party scripts/APIs | **both** `frontend/nginx/security-headers.conf` (pages) **and** `SecurityConfig.API_CSP` (API) | Add exact origins only. Never `'unsafe-inline'` in `script-src`. |

## 4. Build your product

- **Frontend**: start in `frontend/src/pages/DashboardPage.tsx`; add routes in
  `App.tsx` wrapped in `<ProtectedRoute>`. Call the API with the client in
  `frontend/src/api/client.ts` — it handles the in-memory access token, silent
  refresh, the CSRF header and the sudo-mode retry for you.
- **Backend**: add packages beside `auth/` (e.g. `<pkg>/orders/`). Every endpoint
  outside `/api/v1/auth/**` is authenticated by default. Take the caller with
  `@AuthenticationPrincipal AuthPrincipal me`; load what they may touch **by
  their id** (`findByIdAndOwnerId(id, me.userId())`), never trusting an id from
  the request alone.
- **Sensitive actions** (anything a session thief would want — payouts, email
  or payment changes, deleting data): call `reauth.require(me)` first. The SPA
  prompts for the password/code or passkey and retries automatically.
- **Admin-only**: put it under `/api/v1/admin/**` — that path already requires
  the `ADMIN` role and a two-factor session; mutations should call
  `reauth.require(me)` too.
- **Audit**: record security-relevant changes with `securityEvents.add(type, user, detail)` (add a type
  to `SecurityEventType`); they reach the DB, the `<name>.audit` logger and
  Prometheus.
- **Schema**: a new migration `V4__orders.sql` in
  `src/main/resources/db/migration/`. Never edit an applied one.
  `MySqlMigrationTest` checks the entities against real MySQL.
- **Rate limits** for new public or expensive endpoints: add a rule in
  `RateLimitFilter` (`new Rule(name, method, path, limit, window)`).
- **Tests**: extend `support/IntegrationTest` for full-flow tests through
  MockMvc; name each after the property it proves.

## 5. Trim what you don't need

| Feature | To remove | Keep in mind |
|---|---|---|
| Turnstile CAPTCHA | Leave `TURNSTILE_*` unset — it's off | Nothing to delete. |
| Breached-password check | `PASSWORD_BREACH_CHECK=false` | Not recommended. |
| Open signup | Admin → Settings, or `SIGNUPS_OPEN=false` | Invite-only flows build on the admin API. |
| Passkeys | `passkey/` package, its controller routes, `frontend/src/api/webauthn.ts` and `pages/account/PasskeysSection.tsx`, the `Permissions-Policy` entries | Drop the tables in a **new** migration. |
| Admin area | Not recommended: it's how you lock accounts and reset 2FA during an incident | — |

Run `./gradlew build` after each removal; the integration tests show what
depended on it.

## 6. Invariants — don't break these

These are what make the template secure. `CONTRIBUTING.md` explains each.

1. Anonymous endpoints reply identically, in the same time, whether or not an
   account exists.
2. Single-use tokens are consumed atomically (`UPDATE … WHERE used_at IS NULL`).
3. Secrets stored hashed (or encrypted if they must be read back), never logged.
4. Authorisation from the database per request, never from token claims.
5. Sensitive changes behind `reauth.require(me)`; every credential change
   records a security event and emails the owner.
6. Tokens in emailed links go in the URL **fragment** (`#token=`), never the query.
7. The CSP keeps `script-src 'self'` (plus exact third-party origins) — no
   inline script, no `eval`.
8. Containers stay as Compose runs them: non-root, read-only, no capabilities;
   the app's DB login stays rows-only.

## 7. Deploy

Follow the [production checklist](operations.md#production-checklist). In short:
two distinct random keys from a secret manager, `https://` `APP_BASE_URL`, real
passwords for both DB logins (the app refuses the published ones), TLS to the
database, a real SMTP relay with SPF/DKIM/DMARC, and the containers run with the
same restrictions as `docker-compose.yml` — check with `scripts/verify-stack.sh`.

CI is ready: `ci.yml` (tests, SpotBugs, npm audit, dependency review),
`security.yml` (gitleaks, Trivy, hardened-stack smoke test), `codeql.yml`.
Enable Dependabot alerts and private vulnerability reporting on your repository.

## 8. Taking upstream fixes later

Security fixes land in Bastion's `CHANGELOG.md`. Because your copy is renamed,
merge by cherry-picking, not by merging branches:

```bash
git fetch bastion
git log --oneline bastion/main            # find the fix
git cherry-pick -x <sha>                  # conflicts are mostly renamed identifiers
```

Then re-run `./gradlew build` and `scripts/verify-stack.sh`.
