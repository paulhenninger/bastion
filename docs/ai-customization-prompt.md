# AI customization prompt

Hand this file to an AI coding assistant (Claude Code, Cursor, Copilot agent, …)
in a fresh copy of Bastion. It interviews you, renames and trims the template,
starts your product, and proves it still passes every security check.

**To use it**, open your copy in the assistant and say:

> Read `docs/ai-customization-prompt.md` and follow it.

Everything below the line is written to the assistant.

---

## Your role

You are turning a fresh copy of **Bastion** — a hardened Spring Boot 4 (Java 25)
+ React 19 authentication starter — into the user's own project. Bastion's
value is its security; your job is to make it theirs **without weakening it**.
Read `README.md`, `CONTRIBUTING.md`, `docs/scaffolding.md` and
`docs/security-model.md` before changing anything.

## Step 1 — Interview

Ask these questions **in one message**, numbered, with the default in brackets.
Accept "default" for any. Don't start editing until the user has answered.

1. **Product name** shown to users? (e.g. "Acme Books")
2. **Identifier** — lowercase, `[a-z][a-z0-9_]*`, used for the database,
   cookies, metrics and images? [derived from the name: "acme_books"]
3. **Java base package**? [`com.<identifier>`]
4. **One sentence**: what does the product do, and for whom? (Goes in the
   README; shapes the first page you build.)
5. **Brand colours**: an accent colour, and light or dark UI? [keep Bastion's dark theme]
6. **Sign-up**: open to anyone, or invite/admin-only? [open]
7. **Features to remove**, if any: passkeys, TOTP two-factor, CAPTCHA
   (Turnstile), breached-password check, the admin area? [keep all — say why if
   they want to remove the admin area or 2FA: they're incident-response tools]
8. **Third-party services** the browser must load or call (analytics, payments,
   maps, fonts)? Exact domains, if known. [none]
9. **The first feature** to build on the dashboard — the core object (e.g.
   "orders: a user creates and lists their own orders")? [none: leave the
   dashboard as a placeholder]
10. **Security contact** for `SECURITY.md` (email or URL)? [GitHub private vulnerability reporting]
11. **Copyright holder** for `LICENSE`? [the git user name]

Repeat the answers back as a short plan and wait for "go".

## Step 2 — Rename (mechanical; use the script)

1. Make sure the working tree is clean and committed.
2. Run `sh scripts/rename-project.sh <identifier> <package> "<Product name>"`.
3. Run `./gradlew build` and `(cd frontend && npm install && npm run build)`.
   Both must pass before you go on. If Docker isn't running, say that
   `MySqlMigrationTest` was skipped; don't claim it passed.
4. `git grep -in bastion` — expect only the credit in `CHANGELOG.md`, `LICENSE`,
   migration comments and these docs. Fix anything else.
5. Commit: "Rename to <Product name>".

## Step 3 — Customize (by hand)

Work through `docs/scaffolding.md` §3 and §5 using the interview answers:

- **Colours**: edit only the `:root` tokens in `frontend/src/styles.css`. Check
  contrast: body text on `--bg` and on `--surface` ≥ 4.5:1.
- **Name in the nav bar** (`NavBar.tsx`) and `README.md` (rewrite the intro from
  answer 4; keep the docs table and the security sections).
- **`SECURITY.md`** contact; **`LICENSE`**: add the holder's line, keep Bastion's.
- **Sign-up** closed → set `SIGNUPS_OPEN=false` in `.env.example` and document it.
- **Removed features**: follow §5 exactly; drop tables only in a **new**
  migration; delete the matching tests only when the feature is gone; update
  `docs/security-model.md` rows for anything removed, so the doc stays true.
- **Third-party origins**: add each *exact* origin to the right directive in
  **both** `frontend/nginx/security-headers.conf` and, if the API must allow it,
  `SecurityConfig`. Never add `'unsafe-inline'` or `'unsafe-eval'` to
  `script-src`, never a wildcard host.

Commit after each bullet that changed something.

## Step 4 — Build the first feature (if answer 9 named one)

Follow `docs/scaffolding.md` §4. For a typical owned resource:

1. Migration `V4__<thing>.sql` (never edit V1–V3): table with `owner_id`
   referencing `users(id)` `ON DELETE CASCADE`, timestamps in UTC.
2. Entity + repository in a new package `<package>.<thing>`; repository methods
   scoped by owner (`findByIdAndOwnerId`, `findAllByOwnerIdOrderByCreatedAtDesc`).
3. Controller under `/api/v1/<things>`, taking `@AuthenticationPrincipal
   AuthPrincipal me`; validate input with Bean Validation; another user's id
   returns 404, not 403 (don't confirm it exists).
4. Destructive or high-value actions call `reauth.require(me)`.
5. Account deletion and data export must include the new data
   (`AccountService` — GDPR export and delete).
6. An integration test extending `support/IntegrationTest` proving: the owner
   can CRUD; another user gets 404 for every verb; anonymous gets 401; invalid
   input is a 400, never a 500.
7. Frontend page using `frontend/src/api/client.ts` (never `fetch` directly —
   the client handles tokens, refresh, CSRF header and re-auth), routed inside
   `<ProtectedRoute>`.
8. Document the endpoints in `docs/api.md`.

## Step 5 — Verify, then report

Run all of these and report each result honestly (passed / failed / skipped and why):

```bash
./gradlew build
(cd frontend && npm run build && npm audit --omit=dev --audit-level=high)
docker compose --profile full up -d --build --wait   # needs JWT_SECRET and DATA_ENCRYPTION_KEY in .env
sh scripts/verify-stack.sh
docker compose --profile full down
```

On Docker Desktop (Windows/macOS) the three "cannot reach the internet" checks
fail by design of Docker Desktop's networking; note it, it passes on Linux CI.

Finish with a short summary: what was renamed, what was removed, what was
built, every command's outcome, and what the user must still do themselves
(generate production keys, set real DB passwords, configure SMTP/SPF/DKIM/DMARC,
TLS, enable Dependabot alerts and private vulnerability reporting).

## Rules for the whole session

- **Never weaken a security control to make something work.** If a test or
  check fails, find the cause. Never delete, skip or loosen a security test,
  `DeploymentSafetyCheck`, a CSP directive, a rate limit, a container
  restriction in `docker-compose.yml`, or a `verify-stack.sh` check.
- Never commit secrets. `.env` is git-ignored; real keys come from
  `openssl rand -base64 32` and live in a secret manager.
- Never edit an applied Flyway migration (`V1`–`V3`); add a new one.
- Keep the invariants in `docs/scaffolding.md` §6.
- Keep comments in the existing style: say what attack a line stops and why.
- Pin exact versions for new frontend dependencies; justify each new dependency.
- Ask before anything irreversible (deleting branches, force-pushing, dropping data).
