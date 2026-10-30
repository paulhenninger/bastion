# Security model

This document is the honest answer to "how secure is Bastion?". It lists what
Bastion protects, the attacks it is designed to stop, how each is stopped, and
which test proves it. Then it lists what Bastion **cannot** protect against and
what you must do yourself.

No system is "unhackable". The goal is defence in depth: every important control
is backed by a second one, failures are loud, and nothing that matters relies on
the client behaving.

## Assets

| Asset | Where it lives | Protection at rest |
|---|---|---|
| Passwords | `users.password_hash` | Argon2id (m=19 MiB, t=2, p=1 — OWASP), per-hash salt |
| Refresh tokens | cookie only; `refresh_tokens.token_hash` | SHA-256 of 256-bit random value |
| Verification / reset / email-change tokens | email only; `*_tokens.token_hash` | SHA-256 of 256-bit random value |
| MFA login challenges | client memory; `mfa_challenges.token_hash` | SHA-256 |
| TOTP shared secrets | `users.totp_secret` | AES-256-GCM, bound to the account by associated data |
| Recovery codes | shown once; `mfa_recovery_codes.code_hash` | SHA-256 (~50 bits each, attempt-limited) |
| Passkey public keys | `webauthn_credentials` | not secret — the private key never leaves the device |
| Access tokens (JWT) | SPA memory only, 15 min | HMAC-SHA256; carry only user id + session id |

A full read of the database therefore yields **no usable credential**: no
session, no link, no password (short of cracking Argon2id), and no TOTP secret
without `DATA_ENCRYPTION_KEY`, which is kept outside the database.

## Threats and controls

### Credential attacks

| Threat | Control | Test |
|---|---|---|
| Online password guessing from one IP | Per-IP rate limit on `/auth/login` (20 / 15 min) and nginx `limit_req` | `RateLimitingIntegrationTest.oneIpHammeringLoginIsThrottledPerIp` |
| Password spraying one account from many IPs | Per-account budget (10 / 15 min), charged *before* the check so parallel bursts can't exceed it, refunded on success; applied identically to unknown addresses | `…passwordSprayingOneAccountFromManyIpsIsThrottledPerAccount` |
| Locking the owner out by spending that budget | **Device cookies** (OWASP): a browser that has signed in to the account before presents a signed, `HttpOnly` cookie and draws on a budget of its own, so only never-seen browsers are blocked during an attack. A forged or stolen cookie buys no more than any new browser gets | `…anAttackerSpendingTheAccountBudgetDoesntLockTheOwnerOutOfAKnownBrowser` |
| Credential stuffing with breached passwords | New passwords checked against Have I Been Pwned (k-anonymity: only 5 hex chars of SHA-1 leave the server); sign-in with a breached password flags the session so the UI demands a change | `SecurityPrimitivesTest.breachCheck…` |
| Weak passwords | Minimum 12 characters (configurable), maximum 128, must not contain the email; no composition rules (NIST SP 800-63B) | `AuthFlowIntegrationTest.weakAndAccountNamePasswordsAreRefused` |
| Offline cracking of a stolen database | Argon2id; legacy BCrypt rehashed to Argon2id at next sign-in | `…legacyBcryptHashesStillWorkAndAreUpgradedToArgon2` |
| Phished or stolen password | Optional TOTP or passkeys; admins *must* use one | `MfaIntegrationTest`, `AccountAndAdminIntegrationTest.theAdminApiRequiresATwoFactorSession` |
| Real-time phishing of a TOTP code | Each code works once (time step persisted); passkeys are origin-bound and so phishing-resistant | `…enablingTotpMakesSignInTakeTwoSteps`, `PasskeyIntegrationTest.aForeignOriginIsRefused` |
| Grinding the 6-digit code after stealing the password | 5 guesses per challenge **and** 5 per account per 15 min (a new challenge doesn't buy new guesses) | `…aChallengeAllowsFiveGuessesThenDies` |

### Account enumeration

| Threat | Control | Test |
|---|---|---|
| "Which emails have accounts?" via signup | Identical reply for new and existing addresses; existing owner emailed instead; Argon2 hash computed in both branches | `…signupForAnExistingAccountRepliesGenericallyAndChangesNothing` |
| …via forgot-password / resend-verification | Identical reply; the account lookup and mail run asynchronously so timing is identical too | `…forgotPasswordForUnknownEmailStaysGeneric` |
| …via login | Unknown users burn one Argon2 comparison against a dummy hash; "unverified"/"locked" only revealed after the correct password | `…wrongPasswordAndUnknownEmailLookIdentical`, `…lockedAccountsAreRefusedOnlyAfterTheRightPassword` |
| …via rate-limit responses | Per-account budgets charge unknown addresses too; the mail cap is silent | `…passwordSpraying…` |
| …via email change (signed-in user) | Same reply whether or not the new address is taken | `…emailChangeDoesNotRevealWhetherTheAddressIsTaken` |

### Account takeover through recovery and lifecycle flows

| Threat | Control | Test |
|---|---|---|
| **Account pre-hijacking** (attacker registers your address first with their password) | Each signup's verification token carries *that signup's* password hash (and display name); verifying requires typing the password, and the signup you prove is the one applied | `…preRegisteringSomeoneElsesAddressGainsNothing`, `…thePreRegisteringAttackersDisplayNameDoesntStick` |
| Reset link reused / raced | Single-use via conditional `UPDATE … WHERE used_at IS NULL`; a newer link kills older ones; any password change kills all | `…passwordResetEndsEverySessionAndLinksAreSingleUse` |
| Inbox compromise bypasses MFA | A reset never removes TOTP and never signs in | `MfaIntegrationTest.passwordResetDoesNotRemoveTheSecondFactor` |
| Tokens leaking via logs or Referer | Emailed links use the URL **fragment** (`#token=`), never sent to servers; SPA strips it from history; `Referrer-Policy: no-referrer` | e2e (link format) |
| Email change by a session thief | Requires recent re-auth; confirmed only by the *new* inbox; old address notified at request and at change; all sessions end | `…emailChangesOnlyWhenTheNewInboxConfirms` |
| Inbox flooding / mail-cost abuse | Max 10 messages per recipient per hour, silently; optional Turnstile CAPTCHA; per-IP limits | — |
| Throwaway / typo addresses | Strict syntax, disposable-domain list, IANA TLD list, MX lookup (fails open on DNS trouble) | `…malformedAddressesAreRefusedWithAReason` |

### Session attacks

| Threat | Control | Test |
|---|---|---|
| XSS steals a long-lived credential | Access token in JS memory only (15 min); refresh token `HttpOnly`; strict CSP with no `unsafe-inline` scripts | `…signupVerifyLoginRefreshLogout` (cookie flags) |
| Stolen refresh token | Rotation on every use; replay after the 60 s grace revokes **every** session and emails the owner. Inside the grace window (two tabs refreshing at once) the stale token is refused *without* clearing the browser's newer cookie | `…refreshTokenReplayRevokesEverySession`, `…twoTabsRefreshingAtOnceDontSignEachOtherOut` |
| Two requests racing one refresh token into two sessions | Rotation takes a row lock (`SELECT … FOR UPDATE`) | `MySqlMigrationTest` (InnoDB) |
| Revoked session keeps working until JWT expiry | Every request re-reads the session row: logout, revoke, lock, password reset take effect on the next request | `…signupVerifyLoginRefreshLogout`, `…lockingAUserEndsTheirSessionsImmediately` |
| Sessions living forever | 14-day idle timeout, 30-day absolute lifetime | `…sessionsEndAtTheirAbsoluteExpiryHoweverActive` |
| Borrowed/hijacked session makes permanent changes | "Sudo mode": changing email, 2FA, passkeys, deleting the account and every admin mutation require re-auth (password + code, or passkey) within 10 min; re-auth guesses are budgeted | `…sensitiveChangesRequireARecentReauthentication`, `RateLimitingIntegrationTest.reauthPasswordGuessesAreBudgetedPerAccount` |
| Unnoticed sign-in from an attacker | Email alert on sign-in from a new device/network; full activity log visible to the user | `…signInFromANewDeviceAlertsTheOwner` |
| CSRF | API uses Bearer tokens; refresh cookie is `SameSite=Strict`, path-scoped, and its endpoints require an `X-Bastion-Client` header (forces a CORS preflight) | `…cookieEndpointsRequireTheClientHeader` |
| JWT forgery / algorithm confusion | HS256 with a ≥256-bit key (startup fails otherwise); `alg: none` and tampered tokens rejected; issuer and audience pinned | `AccountAndAdminIntegrationTest.forgedOrForeignTokensAreRejected`, `SecurityPrimitivesTest.jwt…` |
| Stale authorisation in a token | JWT carries no role or email; role is read from the database per request | `…demotionTakesEffectOnTheNextRequest` |

### Passkeys (WebAuthn)

| Threat | Control | Test |
|---|---|---|
| Phishing site relays the ceremony | Origin and RP ID checked against `APP_BASE_URL` | `PasskeyIntegrationTest.aForeignOriginIsRefused` |
| Assertion replay | Single-use, purpose-bound, 5-minute challenges consumed atomically | `…anAssertionCantBeReplayed` |
| Cloned authenticator | Signature counter must increase | `…aClonedAuthenticatorIsDetectedByItsCounter` |
| Someone else's finger on an unlocked phone | User verification (biometric/PIN) required at registration and every use | (enforced in `PasskeyService`) |
| Session thief plants a passkey | Registration requires recent re-auth; owner emailed | `…addingAPasskeyRequiresRecentReauthentication…` |
| Locked account signs in with a passkey | Lock and verification checked on passkey sign-in | `…lockedAccountsCantSignInWithAPasskey` |

### Administration

| Threat | Control | Test |
|---|---|---|
| Stolen admin password | Admin API requires a session that signed in with two factors | `…theAdminApiRequiresATwoFactorSession` |
| Hijacked admin session | Every admin mutation requires recent re-auth | `…adminsCantActOnThemselvesAndMutationsNeedReauth` |
| Admin locks themselves out / no admin left | Admins can't modify their own account via the admin API; the last admin can't delete themselves | same |
| Default/seeded admin credentials | None exist. `BOOTSTRAP_ADMIN_EMAIL` promotes a *verified* account, only while no admin exists; no password is ever generated or logged | `…theBootstrapEmailBecomesTheFirstAdminOnlyWhenNoneExists` |
| Untraceable admin actions | Every admin action is logged with the admin as actor; the affected user is emailed | `…securityEventsAreRecordedAndSearchable` |

### Application and infrastructure

| Threat | Control | Test |
|---|---|---|
| Memory exhaustion via huge bodies | 64 KiB body cap enforced before parsing (also nginx `client_max_body_size`) | `…oversizedBodiesAreRefusedBeforeBeingRead` |
| Error responses leaking internals | Uniform JSON errors; framework exceptions mapped to their 4xx; stack traces never returned | `…malformedRequestsAre4xxNever500` |
| Clickjacking, MIME sniffing, XSS | CSP (`frame-ancestors 'none'`, no inline script), `X-Frame-Options`, `nosniff`, COOP/CORP, `Permissions-Policy` | `…apiResponsesCarrySecurityHeaders` |
| IP spoofing to evade limits | `X-Forwarded-For` trusted only when configured, and nginx *resets* it; non-IP values ignored | e2e |
| Log injection | Control characters stripped from user agents and event details; request ids validated | — |
| Exposed metrics / health | Actuator on a separate port that nginx never proxies | e2e (404 through nginx) |
| Container escape impact | Non-root users, read-only root filesystems, every capability dropped, `no-new-privileges`, memory/PID limits | `scripts/verify-stack.sh` (CI) |
| Lateral movement after an app compromise | Segmented networks (web can't reach the DB; only the app reaches the internet); the app's DB login can only read/write rows, never DDL or other schemas, and a deployment refuses to start otherwise (`DatabaseLoginCheck`); DB root only from inside its container; DB TLS required | `scripts/verify-stack.sh` (CI), `MySqlMigrationTest` |
| Deploying on development defaults | `DeploymentSafetyCheck` refuses `http://`, published DB passwords and a shared key once `APP_BASE_URL` names a real host | `DeploymentSafetyCheckTest` |
| Secrets in query strings reaching logs | Emailed tokens live in the URL fragment; nginx logs paths without query strings | `scripts/verify-stack.sh` (CI) |
| Vulnerable dependencies | Dependabot (Java dependencies via the submitted Gradle graph, digest-pinned images included), `dependency-review` on PRs, `npm audit`, Trivy on both images and the npm lockfile (daily), CodeQL, SpotBugs + find-sec-bugs | CI |
| Supply-chain tampering | Base images pinned by digest, GitHub Actions pinned by commit SHA, Gradle distribution checksum-verified, scanners run from digest-pinned images; gitleaks over all history | CI |
| Schema drift | Flyway migrations run on real MySQL and validated against the entities in CI | `MySqlMigrationTest` |
| Data loss on DB theft | See *Assets* | `MfaIntegrationTest.totpSecretsAreEncryptedAtRest`, `SecurityPrimitivesTest.cipher…` |

## Design decisions you might question

**Why no email or SMS second factor?** Email is the recovery channel, so an
emailed code isn't an independent factor: whoever controls the inbox can reset
the password *and* read the code. NIST SP 800-63B prohibits email for
out-of-band authentication and restricts SMS (SIM swap, SS7 interception).
TOTP and passkeys are offered instead.

**Why can't a password reset turn off 2FA?** Otherwise a compromised inbox
alone would defeat two-factor. Recovery codes, a passkey, or an administrator
(after verifying identity out of band) are the way back.

**Why a soft lockout rather than locking accounts after N failures?** A hard
lockout lets anyone who knows an address deny its owner service. Bastion's
throttle lifts after 15 minutes and applies identically to unknown addresses —
and even while it's in force, a browser that has signed in to the account before
keeps its own budget (device cookies), so the owner isn't locked out. Someone
signing in from a brand-new browser during an attack can wait it out, use a
passkey (not throttled per account), or reset their password.

**Why does verifying an email require the password?** It's what defeats
account pre-hijacking; it costs the user one field they'd type at sign-in anyway.

**Why is the session checked in the database on every request?** It makes
revocation immediate. The cost is one indexed query per request; if that
becomes your bottleneck, cache it for a few seconds — not for the token lifetime.

## Residual risks and your responsibilities

Bastion cannot protect against these; plan for them:

1. **Compromise of the running application or host.** Whoever controls the
   process has the keys. Patch the host, restrict access, use secrets
   management for `JWT_SECRET` and `DATA_ENCRYPTION_KEY`.
2. **Malware on the user's device** can act within a live session. Sudo mode,
   new-device alerts and the activity log limit and expose the damage; they
   don't prevent it.
3. **XSS in code you add.** The CSP is a strong backstop; keep it strict. Never
   add `'unsafe-inline'` to `script-src`, never use `dangerouslySetInnerHTML`
   with user data.
4. **Multiple instances.** Rate limits and attempt budgets are in-process memory.
   Behind a load balancer each instance counts separately; move them to Redis
   (see [operations.md](operations.md)) before scaling out.
5. **TLS.** Bastion assumes HTTPS in production (the refresh cookie becomes
   `Secure` when `APP_BASE_URL` is `https://`). Terminate TLS properly and
   add HSTS at the terminator.
6. **Email security.** Account recovery is only as strong as the user's inbox.
   Configure SPF, DKIM and DMARC for your sending domain so reset emails can't be
   spoofed and actually arrive.
7. **Social engineering of administrators.** An admin can reset another user's
   2FA. Verify identity out of band first.
8. **Key loss.** Losing `DATA_ENCRYPTION_KEY` means every TOTP user must
   re-enrol (via admin reset). Back it up separately from the database.
9. **Third-party availability.** The breached-password check, Turnstile and the
   MX lookup fail *open* by design, so an outage at HIBP or Cloudflare degrades
   protection rather than availability.

## Standards alignment

Bastion's controls were designed against **OWASP ASVS 5.0** chapters V6
(Authentication), V7 (Session Management) and V8 (Authorization), the **OWASP
Authentication, Session Management, Password Storage and Forgot Password cheat
sheets**, and **NIST SP 800-63B-4**. Alignment is not certification; have your
deployment assessed if you need that.
