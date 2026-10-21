# API reference

Base path `/api/v1`. JSON in and out. Authenticated routes take
`Authorization: Bearer <accessToken>`. The refresh token is an `HttpOnly`
cookie (`bastion_refresh`, path `/api/v1/auth`) that the browser sends by itself.

## Errors

Every error has the same shape:

```json
{ "message": "Human-readable reason", "code": "OPTIONAL_MACHINE_CODE", "fields": { "email": "…" } }
```

| `code` | Status | Meaning — what the client should do |
|---|---|---|
| `EMAIL_NOT_VERIFIED` | 403 | Correct password, unverified address — offer to resend the link. |
| `ACCOUNT_LOCKED` | 403 | An administrator locked the account. |
| `REAUTH_REQUIRED` | 403 | Sensitive action — re-authenticate (`POST /users/me/reauth…`) and retry. |
| `ADMIN_MFA_REQUIRED` | 403 | Admin API needs a session signed in with two factors. |
| `SIGNUPS_CLOSED` | 403 | New accounts are disabled. |
| `BREACHED_PASSWORD` | 400 | Pick a different password. |
| `RATE_LIMITED` | 429 | Slow down; `Retry-After` is set on per-IP limits. |

A `401` always means "no valid session — refresh or sign in". Authorisation
failures are `403`, never `401`, so clients don't loop on refresh.

Every response carries an `X-Request-Id`; quote it when reporting a problem.

## Anonymous — `/auth`

| Method | Path | Body | Result |
|---|---|---|---|
| GET | `/auth/config` | — | `{appName, signupsOpen, passwordMinLength, passwordMaxLength, turnstileSiteKey}` |
| POST | `/auth/signup` | `{email, password, name?, captchaToken?}` | `201` generic message (identical whether or not the address exists) |
| POST | `/auth/verify-email` | `{token, password}` | Session ¹ |
| POST | `/auth/resend-verification` | `{email, captchaToken?}` | Generic message |
| POST | `/auth/login` | `{email, password}` | Session ¹, or `{mfaRequired: true, mfaToken}` |
| POST | `/auth/mfa` | `{mfaToken, code}` — TOTP or recovery code | Session ¹ |
| POST | `/auth/passkey/options` | — | `PublicKeyCredentialRequestOptions` (base64url fields) |
| POST | `/auth/passkey/verify` | `{credentialId, clientDataJSON, authenticatorData, signature, userHandle?}` | Session ¹ |
| POST | `/auth/refresh` | — (cookie) ² | Session ¹ with a rotated cookie, or `401` |
| POST | `/auth/logout` | — (cookie) ² | Ends the session; clears the cookie |
| POST | `/auth/forgot-password` | `{email, captchaToken?}` | Generic message |
| POST | `/auth/reset-password` | `{token, newPassword}` | Ends every session; does not sign in |
| POST | `/auth/confirm-email-change` | `{token}` | Ends every session |

¹ **Session** = `Set-Cookie: bastion_refresh=…; HttpOnly; SameSite=Strict; Path=/api/v1/auth` (sign-ins also set a
`bastion_device` cookie, same flags, 1 year: it marks the browser as known for sign-in throttling and grants nothing else) and
`{accessToken, expiresIn, user: {id, email, name, role, mfaEnabled}, passwordBreached?}`.
`passwordBreached: true` means the password used appears in a breach — prompt a change.

² Requires the header `X-Bastion-Client` (any value) — CSRF defence.

Tokens from emails arrive in the URL fragment: `/verify-email#token=…`,
`/reset-password#token=…`, `/confirm-email#token=…`.

## Signed in — `/users/me`

🔒 = requires a re-authentication within `REAUTH_MINUTES` (else `403 REAUTH_REQUIRED`).

| Method | Path | Body | Notes |
|---|---|---|---|
| GET | `/users/me` | — | Profile, incl. `mfaEnabled`, `strongSession` |
| PUT | `/users/me` | `{name}` | |
| POST | `/users/me/change-password` | `{currentPassword, newPassword, code?}` | `code` required when TOTP is on. Ends other sessions. |
| POST | `/users/me/email` 🔒 | `{newEmail}` | Sends confirmation to the new address |
| DELETE | `/users/me` 🔒 | — | Deletes the account (refused for the last admin) |
| GET | `/users/me/export` | — | All personal data as JSON (no secrets) |
| GET | `/users/me/activity` | — | Last 50 security events for this account |
| GET | `/users/me/sessions` | — | Active sessions, `current: true` marks this one |
| DELETE | `/users/me/sessions/{id}` | — | |
| POST | `/users/me/sessions/revoke-others` | — | |
| GET | `/users/me/reauth` | — | `{reauthenticatedUntil, totpEnabled, hasPasskeys}` |
| POST | `/users/me/reauth` | `{password, code?}` | Opens the sudo window |
| POST | `/users/me/reauth/passkey/options` | — | Request options limited to own passkeys |
| POST | `/users/me/reauth/passkey` | assertion (as `/auth/passkey/verify`) | Opens the sudo window |
| GET | `/users/me/mfa` | — | `{totpEnabled, recoveryCodesRemaining}` |
| POST | `/users/me/mfa/totp/setup` 🔒 | — | `{secret, otpauthUri}` — not active yet |
| POST | `/users/me/mfa/totp/enable` 🔒 | `{code}` | `{recoveryCodes}` — shown once |
| POST | `/users/me/mfa/totp/disable` 🔒 | — | |
| POST | `/users/me/mfa/recovery-codes` 🔒 | — | New codes; old ones stop working |
| GET | `/users/me/passkeys` | — | |
| POST | `/users/me/passkeys/options` 🔒 | — | `PublicKeyCredentialCreationOptions` |
| POST | `/users/me/passkeys` 🔒 | `{attestationObject, clientDataJSON, transports, label}` | `201` |
| PATCH | `/users/me/passkeys/{id}` | `{label}` | |
| DELETE | `/users/me/passkeys/{id}` 🔒 | — | `204` |

## Administrators — `/admin`

Requires role `ADMIN` and (by default) a two-factor session. Admins cannot act on
their own account here.

| Method | Path | Body | Notes |
|---|---|---|---|
| GET | `/admin/users?page&size&q` | — | Paged; `q` searches email and name |
| GET | `/admin/users/{id}` | — | Detail: sessions, passkey count, recent events |
| PUT | `/admin/users/{id}/role` 🔒 | `{role: "USER"\|"ADMIN"}` | User is emailed |
| PUT | `/admin/users/{id}/locked` 🔒 | `{locked}` | Locking ends all sessions |
| POST | `/admin/users/{id}/sessions/revoke` | — | Sign out everywhere |
| DELETE | `/admin/users/{id}/mfa` 🔒 | — | Turns TOTP off; verify identity first |
| DELETE | `/admin/users/{id}` 🔒 | — | |
| GET | `/admin/security-events?userId&email&ip&type&page&size` | — | Searchable security log |
| GET / PUT | `/admin/settings` | `{signupsOpen}` (PUT 🔒) | |

## Rate limits (per client IP, 15-minute windows unless noted)

| Endpoint | Limit |
|---|---|
| `POST /auth/signup` | 5 accepted per hour (attempts refused as invalid don't count), 30 attempts per hour |
| `POST /auth/login` | 20 — plus 10 per *account* across all IPs; a browser that has signed in to the account before has its own 10 |
| `POST /auth/mfa` | 20 — plus 5 wrong codes per account |
| `POST /auth/forgot-password`, `/auth/resend-verification` | 5 |
| `POST /auth/reset-password` | 10 |
| `POST /auth/verify-email` | 20 — plus 5 wrong passwords per account |
| `POST /auth/passkey/*` | 60 |
| `POST /auth/refresh` | 300 |
| other `/auth/*` | 120 |
| `POST /users/me/reauth` | 20 — plus 5 wrong attempts per account |
| any other `/api/*` | 3000 |
| emails to one recipient | 10 per hour (silent) |
