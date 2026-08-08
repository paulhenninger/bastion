# Changelog

## 1.0.0 — 2026-08-08

Initial release.

- Spring Boot 4.1 (Spring Framework 7) / Java 25 backend; React 19 + Vite 8 +
  TypeScript SPA — every dependency on its current major
- Sessions: 15-min HS256 access tokens (in-memory in the SPA) + rotating
  opaque refresh tokens (HttpOnly SameSite=Lax cookie, SHA-256 at rest)
- Refresh-token theft detection with a two-tab grace window
- Signup with email verification; password reset via emailed single-use link;
  change password — all destructive paths revoke every session
- Enumeration-safe signup/recovery flows; constant-shape login
- USER/ADMIN roles, paginated admin user management (promote, lock, delete)
  with server-side self-targeting guards
- Per-IP auth rate limiting with a bounded in-memory table
- Flyway schema, Mailpit dev mail catcher, Docker Compose stack, GitHub
  Actions CI
- 15 backend tests including the full auth flow end-to-end through MockMvc
