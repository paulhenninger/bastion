# Notes for AI coding agents

Bastion is a security-focused auth starter: Spring Boot 4.1 / Java 25 backend
(`src/main/java/dev/bastion`), React 19 + Vite SPA (`frontend/`), MySQL 9.7,
nginx. Read `CONTRIBUTING.md` and `docs/security-model.md` before changing
security-relevant code.

**Turning this template into a new project?** Follow
[docs/ai-customization-prompt.md](docs/ai-customization-prompt.md) — it starts
with an interview; don't skip it.

## Commands

```bash
./gradlew build                     # all tests (MySqlMigrationTest needs Docker) + SpotBugs
./gradlew test --tests '*Passkey*'  # a subset
cd frontend && npm ci && npm run build
docker compose up -d                # MySQL (+ its two logins) and Mailpit for bootRun
docker compose --profile full up -d --build --wait && sh scripts/verify-stack.sh
```

## Rules

- Never weaken a control to make something pass: no skipping or loosening
  security tests, CSP, rate limits, `DeploymentSafetyCheck`, container
  restrictions in `docker-compose.yml`, or `scripts/verify-stack.sh` checks.
- Schema changes are a new migration (`V4__…`); never edit an applied one.
- New endpoints are authenticated by default; scope data by the caller's id;
  sensitive actions call `reauth.require(me)`; record security events.
- Tokens in links go in the URL fragment; secrets are hashed or encrypted and
  never logged; anonymous endpoints are enumeration-safe.
- Runtimes stay on LTS lines (Java 25, Node 26, MySQL 9.7); CI fails if
  `build.gradle`, the Dockerfiles and Compose disagree.
- Images are pinned by digest and Actions by commit SHA — keep it that way.
- On Docker Desktop, verify-stack's three "cannot reach the internet" checks fail
  by design of its networking; they pass on Linux CI.
