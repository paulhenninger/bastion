# Contributing

Thanks for helping. Bastion is security software, so the bar for changes is
"provably correct and explained", not just "works".

**Security issues: don't open a public issue — see [SECURITY.md](SECURITY.md).**

## Build and test

```bash
./gradlew build          # compile, all tests, SpotBugs (needs Docker for MySqlMigrationTest)
./gradlew test --tests '*Passkey*'
cd frontend && npm ci && npm run build   # type-check + production build
```

`MySqlMigrationTest` runs the Flyway migrations on real MySQL via Testcontainers
and is skipped when Docker isn't available. CI always runs it.

Reports: `build/reports/tests/test/index.html`, `build/reports/spotbugs/main.html`.

## Expectations for a pull request

- **A test for every security property you add or change**, ideally one that
  fails without your change. Name it after the property
  (`lockedAccountsCantSignInWithAPasskey`), not the method.
- **Explain the why in the code.** The existing comments say what attack a line
  stops and why the obvious alternative is wrong; keep that up.
- **Update the docs** your change touches: `docs/security-model.md` (threat →
  control → test), `docs/api.md`, `docs/configuration.md`, `CHANGELOG.md`.
- **Schema changes** are a new Flyway migration (`V3__…`), never an edit to an
  existing one. `MySqlMigrationTest` will tell you if the entities disagree.
- **No new SpotBugs findings.** Fix them, or add a reviewed, commented entry to
  `config/spotbugs/exclude.xml`.
- **Dependencies**: pin exact versions in the frontend, prefer well-maintained
  libraries, and say why a new one is worth its attack surface.

## Conventions that matter here

- Anything an anonymous caller can reach must reply identically — and in the
  same time — whether or not an account exists.
- Single-use things are consumed atomically (conditional `UPDATE … WHERE used_at IS NULL`
  or a row lock), never read-check-write.
- Secrets are stored hashed (or encrypted if they must be read back) and are
  never logged.
- Authorisation is decided from the database per request, never from token claims.
- Anything a session thief would want to change goes behind `reauth.require(me)`.
- Every change to how an account can be accessed records a security event and
  emails the owner.
