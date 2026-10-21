# Security policy

Bastion is authentication infrastructure, so a vulnerability in it is a
vulnerability in every application built on it. Reports are very welcome and
are treated as the highest priority.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report privately through GitHub: **Security → Report a vulnerability** on this
repository (GitHub private vulnerability reporting). Include:

- what an attacker can do, and what they need first (an account? a stolen
  session? network position?);
- steps or a proof of concept against a local `docker compose --profile full`
  stack;
- the commit or release you tested.

What to expect:

| Step | Target |
|------|--------|
| Acknowledgement | within 3 working days |
| Initial assessment (severity, affected versions) | within 7 days |
| Fix released for critical/high severity | within 30 days, usually much sooner |
| Public advisory and credit (if you want it) | when the fix ships |

Please give us a reasonable chance to ship a fix before disclosing publicly.
Good-faith research that respects this policy will not be pursued legally.

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅ security fixes |
| 1.x     | ❌ — upgrade; 1.x has known weaknesses fixed in 2.0 (see CHANGELOG) |

## Scope

In scope: everything in this repository — the Spring Boot backend, the React
SPA, the bundled nginx configuration, Dockerfiles and Flyway migrations, and
the defaults they ship with.

Out of scope: vulnerabilities in your own code built on Bastion, in
infrastructure you deploy it on, or that require a misconfiguration the docs
warn against (for example `TRUST_FORWARDED_FOR=true` without a proxy that resets
the header, or exposing the management port publicly). Reports that the docs are
unclear about such a setting *are* in scope.

## What Bastion does and doesn't promise

No software is unbreakable, and a starter kit can only secure the parts it owns.
[docs/security-model.md](docs/security-model.md) lists every threat Bastion
defends against, how, which test proves it, and — just as important — the
residual risks and what remains your responsibility when you deploy it.
