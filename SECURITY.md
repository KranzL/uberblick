# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a vulnerability

If you discover a vulnerability in Überblick itself, please report it privately.

**Preferred:** Open a [GitHub Security Advisory](https://github.com/KranzL/uberblick/security/advisories/new) for this repository.

**Alternate:** Email `luke.kranz.ucf@gmail.com` with the subject line `[uberblick security]`.

Include:
- A description of the issue and its impact.
- Steps to reproduce, ideally against the synthetic data generator (`uberblick synthetic`) so no real Snowflake account is involved.
- The version of Überblick and Python you're running.

You can expect:
- An acknowledgement within 72 hours.
- A fix or mitigation plan within 14 days for confirmed vulnerabilities.
- Credit in the changelog and release notes (unless you'd prefer to remain anonymous).

## Scope

**In scope:**
- Code execution, credential leakage, or privilege escalation in the Überblick CLI or library code.
- Vulnerabilities in the generated HTML report (XSS, exfiltration via the baked-in JSON, etc.).
- Issues in the snapshot extractors that could leak Snowflake credentials or data.
- Supply-chain issues with the published PyPI package.

**Out of scope:**
- Misconfigurations Überblick *surfaces* in your Snowflake account. Those are findings, not vulnerabilities in Überblick — fix them in Snowflake.
- Denial-of-service from feeding the tool extreme inputs (e.g. 10M-row synthetic snapshots). Performance issues are welcome as regular bug reports.
- Vulnerabilities in upstream dependencies that don't affect Überblick's exposed surface.

## Disclosure

After a fix is released, we'll publish a security advisory on the repository describing the issue, affected versions, and the fixed version. Coordinated disclosure timeline is negotiable based on severity.
