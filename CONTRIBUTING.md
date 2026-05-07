# Contributing to Überblick

Thanks for considering a contribution. Überblick is a small, opinionated tool — bug reports, finding rules, and report-UX improvements are especially welcome.

## Dev environment

```bash
git clone https://github.com/KranzL/uberblick
cd uberblick
python3 -m venv .venv
.venv/bin/pip install -e "./scripts[dev]"
```

Required: Python 3.10+. The CI matrix runs 3.10–3.13 — please make sure your change doesn't depend on a newer language feature.

## Running tests

```bash
.venv/bin/pytest scripts/tests/ -q
```

The test suite is fast (under 5s) and uses the synthetic generator — no Snowflake account required.

## Trying changes against synthetic data

```bash
.venv/bin/uberblick synthetic --profile realistic --output /tmp/snap.duckdb
.venv/bin/uberblick report --snapshot /tmp/snap.duckdb --output /tmp/report.html
open /tmp/report.html
```

Available profiles: `small` (12 schemas), `medium` (50), `realistic` (100), `large` (120), `huge` (240).

## Trying changes against a real Snowflake account

Create a `.env` from `.env.example`. The minimum role setup is in `examples/setup.sql`.

```bash
.venv/bin/uberblick verify
.venv/bin/uberblick snapshot --output snap.duckdb
```

## Code style

Pinned in `CLAUDE.md`:

- No code comments. Use clear identifiers and tight functions.
- No emojis in source, output, or docs.
- New rules go in `findings.py` and must be mapped into one or more packs in `audit_packs.py`.
- Group by what roles **do** (grant graph), not what they're **called** (no name regex as primary signal).

## Submitting a PR

1. Open an issue first for non-trivial changes so we can align on scope.
2. Add tests under `scripts/tests/`. Aim for one test per new finding rule and one test per new public function.
3. Update `CHANGELOG.md` under `[Unreleased]`. Follow the existing format.
4. Keep PRs focused — one concern per PR.
5. CI must pass on all four Python versions.

## What's out of scope

These are permanent decisions, not roadmap items:

- Cross-warehouse support (Snowflake-only by design)
- Provisioning / write actions (read-only forever)
- Hosted SaaS
- IGA workflow features (UAR campaigns, ticketing, etc.)

## Reporting security issues

See `SECURITY.md`. Please do **not** open a public issue for security reports.
