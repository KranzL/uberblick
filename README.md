# Überblick

A read-only Snowflake role and access auditor. Sibling project to [einblick](https://github.com/KranzL/einblick).

[![tests](https://img.shields.io/github/actions/workflow/status/KranzL/uberblick/test.yml?branch=main&label=tests)](https://github.com/KranzL/uberblick/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/uberblick.svg)](https://pypi.org/project/uberblick/)
[![Python versions](https://img.shields.io/pypi/pyversions/uberblick.svg)](https://pypi.org/project/uberblick/)
[![License](https://img.shields.io/github/license/KranzL/uberblick.svg)](LICENSE)

Point it at a Snowflake account, get a self-contained HTML report that answers the questions your security team and platform engineers ask repeatedly: who can read what, what does this role actually grant, who's over-privileged, what changed since last week.

> **See it in action:** [Live demo report](https://kranzl.github.io/uberblick/demo/) (synthetic data, regenerated weekly)

## Install

```bash
pip install uberblick
```

The reader role needs `IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE` and a small warehouse. A minimal setup script is in [`examples/setup.sql`](examples/setup.sql) — copy, edit the password, run as `ACCOUNTADMIN`.

## Screenshots

![Findings panel grouped by rule with audit-pack badges and severity](docs/img/findings.png)

![Role Atlas focus mode showing inherited roles, granted-to roles, and object grants](docs/img/atlas.png)

![User Blast Radius listing every reachable object for a single user](docs/img/blast-radius.png)

## Quick start

```bash
uberblick verify
uberblick snapshot --output snap.duckdb
uberblick report --snapshot snap.duckdb --output report.html
```

`uberblick audit` runs all three in one shot and writes `snapshot.duckdb`, `findings.json`, and `report.html` into the current directory.

To try it without a Snowflake account, generate a synthetic snapshot:

```bash
uberblick synthetic --profile realistic --output sample.duckdb
uberblick report --snapshot sample.duckdb --output sample.html
open sample.html
```

Profiles: `small` (12 schemas), `medium` (50), `realistic` (100), `large` (120), `huge` (240). Override any dimension with `--users`, `--functional`, `--databases`, `--schemas-total`, `--tables-per-schema`. Synthetic seeds masking policies, tags, service accounts, and toxic role combinations so the badges and findings render as they would on a real account.

## What it does

Pulls 18 `SNOWFLAKE.ACCOUNT_USAGE` views into a local DuckDB snapshot, computes a cycle-safe role hierarchy closure, classifies role origins (Snowflake-shipped / system / functional / customer), and generates a single self-contained HTML report.

- 26 finding rules covering structural anti-patterns, secondary-role risk, behavioral signals, and hygiene
- 5 audit packs with mapped control references: CIS Snowflake Foundations, SOC2 CC6, SOX ITGC, HIPAA §164.312, UNC5537 (2024 breach lessons)
- Role Atlas: 3-band stratigraphic layout (system / functional / database groups). At 500+ roles the customer band collapses to database-level group nodes by default; click to drill in
- Role impersonation: type any role name, see its full inherited surface plus every object grant and every user holding it, without granting it to yourself
- User blast radius: per-user list of every reachable object across all primary and secondary roles
- Secondary-roles analytics: per-user breakdown of which role contributes which unique privilege under `USE SECONDARY ROLES ALL`
- Path Finder: client-side substring search resolving any user-to-object grant chain
- Snapshot diff: added/removed roles, users, grants, MFA toggles, default-role changes between any two snapshots
- Policy/tag awareness: masking, row-access, and aggregation policies surface as badges on grants in path-finder and impersonation views
- Slack Block Kit integration with digest and alert modes; HRIS CSV overlay for joiner/leaver tagging

Output is one HTML file (~5 MB at large scale). No CDN, no telemetry, no live API calls — everything baked in at build time.

## Two deployment paths

**Local.** The `.duckdb` snapshot stays on your laptop in `~/.uberblick/history/`. You open `report.html` in a browser. Nothing leaves your machine.

**Scheduled.** A GitHub Actions cron runs `uberblick audit` in CI's ephemeral filesystem. Snapshot is a workflow artifact (auto-deletes); only the HTML report goes to `gh-pages`. Raw grant data never enters git.

## What it explicitly is not

These are permanent design decisions, not roadmap items.

- **Not multi-warehouse.** Snowflake-only. No Databricks, no Redshift, no BigQuery.
- **Read-only forever.** No provisioning, no remediation auto-apply. Findings include structured remediation proposals as text.
- **Not a SaaS.** Free OSS only. There is no hosted version.
- **Not an IGA workflow tool.** No UAR campaigns, no email reminders, no ticket integrations. ConductorOne and Drata cover that lane.
- **Not a runtime enforcer.** No inline query proxy, no policy engine. Satori covers that lane.

## Architecture

```
scripts/src/uberblick/
├── connector.py          Snowflake connection
├── extractor.py          ACCOUNT_USAGE pulls
├── live_extractor.py     SHOW commands fallback (--live mode)
├── snapshot.py           Orchestration + DuckDB persistence
├── classifier.py         Role origin classification
├── closure.py            Cycle-safe role hierarchy closure
├── findings.py           26 rules
├── audit_packs.py        CIS / SOC2 / SOX / HIPAA / UNC5537 mappings
├── paths.py              Path-finder
├── diff.py               Snapshot diff
├── history.py            Snapshot history management
├── report_data.py        Report computations
├── report_html.py        HTML template + JS
├── synthetic.py          Test fixture generator
└── cli.py                Click CLI
```

Snapshots are DuckDB files. Closure and classifier are derived tables computed inside the snapshot. A `.meta.json` sidecar lives next to each snapshot.

## Design principles

1. Group by what roles **do** (grant graph), not by what they're **called**. Two roles touching the same schema with the same privilege envelope are functionally equivalent regardless of name. No naming-regex grouping as the primary mechanism.
2. Don't bake any specific consultancy or dbt model into the tool as default. dbt's three-role pattern is dbt-specific, not Snowflake-general.
3. Most published Snowflake-RBAC content is vendor or consultancy marketing. Practitioner-grounded sources (Veza customer audits, Mandiant UNC5537 postmortem, sfgrantreport README) describe production reality.
4. Scale targets: 500+ roles, 400K+ grants, 5K+ users. All views must remain usable at that scale.
5. Read-only forever. Remediation is structured proposals only.

## Links

- [CHANGELOG.md](CHANGELOG.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [LICENSE](LICENSE)
