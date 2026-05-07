# Changelog

All notable changes to Überblick are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-05-07

### Added

- 26 finding rules covering structural anti-patterns, secondary-role risk, behavioral signals, and hygiene issues
- 5 audit packs with mapped control references: CIS Snowflake Foundations, SOC2 CC6, SOX ITGC, HIPAA §164.312, UNC5537 (2024 breach lessons)
- Snapshot pipeline pulling 18 `ACCOUNT_USAGE` views into local DuckDB with cycle-safe role hierarchy closure and origin classification
- `--live` mode using real-time `SHOW` commands when `ACCOUNT_USAGE` lag is unacceptable
- Static HTML report (single self-contained file) with 10 cross-linked sections:
  - Snapshot inventory with per-view freshness
  - Findings (grouped by rule, expandable, with audit-pack badges)
  - Privileged reach
  - Direct user grants
  - Path Finder (interactive client-side, substring search)
  - Role Impersonation (per-role full surface)
  - Secondary Roles (per-user privilege expansion breakdown)
  - User Census (sortable, expandable rows)
  - Role Census (sortable, searchable)
  - Role Atlas (3-band stratigraphic layout: system / functional / database groups)
- Time-series diff between snapshots (`uberblick diff`) with auto-pull of latest two from history
- Snapshot history (`~/.uberblick/history/<account>/`) with configurable retention
- Synthetic data generator (`uberblick synthetic`) with 5 profiles (small/medium/realistic/large/huge) and dimensional overrides (`--users`, `--functional`, `--databases`, `--schemas-total`, `--tables-per-schema`); seeds policy/tag references and toxic role combinations
- Tag-based masking and row-access policy badges on path-finder + impersonation results
- Atlas → impersonation handoff (click any role for "→ Impersonate this role" link)
- User Census row expansion → click user → see direct roles → click role to impersonate
- 13 pytest smoke tests covering synthetic generation, findings rule execution, audit pack filtering, and diff
- Engineering-specification HTML aesthetic via `frontend-design` skill: cream paper background, oxide accents, serif typography with monospace data, dot-leader evidence formatting
- audit super-command (orchestrates snapshot + report in one step)
- Slack Block Kit integration with digest and alert modes
- HRIS CSV overlay for joiner/leaver tagging
- snapshot history + diff command for tracking changes between runs
- user blast radius view (per-user reachable object surface)
- secondary-role analytics (USE SECONDARY ROLES coverage)
- policy and tag classifications in atlas
- 54 pytest tests (up from 13)

### Fixed

- network_policies extractor: removed non-existent DELETED_ON column reference
- authentication_policies extractor: removed non-existent DELETED_ON column reference
- first_time_admin_activation rule: now requires 60-day baseline window to suppress greenfield false positives

### Changed

- Version bumped to 1.0.0 with Production/Stable classifier
- Python 3.10–3.13 officially supported (CI matrix)
- Released to PyPI as `uberblick`

### Design principles (locked in `CLAUDE.md`)

- Group by what roles DO (grant graph), not by what they're called
- Don't bake any specific consultancy or dbt model into the tool as default
- Scale targets: 500+ roles, 400K+ grants, 5K+ users
- Read-only forever; remediation is structured proposals only
- Snowflake-only; no cross-warehouse support

[Unreleased]: https://github.com/KranzL/uberblick/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/KranzL/uberblick/releases/tag/v1.0.0
