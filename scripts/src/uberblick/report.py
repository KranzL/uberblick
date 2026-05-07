from __future__ import annotations

from datetime import datetime
from io import StringIO
from typing import Any

from uberblick.models import Finding, GrantPath


_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def render_findings_markdown(
    findings: list[Finding],
    snapshot_metadata: dict[str, Any] | None = None,
) -> str:
    out = StringIO()
    out.write("# Uberblick Findings Report\n\n")
    if snapshot_metadata:
        out.write(f"- Snapshot: `{snapshot_metadata.get('output_path', 'unknown')}`\n")
        out.write(f"- Captured: `{snapshot_metadata.get('snapshot_at', 'unknown')}`\n")
        out.write(f"- Account: `{snapshot_metadata.get('account', 'unknown')}`\n")
        out.write(f"- Snapshot user: `{snapshot_metadata.get('user', 'unknown')}` "
                  f"as `{snapshot_metadata.get('role', 'unknown')}`\n")
    out.write(f"- Generated: `{datetime.now().isoformat(timespec='seconds')}`\n")
    out.write(f"- Total findings: **{len(findings)}**\n\n")

    by_severity: dict[str, list[Finding]] = {s: [] for s in _SEVERITY_ORDER}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f)

    out.write("## Summary\n\n")
    out.write("| Severity | Count |\n")
    out.write("|----------|-------|\n")
    for sev in _SEVERITY_ORDER:
        count = len(by_severity.get(sev, []))
        if count:
            out.write(f"| {sev} | {count} |\n")
    out.write("\n")

    if not findings:
        out.write("_No findings._\n")
        return out.getvalue()

    for sev in _SEVERITY_ORDER:
        bucket = by_severity.get(sev, [])
        if not bucket:
            continue
        out.write(f"## {sev}\n\n")
        for f in bucket:
            out.write(f"### {f.title}\n\n")
            out.write(f"- **Rule:** `{f.rule_id}`\n")
            out.write(f"- **Category:** `{f.category}`\n")
            out.write(f"\n{f.summary}\n\n")
            if f.evidence:
                out.write("**Evidence:**\n\n")
                out.write("```\n")
                for k, v in f.evidence.items():
                    out.write(f"  {k}: {v}\n")
                out.write("```\n\n")
            if f.remediation:
                out.write(f"**Remediation:**\n\n```sql\n{f.remediation}\n```\n\n")
            out.write("---\n\n")

    return out.getvalue()


def render_paths_markdown(
    title: str,
    paths: list[GrantPath],
) -> str:
    out = StringIO()
    out.write(f"# {title}\n\n")
    out.write(f"- Total paths: **{len(paths)}**\n\n")
    if not paths:
        out.write("_No paths found._\n")
        return out.getvalue()
    by_user: dict[str, list[GrantPath]] = {}
    for p in paths:
        by_user.setdefault(p.source, []).append(p)
    for user, paths_list in by_user.items():
        out.write(f"## {user}\n\n")
        for i, p in enumerate(paths_list, 1):
            out.write(f"{i}. `{p.render()}`\n")
        out.write("\n")
    return out.getvalue()
