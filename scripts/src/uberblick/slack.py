from __future__ import annotations

import json
import urllib.request
from collections import Counter
from typing import Any

from uberblick.models import Finding


_SEVERITY_EMOJI = {
    "CRITICAL": ":rotating_light:",
    "HIGH": ":warning:",
    "MEDIUM": ":large_yellow_circle:",
    "LOW": ":large_blue_circle:",
    "INFO": ":white_circle:",
}


def build_block_kit_payload(
    findings: list[Finding],
    snapshot_meta: dict[str, Any] | None = None,
    audit_pack: str | None = None,
    report_url: str | None = None,
) -> dict[str, Any]:
    by_sev = Counter(f.severity for f in findings)
    account = (snapshot_meta or {}).get("account", "unknown")
    captured = (snapshot_meta or {}).get("snapshot_at", "unknown")

    blocks: list[dict[str, Any]] = []
    title = "Uberblick findings"
    if audit_pack:
        title = f"{title} ({audit_pack.upper()})"
    blocks.append(
        {
            "type": "header",
            "text": {"type": "plain_text", "text": title},
        }
    )
    blocks.append(
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Account*\n`{account}`"},
                {"type": "mrkdwn", "text": f"*Captured*\n`{captured}`"},
                {"type": "mrkdwn", "text": f"*Total findings*\n{len(findings)}"},
                {
                    "type": "mrkdwn",
                    "text": "*Severity*\n"
                    + ", ".join(
                        f"{_SEVERITY_EMOJI.get(s, '')} {s}: {by_sev[s]}"
                        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                        if by_sev.get(s, 0)
                    ),
                },
            ],
        }
    )

    rule_groups: dict[str, list[Finding]] = {}
    for f in findings:
        rule_groups.setdefault(f.rule_id, []).append(f)
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_groups = sorted(
        rule_groups.items(),
        key=lambda kv: (severity_rank.get(kv[1][0].severity, 5), -len(kv[1])),
    )

    if sorted_groups:
        blocks.append({"type": "divider"})
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Top rule groups*"},
            }
        )
        for rule_id, items in sorted_groups[:8]:
            sample = items[0]
            emoji = _SEVERITY_EMOJI.get(sample.severity, "")
            text = (
                f"{emoji} *{sample.severity}* `{rule_id}` "
                f"- {len(items)} finding(s)\n  _{sample.title[:200]}_"
            )
            blocks.append(
                {"type": "section", "text": {"type": "mrkdwn", "text": text}}
            )

    if report_url:
        blocks.append({"type": "divider"})
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"<{report_url}|Open full HTML report>"}
                ],
            }
        )

    return {"text": title, "blocks": blocks}


def post_to_slack(webhook_url: str, payload: dict[str, Any]) -> tuple[int, str]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"
