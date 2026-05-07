from __future__ import annotations

from uberblick.models import Finding
from uberblick.slack import build_block_kit_payload


def test_slack_payload_empty_findings() -> None:
    payload = build_block_kit_payload([], snapshot_meta={"account": "X", "snapshot_at": "T"})
    assert payload["text"] == "Uberblick findings"
    assert any(b.get("type") == "header" for b in payload["blocks"])


def test_slack_payload_with_findings() -> None:
    findings = [
        Finding(
            rule_id="user_no_mfa",
            severity="HIGH",
            category="authentication",
            title="Human user X has no MFA",
            summary="User X needs MFA",
        ),
        Finding(
            rule_id="user_no_mfa",
            severity="HIGH",
            category="authentication",
            title="Human user Y has no MFA",
            summary="User Y needs MFA",
        ),
        Finding(
            rule_id="accountadmin_concentration",
            severity="CRITICAL",
            category="privileged_access",
            title="Too many ACCOUNTADMIN holders",
            summary="...",
        ),
    ]
    payload = build_block_kit_payload(findings, snapshot_meta={"account": "X"})
    text = str(payload)
    assert "CRITICAL" in text
    assert "HIGH" in text
    assert "user_no_mfa" in text
    assert "accountadmin_concentration" in text


def test_slack_payload_audit_pack_in_title() -> None:
    payload = build_block_kit_payload([], audit_pack="cis")
    assert "CIS" in payload["text"]


def test_slack_payload_includes_report_url() -> None:
    payload = build_block_kit_payload([], report_url="https://example.com/r.html")
    text = str(payload)
    assert "example.com" in text
