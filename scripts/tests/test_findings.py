from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from uberblick.findings import _RULES, run_rules
from uberblick.synthetic import generate


@pytest.fixture(scope="module")
def realistic_snapshot(tmp_path_factory) -> Path:
    output = tmp_path_factory.mktemp("data") / "realistic.duckdb"
    generate("realistic", output)
    return output


def test_rules_run_without_crashing(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        results = run_rules(con)
    finally:
        con.close()
    info_findings = [f for f in results if f.severity == "INFO"]
    failed_rules = [f.rule_id for f in info_findings if "failed" in f.title.lower()]
    assert not failed_rules, f"Rules crashed: {failed_rules}"


def test_secondary_role_expansion_fires(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        results = run_rules(con)
    finally:
        con.close()
    sec = [f for f in results if f.rule_id == "secondary_role_expansion"]
    assert len(sec) > 0


def test_user_no_mfa_fires(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        results = run_rules(con)
    finally:
        con.close()
    mfa = [f for f in results if f.rule_id == "user_no_mfa"]
    assert len(mfa) > 0


def test_audit_pack_filtering(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        cis = run_rules(con, audit_pack="cis")
        unc = run_rules(con, audit_pack="unc5537")
        all_results = run_rules(con)
    finally:
        con.close()
    assert len(cis) > 0
    assert len(unc) > 0
    assert len(cis) <= len(all_results)


def test_findings_have_audit_pack_metadata(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        results = run_rules(con)
    finally:
        con.close()
    mfa = [f for f in results if f.rule_id == "user_no_mfa"]
    assert mfa
    f = mfa[0]
    pack_ids = {p["pack"] for p in f.audit_packs}
    assert "cis" in pack_ids
    assert "unc5537" in pack_ids


def test_rule_count_stable() -> None:
    assert len(_RULES) >= 25
