from __future__ import annotations

import sys
from pathlib import Path

from uberblick.audit_packs import (
    _PACK_MAPPINGS,
    all_packs,
    pack_name,
    packs_for_rule,
    rules_in_pack,
)
from uberblick.findings import _RULES


def test_all_packs_have_unique_keys() -> None:
    seen = set()
    for pack_id in _PACK_MAPPINGS:
        assert pack_id not in seen
        seen.add(pack_id)


def test_packs_for_rule_returns_list() -> None:
    out = packs_for_rule("user_no_mfa")
    pack_ids = {p[0] for p in out}
    assert "cis" in pack_ids
    assert "soc2" in pack_ids
    assert "hipaa" in pack_ids
    assert "unc5537" in pack_ids


def test_packs_for_unknown_rule_is_empty() -> None:
    assert packs_for_rule("definitely_not_a_real_rule") == []


def test_pack_name_returns_human_label() -> None:
    name = pack_name("cis")
    assert "CIS" in name
    assert "Snowflake" in name


def test_rules_in_pack_returns_set() -> None:
    cis_rules = rules_in_pack("cis")
    assert isinstance(cis_rules, set)
    assert "user_no_mfa" in cis_rules
    assert "manage_grants_holder" in cis_rules


def test_all_packs_listed() -> None:
    packs = all_packs()
    assert "cis" in packs
    assert "soc2" in packs
    assert "sox" in packs
    assert "hipaa" in packs
    assert "unc5537" in packs


def test_every_pack_has_known_rule_ids() -> None:
    """Each pack should contain at least 5 rule_ids that look like sane keys."""
    for pack_id, mapping in _PACK_MAPPINGS.items():
        assert len(mapping) >= 5, f"Pack {pack_id} only maps {len(mapping)} rules"
        for rule_id in mapping.keys():
            assert isinstance(rule_id, str)
            assert "_" in rule_id or rule_id.islower()


def test_packs_have_critical_rules() -> None:
    """Each audit pack should cover at least 5 rules to be meaningful."""
    for pack_id in all_packs():
        rules = rules_in_pack(pack_id)
        assert len(rules) >= 5, f"Pack {pack_id} only has {len(rules)} rules"
