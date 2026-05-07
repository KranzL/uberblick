from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from uberblick.report_data import (
    compute_admin_reach,
    compute_all_role_impersonation_details,
    compute_policy_protections,
    compute_role_census,
    compute_role_groupings,
    compute_role_impersonation_detail,
    compute_role_impersonation_surface,
    compute_secondary_role_breakdown,
    compute_tag_classifications,
    compute_user_census,
    compute_user_secondary_reach,
    compute_view_summary,
)
from uberblick.synthetic import generate


@pytest.fixture(scope="module")
def realistic_snapshot(tmp_path_factory) -> Path:
    output = tmp_path_factory.mktemp("rd") / "realistic.duckdb"
    generate("realistic", output)
    return output


def test_view_summary_returns_views(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        views = compute_view_summary(con)
    finally:
        con.close()
    assert views
    names = {v["name"] for v in views}
    assert "roles" in names
    assert "users" in names


def test_role_census_has_origin(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        census = compute_role_census(con)
    finally:
        con.close()
    assert census
    sample = census[0]
    assert "name" in sample
    assert "origin" in sample
    assert "user_count" in sample


def test_user_census_includes_flags(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        users = compute_user_census(con)
    finally:
        con.close()
    assert users
    assert any("flags" in u for u in users)
    person_users = [u for u in users if u.get("type") == "PERSON"]
    assert person_users


def test_role_groupings_has_three_bands(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        g = compute_role_groupings(con)
    finally:
        con.close()
    assert "system" in g
    assert "functional" in g
    assert "database_groups" in g
    assert g["system"]
    assert g["database_groups"]


def test_impersonation_surface_per_role(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        surface = compute_role_impersonation_surface(con)
    finally:
        con.close()
    assert surface
    customer_roles = [r for r in surface if r["origin"] == "customer"]
    assert customer_roles


def test_impersonation_detail_for_specific_role(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        names = con.execute(
            "SELECT NAME FROM roles_with_origin WHERE origin = 'customer' LIMIT 1"
        ).fetchall()
        assert names
        target = str(names[0][0])
        detail = compute_role_impersonation_detail(con, target)
    finally:
        con.close()
    assert detail.get("role") == target
    assert "inherited_roles" in detail
    assert "object_grants" in detail


def test_all_role_impersonation_details_keyed_by_role(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        details = compute_all_role_impersonation_details(con)
    finally:
        con.close()
    assert details
    sample_role = next(iter(details))
    assert "inherited_roles" in details[sample_role]


def test_secondary_role_breakdown(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        breakdown = compute_secondary_role_breakdown(con)
    finally:
        con.close()
    assert breakdown
    sample = breakdown[0]
    assert "user" in sample
    assert "role" in sample
    assert "unique_priv_count" in sample


def test_user_secondary_reach(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        reach = compute_user_secondary_reach(con)
    finally:
        con.close()
    assert reach
    expanded = [r for r in reach if r["delta"] > 0]
    assert expanded


def test_admin_reach(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        reach = compute_admin_reach(con)
    finally:
        con.close()
    assert isinstance(reach, list)


def test_policy_protections_loaded(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        prot = compute_policy_protections(con)
    finally:
        con.close()
    assert "tables" in prot
    assert "columns" in prot


def test_tag_classifications_loaded(realistic_snapshot: Path) -> None:
    con = duckdb.connect(str(realistic_snapshot), read_only=True)
    try:
        tags = compute_tag_classifications(con)
    finally:
        con.close()
    assert "tables" in tags
    assert "columns" in tags
    assert tags["columns"]
