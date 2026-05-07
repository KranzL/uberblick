from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from uberblick.classifier import build_roles_with_origin, origin_breakdown
from uberblick.synthetic import generate


@pytest.fixture
def small_snapshot(tmp_path: Path) -> Path:
    output = tmp_path / "small.duckdb"
    generate("small", output)
    return output


def test_classifier_creates_table(small_snapshot: Path) -> None:
    con = duckdb.connect(str(small_snapshot))
    try:
        n = build_roles_with_origin(con)
        assert n > 0
        cols = con.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'roles_with_origin' ORDER BY ordinal_position"
        ).fetchall()
        col_names = [str(c[0]) for c in cols]
        assert "origin" in col_names
        assert "NAME" in col_names
    finally:
        con.close()


def test_system_roles_tagged_system(small_snapshot: Path) -> None:
    con = duckdb.connect(str(small_snapshot))
    try:
        build_roles_with_origin(con)
        rows = con.execute(
            "SELECT NAME, origin FROM roles_with_origin "
            "WHERE NAME IN ('ACCOUNTADMIN', 'SECURITYADMIN', 'SYSADMIN', 'PUBLIC')"
        ).fetchall()
        for r in rows:
            assert str(r[1]) == "system", f"{r[0]} should be system, got {r[1]}"
    finally:
        con.close()


def test_customer_roles_tagged_customer(small_snapshot: Path) -> None:
    con = duckdb.connect(str(small_snapshot))
    try:
        build_roles_with_origin(con)
        rows = con.execute(
            "SELECT NAME FROM roles_with_origin "
            "WHERE origin = 'customer' "
            "ORDER BY NAME LIMIT 5"
        ).fetchall()
        names = [str(r[0]) for r in rows]
        assert names, "expected at least one customer role"
        for name in names:
            assert name not in (
                "ACCOUNTADMIN", "SECURITYADMIN", "SYSADMIN",
                "USERADMIN", "ORGADMIN", "PUBLIC",
            )
    finally:
        con.close()


def test_origin_breakdown_returns_counts(small_snapshot: Path) -> None:
    con = duckdb.connect(str(small_snapshot))
    try:
        build_roles_with_origin(con)
        breakdown = origin_breakdown(con)
        assert breakdown
        origins = {origin for origin, _ in breakdown}
        assert "system" in origins
        assert "customer" in origins
        for origin, count in breakdown:
            assert isinstance(count, int)
            assert count > 0
    finally:
        con.close()
