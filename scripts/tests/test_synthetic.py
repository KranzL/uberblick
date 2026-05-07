from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from uberblick.synthetic import generate


def test_synthetic_small_generates(tmp_path: Path) -> None:
    output = tmp_path / "small.duckdb"
    counts = generate("small", output)
    assert output.exists()
    assert counts["roles"] > 0
    assert counts["users"] > 0
    assert counts["grants_to_roles"] > 0


def test_synthetic_realistic_dimensions(tmp_path: Path) -> None:
    output = tmp_path / "realistic.duckdb"
    counts = generate("realistic", output)
    assert counts["roles"] >= 200
    assert counts["users"] >= 800
    con = duckdb.connect(str(output), read_only=True)
    grant_count = con.execute(
        "SELECT COUNT(*) FROM grants_to_roles"
    ).fetchone()[0]
    assert grant_count > 1000
    con.close()


def test_synthetic_overrides(tmp_path: Path) -> None:
    output = tmp_path / "custom.duckdb"
    counts = generate(
        "small",
        output,
        overrides={"users": 25, "functional": 5, "databases": 2,
                   "schemas_total": 4, "tables_per_schema": 3},
    )
    assert counts["users"] == 25 + 2  # 25 + ETL_FIVETRAN_SVC + LEGACY_LOOKER
    con = duckdb.connect(str(output), read_only=True)
    rows = con.execute("SELECT COUNT(DISTINCT NAME) FROM roles WHERE OWNER = 'USERADMIN'").fetchone()[0]
    assert rows == 5 + 4 * 2
    con.close()


def test_synthetic_seeds_policies_and_tags(tmp_path: Path) -> None:
    output = tmp_path / "policies.duckdb"
    generate("realistic", output)
    con = duckdb.connect(str(output), read_only=True)
    pol_count = con.execute("SELECT COUNT(*) FROM policy_references").fetchone()[0]
    tag_count = con.execute("SELECT COUNT(*) FROM tag_references").fetchone()[0]
    con.close()
    assert pol_count > 0
    assert tag_count > 0
