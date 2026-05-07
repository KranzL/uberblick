from __future__ import annotations

from pathlib import Path

from uberblick.diff import compute_diff
from uberblick.synthetic import generate


def test_diff_identical_snapshots(tmp_path: Path) -> None:
    a = tmp_path / "a.duckdb"
    b = tmp_path / "b.duckdb"
    generate("small", a, seed=42)
    generate("small", b, seed=42)
    d = compute_diff(a, b)
    assert d.added_roles == []
    assert d.removed_roles == []
    assert d.added_users == []
    assert d.removed_users == []
    assert d.added_user_role_grants == []
    assert d.removed_user_role_grants == []


def test_diff_different_seeds_produces_changes(tmp_path: Path) -> None:
    a = tmp_path / "a.duckdb"
    b = tmp_path / "b.duckdb"
    generate("small", a, seed=42)
    generate("small", b, seed=43)
    d = compute_diff(a, b)
    total_user_grant_changes = (
        len(d.added_user_role_grants) + len(d.removed_user_role_grants)
    )
    assert total_user_grant_changes > 0


def test_diff_metadata_present(tmp_path: Path) -> None:
    a = tmp_path / "a.duckdb"
    b = tmp_path / "b.duckdb"
    generate("small", a, seed=42)
    generate("small", b, seed=43)
    d = compute_diff(a, b)
    assert d.from_path.endswith("a.duckdb")
    assert d.to_path.endswith("b.duckdb")
    assert d.from_at is not None
    assert d.to_at is not None
