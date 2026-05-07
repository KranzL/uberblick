from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from uberblick.closure import build_role_closure
from uberblick.synthetic import generate


@pytest.fixture
def small_snapshot(tmp_path: Path) -> Path:
    output = tmp_path / "small.duckdb"
    generate("small", output)
    return output


def test_closure_includes_self_at_depth_zero(small_snapshot: Path) -> None:
    con = duckdb.connect(str(small_snapshot))
    try:
        build_role_closure(con)
        rows = con.execute(
            "SELECT root_role, reachable_role, depth "
            "FROM role_closure WHERE depth = 0 LIMIT 5"
        ).fetchall()
        for r in rows:
            assert r[0] == r[1], "depth 0 entries must be self-referential"
    finally:
        con.close()


def test_closure_has_edges(small_snapshot: Path) -> None:
    con = duckdb.connect(str(small_snapshot))
    try:
        stats = build_role_closure(con)
        assert stats.edges > 0
        assert stats.max_depth_observed >= 1
    finally:
        con.close()


def test_closure_depth_cap_honored(small_snapshot: Path) -> None:
    con = duckdb.connect(str(small_snapshot))
    try:
        stats = build_role_closure(con, depth_cap=2)
        max_depth = con.execute(
            "SELECT MAX(depth) FROM role_closure"
        ).fetchone()[0]
        assert max_depth is not None
        assert max_depth <= 2
        assert stats.depth_cap == 2
    finally:
        con.close()


def test_closure_no_cycles_in_path(small_snapshot: Path) -> None:
    con = duckdb.connect(str(small_snapshot))
    try:
        build_role_closure(con)
        rows = con.execute(
            "SELECT root_role, reachable_role, path FROM role_closure "
            "WHERE depth > 0 LIMIT 50"
        ).fetchall()
        for r in rows:
            path = list(r[2]) if r[2] else []
            assert len(path) == len(set(path)), "path contains duplicates (cycle)"
    finally:
        con.close()
