from __future__ import annotations

from pathlib import Path

import duckdb
import pytest

from uberblick.paths import find_paths_to_object, find_paths_user_to_object
from uberblick.synthetic import generate


@pytest.fixture(scope="module")
def small_snapshot(tmp_path_factory) -> Path:
    output = tmp_path_factory.mktemp("paths") / "small.duckdb"
    generate("small", output)
    return output


def test_paths_from_user_returns_results(small_snapshot: Path) -> None:
    con = duckdb.connect(str(small_snapshot), read_only=True)
    try:
        users = con.execute(
            "SELECT GRANTEE_NAME FROM grants_to_users LIMIT 1"
        ).fetchall()
        assert users
        user = str(users[0][0])
        databases = con.execute(
            "SELECT DISTINCT NAME FROM grants_to_roles "
            "WHERE GRANTED_ON = 'DATABASE' LIMIT 1"
        ).fetchall()
        assert databases
        db = str(databases[0][0])
    finally:
        con.close()
    con = duckdb.connect(str(small_snapshot), read_only=True)
    try:
        paths = find_paths_user_to_object(con, user, db, limit=10)
    finally:
        con.close()
    if paths:
        for p in paths:
            assert p.source == user
            assert p.privilege


def test_paths_to_object_finds_users(small_snapshot: Path) -> None:
    con = duckdb.connect(str(small_snapshot), read_only=True)
    try:
        databases = con.execute(
            "SELECT DISTINCT NAME FROM grants_to_roles "
            "WHERE GRANTED_ON = 'DATABASE' LIMIT 1"
        ).fetchall()
        assert databases
        db = str(databases[0][0])
        paths = find_paths_to_object(con, db, limit=20)
    finally:
        con.close()
    if paths:
        users = {p.source for p in paths}
        assert users
        for p in paths:
            assert p.destination


def test_paths_unknown_user_returns_empty(small_snapshot: Path) -> None:
    con = duckdb.connect(str(small_snapshot), read_only=True)
    try:
        paths = find_paths_user_to_object(con, "NO_SUCH_USER", "ANY", limit=5)
    finally:
        con.close()
    assert paths == []
