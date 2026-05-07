from __future__ import annotations

import os
from pathlib import Path

import pytest

from uberblick.history import (
    account_dir,
    history_root,
    latest_two,
    list_history,
    save_to_history,
    trim_history,
)


@pytest.fixture
def isolated_history(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv("UBERBLICK_HISTORY_DIR", str(tmp_path / "history"))
    return tmp_path / "history"


def test_history_root_uses_env_var(isolated_history: Path) -> None:
    assert history_root().resolve() == isolated_history.resolve()


def test_account_dir_sanitizes_name(isolated_history: Path) -> None:
    d = account_dir("Account/With/Slashes")
    assert "/" not in d.name
    assert d.parent.resolve() == isolated_history.resolve()


def test_save_and_list_history(isolated_history: Path, tmp_path: Path) -> None:
    snap = tmp_path / "snapshot.duckdb"
    snap.write_bytes(b"fake-duckdb-content")
    saved = save_to_history(snap, "TEST_ACCOUNT")
    assert saved.exists()
    assert saved.parent.resolve() == account_dir("TEST_ACCOUNT").resolve()
    snaps = list_history("TEST_ACCOUNT")
    assert len(snaps) == 1


def test_trim_history(isolated_history: Path, tmp_path: Path) -> None:
    snap = tmp_path / "snapshot.duckdb"
    snap.write_bytes(b"x")
    for _ in range(5):
        save_to_history(snap, "TEST")
    snaps = list_history("TEST")
    assert len(snaps) == 5
    removed = trim_history("TEST", keep=3)
    assert removed == 2
    assert len(list_history("TEST")) == 3


def test_latest_two(isolated_history: Path, tmp_path: Path) -> None:
    snap = tmp_path / "snapshot.duckdb"
    snap.write_bytes(b"x")
    for _ in range(3):
        save_to_history(snap, "TEST_LT")
    prev, curr = latest_two("TEST_LT")
    assert prev is not None
    assert curr is not None
    assert prev.stat().st_mtime <= curr.stat().st_mtime


def test_latest_two_empty(isolated_history: Path) -> None:
    prev, curr = latest_two("NONEXISTENT")
    assert prev is None
    assert curr is None
