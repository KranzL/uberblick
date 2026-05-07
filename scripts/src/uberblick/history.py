from __future__ import annotations

import os
import shutil
from datetime import datetime, timezone
from pathlib import Path


_DEFAULT_KEEP = 30


def history_root() -> Path:
    custom = os.environ.get("UBERBLICK_HISTORY_DIR")
    if custom:
        return Path(custom).resolve()
    return Path.home() / ".uberblick" / "history"


def account_dir(account: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in account)
    return history_root() / safe


def save_to_history(snapshot_path: Path, account: str, sidecar_path: Path | None = None) -> Path:
    snapshot_path = Path(snapshot_path).resolve()
    if not snapshot_path.exists():
        raise FileNotFoundError(f"snapshot not found: {snapshot_path}")
    target_dir = account_dir(account)
    target_dir.mkdir(parents=True, exist_ok=True)
    base_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    timestamp = base_ts
    suffix = 0
    target_path = target_dir / f"{timestamp}.duckdb"
    while target_path.exists():
        suffix += 1
        timestamp = f"{base_ts}-{suffix:02d}"
        target_path = target_dir / f"{timestamp}.duckdb"
    shutil.copy2(snapshot_path, target_path)
    if sidecar_path is None:
        sidecar_path = snapshot_path.parent / f"{snapshot_path.name}.meta.json"
    if sidecar_path.exists():
        shutil.copy2(sidecar_path, target_dir / f"{timestamp}.meta.json")
    return target_path


def list_history(account: str) -> list[Path]:
    d = account_dir(account)
    if not d.exists():
        return []
    snaps = sorted(d.glob("*.duckdb"))
    return snaps


def trim_history(account: str, keep: int = _DEFAULT_KEEP) -> int:
    snaps = list_history(account)
    if len(snaps) <= keep:
        return 0
    to_remove = snaps[: len(snaps) - keep]
    for s in to_remove:
        try:
            s.unlink()
            sidecar = s.parent / f"{s.stem}.meta.json"
            if sidecar.exists():
                sidecar.unlink()
        except OSError:
            pass
    return len(to_remove)


def latest_two(account: str) -> tuple[Path | None, Path | None]:
    snaps = list_history(account)
    if len(snaps) < 2:
        return (None, snaps[-1] if snaps else None)
    return (snaps[-2], snaps[-1])
