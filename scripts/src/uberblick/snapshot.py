from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb

from uberblick.classifier import build_roles_with_origin, origin_breakdown
from uberblick.closure import DEFAULT_DEPTH_CAP, build_role_closure
from uberblick.extractor import (
    ViewExtraction,
    all_specs,
    documented_max_lag_minutes,
    extract,
    extract_account_parameters,
)
from uberblick.live_extractor import (
    extract_grants_to_roles_live,
    extract_grants_to_users_live,
    extract_roles_live,
    extract_users_live,
)


@dataclass
class SnapshotResult:
    output_path: str
    snapshot_at: str
    account: str
    user: str
    role: str
    lookback_days: int
    views: dict[str, dict[str, Any]] = field(default_factory=dict)
    role_origin_breakdown: list[tuple[str, int]] = field(default_factory=list)
    closure_edges: int = 0
    closure_max_depth: int = 0
    closure_depth_cap: int = DEFAULT_DEPTH_CAP


def _account_context(conn: Any) -> tuple[str, str, str]:
    cur = conn.cursor()
    try:
        cur.execute(
            "SELECT CURRENT_ACCOUNT(), CURRENT_USER(), CURRENT_ROLE()"
        )
        row = cur.fetchone()
        return str(row[0]), str(row[1]), str(row[2])
    finally:
        cur.close()


_LIVE_OVERRIDES = ("roles", "users", "grants_to_roles", "grants_to_users")


def _build_live_view(
    conn: Any, view_name: str, role_names: list[str], user_names: list[str]
):
    if view_name == "roles":
        return extract_roles_live(conn)
    if view_name == "users":
        return extract_users_live(conn)
    if view_name == "grants_to_roles":
        return extract_grants_to_roles_live(conn, role_names)
    if view_name == "grants_to_users":
        return extract_grants_to_users_live(conn, user_names)
    return None


def run_snapshot(
    conn: Any,
    output_path: Path,
    days: int = 30,
    depth_cap: int = DEFAULT_DEPTH_CAP,
    on_view_start: Any = None,
    on_view_done: Any = None,
    on_phase: Any = None,
    live: bool = False,
) -> SnapshotResult:
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.exists():
        output_path.unlink()

    account, user, role = _account_context(conn)
    snapshot_at = datetime.now(timezone.utc).isoformat()

    result = SnapshotResult(
        output_path=str(output_path),
        snapshot_at=snapshot_at,
        account=account,
        user=user,
        role=role,
        lookback_days=days,
        closure_depth_cap=depth_cap,
    )

    duck = duckdb.connect(str(output_path))
    try:
        duck.execute(
            "CREATE TABLE snapshot_metadata ("
            "snapshot_at TIMESTAMPTZ, account VARCHAR, snapshot_user VARCHAR, "
            "snapshot_role VARCHAR, lookback_days INTEGER, depth_cap INTEGER"
            ")"
        )
        duck.execute(
            "INSERT INTO snapshot_metadata VALUES (?, ?, ?, ?, ?, ?)",
            [snapshot_at, account, user, role, days, depth_cap],
        )
        duck.execute(
            "CREATE TABLE snapshot_views ("
            "name VARCHAR, rows INTEGER, "
            "minutes_since_latest_record INTEGER, "
            "documented_max_lag_minutes INTEGER, "
            "error VARCHAR"
            ")"
        )

        if on_phase:
            on_phase("extract" if not live else "extract (live mode)")

        live_role_names: list[str] = []
        live_user_names: list[str] = []
        if live:
            roles_table = extract_roles_live(conn)
            if roles_table is not None and roles_table.num_columns > 0:
                names = roles_table.column("NAME").to_pylist()
                live_role_names = [n for n in names if n]
            users_table = extract_users_live(conn)
            if users_table is not None and users_table.num_columns > 0:
                names = users_table.column("NAME").to_pylist()
                live_user_names = [n for n in names if n]

        for spec in all_specs(days=days):
            if on_view_start:
                on_view_start(spec.name)

            extraction: ViewExtraction
            if live and spec.name in _LIVE_OVERRIDES:
                try:
                    live_table = _build_live_view(
                        conn, spec.name, live_role_names, live_user_names
                    )
                    extraction = ViewExtraction(
                        name=spec.name,
                        rows=live_table.num_rows if live_table is not None else 0,
                        minutes_since_latest_record=0,
                        table=live_table,
                        error=None,
                    )
                except Exception as e:
                    extraction = ViewExtraction(
                        name=spec.name,
                        rows=0,
                        minutes_since_latest_record=None,
                        table=None,
                        error=f"live: {type(e).__name__}: {e}",
                    )
            elif live and spec.name in (
                "login_history",
                "query_history",
                "access_history",
                "policy_references",
                "tag_references",
                "object_dependencies",
            ):
                extraction = ViewExtraction(
                    name=spec.name,
                    rows=0,
                    minutes_since_latest_record=None,
                    table=None,
                    error="skipped in --live mode",
                )
            else:
                extraction = extract(conn, spec)

            if (
                extraction.table is not None
                and extraction.table.num_columns > 0
            ):
                arrow_tbl = extraction.table
                duck.register("_uberblick_tmp_arrow", arrow_tbl)
                duck.execute(
                    f'CREATE TABLE "{spec.name}" AS '
                    f"SELECT * FROM _uberblick_tmp_arrow"
                )
                duck.unregister("_uberblick_tmp_arrow")

            duck.execute(
                "INSERT INTO snapshot_views VALUES (?, ?, ?, ?, ?)",
                [
                    extraction.name,
                    extraction.rows,
                    extraction.minutes_since_latest_record,
                    documented_max_lag_minutes(extraction.name),
                    extraction.error,
                ],
            )

            result.views[extraction.name] = {
                "rows": extraction.rows,
                "minutes_since_latest_record": extraction.minutes_since_latest_record,
                "documented_max_lag_minutes": documented_max_lag_minutes(
                    extraction.name
                ),
                "error": extraction.error,
            }

            if on_view_done:
                on_view_done(extraction)

        if on_phase:
            on_phase("account parameters")
        try:
            params_table = extract_account_parameters(conn)
            if params_table is not None and params_table.num_columns > 0:
                duck.register("_uberblick_params", params_table)
                duck.execute(
                    "CREATE TABLE account_parameters AS "
                    "SELECT * FROM _uberblick_params"
                )
                duck.unregister("_uberblick_params")
        except Exception as e:
            if on_phase:
                on_phase(f"params failed: {type(e).__name__}: {e}")

        if on_phase:
            on_phase("classify")
        try:
            build_roles_with_origin(duck)
            result.role_origin_breakdown = origin_breakdown(duck)
        except Exception as e:
            result.role_origin_breakdown = [("error", 0)]
            if on_phase:
                on_phase(f"classify failed: {type(e).__name__}: {e}")

        if on_phase:
            on_phase("closure")
        try:
            stats = build_role_closure(duck, depth_cap=depth_cap)
            result.closure_edges = stats.edges
            result.closure_max_depth = stats.max_depth_observed
        except Exception as e:
            if on_phase:
                on_phase(f"closure failed: {type(e).__name__}: {e}")
    finally:
        duck.close()

    sidecar = output_path.parent / f"{output_path.name}.meta.json"
    sidecar.write_text(json.dumps(asdict(result), indent=2))

    return result
