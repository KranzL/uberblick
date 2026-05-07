from __future__ import annotations

from pathlib import Path
from typing import Any

import duckdb


def load_hris_into(duck: Any, csv_path: Path) -> int:
    """Load an HRIS CSV into a DuckDB table named `hris`.

    The CSV is expected to have columns including (case-insensitive):
    - login_name OR email OR snowflake_user (key for joining)
    - status (active / terminated / on_leave)
    - term_date (optional, ISO date)
    - manager (optional)
    - department (optional)

    Extra columns are kept verbatim. Returns row count loaded.
    """
    csv_path = Path(csv_path).resolve()
    if not csv_path.exists():
        raise FileNotFoundError(f"HRIS CSV not found: {csv_path}")
    duck.execute("DROP TABLE IF EXISTS hris")
    duck.execute(
        f"CREATE TABLE hris AS SELECT * FROM read_csv_auto('{csv_path}', header=true)"
    )
    cols_meta = duck.execute(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'hris'"
    ).fetchall()
    cols = [str(r[0]).lower() for r in cols_meta]
    join_col = None
    for cand in ("login_name", "email", "snowflake_user", "username"):
        if cand in cols:
            join_col = cand
            break
    if not join_col:
        raise ValueError(
            "HRIS CSV must contain one of: login_name, email, snowflake_user, username"
        )
    duck.execute(
        f"CREATE OR REPLACE VIEW hris_normalized AS "
        f"SELECT UPPER(\"{join_col}\") AS hris_key, * FROM hris"
    )
    row = duck.execute("SELECT COUNT(*) FROM hris").fetchone()
    return int(row[0])
