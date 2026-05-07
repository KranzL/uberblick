from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pyarrow as pa


@dataclass(frozen=True)
class ViewSpec:
    name: str
    extract_sql: str
    lag_sql: str | None
    enterprise_only: bool = False


_DOCUMENTED_PIPELINE_LAG_MAX_MINUTES: dict[str, int] = {
    "roles": 120,
    "users": 120,
    "grants_to_roles": 120,
    "grants_to_users": 120,
    "policy_references": 120,
    "tag_references": 120,
    "object_dependencies": 180,
    "login_history": 120,
    "query_history": 45,
    "access_history": 180,
    "procedures": 90,
    "functions": 90,
    "tasks": 90,
    "pipes": 90,
    "stages": 90,
    "credentials": 120,
    "authentication_policies": 120,
    "network_policies": 120,
}


def documented_max_lag_minutes(view_name: str) -> int | None:
    return _DOCUMENTED_PIPELINE_LAG_MAX_MINUTES.get(view_name)


@dataclass
class ViewExtraction:
    name: str
    rows: int
    minutes_since_latest_record: int | None
    table: pa.Table | None
    error: str | None = None


_TIMELESS_VIEWS: tuple[ViewSpec, ...] = (
    ViewSpec(
        name="roles",
        extract_sql="SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES WHERE DELETED_ON IS NULL",
        lag_sql=(
            "SELECT DATEDIFF('minute', MAX(CREATED_ON), CURRENT_TIMESTAMP()) "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.ROLES"
        ),
    ),
    ViewSpec(
        name="users",
        extract_sql="SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.USERS WHERE DELETED_ON IS NULL",
        lag_sql=(
            "SELECT DATEDIFF('minute', MAX(CREATED_ON), CURRENT_TIMESTAMP()) "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.USERS"
        ),
    ),
    ViewSpec(
        name="grants_to_roles",
        extract_sql=(
            "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES "
            "WHERE DELETED_ON IS NULL"
        ),
        lag_sql=(
            "SELECT DATEDIFF('minute', MAX(CREATED_ON), CURRENT_TIMESTAMP()) "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES "
            "WHERE DELETED_ON IS NULL"
        ),
    ),
    ViewSpec(
        name="grants_to_users",
        extract_sql=(
            "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS "
            "WHERE DELETED_ON IS NULL"
        ),
        lag_sql=(
            "SELECT DATEDIFF('minute', MAX(CREATED_ON), CURRENT_TIMESTAMP()) "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS "
            "WHERE DELETED_ON IS NULL"
        ),
    ),
    ViewSpec(
        name="policy_references",
        extract_sql="SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES",
        lag_sql=None,
    ),
    ViewSpec(
        name="tag_references",
        extract_sql="SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES",
        lag_sql=None,
    ),
    ViewSpec(
        name="object_dependencies",
        extract_sql="SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.OBJECT_DEPENDENCIES",
        lag_sql=None,
    ),
    ViewSpec(
        name="procedures",
        extract_sql=(
            "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.PROCEDURES "
            "WHERE DELETED IS NULL"
        ),
        lag_sql=(
            "SELECT DATEDIFF('minute', MAX(CREATED), CURRENT_TIMESTAMP()) "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.PROCEDURES"
        ),
    ),
    ViewSpec(
        name="functions",
        extract_sql=(
            "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.FUNCTIONS "
            "WHERE DELETED IS NULL"
        ),
        lag_sql=(
            "SELECT DATEDIFF('minute', MAX(CREATED), CURRENT_TIMESTAMP()) "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.FUNCTIONS"
        ),
    ),
    ViewSpec(
        name="tasks",
        extract_sql=(
            "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.TASKS "
            "WHERE DELETED IS NULL"
        ),
        lag_sql=(
            "SELECT DATEDIFF('minute', MAX(CREATED), CURRENT_TIMESTAMP()) "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.TASKS"
        ),
    ),
    ViewSpec(
        name="pipes",
        extract_sql=(
            "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.PIPES "
            "WHERE DELETED IS NULL"
        ),
        lag_sql=(
            "SELECT DATEDIFF('minute', MAX(CREATED), CURRENT_TIMESTAMP()) "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.PIPES"
        ),
    ),
    ViewSpec(
        name="stages",
        extract_sql=(
            "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.STAGES "
            "WHERE DELETED IS NULL"
        ),
        lag_sql=(
            "SELECT DATEDIFF('minute', MAX(CREATED), CURRENT_TIMESTAMP()) "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.STAGES"
        ),
    ),
    ViewSpec(
        name="credentials",
        extract_sql="SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.CREDENTIALS",
        lag_sql=(
            "SELECT DATEDIFF('minute', MAX(CREATED_ON), CURRENT_TIMESTAMP()) "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.CREDENTIALS"
        ),
    ),
    ViewSpec(
        name="authentication_policies",
        extract_sql="SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.AUTHENTICATION_POLICIES",
        lag_sql=(
            "SELECT DATEDIFF('minute', MAX(CREATED), CURRENT_TIMESTAMP()) "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.AUTHENTICATION_POLICIES"
        ),
    ),
    ViewSpec(
        name="network_policies",
        extract_sql="SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.NETWORK_POLICIES",
        lag_sql=(
            "SELECT DATEDIFF('minute', MAX(CREATED_ON), CURRENT_TIMESTAMP()) "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.NETWORK_POLICIES"
        ),
    ),
)


def _time_filtered_views(days: int) -> tuple[ViewSpec, ...]:
    return (
        ViewSpec(
            name="login_history",
            extract_sql=(
                "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY "
                f"WHERE EVENT_TIMESTAMP >= DATEADD('day', -{days}, CURRENT_TIMESTAMP())"
            ),
            lag_sql=(
                "SELECT DATEDIFF('minute', MAX(EVENT_TIMESTAMP), CURRENT_TIMESTAMP()) "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY"
            ),
        ),
        ViewSpec(
            name="query_history",
            extract_sql=(
                "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY "
                f"WHERE START_TIME >= DATEADD('day', -{days}, CURRENT_TIMESTAMP())"
            ),
            lag_sql=(
                "SELECT DATEDIFF('minute', MAX(START_TIME), CURRENT_TIMESTAMP()) "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY"
            ),
        ),
        ViewSpec(
            name="access_history",
            extract_sql=(
                "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY "
                f"WHERE QUERY_START_TIME >= DATEADD('day', -{days}, CURRENT_TIMESTAMP())"
            ),
            lag_sql=(
                "SELECT DATEDIFF('minute', MAX(QUERY_START_TIME), CURRENT_TIMESTAMP()) "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY"
            ),
            enterprise_only=True,
        ),
    )


def all_specs(days: int = 30) -> tuple[ViewSpec, ...]:
    return _TIMELESS_VIEWS + _time_filtered_views(days)


def extract_account_parameters(conn: Any) -> pa.Table:
    interesting = (
        "PREVENT_UNLOAD_TO_INLINE_URL",
        "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION",
        "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION",
        "PREVENT_LOAD_FROM_INLINE_URL",
        "ENFORCE_NETWORK_RULES_FOR_INTERNAL_STAGES",
        "MIN_DATA_RETENTION_TIME_IN_DAYS",
        "DATA_RETENTION_TIME_IN_DAYS",
        "ALLOW_CLIENT_MFA_CACHING",
        "ALLOW_ID_TOKEN",
        "PASSWORD_POLICY",
        "AUTHENTICATION_POLICY",
        "NETWORK_POLICY",
        "SSO_LOGIN_PAGE",
        "USER_TASK_TIMEOUT_MS",
        "DEFAULT_NULL_ORDERING",
    )
    cur = conn.cursor()
    rows: list[dict[str, Any]] = []
    try:
        cur.execute("SHOW PARAMETERS IN ACCOUNT")
        cols = [d[0].lower() for d in cur.description]
        for r in cur.fetchall():
            d = dict(zip(cols, r))
            name = str(d.get("key", ""))
            if name in interesting:
                rows.append({
                    "PARAMETER_NAME": name,
                    "VALUE": str(d.get("value", "")),
                    "DEFAULT_VALUE": str(d.get("default", "")),
                    "LEVEL": str(d.get("level", "")),
                    "DESCRIPTION": str(d.get("description", "")),
                })
    except Exception:
        pass
    finally:
        cur.close()
    if not rows:
        return pa.table({})
    return pa.Table.from_pylist(rows)


def extract(conn: Any, spec: ViewSpec) -> ViewExtraction:
    cur = conn.cursor()
    try:
        minutes_since_latest_record: int | None = None
        if spec.lag_sql:
            try:
                cur.execute(spec.lag_sql)
                row = cur.fetchone()
                if row and row[0] is not None:
                    minutes_since_latest_record = int(row[0])
            except Exception:
                minutes_since_latest_record = None

        try:
            cur.execute(spec.extract_sql)
            table = cur.fetch_arrow_all()
        except Exception as e:
            return ViewExtraction(
                name=spec.name,
                rows=0,
                minutes_since_latest_record=minutes_since_latest_record,
                table=None,
                error=f"{type(e).__name__}: {e}",
            )

        if table is None:
            table = pa.table({})

        return ViewExtraction(
            name=spec.name,
            rows=table.num_rows,
            minutes_since_latest_record=minutes_since_latest_record,
            table=table,
        )
    finally:
        cur.close()
