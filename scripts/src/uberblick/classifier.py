from __future__ import annotations

from typing import Any

_SYSTEM_ROLE_NAMES = (
    "ACCOUNTADMIN",
    "SYSADMIN",
    "SECURITYADMIN",
    "USERADMIN",
    "ORGADMIN",
    "PUBLIC",
)


_ROLE_ORIGIN_SQL = """
CREATE TABLE roles_with_origin AS
SELECT
    NAME,
    ROLE_TYPE,
    OWNER,
    COMMENT,
    CREATED_ON,
    DELETED_ON,
    CASE
        WHEN NAME IN ({system_names}) THEN 'system'
        WHEN ROLE_TYPE = 'APPLICATION_ROLE' THEN 'snowflake-application'
        WHEN ROLE_TYPE = 'INSTANCE_ROLE' THEN 'snowflake-instance'
        WHEN OWNER = 'SNOWFLAKE' THEN 'snowflake-shipped'
        ELSE 'customer'
    END AS origin
FROM roles
"""


def build_roles_with_origin(duck: Any) -> int:
    system_names = ", ".join(f"'{n}'" for n in _SYSTEM_ROLE_NAMES)
    duck.execute("DROP TABLE IF EXISTS roles_with_origin")
    duck.execute(_ROLE_ORIGIN_SQL.format(system_names=system_names))
    row = duck.execute("SELECT COUNT(*) FROM roles_with_origin").fetchone()
    return int(row[0]) if row else 0


def origin_breakdown(duck: Any) -> list[tuple[str, int]]:
    rows = duck.execute(
        "SELECT origin, COUNT(*) FROM roles_with_origin GROUP BY origin ORDER BY 2 DESC"
    ).fetchall()
    return [(str(r[0]), int(r[1])) for r in rows]
