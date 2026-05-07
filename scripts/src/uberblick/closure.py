from __future__ import annotations

from dataclasses import dataclass
from typing import Any

DEFAULT_DEPTH_CAP = 30


@dataclass
class ClosureStats:
    depth_cap: int
    edges: int
    max_depth_observed: int
    cycles_blocked: bool


_CLOSURE_SQL = """
CREATE TABLE role_closure AS
WITH RECURSIVE H AS (
    SELECT
        NAME AS root_role,
        NAME AS reachable_role,
        0 AS depth,
        [NAME] AS path,
        FALSE AS cycle_blocked
    FROM roles
    UNION ALL
    SELECT
        H.root_role,
        G.NAME AS reachable_role,
        H.depth + 1,
        list_append(H.path, G.NAME),
        FALSE
    FROM grants_to_roles G
    JOIN H ON G.GRANTEE_NAME = H.reachable_role
    WHERE G.PRIVILEGE = 'USAGE'
      AND G.GRANTED_ON IN ('ROLE', 'DATABASE_ROLE')
      AND G.GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
      AND H.depth < {depth_cap}
      AND NOT list_contains(H.path, G.NAME)
)
SELECT root_role, reachable_role, depth, path
FROM H
"""


def build_role_closure(duck: Any, depth_cap: int = DEFAULT_DEPTH_CAP) -> ClosureStats:
    duck.execute("DROP TABLE IF EXISTS role_closure")
    duck.execute(_CLOSURE_SQL.format(depth_cap=depth_cap))

    edges = int(duck.execute("SELECT COUNT(*) FROM role_closure").fetchone()[0])
    max_depth = int(
        duck.execute("SELECT COALESCE(MAX(depth), 0) FROM role_closure").fetchone()[0]
    )
    return ClosureStats(
        depth_cap=depth_cap,
        edges=edges,
        max_depth_observed=max_depth,
        cycles_blocked=True,
    )
