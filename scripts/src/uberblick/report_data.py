from __future__ import annotations

from typing import Any


def compute_role_groupings(duck: Any) -> dict[str, Any]:
    if not _table_exists(duck, "roles_with_origin"):
        return {"functional": [], "database_groups": [], "system": []}

    object_grant_rows = duck.execute(
        """
        WITH per_role AS (
            SELECT
                GRANTEE_NAME AS role,
                TABLE_CATALOG,
                TABLE_SCHEMA,
                CASE
                    WHEN PRIVILEGE = 'OWNERSHIP' THEN 'owner'
                    WHEN PRIVILEGE IN ('SELECT', 'REFERENCES', 'USAGE') THEN 'viewer'
                    ELSE 'admin'
                END AS env_class,
                COUNT(*) AS n
            FROM grants_to_roles
            WHERE GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
              AND DELETED_ON IS NULL
              AND GRANTED_ON NOT IN ('ROLE', 'DATABASE_ROLE',
                                     'INSTANCE_ROLE', 'APPLICATION_ROLE',
                                     'ACCOUNT', 'WAREHOUSE', 'INTEGRATION', 'USER')
              AND TABLE_CATALOG IS NOT NULL
            GROUP BY 1, 2, 3, 4
        ),
        role_primary AS (
            SELECT
                role,
                TABLE_CATALOG AS db,
                TABLE_SCHEMA AS schema,
                env_class,
                ROW_NUMBER() OVER (
                    PARTITION BY role
                    ORDER BY n DESC, env_class, TABLE_CATALOG, TABLE_SCHEMA
                ) AS rk
            FROM per_role
        )
        SELECT role, db, schema, env_class
        FROM role_primary
        WHERE rk = 1
        """
    ).fetchall()
    role_to_primary: dict[str, tuple[str, str | None, str]] = {}
    for r in object_grant_rows:
        role = str(r[0])
        db = str(r[1]) if r[1] else None
        schema = str(r[2]) if r[2] else None
        env = str(r[3])
        if db:
            role_to_primary[role] = (db, schema, env)

    role_role_grants = duck.execute(
        """
        SELECT GRANTEE_NAME, COUNT(*) AS n_inherits
        FROM grants_to_roles
        WHERE PRIVILEGE = 'USAGE'
          AND GRANTED_ON IN ('ROLE', 'DATABASE_ROLE')
          AND GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
          AND DELETED_ON IS NULL
        GROUP BY 1
        """
    ).fetchall()
    role_inherits_count = {str(r[0]): int(r[1]) for r in role_role_grants}

    all_roles = duck.execute(
        "SELECT NAME, origin FROM roles_with_origin"
    ).fetchall()

    functional: list[dict[str, Any]] = []
    system: list[dict[str, Any]] = []
    db_groups_map: dict[str, dict[str, Any]] = {}

    for r in all_roles:
        name = str(r[0])
        origin = str(r[1])
        if origin == "system":
            system.append({"id": name, "name": name, "origin": origin})
            continue
        primary = role_to_primary.get(name)
        if primary is None:
            functional.append(
                {
                    "id": name,
                    "name": name,
                    "origin": origin,
                    "inherits_count": role_inherits_count.get(name, 0),
                }
            )
        else:
            db, schema, env = primary
            grp = db_groups_map.setdefault(
                db, {"id": db, "db": db, "schemas": {}, "roles": []}
            )
            grp["roles"].append(
                {
                    "name": name,
                    "schema": schema,
                    "envelope": env,
                    "origin": origin,
                }
            )
            schema_entry = grp["schemas"].setdefault(
                schema or "", {"schema": schema, "roles": []}
            )
            schema_entry["roles"].append(
                {"name": name, "envelope": env, "origin": origin}
            )

    db_groups: list[dict[str, Any]] = []
    for db, info in sorted(db_groups_map.items()):
        schemas_sorted = []
        for skey, sinfo in sorted(info["schemas"].items()):
            sinfo["roles"].sort(key=lambda r: (r["envelope"], r["name"]))
            schemas_sorted.append(sinfo)
        info["schemas"] = schemas_sorted
        info["roles"].sort(key=lambda r: (r.get("schema") or "", r["envelope"], r["name"]))
        info["role_count"] = len(info["roles"])
        info["schema_count"] = len(schemas_sorted)
        db_groups.append(info)

    edge_rows = duck.execute(
        """
        SELECT G.NAME AS parent, G.GRANTEE_NAME AS child
        FROM grants_to_roles G
        WHERE G.PRIVILEGE = 'USAGE'
          AND G.GRANTED_ON IN ('ROLE', 'DATABASE_ROLE')
          AND G.GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
          AND G.DELETED_ON IS NULL
        """
    ).fetchall()

    role_to_group: dict[str, str] = {}
    for grp in db_groups:
        for role_info in grp["roles"]:
            role_to_group[role_info["name"]] = grp["id"]

    aggregated_edges: dict[tuple[str, str], int] = {}
    for r in edge_rows:
        parent = str(r[0])
        child = str(r[1])
        src = role_to_group.get(child, child)
        tgt = role_to_group.get(parent, parent)
        if src == tgt:
            continue
        key = (src, tgt)
        aggregated_edges[key] = aggregated_edges.get(key, 0) + 1

    edges = [
        {"source": src, "target": tgt, "weight": w}
        for (src, tgt), w in aggregated_edges.items()
    ]

    return {
        "functional": sorted(functional, key=lambda r: r["name"]),
        "database_groups": db_groups,
        "system": sorted(system, key=lambda r: r["name"]),
        "edges": edges,
        "role_to_group": role_to_group,
    }


def compute_role_graph(duck: Any) -> dict[str, Any]:
    nodes_rows = duck.execute(
        """
        SELECT NAME, ROLE_TYPE, OWNER, origin
        FROM roles_with_origin
        ORDER BY origin, NAME
        """
    ).fetchall()
    nodes = [
        {
            "id": str(r[0]),
            "role_type": str(r[1]) if r[1] else None,
            "owner": str(r[2]) if r[2] else None,
            "origin": str(r[3]),
        }
        for r in nodes_rows
    ]

    edge_rows = duck.execute(
        """
        SELECT G.NAME AS parent, G.GRANTEE_NAME AS child
        FROM grants_to_roles G
        WHERE G.PRIVILEGE = 'USAGE'
          AND G.GRANTED_ON IN ('ROLE', 'DATABASE_ROLE')
          AND G.GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
          AND G.DELETED_ON IS NULL
        """
    ).fetchall()
    edges = [
        {"source": str(r[1]), "target": str(r[0])}
        for r in edge_rows
    ]
    return {"nodes": nodes, "edges": edges}


def compute_admin_reach(duck: Any) -> list[dict[str, Any]]:
    if not _table_exists(duck, "role_closure"):
        return []
    rows = duck.execute(
        """
        WITH user_roles AS (
            SELECT GRANTEE_NAME AS user_name, ROLE
            FROM grants_to_users
            WHERE DELETED_ON IS NULL
        ),
        admin_paths AS (
            SELECT
                ur.user_name,
                ur.ROLE AS direct_role,
                rc.reachable_role,
                rc.depth,
                rc.path
            FROM user_roles ur
            JOIN role_closure rc ON rc.root_role = ur.ROLE
            WHERE rc.reachable_role IN (
                'ACCOUNTADMIN', 'SECURITYADMIN', 'ORGADMIN', 'USERADMIN', 'SYSADMIN'
            )
        )
        SELECT user_name, reachable_role, MIN(depth) AS shortest_depth,
               LIST(DISTINCT direct_role) AS via_roles
        FROM admin_paths
        GROUP BY user_name, reachable_role
        ORDER BY reachable_role, user_name
        """
    ).fetchall()
    return [
        {
            "user": str(r[0]),
            "admin_role": str(r[1]),
            "shortest_depth": int(r[2]),
            "via_roles": [str(x) for x in (r[3] or [])],
        }
        for r in rows
    ]


def compute_direct_user_grants(duck: Any) -> list[dict[str, Any]]:
    rows = duck.execute(
        """
        SELECT GRANTEE_NAME, PRIVILEGE, GRANTED_ON, NAME, TABLE_CATALOG, TABLE_SCHEMA, GRANT_OPTION
        FROM grants_to_roles
        WHERE GRANTED_TO = 'USER'
          AND DELETED_ON IS NULL
        ORDER BY GRANTEE_NAME, PRIVILEGE
        """
    ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        granted_on = str(r[2])
        name = str(r[3])
        catalog = str(r[4]) if r[4] else None
        schema = str(r[5]) if r[5] else None
        if granted_on == "DATABASE":
            qualified = name
        elif granted_on == "SCHEMA":
            qualified = ".".join(p for p in (catalog, name) if p)
        else:
            qualified = ".".join(p for p in (catalog, schema, name) if p)
        out.append(
            {
                "user": str(r[0]),
                "privilege": str(r[1]),
                "object_type": granted_on,
                "object_name": qualified,
                "with_grant_option": bool(r[6]) if r[6] is not None else False,
            }
        )
    return out


def compute_view_summary(duck: Any) -> list[dict[str, Any]]:
    rows = duck.execute(
        """
        SELECT name, rows, minutes_since_latest_record,
               documented_max_lag_minutes, error
        FROM snapshot_views
        ORDER BY rows DESC
        """
    ).fetchall()
    return [
        {
            "name": str(r[0]),
            "rows": int(r[1]),
            "minutes_since_latest_record": (
                int(r[2]) if r[2] is not None else None
            ),
            "documented_max_lag_minutes": (
                int(r[3]) if r[3] is not None else None
            ),
            "error": str(r[4]) if r[4] else None,
        }
        for r in rows
    ]


def compute_role_census(duck: Any) -> list[dict[str, Any]]:
    if not _table_exists(duck, "roles_with_origin"):
        return []
    if not _table_exists(duck, "role_closure"):
        rows = duck.execute(
            """
            SELECT NAME, ROLE_TYPE, OWNER, origin
            FROM roles_with_origin
            ORDER BY origin, NAME
            """
        ).fetchall()
        return [
            {
                "name": str(r[0]),
                "role_type": str(r[1]) if r[1] else None,
                "owner": str(r[2]) if r[2] else None,
                "origin": str(r[3]),
                "inherits_count": 0,
                "inherited_by_count": 0,
                "user_count": 0,
                "max_reach_depth": 0,
            }
            for r in rows
        ]
    rows = duck.execute(
        """
        WITH inherits_count AS (
            SELECT root_role AS name, COUNT(DISTINCT reachable_role) - 1 AS n
            FROM role_closure
            GROUP BY root_role
        ),
        inherited_by AS (
            SELECT reachable_role AS name, COUNT(DISTINCT root_role) - 1 AS n
            FROM role_closure
            GROUP BY reachable_role
        ),
        users AS (
            SELECT ROLE AS name, COUNT(DISTINCT GRANTEE_NAME) AS n
            FROM grants_to_users
            WHERE DELETED_ON IS NULL
            GROUP BY ROLE
        ),
        depths AS (
            SELECT root_role AS name, MAX(depth) AS d
            FROM role_closure
            GROUP BY root_role
        )
        SELECT
            r.NAME, r.ROLE_TYPE, r.OWNER, r.origin,
            COALESCE(i.n, 0) AS inherits_count,
            COALESCE(b.n, 0) AS inherited_by_count,
            COALESCE(u.n, 0) AS user_count,
            COALESCE(d.d, 0) AS max_reach_depth
        FROM roles_with_origin r
        LEFT JOIN inherits_count i ON i.name = r.NAME
        LEFT JOIN inherited_by    b ON b.name = r.NAME
        LEFT JOIN users           u ON u.name = r.NAME
        LEFT JOIN depths          d ON d.name = r.NAME
        ORDER BY r.origin, r.NAME
        """
    ).fetchall()
    return [
        {
            "name": str(r[0]),
            "role_type": str(r[1]) if r[1] else None,
            "owner": str(r[2]) if r[2] else None,
            "origin": str(r[3]),
            "inherits_count": int(r[4]),
            "inherited_by_count": int(r[5]),
            "user_count": int(r[6]),
            "max_reach_depth": int(r[7]),
        }
        for r in rows
    ]


def compute_policy_protections(duck: Any) -> dict[str, dict[str, list[dict[str, Any]]]]:
    out: dict[str, dict[str, list[dict[str, Any]]]] = {"tables": {}, "columns": {}}
    if not _table_exists(duck, "policy_references"):
        return out
    rows = duck.execute(
        """
        SELECT
            POLICY_KIND,
            POLICY_NAME,
            POLICY_DB,
            POLICY_SCHEMA,
            REF_DATABASE_NAME,
            REF_SCHEMA_NAME,
            REF_ENTITY_NAME,
            REF_ENTITY_DOMAIN,
            REF_COLUMN_NAME,
            TAG_DATABASE,
            TAG_SCHEMA,
            TAG_NAME,
            POLICY_STATUS
        FROM policy_references
        WHERE COALESCE(POLICY_STATUS, 'ACTIVE') = 'ACTIVE'
        """
    ).fetchall()
    for r in rows:
        kind = str(r[0]) if r[0] else "POLICY"
        policy_qualified = ".".join(p for p in (
            str(r[2]) if r[2] else None,
            str(r[3]) if r[3] else None,
            str(r[1]) if r[1] else None,
        ) if p)
        ref_db = str(r[4]) if r[4] else None
        ref_schema = str(r[5]) if r[5] else None
        ref_entity = str(r[6]) if r[6] else None
        ref_domain = str(r[7]) if r[7] else None
        ref_column = str(r[8]) if r[8] else None
        via_tag = None
        if r[10] or r[11]:
            via_tag = ".".join(p for p in (
                str(r[9]) if r[9] else None,
                str(r[10]) if r[10] else None,
                str(r[11]) if r[11] else None,
            ) if p)
        if not ref_entity:
            continue
        table_key = ".".join(p for p in (ref_db, ref_schema, ref_entity) if p)
        protection = {
            "kind": kind,
            "policy": policy_qualified,
            "via_tag": via_tag,
        }
        if ref_column:
            col_key = f"{table_key}.{ref_column}"
            out["columns"].setdefault(col_key, []).append(protection)
        else:
            out["tables"].setdefault(table_key, []).append(protection)
    return out


def compute_tag_classifications(duck: Any) -> dict[str, dict[str, list[dict[str, Any]]]]:
    out: dict[str, dict[str, list[dict[str, Any]]]] = {"tables": {}, "columns": {}}
    if not _table_exists(duck, "tag_references"):
        return out
    rows = duck.execute(
        """
        SELECT
            TAG_DATABASE, TAG_SCHEMA, TAG_NAME, TAG_VALUE,
            OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME,
            COLUMN_NAME, DOMAIN
        FROM tag_references
        """
    ).fetchall()
    for r in rows:
        tag_qualified = ".".join(p for p in (
            str(r[0]) if r[0] else None,
            str(r[1]) if r[1] else None,
            str(r[2]) if r[2] else None,
        ) if p)
        tag_value = str(r[3]) if r[3] else None
        obj_db = str(r[4]) if r[4] else None
        obj_schema = str(r[5]) if r[5] else None
        obj_name = str(r[6]) if r[6] else None
        col_name = str(r[7]) if r[7] else None
        domain = str(r[8]) if r[8] else None
        if not obj_name:
            continue
        table_key = ".".join(p for p in (obj_db, obj_schema, obj_name) if p)
        tag_entry = {
            "tag": tag_qualified,
            "value": tag_value,
        }
        if domain == "COLUMN" and col_name:
            col_key = f"{table_key}.{col_name}"
            out["columns"].setdefault(col_key, []).append(tag_entry)
        else:
            out["tables"].setdefault(table_key, []).append(tag_entry)
    return out


def compute_role_impersonation_surface(duck: Any) -> list[dict[str, Any]]:
    if not _table_exists(duck, "role_closure"):
        return []
    if not _table_exists(duck, "roles_with_origin"):
        return []
    rows = duck.execute(
        """
        WITH role_objects AS (
            SELECT
                rc.root_role AS role,
                COUNT(DISTINCT
                    g.GRANTED_ON || '|' ||
                    COALESCE(g.TABLE_CATALOG, '') || '|' ||
                    COALESCE(g.TABLE_SCHEMA, '') || '|' || g.NAME
                ) AS reachable_objects,
                COUNT(DISTINCT
                    CASE WHEN g.GRANTED_ON = 'TABLE' THEN
                        COALESCE(g.TABLE_CATALOG, '') || '.' ||
                        COALESCE(g.TABLE_SCHEMA, '') || '.' || g.NAME END
                ) AS reachable_tables,
                COUNT(DISTINCT
                    CASE WHEN g.GRANTED_ON = 'SCHEMA' THEN
                        COALESCE(g.TABLE_CATALOG, '') || '.' || g.NAME END
                ) AS reachable_schemas,
                COUNT(DISTINCT
                    CASE WHEN g.GRANTED_ON = 'DATABASE' THEN g.NAME END
                ) AS reachable_databases,
                BOOL_OR(g.PRIVILEGE IN (
                    'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE',
                    'CREATE TABLE', 'CREATE VIEW', 'CREATE STAGE',
                    'OWNERSHIP', 'MODIFY'
                )) AS has_write,
                BOOL_OR(g.PRIVILEGE = 'OWNERSHIP') AS has_ownership,
                BOOL_OR(g.PRIVILEGE IN ('MANAGE GRANTS', 'CREATE ROLE', 'CREATE USER')) AS has_grant_admin,
                BOOL_OR(rc.reachable_role IN (
                    'ACCOUNTADMIN', 'SECURITYADMIN', 'ORGADMIN', 'USERADMIN'
                )) AS reaches_admin
            FROM role_closure rc
            LEFT JOIN grants_to_roles g
              ON g.GRANTEE_NAME = rc.reachable_role
             AND g.GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
             AND g.DELETED_ON IS NULL
             AND g.GRANTED_ON NOT IN (
               'ROLE', 'DATABASE_ROLE', 'INSTANCE_ROLE', 'APPLICATION_ROLE'
             )
            GROUP BY rc.root_role
        )
        SELECT
            r.NAME, r.origin, r.OWNER,
            COALESCE(ro.reachable_objects, 0) AS reachable_objects,
            COALESCE(ro.reachable_tables, 0) AS reachable_tables,
            COALESCE(ro.reachable_schemas, 0) AS reachable_schemas,
            COALESCE(ro.reachable_databases, 0) AS reachable_databases,
            COALESCE(ro.has_write, FALSE) AS has_write,
            COALESCE(ro.has_ownership, FALSE) AS has_ownership,
            COALESCE(ro.has_grant_admin, FALSE) AS has_grant_admin,
            COALESCE(ro.reaches_admin, FALSE) AS reaches_admin
        FROM roles_with_origin r
        LEFT JOIN role_objects ro ON ro.role = r.NAME
        ORDER BY ro.reachable_objects DESC NULLS LAST, r.NAME
        """
    ).fetchall()
    return [
        {
            "role": str(r[0]),
            "origin": str(r[1]),
            "owner": str(r[2]) if r[2] else None,
            "reachable_objects": int(r[3]),
            "reachable_tables": int(r[4]),
            "reachable_schemas": int(r[5]),
            "reachable_databases": int(r[6]),
            "has_write": bool(r[7]),
            "has_ownership": bool(r[8]),
            "has_grant_admin": bool(r[9]),
            "reaches_admin": bool(r[10]),
        }
        for r in rows
    ]


def compute_role_impersonation_detail(duck: Any, role_name: str) -> dict[str, Any]:
    if not _table_exists(duck, "role_closure"):
        return {}
    role_name = role_name.upper()
    inherited = duck.execute(
        """
        SELECT DISTINCT reachable_role, depth
        FROM role_closure
        WHERE UPPER(root_role) = ?
        ORDER BY depth, reachable_role
        """,
        [role_name],
    ).fetchall()
    object_grants = duck.execute(
        """
        SELECT
            g.GRANTED_ON,
            COALESCE(g.TABLE_CATALOG, '') AS db,
            COALESCE(g.TABLE_SCHEMA, '') AS schema,
            g.NAME,
            g.PRIVILEGE,
            g.GRANTEE_NAME AS via_role,
            g.GRANT_OPTION
        FROM role_closure rc
        JOIN grants_to_roles g
          ON g.GRANTEE_NAME = rc.reachable_role
         AND g.GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
         AND g.DELETED_ON IS NULL
         AND g.GRANTED_ON NOT IN (
           'ROLE', 'DATABASE_ROLE', 'INSTANCE_ROLE', 'APPLICATION_ROLE'
         )
        WHERE UPPER(rc.root_role) = ?
        ORDER BY g.GRANTED_ON, db, schema, g.NAME, g.PRIVILEGE
        """,
        [role_name],
    ).fetchall()
    users = duck.execute(
        """
        WITH expansion AS (
            SELECT GRANTEE_NAME AS user_name FROM grants_to_users WHERE UPPER(ROLE) = ?
        )
        SELECT user_name FROM expansion ORDER BY user_name
        """,
        [role_name],
    ).fetchall()
    return {
        "role": role_name,
        "inherited_roles": [
            {"name": str(r[0]), "depth": int(r[1])} for r in inherited
        ],
        "object_grants": [
            {
                "object_type": str(r[0]),
                "database": str(r[1]) if r[1] else None,
                "schema": str(r[2]) if r[2] else None,
                "name": str(r[3]),
                "privilege": str(r[4]),
                "via_role": str(r[5]),
                "with_grant_option": bool(r[6]) if r[6] is not None else False,
            }
            for r in object_grants
        ],
        "users_holding_role": [str(r[0]) for r in users],
    }


def compute_secondary_role_breakdown(duck: Any) -> list[dict[str, Any]]:
    if not _table_exists(duck, "role_closure"):
        return []
    rows = duck.execute(
        """
        WITH user_grants AS (
            SELECT GRANTEE_NAME AS user_name, ROLE
            FROM grants_to_users
            WHERE DELETED_ON IS NULL
        ),
        per_user_role_objs AS (
            SELECT DISTINCT
                ug.user_name,
                ug.ROLE AS source_role,
                g.GRANTED_ON || '|' ||
                COALESCE(g.TABLE_CATALOG, '') || '|' ||
                COALESCE(g.TABLE_SCHEMA, '') || '|' || g.NAME ||
                '|' || g.PRIVILEGE AS priv_key
            FROM user_grants ug
            JOIN role_closure rc ON rc.root_role = ug.ROLE
            JOIN grants_to_roles g
              ON g.GRANTEE_NAME = rc.reachable_role
             AND g.GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
             AND g.DELETED_ON IS NULL
             AND g.GRANTED_ON NOT IN (
               'ROLE', 'DATABASE_ROLE', 'INSTANCE_ROLE', 'APPLICATION_ROLE'
             )
        ),
        per_role_count AS (
            SELECT user_name, source_role,
                   COUNT(*) AS role_priv_count
            FROM per_user_role_objs
            GROUP BY user_name, source_role
        ),
        unique_per_role AS (
            SELECT user_name, source_role,
                   COUNT(*) AS unique_priv_count
            FROM (
                SELECT user_name, source_role, priv_key,
                       COUNT(*) OVER (PARTITION BY user_name, priv_key) AS appears_in
                FROM per_user_role_objs
            )
            WHERE appears_in = 1
            GROUP BY user_name, source_role
        )
        SELECT
            ug.user_name,
            ug.ROLE,
            COALESCE(prc.role_priv_count, 0) AS role_priv_count,
            COALESCE(upr.unique_priv_count, 0) AS unique_priv_count
        FROM user_grants ug
        LEFT JOIN per_role_count prc
          ON prc.user_name = ug.user_name AND prc.source_role = ug.ROLE
        LEFT JOIN unique_per_role upr
          ON upr.user_name = ug.user_name AND upr.source_role = ug.ROLE
        WHERE EXISTS (
            SELECT 1 FROM grants_to_users gu
            WHERE gu.GRANTEE_NAME = ug.user_name
            GROUP BY gu.GRANTEE_NAME
            HAVING COUNT(*) >= 2
        )
        ORDER BY ug.user_name, COALESCE(upr.unique_priv_count, 0) DESC
        """
    ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        out.append(
            {
                "user": str(r[0]),
                "role": str(r[1]),
                "role_priv_count": int(r[2]),
                "unique_priv_count": int(r[3]),
            }
        )
    return out


def compute_all_role_impersonation_details(duck: Any) -> dict[str, dict[str, Any]]:
    if not _table_exists(duck, "role_closure"):
        return {}
    inherited_rows = duck.execute(
        """
        SELECT root_role, reachable_role, depth
        FROM role_closure
        ORDER BY root_role, depth, reachable_role
        """
    ).fetchall()
    object_rows = duck.execute(
        """
        SELECT
            rc.root_role,
            g.GRANTED_ON,
            COALESCE(g.TABLE_CATALOG, '') AS db,
            COALESCE(g.TABLE_SCHEMA, '') AS schema,
            g.NAME,
            g.PRIVILEGE,
            g.GRANTEE_NAME AS via_role,
            g.GRANT_OPTION
        FROM role_closure rc
        JOIN grants_to_roles g
          ON g.GRANTEE_NAME = rc.reachable_role
         AND g.GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
         AND g.DELETED_ON IS NULL
         AND g.GRANTED_ON NOT IN (
           'ROLE', 'DATABASE_ROLE', 'INSTANCE_ROLE', 'APPLICATION_ROLE'
         )
        ORDER BY rc.root_role, g.GRANTED_ON, db, schema, g.NAME, g.PRIVILEGE
        """
    ).fetchall()
    user_rows = duck.execute(
        """
        SELECT ROLE, GRANTEE_NAME
        FROM grants_to_users
        WHERE DELETED_ON IS NULL
        ORDER BY ROLE, GRANTEE_NAME
        """
    ).fetchall()

    out: dict[str, dict[str, Any]] = {}
    for r in inherited_rows:
        root = str(r[0])
        if root not in out:
            out[root] = {
                "role": root,
                "inherited_roles": [],
                "object_grants": [],
                "users_holding_role": [],
            }
        out[root]["inherited_roles"].append(
            {"name": str(r[1]), "depth": int(r[2])}
        )
    for r in object_rows:
        root = str(r[0])
        if root not in out:
            continue
        out[root]["object_grants"].append(
            {
                "object_type": str(r[1]),
                "database": str(r[2]) if r[2] else None,
                "schema": str(r[3]) if r[3] else None,
                "name": str(r[4]),
                "privilege": str(r[5]),
                "via_role": str(r[6]),
                "with_grant_option": bool(r[7]) if r[7] is not None else False,
            }
        )
    for r in user_rows:
        role = str(r[0])
        user = str(r[1])
        if role in out:
            out[role]["users_holding_role"].append(user)
    return out


def compute_user_blast_radius(duck: Any, max_users: int = 100) -> dict[str, dict[str, Any]]:
    if not _table_exists(duck, "role_closure"):
        return {}
    candidate_rows = duck.execute(
        f"""
        WITH user_grants AS (
            SELECT GRANTEE_NAME AS user_name, ROLE
            FROM grants_to_users WHERE DELETED_ON IS NULL
        ),
        user_reach AS (
            SELECT ug.user_name,
                   COUNT(DISTINCT rc.reachable_role) AS role_reach,
                   BOOL_OR(rc.reachable_role IN (
                     'ACCOUNTADMIN', 'SECURITYADMIN', 'ORGADMIN', 'USERADMIN'
                   )) AS reaches_admin
            FROM user_grants ug
            JOIN role_closure rc ON rc.root_role = ug.ROLE
            GROUP BY ug.user_name
        )
        SELECT user_name FROM user_reach
        ORDER BY reaches_admin DESC, role_reach DESC
        LIMIT {max_users}
        """
    ).fetchall()
    candidate_users = [str(r[0]) for r in candidate_rows]
    if not candidate_users:
        return {}

    placeholders = ", ".join(f"'{u}'" for u in candidate_users)
    rows = duck.execute(
        f"""
        WITH user_grants AS (
            SELECT GRANTEE_NAME AS user_name, ROLE
            FROM grants_to_users
            WHERE DELETED_ON IS NULL
              AND GRANTEE_NAME IN ({placeholders})
        )
        SELECT
            ug.user_name,
            ug.ROLE AS via_direct_role,
            rc.reachable_role,
            g.GRANTED_ON,
            COALESCE(g.TABLE_CATALOG, '') AS db,
            COALESCE(g.TABLE_SCHEMA, '') AS schema,
            g.NAME,
            g.PRIVILEGE,
            g.GRANT_OPTION
        FROM user_grants ug
        JOIN role_closure rc ON rc.root_role = ug.ROLE
        JOIN grants_to_roles g
          ON g.GRANTEE_NAME = rc.reachable_role
         AND g.GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
         AND g.DELETED_ON IS NULL
         AND g.GRANTED_ON NOT IN (
           'ROLE', 'DATABASE_ROLE', 'INSTANCE_ROLE', 'APPLICATION_ROLE'
         )
        ORDER BY ug.user_name, g.GRANTED_ON, db, schema, g.NAME, g.PRIVILEGE
        """
    ).fetchall()
    out: dict[str, dict[str, Any]] = {u: {"user": u, "grants": []} for u in candidate_users}
    for r in rows:
        user = str(r[0])
        if user not in out:
            continue
        out[user]["grants"].append({
            "via_direct_role": str(r[1]),
            "via_inherited_role": str(r[2]),
            "object_type": str(r[3]),
            "database": str(r[4]) if r[4] else None,
            "schema": str(r[5]) if r[5] else None,
            "name": str(r[6]),
            "privilege": str(r[7]),
            "with_grant_option": bool(r[8]) if r[8] is not None else False,
        })
    for user in list(out.keys()):
        if not out[user]["grants"]:
            del out[user]
    return out


def compute_user_secondary_reach(duck: Any) -> list[dict[str, Any]]:
    if not _table_exists(duck, "role_closure"):
        return []
    rows = duck.execute(
        """
        WITH user_grants AS (
            SELECT GRANTEE_NAME AS user_name, ROLE
            FROM grants_to_users
            WHERE DELETED_ON IS NULL
        ),
        user_objects_via_each_role AS (
            SELECT DISTINCT
                ug.user_name,
                ug.ROLE AS source_role,
                g.GRANTED_ON || '|' ||
                COALESCE(g.TABLE_CATALOG, '') || '|' ||
                COALESCE(g.TABLE_SCHEMA, '') || '|' || g.NAME AS object_key,
                g.PRIVILEGE
            FROM user_grants ug
            JOIN role_closure rc ON rc.root_role = ug.ROLE
            JOIN grants_to_roles g
              ON g.GRANTEE_NAME = rc.reachable_role
             AND g.GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
             AND g.DELETED_ON IS NULL
             AND g.GRANTED_ON NOT IN (
               'ROLE', 'DATABASE_ROLE', 'INSTANCE_ROLE', 'APPLICATION_ROLE'
             )
        ),
        primary_set AS (
            SELECT u.NAME AS user_name,
                   COUNT(DISTINCT (object_key || '|' || PRIVILEGE)) AS primary_priv_count
            FROM users u
            LEFT JOIN user_objects_via_each_role uoer
              ON uoer.user_name = u.NAME
             AND uoer.source_role = u.DEFAULT_ROLE
            WHERE u.DELETED_ON IS NULL
            GROUP BY u.NAME
        ),
        secondary_set AS (
            SELECT user_name,
                   COUNT(DISTINCT (object_key || '|' || PRIVILEGE)) AS secondary_priv_count,
                   COUNT(DISTINCT source_role) AS role_count
            FROM user_objects_via_each_role
            GROUP BY user_name
        )
        SELECT
            u.NAME,
            u.DEFAULT_ROLE,
            COALESCE(p.primary_priv_count, 0) AS primary_count,
            COALESCE(s.secondary_priv_count, 0) AS secondary_count,
            COALESCE(s.role_count, 0) AS role_count
        FROM users u
        LEFT JOIN primary_set p ON p.user_name = u.NAME
        LEFT JOIN secondary_set s ON s.user_name = u.NAME
        WHERE u.DELETED_ON IS NULL
        ORDER BY (COALESCE(s.secondary_priv_count, 0) - COALESCE(p.primary_priv_count, 0)) DESC, u.NAME
        """
    ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        primary = int(r[2])
        secondary = int(r[3])
        delta = secondary - primary
        ratio = (secondary / primary) if primary > 0 else (float("inf") if secondary > 0 else 1.0)
        out.append(
            {
                "user": str(r[0]),
                "default_role": str(r[1]) if r[1] else None,
                "primary_priv_count": primary,
                "secondary_priv_count": secondary,
                "delta": delta,
                "expansion_ratio": (round(ratio, 2) if ratio != float("inf") else None),
                "role_count": int(r[4]),
            }
        )
    return out


def compute_user_census(duck: Any) -> list[dict[str, Any]]:
    if not _table_exists(duck, "users"):
        return []
    if not _table_exists(duck, "grants_to_users"):
        return []

    has_closure = _table_exists(duck, "role_closure")
    if has_closure:
        rows = duck.execute(
            """
            WITH user_direct AS (
                SELECT GRANTEE_NAME AS user_name, COUNT(DISTINCT ROLE) AS direct_n,
                       LIST(DISTINCT ROLE) AS direct_roles
                FROM grants_to_users
                WHERE DELETED_ON IS NULL
                GROUP BY GRANTEE_NAME
            ),
            user_reach AS (
                SELECT gu.GRANTEE_NAME AS user_name,
                       COUNT(DISTINCT rc.reachable_role) AS reach_n,
                       MAX(rc.depth) AS max_depth,
                       BOOL_OR(rc.reachable_role IN (
                         'ACCOUNTADMIN', 'SECURITYADMIN', 'ORGADMIN', 'USERADMIN'
                       )) AS reaches_admin
                FROM grants_to_users gu
                JOIN role_closure rc ON rc.root_role = gu.ROLE
                WHERE gu.DELETED_ON IS NULL
                GROUP BY gu.GRANTEE_NAME
            )
            SELECT
                u.NAME,
                u.TYPE,
                u.HAS_MFA,
                u.HAS_PASSWORD,
                u.HAS_RSA_PUBLIC_KEY,
                u.DEFAULT_ROLE,
                u.DISABLED,
                u.LAST_SUCCESS_LOGIN,
                COALESCE(d.direct_n, 0) AS direct_n,
                d.direct_roles,
                COALESCE(r.reach_n, 0) AS reach_n,
                COALESCE(r.max_depth, 0) AS max_depth,
                COALESCE(r.reaches_admin, FALSE) AS reaches_admin
            FROM users u
            LEFT JOIN user_direct d ON d.user_name = u.NAME
            LEFT JOIN user_reach r ON r.user_name = u.NAME
            WHERE u.DELETED_ON IS NULL
            ORDER BY r.reaches_admin DESC NULLS LAST, r.reach_n DESC NULLS LAST, u.NAME
            """
        ).fetchall()
    else:
        rows = duck.execute(
            """
            WITH user_direct AS (
                SELECT GRANTEE_NAME AS user_name, COUNT(DISTINCT ROLE) AS direct_n,
                       LIST(DISTINCT ROLE) AS direct_roles
                FROM grants_to_users
                WHERE DELETED_ON IS NULL
                GROUP BY GRANTEE_NAME
            )
            SELECT
                u.NAME, u.TYPE, u.HAS_MFA, u.HAS_PASSWORD, u.HAS_RSA_PUBLIC_KEY,
                u.DEFAULT_ROLE, u.DISABLED, u.LAST_SUCCESS_LOGIN,
                COALESCE(d.direct_n, 0) AS direct_n,
                d.direct_roles,
                0 AS reach_n, 0 AS max_depth, FALSE AS reaches_admin
            FROM users u
            LEFT JOIN user_direct d ON d.user_name = u.NAME
            WHERE u.DELETED_ON IS NULL
            ORDER BY u.NAME
            """
        ).fetchall()

    out: list[dict[str, Any]] = []
    for row in rows:
        name = str(row[0])
        type_v = str(row[1]) if row[1] else None
        has_mfa = bool(row[2]) if row[2] is not None else None
        has_password = bool(row[3]) if row[3] is not None else None
        has_rsa = bool(row[4]) if row[4] is not None else None
        default_role = str(row[5]) if row[5] else None
        disabled_raw = row[6]
        if isinstance(disabled_raw, bool):
            disabled = disabled_raw
        elif disabled_raw is None:
            disabled = False
        else:
            disabled = str(disabled_raw).strip().lower() in ("true", "yes", "1")
        last_login = row[7]
        direct_n = int(row[8])
        direct_roles = list(row[9] or [])
        reach_n = int(row[10])
        max_depth = int(row[11])
        reaches_admin = bool(row[12])

        flags: list[str] = []
        if reaches_admin:
            flags.append("reaches_admin")
        if type_v == "PERSON" and not has_mfa:
            flags.append("person_no_mfa")
        if type_v in (None, "LEGACY_SERVICE") and has_password and not has_mfa:
            flags.append("legacy_password_auth")
        if disabled and direct_n > 0:
            flags.append("disabled_with_grants")
        if last_login is None and direct_n > 0:
            flags.append("never_logged_in")

        out.append(
            {
                "name": name,
                "type": type_v,
                "has_mfa": has_mfa,
                "has_password": has_password,
                "has_rsa_public_key": has_rsa,
                "default_role": default_role,
                "disabled": disabled,
                "last_login": str(last_login) if last_login else None,
                "direct_role_count": direct_n,
                "direct_roles": [str(r) for r in direct_roles],
                "reachable_role_count": reach_n,
                "max_path_depth": max_depth,
                "flags": flags,
            }
        )
    return out


def compute_role_origin_breakdown(duck: Any) -> list[dict[str, Any]]:
    rows = duck.execute(
        """
        SELECT origin, COUNT(*) AS n
        FROM roles_with_origin
        GROUP BY origin
        ORDER BY n DESC
        """
    ).fetchall()
    return [{"origin": str(r[0]), "count": int(r[1])} for r in rows]


def _table_exists(duck: Any, name: str) -> bool:
    row = duck.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?",
        [name],
    ).fetchone()
    return bool(row and row[0])
