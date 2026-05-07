from __future__ import annotations

from typing import Any

from uberblick.models import GrantPath, PathHop


def _split_object(obj: str) -> tuple[str | None, str | None, str]:
    parts = obj.split(".")
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    if len(parts) == 2:
        return parts[0], None, parts[1]
    return None, None, parts[0]


def _build_object_match_sql(catalog: str | None, schema: str | None, name: str) -> tuple[str, list[Any]]:
    parts: list[str] = []
    args: list[Any] = []

    direct_clause = ["UPPER(g.NAME) = UPPER(?)"]
    direct_args: list[Any] = [name]
    if catalog:
        direct_clause.append("UPPER(g.TABLE_CATALOG) = UPPER(?)")
        direct_args.append(catalog)
    if schema:
        direct_clause.append("UPPER(g.TABLE_SCHEMA) = UPPER(?)")
        direct_args.append(schema)
    parts.append(f"({' AND '.join(direct_clause)})")
    args.extend(direct_args)

    if catalog and schema:
        parts.append(
            "(g.GRANTED_ON = 'SCHEMA' AND UPPER(g.NAME) = UPPER(?) "
            "AND UPPER(g.TABLE_CATALOG) = UPPER(?))"
        )
        args.extend([schema, catalog])

    if catalog:
        parts.append(
            "(g.GRANTED_ON = 'DATABASE' AND UPPER(g.NAME) = UPPER(?))"
        )
        args.append(catalog)

    return "(" + " OR ".join(parts) + ")", args


def find_paths_user_to_object(
    duck: Any,
    user: str,
    object_name: str,
    privilege: str | None = None,
    limit: int = 50,
) -> list[GrantPath]:
    user = user.upper()
    catalog, schema, name = _split_object(object_name)
    object_match_sql, object_match_args = _build_object_match_sql(catalog, schema, name)

    privilege_filter = ""
    privilege_args: list[Any] = []
    if privilege:
        privilege_filter = "AND UPPER(g.PRIVILEGE) = UPPER(?)"
        privilege_args = [privilege]

    sql = f"""
    WITH user_direct_roles AS (
        SELECT DISTINCT ROLE FROM grants_to_users WHERE UPPER(GRANTEE_NAME) = ?
    ),
    user_reach AS (
        SELECT DISTINCT
            udr.ROLE AS direct_role,
            rc.reachable_role,
            rc.depth,
            rc.path
        FROM user_direct_roles udr
        JOIN role_closure rc ON rc.root_role = udr.ROLE
    ),
    role_paths AS (
        SELECT
            ur.direct_role,
            ur.reachable_role,
            ur.depth,
            ur.path,
            g.PRIVILEGE,
            g.GRANTED_ON,
            g.NAME,
            g.TABLE_CATALOG,
            g.TABLE_SCHEMA,
            g.GRANT_OPTION,
            'role' AS path_kind
        FROM user_reach ur
        JOIN grants_to_roles g
          ON UPPER(g.GRANTEE_NAME) = UPPER(ur.reachable_role)
         AND g.GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
        WHERE {object_match_sql}
          {privilege_filter}
    ),
    direct_user_paths AS (
        SELECT
            'DIRECT' AS direct_role,
            NULL AS reachable_role,
            0 AS depth,
            CAST([?] AS VARCHAR[]) AS path,
            g.PRIVILEGE,
            g.GRANTED_ON,
            g.NAME,
            g.TABLE_CATALOG,
            g.TABLE_SCHEMA,
            g.GRANT_OPTION,
            'direct_user' AS path_kind
        FROM grants_to_roles g
        WHERE g.GRANTED_TO = 'USER'
          AND UPPER(g.GRANTEE_NAME) = ?
          AND {object_match_sql}
          {privilege_filter}
    )
    SELECT * FROM role_paths
    UNION ALL
    SELECT * FROM direct_user_paths
    ORDER BY depth ASC, PRIVILEGE
    LIMIT ?
    """

    args = (
        [user]
        + object_match_args
        + privilege_args
        + [user, user]
        + object_match_args
        + privilege_args
        + [limit]
    )
    rows = duck.execute(sql, args).fetchall()

    out: list[GrantPath] = []
    for row in rows:
        direct_role = str(row[0])
        reachable_role = str(row[1]) if row[1] else direct_role
        depth = int(row[2])
        path_list = list(row[3]) if row[3] else [direct_role]
        priv = str(row[4])
        granted_on = str(row[5])
        obj = str(row[6])
        cat = str(row[7]) if row[7] else None
        sch = str(row[8]) if row[8] else None
        with_grant = bool(row[9]) if row[9] is not None else False
        path_kind = str(row[10]) if len(row) > 10 else "role"
        if granted_on == "DATABASE":
            qualified = obj
        elif granted_on == "SCHEMA":
            qualified = ".".join(p for p in (cat, obj) if p)
        else:
            qualified = ".".join(p for p in (cat, sch, obj) if p)

        hops: list[PathHop] = []
        if path_kind == "direct_user":
            hops.append(
                PathHop(
                    kind="grant_object",
                    name=qualified,
                    detail=f"direct {priv}{' WITH GRANT OPTION' if with_grant else ''}",
                )
            )
        else:
            hops.append(PathHop(kind="grant_role", name=direct_role, detail="USAGE"))
            for i in range(1, len(path_list)):
                hops.append(
                    PathHop(kind="inherits", name=str(path_list[i]), detail=None)
                )
            hops.append(
                PathHop(
                    kind="grant_object",
                    name=qualified,
                    detail=f"{priv}{' WITH GRANT OPTION' if with_grant else ''}",
                )
            )

        out.append(
            GrantPath(
                source=user,
                source_kind="USER",
                destination=qualified,
                destination_kind=granted_on,
                privilege=priv,
                hops=hops,
                role_chain_depth=depth,
            )
        )
    return out


def find_paths_to_object(
    duck: Any,
    object_name: str,
    privilege: str | None = None,
    limit: int = 100,
) -> list[GrantPath]:
    catalog, schema, name = _split_object(object_name)

    object_filter_parts = ["UPPER(g.NAME) = UPPER(?)"]
    object_filter_args: list[Any] = [name]
    if catalog:
        object_filter_parts.append("UPPER(g.TABLE_CATALOG) = UPPER(?)")
        object_filter_args.append(catalog)
    if schema:
        object_filter_parts.append("UPPER(g.TABLE_SCHEMA) = UPPER(?)")
        object_filter_args.append(schema)
    object_filter = " AND ".join(object_filter_parts)

    privilege_filter = ""
    privilege_args: list[Any] = []
    if privilege:
        privilege_filter = "AND UPPER(g.PRIVILEGE) = UPPER(?)"
        privilege_args = [privilege]

    sql = f"""
    WITH role_with_grant AS (
        SELECT
            g.GRANTEE_NAME AS role_with_direct_grant,
            g.PRIVILEGE,
            g.GRANTED_ON,
            g.NAME,
            g.TABLE_CATALOG,
            g.TABLE_SCHEMA,
            g.GRANT_OPTION
        FROM grants_to_roles g
        WHERE {object_filter}
          {privilege_filter}
    ),
    user_via_role AS (
        SELECT
            gu.GRANTEE_NAME AS user_name,
            gu.ROLE AS direct_role,
            rc.reachable_role,
            rc.depth,
            rwg.PRIVILEGE,
            rwg.GRANTED_ON,
            rwg.NAME,
            rwg.TABLE_CATALOG,
            rwg.TABLE_SCHEMA,
            rwg.GRANT_OPTION
        FROM grants_to_users gu
        JOIN role_closure rc ON rc.root_role = gu.ROLE
        JOIN role_with_grant rwg
          ON UPPER(rwg.role_with_direct_grant) = UPPER(rc.reachable_role)
    )
    SELECT
        user_name,
        direct_role,
        reachable_role,
        depth,
        PRIVILEGE,
        GRANTED_ON,
        NAME,
        TABLE_CATALOG,
        TABLE_SCHEMA,
        GRANT_OPTION
    FROM user_via_role
    ORDER BY depth ASC, user_name, PRIVILEGE
    LIMIT ?
    """

    args = object_filter_args + privilege_args + [limit]
    rows = duck.execute(sql, args).fetchall()

    out: list[GrantPath] = []
    for row in rows:
        user = str(row[0])
        direct_role = str(row[1])
        reachable_role = str(row[2])
        depth = int(row[3])
        priv = str(row[4])
        granted_on = str(row[5])
        obj = str(row[6])
        cat = str(row[7]) if row[7] else None
        sch = str(row[8]) if row[8] else None
        with_grant = bool(row[9]) if row[9] is not None else False
        if granted_on == "DATABASE":
            qualified = obj
        elif granted_on == "SCHEMA":
            qualified = ".".join(p for p in (cat, obj) if p)
        else:
            qualified = ".".join(p for p in (cat, sch, obj) if p)

        hops: list[PathHop] = []
        hops.append(PathHop(kind="grant_role", name=direct_role, detail="USAGE"))
        if reachable_role != direct_role:
            hops.append(
                PathHop(kind="inherits", name=reachable_role, detail=f"depth={depth}")
            )
        hops.append(
            PathHop(
                kind="grant_object",
                name=qualified,
                detail=f"{priv}{' WITH GRANT OPTION' if with_grant else ''}",
            )
        )

        out.append(
            GrantPath(
                source=user,
                source_kind="USER",
                destination=qualified,
                destination_kind=granted_on,
                privilege=priv,
                hops=hops,
                role_chain_depth=depth,
            )
        )
    return out
