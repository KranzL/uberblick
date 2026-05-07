from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import duckdb


@dataclass
class SnapshotDiff:
    from_path: str
    to_path: str
    from_at: str | None
    to_at: str | None
    added_roles: list[dict[str, Any]] = field(default_factory=list)
    removed_roles: list[dict[str, Any]] = field(default_factory=list)
    added_users: list[dict[str, Any]] = field(default_factory=list)
    removed_users: list[dict[str, Any]] = field(default_factory=list)
    added_user_role_grants: list[dict[str, Any]] = field(default_factory=list)
    removed_user_role_grants: list[dict[str, Any]] = field(default_factory=list)
    added_role_grants: list[dict[str, Any]] = field(default_factory=list)
    removed_role_grants: list[dict[str, Any]] = field(default_factory=list)
    user_mfa_toggled: list[dict[str, Any]] = field(default_factory=list)
    user_default_role_changed: list[dict[str, Any]] = field(default_factory=list)


def compute_diff(from_path: Path, to_path: Path) -> SnapshotDiff:
    from_path = Path(from_path).resolve()
    to_path = Path(to_path).resolve()

    con = duckdb.connect(":memory:")
    con.execute(f"ATTACH '{from_path}' AS prev (READ_ONLY)")
    con.execute(f"ATTACH '{to_path}' AS curr (READ_ONLY)")

    def fetch_meta(alias: str) -> str | None:
        try:
            row = con.execute(f"SELECT snapshot_at FROM {alias}.snapshot_metadata").fetchone()
            return str(row[0]) if row and row[0] else None
        except Exception:
            return None

    diff = SnapshotDiff(
        from_path=str(from_path),
        to_path=str(to_path),
        from_at=fetch_meta("prev"),
        to_at=fetch_meta("curr"),
    )

    diff.added_roles = [
        {"name": str(r[0]), "owner": str(r[1]) if r[1] else None}
        for r in con.execute(
            """
            SELECT NAME, OWNER
            FROM curr.roles
            WHERE NAME NOT IN (SELECT NAME FROM prev.roles)
            ORDER BY NAME
            """
        ).fetchall()
    ]
    diff.removed_roles = [
        {"name": str(r[0]), "owner": str(r[1]) if r[1] else None}
        for r in con.execute(
            """
            SELECT NAME, OWNER
            FROM prev.roles
            WHERE NAME NOT IN (SELECT NAME FROM curr.roles)
            ORDER BY NAME
            """
        ).fetchall()
    ]

    diff.added_users = [
        {"name": str(r[0]), "type": str(r[1]) if r[1] else None}
        for r in con.execute(
            """
            SELECT NAME, TYPE
            FROM curr.users
            WHERE NAME NOT IN (SELECT NAME FROM prev.users)
            ORDER BY NAME
            """
        ).fetchall()
    ]
    diff.removed_users = [
        {"name": str(r[0]), "type": str(r[1]) if r[1] else None}
        for r in con.execute(
            """
            SELECT NAME, TYPE
            FROM prev.users
            WHERE NAME NOT IN (SELECT NAME FROM curr.users)
            ORDER BY NAME
            """
        ).fetchall()
    ]

    diff.added_user_role_grants = [
        {"user": str(r[0]), "role": str(r[1])}
        for r in con.execute(
            """
            SELECT GRANTEE_NAME, ROLE
            FROM curr.grants_to_users
            WHERE COALESCE(DELETED_ON, NULL) IS NULL
              AND (GRANTEE_NAME, ROLE) NOT IN (
                SELECT GRANTEE_NAME, ROLE FROM prev.grants_to_users
                WHERE COALESCE(DELETED_ON, NULL) IS NULL
              )
            ORDER BY GRANTEE_NAME, ROLE
            """
        ).fetchall()
    ]
    diff.removed_user_role_grants = [
        {"user": str(r[0]), "role": str(r[1])}
        for r in con.execute(
            """
            SELECT GRANTEE_NAME, ROLE
            FROM prev.grants_to_users
            WHERE COALESCE(DELETED_ON, NULL) IS NULL
              AND (GRANTEE_NAME, ROLE) NOT IN (
                SELECT GRANTEE_NAME, ROLE FROM curr.grants_to_users
                WHERE COALESCE(DELETED_ON, NULL) IS NULL
              )
            ORDER BY GRANTEE_NAME, ROLE
            """
        ).fetchall()
    ]

    grant_key_sql = (
        "GRANTEE_NAME || '|' || PRIVILEGE || '|' || GRANTED_ON || '|' || "
        "COALESCE(TABLE_CATALOG, '') || '|' || COALESCE(TABLE_SCHEMA, '') "
        "|| '|' || NAME"
    )
    diff.added_role_grants = [
        {
            "grantee": str(r[0]),
            "privilege": str(r[1]),
            "granted_on": str(r[2]),
            "object": _qualified(str(r[2]), str(r[5]) if r[5] else None,
                                 str(r[3]) if r[3] else None,
                                 str(r[4]) if r[4] else None),
        }
        for r in con.execute(
            f"""
            SELECT GRANTEE_NAME, PRIVILEGE, GRANTED_ON,
                   TABLE_CATALOG, TABLE_SCHEMA, NAME
            FROM curr.grants_to_roles
            WHERE DELETED_ON IS NULL
              AND ({grant_key_sql}) NOT IN (
                SELECT {grant_key_sql} FROM prev.grants_to_roles
                WHERE DELETED_ON IS NULL
              )
            ORDER BY GRANTEE_NAME, PRIVILEGE, GRANTED_ON
            LIMIT 5000
            """
        ).fetchall()
    ]
    diff.removed_role_grants = [
        {
            "grantee": str(r[0]),
            "privilege": str(r[1]),
            "granted_on": str(r[2]),
            "object": _qualified(str(r[2]), str(r[5]) if r[5] else None,
                                 str(r[3]) if r[3] else None,
                                 str(r[4]) if r[4] else None),
        }
        for r in con.execute(
            f"""
            SELECT GRANTEE_NAME, PRIVILEGE, GRANTED_ON,
                   TABLE_CATALOG, TABLE_SCHEMA, NAME
            FROM prev.grants_to_roles
            WHERE DELETED_ON IS NULL
              AND ({grant_key_sql}) NOT IN (
                SELECT {grant_key_sql} FROM curr.grants_to_roles
                WHERE DELETED_ON IS NULL
              )
            ORDER BY GRANTEE_NAME, PRIVILEGE, GRANTED_ON
            LIMIT 5000
            """
        ).fetchall()
    ]

    diff.user_mfa_toggled = [
        {"user": str(r[0]), "from_mfa": bool(r[1]) if r[1] is not None else None,
         "to_mfa": bool(r[2]) if r[2] is not None else None}
        for r in con.execute(
            """
            SELECT c.NAME, p.HAS_MFA, c.HAS_MFA
            FROM curr.users c
            JOIN prev.users p ON p.NAME = c.NAME
            WHERE COALESCE(p.HAS_MFA, FALSE) <> COALESCE(c.HAS_MFA, FALSE)
            """
        ).fetchall()
    ]
    diff.user_default_role_changed = [
        {"user": str(r[0]),
         "from_default": str(r[1]) if r[1] else None,
         "to_default": str(r[2]) if r[2] else None}
        for r in con.execute(
            """
            SELECT c.NAME, p.DEFAULT_ROLE, c.DEFAULT_ROLE
            FROM curr.users c
            JOIN prev.users p ON p.NAME = c.NAME
            WHERE COALESCE(p.DEFAULT_ROLE, '') <> COALESCE(c.DEFAULT_ROLE, '')
            """
        ).fetchall()
    ]

    con.close()
    return diff


def _qualified(granted_on: str, name: str | None, catalog: str | None, schema: str | None) -> str:
    if granted_on == "DATABASE":
        return name or ""
    if granted_on == "SCHEMA":
        parts = [catalog, name]
    else:
        parts = [catalog, schema, name]
    return ".".join(p for p in parts if p)
