from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pyarrow as pa


def _parse_qualified(granted_on: str, name: str) -> tuple[str, str | None, str | None]:
    if granted_on == "DATABASE":
        return name, None, None
    if granted_on == "SCHEMA":
        parts = name.split(".")
        if len(parts) == 2:
            return parts[1], parts[0], None
        return name, None, None
    if granted_on in (
        "TABLE", "VIEW", "MATERIALIZED VIEW", "STAGE", "STREAM", "TASK",
        "PIPE", "FUNCTION", "PROCEDURE", "SEQUENCE", "FILE FORMAT",
        "EXTERNAL TABLE", "DYNAMIC TABLE", "ICEBERG TABLE",
    ):
        parts = name.split(".")
        if len(parts) == 3:
            return parts[2], parts[0], parts[1]
        if len(parts) == 2:
            return parts[1], parts[0], None
        return name, None, None
    return name, None, None


def _show_to_dict(cur: Any) -> list[dict[str, Any]]:
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def extract_roles_live(conn: Any) -> pa.Table:
    cur = conn.cursor()
    try:
        cur.execute("SHOW ROLES")
        rows = _show_to_dict(cur)
    finally:
        cur.close()
    if not rows:
        return pa.table({})
    return pa.table(
        {
            "USER_ID": pa.array([None] * len(rows), type=pa.int64()),
            "NAME": [r.get("name") for r in rows],
            "CREATED_ON": [r.get("created_on") for r in rows],
            "DELETED_ON": pa.array([None] * len(rows), type=pa.timestamp("us", tz="UTC")),
            "ROLE_TYPE": ["ROLE"] * len(rows),
            "OWNER": [r.get("owner") for r in rows],
            "COMMENT": [r.get("comment") for r in rows],
        }
    )


def extract_users_live(conn: Any) -> pa.Table:
    cur = conn.cursor()
    try:
        cur.execute("SHOW USERS")
        rows = _show_to_dict(cur)
    finally:
        cur.close()
    if not rows:
        return pa.table({})

    def to_bool(v: Any) -> bool | None:
        if v is None:
            return None
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        if s in ("true", "yes", "y", "1"):
            return True
        if s in ("false", "no", "n", "0"):
            return False
        return None

    return pa.table(
        {
            "NAME": [r.get("name") for r in rows],
            "CREATED_ON": [r.get("created_on") for r in rows],
            "DELETED_ON": pa.array([None] * len(rows), type=pa.timestamp("us", tz="UTC")),
            "LOGIN_NAME": [r.get("login_name") for r in rows],
            "DISPLAY_NAME": [r.get("display_name") for r in rows],
            "EMAIL": [r.get("email") for r in rows],
            "DISABLED": [r.get("disabled") for r in rows],
            "DEFAULT_ROLE": [r.get("default_role") for r in rows],
            "HAS_MFA": [to_bool(r.get("has_mfa")) for r in rows],
            "HAS_PASSWORD": [to_bool(r.get("has_password")) for r in rows],
            "HAS_RSA_PUBLIC_KEY": [to_bool(r.get("has_rsa_public_key")) for r in rows],
            "TYPE": [r.get("type") for r in rows],
            "OWNER": [r.get("owner") for r in rows],
            "LAST_SUCCESS_LOGIN": [r.get("last_success_login") for r in rows],
        }
    )


def extract_grants_to_roles_live(conn: Any, role_names: list[str]) -> pa.Table:
    all_rows: list[dict[str, Any]] = []
    cur = conn.cursor()
    try:
        for role in role_names:
            try:
                cur.execute(f'SHOW GRANTS TO ROLE "{role}"')
                rows = _show_to_dict(cur)
                all_rows.extend(rows)
            except Exception:
                continue
    finally:
        cur.close()
    if not all_rows:
        return pa.table({})

    def parse_grant_option(v: Any) -> bool:
        return str(v).strip().lower() == "true"

    parsed = [_parse_qualified(r.get("granted_on", ""), r.get("name", "")) for r in all_rows]
    return pa.table(
        {
            "CREATED_ON": [r.get("created_on") for r in all_rows],
            "MODIFIED_ON": [r.get("created_on") for r in all_rows],
            "PRIVILEGE": [r.get("privilege") for r in all_rows],
            "GRANTED_ON": [r.get("granted_on") for r in all_rows],
            "NAME": [p[0] for p in parsed],
            "TABLE_CATALOG": [p[1] for p in parsed],
            "TABLE_SCHEMA": [p[2] for p in parsed],
            "GRANTED_TO": [r.get("granted_to") for r in all_rows],
            "GRANTEE_NAME": [r.get("grantee_name") for r in all_rows],
            "GRANT_OPTION": [parse_grant_option(r.get("grant_option")) for r in all_rows],
            "GRANTED_BY": [r.get("granted_by") for r in all_rows],
            "DELETED_ON": pa.array(
                [None] * len(all_rows), type=pa.timestamp("us", tz="UTC")
            ),
            "GRANTED_BY_ROLE_TYPE": [None] * len(all_rows),
            "OBJECT_INSTANCE": [None] * len(all_rows),
        }
    )


def extract_grants_to_users_live(conn: Any, user_names: list[str]) -> pa.Table:
    all_rows: list[dict[str, Any]] = []
    cur = conn.cursor()
    try:
        for user in user_names:
            try:
                cur.execute(f'SHOW GRANTS TO USER "{user}"')
                rows = _show_to_dict(cur)
                for r in rows:
                    all_rows.append(r)
            except Exception:
                continue
    finally:
        cur.close()
    if not all_rows:
        return pa.table({})
    return pa.table(
        {
            "CREATED_ON": [r.get("created_on") for r in all_rows],
            "DELETED_ON": pa.array(
                [None] * len(all_rows), type=pa.timestamp("us", tz="UTC")
            ),
            "ROLE": [r.get("role") or r.get("name") for r in all_rows],
            "GRANTED_TO": [r.get("granted_to", "USER") for r in all_rows],
            "GRANTEE_NAME": [r.get("grantee_name") for r in all_rows],
            "GRANTED_BY": [r.get("granted_by") for r in all_rows],
        }
    )
