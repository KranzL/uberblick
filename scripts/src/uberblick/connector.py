from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Generator


class SnowflakeConnectionError(Exception):
    pass


@contextmanager
def connect() -> Generator[Any, None, None]:
    import snowflake.connector

    account = os.environ.get("SNOWFLAKE_ACCOUNT")
    user = os.environ.get("SNOWFLAKE_USER")
    password = os.environ.get("SNOWFLAKE_PASSWORD")
    role = os.environ.get("SNOWFLAKE_ROLE")
    warehouse = os.environ.get("SNOWFLAKE_WAREHOUSE")

    missing = [
        k
        for k, v in {
            "SNOWFLAKE_ACCOUNT": account,
            "SNOWFLAKE_USER": user,
            "SNOWFLAKE_PASSWORD": password,
        }.items()
        if not v
    ]
    if missing:
        raise SnowflakeConnectionError(
            f"Missing required env vars: {', '.join(missing)}. "
            f"Set them in .env at the repo root."
        )

    kwargs: dict[str, Any] = {"account": account, "user": user, "password": password}
    if role:
        kwargs["role"] = role
    if warehouse:
        kwargs["warehouse"] = warehouse

    conn = snowflake.connector.connect(**kwargs)
    try:
        yield conn
    finally:
        conn.close()
