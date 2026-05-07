from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import duckdb
import pyarrow as pa


_PROFILES = {
    "small": dict(users=50, functional=8, databases=3, schemas_total=12, tables_per_schema=10),
    "medium": dict(users=500, functional=20, databases=5, schemas_total=50, tables_per_schema=20),
    "realistic": dict(users=800, functional=30, databases=30, schemas_total=100, tables_per_schema=15),
    "large": dict(users=2000, functional=40, databases=8, schemas_total=120, tables_per_schema=30),
    "huge": dict(users=5000, functional=80, databases=12, schemas_total=240, tables_per_schema=50),
}

_SYSTEM_ROLES = [
    ("ACCOUNTADMIN", None),
    ("SECURITYADMIN", None),
    ("USERADMIN", None),
    ("SYSADMIN", None),
    ("ORGADMIN", None),
    ("PUBLIC", None),
]

_FUNCTIONAL_NAMES = [
    "DATA_ENGINEER", "DATA_ANALYST", "ANALYTICS_ENGINEER", "ML_ENGINEER",
    "FINANCE_ANALYST", "FINANCE_LEAD", "SALES_ANALYST", "SALES_OPS",
    "MARKETING_ANALYST", "MARKETING_LEAD", "PRODUCT_ANALYST", "PRODUCT_MANAGER",
    "CUSTOMER_SUCCESS_LEAD", "CUSTOMER_ANALYST", "OPERATIONS_ANALYST",
    "SUPPORT_LEAD", "EXEC_VIEWER", "BI_DEVELOPER", "DBA", "SECURITY_AUDITOR",
    "PRIVACY_OFFICER", "FINOPS_ANALYST", "ML_OPS", "DATA_GOVERNANCE",
    "DATA_SCIENTIST", "RESEARCH_ANALYST", "REVOPS_ANALYST", "GROWTH_ANALYST",
    "RETENTION_ANALYST", "HRIS_ANALYST", "PEOPLE_OPS", "LEGAL_REVIEWER",
    "COMPLIANCE_OFFICER", "RISK_ANALYST", "RECRUITING_ANALYST",
    "FIELD_SALES", "PARTNERSHIPS", "ENTERPRISE_AE", "VP_FINANCE", "CFO_VIEWER",
]

_SCHEMA_NAMES = [
    "SALESFORCE", "HUBSPOT", "STRIPE", "ZUORA", "NETSUITE", "WORKDAY",
    "GUSTO", "SEGMENT", "AMPLITUDE", "MIXPANEL", "ZENDESK", "INTERCOM",
    "SHOPIFY", "MARKETO", "PARDOT", "GOOGLE_ADS", "FACEBOOK_ADS", "LINKEDIN",
    "JIRA", "GITHUB", "SLACK", "OKTA", "AUTH0", "PAGERDUTY", "DATADOG",
    "FIVETRAN_LOG", "DBT_AUDIT", "AIRFLOW_DAGS", "SNOWPIPE_INGEST",
    "EVENTS", "CLICKSTREAM", "SESSIONS", "USERS_RAW", "ORDERS_RAW",
    "INVENTORY", "PRODUCTS", "CATALOG", "PAYMENTS", "REFUNDS", "DISPUTES",
]

_DATABASE_NAMES = ["SOURCE", "RAW", "STAGING", "ANALYTICS", "MARTS", "EXPORT", "AUDIT", "ML_FEATURES", "REPORTING", "OPS", "FINANCE", "PEOPLE"]


def _now(offset_days: int = 0) -> datetime:
    return datetime(2026, 5, 1, tzinfo=timezone.utc) + timedelta(days=offset_days)


def generate(
    profile: str,
    output: Path,
    seed: int = 42,
    overrides: dict[str, int] | None = None,
) -> dict[str, int]:
    if profile not in _PROFILES:
        raise ValueError(f"unknown profile {profile!r}; choose from {list(_PROFILES)}")
    cfg = dict(_PROFILES[profile])
    if overrides:
        for k, v in overrides.items():
            if v is not None:
                cfg[k] = v
    rng = random.Random(seed)

    output = Path(output).resolve()
    if output.exists():
        output.unlink()

    duck = duckdb.connect(str(output))

    snapshot_at = _now(0).isoformat()
    duck.execute(
        "CREATE TABLE snapshot_metadata ("
        "snapshot_at TIMESTAMPTZ, account VARCHAR, snapshot_user VARCHAR, "
        "snapshot_role VARCHAR, lookback_days INTEGER, depth_cap INTEGER"
        ")"
    )
    duck.execute(
        "INSERT INTO snapshot_metadata VALUES (?, ?, ?, ?, ?, ?)",
        [snapshot_at, f"SYNTHETIC_{profile.upper()}", "SYNTHETIC", "SYNTHETIC", 30, 30],
    )
    duck.execute(
        "CREATE TABLE snapshot_views ("
        "name VARCHAR, rows INTEGER, "
        "minutes_since_latest_record INTEGER, "
        "documented_max_lag_minutes INTEGER, "
        "error VARCHAR"
        ")"
    )

    needed_dbs = cfg["databases"]
    if needed_dbs <= len(_DATABASE_NAMES):
        databases = _DATABASE_NAMES[:needed_dbs]
    else:
        databases = list(_DATABASE_NAMES) + [
            f"DB_{i:03d}" for i in range(needed_dbs - len(_DATABASE_NAMES))
        ]

    schemas_total = cfg["schemas_total"]
    schemas: list[tuple[str, str]] = []
    schema_idx = 0
    db_distribution: list[int] = []
    base_per_db = schemas_total // len(databases)
    extra = schemas_total - base_per_db * len(databases)
    for i, db in enumerate(databases):
        n_schemas = base_per_db + (1 if i < extra else 0)
        db_distribution.append(n_schemas)
        for _ in range(n_schemas):
            schema_name = (
                _SCHEMA_NAMES[schema_idx % len(_SCHEMA_NAMES)]
                if schema_idx < len(_SCHEMA_NAMES)
                else f"SCHEMA_{schema_idx:03d}"
            )
            schemas.append((db, schema_name))
            schema_idx += 1

    functional_roles = _FUNCTIONAL_NAMES[: cfg["functional"]]
    if cfg["functional"] > len(_FUNCTIONAL_NAMES):
        functional_roles += [f"TEAM_{i}_LEAD" for i in range(cfg["functional"] - len(_FUNCTIONAL_NAMES))]

    access_roles: list[tuple[str, str, str]] = []
    for db, schema in schemas:
        access_roles.append((db, schema, f"{db}_{schema}_VIEWER"))
        access_roles.append((db, schema, f"{db}_{schema}_ADMIN"))

    role_rows: list[dict[str, Any]] = []
    for name, _ in _SYSTEM_ROLES:
        role_rows.append(
            dict(NAME=name, ROLE_TYPE="ROLE", OWNER=None, COMMENT=None,
                 CREATED_ON=_now(-365), DELETED_ON=None)
        )
    for name in functional_roles:
        role_rows.append(
            dict(NAME=name, ROLE_TYPE="ROLE", OWNER="USERADMIN",
                 COMMENT=f"Functional role: {name.replace('_',' ').title()}",
                 CREATED_ON=_now(-300), DELETED_ON=None)
        )
    for _, _, name in access_roles:
        role_rows.append(
            dict(NAME=name, ROLE_TYPE="ROLE", OWNER="USERADMIN",
                 COMMENT=f"Access role for {name}",
                 CREATED_ON=_now(-200), DELETED_ON=None)
        )

    user_rows: list[dict[str, Any]] = []
    for i in range(cfg["users"]):
        user_rows.append(
            dict(
                NAME=f"USER_{i:05d}",
                CREATED_ON=_now(-rng.randint(1, 600)),
                DELETED_ON=None,
                LOGIN_NAME=f"user.{i:05d}@example.com",
                DISPLAY_NAME=f"User {i:05d}",
                EMAIL=f"user.{i:05d}@example.com",
                DISABLED="false",
                DEFAULT_ROLE=rng.choice(functional_roles),
                HAS_MFA=rng.random() > 0.15,
                HAS_PASSWORD=True,
                HAS_RSA_PUBLIC_KEY=False,
                TYPE="PERSON",
                OWNER="USERADMIN",
                LAST_SUCCESS_LOGIN=_now(-rng.randint(0, 30)),
            )
        )
    user_rows.append(
        dict(
            NAME="ETL_FIVETRAN_SVC", CREATED_ON=_now(-300), DELETED_ON=None,
            LOGIN_NAME="fivetran_svc", DISPLAY_NAME="Fivetran service",
            EMAIL=None, DISABLED="false", DEFAULT_ROLE="DATA_ENGINEER",
            HAS_MFA=False, HAS_PASSWORD=False, HAS_RSA_PUBLIC_KEY=True,
            TYPE="SERVICE", OWNER="USERADMIN",
            LAST_SUCCESS_LOGIN=_now(0),
        )
    )
    user_rows.append(
        dict(
            NAME="LEGACY_LOOKER", CREATED_ON=_now(-450), DELETED_ON=None,
            LOGIN_NAME="looker", DISPLAY_NAME="Looker (legacy)",
            EMAIL=None, DISABLED="false", DEFAULT_ROLE="DATA_ENGINEER",
            HAS_MFA=False, HAS_PASSWORD=True, HAS_RSA_PUBLIC_KEY=False,
            TYPE="LEGACY_SERVICE", OWNER="USERADMIN",
            LAST_SUCCESS_LOGIN=_now(-2),
        )
    )

    grants_to_users: list[dict[str, Any]] = []
    for i, u in enumerate(user_rows):
        if u["NAME"] in ("ETL_FIVETRAN_SVC", "LEGACY_LOOKER"):
            grants_to_users.append(
                dict(CREATED_ON=u["CREATED_ON"], DELETED_ON=None,
                     ROLE="DATA_ENGINEER", GRANTED_TO="USER",
                     GRANTEE_NAME=u["NAME"], GRANTED_BY="USERADMIN")
            )
            continue
        n_funcs = rng.randint(1, 3)
        for fr in rng.sample(functional_roles, min(n_funcs, len(functional_roles))):
            grants_to_users.append(
                dict(CREATED_ON=u["CREATED_ON"], DELETED_ON=None,
                     ROLE=fr, GRANTED_TO="USER",
                     GRANTEE_NAME=u["NAME"], GRANTED_BY="USERADMIN")
            )
    grants_to_users.append(
        dict(CREATED_ON=_now(-365), DELETED_ON=None,
             ROLE="ACCOUNTADMIN", GRANTED_TO="USER",
             GRANTEE_NAME="USER_00000", GRANTED_BY=None)
    )

    if cfg["users"] >= 200 and len(functional_roles) >= 6:
        toxic_users = ["USER_00050", "USER_00100", "USER_00150"]
        toxic_combos = [
            ["FINANCE_ANALYST", "DATA_ENGINEER", "SECURITY_AUDITOR"],
            ["CUSTOMER_ANALYST", "FINANCE_LEAD", "DBA"],
            ["RISK_ANALYST", "ML_ENGINEER", "PRIVACY_OFFICER"],
        ]
        for tu, combo in zip(toxic_users, toxic_combos):
            picks = [r for r in combo if r in functional_roles]
            if not picks:
                continue
            grants_to_users = [
                g for g in grants_to_users if g["GRANTEE_NAME"] != tu
            ]
            for fr in picks:
                grants_to_users.append(
                    dict(CREATED_ON=_now(-90), DELETED_ON=None,
                         ROLE=fr, GRANTED_TO="USER",
                         GRANTEE_NAME=tu, GRANTED_BY="USERADMIN")
                )

    grants_to_roles: list[dict[str, Any]] = []
    for fr in functional_roles:
        grants_to_roles.append(
            dict(CREATED_ON=_now(-300), MODIFIED_ON=_now(-300),
                 PRIVILEGE="USAGE", GRANTED_ON="ROLE", NAME=fr,
                 TABLE_CATALOG=None, TABLE_SCHEMA=None,
                 GRANTED_TO="ROLE", GRANTEE_NAME="SYSADMIN",
                 GRANT_OPTION=False, GRANTED_BY="SECURITYADMIN",
                 DELETED_ON=None, GRANTED_BY_ROLE_TYPE="ROLE", OBJECT_INSTANCE=None)
        )
    for _, _, ar in access_roles:
        grants_to_roles.append(
            dict(CREATED_ON=_now(-200), MODIFIED_ON=_now(-200),
                 PRIVILEGE="USAGE", GRANTED_ON="ROLE", NAME=ar,
                 TABLE_CATALOG=None, TABLE_SCHEMA=None,
                 GRANTED_TO="ROLE", GRANTEE_NAME="SYSADMIN",
                 GRANT_OPTION=False, GRANTED_BY="SECURITYADMIN",
                 DELETED_ON=None, GRANTED_BY_ROLE_TYPE="ROLE", OBJECT_INSTANCE=None)
        )

    funcs_rng = random.Random(seed + 1)
    schemas_per_func_min = max(2, len(access_roles) // (cfg["functional"] * 4))
    schemas_per_func_max = max(schemas_per_func_min + 1, len(access_roles) // (cfg["functional"]))
    for fr_idx, fr in enumerate(functional_roles):
        is_admin_role = "ENGINEER" in fr or "OPS" in fr or "DBA" in fr
        n_grants = funcs_rng.randint(schemas_per_func_min, schemas_per_func_max)
        chosen = funcs_rng.sample(access_roles, min(n_grants, len(access_roles)))
        for db, schema, ar in chosen:
            if ar.endswith("_ADMIN") and not is_admin_role:
                ar = ar.replace("_ADMIN", "_VIEWER")
            grants_to_roles.append(
                dict(CREATED_ON=_now(-180 + fr_idx), MODIFIED_ON=_now(-180 + fr_idx),
                     PRIVILEGE="USAGE", GRANTED_ON="ROLE", NAME=ar,
                     TABLE_CATALOG=None, TABLE_SCHEMA=None,
                     GRANTED_TO="ROLE", GRANTEE_NAME=fr,
                     GRANT_OPTION=False, GRANTED_BY="SECURITYADMIN",
                     DELETED_ON=None, GRANTED_BY_ROLE_TYPE="ROLE", OBJECT_INSTANCE=None)
            )

    for db, schema, ar in access_roles:
        is_admin = ar.endswith("_ADMIN")
        grants_to_roles.append(
            dict(CREATED_ON=_now(-200), MODIFIED_ON=_now(-200),
                 PRIVILEGE="USAGE", GRANTED_ON="DATABASE", NAME=db,
                 TABLE_CATALOG=db, TABLE_SCHEMA=None,
                 GRANTED_TO="ROLE", GRANTEE_NAME=ar,
                 GRANT_OPTION=False, GRANTED_BY="SECURITYADMIN",
                 DELETED_ON=None, GRANTED_BY_ROLE_TYPE="ROLE", OBJECT_INSTANCE=None)
        )
        grants_to_roles.append(
            dict(CREATED_ON=_now(-200), MODIFIED_ON=_now(-200),
                 PRIVILEGE="USAGE", GRANTED_ON="SCHEMA", NAME=schema,
                 TABLE_CATALOG=db, TABLE_SCHEMA=None,
                 GRANTED_TO="ROLE", GRANTEE_NAME=ar,
                 GRANT_OPTION=False, GRANTED_BY="SECURITYADMIN",
                 DELETED_ON=None, GRANTED_BY_ROLE_TYPE="ROLE", OBJECT_INSTANCE=None)
        )
        for t in range(cfg["tables_per_schema"]):
            tname = f"TABLE_{t:02d}"
            for priv in (("SELECT",) if not is_admin else ("SELECT", "INSERT", "UPDATE", "DELETE")):
                grants_to_roles.append(
                    dict(CREATED_ON=_now(-150), MODIFIED_ON=_now(-150),
                         PRIVILEGE=priv, GRANTED_ON="TABLE", NAME=tname,
                         TABLE_CATALOG=db, TABLE_SCHEMA=schema,
                         GRANTED_TO="ROLE", GRANTEE_NAME=ar,
                         GRANT_OPTION=False, GRANTED_BY="SYSADMIN",
                         DELETED_ON=None, GRANTED_BY_ROLE_TYPE="ROLE", OBJECT_INSTANCE=None)
                )

    duck.register("_roles", pa.Table.from_pylist(role_rows))
    duck.execute("CREATE TABLE roles AS SELECT * FROM _roles")
    duck.unregister("_roles")

    duck.register("_users", pa.Table.from_pylist(user_rows))
    duck.execute("CREATE TABLE users AS SELECT * FROM _users")
    duck.unregister("_users")

    duck.register("_gtu", pa.Table.from_pylist(grants_to_users))
    duck.execute("CREATE TABLE grants_to_users AS SELECT * FROM _gtu")
    duck.unregister("_gtu")

    duck.register("_gtr", pa.Table.from_pylist(grants_to_roles))
    duck.execute("CREATE TABLE grants_to_roles AS SELECT * FROM _gtr")
    duck.unregister("_gtr")

    policy_rows: list[dict[str, Any]] = []
    tag_rows: list[dict[str, Any]] = []

    sensitive_columns = ["EMAIL", "PHONE", "SSN", "NAME", "ADDRESS", "BIRTH_DATE"]
    financial_columns = ["AMOUNT", "REVENUE", "SALARY", "BONUS"]

    pii_schemas = [s for s in schemas if s[1] in (
        "SALESFORCE", "HUBSPOT", "ZENDESK", "WORKDAY", "GUSTO",
        "USERS_RAW", "CONTACTS"
    )]
    fin_schemas = [s for s in schemas if s[1] in (
        "STRIPE", "ZUORA", "NETSUITE", "PAYMENTS", "REFUNDS", "ORDERS_RAW"
    )]
    pii_sample = pii_schemas[: min(8, len(pii_schemas))]
    fin_sample = fin_schemas[: min(5, len(fin_schemas))]

    for db_name, schema_name in pii_sample:
        for col in sensitive_columns[:3]:
            tag_rows.append({
                "TAG_DATABASE": "GOVERNANCE", "TAG_SCHEMA": "POLICY",
                "TAG_NAME": "DATA_CLASSIFICATION", "TAG_VALUE": "PII",
                "OBJECT_DATABASE": db_name, "OBJECT_SCHEMA": schema_name,
                "OBJECT_NAME": "TABLE_00", "COLUMN_NAME": col, "DOMAIN": "COLUMN",
            })
            policy_rows.append({
                "POLICY_DB": "GOVERNANCE", "POLICY_SCHEMA": "POLICY",
                "POLICY_NAME": "MASK_PII", "POLICY_KIND": "MASKING_POLICY",
                "REF_DATABASE_NAME": db_name, "REF_SCHEMA_NAME": schema_name,
                "REF_ENTITY_NAME": "TABLE_00", "REF_ENTITY_DOMAIN": "COLUMN",
                "REF_COLUMN_NAME": col,
                "TAG_DATABASE": "GOVERNANCE", "TAG_SCHEMA": "POLICY",
                "TAG_NAME": "DATA_CLASSIFICATION", "TAG_VALUE": "PII",
                "POLICY_STATUS": "ACTIVE",
            })

    for db_name, schema_name in fin_sample:
        tag_rows.append({
            "TAG_DATABASE": "GOVERNANCE", "TAG_SCHEMA": "POLICY",
            "TAG_NAME": "DATA_CLASSIFICATION", "TAG_VALUE": "FINANCIAL",
            "OBJECT_DATABASE": db_name, "OBJECT_SCHEMA": schema_name,
            "OBJECT_NAME": "TABLE_00", "COLUMN_NAME": None, "DOMAIN": "TABLE",
        })
        policy_rows.append({
            "POLICY_DB": "GOVERNANCE", "POLICY_SCHEMA": "POLICY",
            "POLICY_NAME": "ROW_ACCESS_FIN", "POLICY_KIND": "ROW_ACCESS_POLICY",
            "REF_DATABASE_NAME": db_name, "REF_SCHEMA_NAME": schema_name,
            "REF_ENTITY_NAME": "TABLE_00", "REF_ENTITY_DOMAIN": "TABLE",
            "REF_COLUMN_NAME": None,
            "TAG_DATABASE": None, "TAG_SCHEMA": None,
            "TAG_NAME": None, "TAG_VALUE": None,
            "POLICY_STATUS": "ACTIVE",
        })

    if policy_rows:
        duck.register("_pol", pa.Table.from_pylist(policy_rows))
        duck.execute("CREATE TABLE policy_references AS SELECT * FROM _pol")
        duck.unregister("_pol")
    else:
        duck.execute("CREATE TABLE policy_references AS SELECT 'x' AS x WHERE 1=0")
    if tag_rows:
        duck.register("_tag", pa.Table.from_pylist(tag_rows))
        duck.execute("CREATE TABLE tag_references AS SELECT * FROM _tag")
        duck.unregister("_tag")
    else:
        duck.execute("CREATE TABLE tag_references AS SELECT 'x' AS x WHERE 1=0")
    duck.execute("CREATE TABLE object_dependencies AS SELECT 'x' AS x WHERE 1=0")

    counts = {
        "roles": len(role_rows),
        "users": len(user_rows),
        "grants_to_roles": len(grants_to_roles),
        "grants_to_users": len(grants_to_users),
    }
    for view, count in counts.items():
        duck.execute(
            "INSERT INTO snapshot_views VALUES (?, ?, ?, ?, ?)",
            [view, count, 0, 120, None],
        )
    for view in ("policy_references", "tag_references", "object_dependencies",
                 "login_history", "query_history", "access_history"):
        duck.execute(
            "INSERT INTO snapshot_views VALUES (?, ?, ?, ?, ?)",
            [view, 0, None, None, "synthetic: not generated"],
        )

    duck.execute("DROP TABLE IF EXISTS roles_with_origin")
    duck.execute(
        """
        CREATE TABLE roles_with_origin AS
        SELECT NAME, ROLE_TYPE, OWNER, COMMENT, CREATED_ON, DELETED_ON,
            CASE
                WHEN NAME IN ('ACCOUNTADMIN','SECURITYADMIN','USERADMIN','SYSADMIN','ORGADMIN','PUBLIC')
                    THEN 'system'
                ELSE 'customer'
            END AS origin
        FROM roles
        """
    )

    duck.execute("DROP TABLE IF EXISTS role_closure")
    duck.execute(
        """
        CREATE TABLE role_closure AS
        WITH RECURSIVE H AS (
            SELECT NAME AS root_role, NAME AS reachable_role, 0 AS depth, [NAME] AS path
            FROM roles
            UNION ALL
            SELECT H.root_role, G.NAME, H.depth + 1, list_append(H.path, G.NAME)
            FROM grants_to_roles G
            JOIN H ON G.GRANTEE_NAME = H.reachable_role
            WHERE G.PRIVILEGE = 'USAGE'
              AND G.GRANTED_ON IN ('ROLE','DATABASE_ROLE')
              AND G.GRANTED_TO IN ('ROLE','DATABASE_ROLE')
              AND H.depth < 30
              AND NOT list_contains(H.path, G.NAME)
        )
        SELECT * FROM H
        """
    )

    duck.close()

    import json
    sidecar = output.parent / f"{output.name}.meta.json"
    sidecar.write_text(json.dumps({
        "output_path": str(output),
        "snapshot_at": snapshot_at,
        "account": f"SYNTHETIC_{profile.upper()}",
        "user": "SYNTHETIC",
        "role": "SYNTHETIC",
        "lookback_days": 30,
        "closure_edges": 0,
        "closure_max_depth": 0,
        "closure_depth_cap": 30,
        "synthetic": True,
        "profile": profile,
        "counts": counts,
    }, indent=2, default=str))

    return counts
