from __future__ import annotations

from dataclasses import asdict
from typing import Any, Callable

from uberblick.audit_packs import packs_for_rule, rules_in_pack
from uberblick.models import Finding, Severity


_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


_SNOWFLAKE_SHIPPED_DATABASES = {
    "SNOWFLAKE",
    "SNOWFLAKE_SAMPLE_DATA",
}

_SYSTEM_ROLES = {
    "ACCOUNTADMIN",
    "SECURITYADMIN",
    "USERADMIN",
    "SYSADMIN",
    "ORGADMIN",
    "PUBLIC",
}


RuleFn = Callable[[Any], list[Finding]]


def _table_exists(duck: Any, name: str) -> bool:
    row = duck.execute(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?",
        [name],
    ).fetchone()
    return bool(row and row[0])


def _qualify(granted_on: str, name: str, catalog: str | None, schema: str | None) -> str:
    if granted_on == "DATABASE":
        return name
    if granted_on == "SCHEMA":
        return ".".join(p for p in (catalog, name) if p)
    parts = [p for p in (catalog, schema, name) if p]
    return ".".join(parts)


def _is_snowflake_shipped_object(catalog: str | None, name: str) -> bool:
    if catalog and catalog in _SNOWFLAKE_SHIPPED_DATABASES:
        return True
    if name in _SNOWFLAKE_SHIPPED_DATABASES:
        return True
    if name.startswith("SYSTEM$"):
        return True
    return False


def rule_accountadmin_default_role(duck: Any) -> list[Finding]:
    accountadmin_rows = duck.execute(
        "SELECT GRANTEE_NAME FROM grants_to_users WHERE ROLE = 'ACCOUNTADMIN'"
    ).fetchall()
    accountadmin_holders = {str(r[0]) for r in accountadmin_rows}
    orgadmin_rows = duck.execute(
        "SELECT GRANTEE_NAME FROM grants_to_users WHERE ROLE = 'ORGADMIN'"
    ).fetchall()
    orgadmin_holders = {str(r[0]) for r in orgadmin_rows}

    rows = duck.execute(
        """
        SELECT NAME, DEFAULT_ROLE, TYPE, HAS_MFA, LAST_SUCCESS_LOGIN
        FROM users
        WHERE DEFAULT_ROLE = 'ACCOUNTADMIN'
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        name = str(row[0])
        is_lone_org_creator = (
            len(accountadmin_holders) == 1
            and name in accountadmin_holders
            and name in orgadmin_holders
        )
        if is_lone_org_creator:
            severity: Severity = "LOW"
            qualifier = " (org-creator pattern: sole user holding both ACCOUNTADMIN and ORGADMIN; expected for solo-owner accounts)"
        else:
            severity = "HIGH"
            qualifier = ""
        findings.append(
            Finding(
                rule_id="accountadmin_default_role",
                severity=severity,
                category="privileged_access",
                title=f"User {name} has ACCOUNTADMIN as default role{qualifier}",
                summary=(
                    f"User '{name}' is configured with DEFAULT_ROLE = ACCOUNTADMIN. "
                    "Snowflake explicitly recommends never setting ACCOUNTADMIN as a "
                    "default role; it leads to destructive mistakes and accidental "
                    "ownership of objects."
                    + (
                        " This account currently has only one ACCOUNTADMIN holder "
                        "and they also hold ORGADMIN, which suggests they are the "
                        "org creator. The risk is reduced but not zero."
                        if is_lone_org_creator
                        else ""
                    )
                ),
                evidence={
                    "user": name,
                    "default_role": str(row[1]) if row[1] else None,
                    "type": str(row[2]) if row[2] else None,
                    "has_mfa": bool(row[3]) if row[3] is not None else None,
                    "last_login": str(row[4]) if row[4] else None,
                    "lone_org_creator": is_lone_org_creator,
                },
                remediation=(
                    f"ALTER USER {name} SET DEFAULT_ROLE = <less_privileged_role>; "
                    "Users can still USE ROLE ACCOUNTADMIN explicitly when needed."
                ),
            )
        )
    return findings


def rule_accountadmin_owned_objects(duck: Any) -> list[Finding]:
    rows = duck.execute(
        """
        SELECT GRANTED_ON, NAME, TABLE_CATALOG, TABLE_SCHEMA, CREATED_ON
        FROM grants_to_roles
        WHERE PRIVILEGE = 'OWNERSHIP'
          AND GRANTEE_NAME = 'ACCOUNTADMIN'
          AND GRANTED_ON NOT IN ('ACCOUNT', 'ROLE', 'DATABASE_ROLE',
                                  'INSTANCE_ROLE', 'APPLICATION_ROLE',
                                  'WAREHOUSE', 'INTEGRATION', 'USER')
        ORDER BY CREATED_ON DESC
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        granted_on = str(row[0])
        name = str(row[1])
        catalog = str(row[2]) if row[2] else None
        schema = str(row[3]) if row[3] else None
        if _is_snowflake_shipped_object(catalog, name):
            continue
        qualified = _qualify(granted_on, name, catalog, schema)
        findings.append(
            Finding(
                rule_id="accountadmin_owned_object",
                severity="MEDIUM",
                category="ownership",
                title=f"ACCOUNTADMIN owns {granted_on} {qualified}",
                summary=(
                    f"The {granted_on.lower()} '{qualified}' is owned by ACCOUNTADMIN. "
                    "Snowflake docs warn against ACCOUNTADMIN-owned business objects: "
                    "they can't be managed by SYSADMIN-rooted hierarchies, and they "
                    "accumulate after a DROP ROLE that runs from an ACCOUNTADMIN session."
                ),
                evidence={
                    "object_type": granted_on,
                    "object_name": qualified,
                    "created_on": str(row[4]) if row[4] else None,
                },
                remediation=(
                    f"GRANT OWNERSHIP ON {granted_on} {qualified} TO ROLE "
                    "<sysadmin_descendant_role> COPY CURRENT GRANTS;"
                ),
            )
        )
    return findings


def rule_accountadmin_concentration(duck: Any) -> list[Finding]:
    rows = duck.execute(
        """
        SELECT GRANTEE_NAME
        FROM grants_to_users
        WHERE ROLE = 'ACCOUNTADMIN'
        ORDER BY GRANTEE_NAME
        """
    ).fetchall()
    holders = [str(r[0]) for r in rows]
    if len(holders) <= 1:
        return []
    return [
        Finding(
            rule_id="accountadmin_concentration",
            severity="HIGH" if len(holders) <= 3 else "CRITICAL",
            category="privileged_access",
            title=f"{len(holders)} users hold ACCOUNTADMIN",
            summary=(
                f"ACCOUNTADMIN is granted to {len(holders)} users: "
                f"{', '.join(holders)}. Snowflake docs recommend limiting "
                "ACCOUNTADMIN to a small handful of named individuals (typically 2-3) "
                "with MFA enforced."
            ),
            evidence={"holders": holders, "count": len(holders)},
            remediation=(
                "Audit the holders. Revoke ACCOUNTADMIN from anyone who doesn't "
                "need it: REVOKE ROLE ACCOUNTADMIN FROM USER <name>;"
            ),
        )
    ]


def rule_user_no_mfa(duck: Any) -> list[Finding]:
    rows = duck.execute(
        """
        SELECT NAME, TYPE, HAS_MFA, LAST_SUCCESS_LOGIN, DISABLED
        FROM users
        WHERE (DISABLED IS NULL OR LOWER(DISABLED) = 'false')
          AND COALESCE(HAS_MFA, FALSE) = FALSE
          AND COALESCE(TYPE, 'PERSON') = 'PERSON'
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        name = str(row[0])
        findings.append(
            Finding(
                rule_id="user_no_mfa",
                severity="HIGH",
                category="authentication",
                title=f"Human user {name} has no MFA",
                summary=(
                    f"User '{name}' has TYPE = PERSON but HAS_MFA = FALSE. "
                    "Snowflake's MFA rollout (Aug-Oct 2025) requires MFA for all "
                    "PERSON users; password sign-ins without MFA are blocked as of "
                    "Nov 2025. The 2024 UNC5537 breach exploited exactly this: human "
                    "users on password-only auth."
                ),
                evidence={
                    "user": name,
                    "type": str(row[1]) if row[1] else None,
                    "last_login": str(row[3]) if row[3] else None,
                },
                remediation=(
                    f"Have {name} enroll MFA via Snowsight or SSO. "
                    "Or apply an authentication policy enforcing MFA on this user."
                ),
            )
        )
    return findings


def rule_legacy_service_or_password_service(duck: Any) -> list[Finding]:
    rows = duck.execute(
        """
        SELECT NAME, TYPE, HAS_MFA, LAST_SUCCESS_LOGIN
        FROM users
        WHERE (DISABLED IS NULL OR LOWER(DISABLED) = 'false')
          AND (
            TYPE = 'LEGACY_SERVICE'
            OR (TYPE IS NULL AND COALESCE(HAS_MFA, FALSE) = FALSE
                AND NAME NOT IN ('SNOWFLAKE'))
          )
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        name = str(row[0])
        type_value = row[1]
        is_legacy = type_value == "LEGACY_SERVICE"
        findings.append(
            Finding(
                rule_id="legacy_or_password_service_user",
                severity="HIGH" if is_legacy else "MEDIUM",
                category="authentication",
                title=(
                    f"Service-style user {name} on deprecated auth"
                    if is_legacy
                    else f"User {name} has no TYPE set and no MFA"
                ),
                summary=(
                    f"User '{name}' has TYPE = {type_value or 'NULL'} and HAS_MFA = FALSE. "
                    "Snowflake's 2026 deprecation removes LEGACY_SERVICE entirely and "
                    "blocks single-factor password auth for all users. Migrate to "
                    "TYPE = SERVICE with key-pair / OAuth / PAT, or to TYPE = PERSON with MFA."
                ),
                evidence={
                    "user": name,
                    "type": str(type_value) if type_value else None,
                    "has_mfa": False,
                    "last_login": str(row[3]) if row[3] else None,
                },
                remediation=(
                    f"For automation: ALTER USER {name} SET TYPE = SERVICE; "
                    "then attach a key-pair (RSA) or OAuth integration. "
                    f"For humans: have {name} enroll MFA."
                ),
            )
        )
    return findings


def rule_unused_customer_role(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "roles_with_origin"):
        return []
    if not _table_exists(duck, "query_history"):
        return []
    rows = duck.execute(
        """
        SELECT r.NAME, r.OWNER, r.CREATED_ON
        FROM roles_with_origin r
        LEFT JOIN (
            SELECT DISTINCT ROLE_NAME FROM query_history WHERE ROLE_NAME IS NOT NULL
        ) q ON UPPER(q.ROLE_NAME) = UPPER(r.NAME)
        WHERE r.origin = 'customer'
          AND q.ROLE_NAME IS NULL
          AND r.CREATED_ON < CURRENT_TIMESTAMP - INTERVAL 7 DAY
        ORDER BY r.CREATED_ON
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        name = str(row[0])
        findings.append(
            Finding(
                rule_id="unused_customer_role",
                severity="LOW",
                category="hygiene",
                title=f"Customer role {name} not used in last 30 days",
                summary=(
                    f"Role '{name}' was created more than 7 days ago and has no "
                    "QUERY_HISTORY activity in the snapshot window (default 30 days). "
                    "Candidate for revocation if confirmed unused."
                ),
                evidence={
                    "role": name,
                    "owner": str(row[1]) if row[1] else None,
                    "created_on": str(row[2]) if row[2] else None,
                },
                remediation=(
                    "Confirm with role owner before revoking. Then: "
                    f"DROP ROLE IF EXISTS {name}; -- ensure no objects are owned first"
                ),
            )
        )
    return findings


def rule_public_role_non_trivial_grant(duck: Any) -> list[Finding]:
    rows = duck.execute(
        """
        SELECT PRIVILEGE, GRANTED_ON, NAME, TABLE_CATALOG, TABLE_SCHEMA, GRANT_OPTION
        FROM grants_to_roles
        WHERE GRANTEE_NAME = 'PUBLIC'
          AND NOT (PRIVILEGE = 'USAGE' AND GRANTED_ON IN ('DATABASE', 'SCHEMA'))
          AND GRANTED_ON NOT IN ('APPLICATION_ROLE', 'INSTANCE_ROLE', 'DATABASE_ROLE')
        ORDER BY PRIVILEGE
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        privilege = str(row[0])
        granted_on = str(row[1])
        obj_name = str(row[2])
        catalog = str(row[3]) if row[3] else None
        schema = str(row[4]) if row[4] else None
        if _is_snowflake_shipped_object(catalog, obj_name):
            continue
        if granted_on == "ACCOUNT":
            continue
        qualified = _qualify(granted_on, obj_name, catalog, schema)
        findings.append(
            Finding(
                rule_id="public_role_non_trivial_grant",
                severity="MEDIUM",
                category="access_leak",
                title=f"PUBLIC role granted {privilege} on {granted_on} {qualified}",
                summary=(
                    f"PUBLIC has {privilege} on {granted_on} '{qualified}'. PUBLIC is "
                    "auto-granted to every user, so any non-trivial privilege on PUBLIC "
                    "is effectively granting that privilege to the entire account."
                ),
                evidence={
                    "privilege": privilege,
                    "object_type": granted_on,
                    "object_name": qualified,
                    "grant_option": bool(row[5]) if row[5] is not None else False,
                },
                remediation=(
                    f"REVOKE {privilege} ON {granted_on} {qualified} FROM ROLE PUBLIC; "
                    "then grant the privilege to a specific role that needs it."
                ),
            )
        )
    return findings


def rule_grant_option_proliferation(duck: Any) -> list[Finding]:
    placeholders = ", ".join(f"'{r}'" for r in _SYSTEM_ROLES)
    rows = duck.execute(
        f"""
        SELECT PRIVILEGE, GRANTED_ON, NAME, TABLE_CATALOG, TABLE_SCHEMA, GRANTEE_NAME
        FROM grants_to_roles
        WHERE GRANT_OPTION = TRUE
          AND GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
          AND GRANTEE_NAME NOT IN ({placeholders})
          AND GRANTED_ON NOT IN ('APPLICATION_ROLE', 'INSTANCE_ROLE', 'ACCOUNT')
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        privilege = str(row[0])
        granted_on = str(row[1])
        obj_name = str(row[2])
        catalog = str(row[3]) if row[3] else None
        schema = str(row[4]) if row[4] else None
        grantee = str(row[5])
        if _is_snowflake_shipped_object(catalog, obj_name):
            continue
        qualified = _qualify(granted_on, obj_name, catalog, schema)
        findings.append(
            Finding(
                rule_id="grant_option_proliferation",
                severity="MEDIUM",
                category="privilege_propagation",
                title=f"Role {grantee} can re-grant {privilege} on {granted_on} {qualified}",
                summary=(
                    f"Role '{grantee}' holds {privilege} WITH GRANT OPTION on "
                    f"{granted_on} '{qualified}'. {grantee} can grant the "
                    "same privilege to any other role, creating uncontrolled fan-out. "
                    "Reserve GRANT OPTION for SECURITYADMIN."
                ),
                evidence={
                    "grantee": grantee,
                    "privilege": privilege,
                    "object_type": granted_on,
                    "object_name": qualified,
                },
                remediation=(
                    f"REVOKE {privilege} ON {granted_on} {qualified} FROM ROLE {grantee}; "
                    f"GRANT {privilege} ON {granted_on} {qualified} TO ROLE {grantee};"
                ),
            )
        )
    return findings


def rule_service_account_overprivileged(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "role_closure"):
        return []
    rows = duck.execute(
        """
        WITH service_users AS (
            SELECT NAME, TYPE, HAS_MFA
            FROM users
            WHERE TYPE IN ('SERVICE', 'LEGACY_SERVICE')
               OR (TYPE IS NULL AND COALESCE(HAS_MFA, FALSE) = FALSE
                   AND NAME LIKE '%_USER')
        ),
        user_roles AS (
            SELECT u.NAME AS user_name, gu.ROLE
            FROM service_users u
            JOIN grants_to_users gu ON gu.GRANTEE_NAME = u.NAME
        ),
        privileged_paths AS (
            SELECT DISTINCT
                ur.user_name,
                ur.ROLE AS direct_role,
                rc.reachable_role AS privileged_role
            FROM user_roles ur
            JOIN role_closure rc ON rc.root_role = ur.ROLE
            WHERE rc.reachable_role IN (
                'ACCOUNTADMIN', 'SECURITYADMIN', 'ORGADMIN', 'USERADMIN'
            )
        )
        SELECT user_name, direct_role, privileged_role
        FROM privileged_paths
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        user = str(row[0])
        direct_role = str(row[1])
        privileged_role = str(row[2])
        findings.append(
            Finding(
                rule_id="service_account_overprivileged",
                severity="CRITICAL",
                category="privileged_access",
                title=f"Service-style user {user} can reach {privileged_role}",
                summary=(
                    f"Service user '{user}' was granted '{direct_role}', which "
                    f"transitively reaches '{privileged_role}'. Service accounts should "
                    "never reach administrative roles. The 2024 UNC5537 breach "
                    "demonstrated that compromised service-account credentials with admin "
                    "reach are the largest blast radius in Snowflake incidents."
                ),
                evidence={
                    "user": user,
                    "direct_role": direct_role,
                    "privileged_role": privileged_role,
                },
                remediation=(
                    f"REVOKE ROLE {direct_role} FROM USER {user}; then grant a narrowly-"
                    "scoped role with only the privileges this service genuinely needs."
                ),
            )
        )
    return findings


def rule_manage_grants_holder(duck: Any) -> list[Finding]:
    placeholders = ", ".join(f"'{r}'" for r in _SYSTEM_ROLES)
    rows = duck.execute(
        f"""
        SELECT DISTINCT GRANTEE_NAME, GRANTED_TO, GRANTED_BY
        FROM grants_to_roles
        WHERE PRIVILEGE = 'MANAGE GRANTS'
          AND GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
          AND GRANTEE_NAME NOT IN ({placeholders})
          AND DELETED_ON IS NULL
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        grantee = str(row[0])
        granted_by = str(row[2]) if row[2] else None
        findings.append(
            Finding(
                rule_id="manage_grants_holder",
                severity="CRITICAL",
                category="privilege_propagation",
                title=f"Role {grantee} holds MANAGE GRANTS",
                summary=(
                    f"Role '{grantee}' has been granted MANAGE GRANTS. Per Snowflake "
                    "docs, a role with global MANAGE GRANTS can grant additional "
                    "privileges to itself -- a documented self-elevation path. CIS "
                    "Snowflake Foundations Benchmark 2.2 requires monitoring every "
                    "new MANAGE GRANTS recipient. Reserve this for SECURITYADMIN."
                ),
                evidence={
                    "grantee": grantee,
                    "granted_by": granted_by,
                },
                remediation=(
                    f"REVOKE MANAGE GRANTS ON ACCOUNT FROM ROLE {grantee}; "
                    "Use SECURITYADMIN for any operation that needs MANAGE GRANTS."
                ),
            )
        )
    return findings


def rule_role_nested_under_admin(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "roles_with_origin"):
        return []
    rows = duck.execute(
        """
        SELECT DISTINCT G.GRANTEE_NAME AS custom_role, G.NAME AS admin_role
        FROM grants_to_roles G
        JOIN roles_with_origin r ON r.NAME = G.GRANTEE_NAME
        WHERE G.PRIVILEGE = 'USAGE'
          AND G.GRANTED_ON = 'ROLE'
          AND G.GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
          AND G.NAME IN ('ACCOUNTADMIN', 'SECURITYADMIN', 'SYSADMIN', 'USERADMIN', 'ORGADMIN')
          AND r.origin = 'customer'
          AND G.DELETED_ON IS NULL
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        custom_role = str(row[0])
        admin_role = str(row[1])
        findings.append(
            Finding(
                rule_id="role_nested_under_admin",
                severity="CRITICAL",
                category="privileged_access",
                title=f"Custom role {custom_role} inherits {admin_role}",
                summary=(
                    f"The system admin role '{admin_role}' was granted TO custom "
                    f"role '{custom_role}'. This means anyone activating "
                    f"{custom_role} silently inherits {admin_role}'s privileges. "
                    "Snowflake best practice grants flow the OPPOSITE direction "
                    "(custom roles roll up TO SYSADMIN, not the other way)."
                ),
                evidence={
                    "custom_role": custom_role,
                    "admin_role": admin_role,
                },
                remediation=(
                    f"REVOKE ROLE {admin_role} FROM ROLE {custom_role}; "
                    f"Investigate who granted this and what {custom_role}'s "
                    "actual responsibilities require."
                ),
            )
        )
    return findings


def rule_role_name_semantic_mismatch(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "roles_with_origin"):
        return []
    rows = duck.execute(
        """
        WITH role_grants AS (
            SELECT
                GRANTEE_NAME AS role,
                BOOL_OR(PRIVILEGE IN (
                    'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE',
                    'CREATE TABLE', 'CREATE VIEW', 'CREATE STAGE',
                    'OWNERSHIP', 'MODIFY'
                )) AS has_write,
                ARRAY_AGG(DISTINCT PRIVILEGE) AS privs
            FROM grants_to_roles
            WHERE GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
              AND GRANTED_ON IN ('TABLE', 'VIEW', 'SCHEMA', 'DATABASE')
              AND DELETED_ON IS NULL
            GROUP BY GRANTEE_NAME
        )
        SELECT r.NAME, rg.privs
        FROM roles_with_origin r
        JOIN role_grants rg ON rg.role = r.NAME
        WHERE r.origin = 'customer'
          AND (
            UPPER(r.NAME) LIKE '%VIEWER%'
            OR UPPER(r.NAME) LIKE '%READER%'
            OR UPPER(r.NAME) LIKE '%READONLY%'
            OR UPPER(r.NAME) LIKE '%READ\\_ONLY%' ESCAPE '\\'
            OR UPPER(r.NAME) LIKE '%\\_RO' ESCAPE '\\'
            OR UPPER(r.NAME) LIKE '%\\_R' ESCAPE '\\'
          )
          AND rg.has_write = TRUE
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        name = str(row[0])
        privs = list(row[1] or [])
        write_privs = sorted(
            p for p in privs
            if p in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "CREATE TABLE",
                     "CREATE VIEW", "CREATE STAGE", "OWNERSHIP", "MODIFY")
        )
        findings.append(
            Finding(
                rule_id="role_name_semantic_mismatch",
                severity="MEDIUM",
                category="naming_drift",
                title=f"Role {name} is named read-only but holds write privileges",
                summary=(
                    f"Role '{name}' has a name suggesting read-only access "
                    "(VIEWER / READER / RO / READONLY) but actually holds write "
                    "privileges. Veza: 'RBAC is governance by shorthand. IAM and "
                    "GRC teams have to trust that the name of a role accurately "
                    "describes the permissions it grants.'"
                ),
                evidence={
                    "role": name,
                    "write_privileges_held": write_privs,
                },
                remediation=(
                    f"Either revoke write privileges from {name} (if name is "
                    "right) or rename the role (if write access is intentional). "
                    "Don't leave the mismatch."
                ),
            )
        )
    return findings


def rule_disabled_user_with_active_grants(duck: Any) -> list[Finding]:
    rows = duck.execute(
        """
        SELECT u.NAME, u.DEFAULT_ROLE,
               LIST(DISTINCT gu.ROLE) AS still_granted
        FROM users u
        JOIN grants_to_users gu ON gu.GRANTEE_NAME = u.NAME
        WHERE LOWER(u.DISABLED) = 'true'
          AND (gu.DELETED_ON IS NULL)
        GROUP BY u.NAME, u.DEFAULT_ROLE
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        name = str(row[0])
        roles = [str(r) for r in (row[2] or [])]
        findings.append(
            Finding(
                rule_id="disabled_user_with_active_grants",
                severity="MEDIUM",
                category="hygiene",
                title=f"Disabled user {name} still has role grants",
                summary=(
                    f"User '{name}' is DISABLED but still holds {len(roles)} "
                    "role grant(s). Disabling prevents login but leaves grants "
                    "in place. If the user is reactivated (or their credentials "
                    "leak via infostealer per the 2024 UNC5537 pattern), they "
                    "regain full access. Revoke role grants on disable."
                ),
                evidence={
                    "user": name,
                    "still_granted_roles": roles,
                },
                remediation=(
                    f"For each role X: REVOKE ROLE X FROM USER {name}; "
                    f"Or DROP USER {name}; if the user is permanently gone."
                ),
            )
        )
    return findings


def rule_direct_user_business_grant(duck: Any) -> list[Finding]:
    rows = duck.execute(
        """
        SELECT DISTINCT GRANTEE_NAME, PRIVILEGE, GRANTED_ON, NAME,
               TABLE_CATALOG, TABLE_SCHEMA
        FROM grants_to_roles
        WHERE GRANTED_TO = 'USER'
          AND GRANTED_ON IN ('TABLE', 'VIEW', 'SCHEMA', 'DATABASE',
                             'STAGE', 'STREAM', 'TASK', 'PIPE')
          AND DELETED_ON IS NULL
          AND NOT (NAME LIKE 'USER$%' OR COALESCE(TABLE_CATALOG, '') LIKE 'USER$%')
          AND NOT (
            COALESCE(TABLE_CATALOG, '') = 'SNOWFLAKE'
            OR NAME = 'SNOWFLAKE'
            OR NAME = 'SNOWFLAKE_SAMPLE_DATA'
          )
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        user = str(row[0])
        privilege = str(row[1])
        granted_on = str(row[2])
        obj_name = str(row[3])
        catalog = str(row[4]) if row[4] else None
        schema = str(row[5]) if row[5] else None
        qualified = _qualify(granted_on, obj_name, catalog, schema)
        findings.append(
            Finding(
                rule_id="direct_user_business_grant",
                severity="HIGH",
                category="bypass_role_layer",
                title=(
                    f"User {user} has direct {privilege} on {granted_on} {qualified}"
                ),
                summary=(
                    f"User '{user}' was granted {privilege} on {granted_on} "
                    f"'{qualified}' DIRECTLY (not through a role). This bypasses "
                    "the role layer and breaks the FR/AR pattern: revocation, "
                    "audit review, and offboarding cycles operate on roles, not "
                    "users. Direct user grants are nearly always a mistake."
                ),
                evidence={
                    "user": user,
                    "privilege": privilege,
                    "object_type": granted_on,
                    "object_name": qualified,
                },
                remediation=(
                    f"REVOKE {privilege} ON {granted_on} {qualified} FROM USER {user}; "
                    "Then grant the privilege to a role and grant the role to the user."
                ),
            )
        )
    return findings


def rule_exfil_prevention_parameters_off(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "account_parameters"):
        return []
    rows = duck.execute(
        """
        SELECT PARAMETER_NAME, VALUE, LEVEL, DESCRIPTION
        FROM account_parameters
        WHERE PARAMETER_NAME IN (
            'PREVENT_UNLOAD_TO_INLINE_URL',
            'REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION',
            'REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION'
        )
          AND LOWER(VALUE) IN ('false', 'f', 'no', 'n', '0', '')
        """
    ).fetchall()
    findings: list[Finding] = []
    cis_map = {
        "PREVENT_UNLOAD_TO_INLINE_URL": "CIS 4.8",
        "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION": "CIS 4.5",
        "REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION": "CIS 4.6",
    }
    for row in rows:
        name = str(row[0])
        value = str(row[1])
        cis_ref = cis_map.get(name, "CIS")
        findings.append(
            Finding(
                rule_id="exfil_prevention_parameter_off",
                severity="HIGH",
                category="data_exfiltration",
                title=f"Account parameter {name} = {value} (should be TRUE)",
                summary=(
                    f"Account parameter '{name}' is set to '{value}'. Per "
                    f"{cis_ref}, this parameter blocks the documented Snowflake "
                    "exfiltration path: `COPY INTO 's3://attacker/...' "
                    "CREDENTIALS=(...)`. With the parameter off, any role "
                    "holding a basic stage / unload privilege can stream data "
                    "to an attacker-controlled bucket. Mitiga and Datadog "
                    "threat-hunting guides flag inline-URL COPY as the primary "
                    "exfil signal."
                ),
                evidence={
                    "parameter": name,
                    "current_value": value,
                    "cis_control": cis_ref,
                },
                remediation=(
                    f"USE ROLE ACCOUNTADMIN; ALTER ACCOUNT SET {name} = TRUE; "
                    "Verify with: SHOW PARAMETERS LIKE '" + name + "' IN ACCOUNT;"
                ),
            )
        )
    return findings


def rule_execute_task_granted_broadly(duck: Any) -> list[Finding]:
    rows = duck.execute(
        """
        SELECT GRANTEE_NAME, COUNT(*) AS grant_count
        FROM grants_to_roles
        WHERE PRIVILEGE = 'EXECUTE TASK'
          AND GRANTED_ON = 'ACCOUNT'
          AND GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
          AND DELETED_ON IS NULL
          AND GRANTEE_NAME NOT IN ('ACCOUNTADMIN', 'SECURITYADMIN', 'SYSADMIN')
        GROUP BY GRANTEE_NAME
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        grantee = str(row[0])
        findings.append(
            Finding(
                rule_id="execute_task_granted_broadly",
                severity="MEDIUM",
                category="privilege_escalation",
                title=f"Role {grantee} holds EXECUTE TASK on account",
                summary=(
                    f"Role '{grantee}' has been granted EXECUTE TASK at the "
                    "account level. EXECUTE TASK lets the holder fire any task "
                    "in the account, and tasks run with their owner's "
                    "privileges. Combined with task_owned_by_admin findings, "
                    "this is a privilege-escalation pivot: a low-privilege role "
                    "with EXECUTE TASK can trigger an admin-owned task body."
                ),
                evidence={"grantee": grantee},
                remediation=(
                    f"REVOKE EXECUTE TASK ON ACCOUNT FROM ROLE {grantee}; "
                    "Then grant per-task or use a dedicated operations role."
                ),
            )
        )
    return findings


def rule_hour_of_day_outlier_login(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "login_history"):
        return []
    rows = duck.execute(
        """
        WITH baseline AS (
            SELECT USER_NAME,
                   AVG(EXTRACT(HOUR FROM EVENT_TIMESTAMP)) AS mean_hour,
                   STDDEV(EXTRACT(HOUR FROM EVENT_TIMESTAMP)) AS sd_hour,
                   COUNT(*) AS n
            FROM login_history
            WHERE EVENT_TIMESTAMP BETWEEN
                  CURRENT_TIMESTAMP - INTERVAL 60 DAY
              AND CURRENT_TIMESTAMP - INTERVAL 7 DAY
              AND IS_SUCCESS = 'YES'
            GROUP BY USER_NAME
            HAVING COUNT(*) >= 10
        ),
        recent AS (
            SELECT USER_NAME, EVENT_TIMESTAMP,
                   EXTRACT(HOUR FROM EVENT_TIMESTAMP) AS h,
                   FIRST_AUTHENTICATION_FACTOR AS auth,
                   REPORTED_CLIENT_TYPE AS client
            FROM login_history
            WHERE EVENT_TIMESTAMP > CURRENT_TIMESTAMP - INTERVAL 7 DAY
              AND IS_SUCCESS = 'YES'
        )
        SELECT r.USER_NAME, r.EVENT_TIMESTAMP, r.h,
               b.mean_hour, b.sd_hour, b.n,
               r.auth, r.client
        FROM recent r
        JOIN baseline b ON b.USER_NAME = r.USER_NAME
        WHERE b.sd_hour > 0
          AND ABS(r.h - b.mean_hour) > 2.5 * b.sd_hour
        ORDER BY r.USER_NAME, r.EVENT_TIMESTAMP DESC
        """
    ).fetchall()
    by_user: dict[str, list] = {}
    for row in rows:
        by_user.setdefault(str(row[0]), []).append(row)
    findings: list[Finding] = []
    for user, occurrences in by_user.items():
        sample = occurrences[0]
        mean_h = float(sample[3])
        sd_h = float(sample[4])
        baseline_n = int(sample[5])
        latest_hour = int(sample[2])
        latest_at = str(sample[1])
        findings.append(
            Finding(
                rule_id="hour_of_day_outlier_login",
                severity="MEDIUM",
                category="behavioral_anomaly",
                title=(
                    f"User {user}: {len(occurrences)} login(s) outside typical "
                    f"hour pattern (mean ~{mean_h:.1f}, sd {sd_h:.1f})"
                ),
                summary=(
                    f"User '{user}' logged in {len(occurrences)} times in the "
                    "last 7 days at an hour-of-day outside their normal pattern "
                    f"(baseline mean = {mean_h:.1f}h, sd = {sd_h:.1f}h, "
                    f"based on {baseline_n} logins in the prior 53 days). "
                    "This is the time-of-day signal that catches unusual logins "
                    "even when IP-based detection is useless behind VPN. "
                    f"Most recent: {latest_at} at hour {latest_hour}."
                ),
                evidence={
                    "user": user,
                    "outlier_login_count_7d": len(occurrences),
                    "baseline_mean_hour": round(mean_h, 1),
                    "baseline_stddev_hour": round(sd_h, 1),
                    "baseline_login_count": baseline_n,
                    "most_recent_outlier": latest_at,
                    "most_recent_hour": latest_hour,
                },
                remediation=(
                    f"Review LOGIN_HISTORY for {user} in the last 7 days. "
                    "If logins at unusual hours don't match a known schedule "
                    "change (travel, on-call), treat as compromised credential. "
                    f"ALTER USER {user} SET DISABLED = TRUE; rotate auth."
                ),
            )
        )
    return findings


def rule_auth_method_changed(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "login_history"):
        return []
    rows = duck.execute(
        """
        WITH user_factors AS (
            SELECT USER_NAME,
                   FIRST_AUTHENTICATION_FACTOR AS factor,
                   MIN(EVENT_TIMESTAMP) AS first_seen,
                   MAX(EVENT_TIMESTAMP) AS last_seen,
                   COUNT(*) AS n
            FROM login_history
            WHERE EVENT_TIMESTAMP > CURRENT_TIMESTAMP - INTERVAL 60 DAY
              AND IS_SUCCESS = 'YES'
              AND FIRST_AUTHENTICATION_FACTOR IS NOT NULL
            GROUP BY USER_NAME, FIRST_AUTHENTICATION_FACTOR
        ),
        user_summary AS (
            SELECT USER_NAME,
                   COUNT(DISTINCT factor) AS distinct_factors,
                   LIST(factor) AS factors,
                   MAX(last_seen) AS most_recent
            FROM user_factors
            GROUP BY USER_NAME
        )
        SELECT us.USER_NAME, us.factors, us.most_recent
        FROM user_summary us
        WHERE us.distinct_factors >= 2
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        user = str(row[0])
        factors = sorted({str(f) for f in (row[1] or [])})
        if "PASSWORD" in factors and any(
            f in factors for f in ("RSA_KEYPAIR", "OAUTH_ACCESS_TOKEN", "OAUTH_REFRESH_TOKEN")
        ):
            severity: Severity = "HIGH"
        else:
            severity = "MEDIUM"
        findings.append(
            Finding(
                rule_id="auth_method_changed",
                severity=severity,
                category="behavioral_anomaly",
                title=f"User {user} used {len(factors)} different auth factors in 60d",
                summary=(
                    f"User '{user}' has authenticated using multiple distinct "
                    f"factors in the past 60 days: {', '.join(factors)}. "
                    "Auth-method changes are a documented compromise signal: "
                    "the 2024 UNC5537 breach saw attackers fall back to "
                    "PASSWORD on accounts that had moved to keypair / OAuth. "
                    "Check whether the change matches a planned migration."
                ),
                evidence={
                    "user": user,
                    "factors_used": factors,
                    "most_recent": str(row[2]) if row[2] else None,
                },
                remediation=(
                    "Confirm the factor change is intentional. If unintentional: "
                    "drop the older factor (e.g. revoke password if keypair is "
                    "the official method) and rotate."
                ),
            )
        )
    return findings


def rule_first_time_admin_activation(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "query_history"):
        return []
    baseline = duck.execute(
        """
        SELECT DATEDIFF('day', MIN(START_TIME), CURRENT_TIMESTAMP)
        FROM query_history
        """
    ).fetchone()
    if not baseline or baseline[0] is None or baseline[0] < 60:
        return []
    rows = duck.execute(
        """
        WITH first_admin_use AS (
            SELECT USER_NAME, ROLE_NAME, MIN(START_TIME) AS first_at
            FROM query_history
            WHERE ROLE_NAME IN (
                'ACCOUNTADMIN', 'SECURITYADMIN', 'ORGADMIN', 'USERADMIN'
            )
              AND START_TIME > CURRENT_TIMESTAMP - INTERVAL 30 DAY
            GROUP BY USER_NAME, ROLE_NAME
        ),
        prior_use AS (
            SELECT DISTINCT USER_NAME, ROLE_NAME
            FROM query_history
            WHERE ROLE_NAME IN (
                'ACCOUNTADMIN', 'SECURITYADMIN', 'ORGADMIN', 'USERADMIN'
            )
              AND START_TIME BETWEEN CURRENT_TIMESTAMP - INTERVAL 365 DAY
                                 AND CURRENT_TIMESTAMP - INTERVAL 30 DAY
        )
        SELECT f.USER_NAME, f.ROLE_NAME, f.first_at
        FROM first_admin_use f
        LEFT JOIN prior_use p
          ON p.USER_NAME = f.USER_NAME AND p.ROLE_NAME = f.ROLE_NAME
        WHERE p.USER_NAME IS NULL
        ORDER BY f.first_at DESC
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        user = str(row[0])
        role = str(row[1])
        first_at = str(row[2]) if row[2] else None
        findings.append(
            Finding(
                rule_id="first_time_admin_activation",
                severity="HIGH",
                category="behavioral_anomaly",
                title=(
                    f"User {user} activated {role} for the first time in 30+ days"
                ),
                summary=(
                    f"User '{user}' activated role '{role}' on {first_at}. "
                    "There is no prior usage of this role by this user in the "
                    "past 365 days (looking back 30+ days from this snapshot). "
                    "First-time admin activation is a classic compromise signal "
                    "and a routine break-glass-not-recorded signal."
                ),
                evidence={
                    "user": user,
                    "role_activated": role,
                    "first_seen": first_at,
                },
                remediation=(
                    f"Review queries run by {user} as {role} since {first_at}. "
                    "Confirm with the user whether this was an intended "
                    "elevation. If unintentional, treat as compromised."
                ),
            )
        )
    return findings


def rule_stale_rsa_key(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "query_history"):
        return []
    if not _table_exists(duck, "users"):
        return []
    rows = duck.execute(
        """
        WITH key_rotations AS (
            SELECT
                REGEXP_EXTRACT(
                    UPPER(QUERY_TEXT),
                    'ALTER USER\\s+([A-Z0-9_]+)\\s+SET\\s+RSA_PUBLIC_KEY',
                    1
                ) AS user_name,
                MAX(START_TIME) AS last_rotation
            FROM query_history
            WHERE UPPER(QUERY_TEXT) LIKE '%RSA_PUBLIC_KEY%'
              AND QUERY_TYPE LIKE 'ALTER%'
            GROUP BY 1
        )
        SELECT u.NAME, u.TYPE, kr.last_rotation,
               DATEDIFF('day', kr.last_rotation, CURRENT_TIMESTAMP) AS days_since
        FROM users u
        LEFT JOIN key_rotations kr
          ON UPPER(kr.user_name) = UPPER(u.NAME)
        WHERE COALESCE(u.HAS_RSA_PUBLIC_KEY, FALSE) = TRUE
          AND u.DELETED_ON IS NULL
          AND COALESCE(LOWER(u.DISABLED), 'false') = 'false'
          AND (kr.last_rotation IS NULL
               OR DATEDIFF('day', kr.last_rotation, CURRENT_TIMESTAMP) > 180)
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        name = str(row[0])
        type_v = str(row[1]) if row[1] else "NULL"
        last_rot = str(row[2]) if row[2] else "never observed"
        days = int(row[3]) if row[3] is not None else 999
        findings.append(
            Finding(
                rule_id="stale_rsa_key",
                severity="HIGH",
                category="credential_hygiene",
                title=(
                    f"User {name} ({type_v}) RSA key not rotated in {days}+ days"
                ),
                summary=(
                    f"User '{name}' has HAS_RSA_PUBLIC_KEY = TRUE but the most "
                    f"recent ALTER USER ... SET RSA_PUBLIC_KEY in QUERY_HISTORY "
                    f"is {last_rot}. CIS Snowflake Foundations 1.7 requires RSA "
                    "key rotation every 180 days. Long-lived service keys are a "
                    "documented compromise vector — the 2024 UNC5537 attackers "
                    "used credentials harvested years before they were used."
                ),
                evidence={
                    "user": name,
                    "type": type_v,
                    "last_rotation_observed": last_rot,
                    "days_since_rotation": days,
                },
                remediation=(
                    f"Generate a new RSA keypair for {name}; "
                    f"ALTER USER {name} SET RSA_PUBLIC_KEY = '<new_key>'; "
                    "Then ALTER USER ... UNSET RSA_PUBLIC_KEY_2 if a 2nd slot "
                    "had the old key. Schedule rotation every 180 days."
                ),
            )
        )
    return findings


def rule_terminated_user_active_grants(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "hris"):
        return []
    rows = duck.execute(
        """
        SELECT u.NAME, u.LOGIN_NAME, h.status, h.term_date,
               COUNT(gu.ROLE) AS grant_count
        FROM users u
        JOIN hris_normalized h
          ON h.hris_key = UPPER(COALESCE(u.LOGIN_NAME, u.EMAIL, u.NAME))
        JOIN grants_to_users gu ON gu.GRANTEE_NAME = u.NAME
        WHERE LOWER(h.status) IN ('terminated', 'inactive', 'departed')
          AND COALESCE(LOWER(u.DISABLED), 'false') = 'false'
          AND u.DELETED_ON IS NULL
          AND gu.DELETED_ON IS NULL
        GROUP BY u.NAME, u.LOGIN_NAME, h.status, h.term_date
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        name = str(row[0])
        login = str(row[1]) if row[1] else None
        status = str(row[2])
        term_date = str(row[3]) if row[3] else "unknown"
        grant_count = int(row[4])
        findings.append(
            Finding(
                rule_id="terminated_user_active_grants",
                severity="CRITICAL",
                category="offboarding_failure",
                title=(
                    f"Terminated user {name} (HRIS status: {status}) "
                    f"still active with {grant_count} role grant(s)"
                ),
                summary=(
                    f"User '{name}' (login: {login}) is marked '{status}' in HRIS "
                    f"with term date {term_date}, but the Snowflake user is not "
                    f"disabled and still holds {grant_count} role grant(s). "
                    "SOC2 CC6.3 and SOX ITGC require termination access removal "
                    "within typically 24 hours. This is the prototypical "
                    "offboarding-SLA failure."
                ),
                evidence={
                    "user": name,
                    "login_name": login,
                    "hris_status": status,
                    "term_date": term_date,
                    "active_role_grants": grant_count,
                },
                remediation=(
                    f"ALTER USER {name} SET DISABLED = TRUE; "
                    "Then revoke all role grants; "
                    "DROP USER once HR sign-off completes."
                ),
            )
        )
    return findings


def rule_snowflake_user_not_in_hris(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "hris"):
        return []
    rows = duck.execute(
        """
        SELECT u.NAME, u.LOGIN_NAME, u.TYPE, COUNT(gu.ROLE) AS grant_count
        FROM users u
        LEFT JOIN hris_normalized h
          ON h.hris_key = UPPER(COALESCE(u.LOGIN_NAME, u.EMAIL, u.NAME))
        LEFT JOIN grants_to_users gu ON gu.GRANTEE_NAME = u.NAME
        WHERE h.hris_key IS NULL
          AND u.DELETED_ON IS NULL
          AND COALESCE(LOWER(u.DISABLED), 'false') = 'false'
          AND COALESCE(u.TYPE, 'PERSON') = 'PERSON'
          AND COALESCE(gu.DELETED_ON, NULL) IS NULL
        GROUP BY u.NAME, u.LOGIN_NAME, u.TYPE
        HAVING COUNT(gu.ROLE) > 0
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        name = str(row[0])
        login = str(row[1]) if row[1] else None
        grant_count = int(row[3])
        findings.append(
            Finding(
                rule_id="snowflake_user_not_in_hris",
                severity="HIGH",
                category="offboarding_failure",
                title=f"Active PERSON user {name} not in HRIS source-of-truth",
                summary=(
                    f"Snowflake user '{name}' (login: {login}) is active and "
                    f"holds {grant_count} role grants but does not appear in "
                    "the supplied HRIS export. Either the user predates the "
                    "HRIS sync (legacy) or they were removed from HR but never "
                    "deprovisioned in Snowflake. Either way, an audit will flag "
                    "this as missing reconciliation."
                ),
                evidence={
                    "user": name,
                    "login_name": login,
                    "active_role_grants": grant_count,
                },
                remediation=(
                    "Confirm with HR whether this person should still have "
                    "Snowflake access. If yes, ensure they're added to the HRIS "
                    f"sync. If no, ALTER USER {name} SET DISABLED = TRUE; "
                    "then revoke role grants."
                ),
            )
        )
    return findings


def rule_tagged_pii_without_masking(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "tag_references"):
        return []
    rows = duck.execute(
        """
        WITH tagged_sensitive AS (
            SELECT
                OBJECT_DATABASE, OBJECT_SCHEMA, OBJECT_NAME, COLUMN_NAME,
                TAG_NAME, TAG_VALUE, DOMAIN
            FROM tag_references
            WHERE DOMAIN IN ('COLUMN', 'TABLE')
              AND (
                UPPER(COALESCE(TAG_VALUE, '')) LIKE '%PII%'
                OR UPPER(COALESCE(TAG_VALUE, '')) LIKE '%PHI%'
                OR UPPER(COALESCE(TAG_VALUE, '')) LIKE '%SENSITIVE%'
                OR UPPER(COALESCE(TAG_VALUE, '')) LIKE '%CONFIDENTIAL%'
                OR UPPER(COALESCE(TAG_VALUE, '')) LIKE '%RESTRICTED%'
                OR UPPER(COALESCE(TAG_NAME, '')) LIKE '%PII%'
                OR UPPER(COALESCE(TAG_NAME, '')) LIKE '%PHI%'
                OR UPPER(COALESCE(TAG_NAME, '')) LIKE '%CLASSIFICATION%'
              )
        ),
        masked AS (
            SELECT
                UPPER(REF_DATABASE_NAME) AS db,
                UPPER(REF_SCHEMA_NAME) AS schema,
                UPPER(REF_ENTITY_NAME) AS entity,
                UPPER(COALESCE(REF_COLUMN_NAME, '')) AS col
            FROM policy_references
            WHERE POLICY_KIND = 'MASKING_POLICY'
              AND COALESCE(POLICY_STATUS, 'ACTIVE') = 'ACTIVE'
        )
        SELECT t.OBJECT_DATABASE, t.OBJECT_SCHEMA, t.OBJECT_NAME,
               t.COLUMN_NAME, t.TAG_NAME, t.TAG_VALUE, t.DOMAIN
        FROM tagged_sensitive t
        LEFT JOIN masked m
          ON m.db = UPPER(t.OBJECT_DATABASE)
         AND m.schema = UPPER(t.OBJECT_SCHEMA)
         AND m.entity = UPPER(t.OBJECT_NAME)
         AND (
           m.col = UPPER(COALESCE(t.COLUMN_NAME, ''))
           OR (m.col = '' AND t.DOMAIN = 'TABLE')
         )
        WHERE m.db IS NULL
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        db = str(row[0]) if row[0] else None
        schema = str(row[1]) if row[1] else None
        obj = str(row[2]) if row[2] else None
        col = str(row[3]) if row[3] else None
        tag_name = str(row[4]) if row[4] else None
        tag_value = str(row[5]) if row[5] else None
        domain = str(row[6]) if row[6] else None
        qualified = ".".join(p for p in (db, schema, obj, col) if p)
        findings.append(
            Finding(
                rule_id="tagged_sensitive_no_masking_policy",
                severity="HIGH",
                category="data_protection_gap",
                title=(
                    f"Sensitive {domain.lower() if domain else 'object'} "
                    f"{qualified} tagged but no masking policy"
                ),
                summary=(
                    f"{domain.title() if domain else 'Object'} '{qualified}' is "
                    f"tagged with {tag_name} = {tag_value} (sensitive class) "
                    "but has no active masking policy attached. The data "
                    "classification exists; the protective control does not. "
                    "Anyone with SELECT on this column gets the raw value. "
                    "Auditors flag this gap as a HIPAA / GDPR / SOC2 PII-control failure."
                ),
                evidence={
                    "object": qualified,
                    "tag_name": tag_name,
                    "tag_value": tag_value,
                    "domain": domain,
                },
                remediation=(
                    f"CREATE MASKING POLICY <name> AS (val STRING) RETURNS STRING -> "
                    "CASE WHEN CURRENT_ROLE() IN ('PRIVILEGED_ROLE') THEN val ELSE '***' END; "
                    f"ALTER TABLE {db}.{schema}.{obj} MODIFY COLUMN {col} "
                    "SET MASKING POLICY <name>;"
                ),
            )
        )
    return findings


def rule_user_never_logged_in_with_grants(duck: Any) -> list[Finding]:
    rows = duck.execute(
        """
        SELECT u.NAME, u.TYPE, u.CREATED_ON, COUNT(gu.ROLE) AS grant_count
        FROM users u
        JOIN grants_to_users gu ON gu.GRANTEE_NAME = u.NAME
        WHERE u.LAST_SUCCESS_LOGIN IS NULL
          AND u.DELETED_ON IS NULL
          AND COALESCE(LOWER(u.DISABLED), 'false') = 'false'
          AND u.CREATED_ON < CURRENT_TIMESTAMP - INTERVAL 30 DAY
          AND gu.DELETED_ON IS NULL
        GROUP BY u.NAME, u.TYPE, u.CREATED_ON
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        name = str(row[0])
        type_v = str(row[1]) if row[1] else None
        created = str(row[2]) if row[2] else None
        grant_count = int(row[3])
        findings.append(
            Finding(
                rule_id="user_never_logged_in",
                severity="MEDIUM",
                category="hygiene",
                title=f"User {name} created 30+ days ago, never logged in, holds {grant_count} role(s)",
                summary=(
                    f"User '{name}' (type: {type_v or 'NULL'}) was created on "
                    f"{created} but has never successfully logged in. They "
                    f"currently hold {grant_count} role grant(s). Provisioned "
                    "but unused -- candidate for revocation. If the user is "
                    "going to be activated soon, the grants are fine; if "
                    "not, this is provisioning leakage."
                ),
                evidence={
                    "user": name,
                    "type": type_v,
                    "created_on": created,
                    "role_grant_count": grant_count,
                },
                remediation=(
                    f"If the user will not be activated: ALTER USER {name} SET "
                    "DISABLED = TRUE; or DROP USER if permanently abandoned. "
                    f"Otherwise leave alone but monitor."
                ),
            )
        )
    return findings


def rule_active_secondary_role_usage(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "query_history"):
        return []
    rows = duck.execute(
        """
        SELECT
            USER_NAME,
            COUNT(*) AS session_count,
            MAX(START_TIME) AS last_seen,
            COUNT(DISTINCT ROLE_NAME) AS distinct_roles_used
        FROM query_history
        WHERE QUERY_TYPE = 'USE'
          AND UPPER(QUERY_TEXT) LIKE '%USE SECONDARY ROLES%'
          AND START_TIME > CURRENT_TIMESTAMP - INTERVAL 30 DAY
        GROUP BY USER_NAME
        ORDER BY session_count DESC
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        user = str(row[0])
        session_count = int(row[1])
        last_seen = str(row[2]) if row[2] else None
        distinct_roles = int(row[3])
        findings.append(
            Finding(
                rule_id="active_secondary_role_usage",
                severity="MEDIUM",
                category="secondary_role_risk",
                title=(
                    f"User {user} actively uses USE SECONDARY ROLES "
                    f"({session_count} times in 30d)"
                ),
                summary=(
                    f"User '{user}' issued USE SECONDARY ROLES commands "
                    f"{session_count} times in the last 30 days, across "
                    f"{distinct_roles} distinct primary roles. This is the "
                    "behavior pattern that activates the privilege-union risk "
                    "in `secondary_role_expansion` -- this user is actively "
                    "exploiting the cross-role join potential, not just "
                    "theoretically holding the grants."
                ),
                evidence={
                    "user": user,
                    "session_count": session_count,
                    "distinct_primary_roles": distinct_roles,
                    "last_seen": last_seen,
                },
                remediation=(
                    f"Review user '{user}' against secondary_role_expansion "
                    "findings. If the cross-role queries are legitimate, "
                    "consolidate into a single dedicated functional role "
                    "documenting the combined responsibility. If not, revoke "
                    "the role grants creating the dangerous union."
                ),
            )
        )
    return findings


def rule_default_role_not_granted(duck: Any) -> list[Finding]:
    rows = duck.execute(
        """
        SELECT u.NAME, u.DEFAULT_ROLE
        FROM users u
        LEFT JOIN grants_to_users gu
          ON gu.GRANTEE_NAME = u.NAME
         AND gu.ROLE = u.DEFAULT_ROLE
         AND gu.DELETED_ON IS NULL
        WHERE u.DEFAULT_ROLE IS NOT NULL
          AND TRIM(u.DEFAULT_ROLE) <> ''
          AND gu.ROLE IS NULL
          AND u.DELETED_ON IS NULL
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        name = str(row[0])
        default_role = str(row[1])
        findings.append(
            Finding(
                rule_id="default_role_not_granted",
                severity="MEDIUM",
                category="hygiene",
                title=(
                    f"User {name} has DEFAULT_ROLE = {default_role} but isn't granted it"
                ),
                summary=(
                    f"User '{name}' has DEFAULT_ROLE = '{default_role}' but the "
                    "role is not granted to them. Their sessions will fall back "
                    "to PUBLIC. This is a config-drift signal: either the user "
                    "lost the role grant via cleanup, or DEFAULT_ROLE was set "
                    "wrong at provisioning. CIS recommends DEFAULT_ROLE always "
                    "match a granted role."
                ),
                evidence={
                    "user": name,
                    "default_role": default_role,
                },
                remediation=(
                    f"Either GRANT ROLE {default_role} TO USER {name}; (if the "
                    "user should have it) OR ALTER USER " + name +
                    " SET DEFAULT_ROLE = <a_role_they_actually_hold>; "
                ),
            )
        )
    return findings


def rule_secondary_role_expansion(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "role_closure"):
        return []
    rows = duck.execute(
        """
        WITH user_grants AS (
            SELECT GRANTEE_NAME AS user_name, ROLE
            FROM grants_to_users
            WHERE DELETED_ON IS NULL
        ),
        objs_per_role AS (
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
        per_user AS (
            SELECT
                user_name,
                COUNT(DISTINCT source_role) AS role_count,
                COUNT(DISTINCT (object_key || '|' || PRIVILEGE)) AS union_count,
                MAX(per_role_count) AS max_single_role_count
            FROM (
                SELECT user_name, source_role, object_key, PRIVILEGE,
                       COUNT(DISTINCT (object_key || '|' || PRIVILEGE))
                         OVER (PARTITION BY user_name, source_role) AS per_role_count
                FROM objs_per_role
            )
            GROUP BY user_name
        )
        SELECT user_name, role_count, union_count, max_single_role_count,
               (union_count - max_single_role_count) AS delta
        FROM per_user
        WHERE role_count >= 2
          AND union_count > max_single_role_count
          AND (union_count - max_single_role_count) >= 5
        ORDER BY delta DESC
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        user = str(row[0])
        role_count = int(row[1])
        union_count = int(row[2])
        max_single = int(row[3])
        delta = int(row[4])
        ratio = (union_count / max_single) if max_single else 0.0
        severity: Severity = "HIGH" if ratio >= 1.5 else "MEDIUM"
        findings.append(
            Finding(
                rule_id="secondary_role_expansion",
                severity=severity,
                category="secondary_role_risk",
                title=(
                    f"User {user}: {role_count} roles combine into "
                    f"{union_count} privilege-grants ({delta} more than any single role)"
                ),
                summary=(
                    f"User '{user}' holds {role_count} roles. With "
                    "USE SECONDARY ROLES ALL active, the union of their privileges "
                    f"covers {union_count} distinct (object, privilege) pairs -- "
                    f"{delta} more than the user's largest single role provides "
                    f"({max_single}). Secondary-role activation creates effective "
                    "privileges that no single role grants on its own. This is "
                    "the audit-failure pattern for SoD: a user can join data "
                    "across roles that were intentionally separated."
                ),
                evidence={
                    "user": user,
                    "role_count": role_count,
                    "union_priv_count": union_count,
                    "largest_single_role_priv_count": max_single,
                    "expansion_delta": delta,
                    "expansion_ratio": round(ratio, 2),
                },
                remediation=(
                    f"Audit user '{user}'s role grants. If they need this combined "
                    "access regularly, consolidate into a single dedicated role "
                    "that documents the combined responsibility. If not, revoke "
                    "the grant that creates the dangerous union. Consider account-"
                    "wide policy: 'USE SECONDARY ROLES ALL' default-off."
                ),
            )
        )
    return findings


def rule_owners_rights_proc_privileged(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "procedures"):
        return []
    rows = duck.execute(
        """
        SELECT PROCEDURE_NAME, PROCEDURE_OWNER, PROCEDURE_CATALOG, PROCEDURE_SCHEMA
        FROM procedures
        WHERE PROCEDURE_OWNER IN (
            'ACCOUNTADMIN', 'SECURITYADMIN', 'ORGADMIN'
          )
          AND DELETED IS NULL
          AND COALESCE(PROCEDURE_CATALOG, '') NOT IN ('SNOWFLAKE')
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        name = str(row[0])
        owner = str(row[1])
        catalog = str(row[2]) if row[2] else None
        schema = str(row[3]) if row[3] else None
        qualified = ".".join(p for p in (catalog, schema, name) if p)
        findings.append(
            Finding(
                rule_id="owners_rights_proc_privileged",
                severity="HIGH",
                category="privilege_escalation",
                title=(
                    f"Owner's-rights procedure {qualified} owned by {owner}"
                ),
                summary=(
                    f"Procedure '{qualified}' is owned by '{owner}'. By default "
                    "Snowflake procedures run with EXECUTE AS OWNER (the default "
                    "since procedure intro). Per CIS Snowflake Foundations 1.16/"
                    "1.17, owner's-rights procedures owned by privileged roles "
                    "are a textbook privilege-escalation pivot: any caller with "
                    f"USAGE inherits {owner}'s privileges for the call."
                ),
                evidence={
                    "procedure": qualified,
                    "owner": owner,
                    "execute_as": "OWNER",
                },
                remediation=(
                    f"ALTER PROCEDURE {qualified} EXECUTE AS CALLER; "
                    "Or transfer ownership to a less-privileged role rooted "
                    "under SYSADMIN."
                ),
            )
        )
    return findings


def rule_task_owned_by_admin(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "tasks"):
        return []
    rows = duck.execute(
        """
        SELECT TASK_NAME, TASK_OWNER, TASK_DATABASE, TASK_SCHEMA, STATE
        FROM tasks
        WHERE TASK_OWNER IN (
            'ACCOUNTADMIN', 'SECURITYADMIN', 'ORGADMIN'
        )
          AND DELETED IS NULL
          AND COALESCE(TASK_DATABASE, '') NOT IN ('SNOWFLAKE')
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        name = str(row[0])
        owner = str(row[1])
        db = str(row[2]) if row[2] else None
        schema = str(row[3]) if row[3] else None
        state = str(row[4]) if row[4] else "?"
        qualified = ".".join(p for p in (db, schema, name) if p)
        findings.append(
            Finding(
                rule_id="task_owned_by_admin",
                severity="HIGH",
                category="privilege_escalation",
                title=f"Task {qualified} owned by {owner} (state: {state})",
                summary=(
                    f"Task '{qualified}' is owned by '{owner}' and runs with "
                    "owner privileges. Per CIS Snowflake Foundations 1.14/1.15, "
                    "tasks should not run as ACCOUNTADMIN/SECURITYADMIN/ORGADMIN. "
                    "Anyone with EXECUTE TASK can trigger this and get the "
                    "owner's privileges through whatever the task body does."
                ),
                evidence={
                    "task": qualified,
                    "owner": owner,
                    "state": state,
                },
                remediation=(
                    "Transfer ownership: GRANT OWNERSHIP ON TASK "
                    f"{qualified} TO ROLE <less_privileged> COPY CURRENT GRANTS;"
                ),
            )
        )
    return findings


def rule_external_stage_no_storage_integration(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "stages"):
        return []
    rows = duck.execute(
        """
        SELECT STAGE_NAME, STAGE_OWNER, STAGE_CATALOG, STAGE_SCHEMA, STAGE_URL
        FROM stages
        WHERE STAGE_TYPE = 'External Named'
          AND (STORAGE_INTEGRATION IS NULL OR TRIM(STORAGE_INTEGRATION) = '')
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        name = str(row[0])
        owner = str(row[1])
        catalog = str(row[2]) if row[2] else None
        schema = str(row[3]) if row[3] else None
        url = str(row[4]) if row[4] else None
        qualified = ".".join(p for p in (catalog, schema, name) if p)
        findings.append(
            Finding(
                rule_id="external_stage_no_storage_integration",
                severity="HIGH",
                category="credential_leak",
                title=f"External stage {qualified} has no storage integration",
                summary=(
                    f"External stage '{qualified}' is configured without a "
                    "STORAGE_INTEGRATION. Per CIS 4.7, this means it likely "
                    "embeds long-lived cloud credentials directly in the stage "
                    "definition, visible to anyone with USAGE on the stage. "
                    "Storage integrations replace embedded credentials with "
                    "role-trust (AWS IAM role, Azure managed identity, GCP SA)."
                ),
                evidence={
                    "stage": qualified,
                    "owner": owner,
                    "url": url,
                },
                remediation=(
                    "Create a STORAGE_INTEGRATION for the cloud, then ALTER "
                    f"STAGE {qualified} SET STORAGE_INTEGRATION = "
                    "<your_integration>; Drop the embedded CREDENTIALS clause."
                ),
            )
        )
    return findings


def rule_stale_credential(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "credentials"):
        return []
    rows = duck.execute(
        """
        SELECT NAME, USER_NAME, TYPE, STATUS, CREATED_ON, LAST_USED_ON,
               EXPIRATION_DATE
        FROM credentials
        WHERE STATUS = 'ACTIVE'
          AND (
            (LAST_USED_ON IS NULL
              AND CREATED_ON < CURRENT_TIMESTAMP - INTERVAL 30 DAY)
            OR (LAST_USED_ON IS NOT NULL
                AND LAST_USED_ON < CURRENT_TIMESTAMP - INTERVAL 90 DAY)
          )
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        name = str(row[0])
        user = str(row[1])
        cred_type = str(row[2])
        last_used = str(row[5]) if row[5] else None
        created = str(row[4]) if row[4] else None
        findings.append(
            Finding(
                rule_id="stale_credential",
                severity="MEDIUM",
                category="credential_hygiene",
                title=(
                    f"Stale {cred_type} credential '{name}' on user {user}"
                ),
                summary=(
                    f"Credential '{name}' (type {cred_type}) on user '{user}' "
                    "is ACTIVE but has not been used recently. "
                    + (
                        f"Last used: {last_used}."
                        if last_used
                        else f"Never used since creation on {created}."
                    )
                    + " Stale credentials are a common compromise vector — "
                    "the 2024 UNC5537 breach exploited credentials that were "
                    "harvested years before they were used."
                ),
                evidence={
                    "credential": name,
                    "user": user,
                    "type": cred_type,
                    "created_on": created,
                    "last_used_on": last_used,
                    "expiration_date": str(row[6]) if row[6] else None,
                },
                remediation=(
                    f"If unused: ALTER USER {user} REMOVE PROGRAMMATIC ACCESS "
                    f"TOKEN {name}; (or the equivalent for keypair / passkey). "
                    "If still needed, document the use case and rotate."
                ),
            )
        )
    return findings


def rule_inbound_share_to_non_system_role(duck: Any) -> list[Finding]:
    rows = duck.execute(
        """
        SELECT GRANTEE_NAME, GRANTED_ON, NAME, GRANTED_BY
        FROM grants_to_roles
        WHERE PRIVILEGE = 'IMPORTED PRIVILEGES'
          AND GRANTED_TO IN ('ROLE', 'DATABASE_ROLE')
          AND GRANTEE_NAME NOT IN ('SYSADMIN', 'ACCOUNTADMIN', 'SECURITYADMIN')
          AND DELETED_ON IS NULL
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        grantee = str(row[0])
        granted_on = str(row[1])
        name = str(row[2])
        findings.append(
            Finding(
                rule_id="inbound_share_to_non_system_role",
                severity="MEDIUM",
                category="data_sharing",
                title=f"Role {grantee} has IMPORTED PRIVILEGES on {granted_on} {name}",
                summary=(
                    f"Role '{grantee}' holds IMPORTED PRIVILEGES on {granted_on} "
                    f"'{name}'. Inbound shares cannot be sub-granted at object "
                    "level in standard schemas, so any role holding this gets "
                    "read access to the entire shared dataset. Best practice: "
                    "hold IMPORTED PRIVILEGES on a single curator role "
                    "(SYSADMIN or a dedicated SHARE_CONSUMER role)."
                ),
                evidence={
                    "grantee": grantee,
                    "object_type": granted_on,
                    "object_name": name,
                    "granted_by": str(row[3]) if row[3] else None,
                },
                remediation=(
                    f"REVOKE IMPORTED PRIVILEGES ON {granted_on} {name} FROM ROLE "
                    f"{grantee}; Grant to a dedicated curator role and have "
                    f"{grantee} inherit from there."
                ),
            )
        )
    return findings


def rule_anomalous_client_type(duck: Any) -> list[Finding]:
    if not _table_exists(duck, "login_history"):
        return []
    KNOWN_GOOD = (
        "PYTHON_DRIVER", "JDBC_DRIVER", "JDBC", "ODBC_DRIVER", "ODBC",
        "GO", "NODE_JS", "RUBY", ".NET", "PHP", "SNOWFLAKE_UI",
        "SNOWFLAKE_KAFKA_CONNECTOR", "SNOWFLAKE_CLI",
        "RUBY_DRIVER", "OAUTH_BROWSER", "PROGRAMMATIC_INTERFACE",
    )
    KNOWN_BAD_PATTERNS = ("rapeflake", "frostbite")
    placeholders = ", ".join(f"'{c}'" for c in KNOWN_GOOD)
    bad_or = " OR ".join(
        f"LOWER(REPORTED_CLIENT_TYPE) LIKE '%{p}%'" for p in KNOWN_BAD_PATTERNS
    )
    rows = duck.execute(
        f"""
        SELECT USER_NAME, REPORTED_CLIENT_TYPE, COUNT(*) AS n,
               MAX(EVENT_TIMESTAMP) AS last_seen
        FROM login_history
        WHERE EVENT_TIMESTAMP > CURRENT_TIMESTAMP - INTERVAL 30 DAY
          AND IS_SUCCESS = 'YES'
          AND REPORTED_CLIENT_TYPE IS NOT NULL
          AND (
            REPORTED_CLIENT_TYPE NOT IN ({placeholders})
            OR ({bad_or})
          )
        GROUP BY USER_NAME, REPORTED_CLIENT_TYPE
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        user = str(row[0])
        client = str(row[1])
        n = int(row[2])
        is_known_bad = any(p in client.lower() for p in KNOWN_BAD_PATTERNS)
        findings.append(
            Finding(
                rule_id="anomalous_client_type",
                severity="HIGH" if is_known_bad else "LOW",
                category="threat_signal",
                title=(
                    f"Suspicious client {client} for user {user}"
                    if is_known_bad
                    else f"Unfamiliar client {client} for user {user}"
                ),
                summary=(
                    f"User '{user}' logged in {n} times in the last 30 days "
                    f"using REPORTED_CLIENT_TYPE = '{client}'. "
                    + (
                        "This client string matches a known threat actor tool "
                        "from the 2024 UNC5537 / Snowflake breach campaign."
                        if is_known_bad
                        else "This client type is outside the standard set "
                        "(PYTHON_DRIVER, JDBC, ODBC, SNOWFLAKE_UI, etc.). "
                        "Review whether it's a legitimate new integration."
                    )
                ),
                evidence={
                    "user": user,
                    "client_type": client,
                    "login_count_30d": n,
                    "last_seen": str(row[3]) if row[3] else None,
                },
                remediation=(
                    f"If unrecognized: ALTER USER {user} SET DISABLED = TRUE; "
                    "rotate credentials, investigate client app inventory, "
                    "and check QUERY_HISTORY for what this session ran."
                ),
            )
        )
    return findings


def rule_public_db_schema_usage(duck: Any) -> list[Finding]:
    rows = duck.execute(
        """
        SELECT GRANTED_ON, NAME, TABLE_CATALOG
        FROM grants_to_roles
        WHERE GRANTEE_NAME = 'PUBLIC'
          AND PRIVILEGE IN ('USAGE', 'REFERENCE_USAGE')
          AND GRANTED_ON IN ('DATABASE', 'SCHEMA')
          AND DELETED_ON IS NULL
          AND COALESCE(TABLE_CATALOG, NAME) NOT IN ('SNOWFLAKE', 'SNOWFLAKE_SAMPLE_DATA')
          AND NOT (NAME LIKE 'USER$%' OR COALESCE(TABLE_CATALOG, '') LIKE 'USER$%')
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        granted_on = str(row[0])
        name = str(row[1])
        catalog = str(row[2]) if row[2] else None
        qualified = _qualify(granted_on, name, catalog, None)
        findings.append(
            Finding(
                rule_id="public_db_schema_usage",
                severity="MEDIUM",
                category="access_leak",
                title=f"PUBLIC has USAGE on {granted_on} {qualified}",
                summary=(
                    f"PUBLIC has USAGE on {granted_on} '{qualified}'. PUBLIC is "
                    "auto-granted to every user, so every user can navigate "
                    "into this database/schema. If future grants of SELECT "
                    "exist on this scope, every new table inherits PUBLIC "
                    "read access forever. Distinct from the generic "
                    "public_role_non_trivial_grant rule because USAGE on "
                    "DB/schema is the specific high-impact pattern."
                ),
                evidence={
                    "object_type": granted_on,
                    "object_name": qualified,
                },
                remediation=(
                    f"REVOKE USAGE ON {granted_on} {qualified} FROM ROLE PUBLIC; "
                    "Grant USAGE to specific functional roles instead."
                ),
            )
        )
    return findings


def rule_accountadmin_holder_no_email(duck: Any) -> list[Finding]:
    rows = duck.execute(
        """
        SELECT u.NAME, u.LAST_SUCCESS_LOGIN
        FROM users u
        JOIN grants_to_users gu ON gu.GRANTEE_NAME = u.NAME
        WHERE gu.ROLE = 'ACCOUNTADMIN'
          AND gu.DELETED_ON IS NULL
          AND (u.EMAIL IS NULL OR u.EMAIL = '')
          AND u.DELETED_ON IS NULL
        """
    ).fetchall()
    findings: list[Finding] = []
    for row in rows:
        name = str(row[0])
        findings.append(
            Finding(
                rule_id="accountadmin_no_email",
                severity="MEDIUM",
                category="break_glass",
                title=f"ACCOUNTADMIN holder {name} has no email",
                summary=(
                    f"User '{name}' holds ACCOUNTADMIN but has no email address "
                    "configured. CIS Snowflake Foundations 1.11 requires this: "
                    "without an email, Snowflake cannot deliver password-reset "
                    "or breach notifications. Common when ACCOUNTADMIN was a "
                    "programmatic bootstrap account that was never reviewed."
                ),
                evidence={
                    "user": name,
                    "last_login": str(row[1]) if row[1] else None,
                },
                remediation=(
                    f"ALTER USER {name} SET EMAIL = '<contact@example.com>'; "
                    "Or revoke ACCOUNTADMIN if this user shouldn't have it."
                ),
            )
        )
    return findings


_RULES: tuple[RuleFn, ...] = (
    rule_accountadmin_default_role,
    rule_accountadmin_owned_objects,
    rule_accountadmin_concentration,
    rule_user_no_mfa,
    rule_legacy_service_or_password_service,
    rule_unused_customer_role,
    rule_public_role_non_trivial_grant,
    rule_grant_option_proliferation,
    rule_service_account_overprivileged,
    rule_manage_grants_holder,
    rule_role_nested_under_admin,
    rule_role_name_semantic_mismatch,
    rule_disabled_user_with_active_grants,
    rule_direct_user_business_grant,
    rule_accountadmin_holder_no_email,
    rule_inbound_share_to_non_system_role,
    rule_anomalous_client_type,
    rule_public_db_schema_usage,
    rule_owners_rights_proc_privileged,
    rule_task_owned_by_admin,
    rule_external_stage_no_storage_integration,
    rule_stale_credential,
    rule_secondary_role_expansion,
    rule_default_role_not_granted,
    rule_active_secondary_role_usage,
    rule_exfil_prevention_parameters_off,
    rule_execute_task_granted_broadly,
    rule_user_never_logged_in_with_grants,
    rule_tagged_pii_without_masking,
    rule_terminated_user_active_grants,
    rule_snowflake_user_not_in_hris,
    rule_hour_of_day_outlier_login,
    rule_auth_method_changed,
    rule_first_time_admin_activation,
    rule_stale_rsa_key,
)


def all_rules() -> tuple[RuleFn, ...]:
    return _RULES


def run_rules(
    duck: Any,
    rules: tuple[RuleFn, ...] | None = None,
    audit_pack: str | None = None,
) -> list[Finding]:
    rules = rules or _RULES
    if audit_pack:
        wanted = rules_in_pack(audit_pack)
        rules = tuple(
            fn for fn in rules
            if fn.__name__.removeprefix("rule_") in wanted
        )
    out: list[Finding] = []
    for fn in rules:
        try:
            for finding in fn(duck):
                finding.audit_packs = [
                    {"pack": pack_id, "control": control}
                    for pack_id, control in packs_for_rule(finding.rule_id)
                ]
                out.append(finding)
        except Exception as e:
            out.append(
                Finding(
                    rule_id=fn.__name__,
                    severity="INFO",
                    category="meta",
                    title=f"Rule {fn.__name__} failed to evaluate",
                    summary=f"Internal error while evaluating rule: {type(e).__name__}: {e}",
                )
            )
    out.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity, 5), f.rule_id))
    return out


def to_json_serializable(findings: list[Finding]) -> list[dict[str, Any]]:
    return [asdict(f) for f in findings]
