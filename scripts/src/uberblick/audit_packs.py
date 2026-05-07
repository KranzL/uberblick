from __future__ import annotations


_PACK_MAPPINGS: dict[str, dict[str, str]] = {
    "cis": {
        "accountadmin_no_email": "CIS 1.11",
        "task_owned_by_admin": "CIS 1.14 / 1.15",
        "owners_rights_proc_privileged": "CIS 1.16 / 1.17",
        "manage_grants_holder": "CIS 2.2",
        "external_stage_no_storage_integration": "CIS 4.7",
        "exfil_prevention_parameter_off": "CIS 4.5 / 4.6 / 4.8",
        "execute_task_granted_broadly": "CIS 1.14",
        "user_never_logged_in": "CIS 1.10",
        "tagged_sensitive_no_masking_policy": "CIS 3.x (data classification)",
        "stale_credential": "CIS 1.7 (partial)",
        "stale_rsa_key": "CIS 1.7",
        "user_no_mfa": "CIS 1.4",
        "legacy_or_password_service_user": "CIS 1.5",
        "public_role_non_trivial_grant": "CIS 1.6",
        "public_db_schema_usage": "CIS 1.6",
        "accountadmin_concentration": "CIS 1.10",
        "accountadmin_default_role": "CIS 1.12",
        "role_nested_under_admin": "CIS 1.13",
    },
    "soc2": {
        "user_no_mfa": "CC6.1",
        "legacy_or_password_service_user": "CC6.1 / CC6.6",
        "accountadmin_concentration": "CC6.1",
        "manage_grants_holder": "CC6.1",
        "role_nested_under_admin": "CC6.1",
        "accountadmin_default_role": "CC6.1",
        "default_role_not_granted": "CC6.2",
        "disabled_user_with_active_grants": "CC6.3",
        "unused_customer_role": "CC6.3",
        "stale_credential": "CC6.1",
        "anomalous_client_type": "CC6.7",
        "secondary_role_expansion": "CC6.1 / SoD",
        "active_secondary_role_usage": "CC6.1 / SoD",
        "exfil_prevention_parameter_off": "CC6.6",
        "user_never_logged_in": "CC6.3",
        "terminated_user_active_grants": "CC6.3 (joiner-mover-leaver)",
        "snowflake_user_not_in_hris": "CC6.2 / CC6.3",
        "tagged_sensitive_no_masking_policy": "CC6.7",
        "hour_of_day_outlier_login": "CC6.7 / CC7.2",
        "auth_method_changed": "CC6.6 / CC7.2",
        "first_time_admin_activation": "CC6.1 / CC7.2",
        "stale_rsa_key": "CC6.6",
    },
    "sox": {
        "accountadmin_concentration": "ITGC-Access",
        "accountadmin_default_role": "ITGC-Access",
        "role_nested_under_admin": "ITGC-Access",
        "manage_grants_holder": "ITGC-Access",
        "disabled_user_with_active_grants": "ITGC-Access",
        "default_role_not_granted": "ITGC-Access",
        "secondary_role_expansion": "ITGC-SoD",
        "active_secondary_role_usage": "ITGC-SoD",
        "role_name_semantic_mismatch": "ITGC-SoD",
        "task_owned_by_admin": "ITGC-ChangeMgmt",
        "owners_rights_proc_privileged": "ITGC-ChangeMgmt",
        "stale_credential": "ITGC-Operations",
        "external_stage_no_storage_integration": "ITGC-Operations",
        "direct_user_business_grant": "ITGC-Access",
        "terminated_user_active_grants": "ITGC-Access (offboarding SLA)",
        "snowflake_user_not_in_hris": "ITGC-Access (provisioning reconciliation)",
        "exfil_prevention_parameter_off": "ITGC-Operations",
        "tagged_sensitive_no_masking_policy": "ITGC-DataProtection",
        "execute_task_granted_broadly": "ITGC-ChangeMgmt",
        "user_never_logged_in": "ITGC-Access",
    },
    "hipaa": {
        "accountadmin_concentration": "164.312(a)(1)",
        "public_role_non_trivial_grant": "164.312(a)(1)",
        "public_db_schema_usage": "164.312(a)(1)",
        "direct_user_business_grant": "164.312(a)(2)(i)",
        "default_role_not_granted": "164.312(a)(2)(i)",
        "disabled_user_with_active_grants": "164.312(a)(2)(ii)",
        "anomalous_client_type": "164.312(b)",
        "active_secondary_role_usage": "164.312(b)",
        "owners_rights_proc_privileged": "164.312(c)(1)",
        "manage_grants_holder": "164.312(c)(1)",
        "user_no_mfa": "164.312(d)",
        "legacy_or_password_service_user": "164.312(d)",
        "stale_credential": "164.312(d)",
        "tagged_sensitive_no_masking_policy": "164.312(c)(1)",
        "exfil_prevention_parameter_off": "164.312(c)(1)",
        "terminated_user_active_grants": "164.312(a)(2)(ii)",
        "snowflake_user_not_in_hris": "164.312(a)(2)(i)",
        "user_never_logged_in": "164.312(a)(2)(ii)",
    },
    "unc5537": {
        "user_no_mfa": "primary attack vector",
        "legacy_or_password_service_user": "compromised credential class",
        "anomalous_client_type": "rapeflake / frostbite tooling",
        "stale_credential": "infostealer-harvested reuse",
        "inbound_share_to_non_system_role": "share-misuse exfil path",
        "external_stage_no_storage_integration": "embedded-cred exfil path",
        "exfil_prevention_parameter_off": "documented exfiltration path",
        "hour_of_day_outlier_login": "off-hours session detection",
        "auth_method_changed": "factor downgrade signal",
        "first_time_admin_activation": "privilege escalation signal",
        "stale_rsa_key": "long-lived service credential",
    },
}

_PACK_NAMES: dict[str, str] = {
    "cis": "CIS Snowflake Foundations v1.0.0",
    "soc2": "SOC2 CC6 - Logical Access Controls",
    "sox": "SOX ITGC",
    "hipaa": "HIPAA Section 164.312 Technical Safeguards",
    "unc5537": "UNC5537 / 2024 Snowflake breach lessons",
}


def packs_for_rule(rule_id: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for pack_id, mapping in _PACK_MAPPINGS.items():
        if rule_id in mapping:
            out.append((pack_id, mapping[rule_id]))
    return out


def rules_in_pack(pack_id: str) -> set[str]:
    return set(_PACK_MAPPINGS.get(pack_id, {}).keys())


def pack_name(pack_id: str) -> str:
    return _PACK_NAMES.get(pack_id, pack_id.upper())


def all_packs() -> list[str]:
    return list(_PACK_MAPPINGS.keys())
