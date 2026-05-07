-- Functional Role / Access Role pattern
-- =====================================
-- This sets up the canonical FR/AR pattern Uberblick is built to visualize.
-- Run as ACCOUNTADMIN (or whoever has CREATE ROLE / CREATE DATABASE).
--
-- Topology produced:
--
--     LUKEKRANZ ----+--> CUSTOMER_ANALYST  --> SOURCE_SALESFORCE_VIEWER  --> [USAGE/SELECT on SOURCE.SALESFORCE.*]
--                  +--> DATA_ENGINEER     --> SOURCE_SALESFORCE_ADMIN   --> [ALL on SOURCE.SALESFORCE.*]
--
-- In production, the user-to-functional-role assignments come from Okta SCIM.
-- We grant them manually here.

-- 1. Functional roles (one per job function)
USE ROLE USERADMIN;
CREATE ROLE IF NOT EXISTS CUSTOMER_ANALYST
    COMMENT = 'Functional role: customer-facing analyst (provisioned via Okta in prod)';
CREATE ROLE IF NOT EXISTS DATA_ENGINEER
    COMMENT = 'Functional role: data engineering (provisioned via Okta in prod)';

-- 2. Access roles (one pair per schema)
CREATE ROLE IF NOT EXISTS SOURCE_SALESFORCE_VIEWER
    COMMENT = 'Access role: read-only on SOURCE.SALESFORCE';
CREATE ROLE IF NOT EXISTS SOURCE_SALESFORCE_ADMIN
    COMMENT = 'Access role: full control on SOURCE.SALESFORCE';

-- 3. Roll all custom roles up under SYSADMIN (Snowflake best practice)
USE ROLE SECURITYADMIN;
GRANT ROLE CUSTOMER_ANALYST          TO ROLE SYSADMIN;
GRANT ROLE DATA_ENGINEER             TO ROLE SYSADMIN;
GRANT ROLE SOURCE_SALESFORCE_VIEWER  TO ROLE SYSADMIN;
GRANT ROLE SOURCE_SALESFORCE_ADMIN   TO ROLE SYSADMIN;

-- 4. Database, schema, and a few realistic tables to grant against
USE ROLE SYSADMIN;
CREATE DATABASE IF NOT EXISTS SOURCE
    COMMENT = 'Source database (raw landing from Fivetran-style connectors)';

USE DATABASE SOURCE;
CREATE SCHEMA IF NOT EXISTS SALESFORCE
    COMMENT = 'Salesforce raw landing (via Fivetran)';

USE SCHEMA SOURCE.SALESFORCE;
CREATE TABLE IF NOT EXISTS ACCOUNT (
    id              STRING,
    name            STRING,
    industry        STRING,
    annual_revenue  NUMBER,
    loaded_at       TIMESTAMP_NTZ
);
CREATE TABLE IF NOT EXISTS OPPORTUNITY (
    id              STRING,
    account_id      STRING,
    amount          NUMBER,
    stage           STRING,
    close_date      DATE,
    loaded_at       TIMESTAMP_NTZ
);
CREATE TABLE IF NOT EXISTS CONTACT (
    id              STRING,
    account_id      STRING,
    email           STRING,
    loaded_at       TIMESTAMP_NTZ
);

-- 5. Grant object privileges to access roles
USE ROLE SECURITYADMIN;

-- Viewer: read-only
GRANT USAGE  ON DATABASE SOURCE                          TO ROLE SOURCE_SALESFORCE_VIEWER;
GRANT USAGE  ON SCHEMA   SOURCE.SALESFORCE               TO ROLE SOURCE_SALESFORCE_VIEWER;
GRANT SELECT ON ALL TABLES IN SCHEMA SOURCE.SALESFORCE   TO ROLE SOURCE_SALESFORCE_VIEWER;
GRANT SELECT ON FUTURE TABLES IN SCHEMA SOURCE.SALESFORCE TO ROLE SOURCE_SALESFORCE_VIEWER;

-- Admin: full control
GRANT USAGE        ON DATABASE SOURCE                       TO ROLE SOURCE_SALESFORCE_ADMIN;
GRANT USAGE        ON SCHEMA   SOURCE.SALESFORCE            TO ROLE SOURCE_SALESFORCE_ADMIN;
GRANT MODIFY, MONITOR, CREATE TABLE, CREATE VIEW
                   ON SCHEMA   SOURCE.SALESFORCE            TO ROLE SOURCE_SALESFORCE_ADMIN;
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES
                   ON ALL TABLES IN SCHEMA SOURCE.SALESFORCE TO ROLE SOURCE_SALESFORCE_ADMIN;
GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES
                   ON FUTURE TABLES IN SCHEMA SOURCE.SALESFORCE TO ROLE SOURCE_SALESFORCE_ADMIN;

-- 6. The FR -> AR wiring (the heart of the pattern)
GRANT ROLE SOURCE_SALESFORCE_VIEWER TO ROLE CUSTOMER_ANALYST;
GRANT ROLE SOURCE_SALESFORCE_ADMIN  TO ROLE DATA_ENGINEER;

-- 7. User assignments (Okta SCIM in production; manual here)
GRANT ROLE CUSTOMER_ANALYST TO USER LUKEKRANZ;
GRANT ROLE DATA_ENGINEER    TO USER LUKEKRANZ;

-- 8. Verification
USE ROLE USERADMIN;
SHOW ROLES LIKE '%ANALYST%';
SHOW ROLES LIKE '%ENGINEER%';
SHOW ROLES LIKE 'SOURCE_%';
