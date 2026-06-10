# Reference SQL

Every statement used in the lab, in order. All objects are in `workspace.uc_security_lab`.

## Part 1 — Grants & inspection

```sql
-- Ownership / existing grants
DESCRIBE SCHEMA EXTENDED workspace.uc_security_lab;
SHOW GRANTS ON SCHEMA workspace.uc_security_lab;

-- Grant, inspect, revoke
GRANT SELECT ON TABLE workspace.uc_security_lab.employees TO `account users`;
SHOW GRANTS ON TABLE workspace.uc_security_lab.employees;

SELECT grantee, privilege_type
FROM workspace.information_schema.table_privileges
WHERE table_schema = 'uc_security_lab' AND table_name = 'employees';

REVOKE SELECT ON TABLE workspace.uc_security_lab.employees FROM `account users`;
```

## Part 2 — Column masks

```sql
-- Mask functions (read the analyst_access control table)
CREATE OR REPLACE FUNCTION workspace.uc_security_lab.ssn_mask(ssn STRING)
RETURN CASE
  WHEN EXISTS (SELECT 1 FROM workspace.uc_security_lab.analyst_access a
               WHERE a.user_email = current_user() AND a.can_view_pii) THEN ssn
  ELSE 'XXX-XX-XXXX'
END;

CREATE OR REPLACE FUNCTION workspace.uc_security_lab.salary_mask(value INT)
RETURN CASE
  WHEN EXISTS (SELECT 1 FROM workspace.uc_security_lab.analyst_access a
               WHERE a.user_email = current_user() AND a.can_view_pii) THEN value
  ELSE NULL
END;

-- Attach them
ALTER TABLE workspace.uc_security_lab.employees    ALTER COLUMN ssn         SET MASK workspace.uc_security_lab.ssn_mask;
ALTER TABLE workspace.uc_security_lab.compensation ALTER COLUMN base_salary SET MASK workspace.uc_security_lab.salary_mask;
ALTER TABLE workspace.uc_security_lab.compensation ALTER COLUMN bonus       SET MASK workspace.uc_security_lab.salary_mask;

-- Grant yourself PII access (also sets region for Part 3)
INSERT INTO workspace.uc_security_lab.analyst_access VALUES (current_user(), 'AMER', true);
```

## Part 3 — Row filter

```sql
CREATE OR REPLACE FUNCTION workspace.uc_security_lab.region_filter(region STRING)
RETURN EXISTS (
  SELECT 1 FROM workspace.uc_security_lab.analyst_access a
  WHERE a.user_email = current_user()
    AND (a.allowed_region = region OR a.allowed_region = 'ALL')
);

ALTER TABLE workspace.uc_security_lab.employees
  SET ROW FILTER workspace.uc_security_lab.region_filter ON (region);

-- Widen to all regions
UPDATE workspace.uc_security_lab.analyst_access
SET allowed_region = 'ALL' WHERE user_email = current_user();
```

## Part 4 — ABAC

Governed tag `pii` (allowed values `ssn`, `email`) must be created first in **Catalog Explorer →
Governed tags** — there is no SQL DDL for governed tags.

```sql
-- Tag a column with the governed tag
ALTER TABLE workspace.uc_security_lab.employees ALTER COLUMN email SET TAGS ('pii' = 'email');

-- One policy that masks every column tagged pii=email across the schema
CREATE OR REPLACE FUNCTION workspace.uc_security_lab.pii_redact(value STRING)
RETURN '*** REDACTED ***';

CREATE POLICY mask_pii_email
ON SCHEMA workspace.uc_security_lab
COLUMN MASK workspace.uc_security_lab.pii_redact
TO `account users`
FOR TABLES
MATCH COLUMNS has_tag_value('pii', 'email') AS c
ON COLUMN c;

-- Tag once, protect everywhere: a new table is covered automatically
CREATE OR REPLACE TABLE workspace.uc_security_lab.contractors (contractor_id INT, contact_email STRING);
INSERT INTO workspace.uc_security_lab.contractors VALUES (1, 'jordan.vance@northwind.example');
ALTER TABLE workspace.uc_security_lab.contractors ALTER COLUMN contact_email SET TAGS ('pii' = 'email');
SELECT * FROM workspace.uc_security_lab.contractors;   -- contact_email is redacted

SHOW POLICIES ON SCHEMA workspace.uc_security_lab;
```

## Cleanup

```sql
-- Note: DROP POLICY does not support IF EXISTS.
DROP POLICY mask_pii_email ON SCHEMA workspace.uc_security_lab;
ALTER TABLE workspace.uc_security_lab.employees    ALTER COLUMN ssn         DROP MASK;
ALTER TABLE workspace.uc_security_lab.compensation ALTER COLUMN base_salary DROP MASK;
ALTER TABLE workspace.uc_security_lab.compensation ALTER COLUMN bonus       DROP MASK;
ALTER TABLE workspace.uc_security_lab.employees    DROP ROW FILTER;
DROP SCHEMA IF EXISTS workspace.uc_security_lab CASCADE;
```
