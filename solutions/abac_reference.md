# ABAC Reference

Deeper notes on Part 4 — attribute-based access control (ABAC) in Unity Catalog.

## The idea

Instead of attaching a mask/filter to each column or table by hand, you:

1. **Tag** securable objects with **governed tags** (e.g. `pii = ssn`, `sensitivity = high`).
2. Write **ABAC policies** whose conditions match those tags (`has_tag` / `has_tag_value`).
3. UC applies the policy's row filter or column mask to **every matching object** in scope —
   including objects created or tagged *after* the policy exists.

One policy can replace hundreds of per-table `ALTER` statements, and coverage follows your data.

ABAC does **both** fine-grained controls — column masks *and* row filters — each driven by a tag:

```sql
-- Column-mask policy: mask any column tagged pii=email
CREATE POLICY mask_pii_email
ON SCHEMA <schema>
COLUMN MASK <schema>.email_mask
TO `account users`
FOR TABLES
MATCH COLUMNS has_tag_value('pii', 'email') AS c
ON COLUMN c;

-- Row-filter policy: filter any table that has a column tagged rls=region.
-- MATCH COLUMNS selects the tagged column; USING COLUMNS feeds its value to the filter function.
CREATE POLICY filter_by_region
ON SCHEMA <schema>
ROW FILTER <schema>.region_scope
TO `account users`
FOR TABLES
MATCH COLUMNS has_tag_value('rls', 'region') AS reg
USING COLUMNS (reg);
```

You can also add a `WHEN has_tag_value('sensitivity','high')` clause to a row-filter policy to
restrict *which tables* it applies to (a table-level tag), on top of the column match.

## Ordinary tags vs. governed tags

| | Ordinary tag | Governed tag |
|---|---|---|
| Vocabulary | Free-form key/value | Centrally defined keys + allowed values |
| Consistency | Not enforced | Enforced |
| Who can apply | Anyone who can modify the object | Controlled by tag permissions |
| Created via | SQL (`ALTER ... SET TAGS`) or UI | **Catalog Explorer → Governed tags** (no SQL DDL) |
| **Allowed in an ABAC policy condition** | ❌ No | ✅ Yes |

**Key takeaway:** ABAC policies require **governed** tags. Referencing an ordinary tag in a
policy condition fails with:

```
[UC_INVALID_POLICY_CONDITION] Unknown tag policy key `pii`.
```

This is why the lab has you create the governed tag `pii` in the UI before writing the policy.

### Free Edition specifics
- The **Governed tags** UI **does work** in Free Edition — as the workspace admin you have the
  `CREATE` permission by default. (Catalog → *Governed tags* → *Create governed tag*.)
- There is **no SQL command** to create a governed tag on any edition; it's UI/account-API only.
- Applying a tag to a column (`ALTER ... SET TAGS`) and `CREATE POLICY` both work via SQL once
  the governed tag exists.

## The production pattern (groups instead of a control table)

In the lab, mask/filter functions read the `analyst_access` table keyed on `current_user()` so the
effect can be toggled and seen **instantly**. (Free Edition *can* create groups, but a
group-membership change is cached and takes minutes plus a new compute session to register — too
slow to demo live.) In a real workspace you'd gate on **group membership** instead — no control
table needed:

```sql
-- Column mask: only HR admins see real SSNs
CREATE FUNCTION ssn_mask(ssn STRING)
RETURN CASE WHEN is_account_group_member('hr_admins') THEN ssn ELSE 'XXX-XX-XXXX' END;

-- Row filter: analysts see only their region's rows
CREATE FUNCTION region_filter(region STRING)
RETURN is_account_group_member(concat('region_', lower(region)));
```

And ABAC policies target groups directly with `TO ... EXCEPT ...`:

```sql
CREATE POLICY mask_ssn
ON SCHEMA prod.hr
COLUMN MASK prod.hr.ssn_redact
TO `account users` EXCEPT `hr_admins`        -- everyone is masked except HR admins
FOR TABLES
MATCH COLUMNS has_tag_value('pii', 'ssn') AS c
ON COLUMN c;
```

## Gotchas confirmed in this lab

- A column **cannot** have both a manually-applied mask **and** an ABAC policy mask — they
  conflict. ABAC *replaces* the manual approach; it doesn't stack. (The lab applies the manual
  mask to `ssn`/`base_salary` and uses ABAC on `email` to avoid the conflict.)
- Row filters and column masks **do** coexist on the same table.
- `MATCH COLUMNS` only accepts tag predicates (`has_tag`, `has_tag_value`) — you can't match a
  column by bare name there.
- Policy and mask/filter functions are evaluated at **query time**, on every read.

## Going further at enterprise scale
- Let **data classification** auto-detect and tag PII so policies cover new data with no manual
  tagging.
- Audit enforcement with `SHOW POLICIES` and the `system.access.audit` system table.
- Define governed tags and policies at the **catalog** level so whole domains are covered at once.
