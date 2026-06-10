# PLAN — Securing Datasets with Unity Catalog (maintainer notes)

Condensed design summary for lab maintainers. Full spec:
`docs/superpowers/specs/2026-06-08-securing-datasets-with-uc-design.md`.

## Goal
A ~45-minute, notebook-driven Databricks **Free Edition** lab teaching UC data security from
coarse `GRANT`s → column masks → row filters → ABAC.

## Scenario
Fictional company HR data in `workspace.uc_security_lab`: `departments`, `employees` (PII:
`ssn`/`dob`/`email`, plus `region`), `compensation` (`base_salary`/`bonus`), and `analyst_access`
(entitlements control table, starts empty).

## Arc
Setup → Part 1 (model: hierarchy, ownership, GRANT/REVOKE, deny-by-default, Catalog Explorer +
MANAGE) → Part 2 (column masks) → Part 3 (row filters) → Part 4 (ABAC) → wrap-up + cleanup.

## Free Edition constraints (the design drivers)
- **Single user.** You can't log in as a second principal, so "have another user query it" is out.
- **Groups exist but membership is cached.** Free Edition *can* create groups (Settings → Identity
  and access → Groups, and via SCIM API), but `is_account_group_member()` is evaluated against a
  cached membership snapshot — a membership change takes minutes + a new compute session to
  register (measured: still `false` 2+ min after adding self). So toggling group membership is
  unusable for a live "watch it flip" demo. A control table flips instantly.
- **Workspace admin.** Catalog is always `workspace`. Serverless only; one 2X-Small warehouse;
  daily compute quota.

## Key design decisions
- **Visible enforcement for one user:** row filters & column masks read the `analyst_access`
  table keyed on `current_user()`. The learner toggles a row and re-runs to see masking/filtering
  change. Each section also shows the production `is_account_group_member(...)` pattern.
- **ABAC requires governed tags.** An ordinary tag in a policy condition errors with
  `Unknown tag policy key`. Governed tags have **no SQL DDL** — created in Catalog Explorer →
  Governed tags. **Confirmed: that UI works in Free Edition** (admin has CREATE by default), so
  Part 4 is fully hands-on: create governed tag `pii` in the UI, then tag + `CREATE POLICY` in SQL.
- **Mask/policy conflict:** a column can't have both a manual mask and an ABAC policy mask. The
  lab applies manual masks to `ssn`/`base_salary`/`bonus` and uses ABAC on `email`.

## Validation status
Validated end-to-end on Databricks Free Edition: `setup_tables.py` runs cleanly (6 departments,
~38 employees, ~38 compensation rows, empty `analyst_access`); Parts 1–3 (grants, column masks,
row filter) and Part 4 (ABAC with a governed tag `pii` created in Catalog Explorer) all behave as
documented; the cleanup cell fully tears everything down. Note: the governed tag's allowed values
must include the value the policy uses (`email`), and `DROP POLICY` does not accept `IF EXISTS`.

## Conventions
Databricks source notebooks (`# COMMAND ----------`, `# MAGIC %md`/`%sql`/`%run`). Lab SQL
hardcodes `workspace.uc_security_lab` (matches the sibling `ai-bi` lab and Free Edition's fixed
catalog); `data/setup_tables.py` keeps a `catalog` widget defaulting to `workspace`.
