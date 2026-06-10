# Databricks notebook source

# MAGIC %md
# MAGIC # Securing Datasets with Unity Catalog
# MAGIC ### Hands-On Lab
# MAGIC
# MAGIC ---
# MAGIC
# MAGIC ## What you'll do
# MAGIC
# MAGIC Unity Catalog (UC) is how you govern data in Databricks. In this lab you'll secure a
# MAGIC fictional company's **HR dataset**, working from coarse-grained permissions all the way
# MAGIC down to row- and column-level security and attribute-based access control (ABAC).
# MAGIC
# MAGIC | Step | What you'll do |
# MAGIC |------|----------------|
# MAGIC | **Setup** | Generate the HR data — `departments`, `employees`, `compensation`, and an `analyst_access` control table |
# MAGIC | **Part 1** | Learn the **UC security model** — the object hierarchy, ownership, and `GRANT`/`REVOKE` |
# MAGIC | **Part 2** | **Column-level security** — mask SSNs and salaries with **column masks** |
# MAGIC | **Part 3** | **Row-level security** — restrict employees by region with a **row filter** |
# MAGIC | **Part 4** | **Scale it with ABAC** — tag columns once and protect them everywhere with a **policy** |
# MAGIC
# MAGIC ---
# MAGIC
# MAGIC ## Prerequisites
# MAGIC
# MAGIC - A **Databricks Free Edition** workspace (Unity Catalog is on by default).
# MAGIC - A **SQL warehouse running** (Free Edition's 2X-Small Serverless Starter is enough).
# MAGIC - This repo cloned as a **Git folder** (`Workspace` → `Create` → `Git folder`).
# MAGIC
# MAGIC > **Free Edition notes**
# MAGIC > - You are the **only user** and a **workspace admin**. Normally you'd test access control
# MAGIC >   by logging in as a *different* user or toggling *group* membership — but Free Edition
# MAGIC >   has no account console to create groups or users. So in Parts 2–3 we make enforcement
# MAGIC >   visible a different way: a small **`analyst_access` control table** that you grant
# MAGIC >   yourself access in, then re-run the query and watch the result change.
# MAGIC > - Your catalog is named **`workspace`** — every table below lives in
# MAGIC >   `workspace.uc_security_lab`.
# MAGIC > - Free Edition has a **daily compute quota**. The lab is lightweight, and the final cell
# MAGIC >   cleans everything up.
# MAGIC
# MAGIC > **Tip:** Run each cell with `Shift + Enter` and read the markdown between cells — that's
# MAGIC > where the instructions live.

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Setup — Generate the HR data
# MAGIC
# MAGIC The cell below runs `data/setup_tables.py`, which creates the schema
# MAGIC `workspace.uc_security_lab` and four tables:
# MAGIC
# MAGIC | Table | Description |
# MAGIC |-------|-------------|
# MAGIC | `departments` | 6 departments, one region each |
# MAGIC | `employees` | ~40 employees with PII (`ssn`, `dob`, `email`) and a `region` column |
# MAGIC | `compensation` | Salary / bonus / equity per employee (sensitive) |
# MAGIC | `analyst_access` | **Empty** control table — you'll add a row to it later |
# MAGIC
# MAGIC Run it once before continuing.

# COMMAND ----------

# MAGIC %run ./data/setup_tables

# COMMAND ----------

# MAGIC %md
# MAGIC ### Verify the setup
# MAGIC You should see row counts for all four tables, and `analyst_access` should be **empty (0)**.

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT 'departments'    AS table_name, COUNT(*) AS row_count FROM workspace.uc_security_lab.departments
# MAGIC UNION ALL SELECT 'employees',      COUNT(*) FROM workspace.uc_security_lab.employees
# MAGIC UNION ALL SELECT 'compensation',   COUNT(*) FROM workspace.uc_security_lab.compensation
# MAGIC UNION ALL SELECT 'analyst_access', COUNT(*) FROM workspace.uc_security_lab.analyst_access
# MAGIC ORDER BY table_name

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Part 1 — The Unity Catalog security model
# MAGIC
# MAGIC Before locking anything down, understand the model.
# MAGIC
# MAGIC **1. Everything is a securable object in a hierarchy:**
# MAGIC
# MAGIC ```
# MAGIC metastore  →  catalog  →  schema  →  table / view / function  →  column
# MAGIC ```
# MAGIC
# MAGIC A name like `workspace.uc_security_lab.employees` is exactly that path: catalog → schema →
# MAGIC table. Privileges **inherit downward** — grant `SELECT` on a schema and it applies to every
# MAGIC table in it.
# MAGIC
# MAGIC **2. UC is deny-by-default.** No one can read an object until they're explicitly granted
# MAGIC access (or they own it, or they're an admin). You never have to "block" access — you only
# MAGIC ever *grant* it.
# MAGIC
# MAGIC **3. Secure by structure first.** Your **first** line of defense is good catalog/schema
# MAGIC layout — put sensitive data in its own schema/catalog and grant narrowly. Row/column controls
# MAGIC (Parts 2–4) are the *fine-grained* layer **on top of** that structure, not a replacement for it.
# MAGIC
# MAGIC **4. Principals** you grant to are **users**, **service principals**, and **groups**. In
# MAGIC production you almost always grant to **groups** (e.g. `hr_analysts`), never individuals —
# MAGIC it's the only thing that scales. (Free Edition can't create groups, so today we'll use the
# MAGIC built-in `account users` group and your own identity.)

# COMMAND ----------

# MAGIC %md
# MAGIC ### 1a. Who owns this schema?
# MAGIC The **owner** of an object has full control over it and can grant access to others. Because
# MAGIC you created it, that's you.

# COMMAND ----------

# MAGIC %sql
# MAGIC DESCRIBE SCHEMA EXTENDED workspace.uc_security_lab

# COMMAND ----------

# MAGIC %md
# MAGIC ### 1b. What grants exist today?
# MAGIC `SHOW GRANTS` lists the privileges on an object. Right now only ownership/admin privileges
# MAGIC exist — nothing has been granted to anyone else yet (deny-by-default).

# COMMAND ----------

# MAGIC %sql
# MAGIC SHOW GRANTS ON SCHEMA workspace.uc_security_lab

# COMMAND ----------

# MAGIC %md
# MAGIC ### 1c. Grant and revoke a privilege
# MAGIC
# MAGIC Let's grant **`SELECT`** on the `employees` table to the built-in **`account users`** group,
# MAGIC inspect it, then revoke it. (In a real deployment you'd grant to a purpose-built group like
# MAGIC `hr_analysts`.)
# MAGIC
# MAGIC > **Two privileges are needed to read data:** traversal (`USE CATALOG`, `USE SCHEMA`) to
# MAGIC > "see" the container, plus `SELECT` on the data itself. As owner you already have both;
# MAGIC > a new group would need `USE CATALOG`/`USE SCHEMA` too. This is the **principle of least
# MAGIC > privilege** — grant only what's required, at the narrowest scope.

# COMMAND ----------

# MAGIC %sql
# MAGIC GRANT SELECT ON TABLE workspace.uc_security_lab.employees TO `account users`

# COMMAND ----------

# MAGIC %sql
# MAGIC SHOW GRANTS ON TABLE workspace.uc_security_lab.employees

# COMMAND ----------

# MAGIC %md
# MAGIC Privileges are also queryable as data via `information_schema` — handy for auditing
# MAGIC "who can see what" across many objects at once.

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT grantee, privilege_type
# MAGIC FROM workspace.information_schema.table_privileges
# MAGIC WHERE table_schema = 'uc_security_lab' AND table_name = 'employees'

# COMMAND ----------

# MAGIC %sql
# MAGIC REVOKE SELECT ON TABLE workspace.uc_security_lab.employees FROM `account users`

# COMMAND ----------

# MAGIC %md
# MAGIC > 💡 **You don't have to use SQL.** Everything here is also point-and-click in **Catalog
# MAGIC > Explorer** (left sidebar → **Catalog**) — select the table, open the **Permissions** tab,
# MAGIC > and Grant/Revoke there. That's how most governance admins work day to day.
# MAGIC >
# MAGIC > 💡 **Delegating without giving away ownership:** the **`MANAGE`** privilege lets you allow
# MAGIC > someone to grant/revoke access on an object *without* making them the owner — useful for
# MAGIC > letting a data steward manage permissions on your tables.

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Part 2 — Column-level security (column masks)
# MAGIC
# MAGIC `GRANT` is all-or-nothing per table: you can read the table or you can't. But our `employees`
# MAGIC table has a Social Security Number, and `compensation` has salaries. We want analysts to query
# MAGIC these tables **without** seeing those sensitive columns in the clear.
# MAGIC
# MAGIC A **column mask** is a SQL function attached to a column. UC runs it on every read and returns
# MAGIC whatever the function returns — so the function decides who sees the real value.
# MAGIC
# MAGIC **In production**, the mask checks group membership:
# MAGIC ```sql
# MAGIC CREATE FUNCTION ssn_mask(ssn STRING) RETURN
# MAGIC   CASE WHEN is_account_group_member('hr_admins') THEN ssn ELSE 'XXX-XX-XXXX' END;
# MAGIC ```
# MAGIC We can't create groups in Free Edition, so instead our mask reads the **`analyst_access`
# MAGIC control table** keyed on `current_user()`. Same idea — the function decides — but we can
# MAGIC drive it by editing a table, with a single user.

# COMMAND ----------

# MAGIC %md
# MAGIC ### 2a. Create the mask functions
# MAGIC `ssn_mask` returns the real SSN only if the current user has `can_view_pii = true` in
# MAGIC `analyst_access`; otherwise it returns `XXX-XX-XXXX`. `salary_mask` does the same for integer
# MAGIC salary/bonus values (returning `NULL` when not entitled).

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION workspace.uc_security_lab.ssn_mask(ssn STRING)
# MAGIC RETURN CASE
# MAGIC   WHEN EXISTS (
# MAGIC     SELECT 1 FROM workspace.uc_security_lab.analyst_access a
# MAGIC     WHERE a.user_email = current_user() AND a.can_view_pii
# MAGIC   ) THEN ssn
# MAGIC   ELSE 'XXX-XX-XXXX'
# MAGIC END

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION workspace.uc_security_lab.salary_mask(value INT)
# MAGIC RETURN CASE
# MAGIC   WHEN EXISTS (
# MAGIC     SELECT 1 FROM workspace.uc_security_lab.analyst_access a
# MAGIC     WHERE a.user_email = current_user() AND a.can_view_pii
# MAGIC   ) THEN value
# MAGIC   ELSE NULL
# MAGIC END

# COMMAND ----------

# MAGIC %md
# MAGIC ### 2b. Attach the masks to columns

# COMMAND ----------

# MAGIC %sql
# MAGIC ALTER TABLE workspace.uc_security_lab.employees
# MAGIC   ALTER COLUMN ssn SET MASK workspace.uc_security_lab.ssn_mask

# COMMAND ----------

# MAGIC %sql
# MAGIC ALTER TABLE workspace.uc_security_lab.compensation
# MAGIC   ALTER COLUMN base_salary SET MASK workspace.uc_security_lab.salary_mask

# COMMAND ----------

# MAGIC %sql
# MAGIC ALTER TABLE workspace.uc_security_lab.compensation
# MAGIC   ALTER COLUMN bonus SET MASK workspace.uc_security_lab.salary_mask

# COMMAND ----------

# MAGIC %md
# MAGIC ### 2c. ▶️ Try it — you are *not* yet entitled
# MAGIC `analyst_access` is empty, so the masks should hide the data. Run both queries: **`ssn` is
# MAGIC `XXX-XX-XXXX`** and **`base_salary`/`bonus` are `NULL`** — even though you own the tables.

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT employee_id, full_name, ssn, region
# MAGIC FROM workspace.uc_security_lab.employees
# MAGIC ORDER BY employee_id
# MAGIC LIMIT 10

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT employee_id, base_salary, bonus, stock_grant, currency
# MAGIC FROM workspace.uc_security_lab.compensation
# MAGIC ORDER BY employee_id
# MAGIC LIMIT 10

# COMMAND ----------

# MAGIC %md
# MAGIC ### 2d. Grant yourself PII access, then re-run
# MAGIC Add a row to `analyst_access` for your own user with `can_view_pii = true`. (We also set
# MAGIC `allowed_region = 'AMER'` now — Part 3 will use it.)

# COMMAND ----------

# MAGIC %sql
# MAGIC INSERT INTO workspace.uc_security_lab.analyst_access
# MAGIC VALUES (current_user(), 'AMER', true)

# COMMAND ----------

# MAGIC %md
# MAGIC Now re-run the same two queries. **The SSN and salary values are in the clear** — nothing
# MAGIC about the query changed, only your entitlement. That's the mask function reacting to
# MAGIC `analyst_access` at query time.

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT employee_id, full_name, ssn, region
# MAGIC FROM workspace.uc_security_lab.employees
# MAGIC ORDER BY employee_id
# MAGIC LIMIT 10

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT employee_id, base_salary, bonus, stock_grant, currency
# MAGIC FROM workspace.uc_security_lab.compensation
# MAGIC ORDER BY employee_id
# MAGIC LIMIT 10

# COMMAND ----------

# MAGIC %md
# MAGIC > 💡 Column masks are the modern, UC-native replacement for the older pattern of hiding
# MAGIC > columns behind hand-written **dynamic views**. The mask lives on the table itself, so every
# MAGIC > query is protected — no one can bypass it by querying the base table directly.

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Part 3 — Row-level security (row filters)
# MAGIC
# MAGIC Masks hide *columns*. A **row filter** hides *rows*. It's a function returning `TRUE`/`FALSE`
# MAGIC that UC evaluates per row — rows that return `FALSE` simply don't appear.
# MAGIC
# MAGIC Our goal: an analyst should only see employees in **their** region. We'll drive it from the
# MAGIC same `analyst_access` table: a user sees a row if `allowed_region` matches that row's region
# MAGIC (or is `'ALL'`).
# MAGIC
# MAGIC > **In production** this filter would typically check a group or a per-user mapping table the
# MAGIC > same way — e.g. `is_account_group_member('region_amer')`.

# COMMAND ----------

# MAGIC %md
# MAGIC ### 3a. Create and attach the row filter
# MAGIC `SET ROW FILTER ... ON (region)` passes each row's `region` value into the function.

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION workspace.uc_security_lab.region_filter(region STRING)
# MAGIC RETURN EXISTS (
# MAGIC   SELECT 1 FROM workspace.uc_security_lab.analyst_access a
# MAGIC   WHERE a.user_email = current_user()
# MAGIC     AND (a.allowed_region = region OR a.allowed_region = 'ALL')
# MAGIC )

# COMMAND ----------

# MAGIC %sql
# MAGIC ALTER TABLE workspace.uc_security_lab.employees
# MAGIC   SET ROW FILTER workspace.uc_security_lab.region_filter ON (region)

# COMMAND ----------

# MAGIC %md
# MAGIC ### 3b. ▶️ Try it — scoped to your region
# MAGIC In Part 2 you set `allowed_region = 'AMER'`. So this query now returns **only AMER
# MAGIC employees** — and notice the **`ssn` is still unmasked** (the Part 2 mask and this row filter
# MAGIC are both active at once). Count the rows: far fewer than the full table.

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT employee_id, full_name, ssn, region
# MAGIC FROM workspace.uc_security_lab.employees
# MAGIC ORDER BY employee_id

# COMMAND ----------

# MAGIC %md
# MAGIC ### 3c. Widen your access to every region
# MAGIC Update your entitlement to `'ALL'` and re-run — now **every region** is visible again.

# COMMAND ----------

# MAGIC %sql
# MAGIC UPDATE workspace.uc_security_lab.analyst_access
# MAGIC SET allowed_region = 'ALL'
# MAGIC WHERE user_email = current_user()

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT region, COUNT(*) AS employees
# MAGIC FROM workspace.uc_security_lab.employees
# MAGIC GROUP BY region
# MAGIC ORDER BY region

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Part 4 — Scaling it with ABAC
# MAGIC
# MAGIC Parts 2–3 worked, but look at what they cost: we wrote a function and ran an `ALTER TABLE`
# MAGIC **for every column and every table**, one at a time. Across hundreds of tables with PII, that
# MAGIC doesn't scale — and it's easy to miss a column or forget a brand-new table.
# MAGIC
# MAGIC **Attribute-Based Access Control (ABAC)** flips it around: you **tag** the sensitive columns,
# MAGIC then write **one policy** that says "mask anything tagged like this." The policy applies to
# MAGIC every matching column across the whole schema — *including tables created later*.
# MAGIC
# MAGIC ### ⚠️ A gotcha first
# MAGIC A column can have **either** a manually-applied mask (Part 2) **or** an ABAC policy mask —
# MAGIC **not both** (they'd conflict). So for ABAC we'll target a column with *no* manual mask:
# MAGIC **`email`**. (Row filters and column masks, on the other hand, happily coexist — you saw that
# MAGIC in Part 3.) Filter/mask functions run at **query time**, every time.

# COMMAND ----------

# MAGIC %md
# MAGIC ### 4a. Ordinary tags vs. governed tags — and why it matters here
# MAGIC
# MAGIC Both are key–value pairs you attach to columns/tables. The difference is governance:
# MAGIC
# MAGIC | | **Ordinary tag** | **Governed tag** |
# MAGIC |---|---|---|
# MAGIC | Vocabulary | Free-form — anyone can invent any key/value | Defined centrally; controlled set of keys + allowed values |
# MAGIC | Consistency | None (`pii`, `PII`, `Pii`…) | Enforced |
# MAGIC | Who can apply | Anyone who can modify the object | Controlled by tag permissions |
# MAGIC | **Usable in an ABAC policy?** | ❌ **No** | ✅ **Yes** |
# MAGIC
# MAGIC **ABAC policies only accept governed tags.** If you reference an ordinary tag in a policy,
# MAGIC you'll get `Unknown tag policy key`. That's *why* the next step creates a governed tag — it's
# MAGIC the controlled vocabulary the policy is allowed to rely on.

# COMMAND ----------

# MAGIC %md
# MAGIC ### 4b. 🖱️ Create a governed tag in the UI (one-time)
# MAGIC
# MAGIC Governed tags are created in **Catalog Explorer** (there's no SQL command for it). Do this once:
# MAGIC
# MAGIC 1. In the left sidebar, click **Catalog**.
# MAGIC 2. Click the **Governed tags** button (gear/tag icon near the top of the Catalog pane), then
# MAGIC    **Create governed tag**.
# MAGIC 3. **Tag key:** `pii`
# MAGIC 4. **Allowed values:** add `ssn` and `email`.
# MAGIC 5. Save.
# MAGIC
# MAGIC > As the workspace admin you have permission to do this in Free Edition. In a larger
# MAGIC > organization, a governance admin defines these tags once for everyone — that's the whole
# MAGIC > point of *governed* tags.
# MAGIC
# MAGIC When the tag exists, run the next cell.

# COMMAND ----------

# MAGIC %md
# MAGIC ### 4c. Tag the sensitive column
# MAGIC Apply the governed tag `pii = email` to `employees.email`. (You can also do this in the UI on
# MAGIC the column's page — but SQL is faster to show here.)

# COMMAND ----------

# MAGIC %sql
# MAGIC ALTER TABLE workspace.uc_security_lab.employees
# MAGIC   ALTER COLUMN email SET TAGS ('pii' = 'email')

# COMMAND ----------

# MAGIC %md
# MAGIC ### 4d. Write ONE policy for everything tagged `pii = email`
# MAGIC First a mask function the policy will use, then the policy itself. `MATCH COLUMNS
# MAGIC has_tag_value('pii','email')` is what makes this apply to **every** matching column in the
# MAGIC schema rather than one named column.

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION workspace.uc_security_lab.pii_redact(value STRING)
# MAGIC RETURN '*** REDACTED ***'

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE POLICY mask_pii_email
# MAGIC ON SCHEMA workspace.uc_security_lab
# MAGIC COLUMN MASK workspace.uc_security_lab.pii_redact
# MAGIC TO `account users`
# MAGIC FOR TABLES
# MAGIC MATCH COLUMNS has_tag_value('pii', 'email') AS c
# MAGIC ON COLUMN c

# COMMAND ----------

# MAGIC %md
# MAGIC ### 4e. ▶️ See the policy applied
# MAGIC Query `employees` — the `email` column is now `*** REDACTED ***`, applied by the policy (not
# MAGIC by any per-column `ALTER` we wrote).

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT employee_id, full_name, email, region
# MAGIC FROM workspace.uc_security_lab.employees
# MAGIC ORDER BY employee_id
# MAGIC LIMIT 10

# COMMAND ----------

# MAGIC %md
# MAGIC ### 4f. ▶️ Tag once, protect everywhere
# MAGIC Here's the payoff. Create a **brand-new** table, tag its email column with the **same**
# MAGIC governed tag, and query it — **no new policy, no `ALTER ... SET MASK`**. The existing policy
# MAGIC already covers it.

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE TABLE workspace.uc_security_lab.contractors (
# MAGIC   contractor_id INT,
# MAGIC   contact_email STRING
# MAGIC )

# COMMAND ----------

# MAGIC %sql
# MAGIC INSERT INTO workspace.uc_security_lab.contractors
# MAGIC VALUES (1, 'jordan.vance@northwind.example'), (2, 'sam.ortega@northwind.example')

# COMMAND ----------

# MAGIC %sql
# MAGIC ALTER TABLE workspace.uc_security_lab.contractors
# MAGIC   ALTER COLUMN contact_email SET TAGS ('pii' = 'email')

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT * FROM workspace.uc_security_lab.contractors

# COMMAND ----------

# MAGIC %md
# MAGIC `contact_email` came back redacted automatically. **That** is the power of ABAC: govern by
# MAGIC *attribute*, and coverage follows your data without per-table work.

# COMMAND ----------

# MAGIC %md
# MAGIC ### 4g. Inspect the policies in the schema

# COMMAND ----------

# MAGIC %sql
# MAGIC SHOW POLICIES ON SCHEMA workspace.uc_security_lab

# COMMAND ----------

# MAGIC %md
# MAGIC > 💡 **At enterprise scale**, a governance team defines a small set of governed tags
# MAGIC > (`pii`, `sensitivity`, …), grants who may apply them, and writes a handful of ABAC policies
# MAGIC > at the catalog level. New data is protected the moment it's tagged — often automatically,
# MAGIC > via UC's data classification. See `solutions/abac_reference.md` for more.

# COMMAND ----------

# MAGIC %md
# MAGIC ---
# MAGIC ## Wrap-up
# MAGIC
# MAGIC You secured a dataset across four levels:
# MAGIC
# MAGIC | Mechanism | Protects | Use it when |
# MAGIC |-----------|----------|-------------|
# MAGIC | **`GRANT` / `REVOKE`** | Whole catalogs / schemas / tables | Deciding *who can touch a dataset at all* — your baseline |
# MAGIC | **Column mask** | Specific columns | A few sensitive columns on a few tables |
# MAGIC | **Row filter** | Specific rows | Users should see only their slice (region, dept, tenant) |
# MAGIC | **ABAC policy + governed tags** | Everything tagged, across the estate | Protecting PII consistently at scale, including future tables |
# MAGIC
# MAGIC ### What to try at work (beyond Free Edition)
# MAGIC - Grant to **groups**, not users — the only thing that scales.
# MAGIC - Define **governed tags** centrally and let **data classification** auto-tag PII.
# MAGIC - **Verify & audit** your controls: `SHOW POLICIES`, and the `system.access.audit` system
# MAGIC   table for "who queried what."
# MAGIC - Explore **lineage** to see where sensitive columns flow downstream.

# COMMAND ----------

# MAGIC %md
# MAGIC ### 🧹 Cleanup (run this to reclaim Free Edition quota)
# MAGIC Drops the policy, masks, row filter, and the entire lab schema. Safe to re-run.

# COMMAND ----------

cleanup_statements = [
    # DROP POLICY does not support IF EXISTS; the try/except below handles "not found".
    "DROP POLICY mask_pii_email ON SCHEMA workspace.uc_security_lab",
    "ALTER TABLE workspace.uc_security_lab.employees ALTER COLUMN ssn DROP MASK",
    "ALTER TABLE workspace.uc_security_lab.compensation ALTER COLUMN base_salary DROP MASK",
    "ALTER TABLE workspace.uc_security_lab.compensation ALTER COLUMN bonus DROP MASK",
    "ALTER TABLE workspace.uc_security_lab.employees DROP ROW FILTER",
    "DROP SCHEMA IF EXISTS workspace.uc_security_lab CASCADE",
]
for stmt in cleanup_statements:
    try:
        spark.sql(stmt)
        print(f"OK: {stmt}")
    except Exception as e:
        print(f"SKIPPED ({stmt}): {e}")

print("\nCleanup complete. (The governed tag 'pii' remains — delete it in Catalog Explorer if you wish.)")
