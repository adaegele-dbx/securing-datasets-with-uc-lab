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
# MAGIC > - You are the **only user** and a **workspace admin**. You *can* create groups (and in
# MAGIC >   production you'd grant access to groups, not individuals), but you can't log in as a
# MAGIC >   second user — and a **group-membership change is cached and can take several minutes
# MAGIC >   (and a new compute session) to take effect**. That's too slow to watch live. So in
# MAGIC >   Parts 2–3 we drive enforcement from a small **`analyst_access` control table** keyed on
# MAGIC >   your identity: you add a row, re-run the query, and the result changes **instantly**.
# MAGIC >   (A control/mapping table like this is also a legitimate production pattern.)
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
# MAGIC it's the only thing that scales. Free Edition *can* create groups
# MAGIC (**Settings → Identity and access → Groups**), and the grant examples below work the same
# MAGIC against a group you create. We'll use the built-in **`account users`** group so the cells run
# MAGIC without a detour.

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
# MAGIC ### 1c. `SELECT` alone is not enough — you also need `USE CATALOG` and `USE SCHEMA`
# MAGIC
# MAGIC > ⚠️ **This trips people up constantly.** Granting `SELECT` on a table does **not**, by
# MAGIC > itself, let someone read it. To reach any object, a principal needs **traversal**
# MAGIC > privileges down the hierarchy first:
# MAGIC >
# MAGIC > | Privilege | Granted on | Why it's needed |
# MAGIC > |-----------|------------|-----------------|
# MAGIC > | `USE CATALOG` | the **catalog** | "see into" the catalog |
# MAGIC > | `USE SCHEMA` | the **schema** | "see into" the schema |
# MAGIC > | `SELECT` | the **table** | actually read the data |
# MAGIC >
# MAGIC > Miss `USE CATALOG` or `USE SCHEMA` and the user gets a permission error even with `SELECT`.
# MAGIC > As the owner you already have all three, which is why your queries work. This layered
# MAGIC > requirement *is* the **principle of least privilege** — access is granted explicitly at
# MAGIC > each level, nothing is implied.
# MAGIC
# MAGIC Let's grant the **full chain** to the built-in **`account users`** group, inspect it, then
# MAGIC revoke it.

# COMMAND ----------

# MAGIC %sql
# MAGIC GRANT USE CATALOG ON CATALOG workspace TO `account users`

# COMMAND ----------

# MAGIC %sql
# MAGIC GRANT USE SCHEMA ON SCHEMA workspace.uc_security_lab TO `account users`

# COMMAND ----------

# MAGIC %sql
# MAGIC GRANT SELECT ON TABLE workspace.uc_security_lab.employees TO `account users`

# COMMAND ----------

# MAGIC %md
# MAGIC `SHOW GRANTS` on the table lists the `SELECT` grant. The `USE CATALOG` / `USE SCHEMA` grants
# MAGIC live on the catalog and schema — try `SHOW GRANTS ON SCHEMA workspace.uc_security_lab`.
# MAGIC
# MAGIC > 💡 **Groups in practice:** here we used the built-in `account users` group. In production
# MAGIC > you'd create a purpose-built group like `hr_analysts` (**Settings → Identity and access →
# MAGIC > Groups**, available in Free Edition) and grant this same chain to it — so access follows
# MAGIC > the group, not individuals.

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

# MAGIC %md
# MAGIC Now revoke the full chain to return to deny-by-default.

# COMMAND ----------

# MAGIC %sql
# MAGIC REVOKE SELECT ON TABLE workspace.uc_security_lab.employees FROM `account users`

# COMMAND ----------

# MAGIC %sql
# MAGIC REVOKE USE SCHEMA ON SCHEMA workspace.uc_security_lab FROM `account users`

# COMMAND ----------

# MAGIC %sql
# MAGIC REVOKE USE CATALOG ON CATALOG workspace FROM `account users`

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
# MAGIC We'll use a small twist so you can **see the effect change live**. Free Edition lets you
# MAGIC create groups, but a group-membership change is cached and takes minutes (and a new compute
# MAGIC session) to register — you couldn't watch it flip. So instead our mask reads the
# MAGIC **`analyst_access` control table** keyed on `current_user()`: same idea (a function decides),
# MAGIC but you can toggle it by editing one row and see the result **instantly**. Swapping the
# MAGIC `EXISTS (...)` check for `is_account_group_member('hr_admins')` is all it takes to use groups
# MAGIC in production.

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
# MAGIC > **In production** this filter would check **group membership** instead of a control table —
# MAGIC > one group per region, and an admin group that sees everything:
# MAGIC > ```sql
# MAGIC > CREATE FUNCTION region_filter(region STRING) RETURN
# MAGIC >   is_account_group_member('hr_admins')                          -- HR admins see all regions
# MAGIC >   OR is_account_group_member(concat('region_', lower(region))); -- else only your region's group
# MAGIC > ```
# MAGIC > With that version, a user in the `region_amer` group sees only AMER rows, and `hr_admins`
# MAGIC > members see everything — no per-user table to maintain. We use the `analyst_access` table
# MAGIC > below only so you can watch the effect change **instantly** (recall: group-membership
# MAGIC > changes are cached and take minutes to register).

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
# MAGIC The same object can have **either** a manually-applied control (Part 2/3) **or** an ABAC
# MAGIC policy — **not both** (they'd conflict). So in this Part we apply ABAC to objects with no
# MAGIC manual control yet:
# MAGIC - the **`email`** column (no manual mask) → column-mask policy, and
# MAGIC - the **`departments`** table (no manual row filter) → row-filter policy.
# MAGIC
# MAGIC `employees` already has a manual mask on `ssn` and a manual row filter, so we leave it alone
# MAGIC here. Mask and filter functions run at **query time**, every time.

# COMMAND ----------

# MAGIC %md
# MAGIC ### 4a. The building blocks of ABAC
# MAGIC
# MAGIC ABAC has four moving parts — worth naming before we build:
# MAGIC
# MAGIC | Piece | What it is | In this lab |
# MAGIC |-------|-----------|-------------|
# MAGIC | **Governed tag** | A centrally-defined *attribute* (key + allowed values) attached to columns/tables | `pii = email`, `rls = region` |
# MAGIC | **UC function** | A SQL UDF doing the work — a **column mask** (returns a value) or a **row filter** (returns true/false) | `email_mask(...)`, `region_scope(...)` |
# MAGIC | **ABAC policy** | A rule binding the two: *"apply this function to every object matching this tag"* | `mask_pii_email`, `filter_by_region` |
# MAGIC | **Principals** (`TO`) | Who the policy applies to — users/groups, with optional `EXCEPT` | `account users` |
# MAGIC
# MAGIC The policy's **`MATCH COLUMNS has_tag_value(...)`** clause is the key idea: instead of naming a
# MAGIC column, it selects *any* column carrying the tag — so one policy covers the whole schema and
# MAGIC every table you add later. The flow is always **tag → policy → function**, evaluated at query
# MAGIC time.

# COMMAND ----------

# MAGIC %md
# MAGIC ### 4b. Ordinary tags vs. governed tags — and why it matters here
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
# MAGIC ### 4c. 🖱️ Create the governed tags in the UI (one-time)
# MAGIC
# MAGIC Governed tags are created in **Catalog Explorer** (there's no SQL command for it). Create the
# MAGIC **two** tags this Part uses:
# MAGIC
# MAGIC 1. In the left sidebar, click **Catalog**.
# MAGIC 2. Click the **Governed tags** button (near the top of the Catalog pane) → **Create governed tag**.
# MAGIC 3. Create the first tag — **key:** `pii`, **allowed values:** `ssn`, `email`. Save.
# MAGIC 4. Create a second tag — **key:** `rls`, **allowed value:** `region`. Save.
# MAGIC
# MAGIC > As the workspace admin you have permission to do this in Free Edition. In a larger
# MAGIC > organization, a governance admin defines these tags once for everyone — that's the whole
# MAGIC > point of *governed* tags.
# MAGIC
# MAGIC When both tags exist, run the next cell.

# COMMAND ----------

# MAGIC %md
# MAGIC ### 4d. Tag the sensitive column
# MAGIC Apply the governed tag `pii = email` to `employees.email`. (You can also do this in the UI on
# MAGIC the column's page — but SQL is faster to show here.)

# COMMAND ----------

# MAGIC %sql
# MAGIC ALTER TABLE workspace.uc_security_lab.employees
# MAGIC   ALTER COLUMN email SET TAGS ('pii' = 'email')

# COMMAND ----------

# MAGIC %md
# MAGIC ### 4e. Write ONE policy for everything tagged `pii = email`
# MAGIC First the mask function, then the policy. Rather than blank out the field, this mask is
# MAGIC **partial** — it keeps the first character and the domain (useful for analytics) and hides
# MAGIC the rest, e.g. `ana.reyes@northwind.example` → `a****@northwind.example`. `MATCH COLUMNS
# MAGIC has_tag_value('pii','email')` is what makes the policy apply to **every** matching column in
# MAGIC the schema rather than one named column.

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION workspace.uc_security_lab.email_mask(value STRING)
# MAGIC RETURN CASE
# MAGIC   WHEN value IS NULL THEN NULL
# MAGIC   WHEN instr(value, '@') = 0 THEN '****'
# MAGIC   ELSE concat(substring(value, 1, 1), '****@', substring(value, instr(value, '@') + 1))
# MAGIC END

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE POLICY mask_pii_email
# MAGIC ON SCHEMA workspace.uc_security_lab
# MAGIC COLUMN MASK workspace.uc_security_lab.email_mask
# MAGIC TO `account users`
# MAGIC FOR TABLES
# MAGIC MATCH COLUMNS has_tag_value('pii', 'email') AS c
# MAGIC ON COLUMN c

# COMMAND ----------

# MAGIC %md
# MAGIC ### 4f. ▶️ See the policy applied
# MAGIC Query `employees` — the `email` column now shows the **partial mask** (`a****@…`), applied by
# MAGIC the policy, not by any per-column `ALTER` we wrote.

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT employee_id, full_name, email, region
# MAGIC FROM workspace.uc_security_lab.employees
# MAGIC ORDER BY employee_id
# MAGIC LIMIT 10

# COMMAND ----------

# MAGIC %md
# MAGIC ### 4g. ▶️ Tag once, protect everywhere
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
# MAGIC `contact_email` came back masked automatically. **That** is the power of ABAC: govern by
# MAGIC *attribute*, and coverage follows your data without per-table work.

# COMMAND ----------

# MAGIC %md
# MAGIC ### 4h. ABAC can filter rows too — not just mask columns
# MAGIC A column-mask policy hides *values*; a **row-filter policy** hides whole *rows*, again driven
# MAGIC by a tag. We'll scope the `departments` table by region. The function is richer than the
# MAGIC constant-style mask — it returns a boolean per row from your entitlement (and honors `'ALL'`):

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE OR REPLACE FUNCTION workspace.uc_security_lab.region_scope(region STRING)
# MAGIC RETURN EXISTS (
# MAGIC   SELECT 1 FROM workspace.uc_security_lab.analyst_access a
# MAGIC   WHERE a.user_email = current_user()
# MAGIC     AND (a.allowed_region = region OR a.allowed_region = 'ALL')
# MAGIC )

# COMMAND ----------

# MAGIC %md
# MAGIC Tag the `region` column of `departments` with the second governed tag, `rls = region`:

# COMMAND ----------

# MAGIC %sql
# MAGIC ALTER TABLE workspace.uc_security_lab.departments
# MAGIC   ALTER COLUMN region SET TAGS ('rls' = 'region')

# COMMAND ----------

# MAGIC %md
# MAGIC Now one row-filter policy covers any table with a column tagged `rls = region`. `MATCH COLUMNS`
# MAGIC selects the tagged column and `USING COLUMNS` feeds its value to the filter function:

# COMMAND ----------

# MAGIC %sql
# MAGIC CREATE POLICY filter_by_region
# MAGIC ON SCHEMA workspace.uc_security_lab
# MAGIC ROW FILTER workspace.uc_security_lab.region_scope
# MAGIC TO `account users`
# MAGIC FOR TABLES
# MAGIC MATCH COLUMNS has_tag_value('rls', 'region') AS reg
# MAGIC USING COLUMNS (reg)

# COMMAND ----------

# MAGIC %md
# MAGIC ### 4i. ▶️ See the row-filter policy scope your rows
# MAGIC You currently have `allowed_region = 'ALL'`, so all 6 departments show. Narrow it to a single
# MAGIC region and re-run — only that region's departments remain. (`employees` is untouched by this
# MAGIC policy — its `region` column isn't tagged `rls`, and it already has a manual row filter.)

# COMMAND ----------

# MAGIC %sql
# MAGIC UPDATE workspace.uc_security_lab.analyst_access
# MAGIC SET allowed_region = 'EMEA'
# MAGIC WHERE user_email = current_user()

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT dept_id, dept_name, region
# MAGIC FROM workspace.uc_security_lab.departments
# MAGIC ORDER BY dept_id

# COMMAND ----------

# MAGIC %md
# MAGIC Only the **EMEA** departments remain — the row-filter policy is enforcing your entitlement via
# MAGIC the tag, with no `ALTER TABLE ... SET ROW FILTER` on `departments` at all.

# COMMAND ----------

# MAGIC %md
# MAGIC ### 4j. Inspect the policies in the schema
# MAGIC You should see **both** policies — `mask_pii_email` (column mask) and `filter_by_region`
# MAGIC (row filter).

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
# MAGIC Drops both ABAC policies, the masks, the row filter, and the entire lab schema. Safe to re-run.

# COMMAND ----------

cleanup_statements = [
    # DROP POLICY does not support IF EXISTS; the try/except below handles "not found".
    "DROP POLICY mask_pii_email ON SCHEMA workspace.uc_security_lab",
    "DROP POLICY filter_by_region ON SCHEMA workspace.uc_security_lab",
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

print("\nCleanup complete. (The governed tags 'pii' and 'rls' remain — delete them in Catalog Explorer if you wish.)")
