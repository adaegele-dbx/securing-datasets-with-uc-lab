# Databricks notebook source

# MAGIC %md
# MAGIC # Securing Datasets with UC — Data Setup
# MAGIC This notebook generates a small synthetic **HR dataset** for the *Securing Datasets with
# MAGIC Unity Catalog* lab. It creates four tables in `${catalog}.uc_security_lab`:
# MAGIC
# MAGIC | Table | Description | Rows |
# MAGIC |-------|-------------|------|
# MAGIC | `departments` | Department reference data, one region per department | 6 |
# MAGIC | `employees` | Employee directory with PII (`ssn`, `dob`, `email`) and a `region` column | ~40 |
# MAGIC | `compensation` | Salary / bonus / equity per employee — sensitive | ~40 |
# MAGIC | `analyst_access` | **Empty** entitlements control table the lab toggles to demo access | 0 |
# MAGIC
# MAGIC It is safe to re-run: tables are overwritten and `analyst_access` is reset to empty.

# COMMAND ----------

dbutils.widgets.text("catalog", "workspace", "Catalog Name")
catalog = dbutils.widgets.get("catalog")
schema = "uc_security_lab"
print(f"Using catalog: {catalog}, schema: {schema}")

# COMMAND ----------

spark.sql(f"CREATE SCHEMA IF NOT EXISTS {catalog}.{schema}")
print(f"Schema {catalog}.{schema} is ready.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Generate the data
# MAGIC Deterministic (seeded) so every learner gets identical rows.

# COMMAND ----------

import random
from datetime import date, timedelta
from pyspark.sql.types import (
    StructType, StructField, IntegerType, StringType, DateType, BooleanType,
)

random.seed(42)

# --- Departments: one region per department ---------------------------------
# region values used throughout the lab: AMER, EMEA, APAC
departments = [
    {"dept_id": 1, "dept_name": "Engineering", "region": "AMER", "cost_center": "CC-1000"},
    {"dept_id": 2, "dept_name": "Sales",       "region": "EMEA", "cost_center": "CC-2000"},
    {"dept_id": 3, "dept_name": "Marketing",   "region": "AMER", "cost_center": "CC-3000"},
    {"dept_id": 4, "dept_name": "Finance",     "region": "EMEA", "cost_center": "CC-4000"},
    {"dept_id": 5, "dept_name": "Operations",  "region": "APAC", "cost_center": "CC-5000"},
    {"dept_id": 6, "dept_name": "People",      "region": "APAC", "cost_center": "CC-6000"},
]
dept_region = {d["dept_id"]: d["region"] for d in departments}
dept_name = {d["dept_id"]: d["dept_name"] for d in departments}

# Currency follows region.
region_currency = {"AMER": "USD", "EMEA": "EUR", "APAC": "SGD"}

# Title -> (min_salary, max_salary) band; first title in a dept is the manager.
titles = [
    ("Manager",            150000, 190000),
    ("Senior Specialist",  115000, 145000),
    ("Specialist",          85000, 115000),
    ("Associate",           65000,  90000),
    ("Coordinator",         55000,  75000),
]

first_names = [
    "Ana", "Bo", "Cyrus", "Dara", "Eli", "Farah", "Gabe", "Hana", "Ivan", "Jia",
    "Kai", "Lena", "Mateo", "Nadia", "Omar", "Priya", "Quinn", "Rosa", "Sven", "Tara",
    "Umar", "Vera", "Wes", "Xiu", "Yara", "Zane", "Ada", "Ben", "Cleo", "Dot",
    "Esme", "Finn", "Gita", "Hugo", "Iris", "Jonas", "Kira", "Liam", "Maya", "Noor",
    "Otis", "Pia",
]
last_names = [
    "Reyes", "Li", "Khan", "Park", "Cohen", "Nasser", "Ortega", "Sato", "Petrov", "Chen",
    "Mwangi", "Bauer", "Silva", "Haddad", "Ali", "Patel", "Doyle", "Marin", "Berg", "Costa",
    "Farouk", "Ivanova", "Brooks", "Wang", "Saab", "Klein", "Lopez", "Novak", "Greco", "Day",
    "Romano", "Frost", "Gupta", "Weber", "Stone", "Eriksen", "Volkov", "Walsh", "Mehta", "Noor",
    "Tan", "Pham",
]

employees = []
compensation = []
emp_id = 1001
# manager_id of the first employee in each department (assigned as we build)
dept_manager_id = {}

# 6 or 7 employees per department -> ~40 total
for d in departments:
    n_in_dept = random.choice([6, 7])
    for i in range(n_in_dept):
        # First employee of the department is the Manager (no manager above them here).
        if i == 0:
            title, lo, hi = titles[0]
            dept_manager_id[d["dept_id"]] = emp_id
            manager_id = None
        else:
            title, lo, hi = random.choice(titles[1:])
            manager_id = dept_manager_id[d["dept_id"]]

        fn = first_names[(emp_id - 1001) % len(first_names)]
        ln = last_names[(emp_id - 1001) % len(last_names)]
        region = d["region"]
        email = f"{fn.lower()}.{ln.lower()}@northwind.example"
        ssn = f"{random.randint(100, 899):03d}-{random.randint(10, 99):02d}-{random.randint(1000, 9999):04d}"
        dob = date(1965, 1, 1) + timedelta(days=random.randint(0, 365 * 35))
        hire_date = date(2015, 1, 1) + timedelta(days=random.randint(0, 365 * 9))

        employees.append({
            "employee_id": emp_id,
            "full_name": f"{fn} {ln}",
            "email": email,
            "ssn": ssn,
            "dob": dob,
            "dept_id": d["dept_id"],
            "region": region,
            "manager_id": manager_id,
            "job_title": title,
            "hire_date": hire_date,
        })

        base_salary = random.randint(lo, hi)
        bonus = int(base_salary * random.uniform(0.08, 0.22))
        stock_grant = random.choice([0, 0, 10000, 25000, 50000])
        compensation.append({
            "employee_id": emp_id,
            "base_salary": base_salary,
            "bonus": bonus,
            "stock_grant": stock_grant,
            "currency": region_currency[region],
        })
        emp_id += 1

print(f"Generated {len(departments)} departments, {len(employees)} employees, {len(compensation)} compensation rows.")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Write the tables (with table & column comments)

# COMMAND ----------

# --- departments -------------------------------------------------------------
dept_schema = StructType([
    StructField("dept_id", IntegerType()),
    StructField("dept_name", StringType()),
    StructField("region", StringType()),
    StructField("cost_center", StringType()),
])
spark.createDataFrame(departments, schema=dept_schema).write.format("delta") \
    .mode("overwrite").option("overwriteSchema", "true") \
    .saveAsTable(f"{catalog}.{schema}.departments")
spark.sql(f"COMMENT ON TABLE {catalog}.{schema}.departments IS 'Department reference data. Each department is anchored to a single region.'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.departments ALTER COLUMN dept_id COMMENT 'Department identifier'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.departments ALTER COLUMN dept_name COMMENT 'Department name'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.departments ALTER COLUMN region COMMENT 'Geographic region: AMER, EMEA, or APAC'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.departments ALTER COLUMN cost_center COMMENT 'Finance cost center code'")
print("departments written.")

# COMMAND ----------

# --- employees ---------------------------------------------------------------
emp_schema = StructType([
    StructField("employee_id", IntegerType()),
    StructField("full_name", StringType()),
    StructField("email", StringType()),
    StructField("ssn", StringType()),
    StructField("dob", DateType()),
    StructField("dept_id", IntegerType()),
    StructField("region", StringType()),
    StructField("manager_id", IntegerType()),
    StructField("job_title", StringType()),
    StructField("hire_date", DateType()),
])
spark.createDataFrame(employees, schema=emp_schema).write.format("delta") \
    .mode("overwrite").option("overwriteSchema", "true") \
    .saveAsTable(f"{catalog}.{schema}.employees")
spark.sql(f"COMMENT ON TABLE {catalog}.{schema}.employees IS 'Employee directory. Contains PII (ssn, dob, email) and a region column used for row-level security in the lab.'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.employees ALTER COLUMN employee_id COMMENT 'Unique employee identifier'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.employees ALTER COLUMN full_name COMMENT 'Employee full name'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.employees ALTER COLUMN email COMMENT 'Work email address (PII)'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.employees ALTER COLUMN ssn COMMENT 'Social Security Number (sensitive PII) — masked in the lab'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.employees ALTER COLUMN dob COMMENT 'Date of birth (PII)'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.employees ALTER COLUMN dept_id COMMENT 'Department the employee belongs to (joins departments.dept_id)'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.employees ALTER COLUMN region COMMENT 'Geographic region: AMER, EMEA, or APAC — used for row filtering'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.employees ALTER COLUMN manager_id COMMENT 'employee_id of this person''s manager (NULL for department heads)'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.employees ALTER COLUMN job_title COMMENT 'Job title'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.employees ALTER COLUMN hire_date COMMENT 'Date the employee was hired'")
print("employees written.")

# COMMAND ----------

# --- compensation ------------------------------------------------------------
comp_schema = StructType([
    StructField("employee_id", IntegerType()),
    StructField("base_salary", IntegerType()),
    StructField("bonus", IntegerType()),
    StructField("stock_grant", IntegerType()),
    StructField("currency", StringType()),
])
spark.createDataFrame(compensation, schema=comp_schema).write.format("delta") \
    .mode("overwrite").option("overwriteSchema", "true") \
    .saveAsTable(f"{catalog}.{schema}.compensation")
spark.sql(f"COMMENT ON TABLE {catalog}.{schema}.compensation IS 'Compensation per employee — highly sensitive. base_salary and bonus are masked in the lab.'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.compensation ALTER COLUMN employee_id COMMENT 'Employee identifier (joins employees.employee_id)'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.compensation ALTER COLUMN base_salary COMMENT 'Annual base salary (sensitive) — masked in the lab'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.compensation ALTER COLUMN bonus COMMENT 'Annual bonus (sensitive) — masked in the lab'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.compensation ALTER COLUMN stock_grant COMMENT 'Equity grant value'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.compensation ALTER COLUMN currency COMMENT 'Currency code, follows region (USD/EUR/SGD)'")
print("compensation written.")

# COMMAND ----------

# --- analyst_access (entitlements control table — starts EMPTY) --------------
# The lab inserts/updates rows here to grant the current user access, so it must
# start empty (every learner begins locked out of PII and all regions).
access_schema = StructType([
    StructField("user_email", StringType()),
    StructField("allowed_region", StringType()),
    StructField("can_view_pii", BooleanType()),
])
spark.createDataFrame([], schema=access_schema).write.format("delta") \
    .mode("overwrite").option("overwriteSchema", "true") \
    .saveAsTable(f"{catalog}.{schema}.analyst_access")
spark.sql(f"COMMENT ON TABLE {catalog}.{schema}.analyst_access IS 'Entitlements control table. Row filters and column masks read this table keyed on current_user(). Starts empty; the lab adds a row to grant access.'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.analyst_access ALTER COLUMN user_email COMMENT 'User this entitlement applies to (match against current_user())'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.analyst_access ALTER COLUMN allowed_region COMMENT 'Region the user may see (AMER/EMEA/APAC), or ALL for every region'")
spark.sql(f"ALTER TABLE {catalog}.{schema}.analyst_access ALTER COLUMN can_view_pii COMMENT 'TRUE if the user may see unmasked PII (ssn, salary, ...)'")
print("analyst_access written (empty).")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Done
# MAGIC All four tables are created. Return to the lab notebook and continue.

# COMMAND ----------

print("Setup complete:")
for t in ["departments", "employees", "compensation", "analyst_access"]:
    n = spark.table(f"{catalog}.{schema}.{t}").count()
    print(f"  {catalog}.{schema}.{t}: {n} rows")
