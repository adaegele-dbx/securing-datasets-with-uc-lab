# Securing Datasets with Unity Catalog

A ~45-minute hands-on lab for learning how to **secure data in Unity Catalog** — from
catalog/schema/table permissions through row- and column-level security to **attribute-based
access control (ABAC)** — using a small HR dataset.

## What You'll Build

By the end of this lab you will have:

- Created a small **HR dataset** in Unity Catalog — `departments`, `employees`, `compensation`,
  and an `analyst_access` entitlements table
- Used **`GRANT` / `REVOKE`** and inspected privileges and ownership
- Applied **column masks** to hide SSNs and salaries, and watched them flip based on an
  entitlement
- Applied a **row filter** so a user only sees employees in their region
- Scaled protection with **ABAC** — a single governed-tag-driven policy that masks every tagged
  column across the schema, including tables created later

The scenario throughout: you're securing the HR data of a fictional company that operates across
three regions (AMER, EMEA, APAC).

## Prerequisites

- A **Databricks Free Edition** workspace (Unity Catalog is on by default)
- A **SQL warehouse running** (Free Edition's 2X-Small Serverless Starter is enough)
- You are a **workspace admin** (the default for your own Free Edition workspace) — needed to
  create a governed tag in Part 4

> ⚠️ **Free Edition notes**
> - You're the only user and have no account console, so you can't create groups/users. Parts 2–3
>   make access control visible instead via a small **control table** you toggle. Each fine-grained
>   section also shows the **production, group-based** pattern you'd use at work.
> - Your catalog is `workspace`; the lab uses the schema `workspace.uc_security_lab`.
> - Free Edition has a **daily compute quota**. The lab is lightweight and ends with a cleanup
>   cell. If compute stops responding, you may have hit the quota — pick up after it resets.
> - If your SQL warehouse fails to start on the first try, that's usually transient — retry.

## Getting Started

### 1. Clone this repo as a Git Folder in your Databricks workspace

1. In your Databricks workspace, go to **Workspace** in the left sidebar
2. Click **Create** → **Git folder**
3. Paste this repository's URL
4. Click **Create Git folder**

### 2. Open the lab notebook

Navigate to `lab_notebook.py` in the cloned folder and open it. All lab instructions are inside.

---

## Repository Structure

```
securing-datasets-with-uc/
├── README.md                  # This file
├── lab_notebook.py            # Central guided notebook — START HERE
│
├── data/
│   └── setup_tables.py        # Generates the 4 HR tables
│
└── solutions/                 # Reference material (the notebook is self-contained)
    ├── README.md
    ├── reference_sql.md        # Every SQL statement used in the lab
    └── abac_reference.md       # ABAC deep-dive: governed tags + production patterns
```

## Lab Outline

| Part | Topic | Time |
|------|-------|------|
| **Setup** | Generate the HR data and verify it | ~3 min |
| **Part 1** | The UC security model — hierarchy, ownership, `GRANT`/`REVOKE`, least privilege | ~7 min |
| **Part 2** | Column-level security — mask SSNs and salaries, toggle access live | ~9 min |
| **Part 3** | Row-level security — restrict employees by region, widen access live | ~9 min |
| **Part 4** | Scale with ABAC — governed tag + one policy, "tag once, protect everywhere" | ~10 min |
| **Wrap-up** | Recap, what to try at work, and cleanup | ~3 min |

**Total: ~41 minutes** of content (the session is budgeted at ~45 to allow for pauses and questions).

## Data Model

```
departments ──┐
              │  (dept_id, region)
employees ────┼──> has PII: ssn, dob, email   + region (AMER/EMEA/APAC)
              │
compensation ─┘  (base_salary, bonus — sensitive)

analyst_access      control table the lab toggles to grant the current user access
```
