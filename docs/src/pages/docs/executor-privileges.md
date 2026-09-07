---
title: Executor privileges
description: The exact PostgreSQL privileges the role running pgroles needs, and why superuser is not one of them.
---

pgroles does not require superuser. It needs `CREATEROLE` plus a handful of scoped grants, and the exact set depends on whether the roles you manage are new or already exist. {% .lead %}

---

## What pgroles actually needs

The table targets PostgreSQL 16. `CREATEROLE` permits ordinary role creation;
existing-role administration and object operations need separate authority.
Protected roles and managed-provider restrictions can impose additional limits.

| pgroles operation | Requires |
|---|---|
| `CREATE ROLE` | `CREATEROLE` attribute |
| `ALTER ROLE` / `COMMENT ON ROLE` / passwords / `ALTER ROLE ... SET` config | `CREATEROLE` + `ADMIN OPTION` on the target role (automatic for roles the executor created itself) |
| `GRANT`/`REVOKE` role memberships | `ADMIN OPTION` on the granted (group) role — automatic for roles the executor created. On PostgreSQL 16+ pgroles revokes each edge `GRANTED BY` its recorded grantor, which additionally requires the privileges of that grantor (membership with inheritance; superusers qualify everywhere) — the plan preflight reports any grantor the executor lacks |
| `GRANT`/`REVOKE` predefined (`pg_*`) role memberships | `ADMIN OPTION` on the predefined role — never automatic: a superuser must run `GRANT pg_read_all_data TO executor WITH ADMIN OPTION` (or the executor must be superuser). The plan preflight warns and apply blocks when this is missing |
| `DROP ROLE` | `CREATEROLE` + `ADMIN OPTION` on the role |
| `CREATE SCHEMA` | `CREATE` on the database; assigning another owner also requires the ability to `SET ROLE` to that owner |
| `ALTER SCHEMA ... OWNER TO` | ownership of the schema, ability to `SET ROLE` to the new owner, and `CREATE` on the database for the new owner |
| `GRANT`/`REVOKE` on tables/sequences/functions | grant authority on every affected object: ownership or the relevant privilege with grant option. Grantor-attributed revokes run as the recorded grantor of each ACL entry (`SET ROLE`), which requires membership in that grantor with the `SET` option (superusers qualify everywhere) — the plan preflight reports any grantor the executor cannot become |
| `ALTER DEFAULT PRIVILEGES FOR ROLE x` | effective privileges of role `x` (self or an inheriting membership path) — `ADMIN OPTION` or the ability to `SET ROLE` alone is **not** enough for pgroles' emitted statement |
| `REASSIGN OWNED BY a TO b` (retirements) | membership (privileges) of **both** `a` and `b`. The executor has `ADMIN OPTION` on roles it created, so it can `GRANT a TO executor` itself first — pgroles does not do this automatically |
| `DROP OWNED BY a` (retirements) | membership (privileges) of `a` |
| `terminate_sessions` (retirements) | membership in `pg_signal_backend` (cannot terminate superuser sessions) |
| inspection (`diff`/`plan`/`generate`) | none beyond `CONNECT` — `pg_roles`, `pg_shdescription`, and ACL columns are readable by any role |

See PostgreSQL's [CREATE SCHEMA](https://www.postgresql.org/docs/16/sql-createschema.html),
[ALTER SCHEMA](https://www.postgresql.org/docs/16/sql-alterschema.html), and
[GRANT](https://www.postgresql.org/docs/16/sql-grant.html) references for these distinctions.

## Greenfield and brownfield prerequisites

PostgreSQL 16 changed `CREATEROLE` semantics: a role with `CREATEROLE` automatically receives `ADMIN OPTION` on any role it creates. That collapses most of the table above into a single attribute for a **greenfield** executor — one that creates every role it will later alter, grant, or drop. A fresh executor needs only:

- `CREATEROLE`
- `CREATE` on the target database (to create schemas)
- ability to `SET ROLE` to any other role assigned as a schema owner
- inherited privileges of each default-privilege creator role (which need not be the schema owner)

Automatic `ADMIN OPTION` does not itself provide `INHERIT` or `SET` access. A
non-superuser cannot create a new owner role and run `ALTER DEFAULT PRIVILEGES
FOR ROLE owner` in the same pgroles transaction. For owner-bound defaults,
pre-create the owner and grant the executor membership, bootstrap in two stages,
or use a superuser for the atomic first apply. Creating a schema owned by a new
role likewise needs a usable `SET ROLE` path before the schema statement.
Declaring a membership in the same manifest is insufficient: pgroles adds
memberships after schema changes and default-privilege grants.

The friction also shows up in **brownfield** adoption. `CREATEROLE` does not retroactively grant `ADMIN OPTION` on roles that already existed before the executor was created. For every pre-existing role pgroles needs to alter, drop, or manage memberships on, a superuser or existing admin must explicitly grant the executor admin rights:

```sql
GRANT adopted_role TO executor WITH ADMIN TRUE;
```

Without this, pgroles can still create new roles and manage grants on objects the executor owns, but altering or dropping the adopted role, or changing its memberships, fails with a permission error. See the [staged adoption guide](/docs/adoption) for the broader brownfield rollout sequence.

## Bootstrap SQL

Run once, by a superuser or an existing admin (RDS `rds_superuser` member, Cloud SQL `cloudsqlsuperuser` member, AlloyDB `alloydbsuperuser` member, etc.), before pointing pgroles at a database for the first time:

```sql
-- Run once as superuser / cloud admin user.

-- 1. The role pgroles connects as.
CREATE ROLE pgroles_executor WITH LOGIN PASSWORD '...' CREATEROLE;

-- 2. Let it create schemas in the target database.
GRANT CREATE ON DATABASE mydb TO pgroles_executor;

-- 3. For an existing role used as both schema owner and default-privilege
--    creator, give the executor the required inheritance and SET paths.
GRANT app_owner TO pgroles_executor WITH INHERIT TRUE, SET TRUE;

-- 4. Brownfield only: for each pre-existing role pgroles must alter,
--    drop, or manage memberships on, grant explicit admin rights.
GRANT some_preexisting_role TO pgroles_executor WITH ADMIN TRUE;
```

Steps 1–2 suffice only when the plan needs no additional owner authority.
Step 3 gives the executor an inheritance path to the owner for default
privileges and a SET path for schema assignment; grant only the options
the plan needs. Repeat for each relevant owner. For owners created by the policy,
use the staged bootstrap above. Step 4 covers pre-existing roles requiring
administration.

## Cloud providers

None of RDS, Cloud SQL, AlloyDB, or Azure Database for PostgreSQL expose true superuser. The bootstrap above is run by the provider's admin user instead — `rds_superuser` member on RDS/Aurora, `cloudsqlsuperuser` member on Cloud SQL, `alloydbsuperuser` member on AlloyDB. See the [AWS RDS & Aurora](/docs/aws-rds) and [Google Cloud SQL](/docs/google-cloud-sql) pages for the specific attributes those admin roles lack and how pgroles adapts around them.

For Cloud SQL IAM authentication, the operator can authenticate as a low-privilege IAM identity and `SET ROLE` to a privileged parent role on every connection via `connection.params.setRole` — see the [operator connection docs](/docs/operator-connections#gke-workload-identity-for-cloud-sql-iam) for the full pattern.

## The superuser shortcut

Running pgroles as superuser works and satisfies every row in the table above automatically — there is nothing to grant, adopt, or troubleshoot. The cost is the one every DBA already weighs: the connection can do anything to the cluster, not just what pgroles' manifest describes. Scoped `CREATEROLE` privileges are the recommended default; superuser is a pragmatic fallback for small or throwaway environments.
