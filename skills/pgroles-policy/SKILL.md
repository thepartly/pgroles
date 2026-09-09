---
name: pgroles-policy
description: Author, review, migrate, and troubleshoot pgroles YAML policies for PostgreSQL roles, profiles, grants, memberships, schema ownership, default privileges, external identities, and role retirement. Use when changing a pgroles manifest, adopting an existing database, or investigating an unexpected SQL plan.
license: MIT
compatibility: Requires a pgroles CLI compatible with the manifest version; database diff and apply workflows require PostgreSQL access.
---

# Pgroles Policy

Use the pgroles version installed by the project. Read its matching documentation
or checked-out source before using fields introduced in newer releases.

## Choose The Source Of Truth

Use pgroles for steady-state roles, memberships, grants, schema ownership, and
default privileges. Keep provider identities and cloud login plumbing in the
cloud/IaC system. Use migrations for ordered object changes that desired-state
reconciliation cannot infer, such as reassigning existing object ownership or
creating `SECURITY DEFINER` functions.

Do not manage the same role attribute, membership, or grant in two systems after
the migration window ends.

## Authoring Workflow

1. Identify the database, PostgreSQL version, executor identity, and installed
   pgroles version.
2. Inspect nearby manifests and the actual database. For brownfield adoption,
   start with `pgroles generate`; use `--suggest-profiles` only after reviewing
   that the refactoring preserves the exact expanded state.
3. Define reusable profiles by access shape, then bind them to schemas. Profiles
   create concrete roles using `role_pattern`: schema override, then policy
   default, then `{schema}-{profile}`. Bundles resolve schema → fragment →
   `shared.role_pattern` → built-in default. Every declared pattern requires
   `{profile}`. Review naming changes as role changes, not cosmetic edits.
4. Declare managed roles and memberships explicitly. Use `external: true` for a
   role whose lifecycle belongs to a provider or another system.
5. Model current and future objects separately: ordinary grants cover existing
   objects; default privileges cover only future objects created by the named
   owner.
6. Validate, inspect the expanded graph, and review the SQL diff before apply.

Useful commands:

```bash
pgroles validate -f pgroles.yaml
pgroles graph desired -f pgroles.yaml
pgroles diff -f pgroles.yaml --database-url "$DATABASE_URL"
```

Use
`pgroles diff --format markdown` for a review artifact and retain stderr
warnings. Bundle changes are attributed to their owning source document. The
redacted report fingerprint identifies that report, not database state or an
execution approval; it excludes password values and database identity. Record
the target environment alongside it. Markdown records declared
password changes without reading their environment variables. Review the SQL and effective
privileges as well as the conservative change priorities.

Never print database URLs, passwords, or rendered Secrets in logs.

## Reconciliation Modes

The CLI `--mode` and operator `spec.reconciliation_mode` select which computed
changes remain in the plan:

- `additive`: creates and additions only. It filters revokes, membership
  removals, existing schema-owner transfers, existing-role rewrites, and role
  retirement. It also omits role comments. Configured password updates are a
  deliberate exception. Because it never revokes, it ignores every
  `ensure: absent` rule with a warning instead of failing the run.
- `adopt`: authoritative convergence except role drops and their retirement
  steps. Revokes and membership removals still occur.
- `authoritative`: retains every change computed within pgroles' managed
  inspection scope.

Authoritative mode is scoped. It does not inventory and delete every role or
schema in PostgreSQL. Inspection follows managed roles, referenced schemas,
managed grantees, and explicitly retired roles.

For a brownfield database, use this progression:

1. generate and review the current state
2. diff in `additive` mode
3. apply additive changes and test effective privileges
4. review an `adopt` or `authoritative` diff, especially every revocation
5. switch modes only when the manifest covers the intended managed state

An additive no-op does not prove that existing role attributes or undeclared
access match the manifest.

## External Roles

`external: true` is a lifecycle filter, not provisioning or validation. pgroles
will not create, alter, drop, or password-manage that role. It may still grant
privileges to it, use it as a schema/default privilege owner, or add it as a
member of a managed group.

Memberships granted **from** an external role follow declared intent: members
listed in a `memberships` stanza converge (e.g. `GRANT rds_iam TO app_user`
can be policy); undeclared live members are left untouched; a stanza-level
`exclusive: true` asserts the member list is complete and plans a REVOKE for
anyone else.

The external role must already exist whenever retained SQL references it. Ensure
the provider or IaC rollout completes before pgroles apply.

## Membership SET Option

pgroles manages membership `inherit` and `admin`, but not `SET`.
Changing those options can revoke and recreate an edge with PostgreSQL's
default `SET TRUE`. Do not use `SET FALSE` as a security boundary on a
pgroles-managed membership; a clean diff does not verify its SET option.

## Predefined (pg_*) Roles

PostgreSQL's predefined roles (`pg_read_all_data`, `pg_monitor`, ...) may be
named directly as a membership grantor with no `roles:` entry; declaring one
under `roles:` requires `external: true`, and its lifecycle is never managed.
Declared members converge; `exclusive: true` revokes undeclared members —
except members that are themselves `pg_*` roles, so PostgreSQL's built-in
hierarchy is never modified. Like every absence assertion, `exclusive`
revocations are skipped (with a warning) under additive reconciliation —
use adopt or authoritative mode to enforce them. Exclusive revocation does
apply to provider management roles such as `rds_superuser`, so account for
every member the platform needs before asserting exclusivity. Granting a predefined role requires the executor
to hold ADMIN OPTION on it (PG16+; CREATEROLE alone is not sufficient) — the
preflight warns at plan and blocks at apply, and also reports a referenced
predefined role the server does not have, with the version that introduced it.
`pgroles inspect` lists all `pg_*` memberships informationally; `pgroles
generate` exports them.

For brownfield roles whose full grant surface is not yet declared,
`preserve_undeclared_grants: true` preserves undeclared object grants through
convergence; explicit `ensure: absent` assertions still revoke. The flag does
not preserve default privileges for future objects or change membership
reconciliation, role attributes, or other convergence behavior. Review those
changes separately before applying an adoption plan. Remove the flag once the
manifest declares the role's full object-grant surface. Adopt mode refuses to
transfer schema ownership away from the live owner unless apply passes
`--allow-schema-owner-transfers`.

## Ownership And ACLs

Schema ownership is modeled specially: pgroles converges the declared owner and
ensures that owner has effective `CREATE` and `USAGE` on the schema.

Table, sequence, function, and type ownership is not modeled. pgroles preserves
existing owner-grantee ACL entries and omits them from `generate`. This is a
pgroles reconciliation choice: PostgreSQL permits owners to revoke their own
ordinary privileges. Declared owner grants produce no SQL when already held;
missing declared privileges can still be granted.

PostgreSQL materializes an object's ACL on the first grant or revoke, including
a revoke of implicit PUBLIC access. Inspection protects owner entries, so
materialization alone should not require an extra owner-repair pass.

Ownership rights such as altering or dropping an object, and the owner's
implicit grant options, remain PostgreSQL behavior outside the object ACL model.

Database grants must set `object.name` explicitly, and that name must match
`current_database()` for the connection used by diff or apply. pgroles never
inspects one database while rendering ACL changes for another.

Default privileges are per creating role, scope, and object type, where a scope
is one schema or the owner-wide global layer. A default owner declaration does
not retroactively grant existing objects and does not cover objects created by
another role.

When a non-superuser plan creates an owner and grants its defaults before membership additions, PostgreSQL 16+ needs `CREATEROLE` and `createrole_self_grant = 'inherit'` (or `'set, inherit'`) on the connection for immediate inherited authority. `'set'` alone is insufficient. Configure the authenticated login/session: `SET ROLE` does not load target-role settings. pgroles reads the setting without enabling it. Later default revokes can instead use inherited authority established by the plan's membership additions; removals and inheritance downgrades must not leave them without authority. A planned grant requires a surviving usable administrator, not just membership or SET access to one. Preflight conservatively excludes administrator paths established by other additions; stage those bootstrap steps separately.

Schema defaults add to the global layer and cannot subtract from it. Removing
PostgreSQL's built-in `PUBLIC EXECUTE` on functions therefore needs a global
rule with `ensure: absent`; a schema-scoped one only removes a schema-scoped
re-grant. Global rules reach every schema in the database, so only the bundle
document that owns the owner role may declare them.

## Privilege Review

Review effective and transitive privileges, not role names alone.

- Sequence `USAGE` permits `nextval`; grant `SELECT` alone when advancement is
  not required.
- `REFERENCES` is needed by the role that creates a foreign key, not by runtime
  writers solely for referential-integrity enforcement.
- Treat `TRIGGER`, `UPDATE`, `DELETE`, `TRUNCATE`, routine `EXECUTE`, and
  schema-wide wildcards as security-sensitive.
- Owner, definer, and other group roles may carry much broader inherited access
  than the new membership suggests.
- Column-level grants are outside desired-state reconciliation. Read inspection
  warnings and review them separately.
- pgroles does not model `MAINTAIN` (introduced in PostgreSQL 17). Inspection
  omits it and manifests cannot declare it; verify maintenance access separately
  even when the diff is clean.
- PUBLIC is reconciled only where a rule names it. A privilege PUBLIC holds that
  no rule mentions is left alone in every mode, so deleting a `present` PUBLIC
  rule does not revoke anything — switch it to `ensure: absent` instead.

Wildcard revocations preserve concrete grantor attribution. Review per-object
changes and ensure the executor can act as every recorded grantor. Do not
replace those statements with a broad plain REVOKE.

## Safe Removal

Removing a role from `roles:` is not sufficient evidence that dropping it is
safe. Use an explicit retirement so pgroles can inspect dependencies and express
the intended cleanup. Review active-session termination, ownership reassignment,
`DROP OWNED`, and the final role drop before applying authoritative mode.

Deleting a Kubernetes `PostgresPolicy` stops management; it does not undo the
database state.

## Validation

Before completing a change:

1. run `pgroles validate`
2. render bundles before reviewing their effective policy
3. inspect `pgroles graph` and the complete SQL diff
4. confirm external roles and referenced undeclared schemas already exist
5. verify executor authority for each SQL phase: `ADMIN` manages role
   memberships, `INHERIT` makes owner privileges available, and `SET` permits
   switching roles. Default-privilege grants precede membership additions, so a
   membership declared in the same plan cannot bootstrap those grants. Schema
   assignment needs a usable SET path; transferring an existing schema also
   requires database `CREATE` for its new owner
6. apply first in a non-production environment when possible
7. run positive and negative SQL checks as the actual login roles
8. run a second diff and require no changes within the selected mode

Read the matching-version documentation for manifest syntax, staged adoption,
executor privileges, managed-provider limitations, and tooling details.
