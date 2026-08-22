---
title: CLI commands
description: Reference for all pgroles CLI commands and options.
---

The `pgroles` CLI provides nine commands for managing PostgreSQL role policies. {% .lead %}

---

## Global options

Commands that operate on desired state accept either:

- `-f` / `--file` for a single manifest file
- `--bundle` for a composed bundle root file

If omitted, manifest-based commands default to `pgroles.yaml` in the current directory.

Commands that connect to a database accept `--database-url` or read from the `DATABASE_URL` environment variable.

## validate

Parse and validate a manifest file or composed bundle without connecting to a database.

```shell
pgroles validate
pgroles validate -f path/to/policy.yaml
pgroles validate --bundle path/to/pgroles.bundle.yaml
```

Reports the number of roles, grants, default privileges, and memberships after profile expansion.

## diff / plan

Show the SQL changes needed to converge the database to the manifest or bundle. `plan` is an alias for `diff`.

```shell
pgroles diff --database-url postgres://localhost/mydb
pgroles plan --database-url postgres://localhost/mydb
pgroles diff --bundle path/to/pgroles.bundle.yaml --database-url postgres://localhost/mydb
```

### Options

| Flag | Description |
|---|---|
| `-f`, `--file` | Manifest file path (default: `pgroles.yaml`) |
| `--bundle` | Bundle root file path |
| `--database-url` | PostgreSQL connection string (or `DATABASE_URL` env) |
| `--format` | Output format: `sql` (default), `summary`, or `json` |
| `--mode` | Reconciliation mode: `authoritative` (default), `additive`, or `adopt` |
| `--exit-code` | Exit with code 2 when drift is detected (default: `true`) |
| `--no-exit-code` | Always exit 0, even when drift is detected |

The `sql` format prints the full SQL script. The `summary` format shows counts of each change type.

For single-manifest mode, the `json` format outputs the change list as a JSON array. For bundle mode, the `json` format returns a typed object with:

- `schema_version`
- `managed_scope`
- per-change ownership annotations (`document` plus managed key details)

### CI drift detection

By default, `diff` exits with code **2** when structural changes are detected and **0** when the database is in sync. Password-only changes are excluded from drift detection because PostgreSQL does not expose password hashes for comparison — they always appear in the plan but will not trigger a non-zero exit. Command failures still use a normal error exit code. This makes it suitable for CI gates and SRE runbooks:

```shell
if pgroles diff --database-url postgres://localhost/mydb; then
  echo "database is in sync"
else
  case $? in
    2) echo "drift detected" ;;
    *) echo "pgroles failed" >&2; exit 1 ;;
  esac
fi
```

Disable this with `--no-exit-code` if you only want the output without a non-zero exit on drift.

If the plan includes role drops, `diff` also runs a live safety check and splits the result into:

- cleanup warnings that the planned retirement steps are expected to handle
- residual blockers that still prevent a safe apply

For intentional removals, declare a `retirements` block in the manifest so pgroles can inspect the soon-to-be-dropped role even though it is absent from the desired role list:

```yaml
roles:
  - name: app_owner

retirements:
  - role: legacy_app
    reassign_owned_to: app_owner
    drop_owned: true
    terminate_sessions: true
```

That causes the generated plan to insert session termination, `REASSIGN OWNED BY`, `DROP OWNED BY`, and then `DROP ROLE`.

`REASSIGN OWNED` and `DROP OWNED` only clean the current database plus shared objects. If the safety report mentions other databases, repeat the cleanup there before expecting the final drop to succeed.

## apply

Apply changes to bring the database in sync with the manifest or bundle.

```shell
pgroles apply --database-url postgres://localhost/mydb
pgroles apply --database-url postgres://localhost/mydb --dry-run
pgroles apply --bundle path/to/pgroles.bundle.yaml --database-url postgres://localhost/mydb
```

### Options

| Flag | Description |
|---|---|
| `-f`, `--file` | Manifest file path (default: `pgroles.yaml`) |
| `--bundle` | Bundle root file path |
| `--database-url` | PostgreSQL connection string (or `DATABASE_URL` env) |
| `--mode` | Reconciliation mode: `authoritative` (default), `additive`, or `adopt` |
| `--dry-run` | Print the SQL without executing it |

`apply` executes the plan inside a single database transaction. Individual changes may still render to multiple SQL statements internally, but the whole apply either commits or rolls back together.

Before executing changes, `apply` detects the connecting role's privilege level — true superuser, cloud provider superuser (for the explicitly supported providers), or regular user — and warns about any planned changes that exceed the detected privileges (for example setting `SUPERUSER` or `BYPASSRLS` through a managed-service admin role).

Provider-aware warning logic recognizes `rds_superuser`, `cloudsqlsuperuser`, `alloydbsuperuser`, and `azure_pg_admin`. Other PostgreSQL-compatible managed services, including Supabase and PlanetScale PostgreSQL, may still work, but privilege warnings are generic rather than provider-specific.

### Insufficient privileges

There are two common cases:

1. pgroles can predict the limitation up front
2. PostgreSQL rejects a statement during inspect or apply

For explicitly recognized managed-service admin roles, pgroles warns before apply when the plan requests unsupported attributes such as `SUPERUSER`, `REPLICATION`, or `BYPASSRLS`.

If PostgreSQL still rejects a query or DDL statement, `apply` fails, the transaction is rolled back, and pgroles exits non-zero. No partial changes from that run are committed.

Typical outcomes:

- `diff` may still succeed if the connecting role can inspect the required catalog state
- `diff` fails non-zero if the connecting role cannot inspect the database state needed for planning
- `apply` fails non-zero if the connecting role cannot execute one of the planned statements

Example of an apply-time failure:

```text
Warning: Cannot create role "app_admin" with SUPERUSER — cloud superuser lacks this privilege
Error: failed to execute: CREATE ROLE "app_admin" LOGIN SUPERUSER ...
Caused by:
    error returned from database: permission denied to create role
```

{% callout type="note" title="Transactional apply" %}
If any statement fails during `apply`, the transaction is rolled back and earlier changes from that run are not committed.
{% /callout %}

{% callout type="warning" title="Residual blockers stop apply" %}
If pgroles still sees unhandled role-drop hazards after accounting for the declared retirement steps, `apply` refuses the change by default instead of attempting a `DROP ROLE`.
{% /callout %}

## inspect

Show the current database state for roles and privileges.

```shell
pgroles inspect --database-url postgres://localhost/mydb
pgroles inspect -f pgroles.yaml --database-url postgres://localhost/mydb
pgroles inspect --bundle path/to/pgroles.bundle.yaml --database-url postgres://localhost/mydb
```

Without `-f` or `--bundle`, `inspect` shows all non-system roles and visible privileges. With `-f`, it scopes inspection to the manifest's managed roles and referenced schemas. With `--bundle`, it scopes inspection to the composed managed ownership boundary and prints a managed-scope summary before the role graph summary.

## generate

Generate a YAML manifest from the current database state. This is the primary tool for brownfield adoption — it introspects all non-system roles, their attributes and config defaults, grants, default privileges, and memberships, then emits a flat manifest (no profiles) that faithfully reproduces the current state.

```shell
pgroles generate --database-url postgres://localhost/mydb
pgroles generate --database-url postgres://localhost/mydb > policy.yaml
pgroles generate --database-url postgres://localhost/mydb --output policy.yaml
```

The generated manifest uses no profiles — all roles, grants, default privileges, and memberships are emitted as top-level entries. When applied back to the same database, it should produce zero diff.

### Options

| Flag | Description |
|---|---|
| `--database-url` | PostgreSQL connection string (or `DATABASE_URL` env) |
| `-o`, `--output` | Write the generated manifest to a file instead of stdout |
| `--suggest-profiles` | Refactor the flat output into reusable [profiles](/docs/profiles) where roles share the same schema-relative privilege shape across multiple schemas |
| `--suggest-min-schemas N` | Minimum schemas a candidate cluster must span before it becomes a profile (default `2`). Only meaningful with `--suggest-profiles` |

### Refining with `--suggest-profiles`

The flat output of `generate` faithfully reproduces the database state but is repetitive — every reader/editor role enumerates its grants per schema. `--suggest-profiles` extracts reusable [profiles](/docs/profiles) automatically, deterministically, and round-trip-safely:

```shell
pgroles generate --database-url $DATABASE_URL --suggest-profiles > pgroles.yaml
```

When run, the suggester:

- Buckets each role's grants by schema and computes a *schema-relative signature* — the grants and default privileges with the schema replaced by a placeholder.
- Clusters roles with identical signatures across `>= min_schemas` schemas into a single profile.
- Picks a uniform role-name pattern (`{schema}-{profile}`, `{schema}_{profile}`, `{profile}-{schema}`, or `{profile}_{schema}`) so the resulting expansion produces the same role names as the input.
- Verifies that re-expanding the suggested manifest produces the same role state as the flat one (modulo auto-generated role comments). If anything would change semantically, the suggestion is dropped and the flat manifest is returned.

To safely collapse per-name grants into wildcards (e.g. turning per-table `GRANT SELECT ON each_table` into a `name: "*"` profile grant), the suggester uses a complete object inventory introspected from the live database — so it cannot accidentally widen privileges to objects that exist but had no grants.

The log output documents what was extracted and why each remaining role stayed flat:

```text
profile suggestion complete profiles_extracted=2 roles_skipped=3
extracted profile profile=reader pattern={schema}_{profile} schemas=["analytics","billing","checkout","inventory"]
extracted profile profile=editor pattern={schema}_{profile} schemas=["billing","checkout","inventory"]
skipped: role spans multiple schemas role="app_owner" schemas=["billing","checkout","inventory"]
skipped: role has attributes profiles can't express role="platform_admin"
skipped: cluster spans only one schema role="analytics_owner" schema="analytics"
```

{% callout type="note" title="Idempotent across re-runs" %}
Re-running `--suggest-profiles` on a database where you've already applied a suggested manifest works as expected. The auto-generated profile comments (`Generated from profile 'X' for schema 'Y'`) are recognised and ignored; user-set role comments still keep a role flat.
{% /callout %}

{% callout type="note" title="Starting point for refinement" %}
The generated manifest — flat or with suggested profiles — is a snapshot of the current state. After generating it, you can reorganize roles into profiles and schemas to take advantage of pgroles' template system.
{% /callout %}

{% callout type="warning" title="Treat generated manifests as authoritative input" %}
`generate` is best used as a starting point for brownfield adoption. Before applying the generated manifest in production, review it like any other infrastructure policy because once committed it becomes the desired state.
{% /callout %}

## render-bundle

Compose a policy bundle into a single flat `PolicyManifest` YAML. The output round-trips through `validate -f`, `diff -f`, and `apply -f`, and is suitable for committing as the source of a `PostgresPolicy` resource in a GitOps repo.

```shell
pgroles render-bundle --bundle path/to/pgroles.bundle.yaml
pgroles render-bundle --bundle path/to/pgroles.bundle.yaml --output pgroles.yaml
pgroles render-bundle --bundle path/to/pgroles.bundle.yaml --check pgroles.yaml
```

### Options

| Flag | Description |
|---|---|
| `--bundle` | Bundle root file path (required) |
| `-o`, `--output` | Write the rendered manifest to a file instead of stdout |
| `--no-header` | Omit the provenance comment block at the top of the output |
| `--check` | Compare the rendered output against an existing file. Exits with code **2** on drift, **0** on match. Mutually exclusive with `--output`. |

### Output shape

The rendered file is byte-deterministic across machines: the header records only the bundle file's basename (never an absolute or `pwd`-relative path), and the YAML body is post-processed to strip serde-emitted defaults (empty optional sequences, `null` scalars, and the default `role_pattern`) so the file does not churn under unrelated upgrades.

The header records the manifest schema version (`pgroles.manifest.v1` today). The schema identifier is bumped only on incompatible changes to the `PolicyManifest` serialization shape, so a `--check` failure after a pgroles upgrade can be diagnosed as "schema bumped — re-render required" rather than mystery drift.

Required-field empty sequences (`Grant.privileges`, `DefaultPrivilege.grant`, `Membership.members`) and named empty profiles such as `noop: {}` are preserved so the rendered output always re-parses as a valid manifest.

Composition errors — scope violations, duplicate ownership claims, overlapping schema facets — are reported before any output is written, so `render-bundle` will not emit a partially-valid manifest.

### CI drift gate

Use `--check` to fail the build when the committed rendered manifest is stale:

```shell
pgroles render-bundle --bundle pgroles.bundle.yaml --check pgroles.yaml
```

This is the recommended companion to a GitOps workflow where the rendered manifest is committed alongside the source bundle. See [CI/CD integration](/docs/ci-cd) for a full GitHub Actions example.

## reconcile

Request an immediate operator reconcile for a Kubernetes `PostgresPolicy` without changing `spec`.

```shell
pgroles reconcile my-policy -n platform
pgroles reconcile postgrespolicy/my-policy -n platform --wait
```

The command patches the policy annotation `reconcile.pgroles.io/requestedAt` with the current RFC 3339 timestamp. The operator treats a new annotation value as an immediate reconcile trigger and mirrors the value to `status.lastHandledReconcileAt` after a successful reconcile or plan.

### Options

| Flag | Description |
|---|---|
| `-n`, `--namespace` | Kubernetes namespace containing the `PostgresPolicy` (default: `default`) |
| `--wait` | Poll the policy until `status.lastHandledReconcileAt` reaches the requested timestamp |
| `--timeout` | Maximum wait duration, e.g. `30s`, `2m`, or `1m30s` (default: `2m`). Requires `--wait` |

## candidate

Propose policy content for review, and read what the operator planned for it. See [Candidates and promotion](/docs/operator-candidates) for the workflow these commands serve; this section is the flag reference.

All four subcommands talk to Kubernetes using your current kubeconfig context, and take `-n` / `--namespace` (default: `default`). No database connection is involved: the operator does the planning.

```shell
pgroles candidate create --policy orders -f policy.yaml
pgroles candidate list --policy orders
pgroles candidate status orders-x7k2p
pgroles candidate diff orders-x7k2p
```

### create

Files a `PostgresPolicyCandidate` carrying the content of a local manifest. The content is validated first through the same path as `pgroles validate`, so a manifest the API server would reject on [size limits](/docs/manifest-reference#size-limits) fails locally with the same field-level message. The object is created with `generateName`, so concurrent filings never collide, and the assigned name is printed.

| Flag | Description |
|---|---|
| `--policy` | Name of the `PostgresPolicy` this candidate proposes content for (required) |
| `-f`, `--file` | Manifest holding the proposed content (required) |
| `--replaces` | Name of an earlier candidate this one supersedes; must belong to the same policy |
| `-n`, `--namespace` | Kubernetes namespace (default: `default`) |

The manifest may be a bare pgroles manifest, a `PostgresPolicy` CR (whose `connection`, `interval`, `mode`, `suspend` and `approval` are dropped, since a candidate takes those from its parent), or a `PostgresPolicyCandidate` CR. A key with no candidate counterpart is rejected rather than silently pruned server-side.

### list

One row per candidate filed against the policy: phase, abbreviated content digest, plan name, and the `Ready` / `Superseded` / `Promoted` conditions with their reasons. A policy with no candidates reports that; a policy that does not exist is a distinct error.

### status

One candidate in detail — phase, full content digest, conditions with their messages, and its plan: the plan's phase, its decision and the identity that made it, whether it is still current or has been superseded, the applied base it is pinned to, and any promotion outcome. A candidate with no plan yet reports that rather than printing an empty plan section.

### diff

Prints the reviewed plan's SQL on stdout — what approving the candidate would execute. It reads `status.sqlInline`, falling back to the gzipped ConfigMap in `status.sqlRef` when the plan is too large to inline. A plan whose SQL survives only as a truncated preview is an error rather than a short diff. Context lines go to stderr, so stdout pipes cleanly into a file or a reviewer's pager.

Deciding a plan is deliberately not a CLI verb: a decision is a status write gated by admission so that `decidedBy` records an authenticated identity. Approve and reject with `kubectl` — see [Deciding a plan](/docs/operator-plan-approval#deciding-a-plan).

## graph

Render the role graph as a terminal tree or machine-readable graph.

```shell
pgroles graph desired -f pgroles.yaml --format tree
pgroles graph desired --bundle path/to/pgroles.bundle.yaml --format json
pgroles graph current --database-url postgres://localhost/mydb --scope all --format tree
pgroles graph current --bundle path/to/pgroles.bundle.yaml --database-url postgres://localhost/mydb --scope managed --format json
```

### desired

Build the graph from a manifest or bundle.

| Flag | Description |
|---|---|
| `-f`, `--file` | Manifest file path |
| `--bundle` | Bundle root file path |
| `--format` | `tree` (default), `json`, `dot`, or `mermaid` |
| `-o`, `--output` | Write the rendered graph to a file |

### current

Build the graph from a live database.

| Flag | Description |
|---|---|
| `-f`, `--file` | Manifest file path |
| `--bundle` | Bundle root file path |
| `--database-url` | PostgreSQL connection string |
| `--scope` | `managed` (default) or `all` |
| `--format` | `tree` (default), `json`, `dot`, or `mermaid` |
| `-o`, `--output` | Write the rendered graph to a file |

`graph current --scope managed` requires either `-f` or `--bundle` so pgroles knows which roles or bundle scope are considered managed.

Bundle-aware graph JSON includes:

- top-level `schema_version`
- the normal graph payload
- `meta.managed_scope` describing bundle-managed roles and schema facets

## Reconciliation modes

The `--mode` flag controls how aggressively pgroles converges the database. Both `diff` and `apply` accept this flag.

### authoritative (default)

Full convergence. Anything not in the manifest is revoked or dropped. This is the standard GitOps model — the manifest is the single source of truth.

```shell
pgroles apply --database-url postgres://localhost/mydb --mode authoritative
```

### additive

Only grant, never revoke. New roles, grants, memberships, and default privileges are created, but nothing is removed. This is the safest mode for incremental adoption — start managing roles without risking disruption to existing access.

```shell
pgroles apply --database-url postgres://localhost/mydb --mode additive
```

Additive mode filters out: `ALTER ROLE`, `COMMENT ON ROLE`, `REVOKE`, `REVOKE DEFAULT PRIVILEGE`, `REMOVE MEMBER`, `ALTER SCHEMA ... OWNER TO ...`, `DROP ROLE`, `DROP OWNED`, `REASSIGN OWNED`, and `TERMINATE SESSIONS`.

Because additive mode never revokes, it also ignores every `ensure: absent` rule. The rest of the plan still applies, and the run does not fail. Use `adopt` or `authoritative` when you need those assertions enforced.

If additive mode skips a schema ownership transfer, pgroles also defers owner-bound follow-up steps such as schema-owner privilege repair and `ALTER DEFAULT PRIVILEGES FOR ROLE ...` for that owner context.

For brownfield roles that already exist, additive mode intentionally leaves role attributes and comments unchanged. That means a pre-existing `LOGIN NOINHERIT` role can stay that way during adoption even if a minimal manifest would otherwise imply `NOLOGIN INHERIT`.

### adopt

Manage declared roles fully (including revoking excess grants within their scope), but never drop undeclared roles. This is the middle ground — you get full convergence for roles in the manifest, but roles outside the manifest are left untouched.

```shell
pgroles apply --database-url postgres://localhost/mydb --mode adopt
```

Adopt mode filters out: `DROP ROLE`, `DROP OWNED`, `REASSIGN OWNED`, and `TERMINATE SESSIONS`. Revokes and membership removals for managed roles still apply. `ensure: absent` rules apply in this mode.

{% callout type="warning" title="Adopt does not preserve undeclared grants" %}
Adopt only filters role drops. Every privilege a declared role holds that the manifest does not declare — including out-of-band grants from migrations or manual SQL — is revoked. Review the full plan (`pgroles diff --mode adopt`) before applying, and stay in additive mode until the manifest declares everything the database relies on.
{% /callout %}

{% callout type="note" title="Adoption path" %}
A common adoption path is: start with `--mode additive` to verify the manifest produces the right grants, then move to `--mode adopt` to start revoking excess grants within managed roles, and finally switch to `--mode authoritative` when you're confident the manifest is complete.
{% /callout %}

## Change ordering

pgroles applies changes in dependency order:

1. Create roles
2. Set passwords (immediately after each role creation, or appended for existing roles)
3. Alter role attributes
4. Grant privileges
5. Set default privileges
6. Remove memberships
7. Add memberships
8. Revoke default privileges
9. Revoke privileges
10. Terminate sessions for retired roles
11. Reassign owned objects for retired roles
12. Drop owned objects / revoke remaining privileges for retired roles
13. Drop roles

This ensures roles exist before they're granted privileges, membership flag changes can be re-applied safely, and retired roles can be drained and cleaned up before the final drop.
