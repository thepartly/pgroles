---
title: Explorer snapshots
description: Prepare a current-state snapshot for the browser plan explorer, scrub it by hand, and understand how the PostgreSQL version and authority-graph settings change the results.
---

The [plan explorer](/docs/explorer) compares a policy with a current-state
snapshot that you write or derive yourself. No pgroles command produces this
file yet, and you must remove secrets from it by hand before importing or
sharing it. {% .lead %}

## Where the format is defined

Snapshots use the `pgroles.explorer.v1` request format. The
[pgroles-wasm README](https://github.com/thepartly/pgroles/blob/main/crates/pgroles-wasm/README.md)
is the only specification of it. This page does not restate the field list.
The analyzer decodes requests strictly and rejects unknown fields, so a typo
fails loudly rather than being ignored.

The explorer accepts either a bare `current` snapshot or a whole request
envelope:

```json
{
  "schema_version": "pgroles.explorer.v1",
  "pg_major_version": 15,
  "authority_graph_complete": false,
  "current": {
    "roles": { "deploy": { "login": true }, "app_owner": {} },
    "memberships": [{ "role": "app_owner", "member": "deploy", "inherit": true, "admin": false }]
  },
  "executor": { "role": "deploy", "createrole": "allowed" }
}
```

The explorer uses `pg_major_version`, `authority_graph_complete`, and the
`executor` facts from an envelope, and shows **From snapshot** beside the
PostgreSQL version when the envelope sets it. A bare snapshot keeps the version
selected in the explorer and is treated as a complete authority graph. An
envelope's `executor.superuser: true` is kept even when `current.roles` lists
the executor without the flag, and the explorer shows **Overrides snapshot**
beside the control; a snapshot `superuser: true` cannot be unset. Typing a role
the snapshot describes starts from that role's flag; tick the box to assert
otherwise.

## No exporter yet

No CLI command writes an explorer snapshot. `pgroles inspect` prints a
summary, `pgroles generate` writes a policy manifest, and
`pgroles diff --review-out` writes a
[recorded review](/docs/recorded-reviews) (`pgroles.review-artifact.v2`).
A recorded review is a different format: the explorer displays it read-only
and cannot replan it, because the export deliberately omits the inputs.

To explore a hypothetical change against a real database, build the snapshot
yourself from catalog queries or from `pgroles inspect` output. Include only
the roles, schemas, grants, default privileges, and memberships that matter
to the plan.

## Scrub credentials by hand

The analyzer rejects `password` fields and password sources in desired YAML,
but it cannot recognise a secret stored in a free-form string. Before you
import or share a snapshot:

- Remove or replace every role `config` value. `ALTER ROLE ... SET` accepts
  arbitrary strings, and teams sometimes store connection strings, API keys,
  or tokens there.
- Remove or replace every role `comment`. Comments are free text and can
  contain credentials or internal notes.
- Review role, schema, and object names, and the executor role. They are
  kept verbatim and can reveal customer or system names.

The browser does not upload, store, or put the snapshot in the URL, but a
file you share with someone else takes its contents with it.

## PostgreSQL version

`pg_major_version` is the target server's major version. It defaults to 16
when omitted. The explorer offers 15 to 18; the analyzer accepts 12 to 20 and
rejects anything else. The results header shows the version the analyzer
used.

The version changes the authority needed to grant or revoke role membership
(adding a member, or removing one without `GRANTED BY`), and what a membership
proves about `SET ROLE`:

- **Before PostgreSQL 16**, an executor with `CREATEROLE` may grant and
  revoke membership in any non-superuser role without `ADMIN OPTION`. When
  `CREATEROLE` is unknown and `ADMIN OPTION` is not proven, the explorer
  reports the authority as not proven.
- **From PostgreSQL 16**, the executor needs `ADMIN OPTION` on the granted
  role, directly or through a role whose privileges it inherits. `CREATEROLE`
  alone is not enough.
- **In every version**, only a superuser executor can grant or revoke
  membership in a superuser role (`superuser_required`).
- **Before PostgreSQL 16**, there is no per-membership `SET` option, so every
  membership in the snapshot, in executor facts, or added by the plan proves
  `SET ROLE` to the granted role. **From PostgreSQL 16**, a membership without
  a `set_role` executor fact is a possible path but not a proven one.

It does not change how the `INHERIT` option is modelled, grantor attribution,
or which changes are planned.

`executor.createrole` (`allowed`, `denied`, or `unknown`, the default) is
consulted only below PostgreSQL 16. `allowed` or `denied` overrides the
snapshot; `unknown` uses the `createrole` attribute of the executor's own
role when the snapshot includes it. The **Executor CREATEROLE** control in the
explorer sets this fact.

## Authority graph completeness

`authority_graph_complete` defaults to `true`. It states whether the snapshot
and executor facts list every role and membership that could give the
executor authority.

- **Complete** (`true`): a missing path proves the executor lacks that
  authority. Roles without a path are `unreachable`, and missing grantor,
  owner, `ADMIN OPTION`, or `CREATEROLE` authority is a
  `required_role_unavailable` error.
- **Partial** (`false`): a missing path is only unproven. Those roles are
  `unknown`, the same gaps are `required_role_reachability_unknown` warnings
  that need a database preflight, and losing a path that was only possible is
  not reported as a disconnection. Losing a proven path is still reported as
  `executor_loses_access`.

Set it to `false` when the snapshot covers only the managed roles. Native
recorded reviews always use `false`, because inspection is scoped to the
policy. The explorer sends `true` unless a bundled scenario variant or an
imported envelope sets it to `false`, and shows the setting under
**Current snapshot**.
