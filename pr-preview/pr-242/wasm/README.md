# pgroles-wasm

`pgroles-wasm` is the browser adapter for the reusable pgroles policy engine. It links
`pgroles-core` without its `passwords` feature and has no inspection, credential, or network
API.

It exposes three versioned operations:

- `analyze` plans a desired policy against a sanitized current snapshot.
- `validate` checks policy YAML without resolving secrets or inspecting a database.
- `compile` returns expanded policy data and a normalized desired graph for authoring tools.

Validation and compilation do not produce executable SQL or approval tokens. SQL rendering
depends on an ordered plan and trusted PostgreSQL execution context, including server version
and live object inventory. The adapter does not accept caller-constructed changes or arbitrary
SQL context. Compiled output also has no source-provenance map; diagnostics include a source
range only when the YAML parser supplies an honest syntax location.

Build a lazy-loadable web package:

```bash
wasm-pack build crates/pgroles-wasm --target web --release --out-dir ../../docs/public/wasm
```

```js
import init, { analyze } from '/pgroles/wasm/pgroles_wasm.js'

await init()
const result = analyze({
  schema_version: 'pgroles.explorer.v1',
  current: { roles: {}, schemas: {}, grants: [], default_privileges: [], memberships: [] },
  desired_yaml: 'roles:\n  - name: application',
  mode: 'authoritative',
  executor: { role: 'postgres', superuser: true },
  // Optional; these are the defaults.
  pg_major_version: 16,
  authority_graph_complete: true,
})
```

Policy authoring uses the smaller `pgroles.policy.v1` request:

```js
import init, { compile, validate } from '/pgroles/wasm/pgroles_wasm.js'

await init()

const request = {
  schema_version: 'pgroles.policy.v1',
  desired_yaml: 'roles:\n  - name: application\n    login: true',
}

const validation = validate(request)
const compilation = compile(request)
```

The generated [policy-authoring.d.ts](policy-authoring.d.ts) provides request,
response, diagnostic, and `PolicyAuthoringEngine` types for TypeScript consumers.
Use the companion interface to type the initialized module's `validate` and
`compile` methods; wasm-bindgen's raw `JsValue` exports remain untyped.
The versioned structural schema is also published as
`generated/manifest-metadata.json` under the docs deployment base path.
Regenerate both artifacts from the Rust types with
`scripts/generate-manifest-metadata.sh` from the repository root.

An invalid policy is a normal response: `validate` returns `valid: false`, while `compile`
returns diagnostics without a `policy`. Unsupported schema versions follow the same diagnostic
path. A malformed outer request, such as a missing field, wrong type, or unknown `context`,
throws at the JavaScript boundary.

Syntax diagnostics may include a zero-width UTF-8 byte cursor as
`range: { startByte, endByte }`. Semantic diagnostics omit `range` rather than guessing where a
normalized error originated. A role password such as `{ from_env: APP_PASSWORD }` is retained
only as source metadata; browser validation and compilation never read the environment or
resolve password material.

The `analyze` request's `current` field is only the managed, password-free snapshot, sanitized by the caller.
Role configuration accepts arbitrary strings and can contain credentials;
remove sensitive values before importing or sharing a snapshot. Its grants may include a
`grantors` map and memberships a `grantors` list when an exporter knows
PostgreSQL 16+ attribution. `inherent_grants` records owner-held ACL entries as
`{ role, object_type, schema, name }`; they are preserved according to the native planner rules.
Duplicate entries for one target merge the way native inspection aggregates catalog rows:
grant and default-privilege privileges union, grantor maps union per grantor, and duplicate
`(role, member)` memberships become one edge whose `inherit` and `admin` apply if any entry
sets them, with the union of their grantors.

The executor is separate auxiliary context:
`memberships` records `{ role, member, set_role, inherit, admin_option }`,
where each authority option is `allowed`, `denied`, or `unknown`. The executor
also accepts `createrole`, `new_membership_set_role`, `new_role_set_role`,
`new_role_inherit`, and `new_role_admin_option` with the same tri-state semantics
(each defaults to `unknown`), and `superuser` (default `false`).

## Optional analysis context

Both fields are optional and backward compatible; omitting them, or passing `null`, keeps the
earlier behaviour. The response echoes the effective values as `pg_major_version` (a number)
and `authority_graph_complete` (a boolean).

| Request field | Default | Effect |
| --- | --- | --- |
| `pg_major_version` | `16` | PostgreSQL major version whose membership-authority rules apply. Values below 12 or above 20 are rejected. |
| `authority_graph_complete` | `true` | Whether absence from the snapshot and executor facts proves absence in PostgreSQL. |

`pg_major_version` changes the authority check for membership grants and revokes
(`AddMember`, and `RemoveMember` without a grantor), and what a membership proves about SET
ROLE. Before PostgreSQL 16, CREATEROLE on the
executor authorizes them for any non-superuser role, as does ADMIN OPTION; an `unknown`
CREATEROLE without proven ADMIN OPTION is reported as not proven. From PostgreSQL 16, ADMIN
OPTION on the granted role is required, held by the executor or by a role whose privileges it
inherits, and CREATEROLE alone is not sufficient. In every version, membership in a SUPERUSER
role can only be granted or revoked by a superuser executor (`superuser_required`). Before
PostgreSQL 16 there is no membership SET option, so every membership in the snapshot, in executor
facts, or added by the plan proves SET ROLE to the granted role; from 16, a membership without a
`set_role` fact is a possible path, not a proven one. The planned changes, INHERIT option
modelling, and grantor attribution do not depend on the version.

With `authority_graph_complete: false`, a role without a proven path is `unknown` rather than
`unreachable`, and missing grantor, owner, ADMIN OPTION, or CREATEROLE authority is a
`required_role_reachability_unknown` warning instead of a `required_role_unavailable` error.
This matches the native review-artifact path, which analyzes scoped inspections as incomplete.

## Executor fact precedence

Executor facts describe the starting state; the plan's own `ALTER ROLE` changes to the executor
role then apply to later steps.

- `superuser: true` wins over the snapshot. `false`, the default, defers to the snapshot's
  `superuser` attribute when the executor role appears in `current.roles`.
- `createrole: allowed` or `denied` wins over the snapshot. `unknown` defers to the snapshot's
  `createrole` attribute for the executor role, and stays unknown when the role is absent.
- In `memberships`, an explicit `allowed` or `denied` `inherit` or `admin_option` overrides what
  a snapshot edge for the same `(role, member)` records. `unknown`, including an omitted option,
  never overrides it. From PostgreSQL 16, snapshot edges never prove SET ROLE, so `set_role`
  comes only from executor facts; before 16, every membership proves it, and an `unknown`
  `set_role` resolves to `allowed`.

## Analysis response

The `analyze` request strictly decodes `schema_version`, `current`, `desired_yaml`,
`mode`, `executor`, `pg_major_version`, and `authority_graph_complete`; unknown fields,
explicit credential fields, password fields, and password sources in desired YAML are
rejected. The response contains the effective `pg_major_version` and
`authority_graph_complete`, ordered `changes`, phase `changes`, `executor_reachability`
(SET ROLE) and `executor_usage` (inherited privileges), findings, a visual graph, and an
illustrative fingerprint. Contiguous changes of one phase form one phase entry, so a phase label
can repeat, for example `create`, `alter`, `create`. The fingerprint binds the mode, version,
completeness, and executor facts, but it is not an approval token: browser analysis has no
verified target identity or execution context. Findings that need ownership, grantor, or live
privilege evidence remain database preflight requirements. `database_preflight_required` is
reported once per phase and change kind; its `change_indices` lists every affected change and
`change_index` names the first. A schema owner change also reports
`ownership_transfer_changes_grantor`, because the new owner becomes the implicit grantor for
privileges on that schema. Dropping a role is not reported as the executor losing access to it.

The docs explorer can also open `pgroles.review-artifact.v2` files exported by
native `pgroles diff --review-out review.pgroles.json`; older `v1` files must be
re-exported. Those files contain recorded results and are rendered without
initializing WASM or recalculating the plan. Recorded phases store reachability
as deltas from the previous phase rather than the full per-phase lists that
`analyze` returns. Artifacts omit exploration inputs; the SQL preview comes from
the native planning run and is omitted when changes contain sensitive values. See the [recorded review workflow](../../docs/src/pages/docs/ci-cd.md#recorded-reviews).

Run browser-safe checks package-scoped, because workspace feature unification
can enable `pgroles-core/passwords` through the CLI or operator:

```bash
cargo test -p pgroles-core --no-default-features
cargo check -p pgroles-core --no-default-features --target wasm32-unknown-unknown
cargo check -p pgroles-wasm --target wasm32-unknown-unknown
cargo test -p pgroles-wasm --test fixture_expectations
WASM_PACK_BIN=wasm-pack scripts/check-wasm-parity.sh
```

Each file in `tests/fixtures/` is `{ description, request, expected }`. `expected` uses the
docs scenario assertion format (`changes`, `absentChanges`, `findings`, `absentFindings`,
`phaseReachability`, and `response` fields), and both the native fixture test and the WASM
parity script check it in addition to native/WASM equality.
