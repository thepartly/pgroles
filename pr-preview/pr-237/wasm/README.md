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
The executor is separate auxiliary context:
`memberships` records `{ role, member, set_role, inherit, admin_option }`,
where each authority option is `allowed`, `denied`, or `unknown`. The executor
also accepts `new_membership_set_role`, `new_role_set_role`, `new_role_inherit`,
and `new_role_admin_option` with the same tri-state semantics.

The `analyze` request strictly decodes `schema_version`, `current`, `desired_yaml`,
`mode`, and `executor`; unknown fields, explicit credential fields, password fields, and
password sources in desired YAML are rejected. The response contains ordered
`changes`, phase `changes`, `executor_reachability` (SET ROLE) and
`executor_usage` (inherited privileges), findings, a visual graph, and an
illustrative fingerprint. The fingerprint is not an approval token: browser
analysis has no verified target identity or execution context. Findings that
need ownership, grantor, or live privilege evidence remain database preflight
requirements.

The docs explorer can also open `pgroles.review-artifact.v1` files exported by
native `pgroles diff --review-out review.pgroles.json`. Those files contain
recorded results and are rendered without initializing WASM or recalculating
the plan. The first artifact version omits exploration inputs; its SQL preview
comes from the native planning run and is omitted when changes contain sensitive
values. See the [recorded review workflow](../../docs/src/pages/docs/ci-cd.md#recorded-reviews).

Run browser-safe checks package-scoped, because workspace feature unification
can enable `pgroles-core/passwords` through the CLI or operator:

```bash
cargo test -p pgroles-core --no-default-features
cargo check -p pgroles-core --no-default-features --target wasm32-unknown-unknown
cargo check -p pgroles-wasm --target wasm32-unknown-unknown
WASM_PACK_BIN=wasm-pack scripts/check-wasm-parity.sh
```
