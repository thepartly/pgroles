# pgroles-wasm

`pgroles-wasm` is the browser-only explorer adapter. It links `pgroles-core`
without its `passwords` feature and has no inspection, credential, or network API.

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

`current` is only the managed, password-free snapshot, sanitized by the caller.
Role configuration accepts arbitrary strings and can contain credentials;
remove sensitive values before importing or sharing a snapshot. Its grants may include a
`grantors` map and memberships a `grantors` list when an exporter knows
PostgreSQL 16+ attribution. `inherent_grants` records owner privilege targets as
`{ role, object_type, schema, name }`, so planning does not revoke intrinsic
privileges. The executor is separate auxiliary context:
`memberships` records `{ role, member, set_role, inherit, admin_option }`,
where each authority option is `allowed`, `denied`, or `unknown`. The executor
also accepts `new_membership_set_role`, `new_role_set_role`, `new_role_inherit`,
and `new_role_admin_option` with the same tri-state semantics.

The request strictly decodes `schema_version`, `current`, `desired_yaml`,
`mode`, and `executor`; unknown fields, explicit credential fields, password fields, and
password sources in desired YAML are rejected. The response contains ordered
`changes`, phase `changes`, `executor_reachability` (SET ROLE) and
`executor_usage` (inherited privileges), findings, a visual graph, and an
illustrative fingerprint. The fingerprint is not an approval token: browser
analysis has no verified target identity or execution context. Findings that
need ownership, grantor, or live privilege evidence remain database preflight
requirements.

Run browser-safe checks package-scoped, because workspace feature unification
can enable `pgroles-core/passwords` through the CLI or operator:

```bash
cargo test -p pgroles-core --no-default-features
cargo check -p pgroles-core --no-default-features --target wasm32-unknown-unknown
cargo check -p pgroles-wasm --target wasm32-unknown-unknown
WASM_PACK_BIN=wasm-pack scripts/check-wasm-parity.sh
```
