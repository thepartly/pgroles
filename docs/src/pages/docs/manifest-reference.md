---
title: Manifest reference
description: Complete reference for the pgroles YAML manifest schema.
---

Complete field reference for pgroles manifests and CLI bundle files. {% .lead %}

---

## Top-level fields

All top-level manifest fields are optional:

```yaml
default_owner: app_migrator      # Owner for ALTER DEFAULT PRIVILEGES
auth_providers: []                # Cloud IAM provider declarations
profiles: {}                      # Reusable privilege templates
schemas: []                       # Managed schemas and schema-profile bindings
roles: []                         # Role definitions
grants: []                        # Object privilege grants
default_privileges: []            # Default privilege rules
memberships: []                   # Role membership edges
retirements: []                   # Safe role removal workflows
```

## auth_providers

Declare cloud authentication providers to document how IAM-mapped roles connect to the database. This metadata is used for validation and documentation.

```yaml
auth_providers:
  - type: cloud_sql_iam
    project: my-gcp-project
  - type: alloydb_iam
    project: my-gcp-project
    cluster: analytics-prod
  - type: rds_iam
    region: us-east-1
  - type: azure_ad
    tenant_id: "00000000-0000-0000-0000-000000000000"
  - type: supabase
    project_ref: abcd1234
  - type: planet_scale
    organization: my-org
```

| Type | Description |
|---|---|
| `cloud_sql_iam` | Google Cloud SQL IAM authentication. Optional `project` field. |
| `alloydb_iam` | Google AlloyDB IAM authentication. Optional `project` and `cluster` fields. |
| `rds_iam` | AWS RDS/Aurora IAM authentication. Optional `region` field. |
| `azure_ad` | Azure Active Directory authentication. Optional `tenant_id` field. |
| `supabase` | Supabase PostgreSQL metadata. Optional `project_ref` field. |
| `planet_scale` | PlanetScale PostgreSQL metadata. Optional `organization` field. |

{% callout type="note" title="Managed service metadata is intentionally narrow" %}
The `auth_providers` block models the provider types listed above, but only RDS/Aurora, Cloud SQL, AlloyDB, and Azure have provider-specific privilege-warning behavior. Supabase and PlanetScale PostgreSQL entries are documentation and validation metadata.
{% /callout %}

## default_owner

The `default_owner` field specifies which role is used as the owner context for `ALTER DEFAULT PRIVILEGES` statements. This is typically the role that creates objects in your database.

```yaml
default_owner: app_migrator
```

Individual schemas can override this with their own `owner` field.

`default_owner` is an ownership claim, not an annotation: every schema binding without an explicit `owner:` resolves to it, so plans include `ALTER SCHEMA ... OWNER TO <default_owner>` wherever the live schema owner differs. If the named role is not declared under `roles:`, pgroles warns — the role's own privileges are neither inspected nor converged, while every un-owned binding still resolves to it.

Inspection never treats an object's owner-grantee ACL entry as granted state: PostgreSQL records the owner's inherent privileges there once any grant materializes the ACL, and planning revokes against it would strip access PostgreSQL considers intrinsic (including foreign-key key-share checks, which run with the table owner's privileges). Owner entries instead cover any declared grant on the same target — declaring privileges on an owner's own objects converges as a no-op — and `pgroles generate` never exports them.

## profiles

Profiles are reusable templates that expand into concrete roles, grants, and default privileges when bound to schemas.

```yaml
profiles:
  editor:
    login: false
    inherit: false
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        object: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table
```

| Field | Type | Default | Description |
|---|---|---|---|
| `login` | bool | `false` | Login attribute for generated roles |
| `inherit` | bool | `true` | Inherit attribute for generated roles |
| `grants` | list[grant template] | `[]` | Grants expanded into each bound schema |
| `default_privileges` | list[default privilege template] | `[]` | Default privileges expanded into each bound schema |
| `config` | map | `{}` | Role-level configuration defaults for generated roles (`ALTER ROLE ... SET`); values support `{schema}`/`{profile}` placeholders — see [role configuration defaults](#role-configuration-defaults) |

A profile is an additive template, so neither `grants` nor `default_privileges` may set `ensure: absent`. Validation rejects the manifest and names the profile. Declare the absence as a top-level `grants` or `default_privileges` entry instead.

The generated role attributes apply only to roles created from `schema x profile` expansion. One-off roles under `roles:` still declare their own attributes directly.

## schemas

The `schemas` section declares schemas pgroles should manage and binds profiles to those schemas.

```yaml
schemas:
  - name: inventory
    owner: app_owner
    profiles: [editor, viewer]
```

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | *required* | Schema name |
| `profiles` | list[string] | `[]` | Profiles to expand for this schema |
| `owner` | string | `default_owner` | Desired schema owner; if omitted and `default_owner` is unset, pgroles only ensures the schema exists |
| `role_pattern` | string | `"{schema}-{profile}"` | Naming pattern for profile-generated roles |

When a schema is declared under `schemas:`, pgroles can create it if it does not exist and can converge its owner with `ALTER SCHEMA ... OWNER TO ...`. pgroles does not drop schemas or reassign ownership of objects inside the schema.

## roles

Each role definition specifies a PostgreSQL role and its attributes:

```yaml
roles:
  - name: analytics
    login: true
    comment: "Analytics read-only role"
  - name: app-service
    login: true
    createdb: false
    connection_limit: 10
    password:
      from_env: APP_SERVICE_PASSWORD
    password_valid_until: "2026-12-31T00:00:00Z"
```

| Attribute | Type | Default | Description |
|---|---|---|---|
| `name` | string | *required* | Role name |
| `external` | bool | `false` | Role lifecycle is managed outside pgroles |
| `login` | bool | `false` | Can the role log in? |
| `superuser` | bool | `false` | Superuser privileges |
| `createdb` | bool | `false` | Can create databases |
| `createrole` | bool | `false` | Can create other roles |
| `inherit` | bool | `true` | Inherits privileges of granted roles |
| `replication` | bool | `false` | Can initiate replication |
| `bypassrls` | bool | `false` | Bypasses row-level security |
| `connection_limit` | int | `-1` (unlimited) | Max concurrent connections |
| `comment` | string | *none* | Comment on the role |
| `password` | object | *none* | Password source |
| `password_valid_until` | string | *none* | Password expiration (ISO 8601) |
| `config` | map | `{}` | Role-level configuration defaults (`ALTER ROLE ... SET`) |

Roles with `login: true` can declare a password source. The password value is never stored in the manifest; it is resolved at apply time from an environment variable in CLI mode or from a Kubernetes Secret in operator mode.

Only `login: true` roles may have a password. Declaring a password on a non-login role is a validation error.

Use `external: true` for roles whose lifecycle is owned by another system, such as Cloud SQL IAM users or groups created by Terraform or the cloud provider API. pgroles may still reference external roles in grants, schema ownership, default privileges, and as members of managed roles, but it will not create, alter, drop, password-manage, or manage memberships granted from the external role.

{% callout type="note" title="Passwords and drift detection" %}
Because PostgreSQL does not expose password hashes for comparison, password changes always appear in the plan. The `diff --exit-code` flag treats password-only changes as non-structural; they do not trigger exit code 2.
{% /callout %}

### Role configuration defaults

`config` declares session defaults that PostgreSQL applies whenever the role logs in, managed via `ALTER ROLE ... SET parameter = value`:

```yaml
roles:
  - name: combined
  - name: blue
    login: true
    config:
      role: combined
      search_path: app
      statement_timeout: "30s"
  - name: green
    login: true
    config:
      role: combined

memberships:
  - role: combined
    members:
      - name: blue
      - name: green
```

Keys are PostgreSQL setting names (including dot-qualified custom settings like `app.tenant`); values are always strings — quote numbers and booleans, e.g. `statement_timeout: "30000"` and `jit: "off"`. The Kubernetes CRD schema types config values as strings, and the CLI enforces the same rule, so a manifest means the same thing whether it is applied with `pgroles` or `kubectl`. PostgreSQL coerces the string to the parameter's type.

Settings are compared against the cluster-wide entries in `pg_roles.rolconfig`. In authoritative and adopt modes, settings present on a managed role in the database but absent from the manifest are removed with `ALTER ROLE ... RESET`. In additive mode, config on pre-existing roles is left unchanged (config on newly created roles is still applied).

The `role: <group>` setting is the standard fix for blue/green credential rotation: both login roles switch to a shared group role at connect time, so objects created by either credential are owned by the group and remain fully accessible after rotation. When the target of a `role:` setting is declared in the same manifest, pgroles validates that a matching membership is declared too — without membership, PostgreSQL rejects the setting at login.

Per-database settings (`ALTER ROLE ... IN DATABASE ... SET`) are not managed and are left untouched.

Profiles can declare `config` too — values support `{schema}`/`{profile}` placeholders, substituted per `schema x profile` expansion; see [profiles](/docs/profiles/#role-configuration-defaults-on-profiles).

{% callout type="warning" title="Behind a transaction-mode pooler" %}
Role config, including `config.role`, is applied by PostgreSQL when a session starts. Behind a transaction-mode pooler (e.g. PgBouncer), client connections share a smaller pool of actual server connections, so config attaches to the pooled server session, not to an individual client. For the blue/green rotation pattern this is fine, since both credentials converge on the same `SET ROLE` target regardless of which pooled connection picks them up. It does mean per-client expectations — a distinct `application_name` per client, for example — do not hold. Pooler reset queries (`server_reset_query`, `DISCARD ALL`) do not remove these role-level defaults either: the `ALTER ROLE ... SET` value *is* the session's default, so `RESET` restores it rather than clearing it.
{% /callout %}

{% callout type="note" title="Value normalization" %}
Values are applied as string literals and read back from `pg_roles.rolconfig`. PostgreSQL stores most values verbatim, so writing the same form you want stored (e.g. `30s` or `30000`, but not both interchangeably) keeps the plan empty once converged.

List-valued parameters (`search_path`, `temp_tablespaces`, and the `*_preload_libraries` family) are handled element-wise: pgroles splits the value on commas (double-quote elements that contain commas or uppercase characters, e.g. `search_path: '"$user", public'`), applies one SQL literal per element, and normalizes quoting and spacing when comparing — so `"$user",public` and `"$user", public` are the same value.
{% /callout %}

## grants

Grants define object privileges:

```yaml
grants:
  - role: analytics
    privileges: [SELECT]
    object: { type: table, schema: public, name: "*" }
  - role: analytics
    privileges: [USAGE]
    object: { type: schema, name: public }
  - role: analytics
    privileges: [CONNECT]
    object: { type: database, name: mydb }
```

The `object` field specifies the grant target:

| Field | Description |
|---|---|
| `type` | Object type |
| `schema` | Schema name; required for most types except `schema` and `database` |
| `name` | Object name, `"*"` for all objects, or omit for schema-level grants. Required for `database`, where it must equal `current_database()` |

Supported object `type` values: `table`, `view`, `materialized_view`, `sequence`, `function`, `schema`, `database`, `type`.

pgroles also accepts a quoted legacy `"on"` key when parsing older manifests, but `object` is the supported spelling for new manifests and generated output.

Each entry also accepts `ensure`:

| Field | Default | Description |
|---|---|---|
| `role` | required | Grantee. The exact value `PUBLIC` means the PostgreSQL pseudo-role |
| `ensure` | `present` | `present` grants the privileges; `absent` revokes them where held |

In `additive` reconciliation, `absent` assertions are ignored with a warning
because that mode never revokes. `adopt` and `authoritative` enforce them.

```yaml
grants:
  - role: PUBLIC
    ensure: absent
    privileges: [EXECUTE]
    object: { type: function, schema: privileged_api, name: "*" }
```

See [Grants](/docs/grants#asserting-a-privilege-is-absent) for what `absent` does and does not promise.

## default_privileges

Default privileges configure what happens when new objects are created:

```yaml
default_privileges:
  - owner: app_migrator
    schema: app
    grant:
      - role: app_migrator
        privileges: [SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER]
        on_type: table
      - role: app_migrator
        privileges: [USAGE, SELECT, UPDATE]
        on_type: sequence
      - role: analytics
        privileges: [SELECT]
        on_type: table
```

If `owner` is omitted, the top-level `default_owner` is used.

| Field | Default | Description |
|---|---|---|
| `owner` | `default_owner` | The role whose newly created objects get these defaults |
| `schema` | — | Shorthand for `scope: {type: schema, schema: ...}` |
| `scope` | — | `{type: schema, schema: NAME}` or `{type: global}`. Set exactly one of `schema` and `scope` |
| `grant[].role` | required | Grantee; `PUBLIC` means the pseudo-role |
| `grant[].ensure` | `present` | `absent` revokes the default where it exists |
| `grant[].on_type` | required | `table`, `sequence`, `function`, `type`, or `schema` (global scope only) |

Global scope omits the `IN SCHEMA` clause and applies to every schema in the database:

```yaml
default_privileges:
  - owner: function_owner
    scope: { type: global }
    grant:
      - role: PUBLIC
        ensure: absent
        privileges: [EXECUTE]
        on_type: function
```

`on_type: database` is rejected because PostgreSQL has no database-level default privileges. `on_type: schema` is global-only. Declare views and materialized views as `table`, which is how `pg_default_acl` records them.

## memberships

Memberships declare which roles are members of other roles:

```yaml
memberships:
  - role: editors
    members:
      - name: "user@example.com"
        inherit: true
      - name: "admin@example.com"
        admin: true
```

| Field | Default | Description |
|---|---|---|
| `inherit` | `true` | Member inherits the role's privileges; omit for PostgreSQL default behavior |
| `admin` | `false` | Member can administer the role |

## retirements

When removing a role that owns objects, declare a retirement workflow so pgroles can safely clean up before dropping it:

```yaml
retirements:
  - role: legacy_app
    reassign_owned_to: app_owner
    drop_owned: true
    terminate_sessions: true
```

| Field | Type | Default | Description |
|---|---|---|---|
| `role` | string | *required* | The role to retire and ultimately drop |
| `reassign_owned_to` | string | *none* | Successor role for `REASSIGN OWNED BY ... TO ...` |
| `drop_owned` | bool | `false` | Run `DROP OWNED BY` before dropping the role |
| `terminate_sessions` | bool | `false` | Terminate other active sessions for the role before dropping it |

Retired roles are included in the inspection scope even though they are absent from the desired role list. The generated plan inserts session termination, `REASSIGN OWNED`, and/or `DROP OWNED` immediately before the `DROP ROLE` statement.

## Bundle mode

The CLI can compose a bundle from one root file plus multiple scoped policy documents. Use this when different teams own different parts of the same database policy.

```yaml
# pgroles.bundle.yaml
shared:
  default_owner: app_owner
  profiles:
    editor:
      grants:
        - privileges: [USAGE]
          object: { type: schema }
sources:
  - file: platform.yaml
  - file: app.yaml
```

Each source file is a `PolicyFragment`:

```yaml
# platform.yaml
policy:
  name: platform
scope:
  roles: [app_owner]
  schemas:
    - name: inventory
      facets: [owner]

roles:
  - name: app_owner

schemas:
  - name: inventory
    owner: app_owner
```

```yaml
# app.yaml
policy:
  name: app
scope:
  schemas:
    - name: inventory
      facets: [bindings]

schemas:
  - name: inventory
    profiles: [editor]
```

Bundle composition is a CLI/core feature. The Kubernetes operator reconciles a single `PostgresPolicy` resource, but you can still feed it composed bundle output via `pgroles render-bundle`, which emits a flat `PolicyManifest` suitable for wrapping into a `PostgresPolicy` resource. See the [bundle composition guide](/docs/bundle-composition).

### Shared bundle fields

| Field | Description |
|---|---|
| `shared.default_owner` | Default owner context shared across source documents |
| `shared.auth_providers` | Shared auth provider metadata |
| `shared.profiles` | Shared profile registry used by source documents |
| `sources` | Relative file paths to policy documents that will be composed together |

### Policy fragment fields

| Field | Description |
|---|---|
| `policy.name` | Human-readable source label used in conflict and plan output |
| `scope` | The ownership boundary this document is allowed to manage |

Schema scope is split into explicit facets:

| Facet | Description |
|---|---|
| `owner` | Manage schema creation and ownership convergence |
| `bindings` | Manage profile expansion, grants, and default privileges tied to the schema |

Two source documents may reference the same schema only when they manage disjoint facets. If two documents claim the same role, grant, default-privilege rule, membership selector, or schema facet, composition fails before any database inspection begins.

## Size limits

Every collection and string in policy content carries an explicit limit. The
same numeric limits are enforced by `pgroles validate` and by the Kubernetes
API server, with two caveats. First, the units differ at the margin:
PostgreSQL truncates identifiers at 63 *bytes* of UTF-8 (`NAMEDATALEN - 1`),
while the OpenAPI schema's `maxLength` counts *characters* — a 63-character
identifier containing multi-byte characters passes schema validation but
exceeds PostgreSQL's byte limit. Second, the OpenAPI schema cannot bound map
keys, so `config` keys are bounded by CLI/manifest validation only, not by the
API server.

| Field | Limit |
|---|---|
| Identifiers — role, schema, owner, member and profile names | 63 (PostgreSQL's `NAMEDATALEN - 1`, which is 63 *bytes* of UTF-8 and silently truncated by the server; the OpenAPI `maxLength` bound counts characters) |
| Object names, comments, config values | 256 characters |
| `role_pattern` | 128 characters |
| `profiles` | 128 entries, each with ≤ 64 `grants` and ≤ 32 `default_privileges` |
| `schemas` | 1024 entries, each referencing ≤ 64 profiles |
| `roles` | 1024 entries, each with ≤ 32 `config` entries |
| `grants` | 4096 entries, each with ≤ 16 `privileges` |
| `default_privileges` | 512 entries, each with ≤ 64 `grant` entries |
| `memberships` | 2048 entries, each with ≤ 512 `members` |
| `retirements` | 512 entries |

Every object was always bounded, by the ~1.5MiB limit Kubernetes inherits from
etcd — that limit was simply implicit, and produced an opaque
`etcdserver: request is too large` rather than naming the field. Declaring the
bounds is also what makes API-server-enforced immutability possible on
[`PostgresPolicyCandidate`](/docs/operator-candidates): a CEL rule comparing a
whole spec is only admissible if its cost can be estimated from the schema.
