---
title: Manifest guide
description: How pgroles manifest sections fit together when designing a policy.
---

A pgroles manifest declares the desired state of PostgreSQL access control: who can log in, which group roles exist, what they can access, and what future objects should inherit. {% .lead %}

---

## The shape of a manifest

Most manifests combine four ideas:

- `roles` define PostgreSQL roles and login attributes
- `grants` define access to current database objects
- `default_privileges` define access for objects created later
- `memberships` connect login roles to group roles

For larger databases, `profiles` and `schemas` remove repetition by expanding one privilege template across many schemas. For field-by-field details, use the [manifest reference](/docs/manifest-reference).

## A complete application example

```yaml
default_owner: app_migrator

profiles:
  app_writer:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        object: { type: table, name: "*" }
      - privileges: [USAGE, SELECT, UPDATE]
        object: { type: sequence, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table
      - privileges: [USAGE, SELECT, UPDATE]
        on_type: sequence

  readonly:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT]
        object: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT]
        on_type: table

schemas:
  - name: app
    owner: app_migrator
    profiles: [app_writer, readonly]

roles:
  - name: app_migrator
    login: true
  - name: app_runtime
    login: true
  - name: analyst
    login: true

memberships:
  - role: app-app_writer
    members:
      - name: app_runtime
  - role: app-readonly
    members:
      - name: analyst
```

This produces two schema-scoped group roles:

- `app-app_writer`, with read/write table access and sequence access in the `app` schema
- `app-readonly`, with read-only table access in the `app` schema

The login roles (`app_runtime`, `analyst`) get access through memberships rather than direct grants. This keeps runtime connection strings stable while letting you change profile grants in one place.

## How the sections connect

| Section | Defines | Referenced by |
|---|---|---|
| [`role_pattern`](/docs/manifest-reference#role-pattern) | Naming convention for generated roles, with per-schema overrides | `profiles`, `schemas` |
| [`default_owner`](/docs/manifest-reference#default-owner) | Default object-creator role for future grants | `default_privileges`, `profiles`, `schemas` |
| [`profiles`](/docs/manifest-reference#profiles) | Reusable schema-relative grant templates | `schemas[].profiles` |
| [`schemas`](/docs/manifest-reference#schemas) | Managed schemas and profile bindings | `profiles`, generated roles, generated grants |
| [`roles`](/docs/manifest-reference#roles) | Explicit PostgreSQL roles | `grants`, `memberships`, `default_privileges` |
| [`grants`](/docs/manifest-reference#grants) | Current object privileges | role names and object targets |
| [`default_privileges`](/docs/manifest-reference#default-privileges) | Future object privileges | owner roles, grantee roles, schemas |
| [`memberships`](/docs/manifest-reference#memberships) | Role inheritance edges | parent roles and member roles |
| [`retirements`](/docs/manifest-reference#retirements) | Safe role removal workflow | roles omitted from desired state |

## Choosing direct grants or profiles

Use direct top-level `grants` for one-off roles or database-level privileges:

```yaml
roles:
  - name: analytics
    login: true

grants:
  - role: analytics
    privileges: [CONNECT]
    object: { type: database, name: mydb }
  - role: analytics
    privileges: [USAGE]
    object: { type: schema, name: reporting }
  - role: analytics
    privileges: [SELECT]
    object: { type: table, schema: reporting, name: "*" }
```

Use profiles when the same access shape repeats across schemas:

```yaml
profiles:
  reader:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT]
        object: { type: table, name: "*" }

schemas:
  - name: inventory
    profiles: [reader]
  - name: catalog
    profiles: [reader]
```

## Declared vs referenced schemas

Declared schemas can be created and have their owner converged by pgroles. Referenced-only schemas must already exist:

```yaml
schemas:
  - name: app_managed
    owner: app_owner
    profiles: []

grants:
  - role: reporting
    privileges: [USAGE]
    object: { type: schema, name: app_managed }

  - role: reporting
    privileges: [SELECT]
    object: { type: table, schema: existing_warehouse, name: "*" }
```

In this example:

- `app_managed` is declared under `schemas:`, so pgroles can create it and set its owner.
- `existing_warehouse` is only referenced from a top-level grant, so it must already exist before `apply` runs.

## Wildcard grants and future objects

Use `name: "*"` to grant on all current objects of a type in a schema. pgroles expands relation wildcards safely by object type, so `table`, `view`, and `materialized_view` privileges do not bleed across each other.

Pair wildcard grants with `default_privileges` when the same role should access future objects created by the migration or owner role. Wildcards cover existing objects at reconcile time; default privileges cover objects created later.

{% callout type="note" title="Managed owners still need declared privileges" %}
pgroles preserves existing owner-held ACL entries during reconciliation. Declare owner privileges when you want missing privileges restored; do not use manifest omission to remove ownership authority.
{% /callout %}

## Convergent model

{% callout type="warning" title="pgroles is convergent" %}
The manifest declares desired state within pgroles’ managed scope. Reconciliation mode determines which changes are permitted, while external roles, PUBLIC rules and preservation settings introduce additional boundaries. Review the complete plan before applying.
{% /callout %}

Next: use the [manifest reference](/docs/manifest-reference) for exact field names, defaults, and bundle-mode details.
