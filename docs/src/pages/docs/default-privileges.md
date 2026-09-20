---
title: Default privileges
description: Configure privileges that are automatically granted on newly created objects.
---

Default privileges control what privileges are automatically granted when new objects are created. This ensures that roles get access to tables, sequences, and functions created after the initial grant. {% .lead %}

---

## Why default privileges?

Wildcard grants like `GRANT SELECT ON ALL TABLES IN SCHEMA` only apply to objects that exist when the grant runs. When a schema change creates a new table later, existing roles won't have access to it unless you re-run the grant.

`ALTER DEFAULT PRIVILEGES` solves this by configuring automatic grants for future objects.

## Syntax

```yaml
default_owner: app_owner

default_privileges:
  - owner: app_owner
    schema: public
    grant:
      - role: analytics
        privileges: [SELECT]
        on_type: table
      - role: analytics
        privileges: [USAGE, SELECT]
        on_type: sequence
```

This generates:

```sql
ALTER DEFAULT PRIVILEGES FOR ROLE "app_owner"
  IN SCHEMA "public"
  GRANT SELECT ON TABLES TO "analytics";

ALTER DEFAULT PRIVILEGES FOR ROLE "app_owner"
  IN SCHEMA "public"
  GRANT SELECT, USAGE ON SEQUENCES TO "analytics";
```

## Scope: one schema or the whole database

The `schema:` field above is shorthand. The long form names a scope explicitly:

```yaml
default_privileges:
  # These two entries mean the same thing.
  - owner: app_owner
    schema: public
    grant: [...]

  - owner: app_owner
    scope: { type: schema, schema: public }
    grant: [...]
```

Global scope has no schema at all. It sets the owner's defaults for every
schema in the database:

```yaml
default_privileges:
  - owner: app_owner
    scope: { type: global }
    grant:
      - role: analytics
        privileges: [SELECT]
        on_type: table
```

```sql
ALTER DEFAULT PRIVILEGES FOR ROLE "app_owner"
  GRANT SELECT ON TABLES TO "analytics";
```

An entry must set either `schema` or `scope`, never both and never neither.

PostgreSQL layers the two. The global rule applies everywhere, and a
schema-scoped rule adds to it for that one schema. A schema-scoped rule cannot
subtract a privilege the global layer grants, which matters when you remove
`PUBLIC EXECUTE`. See [Removing PUBLIC privileges](#removing-public-privileges).

Global scope accepts `on_type: schema` as well as table, sequence, function,
and type. Schema scope accepts everything except `schema`, because a schema is
not contained in another schema. PostgreSQL has no database-level default
privileges, so `on_type: database` is rejected in both.

`pg_default_acl` records views and materialized views as plain tables, so
declare `on_type: table` for them. pgroles rejects `on_type: view` here rather
than emit a rule that could never converge.

{% callout type="warning" title="Global rules reach every schema" %}
A global rule affects every schema in the database, including ones no policy
manages. `pgroles diff` counts global changes on their own line so they stand
out in a plan.
{% /callout %}

## Removing PUBLIC privileges

PostgreSQL grants `EXECUTE` on every new function to `PUBLIC`, and it does so
without writing an ACL entry. Granting `EXECUTE` to the roles you intend
therefore does not stop anyone else from calling the function.

Write `ensure: absent` to assert that a privilege must not exist:

```yaml
grants:
  # Existing routines.
  - role: PUBLIC
    ensure: absent
    privileges: [EXECUTE]
    object: { type: function, schema: privileged_api, name: "*" }

default_privileges:
  # Future routines, everywhere this owner creates them.
  - owner: function_owner
    scope: { type: global }
    grant:
      - role: PUBLIC
        ensure: absent
        privileges: [EXECUTE]
        on_type: function

  # Defend one schema against a later schema-scoped re-grant.
  - owner: function_owner
    scope: { type: schema, schema: privileged_api }
    grant:
      - role: PUBLIC
        ensure: absent
        privileges: [EXECUTE]
        on_type: function
```

`additive` reconciliation never revokes, so it ignores default-privilege
absence assertions and emits a warning. Use `adopt` or `authoritative` to
enforce them.

The global rule is what removes PostgreSQL's built-in default. The
schema-scoped rule cannot do that on its own, because schema defaults add to
the global layer instead of subtracting from it. Its job is to remove a
schema-scoped `GRANT ... TO PUBLIC` if one appears later.

The inverse works too. Remove the privilege globally, then hand it back in one
schema:

```yaml
default_privileges:
  - owner: function_owner
    scope: { type: global }
    grant:
      - role: PUBLIC
        ensure: absent
        privileges: [EXECUTE]
        on_type: function
  - owner: function_owner
    scope: { type: schema, schema: public_api }
    grant:
      - role: PUBLIC
        privileges: [EXECUTE]
        on_type: function
```

Read [Grants](/docs/grants) for `ensure: absent` on existing objects, and for
what pgroles does and does not manage about `PUBLIC`. The complete worked
manifest is
[examples/security-definer-api.yaml](https://github.com/thepartly/pgroles/blob/main/examples/security-definer-api.yaml).

## Owner context

The `owner` field specifies which role's object creation triggers the default grant. This is typically the role that creates tables, such as `app_migrator` or `app_owner`.

PostgreSQL uses the defaults of the **current role that creates the object**. It does not combine defaults from roles that the creator merely belongs to. If migrations connect as `app_migrator` but the defaults belong to `app_owner`, the migration must `SET ROLE app_owner` before creating the object (or the defaults must be declared for `app_migrator`).

If `owner` is omitted on a default privilege entry, the top-level `default_owner` is used. If neither is set, it falls back to `postgres`.

The executor must already be able to act as the owner. A non-superuser cannot
gain that authority merely because the same plan creates the owner: PostgreSQL
grants `ADMIN OPTION`, not membership, to a `CREATEROLE` role that creates
another role. Pre-create the owner and grant the executor membership, use a
two-stage bootstrap, or use a superuser for the atomic create-and-defaults
bootstrap.

{% explorer-scenario scenario="acme-default-privileges" /%}

## Default privileges in profiles

When using profiles, default privileges are expanded automatically:

```yaml
profiles:
  viewer:
    grants:
      - privileges: [SELECT]
        object: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT]
        on_type: table

schemas:
  - name: inventory
    profiles: [viewer]
```

This generates a default privilege rule for `inventory-viewer` on tables in the `inventory` schema, using the `default_owner` as the owner context.

{% callout title="Pair wildcards with defaults" %}
It's good practice to pair wildcard grants (`name: "*"`) with matching default privileges. The wildcard covers existing objects; the default privilege covers future ones.
{% /callout %}

{% callout title="Tables are not enough" %}
If a role writes to tables created after pgroles runs, check whether it also needs sequence and function defaults. Identity/serial-backed inserts typically need sequence access, and trigger-driven schemas often need `EXECUTE` on functions too.
{% /callout %}

{% callout type="warning" title="Global defaults need an explicit owner" %}
pgroles manages declared schema and global default privileges for named roles and `PUBLIC`. A global rule affects every schema where that owner creates objects, so only the policy document that owns the creating role may declare it. PostgreSQL adds schema-scoped defaults to global defaults; a schema rule cannot subtract a privilege supplied globally. Use a global `ensure: absent` rule to remove the built-in `PUBLIC EXECUTE` default for future routines.
{% /callout %}
