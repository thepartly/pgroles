---
title: Grants & privileges
description: How pgroles manages object privileges via GRANT and REVOKE statements.
---

Grants define direct ACL entries for roles on database objects. pgroles supports granting on specific objects, all objects of a type in a schema, schemas themselves, and databases. {% .lead %}

---

## Grant syntax

```yaml
grants:
  - role: analytics
    privileges: [SELECT]
    object:
      type: table
      schema: public
      name: "*"
```

The preferred key is `object`. pgroles still accepts a quoted legacy `"on"` key when parsing older manifests, but new manifests should use `object` to avoid YAML 1.1 boolean coercion.

## Function signatures

Name individual functions and procedures by their input argument types:

```yaml
grants:
  - role: app_runtime
    privileges: [EXECUTE]
    object:
      type: function
      schema: app
      name: "backoff_duration(smallint, smallint)"
```

Parameter names, defaults, and output-only arguments are not part of PostgreSQL's
routine identity. Include the input type of `INOUT` arguments and the array type
of variadic arguments. Schema-qualify custom types when necessary.

Live inspection resolves type aliases through PostgreSQL (`int2` and `smallint`,
for example) and accepts the catalog's named-argument signatures emitted by
older `pgroles generate` versions, spelled exactly as
`pg_get_function_identity_arguments` formats them. New exports use input types
only. Equivalent spellings converge to one target; opposite present/absent rules
for that target are rejected during inspection, before apply. Offline validation
cannot resolve catalog identities. Bare names resolve only when the routine is
unambiguous.

A target that PostgreSQL cannot resolve fails inspection for the policy that
names it and lists the input-type signatures of routines with that name in the
schema. This covers an ambiguous bare name, a named-argument signature spelled
differently from the catalog, and an `ensure: present` rule for a routine that
does not exist. An `ensure: absent` rule for a routine that does not exist is
already satisfied.

## Privilege types

| Privilege | Applies to |
|---|---|
| `SELECT` | tables, views, sequences |
| `INSERT` | tables |
| `UPDATE` | tables, sequences |
| `DELETE` | tables |
| `TRUNCATE` | tables |
| `REFERENCES` | tables |
| `TRIGGER` | tables |
| `EXECUTE` | functions and procedures (`function` targets render as PostgreSQL routines) |
| `USAGE` | schemas, sequences, types |
| `CREATE` | schemas, databases |
| `CONNECT` | databases |
| `TEMPORARY` | databases |

## Grant targets

### Schema-level

Grant privileges on the schema itself (e.g. `USAGE` to allow accessing objects within it):

```yaml
grants:
  - role: analytics
    privileges: [USAGE]
    object: { type: schema, name: public }
```

Generates: `GRANT USAGE ON SCHEMA "public" TO "analytics";`

Schema `USAGE` is a separate namespace gate. A table grant does not imply it, and putting a schema in `search_path` grants no access. The [PostgreSQL access course](/docs/postgresql-access-model#keep-one-rule) makes both gates runnable.

### Database-level

```yaml
grants:
  - role: analytics
    privileges: [CONNECT]
    object: { type: database, name: mydb }
```

Generates: `GRANT CONNECT ON DATABASE "mydb" TO "analytics";`

Database targets are deliberately concrete: `name` is required and must equal
the database named by the current connection (`current_database()`). pgroles
inspects and reconciles only that database's ACL. A different name fails before
planning instead of emitting SQL against a database the connection did not
inspect.

### Wildcard (all objects of a type in schema)

Use `name: "*"` to grant on all existing objects of a type:

```yaml
grants:
  - role: analytics
    privileges: [SELECT]
    object: { type: table, schema: public, name: "*" }
```

pgroles expands wildcard relation grants against the current objects of the
requested type in that schema. That keeps `table`, `view`, and
`materialized_view` grants scoped correctly instead of letting one subtype
touch the others.

If a schema has no objects of the declared type (e.g. no sequences yet), the wildcard grant is treated as vacuously satisfied — pgroles will not re-issue the statement on subsequent reconciles. When objects are later added, the next reconcile detects the new objects and applies the appropriate grants.

Wildcard grants are strict desired state. `name: "*"` means every matching
current object in the schema, not only the objects the current executor happens
to own. During `diff`, `plan`, and `apply`, pgroles checks whether each missing
wildcard privilege is grantable by the connected database user. If a matching
object is missing the requested privilege and the executor lacks the matching
`WITH GRANT OPTION`, pgroles stops with `UnsatisfiableWildcardGrant` instead of
printing or applying a wildcard `GRANT` that would churn on every reconcile.

The diagnostic includes the role, object type, schema, requested privileges,
executor, skipped object count, and example object names with owners. To resolve
it, run pgroles as a role that can grant the requested privileges on every
matching object, transfer ownership, grant the executor the needed grant option,
or narrow the manifest to objects that are intentionally managed by that
executor.

### Specific object

```yaml
grants:
  - role: analytics
    privileges: [SELECT]
    object: { type: table, schema: public, name: users }
```

Generates: `GRANT SELECT ON TABLE "public"."users" TO "analytics";`

## Privilege merging

If multiple grant entries target the same role and object, their privileges are merged:

```yaml
grants:
  - role: app
    privileges: [SELECT]
    object: { type: table, schema: public, name: "*" }
  - role: app
    privileges: [INSERT, UPDATE]
    object: { type: table, schema: public, name: "*" }
```

This is equivalent to granting `SELECT, INSERT, UPDATE` on all tables.

## Convergent revocation

Privileges present in the database but absent from the manifest are revoked. If a role has `DELETE` on a table but your manifest only grants `SELECT`, pgroles will generate a `REVOKE DELETE` statement.

Revocation is driven by the manifest as a whole, so removing a grant entry is
enough to revoke it. `PUBLIC` is the exception, described below.

## Asserting a privilege is absent

Some privileges exist without anyone granting them. PostgreSQL gives `EXECUTE`
on every function to `PUBLIC`, `USAGE` on every type to `PUBLIC`, and `CONNECT`
plus `TEMPORARY` on the database to `PUBLIC`. There is no ACL entry to delete,
so leaving them out of the manifest changes nothing.

`ensure: absent` states that a privilege must not exist:

```yaml
grants:
  - role: PUBLIC
    ensure: absent
    privileges: [EXECUTE]
    object: { type: function, schema: privileged_api, name: "*" }
```

```sql
REVOKE EXECUTE ON ALL ROUTINES IN SCHEMA "privileged_api" FROM PUBLIC;
```

Every grant entry carries `ensure`, which defaults to `present`. An absent rule
revokes only the privileges it lists, and only where they are actually held. If
nothing holds them, it plans nothing.

`additive` reconciliation never revokes, so it ignores every `ensure: absent`
assertion and emits a warning. Use `adopt` or `authoritative` when absence must
be enforced.

`ensure: absent` is not a PostgreSQL deny. It controls one ACL edge. A role that
also reaches the object through membership or ownership still reaches it.

Use `ensure: absent` on the objects that exist today, and pair it with a global
default-privilege rule for the objects created tomorrow. See
[Default privileges](/docs/default-privileges#removing-public-privileges).

## PUBLIC

`PUBLIC` is the PostgreSQL pseudo-role that every role belongs to. Write it as
the exact uppercase value `PUBLIC` in a `role:` field:

```yaml
grants:
  - role: PUBLIC
    privileges: [USAGE]
    object: { type: schema, name: public_api }
```

The name is reserved. pgroles rejects a manifest that declares a role, a
membership, a retirement, a schema owner, or a default-privilege owner called
`PUBLIC`. A role whose name merely resembles the keyword is an ordinary role and
is quoted as one in the generated SQL.

pgroles manages a `PUBLIC` privilege only where a rule names it. This differs
from ordinary roles:

- A `PUBLIC` privilege no rule mentions is left alone, even in authoritative
  mode. Databases are full of `PUBLIC` grants that extensions and PostgreSQL
  itself created, and revoking them wholesale would break things pgroles was
  never asked to manage.
- Deleting a `present` rule for `PUBLIC` therefore does not revoke anything.
  Change it to `ensure: absent` when you want the privilege gone.

`pgroles generate` never emits `PUBLIC` rules or `ensure: absent`. A privilege
that happens to be missing today is not evidence you want pgroles to keep it
missing.

{% callout title="Migrations still matter" %}
Reconciliation is not part of your migration transaction. A function created
between two pgroles runs carries the built-in `PUBLIC EXECUTE` until the next
run. Apply the global default rule before the migration that creates the
function, or revoke inside the migration itself.
{% /callout %}

This converges the managed direct ACL, not every way PostgreSQL can authorize a
role. The role might still reach the privilege through membership, ownership,
or `PUBLIC`. pgroles also does not model `WITH GRANT OPTION` for application
grantees; the executor grantability check described above is a safety preflight,
not desired-state management of those grant options. See
[The permission chain](/docs/postgresql-access-model#keep-one-rule)
and [Limitations](/docs/limitations#grant-options-and-effective-access).
