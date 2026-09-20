---
title: 5. Future objects
description: Break the report with a new table, then align the creating role, ownership, existing grants, and default privileges.
---

Refunds launches. Deploy creates `app.refunds`, but the report immediately fails. Nothing removed the working grants on `orders`; the new object simply never received them. {% .lead %}

{% postgres-default-privileges-lab /%}

## Existing objects and future objects are separate problems

- A wildcard object grant covers matching objects that exist when reconciliation runs.
- A default privilege changes what a particular owner grants when that owner creates a future object.
- PostgreSQL looks at the `current_user` that creates the object. Creating as `deploy` does not use `app_owner`'s defaults merely because `app_owner` owns the schema; creating after `SET ROLE app_owner` does.

Merge these entries into chapter 4's policy. Replace the reader's table-specific `orders` grant with the wildcard below, retaining schema `USAGE`, all role definitions, and existing memberships. Add the default privilege rule:

```yaml {% schema="pgroles-manifest" policy="fragment" %}
default_owner: app_owner

grants:
  - role: orders_reader
    privileges: [SELECT]
    object: { type: table, schema: app, name: "*" }

default_privileges:
  - owner: app_owner
    scope: { type: schema, schema: app }
    grant:
      - role: orders_reader
        privileges: [SELECT]
        on_type: table
```

The wildcard repairs and maintains existing tables. The default covers tables created later by `app_owner`. Neither substitutes for the other.

The lab compares both cases after installing the same default: a table created as `deploy` does not receive it, while a table created with `current_user = app_owner` does. Ownership transfers are not retroactive creation events, so moving an old table to `app_owner` does not apply the default either.

**At creation time, PostgreSQL applies the defaults configured for `current_user`, including the relevant schema-specific defaults. Inheriting another role's privileges does not inherit its default privileges.**

[Download the complete policy after this chapter](/examples/acme-policy/chapter-5.yaml).

{% quick-links %}
{% quick-link title="Continue: offboarding" description="Use the durable owner to remove Priya without deleting her objects." icon="lightbulb" href="/docs/postgresql-offboarding" /%}
{% quick-link title="Default privileges reference" description="See schema and global scopes, PUBLIC defaults, and object types." icon="installation" href="/docs/default-privileges" /%}
{% /quick-links %}
