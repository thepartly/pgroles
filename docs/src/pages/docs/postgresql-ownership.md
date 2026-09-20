---
title: 4. Ownership
description: Watch deploy fail to alter Priya's table, then introduce a durable app_owner role for migrations.
---

Acme’s migration pipeline wants to add a column to `orders`. The grants that make reports work are irrelevant: Priya created the table, so Priya owns it. {% .lead %}

{% postgres-ownership-lab /%}

## A durable production shape

The capability role answers “who may read?” The owner role answers “who may change the objects?” They are different jobs.

```text
Bob / reporting_app ──member of──> orders_reader ──USAGE + SELECT──> app.orders

deploy ──member of──> app_owner ──owns──> app schema and its objects
```

Because the membership inherits, deploy already carries the owner’s authority for owner-only DDL. The migration recipe still uses `SET ROLE app_owner` before creating objects—not to pass the ownership check, but so that everything the migration **creates** belongs to the durable owner rather than to the deployment login.

Add the durable owner and make schema ownership explicit:

```yaml {% schema="pgroles-manifest" %}
roles:
  - name: deploy
    login: true
  - name: app_owner
  - name: orders_reader

schemas:
  - name: app
    owner: app_owner

memberships:
  - role: app_owner
    members:
      - name: deploy
```

pgroles converges the `app` schema owner. It does not change the owner of every table inside the schema; existing objects need a migration or retirement workflow. Future migrations should create objects as `app_owner`.

**Ownership is authority over the object, not another ACL entry. Give it to a durable role, not a person or deployment login.**

The lesson used `SET ROLE app_owner` as a migration recipe so new objects land on the durable owner. The membership-mechanics chapter later takes the edge itself apart: `INHERIT`, `SET`, and `ADMIN` are three separate facts.

{% quick-links %}
{% quick-link title="Continue: future objects" description="Create a new table and see why old wildcard grants do not follow it." icon="installation" href="/docs/postgresql-default-privileges" /%}
{% quick-link title="Executor privileges" description="Check what the pgroles executor needs to transfer ownership." icon="plugins" href="/docs/executor-privileges" /%}
{% /quick-links %}

{% explorer-scenario scenario="acme-default-privileges" /%}
