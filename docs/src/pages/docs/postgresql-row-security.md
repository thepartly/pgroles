---
title: 8. Same table, different rows
description: Two tenant logins receive the same table grant, then row-level security limits each to its own orders.
---

Acme has one `app.orders` table and two tenant-facing applications. Both need to read orders. A table grant opens the table, but it cannot decide which rows either application may see. PostgreSQL row-level security (RLS) adds that second decision. {% .lead %}

{% postgres-row-security-lab /%}

## Policy is another permission gate

Define and maintain the row policy in a SQL migration. This SQL example includes ordinary grants to show both permission gates. The policy names the roles and checks `current_user`, so the visible customer is tied to the active database identity.

```sql
GRANT USAGE ON SCHEMA app TO acme_app, globex_app;
GRANT SELECT, INSERT, UPDATE ON app.orders TO acme_app, globex_app;

ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_rows ON app.orders
  FOR ALL TO acme_app, globex_app
  USING (
    (current_user = 'acme_app' AND customer = 'Acme')
    OR (current_user = 'globex_app' AND customer = 'Globex')
  )
  WITH CHECK (
    (current_user = 'acme_app' AND customer = 'Acme')
    OR (current_user = 'globex_app' AND customer = 'Globex')
  );
```

pgroles manages the surrounding roles and grants through this manifest:

```yaml {% schema="pgroles-manifest" %}
roles:
  - name: acme_app
    login: true
  - name: globex_app
    login: true

grants:
  - role: acme_app
    privileges: [USAGE]
    object: { type: schema, name: app }
  - role: acme_app
    privileges: [SELECT, INSERT, UPDATE]
    object: { type: table, schema: app, name: orders }
  - role: globex_app
    privileges: [USAGE]
    object: { type: schema, name: app }
  - role: globex_app
    privileges: [SELECT, INSERT, UPDATE]
    object: { type: table, schema: app, name: orders }
```

`USING` filters existing rows that a command may see or change. `WITH CHECK` tests the proposed values of an `INSERT` or `UPDATE`, rejecting a cross-tenant value. PostgreSQL documents the distinctions in [row security policies](https://www.postgresql.org/docs/18/ddl-rowsecurity.html) and [`CREATE POLICY`](https://www.postgresql.org/docs/18/sql-createpolicy.html).

pgroles does not model, inspect, or apply RLS policies. Keep the `ALTER TABLE` and `CREATE POLICY` statements in migrations, and test them in PostgreSQL. The plan explorer can show the role and grant changes from a [snapshot you prepare and scrub](/docs/explorer-snapshots); its graph cannot guarantee which rows an RLS policy will return.

## Test the identity, not a supplied tenant value

Run the same query as each login and assert that `acme_app` sees only Acme rows while `globex_app` sees only Globex rows. A shared login whose caller supplies a tenant value is not authentication: a caller can choose a different value unless another trusted boundary binds it to identity.

Table owners normally bypass RLS. `ALTER TABLE ... FORCE ROW LEVEL SECURITY` subjects an owner to policy evaluation, but it does not constrain superusers or roles with `BYPASSRLS`; use scoped test logins for these assertions. A table with RLS enabled and no applicable policy is default-deny for ordinary roles.

FORCE makes ordinary owner queries obey RLS, but it does not remove the owner's ability to change or disable it. Keep application roles separate from table ownership and policy administration.

## Optional challenges

Use the “Query as Acme” step, which starts with `tenant_rows` installed. Select the database superuser to change policies, then use `SET ROLE acme_app` for the query. Put the policy changes and verification in the same script: every Run starts a fresh database.

Add another permissive `SELECT` policy for `acme_app` that permits Globex rows:

```sql
CREATE POLICY extra_customer ON app.orders
  FOR SELECT TO acme_app
  USING (customer = 'Globex');
```

Run the `SELECT` again as `acme_app`: it now sees both customers.

Only applicable policies participate: permissive policies combine with `OR`, while restrictive policies constrain them through `AND`. Add a restrictive policy for the same role and command:

```sql
CREATE POLICY acme_boundary ON app.orders
  AS RESTRICTIVE FOR SELECT TO acme_app
  USING (customer = 'Acme');
```

Remove every applicable permissive policy and verify that restrictive policies alone allow zero rows.

Try replacing the two logins with one shared login and a caller-supplied tenant setting. That setting is freely chosen input, not authentication, unless a trusted boundary binds it to the caller's identity.

{% quick-links %}
{% quick-link title="Continue: security review" description="Trace effective access through PUBLIC, delegation, and predefined roles." icon="lightbulb" href="/docs/postgresql-security-review" /%}
{% quick-link title="Memberships" description="See how PostgreSQL role membership changes a login's usable authority." icon="presets" href="/docs/memberships" /%}
{% /quick-links %}
