---
title: 2. Capability roles
description: Replace copied grants with an orders_reader capability role and expose Alice's duplicate access path.
---

Acme launches an automated reporting service. It needs exactly the access Alice already has, but copying Alice’s grants onto another login will make every team change harder to audit. And this time nobody suggests reusing the admin credentials—`reporting_app` becomes the first login at Acme whose access is actually designed. {% .lead %}

{% postgres-capability-roles-lab /%}

## Put privileges on jobs, not people

`orders_reader` cannot log in. It names one capability: reach `app`, then read `app.orders`. Alice and `reporting_app` receive that capability through membership.

PostgreSQL also supplies predefined capabilities, but they serve different jobs. `pg_read_all_data` and `pg_write_all_data` provide broad data access across schemas, without bypassing row-level security; they are much broader than this application's need to read only `app.orders`. A monitoring agent may appropriately use `pg_monitor` or one of its narrower monitoring roles to inspect database activity without gaining blanket access to business tables. Choose a capability by the job it must do. The [security review](/docs/postgresql-security-review#review-predefined-roles-by-capability) compares these categories with the special database-owner role and higher-risk server capabilities.

```yaml {% schema="pgroles-manifest" %}
roles:
  - name: alice
    login: true
  - name: reporting_app
    login: true
  - name: orders_reader

grants:
  - role: orders_reader
    privileges: [USAGE]
    object: { type: schema, name: app }
  - role: orders_reader
    privileges: [SELECT]
    object: { type: table, schema: app, name: orders }

memberships:
  - role: orders_reader
    members:
      - name: alice
      - name: reporting_app
```

The lesson deliberately left Alice’s original direct grants in the database. The desired policy no longer declares them. That difference becomes the bug in the next chapter—and the reason a declarative plan is more useful than a pile of successful `GRANT` statements.

**A membership adds a path; it does not erase any path that already exists.**

{% quick-links %}
{% quick-link title="Continue: drift" description="Change the team and watch an old direct grant defeat the intended offboarding." icon="lightbulb" href="/docs/postgresql-access-drift" /%}
{% quick-link title="Memberships reference" description="See pgroles membership syntax and reconciliation behavior." icon="presets" href="/docs/memberships" /%}
{% /quick-links %}
