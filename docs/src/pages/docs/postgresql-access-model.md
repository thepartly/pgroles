---
title: 1. The permission chain
description: Alice's first query at Acme is denied. Follow PostgreSQL's error from gate to gate and open the smallest path that makes the report work.
---

Acme is a small startup with one application and one database. Priya, the founder, created the `app.orders` table herself in the early days, and the application has been reading and writing it ever since—connected, as early applications usually are, with the admin credentials Priya set up at the start. Today Alice joins as the first analyst, hired to answer the company’s favourite question: what did we sell? {% .lead %}

Her report is a single query, and the application runs the same one constantly. But when Alice runs it, PostgreSQL refuses—and that refusal is the best introduction there is to how PostgreSQL decides who may do what.

This course follows Acme’s database as the company grows, one incident per chapter:

- **Priya**, the founder, created the original `app` schema and `orders` table by hand. That detail looks harmless today; it will not stay harmless.
- **The application**, which still connects with the admin credentials from Acme’s first week—the decision that made everything work and hid every problem in this course.
- **Alice**, the first analyst, needs to read orders.
- **deploy**, Acme’s migration login, will matter once the schema starts changing.
- **reporting_app**, an automated reporting service, arrives in the next chapter.

Each chapter has the same rhythm: something happens at Acme, you reproduce it against a real PostgreSQL running in your browser, and then—below the lab—you write down what should stay true. Start where Alice starts:

{% postgres-permission-lab /%}

## Keep one rule

**PostgreSQL must be able to reach the schema and authorize the object operation.**

For this query that reads `app.orders`, schema `USAGE` makes the name reachable and table `SELECT` authorizes the read. `search_path` changes name lookup, not privileges. A table grant does not imply schema access, and schema access does not imply a table operation.

In this query, schema lookup fails before PostgreSQL checks the table privilege. The first error does not list everything that is missing, which is why the same query produced two different errors as each gate opened.

Superusers bypass ordinary privilege checks. Object owners start with ordinary privileges on their objects, but can revoke their own `SELECT` privilege and then fail the same query. They retain ownership rights, including the ability to grant those privileges back. Owning `app.orders` also does not grant access to every schema or other object. Acme's superuser connection hid these missing grants; a scoped login exposes them.

{% callout title="Three similar names, three different mechanisms" %}

`PUBLIC` means every current and future database role when it appears as a grantee. The `public` schema is simply a schema with that name. Predefined roles such as `pg_read_all_data` are built-in PostgreSQL roles with privileged capabilities; membership is how a recipient receives one.

{% /callout %}

The lab shows `session_user → current_user` before and after each run. `session_user` identifies the session; `current_user` is the identity used for permission checks. `SET ROLE` changes `current_user`, and a `SECURITY DEFINER` function temporarily uses its owner's identity while it runs.

## The policy so far

The lab fixed today’s database, and its `GRANT` statements remain durable catalog state. They do not, however, record version-controlled intent about which roles, grants, and memberships should exist. This is where **pgroles** enters the story: you declare that intent in YAML, and `pgroles plan` compares it with the live database and proposes SQL to converge them. Every chapter records its repair this way, and by chapter 3 the difference between “what the database accumulated” and “what the policy declares” becomes the whole plot.

This first policy is the small team’s literal state: Alice receives both grants directly. Priya is declared `external` so pgroles may reference the founder-owned role without managing its attributes yet.

Later lessons show **Policy fragments** to merge into this file. Update entries inside its existing `roles`, `grants`, and `memberships` lists; do not concatenate YAML blocks and create duplicate top-level keys. Each core chapter also links a complete cumulative policy you can use as a replacement.

```yaml {% schema="pgroles-manifest" %}
roles:
  - name: priya
    external: true
  - name: alice
    login: true

grants:
  - role: alice
    privileges: [USAGE]
    object: { type: schema, name: app }
  - role: alice
    privileges: [SELECT]
    object: { type: table, schema: app, name: orders }
```

It works, but every new reader would duplicate those ACL entries. The next chapter gives the permission bundle a reusable name.

[Download the complete policy after this chapter](/examples/acme-policy/chapter-1.yaml).

{% quick-links %}
{% quick-link title="Continue: capability roles" description="Give Alice and an application the same access without copying grants." icon="presets" href="/docs/postgresql-capability-roles" /%}
{% quick-link title="Grants reference" description="See every object type and privilege pgroles manages." icon="plugins" href="/docs/grants" /%}
{% /quick-links %}
