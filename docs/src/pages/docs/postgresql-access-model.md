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

For a query that reads `app.orders`, schema `USAGE` makes the name reachable and table `SELECT` authorizes the read. `search_path` changes name lookup, not privileges. A table grant does not imply schema access, and schema access does not imply a table operation.

The gates are evaluated in order, and the error names the first gate that failed—not everything that is missing. That is why the same query produced two different errors in the lab as each gate opened.

Superusers bypass ordinary privilege checks. Object owners start with ordinary privileges on their objects, but can revoke their own `SELECT` privilege and then fail the same query. They retain ownership rights, including the ability to grant those privileges back. Owning `app.orders` also does not grant access to every schema or other object. Acme's superuser connection hid these missing grants; a scoped login exposes them.

{% callout title="Three similar names, three different mechanisms" %}

`PUBLIC` means every current and future database role when it appears as a grantee. The `public` schema is simply a schema with that name. Predefined roles such as `pg_read_all_data` are named capability roles that users receive through membership.

{% /callout %}

The lab shows `session_user → current_user` before and after each run. `session_user` identifies the session; `current_user` is the identity used for permission checks. `SET ROLE` changes `current_user`, and a `SECURITY DEFINER` function temporarily uses its owner's identity while it runs.

## The policy so far

The lab fixed today’s database, but the two `GRANT` statements you ran live only in PostgreSQL’s catalogs now—invisible history the moment your session ends. This is where **pgroles** enters the story: you describe the roles, grants, and memberships that *should* exist in a YAML policy, and `pgroles plan` compares that intent with the live database and proposes the exact SQL to converge them. Every chapter ends by recording its repair this way, and by chapter 3 the difference between “what the database accumulated” and “what the policy declares” becomes the whole plot.

This first policy is the small team’s literal state: Alice receives both grants directly.

```yaml {% schema="pgroles-manifest" %}
roles:
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

{% quick-links %}
{% quick-link title="Continue: capability roles" description="Give Alice and an application the same access without copying grants." icon="presets" href="/docs/postgresql-capability-roles" /%}
{% quick-link title="Grants reference" description="See every object type and privilege pgroles manages." icon="plugins" href="/docs/grants" /%}
{% /quick-links %}
