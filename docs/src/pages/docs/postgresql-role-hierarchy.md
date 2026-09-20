---
title: 7. Membership mechanics
description: Nest Bob behind an analyst job role, then control automatic inheritance, SET ROLE, and delegated membership administration.
---

The core Acme story needed only one membership edge and one migration recipe. Now take the edge itself apart: nested roles, automatic privilege flow, deliberate role switching, and delegation. {% .lead %}

## Follow one directed graph

```text
bob (LOGIN)
      │ member of
      ▼
analyst (NOLOGIN)
      │ member of
      ▼
orders_reader (NOLOGIN) ──> schema USAGE + table SELECT
```

Read `GRANT orders_reader TO analyst` as **analyst becomes a member of orders_reader**. Reversing the names reverses the privilege flow—the lab lets you make that mistake and watch the chain break.

{% postgres-role-hierarchy-lab /%}

## Declare the edges

```yaml {% schema="pgroles-manifest" %}
roles:
  - name: bob
    login: true
  - name: dana
    login: true
  - name: team_lead
    login: true
  - name: analyst
  - name: orders_reader

memberships:
  - role: orders_reader
    members:
      - name: analyst
  - role: analyst
    members:
      - name: bob
        inherit: false
      - name: dana
      - name: team_lead
        inherit: false
        admin: true
```

`INHERIT` answers whether ordinary privileges flow automatically. `SET` answers whether the member may become the granted role. `ADMIN` answers whether the member may grant or revoke that membership for others. These are three separate facts.

{% callout type="warning" title="SET is outside the pgroles model" %}
PostgreSQL 16 and later stores `INHERIT`, `SET`, and `ADMIN` per membership. pgroles manages `inherit` and `admin`, but does not inspect or converge `SET`. A managed edge receives PostgreSQL’s default `SET TRUE`; do not rely on `SET FALSE` remaining a security boundary on that edge.
{% /callout %}

Delegated administration and desired-state reconciliation also answer different questions. When the team lead grants `analyst` to Dana in PostgreSQL, the access is real immediately—but if that edge is absent from policy, the next authoritative pgroles plan treats it as drift. Durable delegation needs a workflow that writes the approved membership back to policy.

Since PostgreSQL 16 each membership edge also records **who granted it**, and [`REVOKE`](https://www.postgresql.org/docs/current/sql-revoke.html) removes only the edge attributed to the revoker: revoking the team lead's grant as anyone else succeeds with just a `WARNING` and leaves Dana's membership in place, unless the revoke runs `GRANTED BY` the team lead with that role's privileges. pgroles revokes each edge `GRANTED BY` its recorded grantor, so reconciling the delegation away works — and the plan preflight names any grantor whose privileges the executor lacks.

The lab exercises a live PostgreSQL role graph. The explorer starts from a sanitized snapshot and shows the ordered planned changes; use it to compare what the policy would change, then return to the lab to prove the resulting database behavior.

{% quick-links %}
{% quick-link title="Continue: same table, different rows" description="Add PostgreSQL row-level policies after the role path is clear." icon="lightbulb" href="/docs/postgresql-row-security" /%}
{% quick-link title="Memberships reference" description="See the complete policy and version behavior." icon="presets" href="/docs/memberships" /%}
{% /quick-links %}

{% explorer-scenario scenario="acme-membership-bridge" /%}
