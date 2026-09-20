---
title: 3. Access drift
description: Add Bob, remove Alice, and discover why revoking one membership does not prove her report is forbidden.
---

Bob joins reporting and Alice moves to another team. The role hierarchy makes the intended change obvious: add Bob to `orders_reader`, remove Alice. The database has a longer memory. {% .lead %}

{% postgres-access-drift-lab /%}

## Desired state turns the surprise into a plan

Merge Bob's role into chapter 2's policy and replace its `orders_reader` member list with the one below. Retain its other roles and grants. Alice remains a login role, but is no longer a member and has no direct grants in the complete policy:

```yaml {% schema="pgroles-manifest" policy="fragment" %}
roles:
  - name: bob
    login: true

memberships:
  - role: orders_reader
    members:
      - name: bob
      - name: reporting_app
```

An authoritative `pgroles plan` compares that graph with PostgreSQL. Alice’s old `USAGE` and `SELECT` appear as revocations instead of remaining invisible history. Review the exact SQL, then apply it as one transaction.

**Revoking one edge proves only that the edge is gone. Verify that this role can no longer perform the forbidden operation—in this story, Alice selecting from `app.orders`.** A failed report does not prove Alice lacks every other database capability.

[Download the complete policy after this chapter](/examples/acme-policy/chapter-3.yaml).

{% callout type="note" title="Negative tests belong in offboarding" %}
PGlite can prove the authorization result, but it does not model passwords, `pg_hba.conf`, concurrent sessions, or session termination. In production, revoke durable authorization, terminate sessions when required, and verify both. [Netchecks](https://netchecks.io/docs/postgres) can run exactly these positive and negative access assertions continuously from inside your cluster.
{% /callout %}

{% quick-links %}
{% quick-link title="Continue: ownership" description="Let Acme's migration login collide with a founder-owned table." icon="installation" href="/docs/postgresql-ownership" /%}
{% quick-link title="Staged adoption" description="Choose additive or authoritative reconciliation deliberately." icon="presets" href="/docs/adoption" /%}
{% /quick-links %}
