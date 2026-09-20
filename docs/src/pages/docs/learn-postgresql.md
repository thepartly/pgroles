---
title: Learn PostgreSQL roles
description: Understand PostgreSQL access through interactive exercises about roles, ownership, memberships, default privileges, and row-level security.
---

Follow Acme as its first query grows into an access policy that a team can maintain. The exercises run PostgreSQL in your browser; no database setup is required. {% .lead %}

Start with the core story or jump directly to an investigation. Each lab includes its own prepared database, and every Run resets that database, so you can experiment without completing earlier chapters.

## Core story

| Lesson | Question to investigate |
| --- | --- |
| [1. The permission chain](/docs/postgresql-access-model) | Why can Alice connect but not query a table? |
| [2. Capability roles](/docs/postgresql-capability-roles) | How can several identities share scoped access? |
| [3. Access drift](/docs/postgresql-access-drift) | Why does access survive a membership change? |
| [4. Ownership](/docs/postgresql-ownership) | Which identity should own objects created by migrations? |
| [5. Future objects](/docs/postgresql-default-privileges) | Why does a new table lack the grants of an existing table? |
| [6. Offboarding an owner](/docs/postgresql-offboarding) | How can an identity be retired while preserving its objects? |

## Advanced investigations

| Lesson | Question to investigate |
| --- | --- |
| [7. Membership mechanics](/docs/postgresql-role-hierarchy) | How do inheritance, role switching, and membership administration differ? |
| [8. Row-level security](/docs/postgresql-row-security) | Why can two identities query the same table but see different rows? |
| [9. The security review](/docs/postgresql-security-review) | Which unexpected paths still permit an operation? |

## Keep experimenting

The [SQL playground](/docs/postgresql-playground) is a sandbox for the core Acme story. Row-policy exercises have their own [RLS lab](/docs/postgresql-row-security).

Contextual “Explore this change” links open the [plan explorer](/docs/explorer) to explain what pgroles would change and what authority the model requires. The PostgreSQL labs demonstrate actual query behaviour; the explorer does not evaluate row policies.

Ready to use pgroles? Go directly to the [CLI quick start](/docs/quick-start) or [operator quick start](/docs/operator-quick-start). This course is optional.
