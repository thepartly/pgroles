---
title: The Acme playground
description: Explore the core Acme sandbox with arbitrary SQL and challenge prompts.
---

The playground is the core Acme course sandbox: durable ownership, capability roles, defaults, the nested analyst hierarchy with its delegated administration, Priya’s reassigned legacy objects, and the security-review function. There is no scripted finish. Choose a role, change the query, and follow the evidence. {% .lead %}

{% postgres-acme-playground /%}

## A practical audit loop

1. Name the exact operation and starting role.
2. Run the operation instead of inferring it from one catalog row.
3. Trace every surviving path: membership, schema and object ACLs, ownership, `PUBLIC`, functions, and delegation.
4. Compare PostgreSQL with the desired pgroles graph.
5. Review the plan, apply it, and repeat the operation as a positive or negative test.

The [grants](/docs/grants), [memberships](/docs/memberships), [default privileges](/docs/default-privileges), and [limitations](/docs/limitations) pages are the exhaustive reference. This course stays focused on the operational story that makes those mechanisms worth remembering.

The playground runs real PostgreSQL interactions in your browser. It intentionally does not seed the separate tenant RLS scenario; use [Same table, different rows](/docs/postgresql-row-security) for that lesson. The explorer complements this sandbox by simulating an ordered pgroles plan from a sanitized snapshot; it does not replace live checks.

{% explorer-scenario scenario="acme-membership-bridge" /%}
