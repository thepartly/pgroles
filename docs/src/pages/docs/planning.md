---
title: Planning and reconciliation modes
description: Preview a pgroles policy and choose the changes reconciliation may make before applying it.
---

Preview the changes against your database before choosing what to apply. {% .lead %}

## Preview a policy

With `DATABASE_URL` set for the target database, validate the policy and inspect an additive plan:

```bash
pgroles validate -f pgroles.yaml
pgroles diff -f pgroles.yaml --mode additive
```

Validation checks the policy without inspecting a database. `diff` connects to the target and plans changes without applying them. Check [executor privileges](/docs/executor-privileges) when inspection or preflight reports a failure.

## Choose a reconciliation mode

| Mode | Review focus |
| --- | --- |
| `additive` | Add declared access while retaining existing access; revocations and drops are skipped. Start here when adopting an existing database. |
| `adopt` | Reconcile declared roles, including removals, while retaining undeclared roles. Review revoked grants and memberships carefully. |
| `authoritative` | Also allow eligible role drops within the managed scope. Review retirement operations and dependencies. |

These modes control the permitted effects, not whether the executor can perform them. See [staged adoption](/docs/adoption) for a rollout sequence and the [mode reference](/docs/cli#reconciliation-modes) for exact behaviour and ownership-transfer guards.

## Share the review

[Export a recorded review](/docs/recorded-reviews) to share the native plan without giving a reviewer database access. Use the [explorer](/docs/explorer) for browser-local policy authoring and hypothetical comparisons, and the [CI/CD guide](/docs/ci-cd) for automated drift checks.

Operator execution has separate observe/apply and approval gates. Follow [plan and approval](/docs/operator-plan-approval) or [candidates and promotion](/docs/operator-candidates) for those workflows. A native review fingerprint does not approve an operator plan.
