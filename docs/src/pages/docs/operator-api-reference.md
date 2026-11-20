---
title: CRD API reference
description: Generated field descriptions, defaults, and validation for all five pgroles custom resources.
---

Use the [operator quick start](/docs/operator-quick-start) for a working deployment. These references describe the served schemas generated from the source revision used to build this documentation, including nested fields, defaults, requiredness, and CEL admission rules. The site can lead the latest release; compare against the CRDs installed in your cluster or the tagged source for your operator version.

| Resource | Purpose |
| --- | --- |
| [PostgresPolicy](/docs/reference/postgrespolicy-v1alpha1) | Desired database access and reconciliation settings. |
| [PostgresPolicyPlan](/docs/reference/postgrespolicyplan-v1alpha1) | Computed changes, approval decisions, and execution results. |
| [PostgresPolicyCandidate](/docs/reference/postgrespolicycandidate-v1alpha1) | Immutable proposed policy content evaluated before promotion. |
| [EphemeralAccessPolicy](/docs/reference/ephemeralaccesspolicy-v1alpha1) | Requestable membership bundles and approval rules. |
| [EphemeralAccessRequest](/docs/reference/ephemeralaccessrequest-v1alpha1) | Temporary access requests and their lifecycle. |
| [PostgresDatabase](/docs/reference/postgresdatabase-v1alpha1) | Prototype for ADR-002: a shared database, its delegations, and the policies attached to it. Not released. |

Schema validation is only the admission boundary. The controller also checks database state, executor authority, target identity, and lifecycle invariants. Follow [plan approval](/docs/operator-plan-approval), [candidate promotion](/docs/operator-candidates), and [ephemeral access](/docs/ephemeral-access) for those workflows.

For contributors: edit the Rust schema descriptions, regenerate CRDs and run `cargo run --bin crdgen -- --docs-dir docs/src/pages/docs/reference --schemas-dir docs/public/crd-reference`, then run `scripts/check-crd-drift.sh` and `scripts/check-crd-docs.sh`. The documentation generator rejects undocumented spec and status fields. CI checks every generated page, including missing or extra files.
