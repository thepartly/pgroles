---
title: Recorded reviews
description: Export a native pgroles plan and review it locally in the explorer without database access.
---

Review the changes from one CLI planning run without recalculating them in the browser. {% .lead %}

## Export once

With `DATABASE_URL` set for the target database, export a review alongside the normal output:

```bash
pgroles diff -f pgroles.yaml --mode adopt --format markdown \
  --review-out review.pgroles.json --target-label staging \
  --policy-commit "$(git rev-parse HEAD)" \
  --no-exit-code > review.md
```

## Open the recorded plan

Open the [explorer](/docs/explorer), choose **Open recorded review**, and select
`review.pgroles.json`. It displays
the CLI's recorded changes, SQL preview, phase analysis, findings, managed scope,
provenance, and preflight evidence. Opening the file neither connects to a
database nor recalculates the plan with the browser's current WASM version.
Markdown and the artifact come from the same planning run.
The viewer displays recorded provenance and fingerprints without authenticating
the file; obtain review artifacts from a trusted source, such as your CI run.

## Understand omissions and evidence

The exporter creates recorded reviews without exploration inputs. It
omits password values, role configuration values, and comments, and records
the omissions. Redacted values do not mean absent values. These files cannot
be replanned exactly; use a separately sanitized snapshot to explore a new,
hypothetical variation. If any change contains sensitive values, the
exporter omits the entire SQL preview rather than inserting executable
placeholder values.

Artifacts retain role and object names, managed scope, and supplied labels.
Review this metadata before sharing. Use `--policy-commit` to record a source
revision and `--executor-role` to identify the intended applying identity.
That executor label does not impersonate the role: live preflight evidence
collected as the inspecting connection identity does not verify a different executor.
The policy content digest covers the original YAML bytes for a single manifest,
or the serialized composed manifest for a bundle.
Authority evidence identifies the targeted checks' coverage and unchecked
changes. Finding no issue in those checks does not establish authority for the
whole plan. Native phase analysis marks its scoped authority graph as incomplete:
a missing path is unknown, rather than proof that the executor cannot reach a
role. Live preflight failures remain separate from that modelled uncertainty.

## Before deployment

Neither review fingerprints nor explorer fingerprints are approval tokens.
At deployment, inspect current database state again, run live preflight, and
use the supported approval/execution contract.
For operator approvals, use [plan and approval](/docs/operator-plan-approval) or
[candidates and promotion](/docs/operator-candidates). For automated reports, use
the [CI recipe](/docs/ci-cd#diff-as-a-pr-comment).
