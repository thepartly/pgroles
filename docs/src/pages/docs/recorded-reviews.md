---
title: Recorded reviews
description: Export a native pgroles plan and review it locally in the explorer without database access.
---

Review the changes from one CLI planning run without recalculating them in the browser. {% .lead %}

## Export once

**Requires pgroles v0.13.0 or later.** Earlier binaries reject `--review-out`
as a usage error. Check your installed binary with `pgroles --version`.

With `DATABASE_URL` set for the target database, export a review alongside the normal output:

```bash
pgroles diff -f pgroles.yaml --mode adopt --format markdown \
  --review-out review.pgroles.json --target-label staging \
  --policy-commit "$(git rev-parse HEAD)" \
  --no-exit-code > review.md
```

`--review-out` works with every output format. The artifact never reads
`password.from_env` variables; only the `sql`, `json`, and `summary` formats
require them. `--target-label` names the environment for reviewers and rejects
values containing `://`, so a connection URL is never recorded.

The command prints `Recorded review written to review.pgroles.json (review
fingerprint sha256:…)` to stderr, and the Markdown report ends with the same
fingerprint. Compare it with the fingerprint the explorer shows after import to
confirm a report and a file come from the same run. If the file cannot be
written, the report is still printed and the command exits with code 1, even
with `--no-exit-code`.

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
be replanned exactly; use a separately [sanitized snapshot](/docs/explorer-snapshots)
to explore a new, hypothetical variation. If any change contains sensitive values, the
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

## File format

Recorded reviews use schema `pgroles.review-artifact.v2`, described by the
generated [JSON Schema](/generated/review-artifact.schema.json). Version 2
records each phase's executor reachability as changes from the previous phase,
so large plans stay within the 4 MiB import limit. Re-export files written by
earlier development builds (`pgroles.review-artifact.v1`).

## Before deployment

Neither review fingerprints nor explorer fingerprints are approval tokens.
At deployment, inspect current database state again, run live preflight, and
use the supported approval/execution contract.
For operator approvals, use [plan and approval](/docs/operator-plan-approval) or
[candidates and promotion](/docs/operator-candidates). For automated reports, use
the [CI recipe](/docs/ci-cd#diff-as-a-pr-comment).
