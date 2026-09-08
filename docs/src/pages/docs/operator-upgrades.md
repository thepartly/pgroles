---
title: Upgrading the operator
description: Upgrade version-matched CRDs and the controller, review changed approvals, and verify convergence.
---

Upgrade the API and controller as one reviewed change. {% .lead %}

## Before upgrading

Read the target release's upgrade notes. Save your current chart version, values,
and policy manifests in your deployment repository. Keep database recovery
procedures separate: rolling back a controller does not reverse committed SQL.

Set the exact release you reviewed, for example `VERSION=0.12.0`. Render and review its resources using your existing values:

```bash
VERSION=0.12.0
helm template pgroles-operator oci://ghcr.io/thepartly/charts/pgroles-operator \
  --version "$VERSION" --namespace pgroles-system --include-crds \
  --values values.yaml > operator-rendered.yaml
```

Check the image, resource limits, admission policies, and CRD changes. The API is
`v1alpha1` with no conversion webhook. Do not assume an older controller can read
newer resources or approvals.

## Update CRDs, then the controller

Helm installs CRDs but does not upgrade them. Extract the CRDs from the **same
chart version**, inspect the diff, then apply them before upgrading:

```bash
set -euo pipefail
helm show crds oci://ghcr.io/thepartly/charts/pgroles-operator \
  --version "$VERSION" > operator-crds.yaml
test -s operator-crds.yaml
kubectl diff --server-side -f operator-crds.yaml
```

`kubectl diff` exits 1 when differences exist. After reviewing them, run:

```bash
kubectl apply --server-side -f operator-crds.yaml
helm upgrade pgroles-operator oci://ghcr.io/thepartly/charts/pgroles-operator \
  --version "$VERSION" --namespace pgroles-system --values values.yaml --wait
```

## Moving from 0.11 to 0.12

- CRD schemas are unchanged. Continue using the chart's version-matched CRDs.
- Readiness now requires all watches to finish initial synchronization and clears during relists or shutdown. A policy error does not by itself make the operator unready. Allow time for watch initialization during rollout.
- Candidate planning now preserves undeclared object grants when requested by the proposed role definitions. Review replanned candidates; changed effects remain subject to the usual approval checks, and preserved-only drift yields `NoEffects` without an approval plan.
- Consecutive revokes attributed to the same grantor share a role block without reordering effects. Diagnostic SQL hashes and statement counts can change; the semantic approval digest is independent of SQL formatting.
- Metrics and logs share service-instance identity and standard SDK metadata. Review resource-label mapping and per-replica counter aggregation using the [monitoring guide](/docs/operator-monitoring). Duration units remain milliseconds.
- Default-owner bootstrap preflight now recognizes PostgreSQL 16+ `createrole_self_grant=inherit`. This does not grant authority itself; configure the executor as described in [Executor privileges](/docs/executor-privileges).

## Moving from 0.10 to 0.11

- Apply all five version-matched CRDs before starting the new controller. The
  plan schema adds the optional diagnostic `passwordSourceDigest` field; it
  does not replace the approval digest or authorize execution.
- Wildcard revocations now retain each concrete object's grantor. Plans can
  contain more revoke statements, and changed effects require fresh approval.
  Review replacement plans and the executor's authority to act as each grantor.
- Plan creation now distinguishes interrupted creates from collisions with
  existing plans. Changes to password source versions also replace stale plans; review
  and approve the replacement when manual approval is required.
- A policy-level `role_pattern` now supplies the naming convention for schemas
  that omit their own pattern. Previously ignored top-level patterns in CLI
  manifests now take effect. Review generated role names and the resulting plan
  before applying; keep explicit schema patterns where names must stay unchanged.
  The old Kubernetes API pruned the unsupported policy-level field, so reapply
  it after upgrading the CRDs. Existing resources may also contain schema-level
  patterns inserted by the previous CRD's defaulting. Inspect the live resource:
  those values still override the policy pattern. Remove an override only when
  you intend that schema to inherit the new convention. Inspect outstanding
  candidates and plans after the upgrade; review any replacement plans before
  approving them.
- Reconciliation concurrency still defaults to one. Retain that setting unless
  measurements justify increasing it.

The CLI's new Markdown report fingerprint identifies report content. It is not
an approval digest or a database identity check; approve operator plans through
the existing plan workflow.

## Moving from 0.9 to 0.10

- Open plans need fresh approval because the effect digest encoding changed to
  v3. Inspect replacement plans; old decisions do not transfer.
- Replace deprecated `mode: plan` with `mode: observe`.
- Database grant targets must include `object.name`, matching the connected database.
- Review declared memberships in external roles: they now take effect.
- Adopt-mode schema-owner transfers require a separate explicit opt-in.
- Validate policy size limits and UTC whole-second `password_valid_until` values.
- Update JSON consumers for tagged default-privilege `scope`. Bundle output is
  `pgroles.bundle_plan.v2`; ordinary diff JSON remains unversioned, so pin its
  producer version.

Version 0.10.1 changes each controller's default reconciliation concurrency to
one. Keep that default until measurements support a higher value; see
[running the operator](/docs/operator-operations#reconcile-concurrency).

## Verify after upgrading

For each policy, inspect conditions, observed generation, current plan, and
warnings. For apply-mode convergence, require the observed generation to match,
`Ready=True` with reason `Reconciled`, and `Drifted=False`; no plan should remain
Pending, Approved, or Applying. An Applied plan may remain referenced.

Observe mode and manual approval can legitimately have pending changes. Review
replacement plans before approving, then test allowed and denied operations as
actual service identities. Check operator restarts and inspection latency.

If the upgrade fails, inspect [troubleshooting](/docs/operator-troubleshooting)
before retrying. Reverting the chart alone neither downgrades CRDs nor undoes SQL.
