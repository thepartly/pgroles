---
title: Bundle composition
description: When to compose policy bundles, and how to feed them to the CLI or operator.
---

A policy bundle is one root file plus multiple scoped policy fragments that pgroles composes into a single effective `PolicyManifest`, with ownership boundaries validated up front. Use bundles when different teams or environments own different parts of the same database policy and you want composition-time conflict detection rather than late-binding merges. {% .lead %}

---

## When to use which workflow

pgroles offers three workflows for managing a `PostgresPolicy`. Pick one per database and stick with it — mixing them is supported but creates ambiguity about who owns what.

| Workflow | Best for | Composition validated at | Operator-compatible |
|---|---|---|---|
| **Single manifest** | Small/medium setups, one owner per database | N/A (no composition) | Yes — write the manifest under `spec:` directly |
| **CLI bundle, direct apply** | Multi-team DBs reconciled via the CLI (e.g. local compose, ad-hoc admin) | `pgroles diff` / `apply` time | No — the CLI talks directly to the database |
| **CLI bundle, rendered for operator** | Multi-team or multi-environment DBs reconciled by the operator | CI time, via `pgroles render-bundle --check` | Yes — render in CI, commit the flat manifest, wrap under `PostgresPolicy.spec` |

The CLI validates bundle composition before it touches the database. The operator accepts only a flat manifest in `PostgresPolicy.spec`, so `render-bundle` moves composition validation into CI and lets the operator reconcile an already-composed manifest. That keeps the operator's existing one-policy-per-database guarantee intact while still giving fragment authors independent files to own.

## Why pre-render for the operator?

The `PostgresPolicy` CRD inlines the manifest fields under `spec` — `roles`, `grants`, `profiles`, and so on — alongside `connection`. The operator does not load policy fragments at reconcile time. To benefit from bundle composition under the operator, you compose ahead of time and commit the result:

```text
bundle.yaml    ─┐
platform.yaml  ─┼─► pgroles render-bundle ─► pgroles.yaml ─► PostgresPolicy.spec
app.yaml       ─┘
```

This keeps three properties:

1. **Fragment authors own their own files.** App teams edit `app.yaml`, the platform team edits `platform.yaml`. Neither needs write access to the other's file.
2. **Conflicts are caught in CI.** `pgroles render-bundle --check pgroles.yaml` fails the build if the bundle composes to something different from the committed flat manifest, or if any fragment claims something outside its declared scope.
3. **The operator stays simple.** Per-database serialization, advisory locking, and conflict detection between `PostgresPolicy` resources all keep working as documented in [the operator guide](/docs/operator).

## Shared role naming

Set `shared.role_pattern` in the bundle for a common naming convention. A
fragment can set its own top-level `role_pattern`; an individual schema can
set `role_pattern` to override both. Resolution is schema → fragment → bundle
shared value → `"{schema}-{profile}"`. Every declared pattern must contain
`{profile}`. Rendered manifests preserve the resolved fragment overrides, so
rendering and reloading a bundle produces the same role names. An explicit
`"{schema}-{profile}"` is preserved even when it overrides a custom shared pattern.

## A minimal end-to-end example

### 1. Author the bundle and fragments

```yaml
# bundle.yaml
shared:
  profiles:
    editor:
      grants:
        - privileges: [USAGE]
          object: { type: schema }
        - privileges: [SELECT, INSERT, UPDATE, DELETE]
          object: { type: table, name: "*" }
sources:
  - file: platform.yaml
  - file: app.yaml
```

```yaml
# platform.yaml
policy:
  name: platform
scope:
  roles: [app_owner]
  schemas:
    - name: inventory
      facets: [owner]
roles:
  - name: app_owner
schemas:
  - name: inventory
    owner: app_owner
```

```yaml
# app.yaml
policy:
  name: app
scope:
  schemas:
    - name: inventory
      facets: [bindings]
schemas:
  - name: inventory
    profiles: [editor]
```

### 2. Render the composed manifest

```shell
pgroles render-bundle --bundle bundle.yaml --output pgroles.yaml
```

The rendered file is byte-deterministic across machines: the header records only the bundle's basename (never a `pwd`-relative path) and the body strips serde-emitted defaults so it doesn't churn under unrelated upgrades. See the [render-bundle CLI reference](/docs/cli#render-bundle) for details on what is and isn't stripped.

### 3. Wrap the rendered manifest into a `PostgresPolicy`

The rendered file is a `PolicyManifest`. To deploy it under the operator, embed its contents under `spec:` alongside `connection:`:

```yaml
# postgres-policy.yaml
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata:
  name: app
spec:
  connection:
    secretRef:
      name: app-db
    secretKey: url
  mode: apply
  approval: auto
  # ... paste the rendered manifest body here:
  profiles:
    editor:
      # ...
  schemas:
    - name: inventory
      # ...
  roles:
    - name: app_owner
      # ...
```

Common ways to automate the wrap step:

- **Helm / cdk8s / Jsonnet**: template the rendered manifest into the resource as part of chart rendering.
- **`yq` or a small script**: merge the rendered manifest fields under `spec` after setting the operator-only fields such as `connection` and `mode`.
- **Kustomize**: generate the wrapped resource in CI before Kustomize runs, then let Kustomize handle environment overlays for metadata and connection references.

The rendered file is the source of truth for policy content; the wrapping step is about deployment metadata (connection, mode, schedule) and is orthogonal to composition correctness.

### 4. Gate drift in CI

Commit `bundle.yaml`, the fragments, and the rendered `pgroles.yaml` together. Add a CI step that fails the build if the rendered file is stale:

```yaml
# .github/workflows/policy.yml
jobs:
  render-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Verify rendered manifest is up-to-date
        run: |
          docker run --rm -v "${{ github.workspace }}:/work" \
            ghcr.io/thepartly/pgroles:latest \
            render-bundle --bundle /work/bundle.yaml --check /work/pgroles.yaml
```

The `--check` flag exits with code **2** on drift and **0** on match, so any CI system that respects exit codes works as a gate.

## What composition rejects

`render-bundle` and the underlying CLI bundle commands reject the same set of errors before any database inspection:

- **Out-of-scope declarations**: a fragment defining a role or schema facet outside its declared `scope`.
- **Duplicate ownership**: two fragments claiming the same role name, grant key, default-privilege key, or membership selector.
- **Overlapping schema facets**: two fragments both managing the `owner` facet of the same schema, or both managing the `bindings` facet.

The error message names both fragments and the conflicting key, so reviewers can resolve it without running the database.

## Limitations

- The operator does not surface a `--check`-style validator on the `PostgresPolicy` resource itself. Drift between the source bundle and a hand-edited `pgroles.yaml` is caught only at `--check` time, not at `kubectl apply` time. Treat the rendered manifest as machine-generated and rely on the CI gate.
- There is no operator-native way to fan out a bundle into multiple `PostgresPolicy` resources today. One bundle composes to one rendered manifest, which becomes one `PostgresPolicy`. Multi-database setups need one bundle per database (cross-environment fragments are shared by reference).
- The schema-version marker in the rendered header (`pgroles.manifest.v1`) only changes on incompatible `PolicyManifest` shape changes. A pgroles upgrade that bumps the schema requires a re-render and a fresh commit.

## See also

- [CLI commands → render-bundle](/docs/cli#render-bundle)
- [Manifest reference → Bundle mode](/docs/manifest-reference#bundle-mode) for fragment and bundle field reference
- [Kubernetes operator](/docs/operator)
- [CI/CD integration](/docs/ci-cd)
