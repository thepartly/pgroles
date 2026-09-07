# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Build & Test Commands

```bash
# Build (SQLX_OFFLINE=true needed when no live database is available)
SQLX_OFFLINE=true cargo build --workspace

# Format + lint (always run before committing)
cargo fmt --all
SQLX_OFFLINE=true cargo clippy --all-targets --all-features -- -D warnings

# Unit tests (no database needed)
cargo test --workspace

# Integration tests (requires live PostgreSQL)
export DATABASE_URL=postgres://postgres:testpassword@localhost:5432/pgroles_test
cargo test --workspace -- --include-ignored

# Run a single test
cargo test -p pgroles-core --lib diff::tests::diff_creates_new_roles -- --exact

# CRD drift check (CI compares every committed CRD copy — chart and k8s/ —
# against crdgen output)
scripts/check-crd-drift.sh
scripts/check-crd-docs.sh

# Regenerate CRDs after modifying crd.rs. crdgen writes into the chart; the
# k8s/ copies are duplicates that must be refreshed by hand, and
# check-crd-drift.sh fails if any copy drifts.
cargo run --bin crdgen -- --output-dir charts/pgroles-operator/crds/
cp charts/pgroles-operator/crds/postgrespolicies.pgroles.io.yaml k8s/crd.yaml
cp charts/pgroles-operator/crds/postgrespolicyplans.pgroles.io.yaml k8s/postgrespolicyplan-crd.yaml
cp charts/pgroles-operator/crds/postgrespolicycandidates.pgroles.io.yaml k8s/postgrespolicycandidate-crd.yaml
cp charts/pgroles-operator/crds/ephemeralaccesspolicies.pgroles.io.yaml k8s/ephemeralaccesspolicy-crd.yaml
cp charts/pgroles-operator/crds/ephemeralaccessrequests.pgroles.io.yaml k8s/ephemeralaccessrequest-crd.yaml
```

### Local PostgreSQL for integration tests

```bash
docker run --rm --name pgroles-pg16 \
  -e POSTGRES_PASSWORD=testpassword \
  -e POSTGRES_DB=pgroles_test \
  -p 5432:5432 \
  postgres:16
```

## Architecture

### Data Pipeline

```
YAML → parse_manifest() → PolicyManifest
     → expand_manifest() → ExpandedManifest (profiles × schemas resolved)
     → RoleGraph::from_expanded() → RoleGraph (desired)
     → [operator only] compose_effective_graph() → RoleGraph (effective desired)
       overlays memberships from active EphemeralAccessRequests

DB   → inspect() → RoleGraph (current)
     → detect_pg_version() → SqlContext

diff(current, effective desired) → Vec<Change> → sql::render_all_with_context() → SQL
```

### Workspace Crates

- **pgroles-core** — Pure library, no IO. Manifest parsing, profile expansion, diff engine, SQL rendering, manifest export. All collections use `BTreeMap`/`BTreeSet` for deterministic output.
- **pgroles-inspect** — Async database introspection via `sqlx`/`pg_catalog`. Version detection, cloud provider detection (RDS, Cloud SQL, AlloyDB, Azure), drop-role safety preflight.
- **pgroles-cli** — Binary crate. Thin orchestration over core + inspect. Subcommands: `validate`, `diff`/`plan`, `apply`, `inspect`, `generate`.
- **pgroles-operator** — Kubernetes operator. Reconciles `PostgresPolicy` CRDs (`pgroles.io/v1alpha1`). Has a `crdgen` binary for generating the CRD YAML.
  - Kubernetes identifiers: every name and label value derived from user input goes through `k8s_names`. Do not hand-roll truncation or character filtering elsewhere — a cut that lands on a separator yields a value the API server rejects, which surfaces as a policy that silently stops reconciling. Invariants are enforced by property tests in `tests/identifier_properties.rs`.
  - Health endpoints: `/livez`, `/readyz`
  - Execution modes: `apply`, `observe` (`plan` is a deprecated spelling of `observe`; omitted approval defaults to manual for either)
  - Metrics/telemetry: prefer OTLP export via OpenTelemetry Collector; do not add a built-in Prometheus scrape endpoint by default unless the change explicitly requires it.

### Diff Change Ordering

`diff()` assembles changes in dependency order: creates → alters/comments → grants → default privileges → object revocations → membership removes → membership adds → default privilege revocations → drops. Retirement steps (terminate sessions, reassign owned, drop owned) are inserted immediately before the matching `DropRole` by `apply_role_retirements()`. `apply` executes the whole plan in a single transaction.

## CI

`.github/workflows/ci.yml` runs:

- **Lint** — `cargo fmt --check`, `clippy -D warnings`, CRD drift check, helm-docs drift check
- **Unit Tests** — `cargo test --workspace`
- **Integration Tests** — PG 16/17/18 matrix, `cargo test --workspace -- --include-ignored`
- **Docker and example smoke tests** — verifies the documented container and example flows work end-to-end
- **Operator E2E** — kind cluster, deploys the operator plus an OpenTelemetry Collector, runs happy-path plus conflict/invalid/missing-secret/insufficient-privilege/secret-rotation scenarios, verifies roles in the database, and verifies OTLP metrics export
- **Plan lifecycle and load E2E** — plan approval flows, plus generated-policy convergence at higher object counts and ephemeral-request load
- **Ephemeral access E2E** — runs twice: once for the trusted-writer posture, once for the Kyverno secure-admission profile in `k8s/security/`

The heavier fairness/load coverage lives in `.github/workflows/operator-fairness-load.yml` and runs on a nightly schedule when `main` has changed. It carries two scenarios — fairness/load, and an ACL inspection burst that measures whether the operator's peak working set tracks the concurrency bound or the policy count — and files a `nightly-failure` issue when either fails, appending to the open one rather than opening a new issue per night.

## Agent Skills

- Canonical public skills live under `skills/<name>/SKILL.md` and follow the
  Agent Skills specification.
- Keep product workflows and version-specific semantics in skills. Keep
  always-on repository contribution rules in this file.
- Validate every skill with
  `uvx --from skills-ref==0.1.1 agentskills validate skills/<name>`.
- Skills ship in tagged source archives and CLI binary archives. Do not copy
  them into crates, runtime images, Kubernetes resources, or Helm templates.
- Update affected skills when behavior or public workflows change; avoid
  duplicating canonical skill content elsewhere.

## Release Process

**Release by pushing the tag. Never publish a release from the GitHub UI.**

Publishing from the UI creates the tag itself, so `release.yml` arrives to find
the release already published — and published releases are immutable, so the CLI
binaries can never be attached. The workflow creates and publishes the release
itself; the tag is the only manual step.

1. Open a release-prep PR against `main`: bump `version` in `Cargo.toml`
   (`workspace.package` plus the `pgroles-core` / `pgroles-inspect`
   path-dependency pins), refresh `Cargo.lock`, set the chart's `version` and
   `appVersion`, regenerate the chart README (`scripts/check-helm-docs.sh`), and
   retitle the changelog's `## [Unreleased]` section to `## [X.Y.Z] - <date>`
   with a fresh empty `## [Unreleased]` above it.
2. Merge it once CI is green.
3. **Wait for the CI run that the merge triggered on `main` to pass.** Releasing
   requires a successful CI run on the exact commit being tagged, and CI runs
   automatically on pushes to `main` and `release/**`, so this is the run to
   wait for — no manual dispatch needed.
4. Tag that green commit and push:
   ```bash
   git checkout main && git pull
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```

The tag push then drives everything, in this order:

1. **`candidate-ci`** requires a successful CI run for the tagged commit. It
   runs before anything else, so tagging a commit CI has not passed costs
   nothing.
2. **`prepare-github-release`** creates a *draft* release, with the body taken
   only from that version's `CHANGELOG.md` section. Never pass `--generate-notes`:
   it appends a duplicate GitHub change list. A missing or empty changelog entry
   stops the release. Every publishing job waits on this gate, so a release that
   was published by hand fails here — while nothing has reached crates.io or GHCR.
3. **`build-binaries`** cross-compiles the CLI for four targets.
4. **`docker-operator`** and **`docker-cli`** push, sign, and attest the images.
5. **`publish-crates`** publishes the four crates, after the images rather than
   beside them. It is the one step that cannot be undone — a GHCR package
   version can be deleted and a draft release discarded, but a crates.io version
   can only be yanked — so it goes as late as possible.
6. **`github-release`** attaches the tarballs to the draft and publishes it.
   Publishing is what freezes the release, so it runs last and acts as the
   commit point for the whole release.

`helm-chart-release.yml` publishes the chart on the same tag in its own run. It
cannot depend on the jobs above, so it repeats both gates itself — the CI check
and the already-published check.

None of this is atomic: crates.io, GHCR, and the chart are three registries, and
the crates publish four times in sequence. A failure between any two of them
leaves a gap no workflow can close. The ordering only ensures nothing publishes
from a commit CI has not passed, and that the irreversible step happens last.

When a release run fails, the release stays a draft and nothing is visible to
users. What to do next depends on how far it got:

- **Failed at `candidate-ci` or `prepare-github-release`** — nothing was
  published. Delete the draft if one was created, fix the cause, delete and
  re-push the tag.
- **Failed after `publish-crates` or a docker job succeeded** — that version is
  spent. crates.io and GHCR do not allow republishing a version, so re-running
  the workflow fails on the already-published crates and can never reach
  `github-release`. Delete the draft and cut the next patch version.

The second case is why the gates run first: everything that can be checked
cheaply is checked before anything becomes irreversible.

## Containers

- Published container images are multi-arch for `linux/amd64` and `linux/arm64`.
- `.github/workflows/release.yml` builds Linux binaries first, then assembles container images from those artifacts using `docker/Dockerfile.runtime`.
- `docker/Dockerfile` remains the source-build path for local Docker builds and any CI path that needs to compile from the repository contents.
- Keep `docker/Dockerfile` package-scoped (`--package pgroles-cli` / `--package pgroles-operator`) and preserve the BuildKit cache mounts for Cargo registry, git, and target directories.
- If you change binary names, targets, or release packaging, update both `build-binaries` and `docker/Dockerfile.runtime` together.
