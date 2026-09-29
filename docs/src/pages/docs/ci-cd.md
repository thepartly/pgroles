---
title: CI/CD integration
description: Use pgroles as a drift gate in your CI/CD pipeline.
---

pgroles integrates into CI/CD pipelines as a drift gate, a deployment step, or both. {% .lead %}

For Cloud SQL or RDS connectivity setup (auth proxies, VPC access, IAM authentication), see the [Google Cloud SQL](/docs/google-cloud-sql) or [AWS RDS](/docs/aws-rds) guides.

---

## Drift detection

`pgroles diff --exit-code` returns specific exit codes for automation:

| Exit code | Meaning |
| --- | --- |
| `0` | Database is in sync with the manifest |
| `2` | Drift detected — roles, grants, or memberships differ |
| Other | Command or connectivity failure |

Command-line usage errors, such as an unknown or misspelled flag, also exit
with `2` before anything is planned. A gate that treats `2` as acceptable drift
must also confirm the run produced its output; the
[PR-comment recipe](#diff-as-a-pr-comment) checks for the review file.

## GitHub Actions

These examples use the published Docker image, which requires no toolchain installation. Your runner needs network access to the database — see the platform guides linked above if you need to set up a proxy or VPN.

### Drift check on PRs

```yaml
jobs:
  drift-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Check for drift
        run: |
          docker run --rm \
            -e DATABASE_URL="${{ secrets.DATABASE_URL }}" \
            -v "${{ github.workspace }}:/work" \
            ghcr.io/thepartly/pgroles:latest \
            diff -f /work/pgroles.yaml --exit-code
```

### Bundle render-check on PRs

If you compose policy from a bundle of fragments and commit the rendered `pgroles.yaml` alongside the source bundle (see the [bundle composition guide](/docs/bundle-composition)), gate the bundle ↔ render relationship with `render-bundle --check`. This catches the case where a fragment was edited but nobody re-ran the renderer.

```yaml
jobs:
  render-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Verify rendered manifest matches the source bundle
        run: |
          docker run --rm \
            -v "${{ github.workspace }}:/work" \
            ghcr.io/thepartly/pgroles:latest \
            render-bundle --bundle /work/bundle.yaml --check /work/pgroles.yaml
```

`--check` exits with code `2` on drift and `0` on match, so it composes naturally with the drift-check job above.

### Apply on merge

```yaml
jobs:
  apply-roles:
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Apply roles
        run: |
          docker run --rm \
            -e DATABASE_URL="${{ secrets.DATABASE_URL }}" \
            -v "${{ github.workspace }}:/work" \
            ghcr.io/thepartly/pgroles:latest \
            apply -f /work/pgroles.yaml
```

### Diff as a PR comment

Generate the Markdown report and recorded review artifact from one planning run.
The CLI exit code controls the CI decision; the explorer is a review interface.
This example accepts both an unchanged plan and detected drift, while failing on
usage, connection, validation, inspection, or export errors:

```yaml
      - name: Generate diff
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
          # Pin a release that supports --review-out (0.13.0 or later).
          PGROLES_IMAGE: ghcr.io/thepartly/pgroles:<version>
        run: |
          rm -f review.md "$GITHUB_WORKSPACE/review.pgroles.json"
          if docker run --rm \
            --user "$(id -u):$(id -g)" \
            -e DATABASE_URL \
            -v "$GITHUB_WORKSPACE:/work" \
            "$PGROLES_IMAGE" \
            diff -f /work/pgroles.yaml --mode adopt --format markdown \
            --target-label staging \
            --policy-commit "$(git rev-parse HEAD)" \
            --review-out /work/review.pgroles.json --exit-code > review.md; then
            status=0
          else
            status=$?
          fi
          case "$status" in
            0|2)
              # Usage errors also exit 2, but never write the review file.
              if [ ! -s "$GITHUB_WORKSPACE/review.pgroles.json" ]; then
                echo "pgroles exited $status without writing review.pgroles.json" >&2
                exit 1
              fi
              ;;
            *) exit "$status" ;;
          esac

      - uses: actions/upload-artifact@v7
        with:
          name: pgroles-review
          path: |
            review.md
            review.pgroles.json

      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('node:fs');
            const report = fs.readFileSync('review.md', 'utf8');
            if (report.trim()) {
              const body = report.length > 60000
                ? report.slice(0, 60000) + '\n\nReport truncated. Download the pgroles-review workflow artifact for the complete review.'
                : report;
              await github.rest.issues.createComment({
                owner: context.repo.owner,
                repo: context.repo.repo,
                issue_number: context.issue.number,
                body
              });
            }
```

Replace `<version>` with a released version, 0.13.0 or later. `--review-out` is not available in
0.12.0 or earlier, where it is a usage error, so do not use a floating tag such
as `latest` for this job. The image runs as an unprivileged user by default;
`--user "$(id -u):$(id -g)"` lets it write the review file into the
runner-owned workspace. The job removes any previous review file first, so a
usage error that exits `2` cannot be mistaken for drift.

The Markdown report ends with the artifact's review fingerprint, and stderr
repeats it with the file path; the explorer shows the same value after import,
so a PR comment can be matched to its uploaded file. If the export fails,
pgroles still prints the report and then exits with an error, which fails the
step.

The comment step needs `pull-requests: write` permission. Treat uploaded reports
as database metadata and choose access and retention accordingly. Report text is
read as data from a file, never interpolated into JavaScript source.
This recipe publishes a review even when drift exists; use the earlier drift
check to fail on differences. `diff` can report preflight findings without
failing, so a CI policy that rejects those findings must inspect the structured
evidence explicitly.

### Using cargo install

If you prefer installing from source instead of Docker, add a Rust toolchain step first:

```yaml
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install pgroles-cli
      - run: pgroles diff -f pgroles.yaml --exit-code
        env:
          DATABASE_URL: ${{ secrets.DATABASE_URL }}
```

## GitLab CI

The published Docker image is a static binary with no shell, so it can't be used directly as a GitLab CI `image:` (which requires `/bin/sh` to run `script:` blocks). Use a Rust image and install from source:

```yaml
drift-check:
  image: rust:latest
  script:
    - cargo install pgroles-cli
    - pgroles diff -f pgroles.yaml --exit-code
  variables:
    DATABASE_URL: $DATABASE_URL
```

## Output formats

`pgroles diff` supports multiple output formats:

```shell
# Raw SQL (default) — execution-oriented output; may contain sensitive values
pgroles diff -f pgroles.yaml

# JSON — machine-readable, good for programmatic processing
pgroles diff -f pgroles.yaml --format json

# Summary — high-level change counts
pgroles diff -f pgroles.yaml --format summary
```

## Reconciliation modes

Use `--mode` to control how aggressively pgroles converges each environment:

```shell
# Staging: full convergence
pgroles apply -f pgroles.yaml --database-url "$STAGING_DATABASE_URL" --mode authoritative

# Production: additive only during initial rollout
pgroles apply -f pgroles.yaml --database-url "$PROD_DATABASE_URL" --mode additive
```

See the [CLI reconciliation modes](/docs/cli#reconciliation-modes) reference for all three modes and a recommended adoption path.

## Multiple environments

Use the same manifest against different databases, or maintain separate manifests:

```shell
# Same manifest, different targets
pgroles apply -f pgroles.yaml --database-url "$STAGING_DATABASE_URL"
pgroles apply -f pgroles.yaml --database-url "$PROD_DATABASE_URL"
```

## Review summaries

Use `--format markdown` to produce a redacted table for a review artifact:

```bash
pgroles diff -f pgroles.yaml --mode adopt --format markdown > pgroles-review.md
# Bundle reports attribute each change to its owning source document.
pgroles diff --bundle bundle.yaml --mode adopt --format markdown > bundle-review.md
```

Markdown records declared password changes without resolving application-password environment variables; database connection credentials are still required. The report includes complete redacted change details, source attribution, and conservative priorities. Revocations, retirement, ownership transfers, password changes, role alterations, PUBLIC grants, elevated new roles, and membership administration are high priority. Other access changes still require review; these labels do not evaluate your application's transitive privileges or availability requirements.

The `pgroles.review.v1` fingerprint identifies the displayed changes, source attribution, and reconciliation mode. Password values, role configuration values, comments, and database identity are excluded. Changes only to those omitted values do not change this fingerprint, and identical reports from different databases share a fingerprint. Record the target environment alongside the artifact. It is not a database-state fingerprint or an operator approval token. Existing `--format json` output remains available for structured integrations, including bundle ownership annotations.

Keep stderr with the report: executor-authority warnings and role-drop preflight findings are emitted there. `--exit-code` returns 2 for structural drift; declared password operations alone return 0 because PostgreSQL passwords cannot be read back for comparison. Posting a report is a separate pipeline action; generating one does not publish it.

## Recorded reviews

Follow [Recorded reviews](/docs/recorded-reviews) to export and open a native plan in the explorer, including its sanitization, provenance, and authority-evidence limitations. The [PR-comment recipe](#diff-as-a-pr-comment) above produces the Markdown summary and review artifact from the same planning run. CI checks decide whether the job passes; the explorer displays the recorded review.
