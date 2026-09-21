#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: DATABASE_URL=... $0 /path/to/pgroles-candidate.tar.gz" >&2
  exit 2
fi
: "${DATABASE_URL:?Set DATABASE_URL to a disposable PostgreSQL database}"

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
archive=$(realpath "$1")
validation_dir=$(mktemp -d)
trap 'rm -rf "$validation_dir"' EXIT

tar -xzf "$archive" -C "$validation_dir"
shopt -s nullglob
binaries=("$validation_dir"/*/pgroles)
if [[ ${#binaries[@]} -ne 1 || ! -x ${binaries[0]} ]]; then
  echo "Expected exactly one packaged pgroles executable in the archive" >&2
  exit 1
fi
candidate=${binaries[0]}
export PGROLES_CANDIDATE_VERSION
PGROLES_CANDIDATE_VERSION=$("$candidate" --version)
export PGROLES_REVIEW_ARTIFACT="$validation_dir/review.pgroles.json"
echo "Checking $PGROLES_CANDIDATE_VERSION from $archive"
"$candidate" diff -f "$repository/docs/tests/fixtures/recorded-review.yaml" \
  --mode adopt --format markdown --review-out "$PGROLES_REVIEW_ARTIFACT" \
  --target-label "Packaged candidate review" --no-exit-code > "$validation_dir/review.md"
test -s "$PGROLES_REVIEW_ARTIFACT"
cat "$validation_dir/review.md"
cd "$repository/docs"
npm run test:browser -- tests/browser/packaged-review.spec.mjs --output="$validation_dir/browser-results"
