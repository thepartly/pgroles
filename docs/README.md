# pgroles docs

The documentation site: [Next.js](https://nextjs.org) (Pages Router) with
[Markdoc](https://markdoc.dev) content in `src/pages/docs`, styled with
Tailwind CSS 4 and built from [Pitstop](https://github.com/thepartly/pitstop),
Partly's component library.

```bash
npm ci
cd ..
rustup target add wasm32-unknown-unknown
wasm-pack build crates/pgroles-wasm --target web --release --out-dir ../../docs/public/wasm
cd docs
npm run dev
```

Pitstop is published as the restricted package `@partly/pitstop`, so `npm ci`
needs a token with read access to the `@partly` scope:

```bash
npm config set //registry.npmjs.org/:_authToken <token>
```

CI reads the same token from the `NPM_TOKEN` repository secret. Pull requests
from forks do not receive it, so the docs workflow skips them.

## Checks

```bash
npm run lint
npm run test:labs
npm run test:explorer
npm run test:routing
DOCS_BASE_PATH=/pgroles/pr-preview/pr-236 npm run build
DOCS_TEST_BASE_PATH=/pgroles/pr-preview/pr-236 npm run test:browser
```

`test:labs` runs the interactive lab exercises in `src/components` against
PGlite. `build` produces the static export in `out/`. `test:browser` serves that
export under the configured deployment path and checks the generated JavaScript
and WASM assets. Use the same base path for both commands. The docs workflow
rebuilds WASM, removes its generated `.gitignore` from the export, and verifies
the assets can be staged for Git-based Pages deployment.

Bundled explorer scenarios live in `src/lib/explorerScenarios.mjs`. Each scenario
defines its inputs, default mode, teaching notes, related guides, and expected
changes/findings/phase authority. Guide pages use the `explorer-scenario` Markdoc
tag with a scenario ID; links never include imported inputs.

`scripts/check-wasm-parity.sh` runs every scenario and variant against both the
native analyzer and release WASM, checking semantic expectations as well as
runtime parity. `test:labs` also exercises the Acme authority examples against
PostgreSQL through PGlite. Browser tests verify the static guide links and
scenario interactions under the deployment base path.

## Documentation versions

The footer identifies the source commit. Clean builds of the latest published
release tag show **Release docs** with the tag; other builds show **Development
docs**, including a modified marker for tracked local edits. CI fetches tags and
queries the latest published GitHub release for this check. Local builds default
to Development docs; set `DOCS_PUBLISHED_RELEASE` to a verified published tag to
label a release build. Compare the release label and feature-specific minimum
versions with `pgroles --version`.
When documenting an unreleased CLI feature, put **Requires pgroles vX.Y.Z or
later (unreleased)** beside its first command. Remove the unreleased qualifier
when preparing that release.

## Packaged release validation

Build the docs and WASM as above, then check the candidate archive for this host
against a disposable database with no `review_app` or `review_app_reader` roles:

```bash
DATABASE_URL=postgres://postgres:testpassword@localhost:5432/pgroles_test \
  DOCS_TEST_BASE_PATH=/pgroles/pr-preview/pr-236 \
  ../scripts/check-packaged-review.sh /path/to/pgroles-candidate.tar.gz
```

This unpacks and runs the packaged executable, exports a fresh review, and imports
that artifact into the built static explorer. It checks recorded changes, SQL,
producer version, and the absence of WASM replanning. The database is inspected;
no plan is applied. Normal browser tests still use fixed fixtures; the packaged
candidate test runs only when invoked with the generated artifact.

## Search

`npm run build` indexes the static export with pinned Pagefind after Next.js
finishes. Publish the complete `out/` directory, including `out/pagefind/`.
Search requires this built index; `npm run dev` alone does not produce it.
`npm run build:search` regenerates the index after inspecting or changing an
existing export. An indexing failure fails the build.

Search covers Docs and Learn PostgreSQL together. Article content, reference
tables and examples are indexed; navigation, build labels, interactive controls
and the Explorer are excluded. Shared page metadata supplies Guide / Reference /
Course badges and optional destination filters. No filter is inferred from the
current page. The browser loads Pagefind only after a query is entered.

The browser suite checks the five relevance queries in
[the search evaluation](design/documentation-search.md), global results,
explicit filters, anchored links, keyboard interaction at 320px, pagination and
network-error recovery. Run it against both a preview path and a root build:

```bash
DOCS_BASE_PATH='' npm run build
DOCS_TEST_BASE_PATH='' npm run test:browser -- tests/browser/search.spec.mjs
```
