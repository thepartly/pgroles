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
