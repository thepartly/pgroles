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
npm run test:browser
npm run test:routing
npm run build
```

`test:labs` runs the interactive lab exercises in `src/components` against
PGlite. `test:browser` uses the generated WASM package in `public/wasm`, and
`build` produces the static export in `out/`. The generated WASM package is
ignored by Git and rebuilt by the docs workflow.
