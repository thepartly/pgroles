const { createHash } = require('node:crypto')
const { readFileSync } = require('node:fs')
const path = require('node:path')
const withMarkdoc = require('@markdoc/next.js')
const { PHASE_DEVELOPMENT_SERVER } = require('next/constants')
const { getBuildVersion } = require('./build/version.cjs')

const buildVersion = getBuildVersion()

const basePath = process.env.DOCS_BASE_PATH || ''

// The explorer imports public/wasm at unversioned paths, so the client appends
// this id to both the glue and the binary. Hashing the assets themselves keeps
// the id identical across build workers and unchanged when WASM is unchanged.
function wasmBuildId() {
  if (process.env.NEXT_PUBLIC_PGROLES_BUILD_ID) {
    return process.env.NEXT_PUBLIC_PGROLES_BUILD_ID
  }
  try {
    const hash = createHash('sha256')
    for (const file of ['pgroles_wasm.js', 'pgroles_wasm_bg.wasm']) {
      hash.update(readFileSync(path.join(__dirname, 'public', 'wasm', file)))
      hash.update('\0')
    }
    return hash.digest('hex').slice(0, 16)
  } catch {
    return (process.env.GITHUB_SHA || 'dev').slice(0, 16)
  }
}

module.exports = (phase) => {
  /** @type {import('next').NextConfig} */
  const nextConfig = {
    basePath,
    assetPrefix: basePath || undefined,
    output: 'export',
    distDir:
      phase === PHASE_DEVELOPMENT_SERVER
        ? '.next'
        : process.env.NEXT_DIST_DIR || 'out',
    trailingSlash: true,
    reactStrictMode: true,
    pageExtensions: ['js', 'jsx', 'md'],
    images: {
      unoptimized: true,
    },
    env: {
      NEXT_PUBLIC_PGROLES_BUILD_ID: wasmBuildId(),
      NEXT_PUBLIC_DOCS_BUILD_LABEL: buildVersion.label,
      NEXT_PUBLIC_DOCS_BUILD_COMMIT: buildVersion.commit,
    },
    experimental: {
      scrollRestoration: true,
    },
  }

  return withMarkdoc()(nextConfig)
}
