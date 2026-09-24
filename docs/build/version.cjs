const { execFileSync } = require('node:child_process')
const { resolve } = require('node:path')

function getBuildVersion(
  repository = resolve(__dirname, '../..'),
  publishedRelease = process.env.DOCS_PUBLISHED_RELEASE
) {
  function git(...args) {
    try {
      return execFileSync('git', args, {
        cwd: repository,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore'],
      }).trim()
    } catch {
      return ''
    }
  }
  const commit = git('rev-parse', 'HEAD')
  const release = git(
    'describe',
    '--tags',
    '--exact-match',
    '--match',
    'v[0-9]*',
    'HEAD'
  )
  const dirty = Boolean(git('diff', 'HEAD', '--name-only'))
  const revision = `${commit.slice(0, 8) || 'unknown revision'}${
    dirty ? ' (modified)' : ''
  }`
  // Production docs deploy from main, which moves past a tag once anything
  // merges after it, so development builds also name the latest release.
  const latest = publishedRelease ? ` · latest release ${publishedRelease}` : ''
  return {
    label:
      release && release === publishedRelease && !dirty
        ? `Release docs · ${release} · ${revision}`
        : `Development docs · ${revision}${latest}`,
    commit,
  }
}

module.exports = { getBuildVersion }
