import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { getBuildVersion } from '../build/version.cjs'

test('only a clean published release identifies as release docs', () => {
  const repository = mkdtempSync(join(tmpdir(), 'pgroles-docs-version-'))
  const git = (...args) => execFileSync('git', args, { cwd: repository, stdio: 'pipe' })
  try {
    git('init')
    git('config', 'user.name', 'Docs test')
    git('config', 'user.email', 'docs@example.invalid')
    writeFileSync(join(repository, 'page.md'), 'Released docs')
    git('add', 'page.md')
    git('commit', '-m', 'Release fixture')
    git('tag', 'v0.12.0')
    assert.match(getBuildVersion(repository, 'v0.12.0').label, /^Release docs · v0.12.0 · [0-9a-f]{8}$/)
    assert.match(getBuildVersion(repository, '').label, /^Development docs/)
    writeFileSync(join(repository, 'page.md'), 'Unreleased docs')
    assert.match(getBuildVersion(repository, 'v0.12.0').label, /^Development docs .*\(modified\)$/)
    git('commit', '-am', 'Development fixture')
    assert.match(getBuildVersion(repository, 'v0.12.0').label, /^Development docs · [0-9a-f]{8}$/)
    git('tag', 'v0.13.0')
    assert.match(getBuildVersion(repository, 'v0.12.0').label, /^Development docs/)
    assert.match(getBuildVersion(repository, 'v0.13.0').label, /^Release docs · v0.13.0/)
  } finally {
    rmSync(repository, { recursive: true, force: true })
  }
})

test('builds without git metadata are explicitly development docs', () => {
  const directory = mkdtempSync(join(tmpdir(), 'pgroles-docs-no-git-'))
  try {
    assert.deepEqual(getBuildVersion(directory, 'v0.12.0'), {
      label: 'Development docs · unknown revision',
      commit: '',
    })
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})
