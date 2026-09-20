import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'
import vm from 'node:vm'
import { parse } from 'yaml'

const guide = readFileSync(new URL('../src/pages/docs/ci-cd.md', import.meta.url), 'utf8')
const recipe = guide.split('### Diff as a PR comment')[1].match(/```yaml\n([\s\S]*?)```/)[1]
const steps = parse(recipe)
const generate = steps.find((step) => step.name === 'Generate diff')
const comment = steps.find((step) => step.name === 'Comment on PR')

test('documented CI recipe accepts drift but propagates real failures', () => {
  const directory = mkdtempSync(join(tmpdir(), 'pgroles-ci-recipe-'))
  try {
    writeFileSync(join(directory, 'docker'), '#!/bin/sh\ncat "$REPORT_SOURCE"\nexit "$DIFF_EXIT"\n', { mode: 0o755 })
    const reportPath = join(directory, 'source.md')
    const payload = '## Review\nA role named `$(exit 92)` stays report data.\n'
    writeFileSync(reportPath, payload)
    for (const [status, expected] of [[0, 0], [2, 0], [1, 1], [125, 125]]) {
      const result = spawnSync('bash', ['-e', '-o', 'pipefail', '-c', generate.run], {
        cwd: directory,
        encoding: 'utf8',
        env: { ...process.env, PATH: `${directory}:${process.env.PATH}`, GITHUB_WORKSPACE: directory, REPORT_SOURCE: reportPath, DIFF_EXIT: String(status) },
      })
      assert.equal(result.status, expected, result.stderr)
      assert.equal(readFileSync(join(directory, 'review.md'), 'utf8'), payload)
    }
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

async function runCommentScript(payload) {
  const comments = []
  const sandbox = {
    require: (name) => {
      assert.equal(name, 'node:fs')
      return { readFileSync: (path, encoding) => {
        assert.equal(path, 'review.md')
        assert.equal(encoding, 'utf8')
        return payload
      } }
    },
    context: { repo: { owner: 'example', repo: 'policies' }, issue: { number: 17 } },
    github: { rest: { issues: { createComment: async (value) => { comments.push(value) } } } },
  }
  await vm.runInNewContext(`(async () => {\n${comment.with.script}\n})()`, sandbox)
  assert.equal(sandbox.injected, undefined)
  return comments.map((value) => value.body)
}

test('documented comment script reads adversarial report content as data', async () => {
  const payload = '`${globalThis.injected = true}`\n${{ secrets.DATABASE_URL }}\n</script>\n'
  assert.deepEqual(await runCommentScript(payload), [payload])
})

test('documented comment script bounds large reports and points to the artifact', async () => {
  const [body] = await runCommentScript('x'.repeat(70000))
  assert.ok(body.length < 65536)
  assert.match(body, /Download the pgroles-review workflow artifact/)
})
