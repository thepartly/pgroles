import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
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

// Stub docker: records its arguments, prints the report, and behaves like a
// pgroles run that either writes the review file (ARTIFACT=write), writes an
// empty one (ARTIFACT=empty), or writes nothing (a usage error, or an image
// without --review-out). It writes through the workspace bind mount only.
const dockerStub = `#!/bin/sh
printf "%s\\n" "$@" > "$ARGS_OUTPUT"
cat "$REPORT_SOURCE"
case "$ARTIFACT" in
  write) printf '{"schema_version":"pgroles.review-artifact.v2"}' > "$GITHUB_WORKSPACE/review.pgroles.json" ;;
  empty) : > "$GITHUB_WORKSPACE/review.pgroles.json" ;;
esac
exit "$DIFF_EXIT"
`

function literalStepEnv(step) {
  return Object.fromEntries(Object.entries(step.env ?? {}).filter(([, value]) => !String(value).includes('${{')))
}

function runGenerate(directory, { status, artifact, stale = false }) {
  const reviewPath = join(directory, 'review.pgroles.json')
  rmSync(reviewPath, { force: true })
  if (stale) writeFileSync(reviewPath, '{"schema_version":"pgroles.review-artifact.v2"}')
  return spawnSync('bash', ['-e', '-o', 'pipefail', '-c', generate.run], {
    cwd: directory,
    encoding: 'utf8',
    env: {
      ...process.env,
      ...literalStepEnv(generate),
      PATH: `${directory}:${process.env.PATH}`,
      GITHUB_WORKSPACE: directory,
      REPORT_SOURCE: join(directory, 'source.md'),
      ARGS_OUTPUT: join(directory, 'docker-args'),
      DIFF_EXIT: String(status),
      ARTIFACT: artifact,
    },
  })
}

test('documented CI recipe accepts drift only when the review file was written', () => {
  const directory = mkdtempSync(join(tmpdir(), 'pgroles-ci-recipe-'))
  try {
    writeFileSync(join(directory, 'docker'), dockerStub, { mode: 0o755 })
    writeFileSync(join(directory, 'git'), '#!/bin/sh\ntest "$1" = rev-parse && test "$2" = HEAD || exit 1\nprintf "%s\\n" 0123456789abcdef\n', { mode: 0o755 })
    const payload = '## Review\nA role named `$(exit 92)` stays report data.\n'
    writeFileSync(join(directory, 'source.md'), payload)
    const cases = [
      // [pgroles exit, review file, expected job exit]
      [{ status: 0, artifact: 'write' }, 0],
      [{ status: 2, artifact: 'write' }, 0],
      // clap usage errors (e.g. 0.12.0 rejecting --review-out) exit 2 and write nothing
      [{ status: 2, artifact: 'none' }, 1],
      [{ status: 2, artifact: 'none', stale: true }, 1],
      [{ status: 2, artifact: 'empty' }, 1],
      [{ status: 0, artifact: 'none' }, 1],
      [{ status: 1, artifact: 'none' }, 1],
      // an export failure still prints the report, then exits 1
      [{ status: 1, artifact: 'write' }, 1],
      [{ status: 125, artifact: 'none' }, 125],
    ]
    for (const [run, expected] of cases) {
      const result = runGenerate(directory, run)
      assert.equal(result.status, expected, `${JSON.stringify(run)}: ${result.stderr}`)
      if (expected === 1 && run.status !== 1) {
        assert.match(result.stderr, /without writing review\.pgroles\.json/)
      }
      assert.equal(readFileSync(join(directory, 'review.md'), 'utf8'), payload)
      const argumentsPassed = readFileSync(join(directory, 'docker-args'), 'utf8').split('\n')
      const value = (flag) => argumentsPassed[argumentsPassed.indexOf(flag) + 1]
      assert.equal(value('--target-label'), 'staging')
      assert.equal(value('--policy-commit'), '0123456789abcdef')
      assert.equal(value('--review-out'), '/work/review.pgroles.json')
      assert.equal(value('-v'), `${directory}:/work`)
      // The image runs as UID 65534; run as the runner so it can write /work.
      assert.equal(value('--user'), `${process.getuid()}:${process.getgid()}`)
    }
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('documented CI recipe pins an image that supports --review-out', () => {
  const image = generate.env.PGROLES_IMAGE
  assert.match(image, /^ghcr\.io\/thepartly\/pgroles:/)
  assert.doesNotMatch(image, /:latest$/)
  assert.match(generate.run, /"\$PGROLES_IMAGE"/)
  assert.doesNotMatch(generate.run, /pgroles:latest/)
  assert.match(guide, /`--review-out` is not available in\s+0\.12\.0 or earlier/)
})

test('documented CI recipe clears a stale review file before running', () => {
  const directory = mkdtempSync(join(tmpdir(), 'pgroles-ci-recipe-'))
  try {
    writeFileSync(join(directory, 'docker'), dockerStub, { mode: 0o755 })
    writeFileSync(join(directory, 'git'), '#!/bin/sh\nprintf "%s\\n" 0123456789abcdef\n', { mode: 0o755 })
    writeFileSync(join(directory, 'source.md'), '')
    const result = runGenerate(directory, { status: 2, artifact: 'none', stale: true })
    assert.equal(result.status, 1, result.stderr)
    assert.equal(existsSync(join(directory, 'review.pgroles.json')), false)
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
