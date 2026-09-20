import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import test from 'node:test'

const repositoryRoot = resolve(import.meta.dirname, '../..')
const generator = resolve(repositoryRoot, 'docs/scripts/generate-manifest-types.mjs')
const tsc = process.env.TSC_BIN ?? resolve(repositoryRoot, 'docs/node_modules/typescript/bin/tsc')

test('generates compilable declarations for refs, maps, intersections, and nullable unions', () => {
  const directory = mkdtempSync(resolve(tmpdir(), 'pgroles-manifest-types-'))
  try {
    const metadataPath = resolve(directory, 'metadata.json')
    const declarationsPath = resolve(directory, 'generated.d.ts')
    const usagePath = resolve(directory, 'usage.ts')
    writeFileSync(metadataPath, JSON.stringify({
      schema_version: 'test.v1',
      manifest_schema: {
        type: 'object',
        properties: {
          direct: { $ref: '#/$defs/Entry' },
          entries: { type: 'object', additionalProperties: { $ref: '#/$defs/Entry' } },
          nullable: { anyOf: [{ $ref: '#/$defs/Entry' }, { type: 'null' }] },
          combined: {
            type: 'object',
            properties: { enabled: { type: 'boolean' } },
            required: ['enabled'],
            allOf: [{ $ref: '#/$defs/Named' }],
          },
        },
        required: ['direct', 'entries', 'nullable', 'combined'],
        $defs: {
          Entry: { type: 'object', properties: { value: { type: 'string' } }, required: ['value'] },
          Named: { type: 'object', properties: { name: { type: 'string' } }, required: ['name'] },
        },
      },
      contracts: {},
    }))
    const generated = spawnSync(process.execPath, [generator, metadataPath, declarationsPath], { encoding: 'utf8' })
    assert.equal(generated.status, 0, generated.stderr)
    const declarations = readFileSync(declarationsPath, 'utf8')
    assert.match(declarations, /Record<string, Entry>/)
    assert.match(declarations, /Entry \| null/)
    assert.match(declarations, /enabled.* & Named/)

    writeFileSync(usagePath, `import type { PolicyManifest } from './generated'
const policy: PolicyManifest = {
  direct: { value: 'one' },
  entries: { second: { value: 'two' } },
  nullable: null,
  combined: { enabled: true, name: 'joined' },
}
void policy
`)
    const checked = spawnSync(tsc, ['--noEmit', '--strict', usagePath], { encoding: 'utf8' })
    assert.equal(checked.status, 0, checked.stdout + checked.stderr)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})

test('the checked-in policy authoring declaration compiles as a consumer module', () => {
  const directory = mkdtempSync(resolve(tmpdir(), 'pgroles-policy-authoring-types-'))
  try {
    const declarations = resolve(repositoryRoot, 'crates/pgroles-wasm/policy-authoring.d.ts')
    const usagePath = resolve(directory, 'usage.ts')
    writeFileSync(usagePath, `import type { PolicyAuthoringEngine, PolicyRequest } from ${JSON.stringify(declarations)}
declare const engine: PolicyAuthoringEngine
const request: PolicyRequest = {
  schema_version: 'pgroles.policy.v1',
  desired_yaml: 'roles: []',
}
engine.validate(request)
engine.compile(request)
`)
    const checked = spawnSync(tsc, ['--noEmit', '--strict', usagePath], { encoding: 'utf8' })
    assert.equal(checked.status, 0, checked.stdout + checked.stderr)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
})
