import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

import {
  MAX_SNAPSHOT_FILE_BYTES,
  REVIEW_ARTIFACT_ENUMS,
  REVIEW_ARTIFACT_SHAPE,
  foldRecordedPhaseReachability,
  reviewArtifactImport,
  validateReviewArtifactFileSize,
} from '../src/lib/pgrolesExplorer.mjs'

// PGROLES_REVIEW_FIXTURE points the importer tests at another exported artifact.
const fixturePath = process.env.PGROLES_REVIEW_FIXTURE ?? fileURLToPath(new URL('./fixtures/recorded-review.json', import.meta.url))
const schemaPath = fileURLToPath(new URL('../public/generated/review-artifact.schema.json', import.meta.url))
const CURRENT_VERSION = 'pgroles.review-artifact.v2'

// Local runs skip until the generated inputs exist; CI never skips.
const skipOutsideCi = (reason) => (process.env.CI ? false : reason)
const fixture = JSON.parse(readFileSync(fixturePath, 'utf8'))
const fixtureSkip = fixture.schema_version === CURRENT_VERSION
  ? false
  : skipOutsideCi(`${fixturePath} is ${fixture.schema_version}; regenerate it as ${CURRENT_VERSION} from the CLI`)
const schemaSkip = existsSync(schemaPath)
  ? false
  : skipOutsideCi(`${schemaPath} is missing; run scripts/generate-manifest-metadata.sh`)

const copy = () => structuredClone(fixture)

function rejects(mutate, pattern, message) {
  const artifact = copy()
  mutate(artifact)
  assert.throws(() => reviewArtifactImport(artifact), pattern, message)
}

test('accepts the CLI-generated fixture unchanged', { skip: fixtureSkip }, () => {
  const artifact = copy()
  assert.equal(reviewArtifactImport(artifact), artifact)
  assert.deepEqual(artifact, fixture)
})

test('rejects retired and unknown schema versions, and oversized files', { skip: fixtureSkip }, () => {
  rejects((artifact) => { artifact.schema_version = 'pgroles.review-artifact.v1' }, /no longer supported; re-export the review with the current pgroles CLI to produce pgroles\.review-artifact\.v2/)
  rejects((artifact) => { artifact.schema_version = 'pgroles.review-artifact.v3' }, /unsupported review artifact schema version: pgroles\.review-artifact\.v3/)
  rejects((artifact) => { delete artifact.schema_version }, /unsupported review artifact schema version: missing/)
  assert.doesNotThrow(() => validateReviewArtifactFileSize(MAX_SNAPSHOT_FILE_BYTES))
  assert.throws(() => validateReviewArtifactFileSize(MAX_SNAPSHOT_FILE_BYTES + 1), /review artifact file is 4194305 bytes; limit is 4194304 bytes/)
})

test('rejects unknown top-level fields', { skip: fixtureSkip }, () => {
  rejects((artifact) => { artifact.smuggled = 'payload' }, /unknown field "smuggled" at \$$/)
  const prototypeKey = JSON.parse(JSON.stringify(fixture).replace(/^\{/, '{"__proto__":{"polluted":true},'))
  assert.throws(() => reviewArtifactImport(prototypeKey), /unknown field "__proto__" at \$$/)
  rejects((artifact) => { artifact.provenance.note = 'x' }, /unknown field "note" at \$\.provenance$/)
  rejects((artifact) => { artifact.recorded.extra = [] }, /unknown field "extra" at \$\.recorded$/)
})

test('rejects unknown fields inside every recorded change, using per-kind key sets', { skip: fixtureSkip }, () => {
  for (const [index] of fixture.recorded.changes.entries()) {
    rejects((artifact) => { artifact.recorded.changes[index].change.smuggled = 'x' }, new RegExp(`unknown field "smuggled" at \\$\\.recorded\\.changes\\[${index}\\]\\.change$`))
    rejects((artifact) => { artifact.recorded.changes[index].note = 'x' }, new RegExp(`unknown field "note" at \\$\\.recorded\\.changes\\[${index}\\]$`))
  }
  // A key valid for one kind is still unknown on another.
  const addMember = fixture.recorded.changes.findIndex((entry) => entry.change.kind === 'add_member')
  if (addMember >= 0) {
    rejects((artifact) => { artifact.recorded.changes[addMember].change.grantor = 'postgres' }, /unknown field "grantor"/)
  }
  const createRole = fixture.recorded.changes.findIndex((entry) => entry.change.kind === 'create_role')
  if (createRole >= 0) {
    rejects((artifact) => { artifact.recorded.changes[createRole].change.state.comment = 'db pass: hunter2' }, /unknown field "comment" at \$\.recorded\.changes\[\d+\]\.change\.state$/)
    rejects((artifact) => { artifact.recorded.changes[createRole].change.state.config = { app: 'x' } }, /unknown field "config"/)
  }
  rejects((artifact) => { artifact.recorded.visual.nodes[0].comment = 'db pass: hunter2' }, /unknown field "comment" at \$\.recorded\.visual\.nodes\[0\]$/)
})

test('rejects credential-like field names anywhere in the artifact', { skip: fixtureSkip }, () => {
  const placements = [
    (artifact, key) => { artifact[key] = 'x' },
    (artifact, key) => { artifact.provenance.policy[key] = 'x' },
    (artifact, key) => { artifact.recorded.changes[0].change[key] = 'x' },
    (artifact, key) => { artifact.recorded.visual.nodes[0][key] = 'x' },
    (artifact, key) => { artifact.recorded.phases[0].executor_reachability_delta.changed[0] = { ...artifact.recorded.phases[0].executor_reachability_delta.changed[0], [key]: 'x' } },
  ]
  for (const key of ['password', 'PASSWORD', 'database_url', 'url', 'client_secret', 'api_token', 'scram_verifier', 'SessionToken']) {
    for (const place of placements) {
      rejects((artifact) => place(artifact, key), new RegExp(`credential-like field "${key}"`))
    }
  }
  assert.doesNotThrow(() => reviewArtifactImport(copy()), 'password_valid_until and omission values stay allowed')
})

test('rejects an available SQL preview alongside omitted sensitive values', { skip: fixtureSkip }, () => {
  const available = fixture.recorded.sql_preview.status === 'available'
  rejects((artifact) => {
    artifact.recorded.changes[0].omissions = [{ field: 'state.comment', reason: 'sensitive_value' }]
    artifact.recorded.sql_preview = { status: 'available', sql: 'CREATE ROLE "x";' }
  }, /SQL preview is available although changes omit sensitive values/)
  rejects((artifact) => {
    for (const entry of artifact.recorded.changes) delete entry.omissions
    artifact.recorded.sql_preview = { status: 'available', sql: 'SELECT 1;', sensitive_change_indices: [0] }
  }, /SQL preview is available although changes omit sensitive values/)
  rejects((artifact) => {
    for (const entry of artifact.recorded.changes) delete entry.omissions
    artifact.recorded.changes[0].omissions = [{ field: 'password', reason: 'sensitive_value' }]
    artifact.recorded.sql_preview = { status: 'omitted', reason: 'sensitive_changes', sensitive_change_indices: [1] }
  }, /sensitive changes do not match the recorded omissions/)
  if (available) {
    const artifact = copy()
    for (const entry of artifact.recorded.changes) delete entry.omissions
    artifact.recorded.changes[0].omissions = [{ field: 'password', reason: 'sensitive_value' }]
    artifact.recorded.sql_preview = { status: 'omitted', reason: 'sensitive_changes', sensitive_change_indices: [0] }
    assert.equal(reviewArtifactImport(artifact), artifact)
  }
})

test('validates the change indices of aggregated findings', { skip: fixtureSkip }, () => {
  const aggregated = fixture.recorded.findings.findIndex((finding) => Array.isArray(finding.change_indices))
  const target = aggregated >= 0 ? aggregated : 0
  const setIndices = (artifact, indices) => {
    const finding = artifact.recorded.findings[target]
    finding.change_indices = indices
    finding.change_index = indices[0]
  }
  const valid = copy()
  setIndices(valid, [0, 1])
  assert.doesNotThrow(() => reviewArtifactImport(valid))
  rejects((artifact) => setIndices(artifact, []), /findings are malformed/, 'empty change_indices')
  rejects((artifact) => setIndices(artifact, [0, 0]), /findings are malformed/, 'duplicate change_indices')
  rejects((artifact) => setIndices(artifact, [0, 99]), /findings are malformed/, 'unknown change index')
  rejects((artifact) => setIndices(artifact, ['0']), /findings are malformed/, 'non-integer change index')
  rejects((artifact) => { setIndices(artifact, [0, 1]); artifact.recorded.findings[target].change_index = 1 }, /findings are malformed/, 'change_index is not the first entry')
})

test('rejects complete executor authority coverage without recorded checks', { skip: fixtureSkip }, () => {
  const executorEvidence = fixture.preflight.findIndex((item) => item.check === 'executor_authority')
  assert.ok(executorEvidence >= 0, 'fixture records executor authority evidence')
  const allChanges = fixture.recorded.changes.map((entry) => entry.index)
  rejects((artifact) => {
    artifact.preflight[executorEvidence].coverage = { kind: 'complete', checks_performed: [], checked_change_indices: allChanges, unchecked_change_indices: [] }
  }, /complete executor authority coverage without any recorded checks/)
  const accepted = copy()
  accepted.preflight[executorEvidence].coverage = { kind: 'complete', checks_performed: ['plan_order_authority'], checked_change_indices: allChanges, unchecked_change_indices: [] }
  assert.doesNotThrow(() => reviewArtifactImport(accepted))
})

test('rejects malformed reachability deltas', { skip: fixtureSkip }, () => {
  const second = fixture.recorded.phases.length > 1 ? 1 : 0
  const firstRole = fixture.recorded.phases[0].executor_reachability_delta.changed[0]?.role ?? 'review_deployer'
  const cases = [
    ['a non-object delta', (phase) => { phase.executor_reachability_delta = [] }],
    ['a null delta', (phase) => { phase.executor_usage_delta = null }],
    ['a missing changed list', (phase) => { delete phase.executor_reachability_delta.changed }],
    ['a non-array removed list', (phase) => { phase.executor_usage_delta.removed = 'role' }],
    ['a non-string removed role', (phase) => { phase.executor_usage_delta.removed = [7] }],
    ['an invalid status', (phase) => { phase.executor_reachability_delta.changed = [{ role: 'x', status: 'maybe' }] }],
    ['a duplicated changed role', (phase) => { phase.executor_reachability_delta.changed = [{ role: 'x', status: 'reachable' }, { role: 'x', status: 'unknown' }] }],
    ['a removed role absent from the previous state', (phase) => { phase.executor_reachability_delta.removed = ['never_present'] }],
    ['unsorted changed roles', (phase) => { phase.executor_reachability_delta.changed = [{ role: 'b', status: 'reachable' }, { role: 'a', status: 'reachable' }] }],
  ]
  for (const [name, mutate] of cases) {
    rejects((artifact) => mutate(artifact.recorded.phases[0]), /phase 1 reachability delta is malformed/, name)
  }
  if (second > 0) {
    rejects((artifact) => {
      const phase = artifact.recorded.phases[second]
      phase.executor_reachability_delta = { changed: [{ role: firstRole, status: 'unknown' }], removed: [firstRole] }
    }, /phase 2 reachability delta is malformed/, 'a role both changed and removed')
    rejects((artifact) => {
      artifact.recorded.phases[second].executor_reachability_delta.removed = [firstRole, firstRole]
    }, /phase 2 reachability delta is malformed/, 'a duplicated removed role')
    const firstStatus = fixture.recorded.phases[0].executor_reachability_delta.changed[0]?.status
    if (firstStatus) {
      rejects((artifact) => {
        artifact.recorded.phases[second].executor_reachability_delta = { changed: [{ role: firstRole, status: firstStatus }], removed: [] }
      }, /phase 2 reachability delta is malformed/, 'a no-op changed entry')
    }
  }
  rejects((artifact) => {
    artifact.recorded.phases.push({ phase: 'retire', change_indices: [], executor_reachability_delta: { changed: [], removed: [] }, executor_usage_delta: { changed: [], removed: [] } })
  }, /phases are malformed/, 'an empty phase')
})

test('orders folded roles by UTF-8 bytes, as the exporter does', () => {
  // U+FF21 sorts before U+1F600 in UTF-8 but after it in UTF-16.
  const roles = ['\uFF21', '\u{1F600}']
  const phases = [{ executor_reachability_delta: { changed: roles.map((role) => ({ role, status: 'unknown' })), removed: [] }, executor_usage_delta: { changed: [], removed: [] } }]
  assert.deepEqual(foldRecordedPhaseReachability(phases)[0].executor_reachability.map((entry) => entry.role), roles)
  assert.throws(() => foldRecordedPhaseReachability([{ ...phases[0], executor_reachability_delta: { changed: [...roles].reverse().map((role) => ({ role, status: 'unknown' })), removed: [] } }]), /reachability delta is malformed/)
})

test('folds recorded deltas into full per-phase reachability', () => {
  const phases = [
    { executor_reachability_delta: { changed: [{ role: 'a', status: 'reachable' }, { role: 'b', status: 'unknown' }], removed: [] }, executor_usage_delta: { changed: [{ role: 'a', status: 'reachable' }], removed: [] } },
    { executor_reachability_delta: { changed: [{ role: 'b', status: 'reachable' }], removed: ['a'] }, executor_usage_delta: { changed: [], removed: [] } },
    { executor_reachability_delta: { changed: [], removed: [] }, executor_usage_delta: { changed: [{ role: 'c', status: 'unreachable' }], removed: ['a'] } },
  ]
  assert.deepEqual(foldRecordedPhaseReachability(phases), [
    { executor_reachability: [{ role: 'a', status: 'reachable' }, { role: 'b', status: 'unknown' }], executor_usage: [{ role: 'a', status: 'reachable' }] },
    { executor_reachability: [{ role: 'b', status: 'reachable' }], executor_usage: [{ role: 'a', status: 'reachable' }] },
    { executor_reachability: [{ role: 'b', status: 'reachable' }], executor_usage: [{ role: 'c', status: 'unreachable' }] },
  ])
  assert.throws(() => foldRecordedPhaseReachability([{ executor_reachability_delta: { changed: [], removed: ['a'] }, executor_usage_delta: { changed: [], removed: [] } }]), /phase 1 reachability delta is malformed/)
})

test('folds the fixture: the first phase delta is the complete state', { skip: fixtureSkip }, () => {
  const folded = foldRecordedPhaseReachability(fixture.recorded.phases)
  const byRole = (entries) => [...entries].sort((left, right) => left.role.localeCompare(right.role))
  assert.deepEqual(folded[0].executor_reachability, byRole(fixture.recorded.phases[0].executor_reachability_delta.changed))
  assert.deepEqual(folded[0].executor_usage, byRole(fixture.recorded.phases[0].executor_usage_delta.changed))
  assert.equal(folded.length, fixture.recorded.phases.length)
})

// ---------------------------------------------------------------------------
// Drift between the importer and the generated JSON Schema.
// ---------------------------------------------------------------------------

function schemaNavigator(schema) {
  const defs = schema.$defs ?? schema.definitions ?? {}
  const deref = (node, path) => {
    let current = node
    for (let depth = 0; depth < 64; depth += 1) {
      assert.ok(current && typeof current === 'object', `schema has no node at ${path}`)
      if (current.$ref) {
        const name = decodeURIComponent(current.$ref.replace(/^#\/(\$defs|definitions)\//, ''))
        assert.ok(defs[name], `schema $ref ${current.$ref} at ${path} does not resolve`)
        current = defs[name]
        continue
      }
      const nullable = current.anyOf ?? (current.oneOf?.some((member) => member.type === 'null') ? current.oneOf : null)
      if (nullable) {
        const members = nullable.filter((member) => member.type !== 'null')
        if (members.length === 1 && members.length !== nullable.length) { current = members[0]; continue }
      }
      if (current.allOf?.length === 1 && !current.properties) { current = current.allOf[0]; continue }
      return current
    }
    throw new Error(`schema reference cycle at ${path}`)
  }
  const branches = (node, tag, path) => {
    const resolved = deref(node, path)
    const members = (resolved.oneOf ?? resolved.anyOf ?? []).map((member) => deref(member, path))
    assert.ok(members.length > 0, `schema at ${path} is not a tagged union on ${tag}`)
    return new Map(members.map((member) => {
      const tagNode = deref(member.properties?.[tag] ?? {}, `${path}.${tag}`)
      const value = tagNode.const ?? tagNode.enum?.[0]
      assert.equal(typeof value, 'string', `schema variant at ${path} has no const ${tag}`)
      return [value, member]
    }))
  }
  const at = (path) => {
    let node = schema
    const trail = ['$']
    for (const segment of path) {
      const resolved = deref(node, trail.join('.'))
      if (segment === '[]') node = resolved.items
      else if (typeof segment === 'object') node = branches(resolved, segment.tag, trail.join('.')).get(segment.variant)
      else node = resolved.properties?.[segment]
      trail.push(typeof segment === 'object' ? `<${segment.variant}>` : segment)
      assert.ok(node, `schema has no ${trail.join('.')}`)
    }
    return node
  }
  const enumValues = (node, path) => {
    const resolved = deref(node, path)
    if (Array.isArray(resolved.enum)) return resolved.enum.filter((value) => typeof value === 'string')
    if (typeof resolved.const === 'string') return [resolved.const]
    const members = resolved.oneOf ?? resolved.anyOf
    assert.ok(members, `schema at ${path} is not an enum`)
    return members.filter((member) => member.type !== 'null').flatMap((member) => enumValues(member, path))
  }
  return { deref, branches, at, enumValues }
}

const sorted = (values) => [...values].sort()

test('importer enum lists match the generated review artifact schema', { skip: schemaSkip }, () => {
  const schema = JSON.parse(readFileSync(schemaPath, 'utf8'))
  const { at, branches, enumValues } = schemaNavigator(schema)
  const grant = ['recorded', 'changes', '[]', 'change', { tag: 'kind', variant: 'grant' }]
  const expectations = {
    changeKinds: () => [...branches(at(['recorded', 'changes', '[]', 'change']), 'kind', 'change').keys()],
    preflightChecks: () => enumValues(at(['preflight', '[]', 'check']), 'preflight.check'),
    evidenceChecks: () => enumValues(at(['preflight', '[]', 'coverage', 'checks_performed', '[]']), 'coverage.checks_performed'),
    evidenceStatuses: () => enumValues(at(['preflight', '[]', 'status']), 'preflight.status'),
    coverageKinds: () => enumValues(at(['preflight', '[]', 'coverage', 'kind']), 'coverage.kind'),
    priorities: () => enumValues(at(['recorded', 'changes', '[]', 'priority']), 'changes.priority'),
    phases: () => enumValues(at(['recorded', 'phases', '[]', 'phase']), 'phases.phase'),
    reachabilityStatuses: () => enumValues(at(['recorded', 'phases', '[]', 'executor_reachability_delta', 'changed', '[]', 'status']), 'delta.status'),
    findingSeverities: () => enumValues(at(['recorded', 'findings', '[]', 'severity']), 'findings.severity'),
    modes: () => enumValues(at(['context', 'mode']), 'context.mode'),
    privileges: () => enumValues(at([...grant, 'privileges', '[]']), 'grant.privileges'),
    objectTypes: () => enumValues(at([...grant, 'object_type']), 'grant.object_type'),
  }
  assert.deepEqual(sorted(Object.keys(expectations)), sorted(Object.keys(REVIEW_ARTIFACT_ENUMS)))
  for (const [name, derive] of Object.entries(expectations)) {
    assert.deepEqual(sorted(REVIEW_ARTIFACT_ENUMS[name]), sorted(derive()), `importer ${name} drifted from ${schemaPath}`)
  }
})

test('importer closed key sets match the generated review artifact schema', { skip: schemaSkip }, () => {
  const schema = JSON.parse(readFileSync(schemaPath, 'utf8'))
  const { deref, branches } = schemaNavigator(schema)
  const compare = (shape, node, path) => {
    if (shape === null) return
    const resolved = deref(node, path)
    if (shape.list) {
      compare(shape.list, resolved.items, `${path}[]`)
      return
    }
    if (shape.fields) {
      assert.deepEqual(sorted(Object.keys(shape.fields)), sorted(Object.keys(resolved.properties ?? {})), `importer keys drifted at ${path}`)
      for (const [key, child] of Object.entries(shape.fields)) compare(child, resolved.properties[key], `${path}.${key}`)
      return
    }
    const variants = branches(resolved, shape.tag, path)
    assert.deepEqual(sorted(Object.keys(shape.variants)), sorted(variants.keys()), `importer ${shape.tag} variants drifted at ${path}`)
    for (const [variant, entries] of Object.entries(shape.variants)) {
      const member = variants.get(variant)
      const memberKeys = Object.keys(member.properties ?? {}).filter((key) => key !== shape.tag)
      assert.deepEqual(sorted(Object.keys(entries)), sorted(memberKeys), `importer keys drifted at ${path}<${variant}>`)
      for (const [key, child] of Object.entries(entries)) compare(child, member.properties[key], `${path}<${variant}>.${key}`)
    }
  }
  compare(REVIEW_ARTIFACT_SHAPE, schema, '$')
})
