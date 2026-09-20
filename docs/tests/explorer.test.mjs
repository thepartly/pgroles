import assert from 'node:assert/strict'
import test from 'node:test'

import {
  analyzeRequest,
  explorerImport,
  loadAnalyzer,
  loadPolicyEngine,
  policyRequest,
  readableWasmError,
  resetAnalyzerForTests,
  reviewArtifactImport,
  validateReviewArtifactFileSize,
  validateSnapshotFileSize,
  wasmModuleUrl,
} from '../src/lib/pgrolesExplorer.mjs'

test('initializes the web module once and exposes analyze', async () => {
  resetAnalyzerForTests()
  let imports = 0
  let initializes = 0
  const analyze = () => ({ schema_version: 'pgroles.explorer.v1' })
  const importer = async (url) => {
    imports += 1
    assert.equal(url, '/pgroles/wasm/pgroles_wasm.js')
    return { default: async () => { initializes += 1 }, analyze }
  }
  assert.equal(await loadAnalyzer('/pgroles', importer), analyze)
  assert.equal(await loadAnalyzer('/pgroles', importer), analyze)
  assert.equal(imports, 1)
  assert.equal(initializes, 1)
})

test('builds the versioned request expected by the Rust boundary', () => {
  assert.deepEqual(analyzeRequest({ current: { roles: {} }, desiredYaml: 'roles: []', mode: 'additive', executorRole: 'deployer' }), {
    schema_version: 'pgroles.explorer.v1', current: { roles: {} }, desired_yaml: 'roles: []', mode: 'additive', executor: { role: 'deployer', superuser: false, memberships: [], new_membership_set_role: 'unknown', new_role_set_role: 'unknown', new_role_inherit: 'unknown', new_role_admin_option: 'unknown' },
  })
})

test('authoring needs only YAML and shares initialization with analysis', async () => {
  resetAnalyzerForTests()
  let imports = 0
  const engine = { default: async () => {}, validate: () => {}, compile: () => {}, analyze: () => {} }
  const importer = async () => { imports += 1; return engine }
  assert.equal(await loadPolicyEngine('/pgroles', importer), engine)
  assert.equal(await loadAnalyzer('/pgroles', importer), engine.analyze)
  assert.equal(imports, 1)
  assert.deepEqual(policyRequest('roles: []'), { schema_version: 'pgroles.policy.v1', desired_yaml: 'roles: []' })
})

test('preserves every imported executor authority fact in the request', () => {
  const memberships = [{ role: 'owner', member: 'deployer', set_role: 'allowed', inherit: 'denied', admin_option: 'unknown' }]
  const request = analyzeRequest({
    current: {}, desiredYaml: 'roles: []', mode: 'authoritative', executorRole: 'deployer',
    executorSuperuser: true, executorMemberships: memberships,
    newMembershipSetRole: 'allowed', newRoleSetRole: 'denied', newRoleInherit: 'allowed', newRoleAdminOption: 'unknown',
  })
  assert.deepEqual(request.executor, {
    role: 'deployer', superuser: true, memberships,
    new_membership_set_role: 'allowed', new_role_set_role: 'denied', new_role_inherit: 'allowed', new_role_admin_option: 'unknown',
  })
})

test('validates an imported envelope version and preserves its executor facts', () => {
  const executor = { role: 'deployer', new_role_inherit: 'allowed' }
  assert.deepEqual(explorerImport({ schema_version: 'pgroles.explorer.v1', current: { roles: {} }, executor }), {
    current: { roles: {} }, executor,
  })
  assert.throws(() => explorerImport({ schema_version: 'pgroles.explorer.v2', current: {} }), /unsupported explorer schema version/)
})

test('rejects oversized snapshot files before reading them', () => {
  assert.doesNotThrow(() => validateSnapshotFileSize(4_194_304))
  assert.throws(() => validateSnapshotFileSize(4_194_305), /4194305 bytes; limit is 4194304 bytes/)
  assert.throws(() => validateReviewArtifactFileSize(4_194_305), /review artifact file is 4194305 bytes/)
})

test('accepts only structurally valid recorded review artifacts', () => {
  const artifact = {
    schema_version: 'pgroles.review-artifact.v1',
    provenance: { tool_version: 'test', captured_at: '2026-01-01T00:00:00Z', target_label: 'test', pg_major_version: 16, policy: { content_digest: `sha256:${'0'.repeat(64)}` } },
    context: { mode: 'additive', inspector: { role: 'inspector' }, intended_executor: { role: 'executor' } },
    preflight: [], exploration: { status: 'omitted', reason: 'recorded_only_export' },
    recorded: { changes: [], phases: [], findings: [], visual: { nodes: [], edges: [] }, sql_preview: { status: 'available', sql: '' }, review_fingerprint: `sha256:${'1'.repeat(64)}` },
  }
  assert.equal(reviewArtifactImport(artifact), artifact)
  assert.doesNotThrow(() => reviewArtifactImport({ ...artifact, preflight: [{ check: 'server_compatibility', status: 'passed', issue_count: 0 }] }))
  assert.throws(() => reviewArtifactImport({ ...artifact, schema_version: 'pgroles.review-artifact.v2' }), /unsupported review artifact schema version/)
  assert.throws(() => reviewArtifactImport({ ...artifact, recorded: { ...artifact.recorded, changes: {} } }), /recorded collections are malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, recorded: { ...artifact.recorded, sql_preview: { status: 'invented' } } }), /SQL preview is malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, preflight: [null] }), /preflight evidence is malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, recorded: { ...artifact.recorded, sql_preview: { status: 'available', sql: {} } } }), /SQL preview content is malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, context: { ...artifact.context, mode: 'invented' } }), /execution context is malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, preflight: [{ check: 'server_compatibility', status: 'passed', issue_count: 1 }] }), /preflight evidence is malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, recorded: { ...artifact.recorded, review_fingerprint: 'sha256:not-a-digest' } }), /fingerprint is malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, exploration: { status: 'omitted', reason: 'invented' } }), /exploration status is malformed/)
})

test('preserves malformed-input errors from wasm-bindgen', () => {
  assert.equal(readableWasmError('missing field `current`'), 'missing field `current`')
  assert.equal(readableWasmError(new Error('invalid YAML')), 'invalid YAML')
})

test('uses the deployment base path for wasm assets', () => {
  assert.equal(wasmModuleUrl(''), '/wasm/pgroles_wasm.js')
  assert.equal(wasmModuleUrl('/pgroles'), '/pgroles/wasm/pgroles_wasm.js')
})

test('allows retry after wasm initialization fails', async () => {
  resetAnalyzerForTests()
  let attempts = 0
  const importer = async () => {
    attempts += 1
    if (attempts === 1) throw new Error('network interrupted')
    return { default: async () => {}, analyze: () => 'ok' }
  }
  await assert.rejects(loadAnalyzer('', importer), /network interrupted/)
  const analyze = await loadAnalyzer('', importer)
  assert.equal(analyze(), 'ok')
  assert.equal(attempts, 2)
})
