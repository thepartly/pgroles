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
    context: { mode: 'additive', authority_graph_complete: false, inspector: { role: 'inspector' }, intended_executor: { role: 'executor' } },
    preflight: [], exploration: { status: 'omitted', reason: 'recorded_only_export' },
    recorded: { changes: [], phases: [], findings: [], visual: { nodes: [], edges: [] }, sql_preview: { status: 'available', sql: '' }, review_fingerprint: `sha256:${'1'.repeat(64)}` },
  }
  assert.equal(reviewArtifactImport(artifact), artifact)
  assert.doesNotThrow(() => reviewArtifactImport({ ...artifact, preflight: [{ check: 'server_compatibility', status: 'passed', issue_count: 0, coverage: { kind: 'targeted', checks_performed: [], checked_change_indices: [], unchecked_change_indices: [] } }] }))
  assert.throws(() => reviewArtifactImport({ ...artifact, schema_version: 'pgroles.review-artifact.v2' }), /unsupported review artifact schema version/)
  assert.throws(() => reviewArtifactImport({ ...artifact, recorded: { ...artifact.recorded, changes: {} } }), /recorded collections are malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, recorded: { ...artifact.recorded, sql_preview: { status: 'invented' } } }), /SQL preview is malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, preflight: [null] }), /preflight evidence is malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, recorded: { ...artifact.recorded, sql_preview: { status: 'available', sql: {} } } }), /SQL preview content is malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, context: { ...artifact.context, mode: 'invented' } }), /execution context is malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, preflight: [{ check: 'server_compatibility', status: 'passed', issue_count: 1, coverage: { kind: 'targeted', checks_performed: [], checked_change_indices: [], unchecked_change_indices: [] } }] }), /preflight evidence is malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, recorded: { ...artifact.recorded, review_fingerprint: 'sha256:not-a-digest' } }), /fingerprint is malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, exploration: { status: 'omitted', reason: 'invented' } }), /exploration status is malformed/)
})

test('rejects falsy nested review fields, malformed change variants, and incomplete phases', () => {
  const artifact = {
    schema_version: 'pgroles.review-artifact.v1',
    provenance: { tool_version: 'test', captured_at: '2026-01-01T00:00:00Z', target_label: 'test', pg_major_version: 16, policy: { content_digest: `sha256:${'0'.repeat(64)}` } },
    context: { mode: 'additive', authority_graph_complete: false, inspector: { role: 'inspector' }, intended_executor: { role: 'executor' } },
    preflight: [], exploration: { status: 'omitted', reason: 'recorded_only_export' },
    recorded: {
      changes: [{ index: 0, priority: 'Review', change: { kind: 'drop_role', name: 'obsolete' } }],
      phases: [{ phase: 'retire', change_indices: [0], executor_reachability: [], executor_usage: [] }],
      findings: [], visual: { nodes: [], edges: [] }, sql_preview: { status: 'available', sql: '' }, review_fingerprint: `sha256:${'1'.repeat(64)}`,
    },
  }
  assert.equal(reviewArtifactImport(artifact), artifact)
  for (const omissions of [false, 0, '']) {
    assert.throws(() => reviewArtifactImport({ ...artifact, recorded: { ...artifact.recorded, changes: [{ ...artifact.recorded.changes[0], omissions }] } }), /changes are malformed/)
  }
  for (const source of [false, 0, '']) {
    assert.throws(() => reviewArtifactImport({ ...artifact, recorded: { ...artifact.recorded, changes: [{ ...artifact.recorded.changes[0], source }] } }), /changes are malformed/)
  }
  assert.throws(() => reviewArtifactImport({ ...artifact, recorded: { ...artifact.recorded, changes: [{ ...artifact.recorded.changes[0], change: { kind: 'drop_role' } }] } }), /changes are malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, recorded: { ...artifact.recorded, phases: [] } }), /phases are malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, recorded: { ...artifact.recorded, phases: [{ ...artifact.recorded.phases[0], change_indices: [0, 0] }] } }), /phases are malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, recorded: { ...artifact.recorded, phases: [{ ...artifact.recorded.phases[0], change_indices: [] }] } }), /phases are malformed/)
})

test('accepts every sanitized ReviewChange variant', () => {
  const state = { login: false, superuser: false, createdb: false, createrole: false, inherit: true, replication: false, bypassrls: false, connection_limit: -1, comment_present: false, password_valid_until: null, config_parameters: [] }
  const changes = [
    { kind: 'create_role', name: 'role', state }, { kind: 'create_schema', name: 'schema', owner: null },
    { kind: 'alter_schema_owner', name: 'schema', owner: 'owner' }, { kind: 'ensure_schema_owner_privileges', name: 'schema', owner: 'owner', privileges: ['USAGE'] },
    { kind: 'alter_role', name: 'role', attributes: [{ kind: 'set_config', parameter: 'work_mem' }, { kind: 'valid_until', value: null }] }, { kind: 'set_comment', name: 'role', comment_present: true },
    { kind: 'grant', role: 'role', privileges: ['SELECT'], object_type: 'table', schema: 'app', name: 'items' }, { kind: 'revoke', role: 'role', privileges: ['SELECT'], object_type: 'table', schema: 'app', name: 'items', grantor: null },
    { kind: 'set_default_privilege', owner: 'owner', scope: { type: 'global' }, on_type: 'table', grantee: 'role', privileges: ['SELECT'] }, { kind: 'revoke_default_privilege', owner: 'owner', scope: { type: 'schema', schema: 'app' }, on_type: 'table', grantee: 'PUBLIC', privileges: ['SELECT'] },
    { kind: 'add_member', role: 'group', member: 'role', inherit: true, admin: false }, { kind: 'remove_member', role: 'group', member: 'role', grantor: null },
    { kind: 'reassign_owned', from_role: 'old', to_role: 'new' }, { kind: 'drop_owned', role: 'old' }, { kind: 'terminate_sessions', role: 'old' }, { kind: 'set_password', name: 'role' }, { kind: 'drop_role', name: 'old' },
  ]
  const artifact = {
    schema_version: 'pgroles.review-artifact.v1', provenance: { tool_version: 'test', captured_at: '2026-01-01T00:00:00Z', target_label: 'test', pg_major_version: 16, policy: { content_digest: `sha256:${'0'.repeat(64)}` } },
    context: { mode: 'additive', authority_graph_complete: false, inspector: { role: 'inspector' }, intended_executor: { role: 'executor' } }, preflight: [], exploration: { status: 'omitted', reason: 'recorded_only_export' },
    recorded: { changes: changes.map((change, index) => ({ index, priority: 'Review', change })), phases: [{ phase: 'create', change_indices: changes.map((_, index) => index), executor_reachability: [], executor_usage: [] }], findings: [], visual: { nodes: [], edges: [] }, sql_preview: { status: 'available', sql: '' }, review_fingerprint: `sha256:${'1'.repeat(64)}` },
  }
  assert.equal(reviewArtifactImport(artifact), artifact)
})

test('rejects authority overclaims, contradictory coverage, and invented source keys', () => {
  const artifact = {
    schema_version: 'pgroles.review-artifact.v1', provenance: { tool_version: 'test', captured_at: '2026-01-01T00:00:00Z', target_label: 'test', pg_major_version: 16, policy: { content_digest: `sha256:${'0'.repeat(64)}` } },
    context: { mode: 'additive', authority_graph_complete: false, inspector: { role: 'inspector' }, intended_executor: { role: 'executor' } }, exploration: { status: 'omitted', reason: 'recorded_only_export' },
    recorded: { changes: [{ index: 0, priority: 'Review', source: { document: 'roles.yaml', managed_key: { kind: 'role', name: 'app' } }, change: { kind: 'drop_role', name: 'app' } }], phases: [{ phase: 'retire', change_indices: [0], executor_reachability: [], executor_usage: [] }], findings: [], visual: { nodes: [], edges: [] }, sql_preview: { status: 'available', sql: '' }, review_fingerprint: `sha256:${'1'.repeat(64)}` },
    preflight: [{ check: 'executor_authority', status: 'unknown', issue_count: 0, coverage: { kind: 'targeted', checks_performed: [], checked_change_indices: [], unchecked_change_indices: [0] } }],
  }
  assert.equal(reviewArtifactImport(artifact), artifact)
  assert.throws(() => reviewArtifactImport({ ...artifact, preflight: [{ ...artifact.preflight[0], status: 'passed' }] }), /preflight evidence is malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, preflight: [{ ...artifact.preflight[0], coverage: { ...artifact.preflight[0].coverage, kind: 'complete' } }] }), /preflight coverage is malformed/)
  assert.throws(() => reviewArtifactImport({ ...artifact, recorded: { ...artifact.recorded, changes: [{ ...artifact.recorded.changes[0], source: { document: 'roles.yaml', managed_key: { kind: 'invented' } } }] } }), /changes are malformed/)
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
