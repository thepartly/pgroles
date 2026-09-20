import assert from 'node:assert/strict'
import test from 'node:test'

import {
  analyzeRequest,
  explorerImport,
  loadAnalyzer,
  readableWasmError,
  resetAnalyzerForTests,
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
