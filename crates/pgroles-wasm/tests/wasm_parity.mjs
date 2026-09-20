import assert from 'node:assert/strict'
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { explorerScenarios } from '../../../docs/src/lib/explorerScenarios.mjs'
import { assertScenarioAnalysis, scenarioCases } from '../../../docs/tests/explorer-scenarios.assertions.mjs'

const [nativeBinary, wasmDirectory, fixturesDirectory] = process.argv.slice(2)
if (!nativeBinary || !wasmDirectory || !fixturesDirectory) {
  throw new Error('usage: wasm_parity.mjs <native-binary> <wasm-directory> <fixtures-directory>')
}

const require = createRequire(import.meta.url)
const wasm = require(resolve(wasmDirectory, 'pgroles_wasm.js'))

const scenarioDirectory = mkdtempSync(resolve(tmpdir(), 'pgroles-scenarios-'))
try {
  for (const scenario of explorerScenarios) {
    for (const { id, request, expected } of scenarioCases(scenario)) {
      const requestPath = resolve(scenarioDirectory, 'request.json')
      writeFileSync(requestPath, JSON.stringify(request))
      const native = spawnSync(nativeBinary, ['analyze', requestPath], { encoding: 'utf8' })
      assert.equal(native.status, 0, `${id}: native analyzer failed: ${native.stderr}`)
      const nativeResponse = JSON.parse(native.stdout)
      const wasmResponse = wasm.analyze(request)
      assertScenarioAnalysis(nativeResponse, expected, `${id} (native)`)
      assertScenarioAnalysis(wasmResponse, expected, `${id} (WASM)`)
      assert.deepEqual(wasmResponse, nativeResponse, `${id}: native/WASM mismatch`)
      console.log(`PASS scenario ${id}`)
    }
  }
} finally {
  rmSync(scenarioDirectory, { recursive: true, force: true })
}

for (const fixtureName of readdirSync(fixturesDirectory).filter((name) => name.endsWith('.json')).sort()) {
  const fixturePath = resolve(fixturesDirectory, fixtureName)
  const input = JSON.parse(readFileSync(fixturePath, 'utf8'))
  const native = spawnSync(nativeBinary, ['analyze', fixturePath], { encoding: 'utf8' })
  assert.equal(native.status, 0, `${fixtureName}: native analyzer failed: ${native.stderr}`)
  const nativeResponse = JSON.parse(native.stdout)
  const wasmResponse = wasm.analyze(input)
  assert.deepEqual(wasmResponse, nativeResponse, `${fixtureName}: WASM response differs from native response`)
  console.log(`PASS ${fixtureName}`)
}

const invalidDirectory = resolve(fixturesDirectory, '..', 'invalid')
for (const invalidName of readdirSync(invalidDirectory).filter((name) => name.endsWith('.json')).sort()) {
  const invalidPath = resolve(invalidDirectory, invalidName)
  const input = JSON.parse(readFileSync(invalidPath, 'utf8'))
  const native = spawnSync(nativeBinary, ['analyze', invalidPath], { encoding: 'utf8' })
  assert.notEqual(native.status, 0, `${invalidName}: native analyzer unexpectedly accepted invalid input`)
  assert.throws(() => wasm.analyze(input), `${invalidName}: WASM analyzer unexpectedly accepted invalid input`)
  console.log(`PASS ${invalidName}`)
}

const policyDirectory = resolve(fixturesDirectory, '..', 'policy')
for (const policyName of readdirSync(policyDirectory).filter((name) => name.endsWith('.json')).sort()) {
  const policyPath = resolve(policyDirectory, policyName)
  const input = JSON.parse(readFileSync(policyPath, 'utf8'))
  for (const operation of ['validate', 'compile']) {
    const native = spawnSync(nativeBinary, [operation, policyPath], { encoding: 'utf8' })
    assert.equal(native.status, 0, `${policyName} ${operation}: native failed: ${native.stderr}`)
    const nativeResponse = JSON.parse(native.stdout)
    const wasmResponse = wasm[operation](input)
    assert.deepEqual(wasmResponse, nativeResponse, `${policyName} ${operation}: native/WASM mismatch`)
  }

  if (policyName === 'password-source.json') {
    const compiled = wasm.compile(input)
    assert.equal(compiled.policy.expanded.roles[0].password.from_env, 'PGROLES_PARITY_UNRESOLVED_SECRET')
  }
  if (policyName === 'valid-profile.json') {
    assert.equal(wasm.validate(input).valid, true)
    assert.equal(wasm.compile(input).policy.expanded.roles[0].name, 'analytics-reader')
  }
  if (policyName === 'invalid-yaml-utf8.json') {
    const validated = wasm.validate(input)
    assert.equal(validated.valid, false)
    assert.equal(validated.diagnostics[0].code, 'invalid_yaml')
    assert.ok(validated.diagnostics[0].range)
    const { startByte, endByte } = validated.diagnostics[0].range
    assert.equal(startByte, 41)
    assert.equal(startByte, endByte)
    const decodedPrefix = Buffer.from(input.desired_yaml).subarray(0, startByte).toString('utf8')
    assert.equal(Buffer.byteLength(decodedPrefix), startByte, 'syntax cursor must be on a UTF-8 boundary')
  }
  if (policyName === 'semantic-error.json') {
    const diagnostic = wasm.validate(input).diagnostics[0]
    assert.equal(diagnostic.code, 'password_without_login')
    assert.equal('range' in diagnostic, false)
  }
  if (policyName === 'exclusive-managed-role.json') {
    const diagnostic = wasm.validate(input).diagnostics[0]
    assert.equal(diagnostic.code, 'exclusive_membership_on_managed_role')
    assert.equal(diagnostic.path, 'memberships[0].exclusive')
    assert.equal('range' in diagnostic, false)
  }
  if (policyName === 'unsupported-schema.json') {
    const compiled = wasm.compile(input)
    assert.equal(compiled.policy, undefined)
    assert.equal(compiled.diagnostics[0].code, 'unsupported_schema_version')
  }
  console.log(`PASS policy ${policyName}`)
}

const malformedPolicyDirectory = resolve(policyDirectory, 'malformed-request')
for (const malformedName of readdirSync(malformedPolicyDirectory).filter((name) => name.endsWith('.json')).sort()) {
  const malformedPath = resolve(malformedPolicyDirectory, malformedName)
  const input = JSON.parse(readFileSync(malformedPath, 'utf8'))
  for (const operation of ['validate', 'compile']) {
    const native = spawnSync(nativeBinary, [operation, malformedPath], { encoding: 'utf8' })
    assert.notEqual(native.status, 0, `${malformedName} ${operation}: native unexpectedly accepted malformed request`)
    assert.throws(() => wasm[operation](input), `${malformedName} ${operation}: WASM unexpectedly accepted malformed request`)
  }
  console.log(`PASS malformed policy request ${malformedName}`)
}

const boundsDirectory = mkdtempSync(resolve(tmpdir(), 'pgroles-policy-bounds-'))
try {
  const oversizedRequest = {
    schema_version: 'pgroles.policy.v1',
    desired_yaml: ' '.repeat(1024 * 1024 + 1),
  }
  const oversizedPath = resolve(boundsDirectory, 'oversized.json')
  writeFileSync(oversizedPath, JSON.stringify(oversizedRequest))
  for (const operation of ['validate', 'compile']) {
    const native = spawnSync(nativeBinary, [operation, oversizedPath], { encoding: 'utf8' })
    assert.equal(native.status, 0, `oversized policy ${operation}: native failed: ${native.stderr}`)
    const nativeResponse = JSON.parse(native.stdout)
    const wasmResponse = wasm[operation](oversizedRequest)
    assert.deepEqual(wasmResponse, nativeResponse, `oversized policy ${operation}: native/WASM mismatch`)
    assert.equal(wasmResponse.diagnostics[0].code, 'policy_too_large')
    assert.equal('policy' in wasmResponse, false)
  }
  console.log('PASS policy input bound')
} finally {
  rmSync(boundsDirectory, { recursive: true, force: true })
}
