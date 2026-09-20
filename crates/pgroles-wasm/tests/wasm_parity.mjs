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
      const native = spawnSync(nativeBinary, [requestPath], { encoding: 'utf8' })
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
  const native = spawnSync(nativeBinary, [fixturePath], { encoding: 'utf8' })
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
  const native = spawnSync(nativeBinary, [invalidPath], { encoding: 'utf8' })
  assert.notEqual(native.status, 0, `${invalidName}: native analyzer unexpectedly accepted invalid input`)
  assert.throws(() => wasm.analyze(input), `${invalidName}: WASM analyzer unexpectedly accepted invalid input`)
  console.log(`PASS ${invalidName}`)
}
