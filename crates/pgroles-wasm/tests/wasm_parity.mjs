import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { createRequire } from 'node:module'

const [nativeBinary, wasmDirectory, fixturesDirectory] = process.argv.slice(2)
if (!nativeBinary || !wasmDirectory || !fixturesDirectory) {
  throw new Error('usage: wasm_parity.mjs <native-binary> <wasm-directory> <fixtures-directory>')
}

const require = createRequire(import.meta.url)
const wasm = require(resolve(wasmDirectory, 'pgroles_wasm.js'))

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
