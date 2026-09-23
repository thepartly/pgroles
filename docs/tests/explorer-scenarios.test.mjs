import assert from 'node:assert/strict'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'
import test from 'node:test'

import { explorerScenarios, getExplorerScenario } from '../src/lib/explorerScenarios.mjs'
import { assertScenarioAnalysis, scenarioCases } from './explorer-scenarios.assertions.mjs'

const pages = fileURLToPath(new URL('../src/pages', import.meta.url))

test('bundled scenarios have unique IDs, resolvable docs, and semantic expectations', () => {
  assert.equal(new Set(explorerScenarios.map(({ id }) => id)).size, explorerScenarios.length)
  for (const scenario of explorerScenarios) {
    assert.match(scenario.id, /^[a-z][a-z0-9-]+$/)
    assert.equal(getExplorerScenario(scenario.id), scenario)
    assert(scenario.title && scenario.description && scenario.explanation)
    assert(scenario.relatedDocs.length > 0)
    for (const doc of scenario.relatedDocs) {
      assert(doc.href.startsWith('/docs/'))
      const pathname = doc.href.split('#')[0]
      assert(['.md', '.jsx'].some((extension) => existsSync(resolve(pages, `.${pathname}${extension}`))), doc.href)
    }
    for (const fixture of scenarioCases(scenario)) {
      assert.equal(fixture.request.schema_version, 'pgroles.explorer.v1')
      assert(['additive', 'adopt', 'authoritative'].includes(fixture.request.mode))
      assert(fixture.request.desired_yaml.length > 0)
      assert(fixture.request.executor.role)
      assert(Object.values(fixture.expected).some((assertions) => assertions.length > 0), `${fixture.id}: empty semantic expectations`)
    }
  }
  assert.equal(getExplorerScenario('unrecognised-scenario'), undefined)
})

test('all documentation launchers use an existing bundled scenario ID', () => {
  function checkDirectory(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = resolve(directory, entry.name)
      if (entry.isDirectory()) checkDirectory(path)
      else if (entry.name.endsWith('.md')) {
        for (const match of readFileSync(path, 'utf8').matchAll(/explorer-scenario\s+scenario="([^"]+)"/g)) {
          assert(getExplorerScenario(match[1]), `${path}: unknown scenario ${match[1]}`)
        }
      }
    }
  }
  checkDirectory(pages)
})

test('semantic assertions reject incorrect effects and phase authority', () => {
  const response = { changes: [{ AddMember: { role: 'analyst', member: 'bob' } }], findings: [], phases: [] }
  assert.throws(() => assertScenarioAnalysis(response, { absentChanges: ['AddMember'] }, 'example'))
  assert.throws(() => assertScenarioAnalysis(response, { changes: [{ kind: 'RemoveMember' }] }, 'example'))
  assert.throws(() => assertScenarioAnalysis(response, { findings: [{ kind: 'required_role_unavailable' }] }, 'example'))
  assert.throws(() => assertScenarioAnalysis(response, {
    phaseReachability: [{ phase: 'membership_remove', role: 'analyst', authority: 'usage', status: 'unreachable' }],
  }, 'example'))
  assert.throws(() => assertScenarioAnalysis({ ...response, pg_major_version: 16 }, { response: { pg_major_version: 15 } }, 'example'))
})

test('phase assertions require an occurrence when a phase label repeats', () => {
  const boundary = (status) => ({ executor_reachability: [], executor_usage: [{ role: 'app', status }] })
  const response = {
    changes: [],
    findings: [],
    phases: [
      { phase: 'create', ...boundary('unknown') },
      { phase: 'alter', ...boundary('unknown') },
      { phase: 'create', ...boundary('reachable') },
    ],
  }
  const assertion = { phase: 'create', role: 'app', authority: 'usage' }
  assert.throws(() => assertScenarioAnalysis(response, { phaseReachability: [{ ...assertion, status: 'reachable' }] }, 'example'), /occurs 2 times/)
  assert.doesNotThrow(() => assertScenarioAnalysis(response, { phaseReachability: [{ ...assertion, occurrence: 0, status: 'unknown' }] }, 'example'))
  assert.doesNotThrow(() => assertScenarioAnalysis(response, { phaseReachability: [{ ...assertion, occurrence: 1, status: 'reachable' }] }, 'example'))
  assert.throws(() => assertScenarioAnalysis(response, { phaseReachability: [{ ...assertion, occurrence: 2, status: 'reachable' }] }, 'example'), /no occurrence 2/)
})

test('scenario requests use supported optional analysis fields', () => {
  for (const scenario of explorerScenarios) {
    for (const { id, request } of scenarioCases(scenario)) {
      if (request.pg_major_version !== undefined) {
        assert(Number.isInteger(request.pg_major_version) && request.pg_major_version >= 12 && request.pg_major_version <= 20, `${id}: pg_major_version`)
      }
      if (request.authority_graph_complete !== undefined) assert.equal(typeof request.authority_graph_complete, 'boolean', `${id}: authority_graph_complete`)
      if (request.executor.createrole !== undefined) assert(['allowed', 'denied', 'unknown'].includes(request.executor.createrole), `${id}: executor.createrole`)
    }
  }
  const versions = new Set(explorerScenarios.flatMap((scenario) => scenarioCases(scenario).map(({ request }) => request.pg_major_version ?? 16)))
  assert(versions.has(15) && versions.has(16), 'scenarios cover PostgreSQL 15 and 16 authority rules')
  assert(explorerScenarios.some((scenario) => scenarioCases(scenario).some(({ request }) => request.authority_graph_complete === false)), 'a scenario covers a partial authority graph')
})
