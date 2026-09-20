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
})
