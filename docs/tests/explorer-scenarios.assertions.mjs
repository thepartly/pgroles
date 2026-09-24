import assert from 'node:assert/strict'

function matches(actual, expected) {
  return Object.entries(expected).every(([key, value]) => actual[key] === value)
}

// Contiguous runs of one phase are grouped, so a plan can repeat a phase
// label (for example create, alter, create). An assertion on a repeated
// phase must say which occurrence it means.
function phaseOccurrence(response, boundary, label) {
  const candidates = response.phases.filter((item) => item.phase === boundary.phase)
  assert(candidates.length > 0, `${label}: missing phase ${boundary.phase}`)
  if (boundary.occurrence === undefined) {
    assert.equal(candidates.length, 1,
      `${label}: phase ${boundary.phase} occurs ${candidates.length} times; set occurrence to choose one`)
    return candidates[0]
  }
  assert(Number.isSafeInteger(boundary.occurrence) && boundary.occurrence >= 0, `${label}: invalid occurrence`)
  const phase = candidates[boundary.occurrence]
  assert(phase, `${label}: phase ${boundary.phase} has no occurrence ${boundary.occurrence}`)
  return phase
}

export function assertScenarioAnalysis(response, expected, label) {
  const changes = response.changes.map((change) => {
    const [kind, details] = Object.entries(change)[0]
    return { kind, ...details }
  })
  for (const change of expected.changes ?? []) {
    assert(changes.some((actual) => matches(actual, change)), `${label}: missing change ${JSON.stringify(change)}`)
  }
  for (const kind of expected.absentChanges ?? []) {
    assert(!changes.some((change) => change.kind === kind), `${label}: unexpected ${kind}`)
  }
  for (const finding of expected.findings ?? []) {
    assert(response.findings.some((actual) => matches(actual, finding)), `${label}: missing finding ${JSON.stringify(finding)}`)
  }
  for (const finding of expected.absentFindings ?? []) {
    assert(!response.findings.some((actual) => matches(actual, finding)), `${label}: unexpected finding ${JSON.stringify(finding)}`)
  }
  for (const boundary of expected.phaseReachability ?? []) {
    const phase = phaseOccurrence(response, boundary, label)
    assert(['usage', 'set_role'].includes(boundary.authority), `${label}: invalid authority assertion`)
    const statuses = boundary.authority === 'usage' ? phase.executor_usage : phase.executor_reachability
    assert.equal(statuses.find((item) => item.role === boundary.role)?.status, boundary.status,
      `${label}: ${boundary.authority} for ${boundary.role} after ${boundary.phase}`)
  }
  for (const [field, value] of Object.entries(expected.response ?? {})) {
    assert.deepEqual(response[field], value, `${label}: response ${field}`)
  }
}

export function scenarioCases(scenario) {
  return [
    { id: scenario.id, request: scenario.request, expected: scenario.expected },
    ...(scenario.cases ?? []).map((variant) => ({
      id: `${scenario.id}/${variant.id}`,
      request: { ...scenario.request, ...variant.requestOverrides },
      expected: variant.expected,
    })),
  ]
}
