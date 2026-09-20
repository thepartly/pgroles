import assert from 'node:assert/strict'

function matches(actual, expected) {
  return Object.entries(expected).every(([key, value]) => actual[key] === value)
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
    const phase = response.phases.find((item) => item.phase === boundary.phase)
    assert(phase, `${label}: missing phase ${boundary.phase}`)
    assert(['usage', 'set_role'].includes(boundary.authority), `${label}: invalid authority assertion`)
    const statuses = boundary.authority === 'usage' ? phase.executor_usage : phase.executor_reachability
    assert.equal(statuses.find((item) => item.role === boundary.role)?.status, boundary.status,
      `${label}: ${boundary.authority} for ${boundary.role} after ${boundary.phase}`)
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
