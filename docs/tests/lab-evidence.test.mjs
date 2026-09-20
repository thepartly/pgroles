import assert from 'node:assert/strict'
import test from 'node:test'
import { PGlite } from '@electric-sql/pglite'
import { acmeChapterSeeds, chapters } from '../src/components/AcmeStoryData.mjs'
import { runLabStep } from '../src/components/labExecution.mjs'

function step(chapter, title) {
  const match = chapters[chapter].steps.find((candidate) => candidate.title === title)
  assert(match, `missing ${chapter} step: ${title}`)
  return match
}

async function runCanonical(chapter, title) {
  const selected = step(chapter, title)
  const output = await runLabStep({
    createDatabase: () => PGlite.create(),
    setup: selected.setup,
    role: selected.role,
    sql: selected.sql,
    inspect: selected.inspect,
    inspectAsActor: selected.inspectAsActor,
  })
  assert(selected.expect(output, output.inspection), `${chapter}: ${title} did not reach its canonical outcome`)
  return { selected, output }
}

async function runMutation(chapter, title, sql) {
  const selected = step(chapter, title)
  const output = await runLabStep({
    createDatabase: () => PGlite.create(),
    setup: selected.setup,
    role: selected.role,
    sql,
    inspect: selected.inspect,
    inspectAsActor: selected.inspectAsActor,
  })
  return { selected, output, cards: selected.cards(output.inspection, output) }
}

test('chapter 1 mutates and verifies under Alice in the same run', async () => {
  const { output } = await runCanonical('gates', 'Open the table gate — and get the rows')
  assert.deepEqual(output.identity.before, { session_user: 'postgres', current_user: 'postgres' })
  assert.deepEqual(output.identity.after, { session_user: 'postgres', current_user: 'alice' })
  assert.equal(output.results[0].rows.length, 2)
})

test('chapter 2 direct-ACL card reads direct catalog evidence', async () => {
  const { selected, output } = await runCanonical('capabilities', 'Count Alice’s access paths')
  const cards = selected.cards(output.inspection, output)
  assert.deepEqual(cards.find(([label]) => label === 'Alice path 2')?.slice(0, 2), ['Alice path 2', 'direct ACL remains'])
  assert.deepEqual(cards.find(([label]) => label === 'Known access paths')?.slice(0, 2), ['Known access paths', '2'])
})

test('effective access cards distinguish inherited and direct paths', async () => {
  const { selected, output } = await runCanonical('drift', 'Make the failed offboarding visible')
  const cards = selected.cards(output.inspection, output)
  assert.deepEqual(cards.find(([label]) => label === 'Inherited reader access')?.slice(0, 2), ['Inherited reader access', 'none'])
  assert.deepEqual(cards.find(([label]) => label === 'Schema')?.slice(0, 2), ['Schema', 'USAGE'])
  assert.deepEqual(cards.find(([label]) => label === 'Table')?.slice(0, 2), ['Table', 'SELECT'])
})

test('direct-ACL card stays absent when inherited effective access survives', async () => {
  const { output, cards } = await runMutation('capabilities', 'Count Alice’s access paths', `REVOKE SELECT ON app.orders FROM alice;
REVOKE USAGE ON SCHEMA app FROM alice;`)
  assert.equal(output.inspection.object_select, true)
  assert.deepEqual(cards.find(([label]) => label === 'Alice path 1')?.slice(0, 2), ['Alice path 1', 'membership'])
  assert.deepEqual(cards.find(([label]) => label === 'Alice path 2')?.slice(0, 2), ['Alice path 2', 'missing'])
  assert.deepEqual(cards.find(([label]) => label === 'Known access paths')?.slice(0, 2), ['Known access paths', '1'])
})

test('INHERIT FALSE keeps membership and SET while disabling inherited usage', async () => {
  const database = await PGlite.create()
  try {
    await database.exec(acmeChapterSeeds.dormantSeed)
    const { rows } = await database.query(`SELECT
      pg_has_role('bob', 'analyst', 'MEMBER') AS member,
      pg_has_role('bob', 'analyst', 'USAGE') AS inherited_usage,
      pg_has_role('bob', 'analyst', 'SET') AS can_set;`)
    assert.deepEqual(rows, [{ member: true, inherited_usage: false, can_set: true }])
  } finally {
    await database.close()
  }
})

test('INHERIT FALSE cards retain membership without claiming inherited access', async () => {
  const membershipStep = await runCanonical('mechanics', 'Turn off automatic inheritance')
  const membershipCards = membershipStep.selected.cards(membershipStep.output.inspection, membershipStep.output)
  assert.deepEqual(membershipCards.find(([label]) => label === 'Membership relationship')?.slice(0, 2), ['Membership relationship', 'exists'])
  assert.deepEqual(membershipCards.find(([label]) => label === 'Inherited analyst access')?.slice(0, 2), ['Inherited analyst access', 'unavailable'])

  const accessStep = await runCanonical('mechanics', 'Feel the dormant edge')
  const accessCards = accessStep.selected.cards(accessStep.output.inspection, accessStep.output)
  assert.deepEqual(accessCards.find(([label]) => label === 'Inherited reader access')?.slice(0, 2), ['Inherited reader access', 'none'])
})

test('reversed edge evidence describes Bob’s effective paths and verifies denial', async () => {
  const { selected, output } = await runCanonical('mechanics', 'Grant the edge backwards')
  const cards = selected.cards(output.inspection, output)
  assert.match(output.error, /permission denied for schema app/)
  assert.deepEqual(cards.find(([label]) => label === 'Bob inherits analyst')?.slice(0, 2), ['Bob inherits analyst', 'available'])
  assert.deepEqual(cards.find(([label]) => label === 'Bob inherits orders_reader')?.slice(0, 2), ['Bob inherits orders_reader', 'unavailable'])
})

test('alternate direct path does not make effective cards claim an analyst edge', async () => {
  const { output, cards } = await runMutation('mechanics', 'Nest the reporting membership', 'GRANT analyst TO bob;')
  assert.equal(output.inspection.via_analyst, true)
  assert.equal(output.inspection.via_reader, true)
  assert.deepEqual(cards.find(([label]) => label === 'Bob inherits analyst')?.slice(0, 2), ['Bob inherits analyst', 'available'])
  assert.deepEqual(cards.find(([label]) => label === 'Bob inherits orders_reader')?.slice(0, 2), ['Bob inherits orders_reader', 'available'])
})

test('ADMIN OPTION holder can activate its own INHERIT and SET options', async () => {
  const { selected, output } = await runCanonical('mechanics', 'Exercise the ADMIN caveat')
  assert.equal(output.results[0].rows.length, 2)
  assert.deepEqual(selected.cards(output.inspection, output).slice(0, 3).map(([label, value]) => [label, value]), [
    ['ADMIN OPTION', 'on'],
    ['INHERIT OPTION', 'on'],
    ['SET OPTION', 'on'],
  ])
})

test('configured defaults follow current_user at object creation', async () => {
  const { output } = await runCanonical('defaults', 'Make tomorrow automatic')
  assert.deepEqual(output.inspection, {
    deploy_created_owner: 'deploy',
    deploy_created_select: false,
    shipments_owner: 'app_owner',
    shipments_select: true,
  })
})
