import assert from 'node:assert/strict'
import test from 'node:test'
import { PGlite } from '@electric-sql/pglite'

import { acmeChapterSeeds } from '../src/components/AcmeStoryData.mjs'
import { getExplorerScenario } from '../src/lib/explorerScenarios.mjs'

test('Acme executor variants distinguish inherited authority from SET ROLE in PostgreSQL', async () => {
  const scenario = getExplorerScenario('acme-executor-authority')
  for (const variant of scenario.cases) {
    const database = await PGlite.create()
    try {
      await database.exec(acmeChapterSeeds.ownerSeed)
      const fact = variant.requestOverrides.executor.memberships.find(({ role }) => role === 'app_owner')
      assert(['allowed', 'denied'].includes(fact.inherit))
      assert(['allowed', 'denied'].includes(fact.set_role))
      await database.exec(`GRANT app_owner TO deploy WITH INHERIT ${fact.inherit === 'allowed'}, SET ${fact.set_role === 'allowed'}; SET SESSION AUTHORIZATION deploy;`)
      const operation = 'ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA app GRANT SELECT ON TABLES TO orders_reader;'
      if (fact.inherit === 'allowed') await database.exec(operation)
      else await assert.rejects(database.exec(operation), { code: '42501' })
    } finally {
      await database.close()
    }
  }
})

test('Acme membership removal loses default-owner authority before the later revoke', async () => {
  const scenario = getExplorerScenario('acme-default-privileges')
  assert.deepEqual(scenario.request.current.memberships, [
    { role: 'app_owner', member: 'deploy', inherit: true, admin: false, grantors: ['team_lead'] },
  ])
  const database = await PGlite.create()
  try {
    await database.exec(acmeChapterSeeds.ownerSeed)
    await database.exec(`
      REVOKE app_owner FROM deploy;
      CREATE ROLE team_lead LOGIN;
      GRANT app_owner TO team_lead WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
      GRANT team_lead TO deploy WITH INHERIT TRUE, SET FALSE;
      SET SESSION AUTHORIZATION team_lead;
      GRANT app_owner TO deploy WITH INHERIT TRUE;
      SET SESSION AUTHORIZATION postgres;
      SET SESSION AUTHORIZATION deploy;
      ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA app GRANT SELECT ON TABLES TO orders_reader;
    `)
    const before = await database.query("SELECT pg_has_role('deploy', 'app_owner', 'USAGE') AS owner_usage;")
    assert.equal(before.rows[0].owner_usage, true)
    await database.exec('REVOKE app_owner FROM deploy GRANTED BY team_lead;')
    const after = await database.query("SELECT pg_has_role('deploy', 'app_owner', 'USAGE') AS owner_usage;")
    assert.equal(after.rows[0].owner_usage, false)
    await assert.rejects(database.exec('ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA app REVOKE SELECT ON TABLES FROM orders_reader;'), { code: '42501' })
  } finally {
    await database.close()
  }
})
