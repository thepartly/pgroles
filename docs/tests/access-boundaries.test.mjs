import assert from 'node:assert/strict'
import test from 'node:test'
import { PGlite } from '@electric-sql/pglite'
import { acmeChapterSeeds, chapters } from '../src/components/AcmeStoryData.mjs'
import { runLabStep } from '../src/components/labExecution.mjs'

async function withAcme(callback) {
  const database = await PGlite.create()
  try {
    await database.exec(acmeChapterSeeds.ownerSeed)
    await callback(database)
  } finally {
    await database.close()
  }
}

test('ownership retains grant authority but does not bypass a revoked SELECT privilege', async () => {
  await withAcme(async (database) => {
    await database.exec('SET SESSION AUTHORIZATION app_owner; REVOKE SELECT ON app.orders FROM app_owner;')
    await assert.rejects(database.query('SELECT * FROM app.orders;'), { code: '42501' })
    await database.exec('GRANT SELECT ON app.orders TO app_owner;')
    assert.deepEqual((await database.query('SELECT customer FROM app.orders ORDER BY customer;')).rows,
      [{ customer: 'Acme' }, { customer: 'Globex' }])
  })
})

test('monitoring capability does not grant business-table SELECT', async () => {
  await withAcme(async (database) => {
    await database.exec('CREATE ROLE monitoring_agent LOGIN; GRANT pg_monitor TO monitoring_agent; GRANT USAGE ON SCHEMA app TO monitoring_agent; SET SESSION AUTHORIZATION monitoring_agent;')
    const result = await database.query("SELECT pg_has_role(current_user, 'pg_monitor', 'USAGE') AS monitoring, has_table_privilege(current_user, 'app.orders', 'SELECT') AS table_select;")
    assert.deepEqual(result.rows, [{ monitoring: true, table_select: false }])
    await database.query('SELECT datname FROM pg_stat_database;')
    await assert.rejects(database.query('SELECT * FROM app.orders;'), { code: '42501' })
  })
})

test('pg_database_owner has implicit database-local membership and cannot be granted', async () => {
  await withAcme(async (database) => {
    const { rows } = await database.query('SELECT current_database() AS name;')
    const name = rows[0].name.replaceAll('"', '""')
    await database.exec(`ALTER DATABASE "${name}" OWNER TO app_owner;`)
    const result = await database.query("SELECT pg_has_role('app_owner', 'pg_database_owner', 'MEMBER') AS owner_member, pg_has_role('alice', 'pg_database_owner', 'MEMBER') AS other_member;")
    assert.deepEqual(result.rows, [{ owner_member: true, other_member: false }])
    await assert.rejects(database.exec('GRANT pg_database_owner TO alice;'), /cannot have explicit members/)
  })
})

async function withRls(stepId, callback) {
  const database = await PGlite.create()
  try {
    const step = chapters.rls.steps.find(({ id }) => id === stepId)
    assert(step, `missing RLS step ${stepId}`)
    await database.exec(step.setup)
    await callback(database)
  } finally {
    await database.close()
  }
}

test('predefined data reader and writer capabilities do not bypass row policies', async () => {
  await withRls('tenant-policy-acme', async (database) => {
    await database.exec(`
      REVOKE SELECT, UPDATE ON app.orders FROM acme_app;
      GRANT pg_read_all_data, pg_write_all_data TO acme_app;
      SET SESSION AUTHORIZATION acme_app;
    `)
    const access = await database.query("SELECT has_table_privilege('app.orders', 'SELECT') AS table_select, row_security_active('app.orders') AS rls;")
    assert.deepEqual(access.rows, [{ table_select: true, rls: true }])
    assert.deepEqual((await database.query('SELECT customer FROM app.orders ORDER BY customer;')).rows, [{ customer: 'Acme' }])
    assert.deepEqual((await database.query("UPDATE app.orders SET total_cents = 1 WHERE customer = 'Globex' RETURNING customer;")).rows, [])
    await assert.rejects(database.exec("UPDATE app.orders SET customer = 'Globex' WHERE customer = 'Acme';"), { code: '42501' })
  })
})

test('permissive policies broaden through OR and restrictive policies constrain through AND', async () => {
  await withRls('tenant-policy-acme', async (database) => {
    await database.exec(`
      CREATE POLICY extra_customer ON app.orders FOR SELECT TO acme_app USING (customer = 'Globex');
      SET SESSION AUTHORIZATION acme_app;
    `)
    assert.deepEqual((await database.query('SELECT customer FROM app.orders ORDER BY customer;')).rows,
      [{ customer: 'Acme' }, { customer: 'Globex' }])
    await database.exec(`
      SET SESSION AUTHORIZATION postgres;
      CREATE POLICY acme_boundary ON app.orders AS RESTRICTIVE FOR SELECT TO acme_app USING (customer = 'Acme');
      SET SESSION AUTHORIZATION acme_app;
    `)
    assert.deepEqual((await database.query('SELECT customer FROM app.orders ORDER BY customer;')).rows, [{ customer: 'Acme' }])
  })
})

test('a restrictive policy alone cannot grant row access', async () => {
  await withRls('default-deny', async (database) => {
    await database.exec(`
      CREATE POLICY restriction_only ON app.orders AS RESTRICTIVE TO acme_app USING (customer = 'Acme');
      SET SESSION AUTHORIZATION acme_app;
    `)
    assert.deepEqual((await database.query('SELECT customer FROM app.orders;')).rows, [])
  })
})

test('lab identity is captured before administrative inspection and preserves SET ROLE', async () => {
  const output = await runLabStep({
    createDatabase: () => PGlite.create(),
    setup: acmeChapterSeeds.ownerSeed,
    role: 'deploy',
    sql: 'SET ROLE app_owner; SELECT session_user, current_user;',
    inspect: 'SELECT session_user, current_user;',
  })
  assert.deepEqual(output.identity.before, { session_user: 'deploy', current_user: 'deploy' })
  assert.deepEqual(output.identity.after, { session_user: 'deploy', current_user: 'app_owner' })
  assert.deepEqual(output.inspection, { session_user: 'postgres', current_user: 'postgres' })
})

test('SECURITY DEFINER changes identity inside the function and restores its caller', async () => {
  const output = await runLabStep({
    createDatabase: () => PGlite.create(),
    setup: `${acmeChapterSeeds.ownerSeed}
      CREATE ROLE identity_auditor LOGIN;
      GRANT USAGE ON SCHEMA app TO identity_auditor;
      SET ROLE app_owner;
      CREATE FUNCTION app.execution_identity() RETURNS TABLE(connection_role name, permission_role name)
        LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog
        AS 'SELECT session_user, current_user';
      RESET ROLE;`,
    role: 'identity_auditor',
    sql: 'SELECT * FROM app.execution_identity();',
  })
  assert.equal(output.error, null)
  assert.deepEqual(output.results[0].rows, [{ connection_role: 'identity_auditor', permission_role: 'app_owner' }])
  assert.deepEqual(output.identity.before, { session_user: 'identity_auditor', current_user: 'identity_auditor' })
  assert.deepEqual(output.identity.after, output.identity.before)
})
