import { runSql } from "./sqlStatements.mjs";

function quoteIdentifier(value) {
  return `"${value.replaceAll('"', '""')}"`;
}

async function readIdentity(database) {
  const result = await database.query("SELECT session_user, current_user;");
  return result.rows[0] ?? {};
}

export async function runLabStep({
  createDatabase,
  setup,
  role,
  sql,
  inspect,
  inspectAsActor,
}) {
  let database;
  try {
    database = await createDatabase();
    await database.exec(setup);
    await database.exec(`SET SESSION AUTHORIZATION ${quoteIdentifier(role)};`);

    const identityBefore = await readIdentity(database);
    const output = {
      passed: false,
      inspection: null,
      actorInspection: {},
      identity: { before: identityBefore, after: null },
      ...(await runSql(database, sql)),
    };

    try {
      output.identity.after = await readIdentity(database);
      if (inspectAsActor) {
        const actorInspection = await database.query(inspectAsActor);
        output.actorInspection = actorInspection.rows[0] ?? {};
      }
    } catch (error) {
      output.actorInspectionError = error.message;
    }

    try {
      await database.exec("SET SESSION AUTHORIZATION postgres;");
      if (inspect) {
        const inspection = await database.query(inspect);
        output.inspection = inspection.rows[0] ?? {};
      }
    } catch (error) {
      output.inspectionError = error.message;
    }

    return output;
  } finally {
    if (database) await database.close().catch(() => {});
  }
}
