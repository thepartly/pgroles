// Execute every canonical lab step against the same PGlite build the browser
// uses, replicating AcmeStoryLab's run loop exactly: seed, impersonate, run,
// inspect, evaluate the step's expectation, render its diagram cards. A PGlite
// upgrade, a changed PostgreSQL error string, or a wrong expectation fails
// here instead of locking a reader out of a chapter.
//
// Run with: npm run test:labs

import { PGlite } from "@electric-sql/pglite";
import {
  chapters,
  acmeChapterSeeds,
} from "../src/components/AcmeStoryData.mjs";
import { runLabStep } from "../src/components/labExecution.mjs";

let failures = 0;

function fail(message) {
  failures += 1;
  console.error(`FAIL  ${message}`);
}

function pass(message) {
  console.log(`PASS  ${message}`);
}

async function withDatabase(callback) {
  const database = await PGlite.create();
  try {
    return await callback(database);
  } finally {
    await database.close().catch(() => {});
  }
}

// --- 1. Every canonical step of every chapter -------------------------------

for (const [chapterKey, lesson] of Object.entries(chapters)) {
  for (const [stepIndex, step] of lesson.steps.entries()) {
    const label = `${chapterKey} step ${stepIndex + 1}: ${step.title}`;
    try {
      const output = await runLabStep({
        createDatabase: () => PGlite.create(),
        setup: step.setup,
        role: step.role,
        sql: step.sql,
        inspect: step.inspect,
        inspectAsActor: step.inspectAsActor,
      });
      if (!step.expect(output, output.inspection)) {
        fail(`${label}\n      error: ${JSON.stringify(output.error)}\n      inspection: ${JSON.stringify(output.inspection)}\n      actor: ${JSON.stringify(output.actorInspection)}\n      results: ${JSON.stringify(output.results)}`);
        continue;
      }
      if (output.identity.before.session_user !== step.role || output.identity.before.current_user !== step.role) {
        fail(`${label}: initial execution identity does not match the selected role`);
        continue;
      }
      const cards = step.cards(output.inspection, output);
      if (!Array.isArray(cards) || cards.length === 0) {
        fail(`${label}: cards did not render`);
        continue;
      }
      pass(label);
    } catch (error) {
      fail(`${label}: setup failed: ${error.message}`);
    }
  }
}

// --- 2. Narration-critical counterfactuals ----------------------------------
// These pin the facts the surrounding prose asserts, including behaviour a
// curious reader can reach by editing the canonical SQL.

// Chapter 4 says inheritance already lets deploy pass owner checks, and that
// SET ROLE matters because created objects belong to the creator.
await withDatabase(async (database) => {
  await database.exec(acmeChapterSeeds.ownerSeed);
  await database.exec(`SET SESSION AUTHORIZATION "deploy";`);
  try {
    await database.exec("ALTER TABLE app.orders ADD COLUMN source text;");
    pass("chapter 4 narration: deploy passes owner checks via inheritance");
  } catch (error) {
    fail(
      `chapter 4 narration: ALTER as deploy should succeed through inheritance, got: ${error.message}`
    );
  }
  await database.exec("CREATE TABLE app.narration_check (id int);");
  await database.exec("SET SESSION AUTHORIZATION postgres;");
  const owner = await database.query(
    `SELECT tableowner FROM pg_tables WHERE schemaname = 'app' AND tablename = 'narration_check';`
  );
  if (owner.rows[0]?.tableowner === "deploy") {
    pass("chapter 4 narration: objects created without SET ROLE belong to deploy");
  } else {
    fail(
      `chapter 4 narration: expected deploy to own its created table, got ${JSON.stringify(owner.rows)}`
    );
  }
});

// The playground claims Priya is retired and her legacy objects survived
// under app_owner, and that Alice's offboarding held.
await withDatabase(async (database) => {
  await database.exec(acmeChapterSeeds.completeSeed);
  const state = await database.query(
    `SELECT
      NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'priya') AS priya_gone,
      (SELECT tableowner FROM pg_tables
        WHERE schemaname = 'legacy' AND tablename = 'customer_notes') AS legacy_owner,
      has_schema_privilege('alice', 'app', 'USAGE') AS alice_schema,
      pg_has_role('dana', 'orders_reader', 'USAGE') AS dana_reads;`
  );
  const row = state.rows[0];
  if (row.priya_gone && row.legacy_owner === "app_owner") {
    pass("playground continuity: Priya retired, legacy objects owned by app_owner");
  } else {
    fail(`playground continuity: ${JSON.stringify(row)}`);
  }
  if (row.alice_schema === false) {
    pass("playground continuity: Alice's offboarding held");
  } else {
    fail("playground continuity: Alice still reaches the app schema");
  }
  if (row.dana_reads === true) {
    pass("playground continuity: Dana reads through the delegated hierarchy");
  } else {
    fail("playground continuity: Dana lost her delegated access");
  }
});

if (failures) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nAll lab steps and narration checks passed");
