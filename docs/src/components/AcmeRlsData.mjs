const actorInspection = `SELECT
  session_user,
  current_user,
  has_table_privilege('app.orders', 'SELECT') AS table_select,
  row_security_active('app.orders') AS row_security_active;`;

const tenantPredicate = `(current_user = 'acme_app' AND customer = 'Acme')
    OR (current_user = 'globex_app' AND customer = 'Globex')`;

export function createRlsChapter(baseSeed) {
  const rolesSeed = `${baseSeed}
CREATE ROLE acme_app LOGIN;
CREATE ROLE globex_app LOGIN;
GRANT USAGE ON SCHEMA app TO acme_app, globex_app;
GRANT SELECT, INSERT, UPDATE ON app.orders TO acme_app, globex_app;
ALTER TABLE app.orders ENABLE ROW LEVEL SECURITY;`;

  const policySeed = `${rolesSeed}
CREATE POLICY tenant_rows ON app.orders
  FOR ALL TO acme_app, globex_app
  USING (${tenantPredicate})
  WITH CHECK (${tenantPredicate});`;

  const forcedSeed = `${policySeed}
ALTER TABLE app.orders FORCE ROW LEVEL SECURITY;
CREATE ROLE rls_bypass LOGIN BYPASSRLS;
GRANT USAGE ON SCHEMA app TO rls_bypass;
GRANT SELECT ON app.orders TO rls_bypass;`;

  const identityResult = (output) => output.results[0]?.rows[0];
  const tenantCards = (tenant) => (row, output) => {
    const result = output.results[1]?.rows ?? [];
    return [
      ["Table SELECT", row?.reader_acl ? "granted" : "missing", row?.reader_acl ? "pass" : "blocked"],
      ["RLS", row?.rls_enabled ? "enabled" : "disabled", row?.rls_enabled ? "focus" : "blocked"],
      ["Visible customer", result[0]?.customer ?? "none", result.length === 1 && result[0]?.customer === tenant ? "pass" : "blocked"],
    ];
  };

  return {
    debrief: {
      href: "#policy-is-another-permission-gate",
      title: "Treat policy as another gate",
    },
    eyebrow: "Chapter 8 · Row-level security",
    title: "Acme and Globex share a table, not each other’s rows",
    description:
      "Table grants open the operation; row-level security decides which existing and proposed rows that operation may touch.",
    next: {
      href: "/docs/postgresql-security-review",
      title: "Audit PUBLIC, definer functions, delegation, and broad roles",
    },
    actors: [
      ["acme_app", "Acme application"],
      ["globex_app", "Globex application"],
      ["app_owner", "Application owner"],
      ["rls_bypass", "BYPASSRLS service"],
      ["postgres", "Database superuser"],
    ],
    steps: [
      {
        id: "default-deny",
        title: "Enable RLS without a policy",
        why: "A table grant and an applicable row policy are separate gates. Once RLS is enabled, an ordinary role with SELECT but no policy gets the default-deny result: no visible rows.",
        prompt: "Prove acme_app has SELECT, then query orders before any policy exists.",
        setup: rolesSeed,
        role: "acme_app",
        sql: `${actorInspection}
SELECT id, customer FROM app.orders ORDER BY id;`,
        inspectAsActor: actorInspection,
        inspect: `SELECT
  relrowsecurity AS rls_enabled,
  has_table_privilege('acme_app', 'app.orders', 'SELECT') AS reader_acl,
  (SELECT count(*)::int FROM pg_policy WHERE polrelid = 'app.orders'::regclass) AS policy_count
FROM pg_class
WHERE oid = 'app.orders'::regclass
GROUP BY relrowsecurity;`,
        cards: (row, output) => [
          ["Table SELECT", row?.reader_acl ? "granted" : "missing", row?.reader_acl ? "pass" : "blocked"],
          ["RLS", row?.rls_enabled ? "enabled" : "disabled", row?.rls_enabled ? "focus" : "blocked"],
          ["Applicable policies", String(row?.policy_count ?? "?"), row?.policy_count === 0 ? "focus" : "blocked"],
          ["Visible rows", String(output.results[1]?.rows.length ?? "?"), output.results[1]?.rows.length === 0 ? "pass" : "blocked"],
        ],
        expect: (output, row) =>
          !output.error &&
          identityResult(output)?.session_user === "acme_app" &&
          identityResult(output)?.current_user === "acme_app" &&
          identityResult(output)?.table_select === true &&
          identityResult(output)?.row_security_active === true &&
          output.results[1]?.rows.length === 0 &&
          row?.rls_enabled === true &&
          row?.reader_acl === true &&
          row?.policy_count === 0,
        observation:
          "SELECT passed the table ACL, but RLS supplied an implicit false condition because no policy applied. Success with zero rows is the default-deny signal here.",
      },
      {
        id: "tenant-policy-acme",
        title: "Query as Acme",
        why: "The policy compares the active database identity with each row’s customer. acme_app should see Acme and nothing from Globex.",
        prompt: "Read orders as acme_app with the tenant policy installed.",
        setup: policySeed,
        role: "acme_app",
        sql: `${actorInspection}
SELECT id, customer FROM app.orders ORDER BY id;`,
        inspectAsActor: actorInspection,
        inspect: `SELECT
  (SELECT relrowsecurity FROM pg_class WHERE oid = 'app.orders'::regclass) AS rls_enabled,
  has_table_privilege('acme_app', 'app.orders', 'SELECT') AS reader_acl;`,
        cards: tenantCards("Acme"),
        expect: (output) =>
          !output.error &&
          identityResult(output)?.current_user === "acme_app" &&
          identityResult(output)?.row_security_active === true &&
          output.results[1]?.rows.length === 1 &&
          output.results[1]?.rows[0]?.customer === "Acme",
        observation:
          "Acme’s query did not need a tenant WHERE clause. PostgreSQL added the policy predicate and returned only Acme’s row.",
      },
      {
        id: "tenant-policy-globex",
        title: "Query as Globex",
        why: "The same SQL and table grant produce a different row set under a different active identity.",
        prompt: "Run the unchanged query as globex_app.",
        setup: policySeed,
        role: "globex_app",
        sql: `${actorInspection}
SELECT id, customer FROM app.orders ORDER BY id;`,
        inspectAsActor: actorInspection,
        inspect: `SELECT
  (SELECT relrowsecurity FROM pg_class WHERE oid = 'app.orders'::regclass) AS rls_enabled,
  has_table_privilege('globex_app', 'app.orders', 'SELECT') AS reader_acl;`,
        cards: tenantCards("Globex"),
        expect: (output) =>
          !output.error &&
          identityResult(output)?.current_user === "globex_app" &&
          identityResult(output)?.row_security_active === true &&
          output.results[1]?.rows.length === 1 &&
          output.results[1]?.rows[0]?.customer === "Globex",
        observation:
          "Globex sees its own row through the same policy. RLS follows the active database role, so a shared login plus an application tenant setting would not establish this boundary.",
      },
      {
        id: "forbidden-insert",
        title: "Separate existing rows from proposed values",
        why: "USING limits rows an operation may find. WITH CHECK validates the row an INSERT or UPDATE proposes. First write a valid Acme row, then try to label a new row as Globex.",
        prompt: "Confirm the same-tenant insert, then watch the cross-tenant insert fail.",
        setup: policySeed,
        role: "acme_app",
        sql: `${actorInspection}
INSERT INTO app.orders (id, customer, total_cents)
VALUES (10, 'Acme', 2500)
RETURNING id, customer;
INSERT INTO app.orders (id, customer, total_cents)
VALUES (11, 'Globex', 2500);`,
        inspectAsActor: actorInspection,
        inspect: `SELECT
  count(*) FILTER (WHERE id = 10 AND customer = 'Acme')::int AS accepted_rows,
  count(*) FILTER (WHERE id = 11)::int AS rejected_rows
FROM app.orders;`,
        cards: (row, output) => [
          ["USING", "existing rows", "neutral"],
          ["WITH CHECK", "proposed values", "focus"],
          ["Acme insert", row?.accepted_rows === 1 ? "accepted" : "missing", row?.accepted_rows === 1 ? "pass" : "blocked"],
          ["Globex insert", output.errorCode === "42501" && row?.rejected_rows === 0 ? "rejected" : "unexpected", output.errorCode === "42501" && row?.rejected_rows === 0 ? "pass" : "blocked"],
        ],
        expect: (output, row) =>
          identityResult(output)?.current_user === "acme_app" &&
          output.results[1]?.rows[0]?.customer === "Acme" &&
          output.errorCode === "42501" &&
          row?.accepted_rows === 1 &&
          row?.rejected_rows === 0,
        observation:
          "This lab executes each statement separately, without an explicit transaction. The Acme insert therefore commits before the Globex insert fails. In a single transaction without error recovery, the failure would abort that transaction. WITH CHECK returned SQLSTATE 42501, so the cross-tenant row never appeared.",
      },
      {
        id: "force-owner",
        title: "Force the owner through RLS",
        why: "Table owners normally bypass row security. FORCE ROW LEVEL SECURITY removes that owner exemption, so app_owner changes from seeing both customers to seeing no rows when no policy applies to it.",
        prompt: "Measure the owner’s view before and after FORCE.",
        setup: policySeed,
        role: "app_owner",
        sql: `${actorInspection}
SELECT count(*)::int AS rows_before_force FROM app.orders;
ALTER TABLE app.orders FORCE ROW LEVEL SECURITY;
${actorInspection}
SELECT count(*)::int AS rows_after_force FROM app.orders;`,
        inspectAsActor: actorInspection,
        inspect: `SELECT relrowsecurity AS rls_enabled, relforcerowsecurity AS rls_forced
FROM pg_class WHERE oid = 'app.orders'::regclass;`,
        cards: (row, output) => [
          ["Owner before FORCE", `${output.results[1]?.rows[0]?.rows_before_force ?? "?"} rows`, output.results[1]?.rows[0]?.rows_before_force === 2 ? "focus" : "blocked"],
          ["FORCE", row?.rls_forced ? "enabled" : "disabled", row?.rls_forced ? "pass" : "blocked"],
          ["Owner after FORCE", `${output.results[3]?.rows[0]?.rows_after_force ?? "?"} rows`, output.results[3]?.rows[0]?.rows_after_force === 0 ? "pass" : "blocked"],
        ],
        expect: (output, row) =>
          !output.error &&
          identityResult(output)?.current_user === "app_owner" &&
          identityResult(output)?.row_security_active === false &&
          output.results[1]?.rows[0]?.rows_before_force === 2 &&
          output.results[2]?.rows[0]?.row_security_active === true &&
          output.results[3]?.rows[0]?.rows_after_force === 0 &&
          row?.rls_forced === true,
        observation:
          "FORCE subjects the owner to policy evaluation. With no app_owner policy, the same default-deny rule now returns zero rows.",
      },
      {
        id: "rls-bypasses",
        title: "Prove the remaining bypasses",
        why: "FORCE changes the table owner’s behavior. It does not constrain a superuser or a role carrying PostgreSQL’s BYPASSRLS attribute.",
        prompt: "Compare the superuser with the dedicated BYPASSRLS role.",
        setup: forcedSeed,
        role: "postgres",
        sql: `${actorInspection}
SELECT customer FROM app.orders ORDER BY customer;
SET SESSION AUTHORIZATION rls_bypass;
${actorInspection}
SELECT customer FROM app.orders ORDER BY customer;`,
        inspectAsActor: actorInspection,
        inspect: `SELECT
  (SELECT relforcerowsecurity FROM pg_class WHERE oid = 'app.orders'::regclass) AS rls_forced,
  (SELECT rolbypassrls FROM pg_roles WHERE rolname = 'rls_bypass') AS has_bypass;`,
        cards: (row, output) => [
          ["FORCE", row?.rls_forced ? "enabled" : "disabled", row?.rls_forced ? "pass" : "blocked"],
          ["Superuser", `${output.results[1]?.rows.length ?? "?"} rows`, output.results[1]?.rows.length === 2 ? "focus" : "blocked"],
          ["BYPASSRLS", `${output.results[3]?.rows.length ?? "?"} rows`, output.results[3]?.rows.length === 2 && row?.has_bypass ? "focus" : "blocked"],
        ],
        expect: (output, row) =>
          !output.error &&
          identityResult(output)?.current_user === "postgres" &&
          identityResult(output)?.row_security_active === false &&
          output.results[1]?.rows.map(({ customer }) => customer).join(",") === "Acme,Globex" &&
          output.results[2]?.rows[0]?.current_user === "rls_bypass" &&
          output.results[2]?.rows[0]?.row_security_active === false &&
          output.results[3]?.rows.map(({ customer }) => customer).join(",") === "Acme,Globex" &&
          row?.rls_forced === true &&
          row?.has_bypass === true,
        observation:
          "Both identities still see every row. FORCE is an owner control; superuser and BYPASSRLS remain explicit escape hatches that need separate governance.",
      },
    ],
  };
}
