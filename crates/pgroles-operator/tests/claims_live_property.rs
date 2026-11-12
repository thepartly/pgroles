//! Live property test for cross-policy conflict detection.
//!
//! `OwnershipClaims::conflicts` decides whether two policies may reconcile the
//! same database side by side. Its contract: if it reports no conflict, then
//! neither policy's plan ever undoes something the other asserts — a grant the
//! other declares present, an absence it declares, a membership edge or its
//! options, a schema owner, or a role the other references (by dropping or
//! retiring it). Each rule in `conflicts` was derived by reading how
//! inspection scopes a policy and what each reconciliation mode keeps; this
//! test checks the derivation against the real thing.
//!
//! For each seed it generates two random policies over a small shared universe
//! of roles, schemas, tables and a function, and skips the pair if
//! `conflicts` reports anything. Otherwise it runs both policies through the
//! same pipeline the CLI and operator use — scoped inspection, `plan_changes`,
//! membership-option resolution, version- and inventory-aware rendering — and
//! executes their plans alternately against PostgreSQL. It asserts:
//!
//! 1. **No undo.** No executed plan contains a change that removes, reverses
//!    or drops something the other policy asserts.
//! 2. **Fixed point.** After a few alternations, neither policy plans
//!    anything.
//!
//! The database is the oracle for scoping and for what statements do, so a
//! wrong belief about inspection shared by `conflicts` and this file cannot
//! hide a violation of (2). The undo predicate in (1) is written from the
//! change list, independently of `OwnershipClaims`.
//!
//! Seeds are fixed (0..N, default 40) so CI is reproducible; override with
//! `PGROLES_CLAIMS_PROPERTY_SEEDS`. Every failure prints the seed and both
//! policies. Requires `DATABASE_URL` and a superuser connection; run with
//! `cargo test -p pgroles-operator --test claims_live_property -- --include-ignored`.

use std::collections::BTreeSet;

use pgroles_core::diff::{Change, ReconciliationMode, plan_changes};
use pgroles_core::manifest::expand_manifest;
use pgroles_core::model::RoleGraph;
use pgroles_core::sql::{SqlContext, render_all_with_context};
use pgroles_inspect::{InspectConfig, inspect};
use pgroles_operator::crd::{OwnershipClaims, PostgresPolicySpec};
use serde_json::{Value, json};
use sqlx::PgPool;

const ROUNDS: usize = 3;

fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live DB tests")
}

fn seed_count() -> u64 {
    std::env::var("PGROLES_CLAIMS_PROPERTY_SEEDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(40)
}

/// xorshift64*, as in the core property tests: reproducible, no dependency.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

/// Names for one seed. Everything is prefixed so seeds cannot see each other.
struct Universe {
    prefix: String,
    roles: Vec<String>,
    owner: String,
    schemas: Vec<String>,
    database: String,
}

impl Universe {
    fn new(seed: u64, database: String) -> Self {
        let prefix = format!("clp{seed}_");
        Self {
            roles: (0..4).map(|i| format!("{prefix}r{i}")).collect(),
            owner: format!("{prefix}owner"),
            schemas: (0..2).map(|i| format!("{prefix}s{i}")).collect(),
            prefix,
            database,
        }
    }

    fn setup_sql(&self) -> Vec<String> {
        let mut sql = vec![format!("CREATE ROLE \"{}\" NOLOGIN", self.owner)];
        for role in &self.roles {
            sql.push(format!("CREATE ROLE \"{role}\" NOLOGIN"));
        }
        for schema in &self.schemas {
            sql.push(format!(
                "CREATE SCHEMA \"{schema}\" AUTHORIZATION \"{}\"",
                self.owner
            ));
            sql.push(format!(
                "CREATE TABLE \"{schema}\".t (id integer); ALTER TABLE \"{schema}\".t OWNER TO \"{}\"",
                self.owner
            ));
        }
        sql.push(format!(
            "CREATE FUNCTION \"{}\".f(integer) RETURNS integer LANGUAGE sql AS 'SELECT 1'; \
             ALTER FUNCTION \"{}\".f(integer) OWNER TO \"{}\"",
            self.schemas[0], self.schemas[0], self.owner
        ));
        sql
    }

    fn cleanup_sql(&self) -> Vec<String> {
        let mut sql: Vec<String> = self
            .schemas
            .iter()
            .map(|schema| format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
            .collect();
        for role in self.roles.iter().chain(std::iter::once(&self.owner)) {
            sql.push(format!(
                "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN \
                 EXECUTE 'DROP OWNED BY \"{role}\"'; EXECUTE 'DROP ROLE \"{role}\"'; END IF; END $$"
            ));
        }
        sql
    }
}

/// A random policy over the universe, as `PostgresPolicySpec` JSON.
fn gen_policy(rng: &mut Rng, u: &Universe) -> Value {
    // Additive is weighted up: most pairs with an adopt or authoritative
    // policy conflict by design, and only accepted pairs exercise the property.
    let mode = *rng.pick(&["additive", "additive", "additive", "adopt", "authoritative"]);
    let mut roles = Vec::new();
    let mut external_roles = BTreeSet::new();
    for role in &u.roles {
        if rng.chance(35) {
            let external = rng.chance(50);
            if external {
                external_roles.insert(role.clone());
                roles.push(json!({"name": role, "external": true}));
            } else {
                roles.push(json!({"name": role, "login": rng.chance(50)}));
            }
        }
    }
    let mut declared: BTreeSet<String> = roles
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_string())
        .collect();

    let mut grants = Vec::new();
    for _ in 0..rng.below(5) {
        let role = rng.pick(&u.roles).clone();
        let schema = rng.pick(&u.schemas).clone();
        let ensure = if rng.chance(25) { "absent" } else { "present" };
        let grant = match rng.below(6) {
            0 => json!({"role": role, "privileges": ["USAGE"], "ensure": ensure,
                        "object": {"type": "schema", "name": schema}}),
            1 => json!({"role": role, "privileges": ["SELECT"], "ensure": ensure,
                        "object": {"type": "table", "schema": schema, "name": "*"}}),
            2 | 5 => json!({"role": role, "privileges": ["EXECUTE"], "ensure": ensure,
                        "object": {"type": "function", "schema": u.schemas[0],
                                   "name": *rng.pick(&["f", "f(integer)"])}}),
            3 => json!({"role": role, "privileges": ["CONNECT"], "ensure": ensure,
                        "object": {"type": "database", "name": u.database}}),
            _ => json!({"role": role, "ensure": ensure,
                        "privileges": [*rng.pick(&["SELECT", "INSERT"])],
                        "object": {"type": "table", "schema": schema, "name": "t"}}),
        };
        grants.push(grant);
    }

    // Declaring a schema claims its owner facet; owners are drawn so two
    // policies can disagree about the same schema.
    let mut schemas = Vec::new();
    for schema in &u.schemas {
        if rng.chance(20) {
            let owner = if rng.chance(50) {
                &u.owner
            } else {
                rng.pick(&u.roles)
            };
            schemas.push(json!({"name": schema, "owner": owner}));
        }
    }

    let mut default_privileges = Vec::new();
    if rng.chance(30) {
        default_privileges.push(json!({
            "owner": u.owner,
            "schema": rng.pick(&u.schemas),
            "grant": [{
                "role": rng.pick(&u.roles),
                "privileges": ["SELECT"],
                "on_type": "table",
                "ensure": if rng.chance(25) { "absent" } else { "present" },
            }],
        }));
    }

    // Edges point from a lower to a higher role name, so the union of both
    // policies' edges can never form a cycle PostgreSQL rejects. One policy
    // declares each edge at most once: a manifest that declares one edge twice
    // with different options oscillates on its own (single-manifest validation
    // does not reject it), which is not what this test is about.
    let mut memberships = Vec::new();
    let mut edges = BTreeSet::new();
    for _ in 0..rng.below(3) {
        let a = rng.below(u.roles.len() as u64) as usize;
        let b = rng.below(u.roles.len() as u64) as usize;
        if a == b || !edges.insert((a.min(b), a.max(b))) {
            continue;
        }
        let (role, member) = (&u.roles[a.min(b)], &u.roles[a.max(b)]);
        let exclusive = external_roles.contains(role) && rng.chance(40);
        memberships.push(json!({
            "role": role,
            "exclusive": exclusive,
            "members": [{"name": member, "inherit": rng.chance(70)}],
        }));
    }

    // pgroles inspects only declared roles, so a grantee or member a policy
    // does not declare never converges. Declare every referenced role, as
    // external unless the policy creates it — the documented usage.
    let referenced: BTreeSet<String> = grants
        .iter()
        .map(|g| g["role"].as_str().unwrap().to_string())
        .chain(
            default_privileges
                .iter()
                .map(|dp| dp["grant"][0]["role"].as_str().unwrap().to_string()),
        )
        .chain(
            schemas
                .iter()
                .map(|s| s["owner"].as_str().unwrap().to_string())
                .filter(|owner| *owner != u.owner),
        )
        .chain(memberships.iter().flat_map(|m| {
            [
                m["role"].as_str().unwrap().to_string(),
                m["members"][0]["name"].as_str().unwrap().to_string(),
            ]
        }))
        .collect();
    for role in referenced {
        if declared.insert(role.clone()) {
            roles.push(json!({"name": role, "external": true}));
        }
    }

    let mut retirements = Vec::new();
    if rng.chance(25) {
        let role = rng.pick(&u.roles);
        if !declared.contains(role) {
            retirements.push(json!({"role": role, "drop_owned": true}));
        }
    }

    json!({
        "connection": {"secretRef": {"name": "db"}},
        "reconciliation_mode": mode,
        "roles": roles,
        "schemas": schemas,
        "grants": grants,
        "default_privileges": default_privileges,
        "memberships": memberships,
        "retirements": retirements,
    })
}

struct Policy {
    spec: PostgresPolicySpec,
    claims: OwnershipClaims,
    desired: RoleGraph,
}

fn prepare(value: &Value) -> Option<Policy> {
    let spec: PostgresPolicySpec = serde_json::from_value(value.clone()).ok()?;
    let claims = spec.ownership_claims().ok()?;
    let manifest = spec.to_policy_manifest();
    let expanded = expand_manifest(&manifest).ok()?;
    let desired = RoleGraph::from_expanded(&expanded, manifest.default_owner.as_deref()).ok()?;
    Some(Policy {
        spec,
        claims,
        desired,
    })
}

/// Plan one policy against the live database exactly as an apply would.
async fn plan(pool: &PgPool, policy: &Policy) -> Result<(Vec<Change>, String), String> {
    let manifest = policy.spec.to_policy_manifest();
    let expanded = expand_manifest(&manifest).map_err(|e| e.to_string())?;
    let has_database_grants = expanded
        .grants
        .iter()
        .any(|g| g.object.object_type == pgroles_core::manifest::ObjectType::Database);
    let config = InspectConfig::from_expanded(&expanded, has_database_grants)
        .with_additional_roles(manifest.retirements.iter().map(|r| r.role.clone()));
    let current = inspect(pool, &config).await.map_err(|e| e.to_string())?;
    let mode: ReconciliationMode = policy.spec.reconciliation_mode.into();
    let changes = plan_changes(&current, &policy.desired, &manifest, &expanded, mode);
    let changes = pgroles_inspect::resolve_membership_options(pool, changes, &current)
        .await
        .map_err(|e| e.to_string())?;

    let schemas: Vec<&str> = config
        .privilege_schemas
        .iter()
        .map(String::as_str)
        .collect();
    let version = pgroles_inspect::detect_pg_version(pool)
        .await
        .map_err(|e| e.to_string())?;
    let context = SqlContext::from_version_num(version.version_num)
        .with_object_inventory(
            pgroles_inspect::fetch_relation_inventory(pool, &schemas)
                .await
                .map_err(|e| e.to_string())?,
        )
        .with_owned_relations(
            pgroles_inspect::fetch_owned_relations(pool, &schemas)
                .await
                .map_err(|e| e.to_string())?,
        );
    let sql = render_all_with_context(&changes, &context).map_err(|e| e.to_string())?;
    Ok((changes, sql))
}

async fn execute(pool: &PgPool, sql: &str) -> Result<(), String> {
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    sqlx::raw_sql(sql)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())
}

fn same_routine(a: &str, b: &str) -> bool {
    a.split('(').next() == b.split('(').next()
}

fn names_overlap(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a == b || a == "*" || b == "*" || same_routine(a, b),
        (None, None) => true,
        _ => false,
    }
}

/// Every role `other` names in any way.
fn mentioned_roles(other: &RoleGraph, spec: &PostgresPolicySpec) -> BTreeSet<String> {
    let mut roles: BTreeSet<String> = other.roles.keys().cloned().collect();
    roles.extend(spec.roles.iter().map(|r| r.name.clone()));
    roles.extend(spec.retirements.iter().map(|r| r.role.clone()));
    for key in other.grants.keys().chain(other.grant_absences.keys()) {
        roles.insert(key.role.as_str().to_string());
    }
    for key in other
        .default_privileges
        .keys()
        .chain(other.default_privilege_absences.keys())
    {
        roles.insert(key.owner.clone());
        roles.insert(key.grantee.as_str().to_string());
    }
    for edge in &other.memberships {
        roles.insert(edge.role.clone());
        roles.insert(edge.member.clone());
    }
    roles.extend(other.schemas.values().filter_map(|s| s.owner.clone()));
    roles
}

/// The first change in `changes` that undoes something `other` asserts.
fn first_undo(changes: &[Change], other: &Policy) -> Option<String> {
    let graph = &other.desired;
    let mentioned = mentioned_roles(graph, &other.spec);
    for change in changes {
        let undo = match change {
            Change::Revoke {
                role,
                privileges,
                object_type,
                schema,
                name,
                ..
            } => graph.grants.iter().any(|(key, state)| {
                key.role.as_str() == role.as_str()
                    && key.object_type == *object_type
                    && key.schema == *schema
                    && names_overlap(key.name.as_deref(), name.as_deref())
                    && !state.privileges.is_disjoint(privileges)
            }),
            Change::Grant {
                role,
                privileges,
                object_type,
                schema,
                name,
            } => graph.grant_absences.iter().any(|(key, absent)| {
                key.role.as_str() == role.as_str()
                    && key.object_type == *object_type
                    && key.schema == *schema
                    && names_overlap(key.name.as_deref(), name.as_deref())
                    && !absent.is_disjoint(privileges)
            }),
            Change::RevokeDefaultPrivilege {
                owner,
                scope,
                on_type,
                grantee,
                privileges,
            } => graph.default_privileges.iter().any(|(key, state)| {
                key.owner == *owner
                    && key.scope == *scope
                    && key.on_type == *on_type
                    && key.grantee == *grantee
                    && !state.privileges.is_disjoint(privileges)
            }),
            Change::SetDefaultPrivilege {
                owner,
                scope,
                on_type,
                grantee,
                privileges,
            } => graph
                .default_privilege_absences
                .iter()
                .any(|(key, absent)| {
                    key.owner == *owner
                        && key.scope == *scope
                        && key.on_type == *on_type
                        && key.grantee == *grantee
                        && !absent.is_disjoint(privileges)
                }),
            Change::RemoveMember { role, member, .. } => graph
                .memberships
                .iter()
                .any(|edge| edge.role == *role && edge.member == *member),
            Change::UpdateMemberOptions {
                role,
                member,
                inherit,
                admin,
                ..
            } => graph.memberships.iter().any(|edge| {
                edge.role == *role
                    && edge.member == *member
                    && (inherit.is_some_and(|v| v != edge.inherit)
                        || admin.is_some_and(|v| v != edge.admin))
            }),
            Change::AlterSchemaOwner { name, owner } => graph
                .schemas
                .get(name)
                .and_then(|schema| schema.owner.as_ref())
                .is_some_and(|theirs| theirs != owner),
            Change::AlterRole { name, .. } => other
                .spec
                .roles
                .iter()
                .any(|role| role.name == *name && !role.external),
            Change::DropRole { name } => mentioned.contains(name),
            Change::DropOwned { role } | Change::TerminateSessions { role } => {
                mentioned.contains(role)
            }
            Change::ReassignOwned { from_role, .. } => mentioned.contains(from_role),
            _ => false,
        };
        if undo {
            return Some(format!("{change:?}"));
        }
    }
    None
}

/// Whether one policy reaches a fixed point on its own. A policy that cannot is
/// a single-policy finding, not evidence about conflict detection.
async fn converges_alone(pool: &PgPool, policy: &Policy) -> Result<(), String> {
    for round in 0..ROUNDS {
        let (_, sql) = plan(pool, policy)
            .await
            .map_err(|e| format!("round {round}: planning: {e}"))?;
        execute(pool, &sql)
            .await
            .map_err(|e| format!("round {round}: executing: {e}\n{sql}"))?;
    }
    let (changes, _) = plan(pool, policy).await?;
    if changes.is_empty() {
        Ok(())
    } else {
        Err(format!("still plans {changes:?}"))
    }
}

async fn with_universe<T>(
    pool: &PgPool,
    universe: &Universe,
    body: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    for statement in universe.cleanup_sql().iter().chain(&universe.setup_sql()) {
        sqlx::raw_sql(statement)
            .execute(pool)
            .await
            .map_err(|e| format!("setup `{statement}`: {e}"))?;
    }
    let result = body.await;
    for statement in universe.cleanup_sql() {
        let _ = sqlx::raw_sql(&statement).execute(pool).await;
    }
    result
}

async fn run_pair(pool: &PgPool, seed: u64, a: &Policy, b: &Policy) -> Result<(), String> {
    let policies = [("A", a, b), ("B", b, a)];
    for round in 0..ROUNDS {
        for (label, this, other) in &policies {
            let (changes, sql) = plan(pool, this)
                .await
                .map_err(|e| format!("round {round}: planning {label}: {e}"))?;
            if let Some(undo) = first_undo(&changes, other) {
                return Err(format!(
                    "round {round}: {label}'s plan undoes the other policy: {undo}"
                ));
            }
            if std::env::var_os("PGROLES_CLAIMS_PROPERTY_TRACE").is_some() {
                eprintln!("--- round {round} {label}: {changes:?}\n{sql}");
            }
            execute(pool, &sql)
                .await
                .map_err(|e| format!("round {round}: executing {label}: {e}\n{sql}"))?;
        }
    }
    for (label, this, _) in &policies {
        let (changes, _) = plan(pool, this).await?;
        if !changes.is_empty() {
            return Err(format!(
                "seed {seed}: {label} still plans {} change(s) after {ROUNDS} rounds: {changes:?}",
                changes.len()
            ));
        }
    }
    Ok(())
}

#[test]
#[ignore]
fn policies_without_conflicts_never_undo_each_other() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let pool = runtime
        .block_on(PgPool::connect(&database_url()))
        .expect("failed to connect to live test database");
    let database: String = runtime
        .block_on(sqlx::query_scalar("SELECT current_database()").fetch_one(&pool))
        .expect("current_database");

    let (mut checked, mut conflicting, mut invalid) = (0, 0, 0);
    let mut failures = Vec::new();
    let mut solo_findings = Vec::new();
    let seeds: Vec<u64> = match std::env::var("PGROLES_CLAIMS_PROPERTY_SEED") {
        Ok(one) => vec![
            one.parse()
                .expect("PGROLES_CLAIMS_PROPERTY_SEED is a number"),
        ],
        Err(_) => (0..seed_count()).collect(),
    };
    for seed in seeds {
        let universe = Universe::new(seed, database.clone());
        let mut rng = Rng::new(seed);
        let (left, right) = (
            gen_policy(&mut rng, &universe),
            gen_policy(&mut rng, &universe),
        );
        let (Some(a), Some(b)) = (prepare(&left), prepare(&right)) else {
            invalid += 1;
            continue;
        };
        if a.claims.overlaps(&b.claims) {
            conflicting += 1;
            continue;
        }

        let solo: Vec<String> = [("A", &a, &left), ("B", &b, &right)]
            .into_iter()
            .filter_map(|(label, policy, raw)| {
                runtime
                    .block_on(with_universe(
                        &pool,
                        &universe,
                        converges_alone(&pool, policy),
                    ))
                    .err()
                    .map(|error| format!("seed {seed} {label} alone: {error}\n  {raw}"))
            })
            .collect();
        if !solo.is_empty() {
            solo_findings.extend(solo);
            continue;
        }
        checked += 1;

        let outcome = runtime.block_on(with_universe(
            &pool,
            &universe,
            run_pair(&pool, seed, &a, &b),
        ));
        if let Err(error) = outcome {
            failures.push(format!(
                "seed {seed} ({}):\n  {error}\n  A = {left}\n  B = {right}",
                universe.prefix
            ));
        }
    }
    eprintln!(
        "claims property: {checked} accepted pairs executed, {conflicting} pairs reported \
         as conflicting, {invalid} invalid, {} policies that do not converge alone",
        solo_findings.len()
    );
    // Not this test's property, but worth seeing: each is a single-policy
    // convergence problem found along the way.
    for finding in &solo_findings {
        eprintln!("single-policy finding: {finding}");
    }
    assert!(checked > 0, "no accepted pair was generated");
    assert!(
        failures.is_empty(),
        "{} accepted pair(s) violated the contract:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
