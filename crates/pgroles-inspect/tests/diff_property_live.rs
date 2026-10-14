//! Live convergence property tests — the real PostgreSQL server is the oracle.
//!
//! `pgroles-core/tests/diff_property.rs` is the fast, every-push logic check:
//! it validates the diff engine against a pure in-test interpreter of `Change`
//! semantics. That interpreter shares authorship (and therefore potential
//! blind spots) with the engine — a wrong shared belief about PostgreSQL
//! semantics (e.g. the GUC list-value bug where `SET search_path = 'a, b'`
//! stored ONE schema literally named `a, b`) is invisible to any purely
//! model-based test. This suite closes that gap by making the database itself
//! the convergence oracle. For each seeded pseudo-random `(current, desired)`
//! graph pair it:
//!
//! 1. **Bootstraps** `current` into the live database:
//!    `diff(empty, current)` → `render_statements` → execute (two phases:
//!    roles+schemas first, then backing tables/sequences, then bindings).
//! 2. **Inspects** the database back into a `RoleGraph` via
//!    `pgroles_inspect::inspect`, scoped to the union of both graphs' role and
//!    schema names (dropped roles must be visible to plan drops).
//! 3. **Converges**: `diff(inspected, desired)` → render → execute.
//! 4. **Asserts live convergence**: re-inspect == `desired`.
//! 5. **Asserts live idempotence**: `diff(re-inspected, desired)` is empty.
//! 6. **Differential check**: the pure interpreter's prediction of step 3
//!    (`apply_changes`, kept in sync with diff_property.rs) must ALSO equal
//!    the re-inspected graph — every modelling assumption of the pure harness
//!    is thereby checked against real PostgreSQL.
//!
//! ## Comparison normalizations (deliberate and minimal)
//!
//! * **Prefix filtering.** Every generated role/schema name carries a
//!   per-seed prefix (`dpl{seed}_`). Inspected graphs are filtered to that
//!   prefix on all axes (roles, schemas, grants, default privileges,
//!   memberships) so state leaked by other tests or prior runs cannot
//!   contaminate the comparison. Generated graphs are entirely prefixed, so
//!   this cannot mask a real mismatch.
//! * **`password_valid_until`** is never generated; instead of normalizing it
//!   away we *assert* it inspects as `None` for every generated role.
//!
//! Nothing else is normalized — graphs are compared field-for-field.
//!
//! ## Generation constraints (DDL-realizable states only)
//!
//! * `current` is restricted to states pgroles itself can produce, so the
//!   bootstrap is just the pgroles pipeline. Extra live-only drift (owner
//!   schema-privilege revocation) is injected with raw SQL after bootstrap —
//!   the first `inspect` absorbs it, so generated graphs need not model it.
//! * Schema owners are always `Some(generated role)` with owner privileges
//!   exactly `{CREATE, USAGE}` (what pgroles converges to).
//! * Grants use concrete table/sequence/schema names only — no wildcards, no
//!   functions, no types, no database privileges. That keeps object bootstrap
//!   simple; wildcard/function coverage lives in the pure harness and the
//!   targeted live tests. **Coverage boundary, not an accident.**
//! * PUBLIC grantees are never generated: PUBLIC ACL entries are
//!   database-global state with no schema prefix to isolate them, so
//!   concurrent seeds would corrupt them for each other.
//! * `ensure: absent` assertions are never generated; absence semantics are
//!   covered by targeted live tests in `crates/pgroles-cli/tests/cli.rs`.
//! * Global-scope default privileges are never generated: like PUBLIC ACLs,
//!   global `pg_default_acl` rows are database-global state with no schema
//!   prefix to isolate them, so concurrent seeds would corrupt them for
//!   each other.
//! * Relation grants (tables/sequences) only target the base schemas present
//!   in *both* graphs: pgroles manages grants, not tables, so an object must
//!   exist before a grant on it can execute — and a schema created by the
//!   convergence plan itself cannot contain pre-created tables. Desired-only
//!   ("extra") schemas exercise `CreateSchema` and carry at most schema-level
//!   grants.
//! * Schema-level grants never target the schema's owner (in either graph):
//!   pgroles' inspection deliberately folds owner CREATE/USAGE into
//!   `SchemaState` (`remove_redundant_schema_owner_grants`), so an explicit
//!   owner self-grant in the manifest can never round-trip.
//! * Default-privilege grantees never equal the default-privilege owner:
//!   `ALTER DEFAULT PRIVILEGES FOR ROLE o ... GRANT ... TO o` materializes
//!   the owner's *implicit* default privileges into `pg_default_acl`, which
//!   would inspect back as far more than the manifest declared.
//! * Membership edges are oriented lexicographically (group < member), so the
//!   union of both graphs' edges can never form a cycle PostgreSQL rejects.
//! * No superusers/replication/bypassrls/createrole, no passwords, plain
//!   ASCII comments (COMMENT ON ROLE round-trips through pg_shdescription).
//! * Role config comes from a small safe set — `statement_timeout`,
//!   `application_name`, a custom `app.stray` drift key, and `search_path`
//!   with 1–2 schema elements, which exercises the GUC-list path live.
//!
//! Seeds are fixed (0..N, default 25) so CI is reproducible; override the
//! count with `PGROLES_LIVE_PROPERTY_SEEDS`. Every assertion prints the seed.
//!
//! Requires DATABASE_URL; run with `cargo test -- --include-ignored`.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use sqlx::{Executor, PgPool};

use pgroles_core::diff::{Change, diff};
use pgroles_core::manifest::{ExpandedManifest, ExpandedSchema, ObjectType, Privilege};
use pgroles_core::model::{
    DefaultPrivKey, DefaultPrivState, DefaultPrivilegeScope, GrantKey, GrantState, Grantee,
    MembershipEdge, RoleAttribute, RoleGraph, RoleState, SchemaState,
    default_schema_owner_privileges,
};
use pgroles_core::sql::{quote_ident, render_statements};
use pgroles_inspect::{InspectConfig, inspect};

// ---------------------------------------------------------------------------
// Test harness plumbing
// ---------------------------------------------------------------------------

fn database_url() -> String {
    std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live DB tests")
}

fn seed_count() -> u64 {
    std::env::var("PGROLES_LIVE_PROPERTY_SEEDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(25)
}

fn with_runtime<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Runtime::new()
        .expect("failed to create tokio runtime")
        .block_on(future)
}

async fn execute_sql(pool: &PgPool, statement: &str, seed: u64, phase: &str) {
    pool.execute(statement)
        .await
        .unwrap_or_else(|error| panic!("seed {seed} [{phase}]: failed `{statement}`: {error}"));
}

async fn execute_changes(pool: &PgPool, changes: &[Change], seed: u64, phase: &str) {
    let changes = if changes
        .iter()
        .any(|c| matches!(c, Change::UpdateMemberOptions { .. }))
    {
        let roles: BTreeSet<String> = changes
            .iter()
            .filter_map(|c| match c {
                Change::UpdateMemberOptions { role, .. } => Some(role.clone()),
                _ => None,
            })
            .collect();
        let expanded = pgroles_core::authoring::prepare_policy("{}")
            .unwrap()
            .expanded;
        let mut config = InspectConfig::from_expanded(&expanded, false);
        config.managed_roles = roles.into_iter().collect();
        let catalog = inspect(pool, &config).await.unwrap();
        pgroles_inspect::resolve_membership_options(pool, changes.to_vec(), &catalog)
            .await
            .unwrap()
    } else {
        changes.to_vec()
    };
    // One connection for the whole change list, mirroring production's
    // single-transaction apply: grantor-targeted revokes render as
    // `SET ROLE grantor; REVOKE ...; RESET ROLE;`, and running those
    // statements across pooled connections would strand a connection with an
    // active SET ROLE (and leave the revoke unattributed).
    let mut conn = pool
        .acquire()
        .await
        .unwrap_or_else(|error| panic!("seed {seed} [{phase}]: failed to acquire: {error}"));
    for change in &changes {
        for statement in render_statements(change).unwrap() {
            conn.execute(statement.as_str())
                .await
                .unwrap_or_else(|error| {
                    panic!("seed {seed} [{phase}]: failed `{statement}`: {error}")
                });
        }
    }
}

/// Drop-guard that removes every generated schema and role, even on panic.
/// Runs in sync context (its own runtime + connection), like `RoleCleanup` in
/// `config_roundtrip.rs`. Errors are ignored — objects may not exist.
struct SeedCleanup {
    roles: Vec<String>,
    schemas: Vec<String>,
}

impl SeedCleanup {
    async fn run(pool: &PgPool, roles: &[String], schemas: &[String]) {
        for schema in schemas {
            let _ = pool
                .execute(format!("DROP SCHEMA IF EXISTS {} CASCADE;", quote_ident(schema)).as_str())
                .await;
        }
        for role in roles {
            // DROP OWNED clears grants and default-privilege entries that
            // would otherwise block DROP ROLE. It fails when the role does
            // not exist — ignored like everything else here.
            let _ = pool
                .execute(format!("DROP OWNED BY {};", quote_ident(role)).as_str())
                .await;
            let _ = pool
                .execute(format!("DROP ROLE IF EXISTS {};", quote_ident(role)).as_str())
                .await;
        }
    }
}

impl Drop for SeedCleanup {
    fn drop(&mut self) {
        let roles = self.roles.clone();
        let schemas = self.schemas.clone();
        with_runtime(async move {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect for cleanup");
            Self::run(&pool, &roles, &schemas).await;
        });
    }
}

// ---------------------------------------------------------------------------
// Tiny seeded PRNG (xorshift64*) — copied from diff_property.rs.
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn usize(&mut self, modulus: usize) -> usize {
        if modulus == 0 {
            return 0;
        }
        (self.next_u64() as usize) % modulus
    }
    fn bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

// ---------------------------------------------------------------------------
// Name pools — every identifier carries the per-seed prefix and stays well
// under PostgreSQL's 63-byte identifier limit.
// ---------------------------------------------------------------------------

struct Names {
    prefix: String,
    role_pool: Vec<String>,
    base_schemas: Vec<String>,
    extra_schemas: Vec<String>,
    tables: Vec<String>,
    sequences: Vec<String>,
}

impl Names {
    fn new(seed: u64) -> Self {
        let prefix = format!("dpl{seed}_");
        Self {
            role_pool: (0..4).map(|i| format!("{prefix}r{i}")).collect(),
            base_schemas: (0..2).map(|i| format!("{prefix}s{i}")).collect(),
            extra_schemas: vec![format!("{prefix}x0")],
            tables: vec!["t0".to_string(), "t1".to_string()],
            sequences: vec!["q0".to_string(), "q1".to_string()],
            prefix,
        }
    }
}

// ---------------------------------------------------------------------------
// Graph generators
// ---------------------------------------------------------------------------

const TABLE_PRIVS: [Privilege; 4] = [
    Privilege::Select,
    Privilege::Insert,
    Privilege::Update,
    Privilege::Delete,
];
const SEQUENCE_PRIVS: [Privilege; 3] = [Privilege::Usage, Privilege::Select, Privilege::Update];
const SCHEMA_PRIVS: [Privilege; 2] = [Privilege::Usage, Privilege::Create];

fn priv_subset(rng: &mut Rng, pool: &[Privilege]) -> BTreeSet<Privilege> {
    let mut out = BTreeSet::new();
    for _ in 0..=rng.usize(pool.len()) {
        out.insert(pool[rng.usize(pool.len())]);
    }
    out
}

/// Role config drawn from a small set that PostgreSQL stores verbatim in
/// `pg_roles.rolconfig` (verified against a live server). `search_path` is
/// the interesting one: it is a `GUC_LIST_QUOTE` parameter, so it exercises
/// the element-wise list handling end to end.
fn gen_config(rng: &mut Rng, names: &Names) -> BTreeMap<String, String> {
    let mut config = BTreeMap::new();
    for _ in 0..rng.usize(3) {
        match rng.usize(3) {
            0 => config.insert(
                "statement_timeout".to_string(),
                ["30s", "45s"][rng.usize(2)].to_string(),
            ),
            1 => config.insert(
                "application_name".to_string(),
                format!("app{}", rng.usize(3)),
            ),
            _ => {
                let first = &names.base_schemas[rng.usize(names.base_schemas.len())];
                let value = if rng.bool() {
                    first.clone()
                } else {
                    let second = &names.base_schemas[rng.usize(names.base_schemas.len())];
                    // Canonical list form ("a, b") — matches
                    // guc::canonicalize_list_guc_value for simple identifiers.
                    format!("{first}, {second}")
                };
                config.insert("search_path".to_string(), value)
            }
        };
    }
    config
}

fn gen_role_state(rng: &mut Rng, names: &Names) -> RoleState {
    RoleState {
        login: rng.bool(),
        superuser: false,
        createdb: rng.bool(),
        createrole: false,
        inherit: rng.usize(4) != 0, // usually true (PG default)
        replication: false,
        bypassrls: false,
        connection_limit: if rng.usize(3) == 0 {
            rng.usize(20) as i32
        } else {
            -1
        },
        comment: if rng.bool() {
            Some(format!("live property role {}", rng.usize(5)))
        } else {
            None
        },
        password_valid_until: None,
        config: gen_config(rng, names),
    }
}

fn pick<'a>(rng: &mut Rng, items: &'a [String]) -> &'a String {
    &items[rng.usize(items.len())]
}

/// Membership edges are oriented by name order (group < member) so the union
/// of current and desired edges is always a DAG — PostgreSQL rejects circular
/// role memberships.
fn membership_edge(rng: &mut Rng, a: &str, b: &str) -> Option<MembershipEdge> {
    if a == b {
        return None;
    }
    let (role, member) = if a < b { (a, b) } else { (b, a) };
    Some(MembershipEdge {
        role: role.to_string(),
        member: member.to_string(),
        inherit: rng.bool(),
        admin: rng.bool(),
    })
}

fn gen_grants(rng: &mut Rng, graph: &mut RoleGraph, names: &Names) {
    let role_names: Vec<String> = graph.roles.keys().cloned().collect();
    let schema_names: Vec<String> = graph.schemas.keys().cloned().collect();
    for _ in 0..rng.usize(7) {
        let role = Grantee::Role(pick(rng, &role_names).clone());
        let (key, privileges) = match rng.usize(3) {
            0 => {
                let schema = pick(rng, &schema_names).clone();
                (
                    GrantKey {
                        role,
                        object_type: ObjectType::Schema,
                        schema: None,
                        name: Some(schema),
                    },
                    priv_subset(rng, &SCHEMA_PRIVS),
                )
            }
            1 => (
                GrantKey {
                    role,
                    object_type: ObjectType::Table,
                    schema: Some(pick(rng, &names.base_schemas).clone()),
                    name: Some(pick(rng, &names.tables).clone()),
                },
                priv_subset(rng, &TABLE_PRIVS),
            ),
            _ => (
                GrantKey {
                    role,
                    object_type: ObjectType::Sequence,
                    schema: Some(pick(rng, &names.base_schemas).clone()),
                    name: Some(pick(rng, &names.sequences).clone()),
                },
                priv_subset(rng, &SEQUENCE_PRIVS),
            ),
        };
        graph.grants.insert(key, GrantState { privileges });
    }
}

fn gen_default_privileges(rng: &mut Rng, graph: &mut RoleGraph, names: &Names) {
    let role_names: Vec<String> = graph.roles.keys().cloned().collect();
    if role_names.len() < 2 {
        return;
    }
    for _ in 0..rng.usize(3) {
        let owner = pick(rng, &role_names).clone();
        let grantee = pick(rng, &role_names).clone();
        if owner == grantee {
            continue; // see the self-grantee boundary in the header
        }
        let (on_type, privileges) = if rng.bool() {
            (ObjectType::Table, priv_subset(rng, &TABLE_PRIVS))
        } else {
            (ObjectType::Sequence, priv_subset(rng, &SEQUENCE_PRIVS))
        };
        graph.default_privileges.insert(
            DefaultPrivKey {
                owner,
                scope: DefaultPrivilegeScope::Schema {
                    schema: pick(rng, &names.base_schemas).clone(),
                },
                on_type,
                grantee: Grantee::Role(grantee),
            },
            DefaultPrivState { privileges },
        );
    }
}

fn gen_memberships(rng: &mut Rng, graph: &mut RoleGraph) {
    let role_names: Vec<String> = graph.roles.keys().cloned().collect();
    for _ in 0..rng.usize(4) {
        let a = pick(rng, &role_names).clone();
        let b = pick(rng, &role_names).clone();
        if let Some(edge) = membership_edge(rng, &a, &b) {
            // Deduplicate by (role, member) — the diff keys memberships by
            // that pair.
            graph
                .memberships
                .retain(|e| !(e.role == edge.role && e.member == edge.member));
            graph.memberships.insert(edge);
        }
    }
}

/// Generate a manifest-shaped graph over the seed's name pools: a subset of
/// the role pool (at least two roles), every base schema (owner = a generated
/// role, owner privileges = the pgroles default `{CREATE, USAGE}`), optional
/// extra schemas when `allow_extras`, and grants/dps/memberships over them.
fn gen_graph(rng: &mut Rng, names: &Names, allow_extras: bool) -> RoleGraph {
    let mut graph = RoleGraph::default();
    for role in &names.role_pool {
        if rng.usize(4) != 0 {
            graph.roles.insert(role.clone(), gen_role_state(rng, names));
        }
    }
    for role in names.role_pool.iter().take(2) {
        graph
            .roles
            .entry(role.clone())
            .or_insert_with(|| gen_role_state(rng, names));
    }

    let role_names: Vec<String> = graph.roles.keys().cloned().collect();
    for schema in &names.base_schemas {
        let owner = pick(rng, &role_names).clone();
        graph.schemas.insert(
            schema.clone(),
            SchemaState {
                owner_privileges: default_schema_owner_privileges(&owner),
                owner: Some(owner),
            },
        );
    }
    if allow_extras {
        for schema in &names.extra_schemas {
            if rng.bool() {
                let owner = pick(rng, &role_names).clone();
                graph.schemas.insert(
                    schema.clone(),
                    SchemaState {
                        owner_privileges: default_schema_owner_privileges(&owner),
                        owner: Some(owner),
                    },
                );
            }
        }
    }

    gen_grants(rng, &mut graph, names);
    gen_default_privileges(rng, &mut graph, names);
    gen_memberships(rng, &mut graph);
    graph
}

/// Remove every reference to `role` from the graph, reassigning any schemas
/// it owns to another surviving role.
fn remove_role(graph: &mut RoleGraph, role: &str) {
    graph.roles.remove(role);
    let survivor = graph
        .roles
        .keys()
        .next()
        .expect("at least one role must survive removal")
        .clone();
    for state in graph.schemas.values_mut() {
        if state.owner.as_deref() == Some(role) {
            state.owner = Some(survivor.clone());
            state.owner_privileges = default_schema_owner_privileges(&survivor);
        }
    }
    graph.grants.retain(|key, _| key.role.as_str() != role);
    graph
        .default_privileges
        .retain(|key, _| key.owner != role && key.grantee.as_str() != role);
    graph
        .memberships
        .retain(|edge| edge.role != role && edge.member != role);
}

fn mutate_grant_privileges(rng: &mut Rng, key: &GrantKey, state: &mut GrantState) {
    let pool: &[Privilege] = match key.object_type {
        ObjectType::Table => &TABLE_PRIVS,
        ObjectType::Sequence => &SEQUENCE_PRIVS,
        _ => &SCHEMA_PRIVS,
    };
    if rng.bool() {
        // Extra privilege valid for the type — desired lacks it → REVOKE.
        // Tables additionally allow TRUNCATE, which desired never uses.
        let extra = if key.object_type == ObjectType::Table && rng.bool() {
            Privilege::Truncate
        } else {
            pool[rng.usize(pool.len())]
        };
        state.privileges.insert(extra);
    } else if state.privileges.len() > 1 {
        let p = *state.privileges.iter().next().unwrap();
        state.privileges.remove(&p); // fewer → GRANT
    }
}

/// Drift strategy: derive a `current` that has diverged from `desired` in
/// ways the pipeline can bootstrap and the diff engine can fully reconcile.
fn derive_current(rng: &mut Rng, desired: &RoleGraph, names: &Names) -> RoleGraph {
    let mut c = desired.clone();

    // ----- Extra schemas: drop some from current → convergence CreateSchema.
    for extra in &names.extra_schemas {
        if c.schemas.contains_key(extra) && rng.bool() {
            c.schemas.remove(extra);
            c.grants
                .retain(|key, _| key.name.as_deref() != Some(extra.as_str()));
        }
    }

    // ----- Roles -----
    for name in desired.roles.keys().cloned().collect::<Vec<_>>() {
        match rng.usize(6) {
            0 => {
                if c.roles.len() > 1 {
                    remove_role(&mut c, &name); // desired re-CREATEs it
                }
            }
            1 => {
                if let Some(st) = c.roles.get_mut(&name) {
                    st.login = !st.login;
                    if rng.bool() {
                        st.createdb = !st.createdb;
                    }
                    if rng.bool() {
                        st.connection_limit = if st.connection_limit == -1 { 7 } else { -1 };
                    }
                    if rng.bool() {
                        st.inherit = !st.inherit;
                    }
                }
            }
            2 => {
                if let Some(st) = c.roles.get_mut(&name) {
                    // Stray custom GUC desired lacks → RESET; drifted value → SET.
                    st.config
                        .insert("app.stray".to_string(), format!("v{}", rng.usize(9)));
                    if rng.bool() {
                        st.config
                            .insert("statement_timeout".to_string(), "60s".to_string());
                    }
                }
            }
            3 => {
                if let Some(st) = c.roles.get_mut(&name) {
                    st.comment = match &st.comment {
                        Some(_) => None,
                        None => Some("drifted".to_string()),
                    };
                }
            }
            _ => {}
        }
    }
    // Stray roles absent from desired → DROP (after their bindings are revoked).
    for i in 0..rng.usize(3) {
        c.roles.insert(
            format!("{}stray{i}", names.prefix),
            gen_role_state(rng, names),
        );
    }
    let current_roles: Vec<String> = c.roles.keys().cloned().collect();

    // ----- Grants -----
    for key in c.grants.keys().cloned().collect::<Vec<_>>() {
        match rng.usize(4) {
            0 => {
                c.grants.remove(&key); // desired re-GRANTs
            }
            1 | 2 => {
                if rng.bool()
                    && let Some(state) = c.grants.get_mut(&key)
                {
                    mutate_grant_privileges(rng, &key, state);
                }
            }
            _ => {}
        }
    }
    // Stray grants absent from desired → REVOKE.
    for _ in 0..rng.usize(3) {
        c.grants.insert(
            GrantKey {
                role: Grantee::Role(pick(rng, &current_roles).clone()),
                object_type: ObjectType::Table,
                schema: Some(pick(rng, &names.base_schemas).clone()),
                name: Some(pick(rng, &names.tables).clone()),
            },
            GrantState {
                privileges: priv_subset(rng, &TABLE_PRIVS),
            },
        );
    }

    // ----- Default privileges -----
    for key in c.default_privileges.keys().cloned().collect::<Vec<_>>() {
        match rng.usize(4) {
            0 => {
                c.default_privileges.remove(&key);
            }
            1 => {
                if let Some(state) = c.default_privileges.get_mut(&key) {
                    let pool: &[Privilege] = if key.on_type == ObjectType::Table {
                        &TABLE_PRIVS
                    } else {
                        &SEQUENCE_PRIVS
                    };
                    state.privileges.insert(pool[rng.usize(pool.len())]);
                }
            }
            2 => {
                if let Some(state) = c.default_privileges.get_mut(&key)
                    && state.privileges.len() > 1
                {
                    let p = *state.privileges.iter().next().unwrap();
                    state.privileges.remove(&p);
                }
            }
            _ => {}
        }
    }
    // Stray current-only default privileges → RevokeDefaultPrivilege. The
    // owner may be a current-only role: the revoke executes before DropRole.
    if current_roles.len() >= 2 {
        for _ in 0..rng.usize(2) {
            let owner = pick(rng, &current_roles).clone();
            let grantee = pick(rng, &current_roles).clone();
            if owner == grantee {
                continue;
            }
            c.default_privileges.insert(
                DefaultPrivKey {
                    owner,
                    scope: DefaultPrivilegeScope::Schema {
                        schema: pick(rng, &names.base_schemas).clone(),
                    },
                    on_type: ObjectType::Table,
                    grantee: Grantee::Role(grantee),
                },
                DefaultPrivState {
                    privileges: [Privilege::Select].into_iter().collect(),
                },
            );
        }
    }

    // ----- Memberships -----
    for edge in c.memberships.iter().cloned().collect::<Vec<_>>() {
        match rng.usize(4) {
            0 => {
                c.memberships.remove(&edge); // desired re-ADDs
            }
            1 => {
                // Flip a flag → diff emits REMOVE + ADD.
                c.memberships.remove(&edge);
                c.memberships.insert(MembershipEdge {
                    inherit: !edge.inherit,
                    ..edge
                });
            }
            _ => {}
        }
    }
    for _ in 0..rng.usize(3) {
        let a = pick(rng, &current_roles).clone();
        let b = pick(rng, &current_roles).clone();
        if let Some(edge) = membership_edge(rng, &a, &b) {
            c.memberships
                .retain(|e| !(e.role == edge.role && e.member == edge.member));
            c.memberships.insert(edge);
        }
    }

    // ----- Schema owner drift (base schemas stay present in current) -----
    for name in c.schemas.keys().cloned().collect::<Vec<_>>() {
        if rng.usize(4) == 0 {
            let owner = pick(rng, &current_roles).clone();
            if let Some(state) = c.schemas.get_mut(&name) {
                state.owner_privileges = default_schema_owner_privileges(&owner);
                state.owner = Some(owner);
            }
        }
    }

    c
}

/// Enforce the per-graph round-trip boundary documented in the header: a
/// schema-level grant whose grantee owns that schema *in the same graph*
/// cannot round-trip, because inspection folds the owner's privileges into
/// `SchemaState` instead of reporting an explicit grant row — a desired-side
/// grant-to-owner would re-plan forever, and a current-side one is not a
/// reachable inspected state.
///
/// The CROSS-graph shape — a stale grant in `current` to a role that becomes
/// the schema's owner in `desired` (issue #140) — is deliberately generatable:
/// the diff engine now suppresses the revoke that the same-plan owner
/// transfer would otherwise turn into a strip of the new owner's USAGE, and
/// this suite proves that fix against real PostgreSQL.
fn strip_owner_schema_grants(current: &mut RoleGraph, desired: &mut RoleGraph) {
    for graph in [current, desired] {
        let owners: BTreeSet<(String, String)> = graph
            .schemas
            .iter()
            .filter_map(|(schema, state)| {
                state
                    .owner
                    .as_ref()
                    .map(|owner| (schema.clone(), owner.clone()))
            })
            .collect();
        graph.grants.retain(|key, _| {
            !(key.object_type == ObjectType::Schema
                && key.name.as_ref().is_some_and(|name| {
                    owners.contains(&(name.clone(), key.role.as_str().to_string()))
                }))
        });
    }
}

/// Live-only drift injected as raw SQL after bootstrap: PostgreSQL lets a
/// schema owner's ordinary CREATE/USAGE be revoked, a state the manifest can
/// not express but the diff must repair (`EnsureSchemaOwnerPrivileges`). The
/// first `inspect` absorbs this, so the generated graphs need not model it.
fn gen_owner_privilege_drift(rng: &mut Rng, current: &RoleGraph) -> Vec<String> {
    let mut statements = Vec::new();
    for (schema, state) in &current.schemas {
        let Some(owner) = &state.owner else { continue };
        if rng.usize(3) == 0 {
            let privilege = ["CREATE", "USAGE", "CREATE, USAGE"][rng.usize(3)];
            statements.push(format!(
                "REVOKE {privilege} ON SCHEMA {} FROM {};",
                quote_ident(schema),
                quote_ident(owner)
            ));
        }
    }
    statements
}

/// One generated test case: bootstrap recipe, drift SQL, and target state.
struct Case {
    current: RoleGraph,
    desired: RoleGraph,
    drift_sql: Vec<String>,
}

fn generate_case(seed: u64, names: &Names) -> Case {
    let mut rng = Rng::new(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(seed) | 1);
    let mut desired = gen_graph(&mut rng, names, true);
    // Mostly the drift strategy; every fifth seed uses an independently
    // generated current over the same name pools (fresh-pair case). Fresh
    // currents get no extra schemas, preserving current.schemas ⊆
    // desired.schemas (the diff engine has no DropSchema).
    let mut current = if seed % 5 == 4 {
        gen_graph(&mut rng, names, false)
    } else {
        derive_current(&mut rng, &desired, names)
    };
    strip_owner_schema_grants(&mut current, &mut desired);
    let drift_sql = gen_owner_privilege_drift(&mut rng, &current);
    Case {
        current,
        desired,
        drift_sql,
    }
}

// ---------------------------------------------------------------------------
// Interpreter: pure-data semantics of each Change variant.
//
// COPIED from pgroles-core/tests/diff_property.rs (integration tests cannot
// share code across crates without a helper crate) — KEEP IN SYNC. The whole
// point of this file is that these semantics are checked against real
// PostgreSQL: if the two interpreters drift apart, one of them is wrong and
// this suite tells you which.
// ---------------------------------------------------------------------------

fn apply_attribute(state: &mut RoleState, attr: &RoleAttribute) {
    match attr {
        RoleAttribute::Login(v) => state.login = *v,
        RoleAttribute::Superuser(v) => state.superuser = *v,
        RoleAttribute::Createdb(v) => state.createdb = *v,
        RoleAttribute::Createrole(v) => state.createrole = *v,
        RoleAttribute::Inherit(v) => state.inherit = *v,
        RoleAttribute::Replication(v) => state.replication = *v,
        RoleAttribute::Bypassrls(v) => state.bypassrls = *v,
        RoleAttribute::ConnectionLimit(v) => state.connection_limit = *v,
        RoleAttribute::ValidUntil(v) => state.password_valid_until = v.clone(),
        RoleAttribute::SetConfig(k, v) => {
            state.config.insert(k.clone(), v.clone());
        }
        RoleAttribute::ResetConfig(k) => {
            state.config.remove(k);
        }
    }
}

/// Apply a diff plan to a `RoleGraph`, returning the resulting graph. Panics
/// on any `Change` variant the diff engine is not supposed to emit.
fn apply_changes(graph: &RoleGraph, changes: &[Change]) -> RoleGraph {
    let mut g = graph.clone();
    for change in changes {
        match change {
            Change::CreateRole { name, state } => {
                g.roles.insert(name.clone(), state.clone());
            }
            Change::AlterRole { name, attributes } => {
                let state = g
                    .roles
                    .get_mut(name)
                    .unwrap_or_else(|| panic!("AlterRole on absent role {name:?}"));
                for attr in attributes {
                    apply_attribute(state, attr);
                }
            }
            Change::SetComment { name, comment } => {
                let state = g
                    .roles
                    .get_mut(name)
                    .unwrap_or_else(|| panic!("SetComment on absent role {name:?}"));
                state.comment = comment.clone();
            }
            Change::DropRole { name } => {
                g.roles.remove(name);
            }
            Change::CreateSchema { name, owner } => {
                let owner_privileges = match owner {
                    Some(o) => default_schema_owner_privileges(o),
                    None => BTreeSet::new(),
                };
                g.schemas.insert(
                    name.clone(),
                    SchemaState {
                        owner: owner.clone(),
                        owner_privileges,
                    },
                );
            }
            Change::AlterSchemaOwner { name, owner } => {
                let state = g
                    .schemas
                    .get_mut(name)
                    .unwrap_or_else(|| panic!("AlterSchemaOwner on absent schema {name:?}"));
                state.owner = Some(owner.clone());
                // PostgreSQL's ALTER SCHEMA ... OWNER TO merges any explicit
                // ACL entry the incoming owner held into the (full) owner
                // entry, and inspection folds owner privileges into
                // SchemaState rather than reporting an explicit grant row —
                // mirror both (see issue #140).
                state.owner_privileges =
                    [Privilege::Create, Privilege::Usage].into_iter().collect();
                g.grants.remove(&GrantKey {
                    role: Grantee::Role(owner.clone()),
                    object_type: ObjectType::Schema,
                    schema: None,
                    name: Some(name.clone()),
                });
            }
            Change::EnsureSchemaOwnerPrivileges {
                name, privileges, ..
            } => {
                let state = g.schemas.get_mut(name).unwrap_or_else(|| {
                    panic!("EnsureSchemaOwnerPrivileges on absent schema {name:?}")
                });
                for p in privileges {
                    state.owner_privileges.insert(*p);
                }
            }
            Change::Grant {
                role,
                privileges,
                object_type,
                schema,
                name,
            } => {
                let key = GrantKey {
                    role: role.clone(),
                    object_type: *object_type,
                    schema: schema.clone(),
                    name: name.clone(),
                };
                let entry = g.grants.entry(key).or_insert_with(|| GrantState {
                    privileges: BTreeSet::new(),
                });
                for p in privileges {
                    entry.privileges.insert(*p);
                }
            }
            Change::Revoke {
                role,
                privileges,
                object_type,
                schema,
                name,
                ..
            } => {
                let key = GrantKey {
                    role: role.clone(),
                    object_type: *object_type,
                    schema: schema.clone(),
                    name: name.clone(),
                };
                let now_empty = if let Some(entry) = g.grants.get_mut(&key) {
                    for p in privileges {
                        entry.privileges.remove(p);
                    }
                    entry.privileges.is_empty()
                } else {
                    false
                };
                // An emptied grant is indistinguishable from "no grant".
                if now_empty {
                    g.grants.remove(&key);
                }
            }
            Change::SetDefaultPrivilege {
                owner,
                scope,
                on_type,
                grantee,
                privileges,
            } => {
                let key = DefaultPrivKey {
                    owner: owner.clone(),
                    scope: scope.clone(),
                    on_type: *on_type,
                    grantee: grantee.clone(),
                };
                let entry = g
                    .default_privileges
                    .entry(key)
                    .or_insert_with(|| DefaultPrivState {
                        privileges: BTreeSet::new(),
                    });
                for p in privileges {
                    entry.privileges.insert(*p);
                }
            }
            Change::RevokeDefaultPrivilege {
                owner,
                scope,
                on_type,
                grantee,
                privileges,
            } => {
                let key = DefaultPrivKey {
                    owner: owner.clone(),
                    scope: scope.clone(),
                    on_type: *on_type,
                    grantee: grantee.clone(),
                };
                let now_empty = if let Some(entry) = g.default_privileges.get_mut(&key) {
                    for p in privileges {
                        entry.privileges.remove(p);
                    }
                    entry.privileges.is_empty()
                } else {
                    false
                };
                if now_empty {
                    g.default_privileges.remove(&key);
                }
            }
            Change::AddMember {
                role,
                member,
                inherit,
                admin,
            } => {
                g.memberships
                    .retain(|e| !(e.role == *role && e.member == *member));
                g.memberships.insert(MembershipEdge {
                    role: role.clone(),
                    member: member.clone(),
                    inherit: *inherit,
                    admin: *admin,
                });
            }
            Change::UpdateMemberOptions {
                role,
                member,
                grantor,
                inherit,
                admin,
                ..
            } => {
                let key = (role.clone(), member.clone());
                let options = g
                    .membership_edge_options
                    .get_mut(&key)
                    .expect("catalog option facts");
                let edge = options.entry(grantor.clone()).or_insert(
                    pgroles_core::model::MembershipOptions {
                        inherit: false,
                        admin: false,
                        set: false,
                    },
                );
                g.membership_edge_grantors
                    .entry(key.clone())
                    .or_default()
                    .insert(grantor.clone());
                if let Some(value) = inherit {
                    edge.inherit = *value;
                }
                if let Some(value) = admin {
                    edge.admin = *value;
                }
                let inherit = options.values().any(|edge| edge.inherit);
                let admin = options.values().any(|edge| edge.admin);
                g.memberships
                    .retain(|e| !(e.role == *role && e.member == *member));
                g.memberships.insert(MembershipEdge {
                    role: role.clone(),
                    member: member.clone(),
                    inherit,
                    admin,
                });
            }
            Change::RemoveMember { role, member, .. } => {
                g.memberships
                    .retain(|e| !(e.role == *role && e.member == *member));
            }
            // Variants the diff engine never emits — presence indicates a bug.
            Change::SetPassword { .. }
            | Change::ReassignOwned { .. }
            | Change::DropOwned { .. }
            | Change::TerminateSessions { .. } => {
                panic!("diff() should never emit {change:?}");
            }
        }
    }
    g
}

// ---------------------------------------------------------------------------
// Comparison helpers
// ---------------------------------------------------------------------------

fn graph_mismatch(got: &RoleGraph, want: &RoleGraph) -> Option<String> {
    if got.roles != want.roles {
        return Some(format!(
            "roles differ:\n  got  {:#?}\n  want {:#?}",
            got.roles, want.roles
        ));
    }
    if got.schemas != want.schemas {
        return Some(format!(
            "schemas differ:\n  got  {:#?}\n  want {:#?}",
            got.schemas, want.schemas
        ));
    }
    if got.grants != want.grants {
        return Some(format!(
            "grants differ:\n  got  {:#?}\n  want {:#?}",
            got.grants, want.grants
        ));
    }
    if got.default_privileges != want.default_privileges {
        return Some(format!(
            "default_privileges differ:\n  got  {:#?}\n  want {:#?}",
            got.default_privileges, want.default_privileges
        ));
    }
    if got.memberships != want.memberships {
        return Some(format!(
            "memberships differ:\n  got  {:#?}\n  want {:#?}",
            got.memberships, want.memberships
        ));
    }
    None
}

/// Restrict an inspected graph to the seed's namespace (see the
/// normalizations note in the header).
fn filter_prefix(graph: &RoleGraph, prefix: &str) -> RoleGraph {
    let mut g = graph.clone();
    g.roles.retain(|name, _| name.starts_with(prefix));
    g.schemas.retain(|name, _| name.starts_with(prefix));
    g.grants
        .retain(|key, _| key.role.as_str().starts_with(prefix));
    g.default_privileges
        .retain(|key, _| key.owner.starts_with(prefix) && key.grantee.as_str().starts_with(prefix));
    g.memberships
        .retain(|edge| edge.role.starts_with(prefix) && edge.member.starts_with(prefix));
    g
}

fn union_names(current: &RoleGraph, desired: &RoleGraph) -> (Vec<String>, Vec<String>) {
    let mut roles: BTreeSet<String> = BTreeSet::new();
    let mut schemas: BTreeSet<String> = BTreeSet::new();
    for graph in [current, desired] {
        roles.extend(graph.roles.keys().cloned());
        schemas.extend(graph.schemas.keys().cloned());
    }
    (roles.into_iter().collect(), schemas.into_iter().collect())
}

/// Build the `InspectConfig` for a case. `InspectConfig`'s `wildcard_grants`
/// field is private, so it cannot be built with a struct literal from outside
/// the crate; instead a minimal `ExpandedManifest` carrying only the union
/// schema names goes through `from_expanded` (yielding empty wildcards and
/// `managed_schemas == privilege_schemas == union schemas`), and the union
/// role names — which must include roles only present in `current`, so drops
/// are planned — are attached via `with_additional_roles`.
fn inspect_config(roles: &[String], schemas: &[String]) -> InspectConfig {
    let expanded = ExpandedManifest {
        schemas: schemas
            .iter()
            .map(|name| ExpandedSchema {
                name: name.clone(),
                owner: None,
            })
            .collect(),
        roles: Vec::new(),
        grants: Vec::new(),
        default_privileges: Vec::new(),
        memberships: Vec::new(),
    };
    InspectConfig::from_expanded(&expanded, false).with_additional_roles(roles.iter().cloned())
}

// ---------------------------------------------------------------------------
// Per-seed execution
// ---------------------------------------------------------------------------

async fn run_seed(pool: &PgPool, seed: u64, names: &Names, case: &Case) {
    let Case {
        current,
        desired,
        drift_sql,
    } = case;
    let (roles, schemas) = union_names(current, desired);
    let config = inspect_config(&roles, &schemas);

    // --- Bootstrap phase 1: roles and schemas of `current`. ---
    let skeleton = RoleGraph {
        roles: current.roles.clone(),
        schemas: current.schemas.clone(),
        ..RoleGraph::default()
    };
    let changes = diff(&RoleGraph::default(), &skeleton);
    execute_changes(pool, &changes, seed, "bootstrap:roles+schemas").await;

    // --- Backing objects: every concrete relation grant target in either
    // graph lives in a base schema, and all base schemas exist in `current`,
    // so creating the full table/sequence pools here covers both graphs.
    // (pgroles manages grants, not tables.) Objects are owned by the
    // superuser executor, never by generated roles.
    for schema in &names.base_schemas {
        for table in &names.tables {
            let sql = format!(
                "CREATE TABLE {}.{} (id integer);",
                quote_ident(schema),
                quote_ident(table)
            );
            execute_sql(pool, &sql, seed, "bootstrap:objects").await;
        }
        for sequence in &names.sequences {
            let sql = format!(
                "CREATE SEQUENCE {}.{};",
                quote_ident(schema),
                quote_ident(sequence)
            );
            execute_sql(pool, &sql, seed, "bootstrap:objects").await;
        }
    }

    // --- Bootstrap phase 2: grants, default privileges, memberships. ---
    let changes = diff(&skeleton, current);
    execute_changes(pool, &changes, seed, "bootstrap:bindings").await;

    // --- Live-only drift (owner schema-privilege revocations). ---
    for statement in drift_sql {
        execute_sql(pool, statement, seed, "drift").await;
    }

    // --- Inspect the real current state. ---
    let inspected_current = filter_prefix(
        &inspect(pool, &config)
            .await
            .unwrap_or_else(|error| panic!("seed {seed}: inspect(current) failed: {error}")),
        &names.prefix,
    );

    // --- Converge, predicting the outcome with the pure interpreter. ---
    let changes = diff(&inspected_current, desired);
    let predicted = apply_changes(&inspected_current, &changes);
    execute_changes(pool, &changes, seed, "converge").await;

    // --- Re-inspect: the live convergence oracle. ---
    let re_inspected = filter_prefix(
        &inspect(pool, &config)
            .await
            .unwrap_or_else(|error| panic!("seed {seed}: inspect(converged) failed: {error}")),
        &names.prefix,
    );

    // Property 1: live convergence — the database now IS the desired graph.
    if let Some(msg) = graph_mismatch(&re_inspected, desired) {
        panic!(
            "seed {seed}: live convergence violated.\n{msg}\n\n--- INSPECTED CURRENT ---\n{inspected_current:#?}\n--- CHANGES ---\n{changes:#?}"
        );
    }

    // password_valid_until is never generated; it must inspect as None
    // (asserted, not normalized).
    for (name, state) in &re_inspected.roles {
        assert!(
            state.password_valid_until.is_none(),
            "seed {seed}: role {name:?} unexpectedly has password_valid_until = {:?}",
            state.password_valid_until
        );
    }

    // Property 2: live idempotence — a re-plan against the converged
    // database is a no-op.
    let residual = diff(&re_inspected, desired);
    assert!(
        residual.is_empty(),
        "seed {seed}: not idempotent against live database, residual changes: {residual:#?}"
    );

    // Property 3: differential check — the pure interpreter's prediction of
    // the plan's effect must match what PostgreSQL actually did.
    if let Some(msg) = graph_mismatch(&predicted, &re_inspected) {
        panic!(
            "seed {seed}: interpreter diverges from PostgreSQL (got=interpreter prediction, want=live re-inspection).\n{msg}\n\n--- INSPECTED CURRENT ---\n{inspected_current:#?}\n--- CHANGES ---\n{changes:#?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The property test
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn live_convergence_matches_desired_and_interpreter() {
    let runtime = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    let pool = runtime
        .block_on(PgPool::connect(&database_url()))
        .expect("failed to connect to live test database");

    for seed in 0..seed_count() {
        let started = Instant::now();
        let names = Names::new(seed);
        let case = generate_case(seed, &names);
        let (roles, schemas) = union_names(&case.current, &case.desired);

        // Defensive pre-clean in case a previous run leaked this namespace.
        runtime.block_on(SeedCleanup::run(&pool, &roles, &schemas));

        // Guard runs even on panic; dropped in sync context so it may build
        // its own runtime.
        let cleanup = SeedCleanup { roles, schemas };
        runtime.block_on(run_seed(&pool, seed, &names, &case));
        drop(cleanup);

        eprintln!(
            "seed {seed}: converged and verified in {:?}",
            started.elapsed()
        );
    }
}

/// Targeted live regression for issue #140: a stale explicit schema grant to
/// the role that becomes the schema's owner in the same plan. Before the fix,
/// the plan's `REVOKE ... FROM z` landed after `ALTER SCHEMA ... OWNER TO z`
/// had merged z's ACL entry into the owner entry, stripping the new owner's
/// USAGE until the next reconcile. The plan must now converge in one pass and
/// leave the owner with USAGE on its own schema.
#[test]
#[ignore]
fn issue_140_owner_transfer_with_stale_owner_grant_converges_single_pass() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    let w = format!("i140_w_{nanos}");
    let z = format!("i140_z_{nanos}");
    let s = format!("i140_s_{nanos}");

    let mut desired = RoleGraph::default();
    desired.roles.insert(w.clone(), RoleState::default());
    desired.roles.insert(z.clone(), RoleState::default());
    desired.schemas.insert(
        s.clone(),
        SchemaState {
            owner: Some(z.clone()),
            owner_privileges: default_schema_owner_privileges(&z),
        },
    );

    let config = inspect_config(&[w.clone(), z.clone()], std::slice::from_ref(&s));

    let _cleanup = SeedCleanup {
        roles: vec![w.clone(), z.clone()],
        schemas: vec![s.clone()],
    };

    with_runtime(async {
        let pool = PgPool::connect(&database_url())
            .await
            .expect("failed to connect to live test database");

        // Bootstrap the exact issue-140 current state via raw SQL.
        for statement in [
            format!(r#"CREATE ROLE "{w}";"#),
            format!(r#"CREATE ROLE "{z}";"#),
            format!(r#"CREATE SCHEMA "{s}" AUTHORIZATION "{w}";"#),
            format!(r#"GRANT USAGE ON SCHEMA "{s}" TO "{z}";"#),
        ] {
            execute_sql(&pool, &statement, 140, "bootstrap").await;
        }

        let inspected = inspect(&pool, &config).await.expect("inspect failed");
        let changes = diff(&inspected, &desired);
        assert!(
            changes
                .iter()
                .any(|c| matches!(c, Change::AlterSchemaOwner { name, owner } if *name == s && *owner == z)),
            "plan must transfer ownership, got: {changes:?}"
        );
        execute_changes(&pool, &changes, 140, "converge").await;

        // The new owner must still hold USAGE on its own schema — the bug
        // stripped it here.
        let (has_usage,): (bool,) = sqlx::query_as("SELECT has_schema_privilege($1, $2, 'USAGE')")
            .bind(&z)
            .bind(&s)
            .fetch_one(&pool)
            .await
            .expect("failed to check schema privilege");
        assert!(
            has_usage,
            "issue #140 regression: new owner lost USAGE on its own schema"
        );

        // Single-pass convergence: the re-diff must be empty.
        let re_inspected = inspect(&pool, &config).await.expect("re-inspect failed");
        let residual = diff(&re_inspected, &desired);
        assert!(
            residual.is_empty(),
            "expected single-pass convergence, residual plan: {residual:?}"
        );
    });
}
