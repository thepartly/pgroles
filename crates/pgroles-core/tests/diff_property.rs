//! Property tests for the convergent diff engine (`pgroles_core::diff`).
//!
//! The diff engine's core contract is **convergence**: applying the change
//! list that `diff(current, desired)` produces to `current` should yield
//! exactly `desired`. These tests exercise that contract (plus self-diff
//! emptiness, idempotence, determinism, and additive-mode soundness) against a
//! large space of pseudo-random `RoleGraph` pairs.
//!
//! To make the properties checkable without a live database, the file carries
//! its own in-test *interpreter* — [`apply_changes`] — which gives the intended
//! pure-data semantics of every `Change` variant the engine emits. The
//! semantics were derived by reading `src/diff.rs` and `src/model.rs`, not
//! guessed; where the engine is deliberately asymmetric the generators are
//! shaped to stay inside the region where the contract is meant to hold (see
//! the notes below).
//!
//! **Scope**: this pure harness is the fast, every-push *logic* check — it can
//! catch engine bugs but not shared misconceptions, because the interpreter
//! and the engine were written from the same reading of PostgreSQL semantics
//! (e.g. the GUC list-value bug, where `SET search_path = 'a, b'` stored ONE
//! schema literally named `a, b`, was invisible to any model-based test). The
//! authoritative convergence oracle is the DB-backed property suite in
//! `pgroles-inspect/tests/diff_property_live.rs`, which replays generated
//! cases against a real PostgreSQL server and differentially validates this
//! interpreter's semantics (a synced copy of [`apply_changes`]) against the
//! re-inspected live state.
//!
//! Like `suggest_property.rs`, this uses a tiny seeded xorshift64* PRNG so the
//! tests are reproducible with no extra dependencies. Every failure prints the
//! `seed` value; re-run a single case by feeding that seed to `Rng::new` in the
//! failing test's loop body.
//!
//! ## Deliberate engine asymmetries the generators respect
//!
//! * **No `DropSchema`.** Schemas present in `current` but absent from
//!   `desired` are never dropped (there is no such `Change`). Convergence
//!   generators therefore keep `current.schemas ⊆ desired.schemas`.
//! * **Schema owner privileges are driven toward
//!   `default_schema_owner_privileges(owner)` (`{CREATE, USAGE}`), *not* toward
//!   `desired.owner_privileges`.** So a managed (owner=`Some`) schema whose
//!   owner privileges are a *superset* of `{CREATE, USAGE}` is not a fixed
//!   point — but the manifest can never express such a state (schemas only have
//!   CREATE/USAGE), so generated owner-privilege sets stay ⊆ `{CREATE, USAGE}`.
//! * **owner=`None` means "ensure existence only".** The engine never touches a
//!   schema's owner or owner privileges when the *desired* owner is `None`, so
//!   convergence uses owner=`Some` for all desired schemas. owner=`None` is
//!   still exercised in the self-diff/determinism tests.
//! * **Wildcard shadow filtering.** A desired `"*"` grant deliberately
//!   suppresses per-name revokes for the same `(role, schema, type)` (flap
//!   prevention), which is intentionally non-convergent. Generated grants use
//!   concrete object names (never `"*"`) so this path is out of scope here.

use std::collections::{BTreeMap, BTreeSet};

use pgroles_core::diff::{Change, ReconciliationMode, diff, filter_changes};
use pgroles_core::manifest::{ObjectType, Privilege};
use pgroles_core::model::{
    DefaultPrivKey, DefaultPrivState, DefaultPrivilegeScope, GrantKey, GrantState, Grantee,
    MembershipEdge, RoleAttribute, RoleGraph, RoleState, SchemaState,
    default_schema_owner_privileges,
};

// ---------------------------------------------------------------------------
// Tiny seeded PRNG (xorshift64*) — copied from suggest_property.rs.
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
// Generators
// ---------------------------------------------------------------------------

fn gen_priv_set(rng: &mut Rng) -> BTreeSet<Privilege> {
    use Privilege::*;
    // The diff engine treats privileges as opaque set elements and does not
    // validate them against the object type, so any non-empty subset works.
    let pool = [
        Select, Insert, Update, Delete, Truncate, References, Trigger, Execute, Usage, Create,
        Connect, Temporary,
    ];
    let n = rng.usize(4) + 1; // 1..=4, never empty
    let mut out = BTreeSet::new();
    for _ in 0..n {
        out.insert(pool[rng.usize(pool.len())]);
    }
    out
}

fn gen_config(rng: &mut Rng, messy: bool) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let n = if messy { rng.usize(4) } else { rng.usize(3) };
    for _ in 0..n {
        // Lowercase parameter names, matching what RoleState::from_definition
        // normalizes to. Values are compared as opaque strings by the diff.
        let (k, v): (String, String) = match rng.usize(5) {
            0 => ("role".into(), format!("r{}", rng.usize(5))),
            1 => (
                "search_path".into(),
                ["public", "app, public", "app"][rng.usize(3)].into(),
            ),
            2 => (
                "statement_timeout".into(),
                ["10s", "30s", "0"][rng.usize(3)].into(),
            ),
            3 => ("app.foo".into(), ["on", "off"][rng.usize(2)].into()),
            _ => ("app.bar".into(), format!("{}", rng.usize(100))),
        };
        m.insert(k, v);
    }
    m
}

fn gen_role_state(rng: &mut Rng, messy: bool) -> RoleState {
    RoleState {
        login: rng.bool(),
        superuser: messy && rng.usize(4) == 0,
        createdb: rng.bool(),
        createrole: messy && rng.bool(),
        inherit: rng.usize(4) != 0, // usually true (PG default)
        replication: messy && rng.usize(5) == 0,
        bypassrls: messy && rng.usize(5) == 0,
        connection_limit: if rng.usize(3) == 0 {
            rng.usize(20) as i32
        } else {
            -1
        },
        comment: if rng.bool() {
            Some(format!("comment-{}", rng.usize(5)))
        } else {
            None
        },
        password_valid_until: if messy && rng.usize(3) == 0 {
            Some(format!("20{}0-01-01T00:00:00Z", rng.usize(3) + 2))
        } else {
            None
        },
        config: gen_config(rng, messy),
    }
}

fn gen_schemas(rng: &mut Rng, allow_none: bool) -> BTreeMap<String, SchemaState> {
    let mut out = BTreeMap::new();
    let n = rng.usize(4); // 0..=3
    for i in 0..n {
        let name = format!("s{i}");
        let owner = if allow_none && rng.usize(4) == 0 {
            None
        } else {
            Some(format!("own{}", rng.usize(3)))
        };
        // Manifest-shaped: owner=Some ⇒ owner_privileges = {CREATE, USAGE};
        // owner=None ⇒ empty (matches RoleGraph::from_expanded).
        let owner_privileges = match &owner {
            Some(o) => default_schema_owner_privileges(o),
            None => BTreeSet::new(),
        };
        out.insert(
            name,
            SchemaState {
                owner,
                owner_privileges,
            },
        );
    }
    out
}

fn gen_grants(rng: &mut Rng, roles: &[String]) -> BTreeMap<GrantKey, GrantState> {
    let mut out = BTreeMap::new();
    if roles.is_empty() {
        return out;
    }
    let n = rng.usize(9); // 0..=8
    for _ in 0..n {
        let role = roles[rng.usize(roles.len())].clone();
        // Concrete object names only — never "*" (see wildcard note at top).
        let (object_type, schema, name) = match rng.usize(4) {
            0 => (ObjectType::Schema, None, Some(format!("s{}", rng.usize(3)))),
            1 => (
                ObjectType::Table,
                Some(format!("s{}", rng.usize(3))),
                Some(format!("t{}", rng.usize(3))),
            ),
            2 => (
                ObjectType::Sequence,
                Some(format!("s{}", rng.usize(3))),
                Some(format!("seq{}", rng.usize(3))),
            ),
            _ => (
                ObjectType::Function,
                Some(format!("s{}", rng.usize(3))),
                Some(format!("fn{}", rng.usize(3))),
            ),
        };
        out.insert(
            GrantKey {
                role: Grantee::Role(role),
                object_type,
                schema,
                name,
            },
            GrantState {
                privileges: gen_priv_set(rng),
            },
        );
    }
    out
}

fn gen_default_privs(
    rng: &mut Rng,
    roles: &[String],
) -> BTreeMap<DefaultPrivKey, DefaultPrivState> {
    let mut out = BTreeMap::new();
    if roles.is_empty() {
        return out;
    }
    let n = rng.usize(5); // 0..=4
    for _ in 0..n {
        let on_type = [
            ObjectType::Table,
            ObjectType::Sequence,
            ObjectType::Function,
        ][rng.usize(3)];
        out.insert(
            DefaultPrivKey {
                owner: format!("own{}", rng.usize(3)),
                scope: DefaultPrivilegeScope::Schema {
                    schema: format!("s{}", rng.usize(3)),
                },
                on_type,
                grantee: Grantee::Role(roles[rng.usize(roles.len())].clone()),
            },
            DefaultPrivState {
                privileges: gen_priv_set(rng),
            },
        );
    }
    out
}

fn gen_memberships(rng: &mut Rng, roles: &[String]) -> BTreeSet<MembershipEdge> {
    let mut out = BTreeSet::new();
    if roles.is_empty() {
        return out;
    }
    // Keep (role, member) unique — the diff keys memberships by that pair.
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let n = rng.usize(5); // 0..=4
    for _ in 0..n {
        let role = roles[rng.usize(roles.len())].clone();
        let member = if rng.bool() {
            roles[rng.usize(roles.len())].clone()
        } else {
            format!("user{}@example.com", rng.usize(4))
        };
        if role == member || !seen.insert((role.clone(), member.clone())) {
            continue;
        }
        out.insert(MembershipEdge {
            role,
            member,
            inherit: rng.bool(),
            admin: rng.bool(),
        });
    }
    out
}

/// Generate a `RoleGraph`. `allow_none` permits owner=`None` schemas; `messy`
/// widens the role-attribute variety. Every output is a *fixed point* of the
/// diff engine (self-diff is empty): owner=`Some` schemas always carry the
/// default owner privileges.
fn gen_graph(rng: &mut Rng, allow_none: bool, messy: bool) -> RoleGraph {
    let role_count = rng.usize(6); // 0..=5
    let mut roles = BTreeMap::new();
    for i in 0..role_count {
        roles.insert(format!("r{i}"), gen_role_state(rng, messy));
    }
    let role_names: Vec<String> = roles.keys().cloned().collect();
    RoleGraph {
        roles,
        schemas: gen_schemas(rng, allow_none),
        grants: gen_grants(rng, &role_names),
        inherent_grants: BTreeSet::new(),
        grant_absences: BTreeMap::new(),
        default_privileges: gen_default_privs(rng, &role_names),
        default_privilege_absences: BTreeMap::new(),
        memberships: gen_memberships(rng, &role_names),
    }
}

/// Strategy (b): start from a manifest-shaped `desired` graph and derive a
/// messy `current` that has drifted from it, in ways the diff engine can fully
/// reconcile. Keeps `current.schemas ⊆ desired.schemas` and schema owner
/// privileges ⊆ `{CREATE, USAGE}` (see asymmetry notes at the top).
fn derive_current(rng: &mut Rng, desired: &RoleGraph) -> RoleGraph {
    let mut c = desired.clone();

    // ----- Roles -----
    for name in desired.roles.keys().cloned().collect::<Vec<_>>() {
        match rng.usize(6) {
            0 => {
                c.roles.remove(&name); // desired will re-CREATE it
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
                    if rng.bool() {
                        st.password_valid_until = match &st.password_valid_until {
                            Some(_) => None,
                            None => Some("2099-01-01T00:00:00Z".to_string()),
                        };
                    }
                }
            }
            2 => {
                if let Some(st) = c.roles.get_mut(&name) {
                    // stray config entry desired lacks → RESET; changed value → SET.
                    st.config
                        .insert("app.stray".to_string(), format!("{}", rng.usize(9)));
                    if let Some(k) = st.config.keys().next().cloned()
                        && rng.bool()
                    {
                        st.config.insert(k, format!("changed{}", rng.usize(9)));
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
    // Stray roles absent from desired → DROP.
    for i in 0..rng.usize(3) {
        c.roles
            .insert(format!("stray{i}"), gen_role_state(rng, true));
    }

    // ----- Grants -----
    for k in c.grants.keys().cloned().collect::<Vec<_>>() {
        match rng.usize(4) {
            0 => {
                c.grants.remove(&k);
            }
            1 => {
                if let Some(gs) = c.grants.get_mut(&k) {
                    gs.privileges.insert(Privilege::Truncate); // maybe extra → REVOKE
                }
            }
            2 => {
                if let Some(gs) = c.grants.get_mut(&k)
                    && gs.privileges.len() > 1
                {
                    let p = *gs.privileges.iter().next().unwrap();
                    gs.privileges.remove(&p); // fewer → GRANT
                }
            }
            _ => {}
        }
    }
    // Stray grant targets absent from desired → REVOKE (then dropped).
    for _ in 0..rng.usize(3) {
        c.grants.insert(
            GrantKey {
                role: Grantee::Role(format!("r{}", rng.usize(6))),
                object_type: ObjectType::Table,
                schema: Some(format!("s{}", rng.usize(3))),
                name: Some(format!("stray{}", rng.usize(3))),
            },
            GrantState {
                privileges: [Privilege::Select].into_iter().collect(),
            },
        );
    }

    // ----- Default privileges -----
    for k in c.default_privileges.keys().cloned().collect::<Vec<_>>() {
        match rng.usize(4) {
            0 => {
                c.default_privileges.remove(&k);
            }
            1 => {
                if let Some(ds) = c.default_privileges.get_mut(&k) {
                    ds.privileges.insert(Privilege::Truncate);
                }
            }
            2 => {
                if let Some(ds) = c.default_privileges.get_mut(&k)
                    && ds.privileges.len() > 1
                {
                    let p = *ds.privileges.iter().next().unwrap();
                    ds.privileges.remove(&p);
                }
            }
            _ => {}
        }
    }
    for _ in 0..rng.usize(2) {
        c.default_privileges.insert(
            DefaultPrivKey {
                owner: format!("own{}", rng.usize(3)),
                scope: DefaultPrivilegeScope::Schema {
                    schema: format!("s{}", rng.usize(3)),
                },
                on_type: ObjectType::Table,
                grantee: Grantee::Role(format!("r{}", rng.usize(6))),
            },
            DefaultPrivState {
                privileges: [Privilege::Select].into_iter().collect(),
            },
        );
    }

    // ----- Memberships -----
    for e in c.memberships.iter().cloned().collect::<Vec<_>>() {
        match rng.usize(4) {
            0 => {
                c.memberships.remove(&e); // desired re-ADDs
            }
            1 => {
                // Flip a flag → diff emits REMOVE + ADD.
                c.memberships.remove(&e);
                c.memberships.insert(MembershipEdge {
                    inherit: !e.inherit,
                    ..e.clone()
                });
            }
            _ => {}
        }
    }
    // Stray memberships absent from desired → REMOVE. `stray@` members never
    // collide with desired members (which are `user@` or role names).
    for _ in 0..rng.usize(2) {
        c.memberships.insert(MembershipEdge {
            role: format!("r{}", rng.usize(6)),
            member: format!("stray{}@x.example", rng.usize(3)),
            inherit: rng.bool(),
            admin: rng.bool(),
        });
    }

    // ----- Schemas (never add one absent from desired) -----
    for name in c.schemas.keys().cloned().collect::<Vec<_>>() {
        match rng.usize(5) {
            0 => {
                c.schemas.remove(&name); // desired re-CREATEs
            }
            1 => {
                if let Some(ss) = c.schemas.get_mut(&name) {
                    ss.owner_privileges.clear(); // → EnsureSchemaOwnerPrivileges
                }
            }
            2 => {
                if let Some(ss) = c.schemas.get_mut(&name) {
                    ss.owner_privileges = [Privilege::Usage].into_iter().collect(); // partial
                }
            }
            3 => {
                if let Some(ss) = c.schemas.get_mut(&name) {
                    // Owner change; privileges stay ⊆ {CREATE, USAGE}.
                    ss.owner = Some(format!("drift{}", rng.usize(3)));
                }
            }
            _ => {}
        }
    }

    c
}

// ---------------------------------------------------------------------------
// Interpreter: intended pure-data semantics of each Change variant.
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

/// Apply a diff plan to a `RoleGraph`, returning the resulting graph. Panics on
/// any `Change` variant the diff engine is not supposed to emit, so the harness
/// surfaces unexpected output instead of silently accepting it.
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
            } => {
                // `REVOKE ... ON ALL ... IN SCHEMA` reaches every object of
                // that type in the schema, not one key.
                let affected: Vec<GrantKey> = if name.as_deref() == Some("*") {
                    g.grants
                        .keys()
                        .filter(|key| {
                            key.role == *role
                                && key.object_type == *object_type
                                && key.schema == *schema
                        })
                        .cloned()
                        .collect()
                } else {
                    vec![GrantKey {
                        role: role.clone(),
                        object_type: *object_type,
                        schema: schema.clone(),
                        name: name.clone(),
                    }]
                };

                for key in affected {
                    let now_empty = if let Some(entry) = g.grants.get_mut(&key) {
                        for p in privileges {
                            entry.privileges.remove(p);
                        }
                        entry.privileges.is_empty()
                    } else {
                        false
                    };
                    // An emptied grant is indistinguishable from "no grant" in
                    // the model (from_expanded only inserts non-empty entries).
                    if now_empty {
                        g.grants.remove(&key);
                    }
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
                // Memberships are keyed by (role, member) in the diff, so an add
                // replaces any existing edge for that pair.
                g.memberships
                    .retain(|e| !(e.role == *role && e.member == *member));
                g.memberships.insert(MembershipEdge {
                    role: role.clone(),
                    member: member.clone(),
                    inherit: *inherit,
                    admin: *admin,
                });
            }
            Change::RemoveMember { role, member } => {
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
// Comparison helper (RoleGraph does not derive PartialEq, but every field does)
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

const ITERATIONS: usize = 200;

// ---------------------------------------------------------------------------
// Property 1: self-diff is empty
// ---------------------------------------------------------------------------

#[test]
fn self_diff_is_empty() {
    let mut outer = Rng::new(0x5E1F_5E1F);
    for _ in 0..ITERATIONS {
        let seed = outer.next_u64();
        let mut rng = Rng::new(seed);

        let manifest_shaped = gen_graph(&mut rng, true, false);
        assert!(
            diff(&manifest_shaped, &manifest_shaped).is_empty(),
            "seed {seed} [manifest]: self-diff was non-empty: {:#?}",
            diff(&manifest_shaped, &manifest_shaped)
        );

        let messy = gen_graph(&mut rng, true, true);
        assert!(
            diff(&messy, &messy).is_empty(),
            "seed {seed} [messy]: self-diff was non-empty: {:#?}",
            diff(&messy, &messy)
        );
    }

    // An owner=None schema is a fixed point even with junk owner_privileges:
    // the engine never inspects owner privileges when the desired owner is None.
    let mut g = RoleGraph::default();
    g.schemas.insert(
        "s".to_string(),
        SchemaState {
            owner: None,
            owner_privileges: [Privilege::Select, Privilege::Usage].into_iter().collect(),
        },
    );
    assert!(diff(&g, &g).is_empty());
}

// ---------------------------------------------------------------------------
// Property 2 + 3: convergence and idempotence
// ---------------------------------------------------------------------------

fn check_convergence(current: &RoleGraph, desired: &RoleGraph, seed: u64, label: &str) {
    let changes = diff(current, desired);
    let converged = apply_changes(current, &changes);
    if let Some(msg) = graph_mismatch(&converged, desired) {
        panic!(
            "seed {seed} [{label}]: convergence violated.\n{msg}\n\n--- CURRENT ---\n{current:#?}\n--- CHANGES ---\n{changes:#?}"
        );
    }
    // Idempotence: once converged, re-diffing against desired is a no-op.
    let residual = diff(&converged, desired);
    assert!(
        residual.is_empty(),
        "seed {seed} [{label}]: not idempotent, residual changes: {residual:#?}"
    );
}

#[test]
fn convergence_and_idempotence() {
    let mut outer = Rng::new(0xC0FF_EE00);
    for _ in 0..ITERATIONS {
        let seed = outer.next_u64();
        let mut rng = Rng::new(seed);

        // Strategy (b): desired, then a drifted current derived from it.
        let desired = gen_graph(&mut rng, false, true);
        let current = derive_current(&mut rng, &desired);
        check_convergence(&current, &desired, seed, "derive");

        // Strategy (a): independent pair. Desired owns all schemas; current's
        // schemas are constrained to a subset of desired's (no DropSchema).
        let b = gen_graph(&mut rng, false, true);
        let mut a = gen_graph(&mut rng, true, true);
        a.schemas.retain(|k, _| b.schemas.contains_key(k));
        check_convergence(&a, &b, seed, "independent");
    }
}

// ---------------------------------------------------------------------------
// Property 4: determinism
// ---------------------------------------------------------------------------

#[test]
fn determinism() {
    let mut outer = Rng::new(0xD37E_2711);
    for _ in 0..ITERATIONS {
        let seed = outer.next_u64();
        let mut rng = Rng::new(seed);

        let desired = gen_graph(&mut rng, true, true);
        let current = derive_current(&mut rng, &desired);

        let first = diff(&current, &desired);
        let second = diff(&current, &desired);
        assert_eq!(
            first, second,
            "seed {seed}: diff was non-deterministic across two calls"
        );
    }
}

// ---------------------------------------------------------------------------
// Property 5: additive-mode soundness
// ---------------------------------------------------------------------------

#[test]
fn additive_mode_soundness() {
    let mut outer = Rng::new(0xADD1_71DE_u64);
    for _ in 0..ITERATIONS {
        let seed = outer.next_u64();
        let mut rng = Rng::new(seed);

        let desired = gen_graph(&mut rng, false, true);
        let current = derive_current(&mut rng, &desired);
        let filtered = filter_changes(diff(&current, &desired), ReconciliationMode::Additive);

        let created: BTreeSet<&str> = filtered
            .iter()
            .filter_map(|c| match c {
                Change::CreateRole { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();

        for change in &filtered {
            match change {
                Change::Revoke { .. }
                | Change::RevokeDefaultPrivilege { .. }
                | Change::RemoveMember { .. }
                | Change::DropRole { .. }
                | Change::AlterSchemaOwner { .. } => {
                    panic!("seed {seed}: additive mode retained destructive change: {change:?}");
                }
                Change::AlterRole { name, attributes } => {
                    assert!(
                        attributes
                            .iter()
                            .all(|a| matches!(a, RoleAttribute::SetConfig(..))),
                        "seed {seed}: additive AlterRole has non-SetConfig attribute: {change:?}"
                    );
                    assert!(
                        created.contains(name.as_str()),
                        "seed {seed}: additive AlterRole for a role without a CreateRole in the plan: {change:?}"
                    );
                }
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Property 6: absence assertions and the PUBLIC exemption
// ---------------------------------------------------------------------------
//
// The equality-based properties above cannot express these semantics: a
// converged graph legitimately keeps PUBLIC privileges no rule mentions, so it
// is not equal to `desired`. The invariants that do hold are checked directly.
//
// Objects are generated across several schemas and object types on purpose. A
// wildcard absence range-scans current grants by `(grantee, object_type,
// schema)` prefix, so a prefix mistake would revoke across a neighbouring
// schema or type and fail `unmanaged_public_survives` or `present_preserved`.

/// A deliberately tiny privilege alphabet. Absence assertions only bite where
/// the same privilege appears in several scopes, so a wide pool would make the
/// interesting collisions vanishingly rare and the range-scan prefix would go
/// untested.
fn gen_narrow_priv_set(rng: &mut Rng) -> BTreeSet<Privilege> {
    let pool = [Privilege::Select, Privilege::Execute];
    let mut out = BTreeSet::new();
    out.insert(pool[rng.usize(pool.len())]);
    if rng.usize(3) == 0 {
        out.insert(pool[rng.usize(pool.len())]);
    }
    out
}

/// Every object coordinate the absence generators draw from.
fn absence_universe() -> Vec<(ObjectType, Option<String>, String)> {
    let mut out = Vec::new();
    for schema in ["s0", "s1"] {
        for name in ["a", "b"] {
            out.push((
                ObjectType::Function,
                Some(schema.to_string()),
                format!("fn_{name}"),
            ));
            out.push((
                ObjectType::Table,
                Some(schema.to_string()),
                format!("t_{name}"),
            ));
        }
    }
    out
}

fn gen_absence_pair(rng: &mut Rng) -> (RoleGraph, RoleGraph) {
    let universe = absence_universe();
    let grantees = [
        Grantee::Public,
        Grantee::Role("r0".to_string()),
        Grantee::Role("r1".to_string()),
    ];

    // --- current: live ACLs, PUBLIC and roles alike ---
    let mut current = RoleGraph::default();
    for (object_type, schema, name) in &universe {
        for grantee in &grantees {
            if rng.usize(3) == 0 {
                continue;
            }
            current.grants.insert(
                GrantKey {
                    role: grantee.clone(),
                    object_type: *object_type,
                    schema: schema.clone(),
                    name: Some(name.clone()),
                },
                GrantState {
                    privileges: gen_narrow_priv_set(rng),
                },
            );
        }
    }

    // --- desired: present grants plus absence assertions ---
    let mut desired = RoleGraph::default();
    for (object_type, schema, name) in &universe {
        for grantee in &grantees {
            if rng.usize(4) != 0 {
                continue;
            }
            desired.grants.insert(
                GrantKey {
                    role: grantee.clone(),
                    object_type: *object_type,
                    schema: schema.clone(),
                    name: Some(name.clone()),
                },
                GrantState {
                    privileges: gen_narrow_priv_set(rng),
                },
            );
        }
    }

    // Absences, exact and wildcard. A real manifest can never assert the same
    // key+privilege both ways (validation rejects it), and a wildcard may not
    // disagree with a named selector in the same scope — mirror both so the
    // generated pair stays reachable from valid YAML.
    let absence_count = rng.usize(5);
    for _ in 0..absence_count {
        let grantee = grantees[rng.usize(grantees.len())].clone();
        let (object_type, schema, name) = &universe[rng.usize(universe.len())];
        let wildcard = rng.usize(2) == 0;
        let key = GrantKey {
            role: grantee.clone(),
            object_type: *object_type,
            schema: schema.clone(),
            name: Some(if wildcard {
                "*".to_string()
            } else {
                name.clone()
            }),
        };

        // Privileges already claimed present anywhere in this scope are off
        // limits for an absence assertion.
        let claimed: BTreeSet<Privilege> = desired
            .grants
            .iter()
            .filter(|(k, _)| {
                k.role == grantee && k.object_type == *object_type && k.schema == *schema
            })
            .flat_map(|(_, state)| state.privileges.iter().copied())
            .collect();
        let absent: BTreeSet<Privilege> = gen_narrow_priv_set(rng)
            .into_iter()
            .filter(|p| !claimed.contains(p))
            .collect();
        if absent.is_empty() {
            continue;
        }
        desired
            .grant_absences
            .entry(key)
            .or_default()
            .extend(absent);
    }

    // Default-privilege absences, in both scopes and for both PostgreSQL
    // object types that carry a built-in PUBLIC privilege.
    let dp_count = rng.usize(3);
    for _ in 0..dp_count {
        let grantee = grantees[rng.usize(grantees.len())].clone();
        let scope = if rng.usize(2) == 0 {
            DefaultPrivilegeScope::Global
        } else {
            DefaultPrivilegeScope::Schema {
                schema: format!("s{}", rng.usize(2)),
            }
        };
        let (on_type, privilege) = if rng.bool() {
            (ObjectType::Function, Privilege::Execute)
        } else {
            (ObjectType::Type, Privilege::Usage)
        };
        let key = DefaultPrivKey {
            owner: format!("r{}", rng.usize(2)),
            scope,
            on_type,
            grantee,
        };
        if desired.default_privileges.contains_key(&key) {
            continue;
        }
        let privileges = BTreeSet::from([privilege]);
        if rng.usize(2) == 0 {
            current.default_privileges.insert(
                key.clone(),
                DefaultPrivState {
                    privileges: BTreeSet::from([privilege]),
                },
            );
        }
        desired.default_privilege_absences.insert(key, privileges);
    }

    (current, desired)
}

#[test]
fn absence_assertions_converge_and_leave_unmanaged_public_alone() {
    let mut outer = Rng::new(0xAB5E_17CE);
    for _ in 0..ITERATIONS {
        let seed = outer.next_u64();
        let mut rng = Rng::new(seed);
        let (current, desired) = gen_absence_pair(&mut rng);

        let changes = diff(&current, &desired);
        let converged = apply_changes(&current, &changes);

        // 1. Every asserted absence holds afterwards.
        for (key, absent) in &desired.grant_absences {
            let held: BTreeSet<Privilege> = if key.name.as_deref() == Some("*") {
                converged
                    .grants
                    .iter()
                    .filter(|(k, _)| {
                        k.role == key.role
                            && k.object_type == key.object_type
                            && k.schema == key.schema
                    })
                    .flat_map(|(_, state)| state.privileges.iter().copied())
                    .collect()
            } else {
                converged
                    .grants
                    .get(key)
                    .map(|state| state.privileges.clone())
                    .unwrap_or_default()
            };
            let still_held: Vec<&Privilege> = absent.intersection(&held).collect();
            assert!(
                still_held.is_empty(),
                "seed {seed}: absence not satisfied for {key:?}: {still_held:?}\n\
                 --- CURRENT ---\n{current:#?}\n--- CHANGES ---\n{changes:#?}"
            );
        }
        for (key, absent) in &desired.default_privilege_absences {
            if let Some(state) = converged.default_privileges.get(key) {
                let still_held: Vec<&Privilege> = absent.intersection(&state.privileges).collect();
                assert!(
                    still_held.is_empty(),
                    "seed {seed}: default-privilege absence not satisfied for {key:?}: {still_held:?}"
                );
            }
        }

        // 2. Everything asserted present is present.
        for (key, want) in &desired.grants {
            let got = converged
                .grants
                .get(key)
                .map(|state| state.privileges.clone())
                .unwrap_or_default();
            let missing: Vec<&Privilege> = want.privileges.difference(&got).collect();
            assert!(
                missing.is_empty(),
                "seed {seed}: present grant not satisfied for {key:?}: missing {missing:?}"
            );
        }

        // 3. PUBLIC privileges no rule names survive. This is the property
        //    that keeps authoritative mode from stripping ACLs pgroles was
        //    never told about, and the one a bad range-scan prefix breaks.
        for (key, state) in &current.grants {
            if !key.role.is_public() {
                continue;
            }
            for privilege in &state.privileges {
                let named_absent = desired.grant_absences.iter().any(|(k, absent)| {
                    k.role == key.role
                        && k.object_type == key.object_type
                        && k.schema == key.schema
                        && (k.name == key.name || k.name.as_deref() == Some("*"))
                        && absent.contains(privilege)
                });
                if named_absent {
                    continue;
                }
                assert!(
                    converged
                        .grants
                        .get(key)
                        .is_some_and(|state| state.privileges.contains(privilege)),
                    "seed {seed}: unmanaged PUBLIC {privilege} on {key:?} was revoked\n\
                     --- CHANGES ---\n{changes:#?}"
                );
            }
        }

        // 4. Idempotence.
        let residual = diff(&converged, &desired);
        assert!(
            residual.is_empty(),
            "seed {seed}: not idempotent, residual: {residual:#?}\n\
             --- CURRENT ---\n{current:#?}\n--- CHANGES ---\n{changes:#?}"
        );
    }
}

#[test]
fn absence_assertions_are_ignored_in_additive_mode() {
    let mut outer = Rng::new(0xADD1_71FE);
    for _ in 0..ITERATIONS {
        let seed = outer.next_u64();
        let mut rng = Rng::new(seed);
        let (current, desired) = gen_absence_pair(&mut rng);

        let additive = pgroles_core::diff::filter_changes(
            diff(&current, &desired),
            pgroles_core::diff::ReconciliationMode::Additive,
        );
        let converged = apply_changes(&current, &additive);

        // Additive never revokes, so nothing loses a privilege it held.
        for (key, state) in &current.grants {
            let after = converged
                .grants
                .get(key)
                .map(|s| s.privileges.clone())
                .unwrap_or_default();
            let lost: Vec<&Privilege> = state.privileges.difference(&after).collect();
            assert!(
                lost.is_empty(),
                "seed {seed}: additive mode revoked {lost:?} from {key:?}"
            );
        }
    }
}
