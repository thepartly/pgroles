//! Property tests for the profile suggester.
//!
//! Generates pseudo-random flat manifests and verifies the contract:
//!
//!   For every input `M`, `expand(suggest(M).manifest)` produces the same
//!   `RoleGraph` as `expand(M)`, modulo auto-generated role comments.
//!
//! Uses a tiny xorshift64* PRNG so the tests are reproducible without
//! pulling in `rand` as a dev-dependency. Each test seed is printed in the
//! panic message so failing cases are easy to reproduce.

use pgroles_core::diff::{Change, diff};
use pgroles_core::manifest::{
    DefaultPrivilege, DefaultPrivilegeGrant, Ensure, Grant, ObjectTarget, ObjectType,
    PolicyManifest, Privilege, RoleDefinition, SchemaBinding, expand_manifest,
};
use pgroles_core::model::RoleGraph;
use pgroles_core::suggest::{
    SuggestOptions, expand_wildcard_grants, inventory_from_manifest_grants, suggest_profiles,
};

// ---------------------------------------------------------------------------
// Tiny seeded PRNG (xorshift64*). Plenty random for fuzz-style coverage and
// trivially deterministic.
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // xorshift64* misbehaves on seed 0.
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

const SEPARATORS: &[char] = &['-', '_'];
const TOKENS: &[&str] = &["rw", "ro", "app", "writer", "reader", "svc"];

fn rand_priv_set(rng: &mut Rng, on_type: ObjectType) -> Vec<Privilege> {
    use Privilege::*;
    let pool: Vec<Privilege> = match on_type {
        ObjectType::Table | ObjectType::View | ObjectType::MaterializedView => {
            vec![
                Select, Insert, Update, Delete, Truncate, References, Trigger,
            ]
        }
        ObjectType::Sequence => vec![Usage, Select, Update],
        ObjectType::Function => vec![Execute],
        ObjectType::Schema => vec![Usage, Create],
        ObjectType::Database => vec![Connect, Temporary, Create],
        ObjectType::Type => vec![Usage],
    };
    let n = rng.usize(pool.len()) + 1;
    let mut indices: Vec<usize> = (0..pool.len()).collect();
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let i = rng.usize(indices.len());
        out.push(pool[indices.remove(i)]);
    }
    out
}

fn random_manifest(rng: &mut Rng) -> PolicyManifest {
    let schema_count = rng.usize(4) + 2; // 2..=5
    let schemas: Vec<String> = (0..schema_count).map(|i| format!("s{i}")).collect();
    let owner = "the_owner".to_string();

    // 1..=3 "kinds" — each kind is a (sep, token, login, grant_templates,
    // dp_templates) triple. Two roles in the same kind across different
    // schemas should cluster.
    let kind_count = rng.usize(3) + 1;
    struct Kind {
        sep: char,
        token: String,
        login: bool,
        grant_templates: Vec<(ObjectType, Option<String>, Vec<Privilege>)>,
        dp_templates: Vec<(ObjectType, Vec<Privilege>)>,
    }
    let mut kinds: Vec<Kind> = Vec::new();
    for _ in 0..kind_count {
        let sep = SEPARATORS[rng.usize(SEPARATORS.len())];
        let token = TOKENS[rng.usize(TOKENS.len())].to_string();
        if kinds.iter().any(|k| k.sep == sep && k.token == token) {
            continue;
        }
        let login = rng.bool();
        let grant_count = rng.usize(4) + 1;
        let mut grant_templates = Vec::new();
        for _ in 0..grant_count {
            let ot = match rng.usize(5) {
                0 => ObjectType::Schema,
                1 => ObjectType::Table,
                2 => ObjectType::Sequence,
                3 => ObjectType::Function,
                _ => ObjectType::Table,
            };
            let name = match ot {
                ObjectType::Schema => None,
                _ => Some(if rng.bool() {
                    "*".to_string()
                } else {
                    format!("obj{}", rng.usize(100))
                }),
            };
            grant_templates.push((ot, name, rand_priv_set(rng, ot)));
        }
        let dp_count = rng.usize(2);
        let mut dp_templates = Vec::new();
        for _ in 0..dp_count {
            let ot = match rng.usize(3) {
                0 => ObjectType::Table,
                1 => ObjectType::Sequence,
                _ => ObjectType::Function,
            };
            dp_templates.push((ot, rand_priv_set(rng, ot)));
        }
        kinds.push(Kind {
            sep,
            token,
            login,
            grant_templates,
            dp_templates,
        });
    }

    let mut roles: Vec<RoleDefinition> = Vec::new();
    let mut grants: Vec<Grant> = Vec::new();
    let mut dp_groups: std::collections::BTreeMap<(String, String), Vec<DefaultPrivilegeGrant>> =
        std::collections::BTreeMap::new();

    for schema in &schemas {
        for kind in &kinds {
            // 25% chance to skip this kind for this schema, so clusters
            // sometimes have <schema_count members.
            if rng.usize(4) == 0 {
                continue;
            }
            let role_name = format!("{schema}{}{}", kind.sep, kind.token);
            // Avoid duplicate role names if two kinds collapse to the same
            // string.
            if roles.iter().any(|r| r.name == role_name) {
                continue;
            }
            // ~1 in 6 roles carries a config map so the fuzz corpus exercises
            // the suggester's config-disqualification path (config-carrying
            // roles must stay flat and keep their config through the
            // suggest → expand round trip).
            let config = if rng.usize(6) == 0 {
                [(
                    "app.tenant".to_string(),
                    pgroles_core::manifest::ConfigValue(format!("t_{role_name}")),
                )]
                .into_iter()
                .collect()
            } else {
                Default::default()
            };
            roles.push(RoleDefinition {
                name: role_name.clone(),
                external: false,
                preserve_undeclared_grants: false,
                login: if kind.login { Some(true) } else { None },
                superuser: None,
                createdb: None,
                createrole: None,
                inherit: None,
                replication: None,
                bypassrls: None,
                connection_limit: None,
                comment: None,
                password: None,
                password_valid_until: None,
                config,
            });
            for (ot, name, privs) in &kind.grant_templates {
                let object = match ot {
                    ObjectType::Schema => ObjectTarget {
                        object_type: ObjectType::Schema,
                        schema: None,
                        name: Some(schema.clone()),
                    },
                    _ => ObjectTarget {
                        object_type: *ot,
                        schema: Some(schema.clone()),
                        name: name.clone(),
                    },
                };
                grants.push(Grant {
                    role: role_name.clone(),
                    privileges: privs.clone(),
                    object,
                    ensure: Ensure::Present,
                });
            }
            for (ot, privs) in &kind.dp_templates {
                dp_groups
                    .entry((owner.clone(), schema.clone()))
                    .or_default()
                    .push(DefaultPrivilegeGrant {
                        role: Some(role_name.clone()),
                        privileges: privs.clone(),
                        on_type: *ot,
                        ensure: Ensure::Present,
                    });
            }
        }
    }

    let default_privileges: Vec<DefaultPrivilege> = dp_groups
        .into_iter()
        .map(|((owner, schema), grant)| DefaultPrivilege {
            owner: Some(owner),
            schema: Some(schema),
            scope: None,
            grant,
        })
        .collect();

    let schemas_yaml: Vec<SchemaBinding> = schemas
        .iter()
        .map(|s| SchemaBinding {
            name: s.clone(),
            profiles: vec![],
            role_pattern: "{schema}-{profile}".to_string(),
            owner: Some(owner.clone()),
        })
        .collect();

    PolicyManifest {
        default_owner: Some(owner),
        auth_providers: vec![],
        profiles: Default::default(),
        schemas: schemas_yaml,
        roles,
        grants,
        default_privileges,
        memberships: vec![],
        retirements: vec![],
    }
}

fn check_round_trip_invariant_with_opts(
    manifest: &PolicyManifest,
    seed: u64,
    opts: &SuggestOptions,
    label: &str,
) {
    let report = suggest_profiles(manifest, opts);

    // For wildcard-aware comparison the round-trip inventory must cover both
    // the manifest's existing grants AND any inventory the suggester used to
    // collapse — otherwise the candidate's freshly-emitted wildcards would
    // expand against fewer objects than the original's per-name grants.
    let mut inventory = inventory_from_manifest_grants(manifest);
    if let Some(full) = &opts.full_inventory {
        for (key, names) in full {
            inventory
                .entry(key.clone())
                .or_default()
                .extend(names.iter().cloned());
        }
    }

    let mut original_expanded = expand_manifest(manifest)
        .unwrap_or_else(|e| panic!("seed {seed} [{label}]: original expand failed: {e}"));
    expand_wildcard_grants(&mut original_expanded.grants, &inventory);
    let original_graph =
        RoleGraph::from_expanded(&original_expanded, manifest.default_owner.as_deref())
            .unwrap_or_else(|e| panic!("seed {seed} [{label}]: original graph failed: {e}"));

    let mut new_expanded = expand_manifest(&report.manifest)
        .unwrap_or_else(|e| panic!("seed {seed} [{label}]: candidate expand failed: {e}"));
    expand_wildcard_grants(&mut new_expanded.grants, &inventory);
    let new_graph =
        RoleGraph::from_expanded(&new_expanded, report.manifest.default_owner.as_deref())
            .unwrap_or_else(|e| panic!("seed {seed} [{label}]: candidate graph failed: {e}"));

    let changes = diff(&original_graph, &new_graph);
    let bad: Vec<_> = changes
        .iter()
        .filter(|c| !matches!(c, Change::SetComment { .. }))
        .collect();

    if !bad.is_empty() {
        let original_yaml = serde_yaml::to_string(manifest).unwrap();
        let candidate_yaml = serde_yaml::to_string(&report.manifest).unwrap();
        panic!(
            "seed {seed} [{label}]: round-trip violated.\n  bad changes ({}): {:#?}\n  round_trip_ok={}\n  profiles: {:?}\n\n--- ORIGINAL ---\n{}\n--- CANDIDATE ---\n{}",
            bad.len(),
            bad,
            report.round_trip_ok,
            report
                .profiles
                .iter()
                .map(|p| (&p.profile_name, &p.role_pattern, &p.schema_to_role))
                .collect::<Vec<_>>(),
            original_yaml,
            candidate_yaml,
        );
    }
}

fn check_round_trip_invariant(manifest: &PolicyManifest, seed: u64) {
    // Path 1: no full_inventory → no collapse path.
    check_round_trip_invariant_with_opts(
        manifest,
        seed,
        &SuggestOptions::default(),
        "no_inventory",
    );
    // Path 2: simulate full inventory by treating the manifest's grants as
    // exhaustive. This exercises the collapse path on the same input.
    let inv = inventory_from_manifest_grants(manifest);
    let opts_with_inv = SuggestOptions {
        full_inventory: Some(inv),
        ..Default::default()
    };
    check_round_trip_invariant_with_opts(manifest, seed, &opts_with_inv, "with_inventory");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn fixed_seeds_round_trip() {
    let seeds: &[u64] = &[
        0,
        1,
        7,
        42,
        100,
        1234,
        99999,
        0xdead_beef,
        0x00c0_ffee,
        0xfeed_face,
    ];
    for &seed in seeds {
        let mut rng = Rng::new(seed);
        let manifest = random_manifest(&mut rng);
        check_round_trip_invariant(&manifest, seed);
    }
}

#[test]
fn many_random_seeds_round_trip() {
    // 500 seeds — ~few seconds. The xorshift64* sequence covers a broad set of
    // shapes; combined with the 25% schema-drop rate we touch sole-schema,
    // pattern-conflict, and partial-cluster edges.
    let mut outer = Rng::new(0xa11ce);
    for _ in 0..500 {
        let seed = outer.next_u64();
        let mut rng = Rng::new(seed);
        let manifest = random_manifest(&mut rng);
        check_round_trip_invariant(&manifest, seed);
    }
}

#[test]
fn produces_at_least_some_profiles_on_uniform_input() {
    let mut found_any = false;
    let mut total_profiles = 0;
    for seed in 1..=50u64 {
        let mut rng = Rng::new(seed);
        let manifest = random_manifest(&mut rng);
        let report = suggest_profiles(&manifest, &SuggestOptions::default());
        if !report.profiles.is_empty() {
            found_any = true;
            total_profiles += report.profiles.len();
        }
    }
    assert!(
        found_any,
        "no profile suggested across 50 seeds (suspicious)"
    );
    assert!(
        total_profiles >= 5,
        "only {total_profiles} profile(s) suggested across 50 seeds — generator may be too random"
    );
}

#[test]
fn determinism_random_inputs() {
    // PolicyManifest.profiles is a BTreeMap, so the entire serialized YAML
    // is deterministic — two runs on the same input must produce
    // byte-identical output.
    for seed in [1u64, 2, 3, 100, 1234] {
        let mut rng1 = Rng::new(seed);
        let mut rng2 = Rng::new(seed);
        let m1 = random_manifest(&mut rng1);
        let m2 = random_manifest(&mut rng2);

        let r1 = suggest_profiles(&m1, &SuggestOptions::default());
        let r2 = suggest_profiles(&m2, &SuggestOptions::default());

        assert_eq!(
            serde_yaml::to_string(&r1.manifest).unwrap(),
            serde_yaml::to_string(&r2.manifest).unwrap(),
            "seed {seed}: suggester output non-deterministic"
        );
    }
}
