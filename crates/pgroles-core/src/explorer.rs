//! Pure plan analysis for untrusted, sanitized explorer snapshots.
//!
//! This module deliberately does not inspect PostgreSQL. Any fact that cannot
//! be established from the supplied snapshot is reported as unknown or as
//! requiring database preflight.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::authoring::prepare_policy;
use crate::bounds::{
    MAX_CONFIG_ENTRIES, MAX_DEFAULT_PRIVILEGES, MAX_GRANTS, MAX_MEMBERSHIPS, MAX_PRIVILEGES,
    MAX_ROLES, MAX_SCHEMAS,
};
use crate::diff::{Change, ReconciliationMode, plan_changes};
use crate::manifest::{ObjectType, Privilege};
use crate::model::{
    DefaultPrivKey, DefaultPrivState, DefaultPrivilegeScope, GrantKey, GrantState, Grantee,
    MembershipEdge, RoleAttribute, RoleGraph, RoleState, SchemaState,
};
use crate::visual::{VisualGraph, VisualSource, build_visual_graph};

pub const EXPLORER_SCHEMA_VERSION: &str = "pgroles.explorer.v1";
pub const MAX_EXPLORER_YAML_BYTES: usize = 1024 * 1024;
/// PostgreSQL major version whose authority rules apply when a request does
/// not name one.
pub const DEFAULT_PG_MAJOR_VERSION: u16 = 16;
/// Oldest PostgreSQL major version the explorer models.
pub const MIN_PG_MAJOR_VERSION: u16 = 12;
/// Newest PostgreSQL major version the explorer accepts.
pub const MAX_PG_MAJOR_VERSION: u16 = 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyzeRequest {
    pub schema_version: String,
    pub current: ExplorerSnapshot,
    pub desired_yaml: String,
    #[serde(
        default,
        serialize_with = "serialize_reconciliation_mode",
        deserialize_with = "deserialize_reconciliation_mode"
    )]
    pub mode: ReconciliationMode,
    pub executor: ExecutorFacts,
    /// PostgreSQL major version whose authority rules apply. `None` means
    /// [`DEFAULT_PG_MAJOR_VERSION`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pg_major_version: Option<u16>,
    /// Whether absence from the snapshot and executor facts proves absence in
    /// PostgreSQL. `None` means `true`; pass `false` for a partial snapshot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_graph_complete: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyzeResponse {
    pub schema_version: String,
    /// Effective PostgreSQL major version used for authority rules.
    pub pg_major_version: u16,
    /// Effective authority-graph completeness used for the analysis.
    pub authority_graph_complete: bool,
    pub changes: Vec<Change>,
    pub phases: Vec<PhaseAnalysis>,
    pub findings: Vec<AuthorityFinding>,
    pub visual: VisualGraph,
    pub plan_fingerprint: String,
    pub fingerprint_kind: FingerprintKind,
}

/// Phase simulation for a plan that has already been produced by a canonical
/// planner. This never computes or filters changes.
#[derive(Debug, Clone, Serialize)]
pub struct PlanAnalysis {
    pub phases: Vec<PhaseAnalysis>,
    pub findings: Vec<AuthorityFinding>,
    pub visual: VisualGraph,
}

#[derive(Debug, Clone, Copy)]
pub struct PlanAnalysisOptions {
    /// Whether absence from the supplied authority graph proves absence in
    /// PostgreSQL. `true` treats the graph as authoritative; scoped native
    /// inspection must use `false`.
    pub authority_graph_complete: bool,
    /// PostgreSQL major version whose membership-authority rules apply.
    /// Before 16, CREATEROLE authorizes membership changes on non-superuser
    /// roles; from 16, ADMIN OPTION is required.
    pub pg_major_version: u16,
}

impl Default for PlanAnalysisOptions {
    fn default() -> Self {
        Self {
            authority_graph_complete: true,
            pg_major_version: DEFAULT_PG_MAJOR_VERSION,
        }
    }
}

/// A password-free snapshot. Callers must sanitize arbitrary role config values.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplorerSnapshot {
    #[serde(default)]
    pub roles: BTreeMap<String, SnapshotRole>,
    #[serde(default)]
    pub schemas: BTreeMap<String, SnapshotSchema>,
    #[serde(default)]
    pub grants: Vec<SnapshotGrant>,
    #[serde(default)]
    pub default_privileges: Vec<SnapshotDefaultPrivilege>,
    #[serde(default)]
    pub memberships: Vec<SnapshotMembership>,
    /// Grant targets known to be intrinsic owner privileges.
    #[serde(default)]
    pub inherent_grants: Vec<SnapshotGrantTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRole {
    #[serde(default)]
    pub login: bool,
    #[serde(default)]
    pub superuser: bool,
    #[serde(default)]
    pub createdb: bool,
    #[serde(default)]
    pub createrole: bool,
    #[serde(default = "default_true")]
    pub inherit: bool,
    #[serde(default)]
    pub replication: bool,
    #[serde(default)]
    pub bypassrls: bool,
    #[serde(default = "default_connection_limit")]
    pub connection_limit: i32,
    #[serde(default)]
    pub comment: Option<String>,
    #[serde(default)]
    pub password_valid_until: Option<String>,
    #[serde(default)]
    pub config: BTreeMap<String, String>,
}

impl Default for SnapshotRole {
    fn default() -> Self {
        Self {
            login: false,
            superuser: false,
            createdb: false,
            createrole: false,
            inherit: true,
            replication: false,
            bypassrls: false,
            connection_limit: -1,
            comment: None,
            password_valid_until: None,
            config: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotSchema {
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub owner_privileges: BTreeSet<Privilege>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotGrant {
    pub role: String,
    pub object_type: ObjectType,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub privileges: BTreeSet<Privilege>,
    /// Live ACL privileges grouped by grantor, when inspection provides them.
    #[serde(default)]
    pub grantors: BTreeMap<String, BTreeSet<Privilege>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotGrantTarget {
    pub role: String,
    pub object_type: ObjectType,
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotDefaultPrivilege {
    pub owner: String,
    #[serde(default)]
    pub schema: Option<String>,
    pub on_type: ObjectType,
    pub grantee: String,
    #[serde(default)]
    pub privileges: BTreeSet<Privilege>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotMembership {
    pub role: String,
    pub member: String,
    #[serde(default = "default_true")]
    pub inherit: bool,
    #[serde(default)]
    pub admin: bool,
    /// Live edge grantors, when PostgreSQL 16+ inspection provides them.
    #[serde(default)]
    pub grantors: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetRoleCapability {
    Allowed,
    Denied,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorFacts {
    pub role: String,
    /// `true` wins over the snapshot; `false` defers to the snapshot's
    /// `superuser` attribute for the executor role.
    #[serde(default)]
    pub superuser: bool,
    /// Whether the executor holds CREATEROLE. `allowed` and `denied` win over
    /// the snapshot; `unknown` defers to the snapshot's `createrole`
    /// attribute for the executor role. Only consulted before PostgreSQL 16.
    #[serde(default)]
    pub createrole: SetRoleCapability,
    /// Authority facts may name executor roles outside the managed snapshot.
    #[serde(default)]
    pub memberships: Vec<ExecutorMembershipFact>,
    /// SET OPTION PostgreSQL will assign to newly granted memberships.
    #[serde(default)]
    pub new_membership_set_role: SetRoleCapability,
    /// Authority PostgreSQL grants the executor on roles created by this plan.
    #[serde(default)]
    pub new_role_set_role: SetRoleCapability,
    #[serde(default)]
    pub new_role_inherit: SetRoleCapability,
    #[serde(default)]
    pub new_role_admin_option: SetRoleCapability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutorMembershipFact {
    pub role: String,
    pub member: String,
    #[serde(default)]
    pub set_role: SetRoleCapability,
    /// Whether privileges flow through this edge (`INHERIT OPTION` / USAGE).
    #[serde(default)]
    pub inherit: SetRoleCapability,
    #[serde(default)]
    pub admin_option: SetRoleCapability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanPhase {
    Create,
    Alter,
    Grant,
    MembershipRemove,
    MembershipAdd,
    Revoke,
    DefaultPrivilegeRevoke,
    Retire,
}

#[derive(Debug, Clone, Serialize)]
pub struct PhaseAnalysis {
    pub phase: PlanPhase,
    pub changes: Vec<Change>,
    pub executor_reachability: Vec<RoleReachability>,
    pub executor_usage: Vec<RoleReachability>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoleReachability {
    pub role: String,
    pub status: ReachabilityStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachabilityStatus {
    Reachable,
    Unreachable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    RequiredRoleUnavailable,
    RequiredRoleReachabilityUnknown,
    ExecutorLosesAccess,
    MembershipDisconnectsRole,
    RoleBecomesReachable,
    DatabasePreflightRequired,
    /// Membership in a SUPERUSER role can only be granted or revoked by a
    /// superuser, in every PostgreSQL version.
    SuperuserRequired,
    /// A schema owner change makes the new owner the implicit grantor for
    /// privileges on that schema.
    OwnershipTransferChangesGrantor,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthorityFinding {
    pub kind: FindingKind,
    pub severity: FindingSeverity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<PlanPhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Every change an aggregated finding covers, in plan order. Only
    /// aggregated findings (database preflight) populate it; `change_index`
    /// then names the first of them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub change_indices: Vec<usize>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintKind {
    Illustrative,
}

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("unsupported explorer schema version: {0}")]
    UnsupportedSchemaVersion(String),
    #[error(transparent)]
    Manifest(#[from] crate::manifest::ManifestError),
    #[error("password sources are not accepted by the browser explorer")]
    PasswordSourceNotAllowed,
    #[error("explorer {collection} has {actual} entries, which exceeds the limit of {limit}")]
    TooManyEntries {
        collection: &'static str,
        actual: usize,
        limit: u32,
    },
    #[error("desired YAML has {actual} bytes, which exceeds the explorer limit of {limit}")]
    DesiredYamlTooLarge { actual: usize, limit: usize },
    #[error(
        "unsupported PostgreSQL major version {version}; the explorer models versions {min} through {max}"
    )]
    UnsupportedPgMajorVersion { version: u16, min: u16, max: u16 },
    #[error("could not serialize illustrative plan: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub fn analyze(request: AnalyzeRequest) -> Result<AnalyzeResponse, AnalysisError> {
    if request.schema_version != EXPLORER_SCHEMA_VERSION {
        return Err(AnalysisError::UnsupportedSchemaVersion(
            request.schema_version,
        ));
    }
    request.validate_bounds()?;
    let pg_major_version = request.effective_pg_major_version()?;
    let authority_graph_complete = request.authority_graph_complete.unwrap_or(true);
    let prepared = prepare_policy(&request.desired_yaml)?;
    if prepared
        .manifest
        .roles
        .iter()
        .any(|role| role.password.is_some())
    {
        return Err(AnalysisError::PasswordSourceNotAllowed);
    }
    let manifest = prepared.manifest;
    let expanded = prepared.expanded;
    let desired = prepared.desired;
    let graph = request.current.into_graph();
    let changes = plan_changes(&graph, &desired, &manifest, &expanded, request.mode);
    let analysis = analyze_changes_with_options(
        graph,
        &changes,
        &request.executor,
        PlanAnalysisOptions {
            authority_graph_complete,
            pg_major_version,
        },
    );
    let phases = analysis.phases;
    let findings = analysis.findings;
    let visual = analysis.visual;
    let fingerprint_bytes = serde_json::to_vec(&(
        EXPLORER_SCHEMA_VERSION,
        request.mode.to_string(),
        pg_major_version,
        authority_graph_complete,
        &request.executor,
        &changes,
        &phases,
        &findings,
    ))?;
    let plan_fingerprint = format!(
        "sha256:{}",
        hex_digest(Sha256::digest(fingerprint_bytes).as_slice())
    );
    Ok(AnalyzeResponse {
        schema_version: EXPLORER_SCHEMA_VERSION.into(),
        pg_major_version,
        authority_graph_complete,
        changes,
        phases,
        findings,
        visual,
        plan_fingerprint,
        fingerprint_kind: FingerprintKind::Illustrative,
    })
}

/// Analyze ordered changes against the inspected starting graph without
/// invoking the diff engine or changing reconciliation semantics.
pub fn analyze_changes(
    graph: RoleGraph,
    changes: &[Change],
    executor: &ExecutorFacts,
) -> PlanAnalysis {
    analyze_changes_with_options(graph, changes, executor, PlanAnalysisOptions::default())
}

pub fn analyze_changes_with_options(
    graph: RoleGraph,
    changes: &[Change],
    executor: &ExecutorFacts,
    options: PlanAnalysisOptions,
) -> PlanAnalysis {
    simulate(graph, changes, executor, options, Recompute::WhenAffected).0
}

/// Per-edge tri-state authority facts keyed by `(granted role, member)`.
type EdgeFacts = BTreeMap<(String, String), SetRoleCapability>;

/// When the simulation recomputes executor reachability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recompute {
    /// Only after changes that can alter reachability (see
    /// [`affects_reachability`]).
    WhenAffected,
    /// After every change; tests use it as the reference model.
    #[cfg(test)]
    Always,
}

/// Simulate the plan phase by phase. Returns the analysis and how many
/// reachability computations it performed.
fn simulate(
    mut graph: RoleGraph,
    changes: &[Change],
    executor: &ExecutorFacts,
    options: PlanAnalysisOptions,
    recompute: Recompute,
) -> (PlanAnalysis, usize) {
    let complete = options.authority_graph_complete;
    let (mut set_role, mut usage, mut admin_options) = initial_edge_facts(&graph, executor);
    let mut attributes = ExecutorAttributes::initial(&graph, executor);
    let mut computations = 2;
    let mut current_reachability = reachability(
        &graph,
        &set_role,
        &executor.role,
        attributes.superuser,
        complete,
    );
    let mut current_usage = reachability(
        &graph,
        &usage,
        &executor.role,
        attributes.superuser,
        complete,
    );
    let mut phases = Vec::new();
    let mut findings = Vec::new();
    let mut preflight = PreflightIndex::new();
    let mut global_change_index = 0;
    for (phase, phase_changes) in grouped_phases(changes) {
        let phase_usage_before = current_usage.clone();
        let mut dropped = BTreeSet::new();
        for change in &phase_changes {
            analyze_required_authority(
                change,
                phase,
                global_change_index,
                AuthorityState {
                    graph: &graph,
                    set_reachable: &current_reachability,
                    usage_reachable: &current_usage,
                    admin_options: &admin_options,
                    is_superuser: attributes.superuser,
                    createrole: attributes.createrole,
                    authority_graph_complete: complete,
                    pg_major_version: options.pg_major_version,
                },
                &mut findings,
                &mut preflight,
            );
            apply_change(
                &mut graph,
                &mut set_role,
                &mut usage,
                &mut admin_options,
                executor,
                change,
            );
            attributes.apply(change, executor);
            if let Change::DropRole { name } = change {
                dropped.insert(name.clone());
            }
            if recompute != Recompute::WhenAffected || affects_reachability(change) {
                current_reachability = reachability(
                    &graph,
                    &set_role,
                    &executor.role,
                    attributes.superuser,
                    complete,
                );
                current_usage = reachability(
                    &graph,
                    &usage,
                    &executor.role,
                    attributes.superuser,
                    complete,
                );
                computations += 2;
            }
            global_change_index += 1;
        }
        compare_reachability(
            phase,
            &phase_usage_before,
            &current_usage,
            &dropped,
            complete,
            &mut findings,
        );
        phases.push(PhaseAnalysis {
            phase,
            changes: phase_changes,
            executor_reachability: reachability_list(&current_reachability),
            executor_usage: reachability_list(&current_usage),
        });
    }
    finish_preflight_findings(&mut findings, &preflight);
    // `graph` is the simulated state after the mode-filtered plan. In additive
    // and adopt modes it can intentionally differ from raw desired state.
    (
        PlanAnalysis {
            phases,
            findings,
            visual: build_visual_graph(&graph, VisualSource::Desired),
        },
        computations,
    )
}

fn reachability_list(statuses: &BTreeMap<String, ReachabilityStatus>) -> Vec<RoleReachability> {
    statuses
        .iter()
        .map(|(role, status)| RoleReachability {
            role: role.clone(),
            status: *status,
        })
        .collect()
}

fn capability(value: bool) -> SetRoleCapability {
    if value {
        SetRoleCapability::Allowed
    } else {
        SetRoleCapability::Denied
    }
}

/// Record `value` for `key` unless it is `Unknown` and something is already
/// known: an explicit fact overrides snapshot evidence, but an omitted one
/// never erases it.
fn merge_fact(facts: &mut EdgeFacts, key: (String, String), value: SetRoleCapability) {
    if value == SetRoleCapability::Unknown {
        facts.entry(key).or_insert(SetRoleCapability::Unknown);
    } else {
        facts.insert(key, value);
    }
}

/// Build SET ROLE, INHERIT, and ADMIN facts from the snapshot, then layer
/// explicit executor facts over them.
fn initial_edge_facts(
    graph: &RoleGraph,
    executor: &ExecutorFacts,
) -> (EdgeFacts, EdgeFacts, EdgeFacts) {
    let mut set_role = EdgeFacts::new();
    let mut usage = EdgeFacts::new();
    let mut admin_options = EdgeFacts::new();
    for edge in &graph.memberships {
        let key = (edge.role.clone(), edge.member.clone());
        // Memberships imported without PG16 option facts are possible SET
        // paths, but never proven ones.
        set_role.insert(key.clone(), SetRoleCapability::Unknown);
        // Duplicate edges for one pair aggregate like inspection does: an
        // option applies if any edge carries it.
        let inherit = usage
            .entry(key.clone())
            .or_insert(SetRoleCapability::Denied);
        if edge.inherit {
            *inherit = SetRoleCapability::Allowed;
        }
        let admin = admin_options
            .entry(key)
            .or_insert(SetRoleCapability::Denied);
        if edge.admin {
            *admin = SetRoleCapability::Allowed;
        }
    }
    for fact in &executor.memberships {
        let key = (fact.role.clone(), fact.member.clone());
        merge_fact(&mut set_role, key.clone(), fact.set_role);
        merge_fact(&mut usage, key.clone(), fact.inherit);
        merge_fact(&mut admin_options, key, fact.admin_option);
    }
    (set_role, usage, admin_options)
}

/// Executor role attributes as they evolve through the plan.
#[derive(Debug, Clone, Copy)]
struct ExecutorAttributes {
    superuser: bool,
    createrole: SetRoleCapability,
}

impl ExecutorAttributes {
    /// Explicit executor facts win over the snapshot's attributes for the
    /// executor role; omitted ones defer to it.
    fn initial(graph: &RoleGraph, executor: &ExecutorFacts) -> Self {
        let snapshot = graph.roles.get(&executor.role);
        Self {
            superuser: executor.superuser || snapshot.is_some_and(|role| role.superuser),
            createrole: match executor.createrole {
                SetRoleCapability::Unknown => snapshot.map_or(SetRoleCapability::Unknown, |role| {
                    capability(role.createrole)
                }),
                explicit => explicit,
            },
        }
    }

    /// Apply the plan's own attribute changes to the executor role.
    fn apply(&mut self, change: &Change, executor: &ExecutorFacts) {
        if let Change::AlterRole { name, attributes } = change
            && *name == executor.role
        {
            for attribute in attributes {
                match attribute {
                    RoleAttribute::Superuser(value) => self.superuser = *value,
                    RoleAttribute::Createrole(value) => self.createrole = capability(*value),
                    _ => {}
                }
            }
        }
    }
}

/// Whether applying `change` can alter executor reachability. Reachability
/// depends only on the role set, membership facts, and the executor's
/// superuser attribute; grants, default privileges, ownership, comments,
/// passwords, and session termination leave all three unchanged. INHERIT
/// attribute changes are included conservatively.
fn affects_reachability(change: &Change) -> bool {
    match change {
        Change::CreateRole { .. }
        | Change::DropRole { .. }
        | Change::AddMember { .. }
        | Change::RemoveMember { .. } => true,
        Change::AlterRole { attributes, .. } => attributes.iter().any(|attribute| {
            matches!(
                attribute,
                RoleAttribute::Superuser(_) | RoleAttribute::Inherit(_)
            )
        }),
        Change::CreateSchema { .. }
        | Change::AlterSchemaOwner { .. }
        | Change::EnsureSchemaOwnerPrivileges { .. }
        | Change::SetComment { .. }
        | Change::Grant { .. }
        | Change::Revoke { .. }
        | Change::SetDefaultPrivilege { .. }
        | Change::RevokeDefaultPrivilege { .. }
        | Change::ReassignOwned { .. }
        | Change::DropOwned { .. }
        | Change::TerminateSessions { .. }
        | Change::SetPassword { .. } => false,
    }
}

impl AnalyzeRequest {
    fn effective_pg_major_version(&self) -> Result<u16, AnalysisError> {
        let version = self.pg_major_version.unwrap_or(DEFAULT_PG_MAJOR_VERSION);
        if !(MIN_PG_MAJOR_VERSION..=MAX_PG_MAJOR_VERSION).contains(&version) {
            return Err(AnalysisError::UnsupportedPgMajorVersion {
                version,
                min: MIN_PG_MAJOR_VERSION,
                max: MAX_PG_MAJOR_VERSION,
            });
        }
        Ok(version)
    }

    fn validate_bounds(&self) -> Result<(), AnalysisError> {
        fn entries(
            collection: &'static str,
            actual: usize,
            limit: u32,
        ) -> Result<(), AnalysisError> {
            if actual > limit as usize {
                return Err(AnalysisError::TooManyEntries {
                    collection,
                    actual,
                    limit,
                });
            }
            Ok(())
        }

        if self.desired_yaml.len() > MAX_EXPLORER_YAML_BYTES {
            return Err(AnalysisError::DesiredYamlTooLarge {
                actual: self.desired_yaml.len(),
                limit: MAX_EXPLORER_YAML_BYTES,
            });
        }
        entries("current.roles", self.current.roles.len(), MAX_ROLES)?;
        entries("current.schemas", self.current.schemas.len(), MAX_SCHEMAS)?;
        entries("current.grants", self.current.grants.len(), MAX_GRANTS)?;
        entries(
            "current.default_privileges",
            self.current.default_privileges.len(),
            MAX_DEFAULT_PRIVILEGES,
        )?;
        entries(
            "current.memberships",
            self.current.memberships.len(),
            MAX_MEMBERSHIPS,
        )?;
        entries(
            "current.inherent_grants",
            self.current.inherent_grants.len(),
            MAX_GRANTS,
        )?;
        entries(
            "executor.memberships",
            self.executor.memberships.len(),
            MAX_MEMBERSHIPS,
        )?;
        for role in self.current.roles.values() {
            entries(
                "current.roles[].config",
                role.config.len(),
                MAX_CONFIG_ENTRIES,
            )?;
        }
        for grant in &self.current.grants {
            entries(
                "current.grants[].privileges",
                grant.privileges.len(),
                MAX_PRIVILEGES,
            )?;
            entries("current.grants[].grantors", grant.grantors.len(), MAX_ROLES)?;
            for privileges in grant.grantors.values() {
                entries(
                    "current.grants[].grantors[].privileges",
                    privileges.len(),
                    MAX_PRIVILEGES,
                )?;
            }
        }
        entries(
            "current.grants[].grantors (total)",
            self.current
                .grants
                .iter()
                .map(|grant| grant.grantors.len())
                .sum(),
            MAX_GRANTS,
        )?;
        for default_privilege in &self.current.default_privileges {
            entries(
                "current.default_privileges[].privileges",
                default_privilege.privileges.len(),
                MAX_PRIVILEGES,
            )?;
        }
        entries(
            "current.memberships[].grantors (total)",
            self.current
                .memberships
                .iter()
                .map(|membership| membership.grantors.len())
                .sum(),
            MAX_MEMBERSHIPS,
        )?;
        Ok(())
    }
}

impl ExplorerSnapshot {
    fn into_graph(self) -> RoleGraph {
        let roles = self
            .roles
            .into_iter()
            .map(|(name, role)| {
                (
                    name,
                    RoleState {
                        login: role.login,
                        superuser: role.superuser,
                        createdb: role.createdb,
                        createrole: role.createrole,
                        inherit: role.inherit,
                        replication: role.replication,
                        bypassrls: role.bypassrls,
                        connection_limit: role.connection_limit,
                        comment: role.comment,
                        password_valid_until: role.password_valid_until,
                        config: role.config,
                    },
                )
            })
            .collect();
        let schemas = self
            .schemas
            .into_iter()
            .map(|(name, schema)| {
                (
                    name,
                    SchemaState {
                        owner: schema.owner,
                        owner_privileges: schema.owner_privileges,
                    },
                )
            })
            .collect();
        // Duplicate entries for one target merge the way inspection
        // aggregates live catalog rows: privileges and grantors union, and a
        // membership option applies if any entry carries it.
        let mut grant_entry_grantors: BTreeMap<GrantKey, BTreeMap<String, BTreeSet<Privilege>>> =
            BTreeMap::new();
        let mut grants: BTreeMap<GrantKey, GrantState> = BTreeMap::new();
        for grant in self.grants {
            let key = GrantKey {
                role: Grantee::parse(&grant.role),
                object_type: grant.object_type,
                schema: grant.schema,
                name: grant.name,
            };
            if !grant.grantors.is_empty() {
                let entry = grant_entry_grantors.entry(key.clone()).or_default();
                for (grantor, privileges) in grant.grantors {
                    entry.entry(grantor).or_default().extend(privileges);
                }
            }
            grants
                .entry(key)
                .or_insert_with(|| GrantState {
                    privileges: BTreeSet::new(),
                })
                .privileges
                .extend(grant.privileges);
        }
        let mut default_privileges: BTreeMap<DefaultPrivKey, DefaultPrivState> = BTreeMap::new();
        for item in self.default_privileges {
            default_privileges
                .entry(DefaultPrivKey {
                    owner: item.owner,
                    scope: item.schema.map_or(DefaultPrivilegeScope::Global, |schema| {
                        DefaultPrivilegeScope::Schema { schema }
                    }),
                    on_type: item.on_type,
                    grantee: Grantee::parse(&item.grantee),
                })
                .or_insert_with(|| DefaultPrivState {
                    privileges: BTreeSet::new(),
                })
                .privileges
                .extend(item.privileges);
        }
        let mut effective_memberships: BTreeMap<(String, String), MembershipEdge> = BTreeMap::new();
        let mut membership_edge_grantors: BTreeMap<(String, String), BTreeSet<String>> =
            BTreeMap::new();
        for item in self.memberships {
            let key = (item.role.clone(), item.member.clone());
            let edge = effective_memberships
                .entry(key.clone())
                .or_insert_with(|| MembershipEdge {
                    role: item.role,
                    member: item.member,
                    inherit: false,
                    admin: false,
                });
            edge.inherit |= item.inherit;
            edge.admin |= item.admin;
            if !item.grantors.is_empty() {
                membership_edge_grantors
                    .entry(key)
                    .or_default()
                    .extend(item.grantors);
            }
        }
        let memberships: BTreeSet<_> = effective_memberships.into_values().collect();
        let inherent_grants = self
            .inherent_grants
            .into_iter()
            .map(|grant| GrantKey {
                role: Grantee::parse(&grant.role),
                object_type: grant.object_type,
                schema: grant.schema,
                name: grant.name,
            })
            .collect();
        RoleGraph {
            roles,
            schemas,
            grants,
            default_privileges,
            memberships,
            inherent_grants,
            membership_edge_grantors,
            grant_entry_grantors,
            ..RoleGraph::default()
        }
    }
}

fn grouped_phases(changes: &[Change]) -> Vec<(PlanPhase, Vec<Change>)> {
    let mut result: Vec<(PlanPhase, Vec<Change>)> = Vec::new();
    for change in changes {
        let phase = phase_for(change);
        if let Some((last, items)) = result.last_mut()
            && *last == phase
        {
            items.push(change.clone());
        } else {
            result.push((phase, vec![change.clone()]));
        }
    }
    result
}

fn phase_for(change: &Change) -> PlanPhase {
    match change {
        Change::CreateRole { .. } | Change::CreateSchema { .. } => PlanPhase::Create,
        Change::AlterRole { .. }
        | Change::SetComment { .. }
        | Change::AlterSchemaOwner { .. }
        | Change::EnsureSchemaOwnerPrivileges { .. }
        | Change::SetPassword { .. } => PlanPhase::Alter,
        Change::Grant { .. } | Change::SetDefaultPrivilege { .. } => PlanPhase::Grant,
        Change::RemoveMember { .. } => PlanPhase::MembershipRemove,
        Change::AddMember { .. } => PlanPhase::MembershipAdd,
        Change::Revoke { .. } => PlanPhase::Revoke,
        Change::RevokeDefaultPrivilege { .. } => PlanPhase::DefaultPrivilegeRevoke,
        Change::ReassignOwned { .. }
        | Change::DropOwned { .. }
        | Change::TerminateSessions { .. }
        | Change::DropRole { .. } => PlanPhase::Retire,
    }
}

fn reachability(
    graph: &RoleGraph,
    facts: &EdgeFacts,
    executor_role: &str,
    executor_superuser: bool,
    authority_graph_complete: bool,
) -> BTreeMap<String, ReachabilityStatus> {
    let mut all_roles: BTreeSet<&str> = graph.roles.keys().map(String::as_str).collect();
    all_roles.insert(executor_role);
    // Index edges by member once so each traversal is linear in the facts.
    let mut granted_to: BTreeMap<&str, Vec<(&str, SetRoleCapability)>> = BTreeMap::new();
    for ((role, member), capability) in facts {
        all_roles.insert(role);
        all_roles.insert(member);
        granted_to
            .entry(member.as_str())
            .or_default()
            .push((role.as_str(), *capability));
    }
    if executor_superuser {
        return all_roles
            .into_iter()
            .map(|role| (role.to_owned(), ReachabilityStatus::Reachable))
            .collect();
    }
    let traverse = |follow: fn(SetRoleCapability) -> bool| {
        let mut seen = BTreeSet::from([executor_role]);
        let mut queue = VecDeque::from([executor_role]);
        while let Some(member) = queue.pop_front() {
            for (role, capability) in granted_to.get(member).into_iter().flatten() {
                if follow(*capability) && seen.insert(role) {
                    queue.push_back(role);
                }
            }
        }
        seen
    };
    let definite = traverse(|capability| capability == SetRoleCapability::Allowed);
    let possible = traverse(|capability| capability != SetRoleCapability::Denied);
    all_roles
        .into_iter()
        .map(|role| {
            (
                role.to_owned(),
                if definite.contains(role) {
                    ReachabilityStatus::Reachable
                } else if possible.contains(role) || !authority_graph_complete {
                    ReachabilityStatus::Unknown
                } else {
                    ReachabilityStatus::Unreachable
                },
            )
        })
        .collect()
}

fn compare_reachability(
    phase: PlanPhase,
    before: &BTreeMap<String, ReachabilityStatus>,
    after: &BTreeMap<String, ReachabilityStatus>,
    dropped: &BTreeSet<String>,
    authority_graph_complete: bool,
    findings: &mut Vec<AuthorityFinding>,
) {
    // A role missing from a map has no recorded path at all; that disproves
    // a path only when the authority graph is complete.
    let unseen = if authority_graph_complete {
        ReachabilityStatus::Unreachable
    } else {
        ReachabilityStatus::Unknown
    };
    let roles: BTreeSet<_> = before.keys().chain(after.keys()).cloned().collect();
    for role in roles {
        // Dropping a role is not a loss of access to it.
        if dropped.contains(&role) && !after.contains_key(&role) {
            continue;
        }
        let after_status = after.get(&role).copied().unwrap_or(unseen);
        let before_status = before.get(&role).copied().unwrap_or(unseen);
        let (kind, severity, verb) = match (before_status, after_status) {
            (
                ReachabilityStatus::Reachable,
                ReachabilityStatus::Unreachable | ReachabilityStatus::Unknown,
            ) => (
                FindingKind::ExecutorLosesAccess,
                FindingSeverity::Warning,
                "loses proven access to",
            ),
            (ReachabilityStatus::Unknown, ReachabilityStatus::Unreachable) => (
                FindingKind::MembershipDisconnectsRole,
                FindingSeverity::Warning,
                "can no longer reach",
            ),
            (
                ReachabilityStatus::Unreachable | ReachabilityStatus::Unknown,
                ReachabilityStatus::Reachable,
            ) => (
                FindingKind::RoleBecomesReachable,
                FindingSeverity::Info,
                "can now reach",
            ),
            _ => continue,
        };
        findings.push(AuthorityFinding {
            kind,
            severity,
            message: format!("executor {verb} role {role}"),
            phase: Some(phase),
            change_index: None,
            role: Some(role),
            change_indices: Vec::new(),
        });
    }
}

struct AuthorityState<'a> {
    graph: &'a RoleGraph,
    set_reachable: &'a BTreeMap<String, ReachabilityStatus>,
    usage_reachable: &'a BTreeMap<String, ReachabilityStatus>,
    admin_options: &'a EdgeFacts,
    is_superuser: bool,
    createrole: SetRoleCapability,
    authority_graph_complete: bool,
    pg_major_version: u16,
}

impl AuthorityState<'_> {
    /// Status for a role with no recorded path.
    fn unseen(&self) -> ReachabilityStatus {
        if self.authority_graph_complete {
            ReachabilityStatus::Unreachable
        } else {
            ReachabilityStatus::Unknown
        }
    }

    /// Whether the executor holds ADMIN OPTION on `role`, directly or through
    /// a role whose privileges it inherits.
    fn admin_option(&self, role: &str) -> ReachabilityStatus {
        self.admin_options
            .range((role.to_owned(), String::new())..)
            .take_while(|((granted_role, _), _)| granted_role == role)
            .map(|((_, member), admin)| {
                (
                    self.usage_reachable
                        .get(member)
                        .copied()
                        .unwrap_or(self.unseen()),
                    *admin,
                )
            })
            .fold(self.unseen(), |best, (member, admin)| {
                match (member, admin) {
                    (ReachabilityStatus::Reachable, SetRoleCapability::Allowed) => {
                        ReachabilityStatus::Reachable
                    }
                    (
                        ReachabilityStatus::Reachable | ReachabilityStatus::Unknown,
                        SetRoleCapability::Unknown | SetRoleCapability::Allowed,
                    ) if best != ReachabilityStatus::Reachable => ReachabilityStatus::Unknown,
                    _ => best,
                }
            })
    }

    /// Authority to grant or revoke membership in a non-superuser role.
    /// Before PostgreSQL 16, CREATEROLE suffices; from 16, only ADMIN OPTION
    /// does.
    fn membership_authority(&self, role: &str) -> ReachabilityStatus {
        let admin = self.admin_option(role);
        if self.pg_major_version >= 16 {
            return admin;
        }
        match self.createrole {
            SetRoleCapability::Allowed => ReachabilityStatus::Reachable,
            SetRoleCapability::Unknown if admin != ReachabilityStatus::Reachable => {
                ReachabilityStatus::Unknown
            }
            _ => admin,
        }
    }
}

fn authority_finding(
    kind: FindingKind,
    severity: FindingSeverity,
    message: String,
    phase: PlanPhase,
    index: usize,
    role: Option<String>,
) -> AuthorityFinding {
    AuthorityFinding {
        kind,
        severity,
        message,
        phase: Some(phase),
        change_index: Some(index),
        role,
        change_indices: Vec::new(),
    }
}

/// Aggregated preflight findings keyed by `(phase, change kind)`, pointing at
/// their position in the findings list.
type PreflightIndex = BTreeMap<(PlanPhase, &'static str), usize>;

fn analyze_required_authority(
    change: &Change,
    phase: PlanPhase,
    index: usize,
    authority: AuthorityState<'_>,
    findings: &mut Vec<AuthorityFinding>,
    preflight: &mut PreflightIndex,
) {
    let required = match change {
        Change::SetDefaultPrivilege { owner, .. }
        | Change::RevokeDefaultPrivilege { owner, .. } => {
            Some((owner, authority.usage_reachable, "USAGE"))
        }
        Change::Revoke {
            grantor: Some(grantor),
            ..
        } => Some((grantor, authority.set_reachable, "SET ROLE")),
        Change::RemoveMember {
            grantor: Some(grantor),
            ..
        } => Some((grantor, authority.usage_reachable, "USAGE")),
        _ => None,
    };
    if !authority.is_superuser
        && let Some((role, reachability, authority_name)) = required
    {
        let status = reachability
            .get(role)
            .copied()
            .unwrap_or(authority.unseen());
        if status != ReachabilityStatus::Reachable {
            let (kind, severity, qualifier) = if status == ReachabilityStatus::Unknown {
                (
                    FindingKind::RequiredRoleReachabilityUnknown,
                    FindingSeverity::Warning,
                    "is not proven",
                )
            } else {
                (
                    FindingKind::RequiredRoleUnavailable,
                    FindingSeverity::Error,
                    "is unavailable",
                )
            };
            findings.push(authority_finding(
                kind,
                severity,
                format!(
                    "required {authority_name} authority for grantor or owner role {role} {qualifier} for this operation"
                ),
                phase,
                index,
                Some(role.clone()),
            ));
        }
    }
    if !authority.is_superuser
        && let Change::AddMember { role, .. } | Change::RemoveMember { role, .. } = change
        && authority
            .graph
            .roles
            .get(role)
            .is_some_and(|state| state.superuser)
    {
        findings.push(authority_finding(
            FindingKind::SuperuserRequired,
            FindingSeverity::Error,
            format!(
                "membership in superuser role {role} can only be granted or revoked by a superuser executor"
            ),
            phase,
            index,
            Some(role.clone()),
        ));
    } else if !authority.is_superuser
        && let Change::AddMember { role, .. }
        | Change::RemoveMember {
            role,
            grantor: None,
            ..
        } = change
    {
        let required = if authority.pg_major_version >= 16 {
            "ADMIN OPTION"
        } else {
            "CREATEROLE or ADMIN OPTION"
        };
        match authority.membership_authority(role) {
            ReachabilityStatus::Reachable => {}
            ReachabilityStatus::Unknown => findings.push(authority_finding(
                FindingKind::RequiredRoleReachabilityUnknown,
                FindingSeverity::Warning,
                format!(
                    "{required} for role {role} is not proven; database preflight is required"
                ),
                phase,
                index,
                Some(role.clone()),
            )),
            ReachabilityStatus::Unreachable => findings.push(authority_finding(
                FindingKind::RequiredRoleUnavailable,
                FindingSeverity::Error,
                if authority.pg_major_version >= 16 {
                    format!(
                        "ADMIN OPTION for role {role} is unavailable; PostgreSQL 16 and later require it to change membership, and CREATEROLE alone is not sufficient"
                    )
                } else {
                    format!("CREATEROLE or ADMIN OPTION for role {role} is unavailable")
                },
                phase,
                index,
                Some(role.clone()),
            )),
        }
    }
    if let Change::AlterSchemaOwner { name, owner } = change {
        let previous = authority
            .graph
            .schemas
            .get(name)
            .and_then(|schema| schema.owner.as_deref());
        let from = previous.map_or_else(
            || "an owner outside the snapshot".to_string(),
            |previous| format!("role {previous}"),
        );
        findings.push(authority_finding(
            FindingKind::OwnershipTransferChangesGrantor,
            FindingSeverity::Info,
            format!(
                "schema {name} ownership moves from {from} to role {owner}; {owner} becomes the implicit grantor for privileges on schema {name}, including entries {} granted",
                previous.unwrap_or("the previous owner")
            ),
            phase,
            index,
            Some(owner.clone()),
        ));
    }
    if matches!(
        change,
        Change::Grant { .. }
            | Change::Revoke { .. }
            | Change::CreateRole { .. }
            | Change::CreateSchema { .. }
            | Change::AlterRole { .. }
            | Change::SetComment { .. }
            | Change::SetPassword { .. }
            | Change::AlterSchemaOwner { .. }
            | Change::EnsureSchemaOwnerPrivileges { .. }
            | Change::ReassignOwned { .. }
            | Change::DropOwned { .. }
            | Change::TerminateSessions { .. }
            | Change::DropRole { .. }
    ) {
        let key = (phase, change_kind(change));
        if let Some(&position) = preflight.get(&key) {
            findings[position].change_indices.push(index);
        } else {
            preflight.insert(key, findings.len());
            findings.push(AuthorityFinding {
                change_indices: vec![index],
                ..authority_finding(
                    FindingKind::DatabasePreflightRequired,
                    FindingSeverity::Warning,
                    String::new(),
                    phase,
                    index,
                    None,
                )
            });
        }
    }
}

/// Word the aggregated preflight findings once every change is counted.
fn finish_preflight_findings(findings: &mut [AuthorityFinding], preflight: &PreflightIndex) {
    for (&(_, kind), &position) in preflight {
        let finding = &mut findings[position];
        finding.message = match finding.change_indices.len() {
            1 => {
                format!("this {kind} operation requires database ownership or privilege preflight")
            }
            count => {
                format!(
                    "{count} {kind} operations require database ownership or privilege preflight"
                )
            }
        };
    }
}

/// The change's variant name, as it appears in serialized plans.
fn change_kind(change: &Change) -> &'static str {
    match change {
        Change::CreateRole { .. } => "CreateRole",
        Change::CreateSchema { .. } => "CreateSchema",
        Change::AlterSchemaOwner { .. } => "AlterSchemaOwner",
        Change::EnsureSchemaOwnerPrivileges { .. } => "EnsureSchemaOwnerPrivileges",
        Change::AlterRole { .. } => "AlterRole",
        Change::SetComment { .. } => "SetComment",
        Change::Grant { .. } => "Grant",
        Change::Revoke { .. } => "Revoke",
        Change::SetDefaultPrivilege { .. } => "SetDefaultPrivilege",
        Change::RevokeDefaultPrivilege { .. } => "RevokeDefaultPrivilege",
        Change::AddMember { .. } => "AddMember",
        Change::RemoveMember { .. } => "RemoveMember",
        Change::ReassignOwned { .. } => "ReassignOwned",
        Change::DropOwned { .. } => "DropOwned",
        Change::TerminateSessions { .. } => "TerminateSessions",
        Change::DropRole { .. } => "DropRole",
        Change::SetPassword { .. } => "SetPassword",
    }
}

fn apply_change(
    graph: &mut RoleGraph,
    set_role: &mut BTreeMap<(String, String), SetRoleCapability>,
    usage: &mut BTreeMap<(String, String), SetRoleCapability>,
    admin_options: &mut BTreeMap<(String, String), SetRoleCapability>,
    executor: &ExecutorFacts,
    change: &Change,
) {
    match change {
        Change::CreateRole { name, state } => {
            graph.roles.insert(name.clone(), state.clone());
            if name != &executor.role {
                let key = (name.clone(), executor.role.clone());
                set_role.insert(key.clone(), executor.new_role_set_role);
                usage.insert(key.clone(), executor.new_role_inherit);
                admin_options.insert(key, executor.new_role_admin_option);
            }
        }
        Change::CreateSchema { name, owner } => {
            graph.schemas.insert(
                name.clone(),
                SchemaState {
                    owner: owner.clone(),
                    owner_privileges: BTreeSet::new(),
                },
            );
        }
        Change::AlterSchemaOwner { name, owner } => {
            if let Some(schema) = graph.schemas.get_mut(name) {
                schema.owner = Some(owner.clone());
            }
        }
        Change::EnsureSchemaOwnerPrivileges {
            name, privileges, ..
        } => {
            if let Some(schema) = graph.schemas.get_mut(name) {
                schema.owner_privileges.extend(privileges);
            }
        }
        Change::AlterRole { name, attributes } => {
            if let Some(role) = graph.roles.get_mut(name) {
                for attribute in attributes {
                    use crate::model::RoleAttribute::*;
                    match attribute {
                        Login(v) => role.login = *v,
                        Superuser(v) => role.superuser = *v,
                        Createdb(v) => role.createdb = *v,
                        Createrole(v) => role.createrole = *v,
                        Inherit(v) => role.inherit = *v,
                        Replication(v) => role.replication = *v,
                        Bypassrls(v) => role.bypassrls = *v,
                        ConnectionLimit(v) => role.connection_limit = *v,
                        ValidUntil(v) => role.password_valid_until = v.clone(),
                        SetConfig(name, value) => {
                            role.config.insert(name.clone(), value.clone());
                        }
                        ResetConfig(name) => {
                            role.config.remove(name);
                        }
                    }
                }
            }
        }
        Change::SetComment { name, comment } => {
            if let Some(role) = graph.roles.get_mut(name) {
                role.comment = comment.clone();
            }
        }
        Change::Grant {
            role,
            privileges,
            object_type,
            schema,
            name,
        } => {
            graph
                .grants
                .entry(GrantKey {
                    role: role.clone(),
                    object_type: *object_type,
                    schema: schema.clone(),
                    name: name.clone(),
                })
                .or_insert_with(|| GrantState {
                    privileges: BTreeSet::new(),
                })
                .privileges
                .extend(privileges);
        }
        Change::Revoke {
            role,
            privileges,
            object_type,
            schema,
            name,
            grantor,
        } => {
            let key = GrantKey {
                role: role.clone(),
                object_type: *object_type,
                schema: schema.clone(),
                name: name.clone(),
            };
            let remaining_attributed = grantor.as_ref().and_then(|grantor| {
                graph.grant_entry_grantors.get_mut(&key).map(|entries| {
                    if let Some(granted) = entries.get_mut(grantor) {
                        granted.retain(|privilege| !privileges.contains(privilege));
                        if granted.is_empty() {
                            entries.remove(grantor);
                        }
                    }
                    entries
                        .values()
                        .flat_map(|privileges| privileges.iter().copied())
                        .collect::<BTreeSet<_>>()
                })
            });
            if let Some(state) = graph.grants.get_mut(&key) {
                if let Some(remaining) = remaining_attributed {
                    if remaining.is_empty() {
                        state.privileges.retain(|p| !privileges.contains(p));
                    } else {
                        state.privileges = remaining;
                    }
                } else {
                    state.privileges.retain(|p| !privileges.contains(p));
                }
                if state.privileges.is_empty() {
                    graph.grants.remove(&key);
                }
            }
            if graph
                .grant_entry_grantors
                .get(&key)
                .is_some_and(BTreeMap::is_empty)
            {
                graph.grant_entry_grantors.remove(&key);
            }
        }
        Change::SetDefaultPrivilege {
            owner,
            scope,
            on_type,
            grantee,
            privileges,
        } => {
            graph
                .default_privileges
                .entry(DefaultPrivKey {
                    owner: owner.clone(),
                    scope: scope.clone(),
                    on_type: *on_type,
                    grantee: grantee.clone(),
                })
                .or_insert_with(|| DefaultPrivState {
                    privileges: BTreeSet::new(),
                })
                .privileges
                .extend(privileges);
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
            if let Some(state) = graph.default_privileges.get_mut(&key) {
                state.privileges.retain(|p| !privileges.contains(p));
                if state.privileges.is_empty() {
                    graph.default_privileges.remove(&key);
                }
            }
        }
        Change::AddMember {
            role,
            member,
            inherit,
            admin,
        } => {
            graph.memberships.insert(MembershipEdge {
                role: role.clone(),
                member: member.clone(),
                inherit: *inherit,
                admin: *admin,
            });
            set_role.insert(
                (role.clone(), member.clone()),
                executor.new_membership_set_role,
            );
            usage.insert(
                (role.clone(), member.clone()),
                if *inherit {
                    SetRoleCapability::Allowed
                } else {
                    SetRoleCapability::Denied
                },
            );
            admin_options.insert(
                (role.clone(), member.clone()),
                if *admin {
                    SetRoleCapability::Allowed
                } else {
                    SetRoleCapability::Denied
                },
            );
        }
        Change::RemoveMember {
            role,
            member,
            grantor,
        } => {
            let key = (role.clone(), member.clone());
            let preserve_edge = grantor.as_ref().is_some_and(|grantor| {
                graph
                    .membership_edge_grantors
                    .get_mut(&key)
                    .map(|grantors| {
                        grantors.remove(grantor);
                        !grantors.is_empty()
                    })
                    .unwrap_or(false)
            });
            if preserve_edge {
                set_role.insert(key.clone(), SetRoleCapability::Unknown);
                usage.insert(key.clone(), SetRoleCapability::Unknown);
                admin_options.insert(key, SetRoleCapability::Unknown);
                return;
            }
            graph.membership_edge_grantors.remove(&key);
            graph
                .memberships
                .retain(|edge| edge.role != *role || edge.member != *member);
            set_role.remove(&key);
            usage.remove(&key);
            admin_options.remove(&key);
        }
        Change::DropRole { name } => {
            graph.roles.remove(name);
            graph
                .memberships
                .retain(|edge| edge.role != *name && edge.member != *name);
            set_role.retain(|(role, member), _| role != name && member != name);
            usage.retain(|(role, member), _| role != name && member != name);
            admin_options.retain(|(role, member), _| role != name && member != name);
        }
        Change::ReassignOwned { from_role, to_role } => {
            for schema in graph.schemas.values_mut() {
                if schema.owner.as_deref() == Some(from_role) {
                    schema.owner = Some(to_role.clone());
                }
            }
        }
        Change::DropOwned { role } => {
            graph
                .schemas
                .retain(|_, schema| schema.owner.as_deref() != Some(role));
            graph.grants.retain(|key, _| key.role.as_str() != role);
            graph
                .grant_entry_grantors
                .retain(|key, _| key.role.as_str() != role);
            graph
                .default_privileges
                .retain(|key, _| key.owner != *role && key.grantee.as_str() != role);
        }
        Change::TerminateSessions { .. } | Change::SetPassword { .. } => {}
    }
}

fn default_true() -> bool {
    true
}
fn default_connection_limit() -> i32 {
    -1
}

fn serialize_reconciliation_mode<S>(
    mode: &ReconciliationMode,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&mode.to_string())
}

fn deserialize_reconciliation_mode<'de, D>(deserializer: D) -> Result<ReconciliationMode, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    match value.as_str() {
        "authoritative" => Ok(ReconciliationMode::Authoritative),
        "additive" => Ok(ReconciliationMode::Additive),
        "adopt" => Ok(ReconciliationMode::Adopt),
        _ => Err(serde::de::Error::unknown_variant(
            &value,
            &["authoritative", "additive", "adopt"],
        )),
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role() -> SnapshotRole {
        SnapshotRole::default()
    }

    fn request(mode: ReconciliationMode) -> AnalyzeRequest {
        AnalyzeRequest {
            schema_version: EXPLORER_SCHEMA_VERSION.into(),
            current: ExplorerSnapshot::default(),
            desired_yaml: "roles: []\n".into(),
            mode,
            executor: ExecutorFacts {
                role: "deployer".into(),
                superuser: false,
                createrole: SetRoleCapability::Unknown,
                memberships: Vec::new(),
                new_membership_set_role: SetRoleCapability::Unknown,
                new_role_set_role: SetRoleCapability::Unknown,
                new_role_inherit: SetRoleCapability::Unknown,
                new_role_admin_option: SetRoleCapability::Unknown,
            },
            pg_major_version: None,
            authority_graph_complete: None,
        }
    }

    #[test]
    fn reconciliation_modes_filter_membership_removal_and_role_drop() {
        for (mode, removes_membership, drops_role) in [
            (ReconciliationMode::Authoritative, true, true),
            (ReconciliationMode::Additive, false, false),
            (ReconciliationMode::Adopt, true, false),
        ] {
            let mut input = request(mode);
            input.current.roles.insert("obsolete".into(), role());
            input.current.roles.insert("deployer".into(), role());
            input.current.memberships.push(SnapshotMembership {
                role: "obsolete".into(),
                member: "deployer".into(),
                inherit: true,
                admin: false,
                grantors: BTreeSet::new(),
            });
            input.executor.memberships.push(ExecutorMembershipFact {
                role: "obsolete".into(),
                member: "deployer".into(),
                set_role: SetRoleCapability::Allowed,
                inherit: SetRoleCapability::Allowed,
                admin_option: SetRoleCapability::Unknown,
            });
            let response = analyze(input).unwrap();
            assert_eq!(
                response
                    .changes
                    .iter()
                    .any(|change| matches!(change, Change::RemoveMember { .. })),
                removes_membership
            );
            assert_eq!(
                response
                    .changes
                    .iter()
                    .any(|change| matches!(change, Change::DropRole { .. })),
                drops_role
            );
        }
    }

    #[test]
    fn membership_removal_reports_lost_executor_access() {
        let mut input = request(ReconciliationMode::Adopt);
        input.current.roles.insert("deployer".into(), role());
        input.current.roles.insert("owner".into(), role());
        input.current.memberships.push(SnapshotMembership {
            role: "owner".into(),
            member: "deployer".into(),
            inherit: true,
            admin: false,
            grantors: BTreeSet::new(),
        });
        input.executor.memberships.push(ExecutorMembershipFact {
            role: "owner".into(),
            member: "deployer".into(),
            set_role: SetRoleCapability::Allowed,
            inherit: SetRoleCapability::Allowed,
            admin_option: SetRoleCapability::Unknown,
        });
        input.desired_yaml = "roles:\n  - name: deployer\n  - name: owner\n".into();

        let response = analyze(input).unwrap();
        assert!(response.findings.iter().any(|finding| {
            finding.kind == FindingKind::ExecutorLosesAccess
                && finding.role.as_deref() == Some("owner")
        }));
    }

    #[test]
    fn added_membership_has_unknown_set_role_semantics() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.current.roles.insert("deployer".into(), role());
        input.current.roles.insert("owner".into(), role());
        input.desired_yaml = "roles:\n  - name: deployer\n  - name: owner\nmemberships:\n  - role: owner\n    members:\n      - name: deployer\n".into();

        let response = analyze(input).unwrap();
        let membership_phase = response
            .phases
            .iter()
            .find(|phase| phase.phase == PlanPhase::MembershipAdd)
            .unwrap();
        assert!(
            membership_phase
                .executor_reachability
                .iter()
                .any(|role| { role.role == "owner" && role.status == ReachabilityStatus::Unknown })
        );
    }

    #[test]
    fn unavailable_default_privilege_owner_is_reported() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.current.roles.insert("deployer".into(), role());
        input.current.roles.insert("owner".into(), role());
        input.desired_yaml = "roles:\n  - name: deployer\n  - name: owner\ndefault_privileges:\n  - owner: owner\n    schema: app\n    grant:\n      - role: deployer\n        privileges: [SELECT]\n        on_type: table\n".into();
        let response = analyze(input).unwrap();
        assert!(response.findings.iter().any(|finding| {
            finding.kind == FindingKind::RequiredRoleUnavailable
                && finding.role.as_deref() == Some("owner")
        }));
    }

    #[test]
    fn incomplete_authority_graph_does_not_disprove_an_unseen_owner_path() {
        let mut graph = RoleGraph::default();
        graph.roles.insert("deployer".into(), RoleState::default());
        graph.roles.insert("owner".into(), RoleState::default());
        let executor = request(ReconciliationMode::Authoritative).executor;
        let changes = vec![Change::SetDefaultPrivilege {
            owner: "owner".into(),
            scope: DefaultPrivilegeScope::Schema {
                schema: "app".into(),
            },
            on_type: ObjectType::Table,
            grantee: Grantee::from("deployer"),
            privileges: BTreeSet::from([Privilege::Select]),
        }];

        let analysis = analyze_changes_with_options(
            graph,
            &changes,
            &executor,
            PlanAnalysisOptions {
                authority_graph_complete: false,
                ..PlanAnalysisOptions::default()
            },
        );
        assert!(!analysis.findings.iter().any(|finding| {
            finding.kind == FindingKind::RequiredRoleUnavailable
                && finding.role.as_deref() == Some("owner")
        }));
        assert!(analysis.findings.iter().any(|finding| {
            finding.kind == FindingKind::RequiredRoleReachabilityUnknown
                && finding.role.as_deref() == Some("owner")
        }));
    }

    #[test]
    fn newly_created_role_authority_is_unknown_without_executor_facts() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.desired_yaml = "roles:\n  - name: created\n".into();
        let response = analyze(input).unwrap();
        let create = response
            .phases
            .iter()
            .find(|phase| phase.phase == PlanPhase::Create)
            .unwrap();
        assert!(
            create.executor_reachability.iter().any(|role| {
                role.role == "created" && role.status == ReachabilityStatus::Unknown
            })
        );
        assert!(
            create.executor_usage.iter().any(|role| {
                role.role == "created" && role.status == ReachabilityStatus::Unknown
            })
        );
    }

    #[test]
    fn ownership_transfer_requires_database_preflight() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.current.roles.insert("deployer".into(), role());
        input.current.roles.insert("owner".into(), role());
        input.current.schemas.insert(
            "app".into(),
            SnapshotSchema {
                owner: Some("deployer".into()),
                owner_privileges: BTreeSet::new(),
            },
        );
        input.desired_yaml =
            "roles:\n  - name: deployer\n  - name: owner\nschemas:\n  - name: app\n    owner: owner\n"
                .into();
        let response = analyze(input).unwrap();
        assert!(response.findings.iter().any(|finding| {
            finding.kind == FindingKind::DatabasePreflightRequired
                && finding.phase == Some(PlanPhase::Alter)
        }));
    }

    #[test]
    fn fingerprint_is_explicitly_illustrative_and_deterministic() {
        let first = analyze(request(ReconciliationMode::Authoritative)).unwrap();
        let second = analyze(request(ReconciliationMode::Authoritative)).unwrap();
        assert!(matches!(
            first.fingerprint_kind,
            FingerprintKind::Illustrative
        ));
        assert_eq!(first.plan_fingerprint, second.plan_fingerprint);
    }

    #[test]
    fn snapshot_rejects_secret_fields() {
        let error = serde_json::from_value::<AnalyzeRequest>(serde_json::json!({
            "schema_version": EXPLORER_SCHEMA_VERSION,
            "current": { "roles": { "app": { "password": "secret" } } },
            "desired_yaml": "roles: []\n",
            "mode": "authoritative",
            "executor": { "role": "deployer" }
        }))
        .unwrap_err();
        assert!(error.to_string().contains("unknown field `password`"));
    }

    #[test]
    fn desired_manifest_rejects_password_sources() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.desired_yaml =
            "roles:\n  - name: app\n    login: true\n    password:\n      from_env: APP_PASSWORD\n"
                .into();
        assert!(matches!(
            analyze(input),
            Err(AnalysisError::PasswordSourceNotAllowed)
        ));
    }

    #[test]
    fn targeted_revoke_reports_unreachable_grantor() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.current.roles.insert("deployer".into(), role());
        input.current.roles.insert("reporting".into(), role());
        input.current.grants.push(SnapshotGrant {
            role: "reporting".into(),
            object_type: ObjectType::Table,
            schema: Some("app".into()),
            name: Some("orders".into()),
            privileges: BTreeSet::from([Privilege::Select]),
            grantors: BTreeMap::from([("owner".into(), BTreeSet::from([Privilege::Select]))]),
        });
        input.desired_yaml = "roles:\n  - name: deployer\n  - name: reporting\n".into();

        let response = analyze(input).unwrap();
        assert!(response.findings.iter().any(|finding| {
            finding.kind == FindingKind::RequiredRoleUnavailable
                && finding.role.as_deref() == Some("owner")
        }));
    }

    #[test]
    fn illustrative_fingerprint_binds_reconciliation_mode_even_without_changes() {
        let authoritative = analyze(request(ReconciliationMode::Authoritative)).unwrap();
        let additive = analyze(request(ReconciliationMode::Additive)).unwrap();
        let adopt = analyze(request(ReconciliationMode::Adopt)).unwrap();
        assert_ne!(authoritative.plan_fingerprint, additive.plan_fingerprint);
        assert_ne!(authoritative.plan_fingerprint, adopt.plan_fingerprint);
        assert_ne!(additive.plan_fingerprint, adopt.plan_fingerprint);
    }

    #[test]
    fn additive_visual_represents_simulated_state() {
        let mut input = request(ReconciliationMode::Additive);
        input.current.roles.insert("existing".into(), role());
        let response = analyze(input).unwrap();
        assert!(response.changes.is_empty());
        assert!(
            response
                .visual
                .nodes
                .iter()
                .any(|node| node.label == "existing")
        );
    }

    #[test]
    fn revoking_executor_superuser_affects_later_authority_checks() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.executor.superuser = true;
        input.current.roles.insert(
            "deployer".into(),
            SnapshotRole {
                superuser: true,
                ..role()
            },
        );
        input.current.roles.insert("owner".into(), role());
        input.desired_yaml = "roles:\n  - name: deployer\n  - name: owner\ndefault_privileges:\n  - owner: owner\n    schema: app\n    grant:\n      - role: deployer\n        privileges: [SELECT]\n        on_type: table\n".into();

        let response = analyze(input).unwrap();
        assert!(response.findings.iter().any(|finding| {
            finding.kind == FindingKind::RequiredRoleUnavailable
                && finding.role.as_deref() == Some("owner")
        }));
    }

    #[test]
    fn snapshot_preserves_global_default_privilege_and_public_scope() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.current.roles.insert("deployer".into(), role());
        input
            .current
            .default_privileges
            .push(SnapshotDefaultPrivilege {
                owner: "deployer".into(),
                schema: None,
                on_type: ObjectType::Function,
                grantee: "PUBLIC".into(),
                privileges: BTreeSet::from([Privilege::Execute]),
            });
        input.desired_yaml = "roles:\n  - name: deployer\ndefault_privileges:\n  - owner: deployer\n    scope: { type: global }\n    grant:\n      - role: PUBLIC\n        ensure: absent\n        privileges: [EXECUTE]\n        on_type: function\n".into();

        let response = analyze(input).unwrap();
        assert!(response.changes.iter().any(|change| matches!(
            change,
            Change::RevokeDefaultPrivilege {
                scope: DefaultPrivilegeScope::Global,
                grantee: Grantee::Public,
                ..
            }
        )));
    }

    fn default_privilege_authority_request(
        set_role: SetRoleCapability,
        inherit: SetRoleCapability,
    ) -> AnalyzeRequest {
        let mut input = request(ReconciliationMode::Authoritative);
        input.current.roles.insert("deployer".into(), role());
        input.current.roles.insert("owner".into(), role());
        input.executor.memberships.push(ExecutorMembershipFact {
            role: "owner".into(),
            member: "deployer".into(),
            set_role,
            inherit,
            admin_option: SetRoleCapability::Denied,
        });
        input.desired_yaml = "roles:\n  - name: deployer\n  - name: owner\ndefault_privileges:\n  - owner: owner\n    schema: app\n    grant:\n      - role: deployer\n        privileges: [SELECT]\n        on_type: table\n".into();
        input
    }

    #[test]
    fn set_role_without_inherit_does_not_authorize_default_privileges() {
        let response = analyze(default_privilege_authority_request(
            SetRoleCapability::Allowed,
            SetRoleCapability::Denied,
        ))
        .unwrap();
        assert!(response.findings.iter().any(|finding| {
            finding.kind == FindingKind::RequiredRoleUnavailable
                && finding.role.as_deref() == Some("owner")
                && finding.message.contains("USAGE")
        }));
    }

    #[test]
    fn inherit_without_set_role_authorizes_default_privileges() {
        let response = analyze(default_privilege_authority_request(
            SetRoleCapability::Denied,
            SetRoleCapability::Allowed,
        ))
        .unwrap();
        assert!(!response.findings.iter().any(|finding| {
            matches!(
                finding.kind,
                FindingKind::RequiredRoleUnavailable | FindingKind::RequiredRoleReachabilityUnknown
            ) && finding.role.as_deref() == Some("owner")
        }));
    }

    #[test]
    fn proven_admin_path_wins_over_an_earlier_unknown_path() {
        let mut input = request(ReconciliationMode::Authoritative);
        for name in ["deployer", "target", "new_member"] {
            input.current.roles.insert(name.into(), role());
        }
        input.executor.memberships.extend([
            ExecutorMembershipFact {
                role: "a".into(),
                member: "deployer".into(),
                set_role: SetRoleCapability::Unknown,
                inherit: SetRoleCapability::Unknown,
                admin_option: SetRoleCapability::Denied,
            },
            ExecutorMembershipFact {
                role: "target".into(),
                member: "a".into(),
                set_role: SetRoleCapability::Unknown,
                inherit: SetRoleCapability::Unknown,
                admin_option: SetRoleCapability::Unknown,
            },
            ExecutorMembershipFact {
                role: "target".into(),
                member: "deployer".into(),
                set_role: SetRoleCapability::Denied,
                inherit: SetRoleCapability::Denied,
                admin_option: SetRoleCapability::Allowed,
            },
        ]);
        input.desired_yaml = "roles:\n  - name: deployer\n  - name: target\n  - name: new_member\nmemberships:\n  - role: target\n    members:\n      - name: new_member\n".into();

        let response = analyze(input).unwrap();
        assert!(
            !response
                .findings
                .iter()
                .any(|finding| finding.message.contains("ADMIN OPTION for role target"))
        );
    }

    #[test]
    fn targeted_membership_revoke_preserves_other_grantor_edges() {
        let key = ("owner".to_string(), "deployer".to_string());
        let mut graph = RoleGraph::default();
        graph.memberships.insert(MembershipEdge {
            role: key.0.clone(),
            member: key.1.clone(),
            inherit: true,
            admin: false,
        });
        graph
            .membership_edge_grantors
            .insert(key.clone(), BTreeSet::from(["a".into(), "b".into()]));
        let mut set = BTreeMap::from([(key.clone(), SetRoleCapability::Allowed)]);
        let mut usage = set.clone();
        let mut admin = BTreeMap::new();
        let executor = request(ReconciliationMode::Authoritative).executor;
        let remove = |grantor: &str| Change::RemoveMember {
            role: key.0.clone(),
            member: key.1.clone(),
            grantor: Some(grantor.into()),
        };

        apply_change(
            &mut graph,
            &mut set,
            &mut usage,
            &mut admin,
            &executor,
            &remove("a"),
        );
        assert_eq!(graph.memberships.len(), 1);
        assert_eq!(
            graph.membership_edge_grantors[&key],
            BTreeSet::from(["b".into()])
        );
        assert_eq!(set[&key], SetRoleCapability::Unknown);
        apply_change(
            &mut graph,
            &mut set,
            &mut usage,
            &mut admin,
            &executor,
            &remove("b"),
        );
        assert!(graph.memberships.is_empty());
        assert!(!set.contains_key(&key));
    }

    #[test]
    fn targeted_object_revoke_preserves_other_grantor_privileges() {
        let key = GrantKey {
            role: Grantee::Role("reader".into()),
            object_type: ObjectType::Table,
            schema: Some("app".into()),
            name: Some("orders".into()),
        };
        let mut graph = RoleGraph::default();
        graph.grants.insert(
            key.clone(),
            GrantState {
                privileges: BTreeSet::from([Privilege::Select]),
            },
        );
        graph.grant_entry_grantors.insert(
            key.clone(),
            BTreeMap::from([
                ("a".into(), BTreeSet::from([Privilege::Select])),
                ("b".into(), BTreeSet::from([Privilege::Select])),
            ]),
        );
        let mut set = BTreeMap::new();
        let mut usage = BTreeMap::new();
        let mut admin = BTreeMap::new();
        let executor = request(ReconciliationMode::Authoritative).executor;
        let revoke = |grantor: &str| Change::Revoke {
            role: key.role.clone(),
            privileges: BTreeSet::from([Privilege::Select]),
            object_type: key.object_type,
            schema: key.schema.clone(),
            name: key.name.clone(),
            grantor: Some(grantor.into()),
        };

        apply_change(
            &mut graph,
            &mut set,
            &mut usage,
            &mut admin,
            &executor,
            &revoke("a"),
        );
        assert_eq!(
            graph.grants[&key].privileges,
            BTreeSet::from([Privilege::Select])
        );
        apply_change(
            &mut graph,
            &mut set,
            &mut usage,
            &mut admin,
            &executor,
            &revoke("b"),
        );
        assert!(!graph.grants.contains_key(&key));
    }

    #[test]
    fn retirement_updates_known_ownership_state() {
        let mut graph = RoleGraph::default();
        graph.schemas.insert(
            "app".into(),
            SchemaState {
                owner: Some("old_owner".into()),
                owner_privileges: BTreeSet::new(),
            },
        );
        let mut set = BTreeMap::new();
        let mut usage = BTreeMap::new();
        let mut admin = BTreeMap::new();
        let executor = request(ReconciliationMode::Authoritative).executor;

        apply_change(
            &mut graph,
            &mut set,
            &mut usage,
            &mut admin,
            &executor,
            &Change::ReassignOwned {
                from_role: "old_owner".into(),
                to_role: "new_owner".into(),
            },
        );
        assert_eq!(graph.schemas["app"].owner.as_deref(), Some("new_owner"));
        apply_change(
            &mut graph,
            &mut set,
            &mut usage,
            &mut admin,
            &executor,
            &Change::DropOwned {
                role: "old_owner".into(),
            },
        );
        assert!(graph.schemas.contains_key("app"));
        apply_change(
            &mut graph,
            &mut set,
            &mut usage,
            &mut admin,
            &executor,
            &Change::DropOwned {
                role: "new_owner".into(),
            },
        );
        assert!(!graph.schemas.contains_key("app"));
    }

    #[test]
    fn snapshot_inherent_grant_does_not_plan_owner_acl_revoke() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.current.roles.insert("owner".into(), role());
        input.current.grants.push(SnapshotGrant {
            role: "owner".into(),
            object_type: ObjectType::Table,
            schema: Some("app".into()),
            name: Some("widgets".into()),
            privileges: BTreeSet::from([Privilege::Select, Privilege::Insert]),
            grantors: BTreeMap::new(),
        });
        input.current.inherent_grants.push(SnapshotGrantTarget {
            role: "owner".into(),
            object_type: ObjectType::Table,
            schema: Some("app".into()),
            name: Some("widgets".into()),
        });
        input.current =
            serde_json::from_value(serde_json::to_value(&input.current).unwrap()).unwrap();
        input.desired_yaml = "roles:\n  - name: owner\ngrants:\n  - role: owner\n    privileges: [SELECT]\n    object: { type: table, schema: app, name: widgets }\n".into();

        let response = analyze(input).unwrap();
        assert!(
            !response
                .changes
                .iter()
                .any(|change| matches!(change, Change::Revoke { .. }))
        );
    }

    #[test]
    fn snapshot_admin_option_authorizes_membership_addition() {
        let mut input = request(ReconciliationMode::Authoritative);
        for name in ["deployer", "target", "new_member"] {
            input.current.roles.insert(name.into(), role());
        }
        input.current.memberships.push(SnapshotMembership {
            role: "target".into(),
            member: "deployer".into(),
            inherit: false,
            admin: true,
            grantors: BTreeSet::new(),
        });
        input.desired_yaml = "roles:\n  - name: deployer\n  - name: target\n  - name: new_member\nmemberships:\n  - role: target\n    members:\n      - name: deployer\n        inherit: false\n        admin: true\n      - name: new_member\n".into();

        let response = analyze(input).unwrap();
        assert!(
            !response
                .findings
                .iter()
                .any(|finding| finding.message.contains("ADMIN OPTION for role target"))
        );
    }

    #[test]
    fn lifecycle_changes_emit_database_preflight_findings() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.current.roles.insert("existing".into(), role());
        input.desired_yaml = "roles:\n  - name: existing\n    login: true\n    comment: managed\n  - name: new_role\nschemas:\n  - name: app\n".into();
        let response = analyze(input).unwrap();
        for expected in ["CreateRole", "CreateSchema", "AlterRole", "SetComment"] {
            assert!(
                response.changes.iter().any(|change| {
                    serde_json::to_value(change)
                        .unwrap()
                        .get(expected)
                        .is_some()
                }),
                "missing {expected}: {:?}",
                response.changes
            );
        }
        let preflight_count = response
            .findings
            .iter()
            .filter(|finding| finding.kind == FindingKind::DatabasePreflightRequired)
            .count();
        assert_eq!(
            preflight_count, 4,
            "CreateRole, CreateSchema, AlterRole, and SetComment"
        );
    }

    #[test]
    fn oversized_snapshot_is_rejected_before_analysis() {
        let mut input = request(ReconciliationMode::Authoritative);
        for index in 0..=MAX_ROLES {
            input.current.roles.insert(format!("role_{index}"), role());
        }
        assert!(matches!(
            analyze(input),
            Err(AnalysisError::TooManyEntries {
                collection: "current.roles",
                ..
            })
        ));
    }

    #[test]
    fn explicit_admin_fact_overrides_snapshot_admin_option() {
        let mut input = request(ReconciliationMode::Authoritative);
        for name in ["deployer", "target", "new_member"] {
            input.current.roles.insert(name.into(), role());
        }
        input.current.memberships.push(SnapshotMembership {
            role: "target".into(),
            member: "deployer".into(),
            inherit: false,
            admin: true,
            grantors: BTreeSet::new(),
        });
        input.executor.memberships.push(ExecutorMembershipFact {
            role: "target".into(),
            member: "deployer".into(),
            set_role: SetRoleCapability::Denied,
            inherit: SetRoleCapability::Denied,
            admin_option: SetRoleCapability::Denied,
        });
        input.desired_yaml = "roles:\n  - name: deployer\n  - name: target\n  - name: new_member\nmemberships:\n  - role: target\n    members:\n      - name: deployer\n        inherit: false\n        admin: true\n      - name: new_member\n".into();

        let response = analyze(input).unwrap();
        assert!(
            response
                .findings
                .iter()
                .any(|finding| finding.message.contains("ADMIN OPTION for role target"))
        );
    }

    fn membership(role: &str, member: &str, inherit: bool, admin: bool) -> SnapshotMembership {
        SnapshotMembership {
            role: role.into(),
            member: member.into(),
            inherit,
            admin,
            grantors: BTreeSet::new(),
        }
    }

    fn has_finding(response: &AnalyzeResponse, kind: FindingKind, role: &str) -> bool {
        response
            .findings
            .iter()
            .any(|finding| finding.kind == kind && finding.role.as_deref() == Some(role))
    }

    /// `deployer` is a direct inheriting member of every `r<i>`, and the
    /// policy grants one table privilege per role round-robin.
    fn star_request(roles: usize, grants: usize) -> AnalyzeRequest {
        use std::fmt::Write as _;
        let mut input = request(ReconciliationMode::Authoritative);
        input.current.roles.insert("deployer".into(), role());
        let mut yaml = String::from("roles:\n  - name: deployer\n");
        let mut memberships = String::from("memberships:\n");
        for index in 0..roles {
            let name = format!("r{index}");
            input.current.roles.insert(name.clone(), role());
            input
                .current
                .memberships
                .push(membership(&name, "deployer", true, false));
            writeln!(yaml, "  - name: {name}").unwrap();
            write!(
                memberships,
                "  - role: {name}\n    members:\n      - name: deployer\n"
            )
            .unwrap();
        }
        yaml.push_str("grants:\n");
        for index in 0..grants {
            write!(
                yaml,
                "  - role: r{}\n    privileges: [SELECT]\n    object: {{ type: table, schema: app, name: t{index} }}\n",
                index % roles
            )
            .unwrap();
        }
        yaml.push_str(&memberships);
        input.desired_yaml = yaml;
        input
    }

    #[test]
    fn large_grant_plan_is_analyzed_quickly_with_one_preflight_finding() {
        let input = star_request(500, 2000);
        let started = std::time::Instant::now();
        let response = analyze(input).unwrap();
        let elapsed = started.elapsed();
        assert_eq!(response.changes.len(), 2000);
        let preflight: Vec<_> = response
            .findings
            .iter()
            .filter(|finding| finding.kind == FindingKind::DatabasePreflightRequired)
            .collect();
        assert_eq!(preflight.len(), 1, "{:?}", response.findings);
        assert_eq!(preflight[0].phase, Some(PlanPhase::Grant));
        assert_eq!(preflight[0].change_index, Some(0));
        assert_eq!(preflight[0].change_indices, (0..2000).collect::<Vec<_>>());
        assert!(preflight[0].message.starts_with("2000 Grant operations"));
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "analysis took {elapsed:?}"
        );
    }

    fn star_graph(roles: usize) -> RoleGraph {
        let mut graph = RoleGraph::default();
        graph.roles.insert("deployer".into(), RoleState::default());
        for index in 0..roles {
            let name = format!("r{index}");
            graph.roles.insert(name.clone(), RoleState::default());
            graph.memberships.insert(MembershipEdge {
                role: name,
                member: "deployer".into(),
                inherit: true,
                admin: false,
            });
        }
        graph
    }

    fn grant(role: &str, table: &str) -> Change {
        Change::Grant {
            role: Grantee::Role(role.into()),
            privileges: BTreeSet::from([Privilege::Select]),
            object_type: ObjectType::Table,
            schema: Some("app".into()),
            name: Some(table.into()),
        }
    }

    #[test]
    fn reachability_is_recomputed_only_after_changes_that_affect_it() {
        let executor = request(ReconciliationMode::Authoritative).executor;
        let mut changes: Vec<_> = (0..200)
            .map(|index| grant(&format!("r{}", index % 50), &format!("t{index}")))
            .collect();
        let (_, computations) = simulate(
            star_graph(50),
            &changes,
            &executor,
            PlanAnalysisOptions::default(),
            Recompute::WhenAffected,
        );
        assert_eq!(computations, 2, "only the initial SET ROLE and USAGE maps");

        changes.push(Change::AddMember {
            role: "r0".into(),
            member: "r1".into(),
            inherit: true,
            admin: false,
        });
        let (_, computations) = simulate(
            star_graph(50),
            &changes,
            &executor,
            PlanAnalysisOptions::default(),
            Recompute::WhenAffected,
        );
        assert_eq!(computations, 4);
    }

    #[test]
    fn incremental_reachability_matches_recomputing_after_every_change() {
        let mut graph = star_graph(4);
        graph.roles.insert("owner".into(), RoleState::default());
        graph.schemas.insert(
            "app".into(),
            SchemaState {
                owner: Some("owner".into()),
                owner_privileges: BTreeSet::new(),
            },
        );
        let mut executor = request(ReconciliationMode::Authoritative).executor;
        executor.memberships.push(ExecutorMembershipFact {
            role: "owner".into(),
            member: "r0".into(),
            set_role: SetRoleCapability::Allowed,
            inherit: SetRoleCapability::Allowed,
            admin_option: SetRoleCapability::Unknown,
        });
        executor.new_role_set_role = SetRoleCapability::Allowed;
        executor.new_role_inherit = SetRoleCapability::Allowed;
        let changes = vec![
            Change::CreateRole {
                name: "fresh".into(),
                state: RoleState::default(),
            },
            Change::AlterRole {
                name: "deployer".into(),
                attributes: vec![RoleAttribute::Superuser(true)],
            },
            Change::AlterSchemaOwner {
                name: "app".into(),
                owner: "fresh".into(),
            },
            Change::AlterRole {
                name: "deployer".into(),
                attributes: vec![RoleAttribute::Superuser(false)],
            },
            grant("r1", "orders"),
            Change::SetDefaultPrivilege {
                owner: "owner".into(),
                scope: DefaultPrivilegeScope::Schema {
                    schema: "app".into(),
                },
                on_type: ObjectType::Table,
                grantee: Grantee::from("r2"),
                privileges: BTreeSet::from([Privilege::Select]),
            },
            Change::RemoveMember {
                role: "r0".into(),
                member: "deployer".into(),
                grantor: None,
            },
            Change::AddMember {
                role: "r3".into(),
                member: "fresh".into(),
                inherit: true,
                admin: true,
            },
            Change::RevokeDefaultPrivilege {
                owner: "owner".into(),
                scope: DefaultPrivilegeScope::Schema {
                    schema: "app".into(),
                },
                on_type: ObjectType::Table,
                grantee: Grantee::from("r2"),
                privileges: BTreeSet::from([Privilege::Select]),
            },
            Change::DropOwned { role: "r2".into() },
            Change::DropRole { name: "r2".into() },
        ];
        for authority_graph_complete in [true, false] {
            let options = PlanAnalysisOptions {
                authority_graph_complete,
                ..PlanAnalysisOptions::default()
            };
            let (incremental, fewer) = simulate(
                graph.clone(),
                &changes,
                &executor,
                options,
                Recompute::WhenAffected,
            );
            let (reference, every) = simulate(
                graph.clone(),
                &changes,
                &executor,
                options,
                Recompute::Always,
            );
            assert_eq!(
                serde_json::to_value(&incremental).unwrap(),
                serde_json::to_value(&reference).unwrap()
            );
            assert!(fewer < every, "{fewer} < {every}");
        }
    }

    #[test]
    fn preflight_findings_aggregate_per_phase_and_change_kind() {
        let executor = request(ReconciliationMode::Authoritative).executor;
        let changes = vec![
            grant("r0", "a"),
            grant("r1", "b"),
            Change::Revoke {
                role: Grantee::Role("r0".into()),
                privileges: BTreeSet::from([Privilege::Select]),
                object_type: ObjectType::Table,
                schema: Some("app".into()),
                name: Some("c".into()),
                grantor: None,
            },
            grant("r2", "d"),
        ];
        let analysis = analyze_changes(star_graph(3), &changes, &executor);
        let preflight: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.kind == FindingKind::DatabasePreflightRequired)
            .map(|finding| {
                (
                    finding.phase,
                    finding.change_index,
                    finding.change_indices.clone(),
                    finding.message.clone(),
                )
            })
            .collect();
        // Grant, Revoke, Grant form three phase runs; the two Grant runs
        // share the (phase, kind) finding.
        assert_eq!(
            preflight,
            vec![
                (
                    Some(PlanPhase::Grant),
                    Some(0),
                    vec![0, 1, 3],
                    "3 Grant operations require database ownership or privilege preflight".into()
                ),
                (
                    Some(PlanPhase::Revoke),
                    Some(2),
                    vec![2],
                    "this Revoke operation requires database ownership or privilege preflight"
                        .into()
                ),
            ]
        );
        assert_eq!(analysis.phases.len(), 3);
    }

    #[test]
    fn set_password_requires_database_preflight() {
        let mut graph = RoleGraph::default();
        graph.roles.insert("deployer".into(), RoleState::default());
        graph.roles.insert("app".into(), RoleState::default());
        let analysis = analyze_changes_with_options(
            graph,
            &[Change::SetPassword {
                name: "app".into(),
                password: "SCRAM-SHA-256$x".into(),
            }],
            &request(ReconciliationMode::Authoritative).executor,
            PlanAnalysisOptions {
                authority_graph_complete: false,
                ..PlanAnalysisOptions::default()
            },
        );
        assert!(analysis.findings.iter().any(|finding| {
            finding.kind == FindingKind::DatabasePreflightRequired
                && finding.phase == Some(PlanPhase::Alter)
                && finding.change_indices == vec![0]
        }));
    }

    #[test]
    fn response_echoes_default_version_and_completeness() {
        let response = analyze(request(ReconciliationMode::Authoritative)).unwrap();
        assert_eq!(response.pg_major_version, DEFAULT_PG_MAJOR_VERSION);
        assert!(response.authority_graph_complete);
        let value = serde_json::to_value(&response).unwrap();
        assert_eq!(value["pg_major_version"], 16);
        assert_eq!(value["authority_graph_complete"], true);
    }

    #[test]
    fn request_accepts_optional_version_and_completeness_fields() {
        let parsed: AnalyzeRequest = serde_json::from_value(serde_json::json!({
            "schema_version": EXPLORER_SCHEMA_VERSION,
            "current": {},
            "desired_yaml": "roles: []\n",
            "executor": { "role": "deployer", "createrole": "allowed" },
            "pg_major_version": 15,
            "authority_graph_complete": false
        }))
        .unwrap();
        assert_eq!(parsed.pg_major_version, Some(15));
        assert_eq!(parsed.authority_graph_complete, Some(false));
        assert_eq!(parsed.executor.createrole, SetRoleCapability::Allowed);
        let response = analyze(parsed).unwrap();
        assert_eq!(response.pg_major_version, 15);
        assert!(!response.authority_graph_complete);

        let defaulted: AnalyzeRequest = serde_json::from_value(serde_json::json!({
            "schema_version": EXPLORER_SCHEMA_VERSION,
            "current": {},
            "desired_yaml": "roles: []\n",
            "executor": { "role": "deployer" },
            "pg_major_version": null,
            "authority_graph_complete": null
        }))
        .unwrap();
        assert_eq!(defaulted.pg_major_version, None);
        assert_eq!(defaulted.authority_graph_complete, None);
        assert_eq!(defaulted.executor.createrole, SetRoleCapability::Unknown);
    }

    #[test]
    fn unsupported_pg_major_versions_are_rejected() {
        for version in [0, 11, 21, 170] {
            let mut input = request(ReconciliationMode::Authoritative);
            input.pg_major_version = Some(version);
            assert!(
                matches!(
                    analyze(input),
                    Err(AnalysisError::UnsupportedPgMajorVersion {
                        version: rejected,
                        min: MIN_PG_MAJOR_VERSION,
                        max: MAX_PG_MAJOR_VERSION,
                    }) if rejected == version
                ),
                "version {version}"
            );
        }
        for version in [MIN_PG_MAJOR_VERSION, 15, 16, 18, MAX_PG_MAJOR_VERSION] {
            let mut input = request(ReconciliationMode::Authoritative);
            input.pg_major_version = Some(version);
            assert_eq!(analyze(input).unwrap().pg_major_version, version);
        }
    }

    #[test]
    fn fingerprint_binds_version_and_completeness() {
        let base = analyze(request(ReconciliationMode::Authoritative)).unwrap();
        let mut pg15 = request(ReconciliationMode::Authoritative);
        pg15.pg_major_version = Some(15);
        let mut explicit16 = request(ReconciliationMode::Authoritative);
        explicit16.pg_major_version = Some(16);
        let mut partial = request(ReconciliationMode::Authoritative);
        partial.authority_graph_complete = Some(false);
        assert_ne!(
            base.plan_fingerprint,
            analyze(pg15).unwrap().plan_fingerprint
        );
        assert_ne!(
            base.plan_fingerprint,
            analyze(partial).unwrap().plan_fingerprint
        );
        assert_eq!(
            base.plan_fingerprint,
            analyze(explicit16).unwrap().plan_fingerprint
        );
    }

    /// `deployer` adds `new_member` to `target` with no ADMIN OPTION path.
    fn membership_grant_request() -> AnalyzeRequest {
        let mut input = request(ReconciliationMode::Authoritative);
        for name in ["target", "new_member"] {
            input.current.roles.insert(name.into(), role());
        }
        input.desired_yaml = "roles:\n  - name: target\n  - name: new_member\nmemberships:\n  - role: target\n    members:\n      - name: new_member\n".into();
        input
    }

    #[test]
    fn createrole_authorizes_membership_changes_only_before_postgres_16() {
        for (version, createrole, expected) in [
            (15, SetRoleCapability::Allowed, None),
            (
                15,
                SetRoleCapability::Unknown,
                Some((
                    FindingKind::RequiredRoleReachabilityUnknown,
                    FindingSeverity::Warning,
                )),
            ),
            (
                15,
                SetRoleCapability::Denied,
                Some((FindingKind::RequiredRoleUnavailable, FindingSeverity::Error)),
            ),
            (
                16,
                SetRoleCapability::Allowed,
                Some((FindingKind::RequiredRoleUnavailable, FindingSeverity::Error)),
            ),
            (
                17,
                SetRoleCapability::Unknown,
                Some((FindingKind::RequiredRoleUnavailable, FindingSeverity::Error)),
            ),
        ] {
            let mut input = membership_grant_request();
            input.pg_major_version = Some(version);
            input.executor.createrole = createrole;
            let response = analyze(input).unwrap();
            let actual = response
                .findings
                .iter()
                .find(|finding| finding.role.as_deref() == Some("target"))
                .map(|finding| (finding.kind, finding.severity));
            assert_eq!(actual, expected, "PG{version} createrole={createrole:?}");
            if let Some(finding) = response
                .findings
                .iter()
                .find(|finding| finding.role.as_deref() == Some("target"))
            {
                assert!(finding.message.contains("ADMIN OPTION for role target"));
                assert_eq!(finding.message.contains("CREATEROLE or"), version < 16);
            }
        }
    }

    #[test]
    fn snapshot_createrole_applies_when_executor_createrole_is_unknown() {
        for (snapshot, explicit, proven) in [
            (true, SetRoleCapability::Unknown, true),
            (false, SetRoleCapability::Unknown, false),
            (false, SetRoleCapability::Allowed, true),
            (true, SetRoleCapability::Denied, false),
        ] {
            let mut input = membership_grant_request();
            input.pg_major_version = Some(15);
            input.executor.createrole = explicit;
            input.current.roles.insert(
                "deployer".into(),
                SnapshotRole {
                    createrole: snapshot,
                    ..role()
                },
            );
            input.desired_yaml = format!(
                "roles:\n  - name: deployer\n    createrole: {snapshot}\n  - name: target\n  - name: new_member\nmemberships:\n  - role: target\n    members:\n      - name: new_member\n"
            );
            let response = analyze(input).unwrap();
            assert_eq!(
                !response
                    .findings
                    .iter()
                    .any(|finding| finding.role.as_deref() == Some("target")),
                proven,
                "snapshot={snapshot} explicit={explicit:?}: {:?}",
                response.findings
            );
        }
    }

    #[test]
    fn disproved_admin_path_is_an_error_only_with_a_complete_graph() {
        let complete = analyze(membership_grant_request()).unwrap();
        assert!(complete.findings.iter().any(|finding| {
            finding.kind == FindingKind::RequiredRoleUnavailable
                && finding.severity == FindingSeverity::Error
                && finding.role.as_deref() == Some("target")
        }));

        let mut input = membership_grant_request();
        input.authority_graph_complete = Some(false);
        let partial = analyze(input).unwrap();
        assert!(!partial.authority_graph_complete);
        assert!(partial.findings.iter().any(|finding| {
            finding.kind == FindingKind::RequiredRoleReachabilityUnknown
                && finding.severity == FindingSeverity::Warning
                && finding.role.as_deref() == Some("target")
        }));
        assert!(
            !has_finding(&partial, FindingKind::RequiredRoleUnavailable, "target"),
            "{:?}",
            partial.findings
        );
    }

    #[test]
    fn partial_authority_graph_reports_unknown_instead_of_unreachable() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.current.roles.insert("deployer".into(), role());
        input.current.roles.insert("owner".into(), role());
        input.authority_graph_complete = Some(false);
        input.desired_yaml = "roles:\n  - name: deployer\n  - name: owner\ndefault_privileges:\n  - owner: owner\n    schema: app\n    grant:\n      - role: deployer\n        privileges: [SELECT]\n        on_type: table\n".into();
        let response = analyze(input).unwrap();
        assert!(has_finding(
            &response,
            FindingKind::RequiredRoleReachabilityUnknown,
            "owner"
        ));
        assert!(!has_finding(
            &response,
            FindingKind::RequiredRoleUnavailable,
            "owner"
        ));
        assert!(response.phases[0].executor_usage.iter().any(|status| {
            status.role == "owner" && status.status == ReachabilityStatus::Unknown
        }));
    }

    #[test]
    fn omitted_executor_fact_options_do_not_erase_snapshot_evidence() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.current.roles.insert("deployer".into(), role());
        input.current.roles.insert("reader".into(), role());
        input
            .current
            .memberships
            .push(membership("reader", "deployer", true, false));
        input.executor.memberships.push(ExecutorMembershipFact {
            role: "reader".into(),
            member: "deployer".into(),
            set_role: SetRoleCapability::Allowed,
            inherit: SetRoleCapability::Unknown,
            admin_option: SetRoleCapability::Unknown,
        });
        input.desired_yaml = "roles:\n  - name: deployer\n  - name: reader\n".into();
        let response = analyze(input.clone()).unwrap();
        assert!(has_finding(
            &response,
            FindingKind::ExecutorLosesAccess,
            "reader"
        ));
        assert!(!has_finding(
            &response,
            FindingKind::MembershipDisconnectsRole,
            "reader"
        ));

        // An explicit denial still overrides the snapshot.
        input.executor.memberships[0].inherit = SetRoleCapability::Denied;
        let response = analyze(input).unwrap();
        assert!(!has_finding(
            &response,
            FindingKind::ExecutorLosesAccess,
            "reader"
        ));
    }

    #[test]
    fn snapshot_admin_option_survives_a_fact_that_omits_it() {
        let mut input = membership_grant_request();
        input.current.roles.insert("deployer".into(), role());
        input
            .current
            .memberships
            .push(membership("target", "deployer", true, true));
        input.executor.memberships.push(ExecutorMembershipFact {
            role: "target".into(),
            member: "deployer".into(),
            set_role: SetRoleCapability::Allowed,
            inherit: SetRoleCapability::Unknown,
            admin_option: SetRoleCapability::Unknown,
        });
        input.desired_yaml = "roles:\n  - name: deployer\n  - name: target\n  - name: new_member\nmemberships:\n  - role: target\n    members:\n      - name: deployer\n        admin: true\n      - name: new_member\n".into();
        let response = analyze(input).unwrap();
        assert!(
            !response
                .findings
                .iter()
                .any(|finding| finding.role.as_deref() == Some("target")),
            "{:?}",
            response.findings
        );
    }

    #[test]
    fn membership_in_a_superuser_role_requires_a_superuser_executor() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.current.roles.insert("deployer".into(), role());
        input.current.roles.insert(
            "root_like".into(),
            SnapshotRole {
                superuser: true,
                ..role()
            },
        );
        input.current.roles.insert("x".into(), role());
        input
            .current
            .memberships
            .push(membership("root_like", "deployer", false, true));
        input.desired_yaml = "roles:\n  - name: deployer\n  - name: root_like\n    superuser: true\n  - name: x\nmemberships:\n  - role: root_like\n    members:\n      - name: deployer\n        inherit: false\n        admin: true\n      - name: x\n".into();
        for version in [15, 16] {
            let mut input = input.clone();
            input.pg_major_version = Some(version);
            input.executor.createrole = SetRoleCapability::Allowed;
            let response = analyze(input).unwrap();
            let finding = response
                .findings
                .iter()
                .find(|finding| finding.kind == FindingKind::SuperuserRequired)
                .unwrap_or_else(|| panic!("PG{version}: {:?}", response.findings));
            assert_eq!(finding.severity, FindingSeverity::Error);
            assert_eq!(finding.role.as_deref(), Some("root_like"));
            assert_eq!(finding.phase, Some(PlanPhase::MembershipAdd));
        }

        input.executor.superuser = true;
        let response = analyze(input).unwrap();
        assert!(
            !response
                .findings
                .iter()
                .any(|finding| finding.kind == FindingKind::SuperuserRequired)
        );
    }

    #[test]
    fn dropped_roles_are_not_reported_as_lost_or_disconnected() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.executor.role = "postgres".into();
        input.executor.superuser = true;
        input.current.roles.insert(
            "postgres".into(),
            SnapshotRole {
                superuser: true,
                ..role()
            },
        );
        input.current.roles.insert(
            "bob".into(),
            SnapshotRole {
                login: true,
                ..role()
            },
        );
        input.desired_yaml = "roles:\n  - name: postgres\n    superuser: true\n".into();
        let response = analyze(input).unwrap();
        assert!(
            response
                .changes
                .iter()
                .any(|change| matches!(change, Change::DropRole { name } if name == "bob"))
        );
        assert!(!has_finding(
            &response,
            FindingKind::ExecutorLosesAccess,
            "bob"
        ));

        let mut graph = RoleGraph::default();
        graph.roles.insert("deployer".into(), RoleState::default());
        for name in ["old_a", "old_b"] {
            graph.roles.insert(name.into(), RoleState::default());
        }
        let analysis = analyze_changes_with_options(
            graph,
            &[
                Change::DropRole {
                    name: "old_a".into(),
                },
                Change::DropRole {
                    name: "old_b".into(),
                },
            ],
            &request(ReconciliationMode::Authoritative).executor,
            PlanAnalysisOptions {
                authority_graph_complete: false,
                ..PlanAnalysisOptions::default()
            },
        );
        assert!(!analysis.findings.iter().any(|finding| matches!(
            finding.kind,
            FindingKind::ExecutorLosesAccess | FindingKind::MembershipDisconnectsRole
        )));
    }

    #[test]
    fn dropping_a_bridge_role_still_reports_roles_reached_through_it() {
        let mut graph = RoleGraph::default();
        for name in ["deployer", "bridge", "owner"] {
            graph.roles.insert(name.into(), RoleState::default());
        }
        for (role, member) in [("bridge", "deployer"), ("owner", "bridge")] {
            graph.memberships.insert(MembershipEdge {
                role: role.into(),
                member: member.into(),
                inherit: true,
                admin: false,
            });
        }
        let analysis = analyze_changes(
            graph,
            &[Change::DropRole {
                name: "bridge".into(),
            }],
            &request(ReconciliationMode::Authoritative).executor,
        );
        let lost: Vec<_> = analysis
            .findings
            .iter()
            .filter(|finding| finding.kind == FindingKind::ExecutorLosesAccess)
            .filter_map(|finding| finding.role.as_deref())
            .collect();
        assert_eq!(lost, vec!["owner"]);
    }

    #[test]
    fn duplicate_snapshot_memberships_merge_options_and_grantors() {
        let mut input = membership_grant_request();
        input.current.roles.insert("deployer".into(), role());
        input.current.memberships.extend([
            SnapshotMembership {
                grantors: BTreeSet::from(["a".into()]),
                ..membership("target", "deployer", false, true)
            },
            SnapshotMembership {
                grantors: BTreeSet::from(["b".into()]),
                ..membership("target", "deployer", true, false)
            },
        ]);
        let graph = input.current.clone().into_graph();
        assert_eq!(
            graph.memberships,
            BTreeSet::from([MembershipEdge {
                role: "target".into(),
                member: "deployer".into(),
                inherit: true,
                admin: true,
            }])
        );
        assert_eq!(
            graph.membership_edge_grantors[&("target".to_string(), "deployer".to_string())],
            BTreeSet::from(["a".to_string(), "b".to_string()])
        );

        input.desired_yaml = "roles:\n  - name: deployer\n  - name: target\n  - name: new_member\nmemberships:\n  - role: target\n    members:\n      - name: deployer\n        admin: true\n      - name: new_member\n".into();
        let response = analyze(input).unwrap();
        assert!(
            !response
                .findings
                .iter()
                .any(|finding| finding.role.as_deref() == Some("target")),
            "{:?}",
            response.findings
        );
        assert!(
            !response
                .changes
                .iter()
                .any(|change| matches!(change, Change::RemoveMember { .. })),
            "merged edge matches the desired membership: {:?}",
            response.changes
        );
    }

    #[test]
    fn duplicate_snapshot_grants_merge_privileges_and_grantors() {
        let target = |privileges: &[Privilege], grantor: &str| SnapshotGrant {
            role: "reader".into(),
            object_type: ObjectType::Table,
            schema: Some("app".into()),
            name: Some("orders".into()),
            privileges: privileges.iter().copied().collect(),
            grantors: BTreeMap::from([(grantor.to_string(), privileges.iter().copied().collect())]),
        };
        let snapshot = ExplorerSnapshot {
            grants: vec![
                target(&[Privilege::Select], "a"),
                target(&[Privilege::Insert], "b"),
                target(&[Privilege::Update], "a"),
            ],
            default_privileges: vec![
                SnapshotDefaultPrivilege {
                    owner: "owner".into(),
                    schema: Some("app".into()),
                    on_type: ObjectType::Table,
                    grantee: "reader".into(),
                    privileges: BTreeSet::from([Privilege::Select]),
                },
                SnapshotDefaultPrivilege {
                    owner: "owner".into(),
                    schema: Some("app".into()),
                    on_type: ObjectType::Table,
                    grantee: "reader".into(),
                    privileges: BTreeSet::from([Privilege::Insert]),
                },
            ],
            ..ExplorerSnapshot::default()
        };
        let graph = snapshot.into_graph();
        let key = GrantKey {
            role: Grantee::Role("reader".into()),
            object_type: ObjectType::Table,
            schema: Some("app".into()),
            name: Some("orders".into()),
        };
        assert_eq!(
            graph.grants[&key].privileges,
            BTreeSet::from([Privilege::Select, Privilege::Insert, Privilege::Update])
        );
        assert_eq!(
            graph.grant_entry_grantors[&key],
            BTreeMap::from([
                (
                    "a".to_string(),
                    BTreeSet::from([Privilege::Select, Privilege::Update])
                ),
                ("b".to_string(), BTreeSet::from([Privilege::Insert])),
            ])
        );
        assert_eq!(graph.default_privileges.len(), 1);
        assert_eq!(
            graph.default_privileges.values().next().unwrap().privileges,
            BTreeSet::from([Privilege::Select, Privilege::Insert])
        );
    }

    #[test]
    fn explicit_executor_superuser_wins_over_snapshot_default() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.executor.role = "postgres".into();
        input.executor.superuser = true;
        input.current.roles.insert("postgres".into(), role());
        input.current.roles.insert("owner".into(), role());
        input.desired_yaml = "roles:\n  - name: postgres\n  - name: owner\ndefault_privileges:\n  - owner: owner\n    schema: app\n    grant:\n      - role: postgres\n        privileges: [SELECT]\n        on_type: table\n".into();
        let response = analyze(input.clone()).unwrap();
        assert!(!has_finding(
            &response,
            FindingKind::RequiredRoleUnavailable,
            "owner"
        ));

        // Omitted (false) defers to the snapshot attribute.
        input.executor.superuser = false;
        input.current.roles.insert(
            "postgres".into(),
            SnapshotRole {
                superuser: true,
                ..role()
            },
        );
        input.desired_yaml = input.desired_yaml.replace(
            "  - name: postgres\n  - name: owner",
            "  - name: postgres\n    superuser: true\n  - name: owner",
        );
        let response = analyze(input).unwrap();
        assert!(!has_finding(
            &response,
            FindingKind::RequiredRoleUnavailable,
            "owner"
        ));
    }

    #[test]
    fn schema_owner_change_reports_the_new_implicit_grantor() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.current.roles.insert("deployer".into(), role());
        input.current.roles.insert("old_owner".into(), role());
        input.current.roles.insert("new_owner".into(), role());
        input.current.schemas.insert(
            "app".into(),
            SnapshotSchema {
                owner: Some("old_owner".into()),
                owner_privileges: BTreeSet::new(),
            },
        );
        input.desired_yaml = "roles:\n  - name: deployer\n  - name: old_owner\n  - name: new_owner\nschemas:\n  - name: app\n    owner: new_owner\n".into();
        let response = analyze(input).unwrap();
        let finding = response
            .findings
            .iter()
            .find(|finding| finding.kind == FindingKind::OwnershipTransferChangesGrantor)
            .expect("ownership transfer finding");
        assert_eq!(finding.severity, FindingSeverity::Info);
        assert_eq!(finding.phase, Some(PlanPhase::Alter));
        assert_eq!(finding.role.as_deref(), Some("new_owner"));
        assert!(
            finding
                .message
                .contains("from role old_owner to role new_owner")
        );
        assert!(finding.message.contains("implicit grantor"));
    }

    #[test]
    fn oversized_desired_yaml_is_rejected_by_explorer_bounds() {
        let mut input = request(ReconciliationMode::Authoritative);
        input.desired_yaml = " ".repeat(MAX_EXPLORER_YAML_BYTES + 1);
        assert!(matches!(
            analyze(input),
            Err(AnalysisError::DesiredYamlTooLarge {
                limit: MAX_EXPLORER_YAML_BYTES,
                ..
            })
        ));
    }
}
