//! Pure plan analysis for untrusted, sanitized explorer snapshots.
//!
//! This module deliberately does not inspect PostgreSQL. Any fact that cannot
//! be established from the supplied snapshot is reported as unknown or as
//! requiring database preflight.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::diff::{
    Change, ReconciliationMode, apply_role_retirements, diff, filter_changes,
    filter_external_role_changes,
};
use crate::manifest::{ObjectType, Privilege, expand_manifest, parse_manifest};
use crate::model::{
    DefaultPrivKey, DefaultPrivState, DefaultPrivilegeScope, GrantKey, GrantState, Grantee,
    MembershipEdge, RoleGraph, RoleState, SchemaState,
};
use crate::visual::{VisualGraph, VisualSource, build_visual_graph};

pub const EXPLORER_SCHEMA_VERSION: &str = "pgroles.explorer.v1";

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
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyzeResponse {
    pub schema_version: String,
    pub changes: Vec<Change>,
    pub phases: Vec<PhaseAnalysis>,
    pub findings: Vec<AuthorityFinding>,
    pub visual: VisualGraph,
    pub plan_fingerprint: String,
    pub fingerprint_kind: FingerprintKind,
}

/// A secret-free representation of the inspected state.
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
    #[serde(default)]
    pub superuser: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
    #[error("could not serialize illustrative plan: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub fn analyze(request: AnalyzeRequest) -> Result<AnalyzeResponse, AnalysisError> {
    if request.schema_version != EXPLORER_SCHEMA_VERSION {
        return Err(AnalysisError::UnsupportedSchemaVersion(
            request.schema_version,
        ));
    }
    let manifest = parse_manifest(&request.desired_yaml)?;
    if manifest.roles.iter().any(|role| role.password.is_some()) {
        return Err(AnalysisError::PasswordSourceNotAllowed);
    }
    let expanded = expand_manifest(&manifest)?;
    let desired = RoleGraph::from_expanded(&expanded, manifest.default_owner.as_deref())?;
    let mut graph = request.current.into_graph();
    let mut set_role: BTreeMap<_, _> = request
        .executor
        .memberships
        .iter()
        .map(|fact| ((fact.role.clone(), fact.member.clone()), fact.set_role))
        .collect();
    // Memberships imported without PG16 option facts are possible SET paths,
    // but never proven ones. Explicit executor facts override this fallback.
    for edge in &graph.memberships {
        set_role
            .entry((edge.role.clone(), edge.member.clone()))
            .or_insert(SetRoleCapability::Unknown);
    }
    let mut usage: BTreeMap<_, _> = graph
        .memberships
        .iter()
        .map(|edge| {
            (
                (edge.role.clone(), edge.member.clone()),
                if edge.inherit {
                    SetRoleCapability::Allowed
                } else {
                    SetRoleCapability::Denied
                },
            )
        })
        .collect();
    for fact in &request.executor.memberships {
        usage.insert((fact.role.clone(), fact.member.clone()), fact.inherit);
    }
    let mut admin_options: BTreeMap<_, _> = request
        .executor
        .memberships
        .iter()
        .map(|fact| ((fact.role.clone(), fact.member.clone()), fact.admin_option))
        .collect();
    let mut changes = diff(&graph, &desired);
    changes = filter_external_role_changes(changes, &expanded.roles, &expanded.memberships);
    changes = apply_role_retirements(changes, &manifest.retirements);
    changes = filter_changes(changes, request.mode);

    let mut phases = Vec::new();
    let mut findings = Vec::new();
    let mut current_reachability = reachability(&graph, &set_role, &request.executor);
    let mut current_usage = reachability(&graph, &usage, &request.executor);
    let mut global_change_index = 0;
    for (phase, phase_changes) in grouped_phases(&changes) {
        let phase_usage_before = current_usage.clone();
        for change in &phase_changes {
            analyze_required_authority(
                change,
                phase,
                global_change_index,
                AuthorityState {
                    set_reachable: &current_reachability,
                    usage_reachable: &current_usage,
                    admin_options: &admin_options,
                    is_superuser: executor_is_superuser(&graph, &request.executor),
                },
                &mut findings,
            );
            apply_change(
                &mut graph,
                &mut set_role,
                &mut usage,
                &mut admin_options,
                &request.executor,
                change,
            );
            current_reachability = reachability(&graph, &set_role, &request.executor);
            current_usage = reachability(&graph, &usage, &request.executor);
            global_change_index += 1;
        }
        let after = reachability(&graph, &set_role, &request.executor);
        let usage_after = reachability(&graph, &usage, &request.executor);
        compare_reachability(phase, &phase_usage_before, &usage_after, &mut findings);
        phases.push(PhaseAnalysis {
            phase,
            changes: phase_changes,
            executor_reachability: after
                .iter()
                .map(|(role, status)| RoleReachability {
                    role: role.clone(),
                    status: *status,
                })
                .collect(),
            executor_usage: usage_after
                .iter()
                .map(|(role, status)| RoleReachability {
                    role: role.clone(),
                    status: *status,
                })
                .collect(),
        });
        current_reachability = after;
        current_usage = usage_after;
    }
    // `graph` is the simulated state after the mode-filtered plan. In additive
    // and adopt modes it can intentionally differ from raw desired state.
    let visual = build_visual_graph(&graph, VisualSource::Desired);
    let fingerprint_bytes = serde_json::to_vec(&(
        EXPLORER_SCHEMA_VERSION,
        request.mode.to_string(),
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
        changes,
        phases,
        findings,
        visual,
        plan_fingerprint,
        fingerprint_kind: FingerprintKind::Illustrative,
    })
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
        let mut grant_entry_grantors = BTreeMap::new();
        let grants = self
            .grants
            .into_iter()
            .map(|grant| {
                let key = GrantKey {
                    role: Grantee::parse(&grant.role),
                    object_type: grant.object_type,
                    schema: grant.schema,
                    name: grant.name,
                };
                if !grant.grantors.is_empty() {
                    grant_entry_grantors.insert(key.clone(), grant.grantors);
                }
                (
                    key,
                    GrantState {
                        privileges: grant.privileges,
                    },
                )
            })
            .collect();
        let default_privileges = self
            .default_privileges
            .into_iter()
            .map(|item| {
                (
                    DefaultPrivKey {
                        owner: item.owner,
                        scope: item.schema.map_or(DefaultPrivilegeScope::Global, |schema| {
                            DefaultPrivilegeScope::Schema { schema }
                        }),
                        on_type: item.on_type,
                        grantee: Grantee::parse(&item.grantee),
                    },
                    DefaultPrivState {
                        privileges: item.privileges,
                    },
                )
            })
            .collect();
        let mut memberships = BTreeSet::new();
        let mut membership_edge_grantors = BTreeMap::new();
        for item in self.memberships {
            if !item.grantors.is_empty() {
                membership_edge_grantors
                    .insert((item.role.clone(), item.member.clone()), item.grantors);
            }
            memberships.insert(MembershipEdge {
                role: item.role,
                member: item.member,
                inherit: item.inherit,
                admin: item.admin,
            });
        }
        RoleGraph {
            roles,
            schemas,
            grants,
            default_privileges,
            memberships,
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
    facts: &BTreeMap<(String, String), SetRoleCapability>,
    executor: &ExecutorFacts,
) -> BTreeMap<String, ReachabilityStatus> {
    if executor_is_superuser(graph, executor) {
        return graph
            .roles
            .keys()
            .cloned()
            .chain(
                facts
                    .keys()
                    .flat_map(|(role, member)| [role.clone(), member.clone()]),
            )
            .chain([executor.role.clone()])
            .map(|role| (role, ReachabilityStatus::Reachable))
            .collect();
    }
    let mut definite = BTreeSet::from([executor.role.clone()]);
    let mut possible = definite.clone();
    let mut queue = VecDeque::from([executor.role.clone()]);
    while let Some(member) = queue.pop_front() {
        for ((role, _), capability) in facts
            .iter()
            .filter(|((_, edge_member), _)| edge_member == &member)
        {
            if *capability == SetRoleCapability::Allowed && definite.insert(role.clone()) {
                queue.push_back(role.clone());
            }
        }
    }
    let mut queue = VecDeque::from_iter(possible.iter().cloned());
    while let Some(member) = queue.pop_front() {
        for ((role, _), capability) in facts
            .iter()
            .filter(|((_, edge_member), _)| edge_member == &member)
        {
            if *capability != SetRoleCapability::Denied && possible.insert(role.clone()) {
                queue.push_back(role.clone());
            }
        }
    }
    let all_roles: BTreeSet<_> = graph
        .roles
        .keys()
        .cloned()
        .chain(
            facts
                .keys()
                .flat_map(|(role, member)| [role.clone(), member.clone()]),
        )
        .chain([executor.role.clone()])
        .collect();
    all_roles
        .into_iter()
        .map(|role| {
            (
                role.clone(),
                if definite.contains(&role) {
                    ReachabilityStatus::Reachable
                } else if possible.contains(&role) {
                    ReachabilityStatus::Unknown
                } else {
                    ReachabilityStatus::Unreachable
                },
            )
        })
        .collect()
}

fn executor_is_superuser(graph: &RoleGraph, executor: &ExecutorFacts) -> bool {
    graph
        .roles
        .get(&executor.role)
        .map(|role| role.superuser)
        .unwrap_or(executor.superuser)
}

fn compare_reachability(
    phase: PlanPhase,
    before: &BTreeMap<String, ReachabilityStatus>,
    after: &BTreeMap<String, ReachabilityStatus>,
    findings: &mut Vec<AuthorityFinding>,
) {
    let roles: BTreeSet<_> = before.keys().chain(after.keys()).cloned().collect();
    for role in roles {
        let after_status = after
            .get(&role)
            .copied()
            .unwrap_or(ReachabilityStatus::Unreachable);
        let before_status = before
            .get(&role)
            .copied()
            .unwrap_or(ReachabilityStatus::Unreachable);
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
        });
    }
}

struct AuthorityState<'a> {
    set_reachable: &'a BTreeMap<String, ReachabilityStatus>,
    usage_reachable: &'a BTreeMap<String, ReachabilityStatus>,
    admin_options: &'a BTreeMap<(String, String), SetRoleCapability>,
    is_superuser: bool,
}

fn analyze_required_authority(
    change: &Change,
    phase: PlanPhase,
    index: usize,
    authority: AuthorityState<'_>,
    findings: &mut Vec<AuthorityFinding>,
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
            .unwrap_or(ReachabilityStatus::Unreachable);
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
            findings.push(AuthorityFinding {
                kind,
                severity,
                message: format!(
                    "required {authority_name} authority for grantor or owner role {role} {qualifier} for this operation"
                ),
                phase: Some(phase),
                change_index: Some(index),
                role: Some(role.clone()),
            });
        }
    }
    if !authority.is_superuser
        && let Change::AddMember { role, .. }
        | Change::RemoveMember {
            role,
            grantor: None,
            ..
        } = change
    {
        let admin_status = authority
            .admin_options
            .iter()
            .filter(|((granted_role, _), _)| granted_role == role)
            .map(|((_, member), admin)| {
                (
                    authority
                        .usage_reachable
                        .get(member)
                        .copied()
                        .unwrap_or(ReachabilityStatus::Unreachable),
                    *admin,
                )
            })
            .fold(
                ReachabilityStatus::Unreachable,
                |best, (member, admin)| match (member, admin) {
                    (ReachabilityStatus::Reachable, SetRoleCapability::Allowed) => {
                        ReachabilityStatus::Reachable
                    }
                    (
                        ReachabilityStatus::Reachable | ReachabilityStatus::Unknown,
                        SetRoleCapability::Unknown | SetRoleCapability::Allowed,
                    ) if best != ReachabilityStatus::Reachable => ReachabilityStatus::Unknown,
                    _ => best,
                },
            );
        if admin_status != ReachabilityStatus::Reachable {
            findings.push(AuthorityFinding {
                kind: FindingKind::RequiredRoleReachabilityUnknown,
                severity: FindingSeverity::Warning,
                message: format!(
                    "ADMIN OPTION for role {role} is not proven; database preflight is required"
                ),
                phase: Some(phase),
                change_index: Some(index),
                role: Some(role.clone()),
            });
        }
    }
    if matches!(
        change,
        Change::Grant { .. }
            | Change::Revoke { .. }
            | Change::AlterSchemaOwner { .. }
            | Change::EnsureSchemaOwnerPrivileges { .. }
            | Change::ReassignOwned { .. }
            | Change::DropOwned { .. }
            | Change::TerminateSessions { .. }
            | Change::DropRole { .. }
    ) {
        findings.push(AuthorityFinding {
            kind: FindingKind::DatabasePreflightRequired,
            severity: FindingSeverity::Warning,
            message: "this operation requires database ownership or privilege preflight".into(),
            phase: Some(phase),
            change_index: Some(index),
            role: None,
        });
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
                memberships: Vec::new(),
                new_membership_set_role: SetRoleCapability::Unknown,
                new_role_set_role: SetRoleCapability::Unknown,
                new_role_inherit: SetRoleCapability::Unknown,
                new_role_admin_option: SetRoleCapability::Unknown,
            },
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
}
