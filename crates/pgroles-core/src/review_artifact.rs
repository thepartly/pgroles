//! Portable, sanitized review artifacts built from an already-produced plan.
//!
//! A review artifact is a versioned file format that the docs explorer imports
//! without replanning. Every type in it is owned by this module instead of
//! being borrowed from the explorer's analysis DTOs, so the wire format changes
//! only together with [`REVIEW_ARTIFACT_SCHEMA_VERSION`]. The generated JSON
//! Schema lives at `docs/public/generated/review-artifact.schema.json`
//! (`cargo run -p pgroles-core --example review_artifact_schema`).

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::diff::{Change, ReconciliationMode};
use crate::explorer::{
    AuthorityFinding, DEFAULT_PG_MAJOR_VERSION, ExecutorFacts, FindingKind, FindingSeverity,
    PlanAnalysis, PlanAnalysisOptions, PlanPhase, ReachabilityStatus, RoleReachability,
    analyze_changes_with_options,
};
use crate::manifest::{ObjectType, Privilege, SchemaBindingFacet};
use crate::model::{DefaultPrivilegeScope, RoleAttribute, RoleGraph, RoleState};
use crate::ownership::ManagedScope;
use crate::report::{BundleChangeOwner, ManagedOwnershipKey};
use crate::review::{ReviewPriority, priority};
use crate::sql::SqlContext;
use crate::visual::{
    EdgeKind, NodeKind, VisualEdge, VisualGraph, VisualManagedScope, VisualMeta, VisualNode,
    VisualSource,
};

/// Version 2 records each phase's executor reachability as a delta from the
/// previous phase (see [`RecordedPhase`]); version 1 repeated every role in
/// every phase.
pub const REVIEW_ARTIFACT_SCHEMA_VERSION: &str = "pgroles.review-artifact.v2";
pub const MAX_REVIEW_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ReviewArtifactInput<'a> {
    pub provenance: ReviewProvenance,
    pub context: ReviewContext,
    pub preflight: Vec<PreflightEvidence>,
    pub current: RoleGraph,
    pub changes: &'a [Change],
    /// Optional bundle ownership metadata in the same order as `changes`.
    pub change_sources: Option<&'a [BundleChangeOwner]>,
    pub executor_facts: ExecutorFacts,
    pub sql_context: &'a SqlContext,
    pub exploration: ReviewExploration,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewArtifact {
    pub schema_version: String,
    pub provenance: ReviewProvenance,
    pub context: ReviewContext,
    pub preflight: Vec<PreflightEvidence>,
    pub recorded: RecordedReview,
    pub exploration: ReviewExploration,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewProvenance {
    pub tool_version: String,
    /// Caller-supplied RFC 3339 capture time.
    pub captured_at: String,
    pub policy: PolicyProvenance,
    /// Human-readable target label; never a connection URL.
    pub target_label: String,
    pub pg_major_version: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyProvenance {
    /// SHA-256 digest of the policy content, prefixed with `sha256:`.
    pub content_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

impl PolicyProvenance {
    pub fn from_content(content: &[u8], commit: Option<String>) -> Self {
        Self {
            content_digest: format!("sha256:{}", hex_digest(Sha256::digest(content).as_slice())),
            commit,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewContext {
    pub mode: ReviewMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_scope: Option<ReviewManagedScope>,
    pub inspector: ReviewIdentity,
    pub intended_executor: ReviewIdentity,
    pub authority_graph_complete: bool,
}

/// Roles and schema facets the reviewed policy manages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewManagedScope {
    pub roles: Vec<String>,
    pub schemas: Vec<ReviewManagedSchema>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewManagedSchema {
    pub name: String,
    pub owner: bool,
    pub bindings: bool,
}

impl From<VisualManagedScope> for ReviewManagedScope {
    fn from(value: VisualManagedScope) -> Self {
        Self {
            roles: value.roles,
            schemas: value
                .schemas
                .into_iter()
                .map(|schema| ReviewManagedSchema {
                    name: schema.name,
                    owner: schema.owner,
                    bindings: schema.bindings,
                })
                .collect(),
        }
    }
}

impl From<&ManagedScope> for ReviewManagedScope {
    fn from(value: &ManagedScope) -> Self {
        VisualManagedScope::from(value).into()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewIdentity {
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superuser: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewMode {
    Authoritative,
    Additive,
    Adopt,
}

impl From<ReconciliationMode> for ReviewMode {
    fn from(value: ReconciliationMode) -> Self {
        match value {
            ReconciliationMode::Authoritative => Self::Authoritative,
            ReconciliationMode::Additive => Self::Additive,
            ReconciliationMode::Adopt => Self::Adopt,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreflightEvidence {
    pub check: PreflightCheck,
    pub status: EvidenceStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_role: Option<String>,
    pub issue_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<PreflightFinding>,
    pub coverage: EvidenceCoverage,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCoverage {
    pub kind: EvidenceCoverageKind,
    /// Targeted probe families that actually ran. Their success does not
    /// establish complete authority for a change.
    pub checks_performed: Vec<EvidenceCheck>,
    /// Changes considered by at least one targeted probe.
    pub checked_change_indices: Vec<usize>,
    /// Changes outside every recorded probe's scope.
    pub unchecked_change_indices: Vec<usize>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCheck {
    DefaultPrivilegeOwner,
    PredefinedRoleMembership,
    GrantorReachability,
    RevokeAclOwnership,
    PlanOrderAuthority,
    DropRoleSafety,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCoverageKind {
    Complete,
    Targeted,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreflightFinding {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PreflightCheck {
    ExecutorAuthority,
    RoleDropSafety,
    ServerCompatibility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Passed,
    Failed,
    NotRun,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordedReview {
    pub changes: Vec<RecordedChange>,
    pub phases: Vec<RecordedPhase>,
    pub findings: Vec<RecordedFinding>,
    pub visual: ReviewVisualGraph,
    pub sql_preview: SqlPreview,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omissions: Vec<ReviewOmission>,
    pub review_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordedChange {
    pub index: usize,
    pub priority: ReviewPriority,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<ReviewChangeSource>,
    pub change: ReviewChange,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omissions: Vec<ReviewOmission>,
}

/// The bundle document that owns a change, and the managed key it owns it by.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewChangeSource {
    pub document: String,
    pub managed_key: ReviewManagedKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReviewManagedKey {
    Role {
        name: String,
    },
    SchemaFacet {
        schema: String,
        facet: SchemaBindingFacet,
    },
    Grant {
        role: String,
        object_type: ObjectType,
        schema: Option<String>,
        name: Option<String>,
    },
    DefaultPrivilege {
        owner: String,
        scope: ReviewDefaultPrivilegeScope,
        on_type: ObjectType,
        grantee: String,
    },
    Membership {
        role: String,
        member: String,
    },
}

impl From<&BundleChangeOwner> for ReviewChangeSource {
    fn from(value: &BundleChangeOwner) -> Self {
        let managed_key = match &value.managed_key {
            ManagedOwnershipKey::Role { name } => ReviewManagedKey::Role { name: name.clone() },
            ManagedOwnershipKey::SchemaFacet { schema, facet } => ReviewManagedKey::SchemaFacet {
                schema: schema.clone(),
                facet: *facet,
            },
            ManagedOwnershipKey::Grant {
                role,
                object_type,
                schema,
                name,
            } => ReviewManagedKey::Grant {
                role: role.to_string(),
                object_type: *object_type,
                schema: schema.clone(),
                name: name.clone(),
            },
            ManagedOwnershipKey::DefaultPrivilege {
                owner,
                scope,
                on_type,
                grantee,
            } => ReviewManagedKey::DefaultPrivilege {
                owner: owner.clone(),
                scope: scope.into(),
                on_type: *on_type,
                grantee: grantee.to_string(),
            },
            ManagedOwnershipKey::Membership { role, member } => ReviewManagedKey::Membership {
                role: role.clone(),
                member: member.clone(),
            },
        };
        Self {
            document: value.document.clone(),
            managed_key,
        }
    }
}

/// Where a default-privilege rule applies; `global` is the owner-wide layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum ReviewDefaultPrivilegeScope {
    Global,
    Schema { schema: String },
}

impl From<&DefaultPrivilegeScope> for ReviewDefaultPrivilegeScope {
    fn from(value: &DefaultPrivilegeScope) -> Self {
        match value {
            DefaultPrivilegeScope::Global => Self::Global,
            DefaultPrivilegeScope::Schema { schema } => Self::Schema {
                schema: schema.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewOmission {
    pub field: String,
    pub reason: OmissionReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OmissionReason {
    SensitiveValue,
}

/// One contiguous run of same-phase changes, in plan order.
///
/// Executor reachability is recorded as deltas so that artifact size tracks
/// what changes rather than roles times phases. The state before the first
/// phase is empty. The state after a phase is the previous phase's state with
/// every `removed` role deleted and then every `changed` entry inserted or
/// replaced, so the first phase's `changed` list is its complete state.
/// `RecordedReview::phase_reachability` performs this fold.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordedPhase {
    pub phase: ReviewPhase,
    pub change_indices: Vec<usize>,
    /// Change in the roles the intended executor can `SET ROLE` to.
    pub executor_reachability_delta: ReviewReachabilityDelta,
    /// Change in the roles whose privileges the intended executor inherits.
    pub executor_usage_delta: ReviewReachabilityDelta,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewReachabilityDelta {
    /// Roles whose status is new or different after this phase, sorted by
    /// role name.
    pub changed: Vec<ReviewReachability>,
    /// Roles present after the previous phase and absent after this one,
    /// sorted. Never overlaps `changed`.
    pub removed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewReachability {
    pub role: String,
    pub status: ReviewReachabilityStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewReachabilityStatus {
    Reachable,
    Unreachable,
    Unknown,
}

impl From<ReachabilityStatus> for ReviewReachabilityStatus {
    fn from(value: ReachabilityStatus) -> Self {
        match value {
            ReachabilityStatus::Reachable => Self::Reachable,
            ReachabilityStatus::Unreachable => Self::Unreachable,
            ReachabilityStatus::Unknown => Self::Unknown,
        }
    }
}

/// Complete executor reachability after one recorded phase.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhaseReachability {
    pub executor_reachability: BTreeMap<String, ReviewReachabilityStatus>,
    pub executor_usage: BTreeMap<String, ReviewReachabilityStatus>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewPhase {
    Create,
    Alter,
    Grant,
    MembershipRemove,
    MembershipAdd,
    Revoke,
    DefaultPrivilegeRevoke,
    Retire,
}

impl From<PlanPhase> for ReviewPhase {
    fn from(value: PlanPhase) -> Self {
        match value {
            PlanPhase::Create => Self::Create,
            PlanPhase::Alter => Self::Alter,
            PlanPhase::Grant => Self::Grant,
            PlanPhase::MembershipRemove => Self::MembershipRemove,
            PlanPhase::MembershipAdd => Self::MembershipAdd,
            PlanPhase::Revoke => Self::Revoke,
            PlanPhase::DefaultPrivilegeRevoke => Self::DefaultPrivilegeRevoke,
            PlanPhase::Retire => Self::Retire,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordedFinding {
    pub kind: ReviewFindingKind,
    pub severity: ReviewFindingSeverity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<ReviewPhase>,
    /// The first affected change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_index: Option<usize>,
    /// Every affected change, when a finding aggregates several.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub change_indices: Vec<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewFindingKind {
    RequiredRoleUnavailable,
    RequiredRoleReachabilityUnknown,
    ExecutorLosesAccess,
    MembershipDisconnectsRole,
    RoleBecomesReachable,
    DatabasePreflightRequired,
    SuperuserRequired,
    OwnershipTransferChangesGrantor,
}

impl From<FindingKind> for ReviewFindingKind {
    fn from(value: FindingKind) -> Self {
        match value {
            FindingKind::RequiredRoleUnavailable => Self::RequiredRoleUnavailable,
            FindingKind::RequiredRoleReachabilityUnknown => Self::RequiredRoleReachabilityUnknown,
            FindingKind::ExecutorLosesAccess => Self::ExecutorLosesAccess,
            FindingKind::MembershipDisconnectsRole => Self::MembershipDisconnectsRole,
            FindingKind::RoleBecomesReachable => Self::RoleBecomesReachable,
            FindingKind::DatabasePreflightRequired => Self::DatabasePreflightRequired,
            FindingKind::SuperuserRequired => Self::SuperuserRequired,
            FindingKind::OwnershipTransferChangesGrantor => Self::OwnershipTransferChangesGrantor,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewFindingSeverity {
    Info,
    Warning,
    Error,
}

impl From<FindingSeverity> for ReviewFindingSeverity {
    fn from(value: FindingSeverity) -> Self {
        match value {
            FindingSeverity::Info => Self::Info,
            FindingSeverity::Warning => Self::Warning,
            FindingSeverity::Error => Self::Error,
        }
    }
}

impl From<&AuthorityFinding> for RecordedFinding {
    fn from(value: &AuthorityFinding) -> Self {
        Self {
            kind: value.kind.into(),
            severity: value.severity.into(),
            phase: value.phase.map(Into::into),
            change_index: value.change_index,
            change_indices: value.change_indices.clone(),
            role: value.role.clone(),
            message: value.message.clone(),
        }
    }
}

/// The simulated post-plan role graph, without role comments.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewVisualGraph {
    pub schema_version: String,
    pub meta: ReviewVisualMeta,
    pub nodes: Vec<ReviewVisualNode>,
    pub edges: Vec<ReviewVisualEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewVisualMeta {
    pub source: ReviewVisualSource,
    pub role_count: usize,
    pub grant_count: usize,
    pub default_privilege_count: usize,
    pub membership_count: usize,
    pub collapsed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_scope: Option<ReviewManagedScope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVisualSource {
    Desired,
    Current,
}

/// A graph node. Role comments are never recorded, so there is no comment
/// field to populate.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewVisualNode {
    pub id: String,
    pub label: String,
    pub kind: ReviewNodeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub privileges: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewNodeKind {
    Role,
    ExternalPrincipal,
    GrantTarget,
    DefaultPrivilegeTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewVisualEdge {
    pub source: String,
    pub target: String,
    pub kind: ReviewEdgeKind,
    pub label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewEdgeKind {
    Membership,
    Grant,
    DefaultPrivilege,
}

impl ReviewVisualGraph {
    /// Convert an analysis graph, dropping role comments. Returns whether any
    /// comment was dropped so the omission can be recorded.
    fn sanitized(graph: VisualGraph) -> (Self, bool) {
        let VisualGraph {
            schema_version,
            meta,
            nodes,
            edges,
        } = graph;
        let VisualMeta {
            source,
            role_count,
            grant_count,
            default_privilege_count,
            membership_count,
            collapsed,
            managed_scope,
        } = meta;
        let comment_omitted = nodes.iter().any(|node| node.comment.is_some());
        let graph = Self {
            schema_version,
            meta: ReviewVisualMeta {
                source: match source {
                    VisualSource::Desired => ReviewVisualSource::Desired,
                    VisualSource::Current => ReviewVisualSource::Current,
                },
                role_count,
                grant_count,
                default_privilege_count,
                membership_count,
                collapsed,
                managed_scope: managed_scope.map(Into::into),
            },
            nodes: nodes
                .into_iter()
                .map(|node| {
                    let VisualNode {
                        id,
                        label,
                        kind,
                        managed,
                        login,
                        privileges,
                        comment: _,
                    } = node;
                    ReviewVisualNode {
                        id,
                        label,
                        kind: match kind {
                            NodeKind::Role => ReviewNodeKind::Role,
                            NodeKind::ExternalPrincipal => ReviewNodeKind::ExternalPrincipal,
                            NodeKind::GrantTarget => ReviewNodeKind::GrantTarget,
                            NodeKind::DefaultPrivilegeTarget => {
                                ReviewNodeKind::DefaultPrivilegeTarget
                            }
                        },
                        managed,
                        login,
                        privileges,
                    }
                })
                .collect(),
            edges: edges
                .into_iter()
                .map(|edge| {
                    let VisualEdge {
                        source,
                        target,
                        kind,
                        label,
                    } = edge;
                    ReviewVisualEdge {
                        source,
                        target,
                        kind: match kind {
                            EdgeKind::Membership => ReviewEdgeKind::Membership,
                            EdgeKind::Grant => ReviewEdgeKind::Grant,
                            EdgeKind::DefaultPrivilege => ReviewEdgeKind::DefaultPrivilege,
                        },
                        label,
                    }
                })
                .collect(),
        };
        (graph, comment_omitted)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum SqlPreview {
    Available {
        sql: String,
    },
    Omitted {
        reason: SqlOmissionReason,
        sensitive_change_indices: Vec<usize>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SqlOmissionReason {
    SensitiveChanges,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReviewExploration {
    Omitted { reason: ExplorationOmissionReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExplorationOmissionReason {
    RecordedOnlyExport,
    SensitiveInputsRemoved,
}

#[derive(Debug, Error)]
pub enum ReviewArtifactError {
    #[error("could not serialize review artifact fingerprint: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("review artifact has {actual} bytes, which exceeds the limit of {limit}")]
    TooLarge { actual: usize, limit: usize },
    #[error("review artifact has {sources} change sources for {changes} changes")]
    ChangeSourceCount { sources: usize, changes: usize },
    #[error("review artifact is malformed: {0}")]
    Malformed(#[source] serde_json::Error),
    #[error("unsupported review artifact schema version: {0}")]
    UnsupportedSchemaVersion(String),
    #[error("review artifact change indices are inconsistent: {0}")]
    InconsistentIndices(&'static str),
    #[error("review artifact phase {phase} has an invalid reachability delta: {reason}")]
    InvalidReachabilityDelta { phase: usize, reason: &'static str },
    #[error("review artifact fingerprint {recorded} does not match its content ({computed})")]
    FingerprintMismatch { recorded: String, computed: String },
}

pub fn build_review_artifact(
    input: ReviewArtifactInput<'_>,
) -> Result<ReviewArtifact, ReviewArtifactError> {
    if let Some(sources) = input.change_sources
        && sources.len() != input.changes.len()
    {
        return Err(ReviewArtifactError::ChangeSourceCount {
            sources: sources.len(),
            changes: input.changes.len(),
        });
    }
    let analysis = analyze_changes_with_options(
        input.current,
        input.changes,
        &input.executor_facts,
        PlanAnalysisOptions {
            authority_graph_complete: input.context.authority_graph_complete,
            pg_major_version: u16::try_from(input.provenance.pg_major_version)
                .unwrap_or(DEFAULT_PG_MAJOR_VERSION),
        },
    );
    let changes: Vec<_> = input
        .changes
        .iter()
        .enumerate()
        .map(|(index, change)| {
            let (sanitized, omissions) = ReviewChange::sanitize(change);
            RecordedChange {
                index,
                priority: priority(change),
                source: input
                    .change_sources
                    .and_then(|sources| sources.get(index))
                    .map(ReviewChangeSource::from),
                change: sanitized,
                omissions,
            }
        })
        .collect();
    let phases = recorded_phases(&analysis);
    let findings = analysis
        .findings
        .iter()
        .map(RecordedFinding::from)
        .collect::<Vec<_>>();
    let (visual, visual_comment_omitted) = ReviewVisualGraph::sanitized(analysis.visual);
    let sensitive_change_indices = changes
        .iter()
        .filter(|change| !change.omissions.is_empty())
        .map(|change| change.index)
        .collect::<Vec<_>>();
    let sql_preview = if sensitive_change_indices.is_empty() {
        SqlPreview::Available {
            sql: crate::sql::render_all_with_context(input.changes, input.sql_context),
        }
    } else {
        SqlPreview::Omitted {
            reason: SqlOmissionReason::SensitiveChanges,
            sensitive_change_indices,
        }
    };
    let omissions = visual_comment_omitted
        .then(|| ReviewOmission {
            field: "visual.nodes[].comment".to_string(),
            reason: OmissionReason::SensitiveValue,
        })
        .into_iter()
        .collect::<Vec<_>>();
    let mut artifact = ReviewArtifact {
        schema_version: REVIEW_ARTIFACT_SCHEMA_VERSION.to_string(),
        provenance: input.provenance,
        context: input.context,
        preflight: input.preflight,
        recorded: RecordedReview {
            changes,
            phases,
            findings,
            visual,
            sql_preview,
            omissions,
            review_fingerprint: String::new(),
        },
        exploration: input.exploration,
    };
    artifact.recorded.review_fingerprint = artifact.computed_review_fingerprint()?;
    let actual = serde_json::to_vec_pretty(&artifact)?.len();
    if actual > MAX_REVIEW_ARTIFACT_BYTES {
        return Err(ReviewArtifactError::TooLarge {
            actual,
            limit: MAX_REVIEW_ARTIFACT_BYTES,
        });
    }
    Ok(artifact)
}

impl ReviewArtifact {
    /// Recompute `recorded.review_fingerprint` from the artifact's content.
    ///
    /// The fingerprint covers the schema version, policy provenance, target
    /// label, PostgreSQL major version, context, preflight evidence, and every
    /// recorded field except the fingerprint itself. Tool version and capture
    /// time are excluded, so identical plans captured at different times match.
    pub fn computed_review_fingerprint(&self) -> Result<String, ReviewArtifactError> {
        let recorded = &self.recorded;
        let bytes = serde_json::to_vec(&(
            &self.schema_version,
            &self.provenance.policy,
            &self.provenance.target_label,
            self.provenance.pg_major_version,
            &self.context,
            &self.preflight,
            &recorded.changes,
            &recorded.phases,
            &recorded.findings,
            &recorded.visual,
            &recorded.sql_preview,
            &recorded.omissions,
        ))?;
        Ok(format!(
            "sha256:{}",
            hex_digest(Sha256::digest(bytes).as_slice())
        ))
    }
}

/// Parse a review artifact and check what its schema cannot express: the size
/// limit, schema version, change-index partition, reachability deltas, and
/// fingerprint. The fingerprint detects accidental edits; it does not
/// authenticate the file.
pub fn parse_review_artifact(json: &[u8]) -> Result<ReviewArtifact, ReviewArtifactError> {
    if json.len() > MAX_REVIEW_ARTIFACT_BYTES {
        return Err(ReviewArtifactError::TooLarge {
            actual: json.len(),
            limit: MAX_REVIEW_ARTIFACT_BYTES,
        });
    }
    // Report another version as such, not as the shape errors it would cause.
    #[derive(Deserialize)]
    struct VersionProbe {
        schema_version: String,
    }
    let probe: VersionProbe =
        serde_json::from_slice(json).map_err(ReviewArtifactError::Malformed)?;
    if probe.schema_version != REVIEW_ARTIFACT_SCHEMA_VERSION {
        return Err(ReviewArtifactError::UnsupportedSchemaVersion(
            probe.schema_version,
        ));
    }
    let artifact: ReviewArtifact =
        serde_json::from_slice(json).map_err(ReviewArtifactError::Malformed)?;
    let recorded = &artifact.recorded;
    let count = recorded.changes.len();
    if recorded
        .changes
        .iter()
        .enumerate()
        .any(|(position, change)| change.index != position)
    {
        return Err(ReviewArtifactError::InconsistentIndices(
            "changes are not indexed in order from zero",
        ));
    }
    if !recorded
        .phases
        .iter()
        .flat_map(|phase| phase.change_indices.iter().copied())
        .eq(0..count)
        || recorded
            .phases
            .iter()
            .any(|phase| phase.change_indices.is_empty())
    {
        return Err(ReviewArtifactError::InconsistentIndices(
            "phases do not partition the changes in order",
        ));
    }
    let mut referenced = recorded
        .findings
        .iter()
        .flat_map(|finding| finding.change_index.iter().chain(&finding.change_indices))
        .chain(artifact.preflight.iter().flat_map(|evidence| {
            evidence
                .coverage
                .checked_change_indices
                .iter()
                .chain(&evidence.coverage.unchecked_change_indices)
        }))
        .chain(match &recorded.sql_preview {
            SqlPreview::Available { .. } => [].iter(),
            SqlPreview::Omitted {
                sensitive_change_indices,
                ..
            } => sensitive_change_indices.iter(),
        });
    if referenced.any(|index| *index >= count) {
        return Err(ReviewArtifactError::InconsistentIndices(
            "an index refers to a change that does not exist",
        ));
    }
    recorded.phase_reachability()?;
    let computed = artifact.computed_review_fingerprint()?;
    if computed != recorded.review_fingerprint {
        return Err(ReviewArtifactError::FingerprintMismatch {
            recorded: recorded.review_fingerprint.clone(),
            computed,
        });
    }
    Ok(artifact)
}

impl RecordedReview {
    /// Rebuild complete executor reachability after each phase by folding the
    /// recorded deltas, rejecting deltas the exporter never produces.
    pub fn phase_reachability(&self) -> Result<Vec<PhaseReachability>, ReviewArtifactError> {
        let mut state = PhaseReachability::default();
        self.phases
            .iter()
            .enumerate()
            .map(|(phase, recorded)| {
                apply_reachability_delta(
                    &mut state.executor_reachability,
                    &recorded.executor_reachability_delta,
                    phase,
                )?;
                apply_reachability_delta(
                    &mut state.executor_usage,
                    &recorded.executor_usage_delta,
                    phase,
                )?;
                Ok(state.clone())
            })
            .collect()
    }
}

fn apply_reachability_delta(
    state: &mut BTreeMap<String, ReviewReachabilityStatus>,
    delta: &ReviewReachabilityDelta,
    phase: usize,
) -> Result<(), ReviewArtifactError> {
    let invalid = |reason| ReviewArtifactError::InvalidReachabilityDelta { phase, reason };
    if !is_strictly_sorted(delta.changed.iter().map(|entry| entry.role.as_str()))
        || !is_strictly_sorted(delta.removed.iter().map(String::as_str))
    {
        return Err(invalid("roles are not sorted and unique"));
    }
    for role in &delta.removed {
        if state.remove(role).is_none() {
            return Err(invalid("removes a role absent from the previous phase"));
        }
    }
    for entry in &delta.changed {
        if delta.removed.binary_search(&entry.role).is_ok() {
            return Err(invalid("lists a role as both changed and removed"));
        }
        if state.insert(entry.role.clone(), entry.status) == Some(entry.status) {
            return Err(invalid("records a status that did not change"));
        }
    }
    Ok(())
}

fn is_strictly_sorted<'a>(mut roles: impl Iterator<Item = &'a str>) -> bool {
    let Some(mut previous) = roles.next() else {
        return true;
    };
    for role in roles {
        if role <= previous {
            return false;
        }
        previous = role;
    }
    true
}

fn recorded_phases(analysis: &PlanAnalysis) -> Vec<RecordedPhase> {
    let mut next_index = 0;
    let mut reachability = BTreeMap::new();
    let mut usage = BTreeMap::new();
    analysis
        .phases
        .iter()
        .map(|phase| {
            let change_indices = (next_index..next_index + phase.changes.len()).collect();
            next_index += phase.changes.len();
            RecordedPhase {
                phase: phase.phase.into(),
                change_indices,
                executor_reachability_delta: reachability_delta(
                    &mut reachability,
                    &phase.executor_reachability,
                ),
                executor_usage_delta: reachability_delta(&mut usage, &phase.executor_usage),
            }
        })
        .collect()
}

/// Diff one phase's complete reachability against the previous phase's and
/// advance `previous` to it.
fn reachability_delta(
    previous: &mut BTreeMap<String, ReviewReachabilityStatus>,
    after: &[RoleReachability],
) -> ReviewReachabilityDelta {
    let after: BTreeMap<String, ReviewReachabilityStatus> = after
        .iter()
        .map(|entry| (entry.role.clone(), entry.status.into()))
        .collect();
    let removed = previous
        .keys()
        .filter(|role| !after.contains_key(*role))
        .cloned()
        .collect();
    let changed = after
        .iter()
        .filter(|(role, status)| previous.get(*role) != Some(status))
        .map(|(role, status)| ReviewReachability {
            role: role.clone(),
            status: *status,
        })
        .collect();
    *previous = after;
    ReviewReachabilityDelta { changed, removed }
}
/// A plan change with sensitive values removed. Omitted values are listed in
/// the owning recorded change's `omissions`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReviewChange {
    CreateRole {
        name: String,
        state: ReviewRoleState,
    },
    CreateSchema {
        name: String,
        owner: Option<String>,
    },
    AlterSchemaOwner {
        name: String,
        owner: String,
    },
    EnsureSchemaOwnerPrivileges {
        name: String,
        owner: String,
        privileges: BTreeSet<Privilege>,
    },
    AlterRole {
        name: String,
        attributes: Vec<ReviewRoleAttribute>,
    },
    SetComment {
        name: String,
        comment_present: bool,
    },
    Grant {
        role: String,
        privileges: BTreeSet<Privilege>,
        object_type: ObjectType,
        schema: Option<String>,
        name: Option<String>,
    },
    Revoke {
        role: String,
        privileges: BTreeSet<Privilege>,
        object_type: ObjectType,
        schema: Option<String>,
        name: Option<String>,
        grantor: Option<String>,
    },
    SetDefaultPrivilege {
        owner: String,
        scope: ReviewDefaultPrivilegeScope,
        on_type: ObjectType,
        grantee: String,
        privileges: BTreeSet<Privilege>,
    },
    RevokeDefaultPrivilege {
        owner: String,
        scope: ReviewDefaultPrivilegeScope,
        on_type: ObjectType,
        grantee: String,
        privileges: BTreeSet<Privilege>,
    },
    AddMember {
        role: String,
        member: String,
        inherit: bool,
        admin: bool,
    },
    RemoveMember {
        role: String,
        member: String,
        grantor: Option<String>,
    },
    ReassignOwned {
        from_role: String,
        to_role: String,
    },
    DropOwned {
        role: String,
    },
    TerminateSessions {
        role: String,
    },
    SetPassword {
        name: String,
    },
    DropRole {
        name: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewRoleState {
    pub login: bool,
    pub superuser: bool,
    pub createdb: bool,
    pub createrole: bool,
    pub inherit: bool,
    pub replication: bool,
    pub bypassrls: bool,
    pub connection_limit: i32,
    pub comment_present: bool,
    pub password_valid_until: Option<String>,
    pub config_parameters: Vec<String>,
}

impl From<&RoleState> for ReviewRoleState {
    fn from(value: &RoleState) -> Self {
        Self {
            login: value.login,
            superuser: value.superuser,
            createdb: value.createdb,
            createrole: value.createrole,
            inherit: value.inherit,
            replication: value.replication,
            bypassrls: value.bypassrls,
            connection_limit: value.connection_limit,
            comment_present: value.comment.is_some(),
            password_valid_until: value.password_valid_until.clone(),
            config_parameters: value.config.keys().cloned().collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReviewRoleAttribute {
    Login { value: bool },
    Superuser { value: bool },
    Createdb { value: bool },
    Createrole { value: bool },
    Inherit { value: bool },
    Replication { value: bool },
    Bypassrls { value: bool },
    ConnectionLimit { value: i32 },
    ValidUntil { value: Option<String> },
    SetConfig { parameter: String },
    ResetConfig { parameter: String },
}

impl ReviewChange {
    fn sanitize(change: &Change) -> (Self, Vec<ReviewOmission>) {
        let mut omissions = Vec::new();
        let sanitized = match change {
            Change::CreateRole { name, state } => {
                if state.comment.is_some() {
                    omit(&mut omissions, "state.comment");
                }
                if !state.config.is_empty() {
                    omit(&mut omissions, "state.config.values");
                }
                Self::CreateRole {
                    name: name.clone(),
                    state: ReviewRoleState::from(state),
                }
            }
            Change::CreateSchema { name, owner } => Self::CreateSchema {
                name: name.clone(),
                owner: owner.clone(),
            },
            Change::AlterSchemaOwner { name, owner } => Self::AlterSchemaOwner {
                name: name.clone(),
                owner: owner.clone(),
            },
            Change::EnsureSchemaOwnerPrivileges {
                name,
                owner,
                privileges,
            } => Self::EnsureSchemaOwnerPrivileges {
                name: name.clone(),
                owner: owner.clone(),
                privileges: privileges.clone(),
            },
            Change::AlterRole { name, attributes } => Self::AlterRole {
                name: name.clone(),
                attributes: attributes
                    .iter()
                    .map(|attribute| sanitize_attribute(attribute, &mut omissions))
                    .collect(),
            },
            Change::SetComment { name, comment } => {
                if comment.is_some() {
                    omit(&mut omissions, "comment");
                }
                Self::SetComment {
                    name: name.clone(),
                    comment_present: comment.is_some(),
                }
            }
            Change::Grant {
                role,
                privileges,
                object_type,
                schema,
                name,
            } => Self::Grant {
                role: role.to_string(),
                privileges: privileges.clone(),
                object_type: *object_type,
                schema: schema.clone(),
                name: name.clone(),
            },
            Change::Revoke {
                role,
                privileges,
                object_type,
                schema,
                name,
                grantor,
            } => Self::Revoke {
                role: role.to_string(),
                privileges: privileges.clone(),
                object_type: *object_type,
                schema: schema.clone(),
                name: name.clone(),
                grantor: grantor.clone(),
            },
            Change::SetDefaultPrivilege {
                owner,
                scope,
                on_type,
                grantee,
                privileges,
            } => Self::SetDefaultPrivilege {
                owner: owner.clone(),
                scope: scope.into(),
                on_type: *on_type,
                grantee: grantee.to_string(),
                privileges: privileges.clone(),
            },
            Change::RevokeDefaultPrivilege {
                owner,
                scope,
                on_type,
                grantee,
                privileges,
            } => Self::RevokeDefaultPrivilege {
                owner: owner.clone(),
                scope: scope.into(),
                on_type: *on_type,
                grantee: grantee.to_string(),
                privileges: privileges.clone(),
            },
            Change::AddMember {
                role,
                member,
                inherit,
                admin,
            } => Self::AddMember {
                role: role.clone(),
                member: member.clone(),
                inherit: *inherit,
                admin: *admin,
            },
            Change::RemoveMember {
                role,
                member,
                grantor,
            } => Self::RemoveMember {
                role: role.clone(),
                member: member.clone(),
                grantor: grantor.clone(),
            },
            Change::ReassignOwned { from_role, to_role } => Self::ReassignOwned {
                from_role: from_role.clone(),
                to_role: to_role.clone(),
            },
            Change::DropOwned { role } => Self::DropOwned { role: role.clone() },
            Change::TerminateSessions { role } => Self::TerminateSessions { role: role.clone() },
            Change::SetPassword { name, .. } => {
                omit(&mut omissions, "password");
                Self::SetPassword { name: name.clone() }
            }
            Change::DropRole { name } => Self::DropRole { name: name.clone() },
        };
        (sanitized, omissions)
    }
}

fn sanitize_attribute(
    attribute: &RoleAttribute,
    omissions: &mut Vec<ReviewOmission>,
) -> ReviewRoleAttribute {
    match attribute {
        RoleAttribute::Login(value) => ReviewRoleAttribute::Login { value: *value },
        RoleAttribute::Superuser(value) => ReviewRoleAttribute::Superuser { value: *value },
        RoleAttribute::Createdb(value) => ReviewRoleAttribute::Createdb { value: *value },
        RoleAttribute::Createrole(value) => ReviewRoleAttribute::Createrole { value: *value },
        RoleAttribute::Inherit(value) => ReviewRoleAttribute::Inherit { value: *value },
        RoleAttribute::Replication(value) => ReviewRoleAttribute::Replication { value: *value },
        RoleAttribute::Bypassrls(value) => ReviewRoleAttribute::Bypassrls { value: *value },
        RoleAttribute::ConnectionLimit(value) => {
            ReviewRoleAttribute::ConnectionLimit { value: *value }
        }
        RoleAttribute::ValidUntil(value) => ReviewRoleAttribute::ValidUntil {
            value: value.clone(),
        },
        RoleAttribute::SetConfig(parameter, _) => {
            omit(omissions, "attributes[].value");
            ReviewRoleAttribute::SetConfig {
                parameter: parameter.clone(),
            }
        }
        RoleAttribute::ResetConfig(parameter) => ReviewRoleAttribute::ResetConfig {
            parameter: parameter.clone(),
        },
    }
}

fn omit(omissions: &mut Vec<ReviewOmission>, field: &str) {
    omissions.push(ReviewOmission {
        field: field.to_string(),
        reason: OmissionReason::SensitiveValue,
    });
}

fn hex_digest(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::explorer::analyze_changes;
    use crate::model::{GrantState, Grantee, MembershipEdge, RoleState};
    use crate::report::ManagedOwnershipKey;
    use std::collections::BTreeMap;

    fn executor(role: &str) -> ExecutorFacts {
        ExecutorFacts {
            role: role.into(),
            superuser: false,
            createrole: Default::default(),
            memberships: Vec::new(),
            new_membership_set_role: Default::default(),
            new_role_set_role: Default::default(),
            new_role_inherit: Default::default(),
            new_role_admin_option: Default::default(),
        }
    }

    fn input<'a>(
        current: RoleGraph,
        changes: &'a [Change],
        sql_context: &'a SqlContext,
    ) -> ReviewArtifactInput<'a> {
        ReviewArtifactInput {
            provenance: ReviewProvenance {
                tool_version: "0.12.0".into(),
                captured_at: "2026-09-20T00:00:00Z".into(),
                policy: PolicyProvenance::from_content(b"roles: []", Some("abc123".into())),
                target_label: "test".into(),
                pg_major_version: 16,
            },
            context: ReviewContext {
                mode: ReviewMode::Authoritative,
                managed_scope: None,
                inspector: ReviewIdentity {
                    role: "inspector".into(),
                    superuser: Some(false),
                },
                intended_executor: ReviewIdentity {
                    role: "deployer".into(),
                    superuser: Some(false),
                },
                authority_graph_complete: true,
            },
            preflight: vec![PreflightEvidence {
                check: PreflightCheck::ExecutorAuthority,
                status: EvidenceStatus::Passed,
                actor_role: Some("deployer".into()),
                issue_count: 0,
                issues: Vec::new(),
                coverage: EvidenceCoverage {
                    kind: EvidenceCoverageKind::Complete,
                    checks_performed: Vec::new(),
                    checked_change_indices: (0..changes.len()).collect(),
                    unchecked_change_indices: Vec::new(),
                },
            }],
            current,
            changes,
            change_sources: None,
            executor_facts: executor("deployer"),
            sql_context,
            exploration: ReviewExploration::Omitted {
                reason: ExplorationOmissionReason::RecordedOnlyExport,
            },
        }
    }

    fn login_roles_with_passwords(count: usize) -> Vec<Change> {
        (0..count)
            .flat_map(|index| {
                let name = format!("bulk_{index:04}");
                [
                    Change::CreateRole {
                        name: name.clone(),
                        state: RoleState {
                            login: true,
                            ..RoleState::default()
                        },
                    },
                    Change::SetPassword {
                        name,
                        password: "SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy".into(),
                    },
                ]
            })
            .collect()
    }

    fn to_statuses(entries: &[RoleReachability]) -> BTreeMap<String, ReviewReachabilityStatus> {
        entries
            .iter()
            .map(|entry| (entry.role.clone(), entry.status.into()))
            .collect()
    }

    #[test]
    fn sanitizes_every_recorded_parallel_representation() {
        let secret_comment = "COMMENT_SECRET_CANARY";
        let secret_config = "CONFIG_SECRET_CANARY";
        let secret_password = "PASSWORD_SECRET_CANARY";
        let state = RoleState {
            comment: Some(secret_comment.into()),
            config: BTreeMap::from([("app.token".into(), secret_config.into())]),
            ..RoleState::default()
        };
        let changes = vec![
            Change::CreateRole {
                name: "app".into(),
                state,
            },
            Change::SetPassword {
                name: "app".into(),
                password: secret_password.into(),
            },
        ];
        let artifact = build_review_artifact(input(
            RoleGraph::default(),
            &changes,
            &SqlContext::default(),
        ))
        .unwrap();
        let json = serde_json::to_string(&artifact).unwrap();
        for canary in [secret_comment, secret_config, secret_password] {
            assert!(!json.contains(canary));
        }
        assert!(!json.contains("\"comment\""));
        assert!(matches!(
            artifact.recorded.sql_preview,
            SqlPreview::Omitted { .. }
        ));
        assert_eq!(artifact.recorded.changes[0].omissions.len(), 2);
        assert_eq!(artifact.recorded.changes[1].omissions.len(), 1);
        assert!(
            artifact
                .recorded
                .omissions
                .iter()
                .any(|item| item.field == "visual.nodes[].comment")
        );
    }

    #[test]
    fn preserves_supplied_change_order_without_rediffing() {
        let changes = vec![
            Change::CreateRole {
                name: "already_present".into(),
                state: RoleState::default(),
            },
            Change::Grant {
                role: Grantee::from("already_present"),
                privileges: BTreeSet::from([Privilege::Select]),
                object_type: ObjectType::Table,
                schema: Some("app".into()),
                name: Some("orders".into()),
            },
            Change::TerminateSessions {
                role: "retired".into(),
            },
            Change::ReassignOwned {
                from_role: "retired".into(),
                to_role: "already_present".into(),
            },
            Change::DropOwned {
                role: "retired".into(),
            },
            Change::DropRole {
                name: "retired".into(),
            },
        ];
        let mut current = RoleGraph::default();
        current
            .roles
            .insert("already_present".into(), RoleState::default());
        current.grants.insert(
            crate::model::GrantKey {
                role: Grantee::from("already_present"),
                object_type: ObjectType::Table,
                schema: Some("app".into()),
                name: Some("orders".into()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Select]),
            },
        );
        let artifact =
            build_review_artifact(input(current, &changes, &SqlContext::default())).unwrap();
        assert_eq!(artifact.recorded.changes.len(), 6);
        assert_eq!(
            artifact
                .recorded
                .phases
                .iter()
                .map(|phase| phase.change_indices.clone())
                .collect::<Vec<_>>(),
            vec![vec![0], vec![1], vec![2, 3, 4, 5]]
        );
        assert!(matches!(
            artifact.recorded.sql_preview,
            SqlPreview::Available { .. }
        ));
    }

    #[test]
    fn records_reachability_as_deltas_that_fold_back_to_the_analysis() {
        // Covers every delta shape: a first phase listing the full state,
        // additions, status changes, unchanged phases, and removals.
        let mut current = RoleGraph::default();
        for role in ["deployer", "team", "retired"] {
            current.roles.insert(role.into(), RoleState::default());
        }
        current.memberships.insert(MembershipEdge {
            role: "retired".into(),
            member: "deployer".into(),
            inherit: true,
            admin: false,
        });
        let changes = vec![
            Change::CreateRole {
                name: "app".into(),
                state: RoleState::default(),
            },
            Change::SetComment {
                name: "team".into(),
                comment: None,
            },
            Change::AddMember {
                role: "team".into(),
                member: "deployer".into(),
                inherit: true,
                admin: false,
            },
            Change::DropRole {
                name: "retired".into(),
            },
        ];
        let expected = analyze_changes(current.clone(), &changes, &executor("deployer"));
        let artifact =
            build_review_artifact(input(current, &changes, &SqlContext::default())).unwrap();
        let folded = artifact.recorded.phase_reachability().unwrap();
        assert_eq!(folded.len(), expected.phases.len());
        for (state, phase) in folded.iter().zip(&expected.phases) {
            assert_eq!(
                state.executor_reachability,
                to_statuses(&phase.executor_reachability)
            );
            assert_eq!(state.executor_usage, to_statuses(&phase.executor_usage));
        }

        let phases = &artifact.recorded.phases;
        // The first phase's delta is its complete state.
        assert_eq!(
            phases[0].executor_usage_delta.changed.len(),
            expected.phases[0].executor_usage.len()
        );
        assert!(phases[0].executor_usage_delta.removed.is_empty());
        // Altering a comment changes no reachability.
        assert_eq!(
            phases[1].executor_usage_delta,
            ReviewReachabilityDelta::default()
        );
        // Granting a membership changes only the role that became usable.
        assert_eq!(
            phases[2].executor_usage_delta.changed,
            vec![ReviewReachability {
                role: "team".into(),
                status: ReviewReachabilityStatus::Reachable,
            }]
        );
        // Dropping a role removes it.
        assert_eq!(
            phases[3].executor_usage_delta.removed,
            vec!["retired".to_string()]
        );
        parse_review_artifact(&serde_json::to_vec(&artifact).unwrap()).unwrap();
    }

    #[test]
    fn many_login_roles_with_passwords_fit_the_import_limit() {
        // SetPassword follows each CreateRole, so every role opens two phases.
        // Complete per-phase lists made this 4.5 MB at 150 roles.
        let changes = login_roles_with_passwords(300);
        let artifact = build_review_artifact(input(
            RoleGraph::default(),
            &changes,
            &SqlContext::default(),
        ))
        .expect("delta-encoded reachability stays within the import limit");
        assert_eq!(artifact.recorded.phases.len(), 600);
        let size = serde_json::to_vec_pretty(&artifact).unwrap().len();
        assert!(
            size < MAX_REVIEW_ARTIFACT_BYTES / 4,
            "artifact has {size} bytes"
        );
        assert!(artifact.recorded.phases[1..].iter().all(|phase| {
            phase.executor_reachability_delta.changed.len() <= 1
                && phase.executor_usage_delta.changed.len() <= 1
        }));
        let folded = artifact.recorded.phase_reachability().unwrap();
        assert!(
            folded
                .last()
                .unwrap()
                .executor_reachability
                .contains_key("bulk_0299")
        );
    }

    #[test]
    fn parse_round_trips_and_detects_edits() {
        let changes = login_roles_with_passwords(2);
        let artifact = build_review_artifact(input(
            RoleGraph::default(),
            &changes,
            &SqlContext::default(),
        ))
        .unwrap();
        let json = serde_json::to_value(&artifact).unwrap();
        let parsed = parse_review_artifact(&serde_json::to_vec(&json).unwrap()).unwrap();
        assert_eq!(
            parsed.recorded.review_fingerprint,
            artifact.recorded.review_fingerprint
        );
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            json,
            "deserialization is lossless"
        );

        let reject = |edit: &dyn Fn(&mut serde_json::Value)| {
            let mut value = json.clone();
            edit(&mut value);
            parse_review_artifact(&serde_json::to_vec(&value).unwrap()).unwrap_err()
        };
        assert!(matches!(
            reject(&|value| value["recorded"]["changes"][0]["change"]["name"] = "other".into()),
            ReviewArtifactError::FingerprintMismatch { .. }
        ));
        assert!(matches!(
            reject(&|value| value["recorded"]["visual"]["nodes"][0]["comment"] = "x".into()),
            ReviewArtifactError::Malformed(_)
        ));
        assert!(matches!(
            reject(&|value| value["schema_version"] = "pgroles.review-artifact.v1".into()),
            ReviewArtifactError::UnsupportedSchemaVersion(_)
        ));
        assert!(matches!(
            reject(
                &|value| value["recorded"]["phases"][0]["executor_reachability_delta"]["removed"] =
                    serde_json::json!(["nobody"])
            ),
            ReviewArtifactError::InvalidReachabilityDelta { phase: 0, .. }
        ));
        assert!(matches!(
            reject(&|value| {
                let changed = value["recorded"]["phases"][0]["executor_usage_delta"]["changed"]
                    .as_array_mut()
                    .unwrap();
                changed.reverse();
            }),
            ReviewArtifactError::InvalidReachabilityDelta { phase: 0, .. }
        ));
        assert!(matches!(
            reject(
                &|value| value["recorded"]["phases"][1]["change_indices"] = serde_json::json!([2])
            ),
            ReviewArtifactError::InconsistentIndices(_)
        ));
    }

    #[test]
    fn docs_fixture_matches_the_rust_contract() {
        // The explorer importer's fixture is CLI output; if the Rust contract
        // drifts, regenerate it with `pgroles diff --review-out` (see
        // docs/tests/fixtures/recorded-review.yaml).
        let fixture = include_str!("../../../docs/tests/fixtures/recorded-review.json");
        let artifact = parse_review_artifact(fixture.as_bytes())
            .expect("docs fixture is a valid current review artifact");
        assert_eq!(artifact.schema_version, REVIEW_ARTIFACT_SCHEMA_VERSION);
        assert_eq!(
            serde_json::to_value(&artifact).unwrap(),
            serde_json::from_str::<serde_json::Value>(fixture).unwrap(),
            "fixture round-trips without loss"
        );
        let folded = artifact.recorded.phase_reachability().unwrap();
        assert_eq!(folded.len(), artifact.recorded.phases.len());
    }

    #[test]
    fn rejects_pretty_artifacts_over_the_import_limit() {
        let changes = Vec::new();
        let sql_context = SqlContext::default();
        let mut artifact_input = input(RoleGraph::default(), &changes, &sql_context);
        artifact_input.provenance.target_label = "x".repeat(MAX_REVIEW_ARTIFACT_BYTES);
        assert!(matches!(
            build_review_artifact(artifact_input),
            Err(ReviewArtifactError::TooLarge { .. })
        ));
    }

    #[test]
    fn records_bundle_source_attribution_in_change_order() {
        let changes = vec![
            Change::DropRole {
                name: "retired".into(),
            },
            Change::SetDefaultPrivilege {
                owner: "owner".into(),
                scope: DefaultPrivilegeScope::Global,
                on_type: ObjectType::Table,
                grantee: Grantee::Public,
                privileges: BTreeSet::from([Privilege::Select]),
            },
        ];
        let sources = vec![
            BundleChangeOwner {
                document: "retirements.yaml".into(),
                managed_key: ManagedOwnershipKey::Role {
                    name: "retired".into(),
                },
            },
            BundleChangeOwner {
                document: "defaults.yaml".into(),
                managed_key: ManagedOwnershipKey::DefaultPrivilege {
                    owner: "owner".into(),
                    scope: DefaultPrivilegeScope::Global,
                    on_type: ObjectType::Table,
                    grantee: Grantee::Public,
                },
            },
        ];
        let sql_context = SqlContext::default();
        let mut artifact_input = input(RoleGraph::default(), &changes, &sql_context);
        artifact_input.change_sources = Some(&sources);
        let artifact = build_review_artifact(artifact_input).unwrap();
        assert_eq!(
            artifact.recorded.changes[0]
                .source
                .as_ref()
                .map(|source| source.document.as_str()),
            Some("retirements.yaml")
        );
        // Artifact-owned types serialize exactly like the report DTOs.
        assert_eq!(
            serde_json::to_value(artifact.recorded.changes[1].source.as_ref().unwrap()).unwrap(),
            serde_json::to_value(&sources[1]).unwrap()
        );
        let recorded = serde_json::to_value(&artifact.recorded.changes[1].change).unwrap();
        assert_eq!(recorded["grantee"], "PUBLIC");
        assert_eq!(recorded["scope"], serde_json::json!({"type": "global"}));
    }
}
