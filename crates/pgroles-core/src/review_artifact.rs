//! Portable, sanitized review artifacts built from an already-produced plan.

use std::collections::BTreeSet;

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::diff::{Change, ReconciliationMode};
use crate::explorer::{
    AuthorityFinding, ExecutorFacts, FindingKind, FindingSeverity, PlanAnalysis,
    PlanAnalysisOptions, PlanPhase, RoleReachability, analyze_changes_with_options,
};
use crate::manifest::{ObjectType, Privilege};
use crate::model::{DefaultPrivilegeScope, Grantee, RoleAttribute, RoleGraph, RoleState};
use crate::report::BundleChangeOwner;
use crate::review::{ReviewPriority, priority};
use crate::sql::SqlContext;
use crate::visual::{VisualGraph, VisualManagedScope};

pub const REVIEW_ARTIFACT_SCHEMA_VERSION: &str = "pgroles.review-artifact.v1";
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

#[derive(Debug, Clone, Serialize)]
pub struct ReviewArtifact {
    pub schema_version: String,
    pub provenance: ReviewProvenance,
    pub context: ReviewContext,
    pub preflight: Vec<PreflightEvidence>,
    pub recorded: RecordedReview,
    pub exploration: ReviewExploration,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewProvenance {
    pub tool_version: String,
    /// Caller-supplied RFC 3339 capture time.
    pub captured_at: String,
    pub policy: PolicyProvenance,
    pub target_label: String,
    pub pg_major_version: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyProvenance {
    /// SHA-256 digest of the policy content, prefixed with `sha256:`.
    pub content_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
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

#[derive(Debug, Clone, Serialize)]
pub struct ReviewContext {
    pub mode: ReviewMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_scope: Option<VisualManagedScope>,
    pub inspector: ReviewIdentity,
    pub intended_executor: ReviewIdentity,
    pub authority_graph_complete: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewIdentity {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superuser: Option<bool>,
}

#[derive(Debug, Clone, Copy, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct PreflightEvidence {
    pub check: PreflightCheck,
    pub status: EvidenceStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_role: Option<String>,
    pub issue_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<PreflightFinding>,
    pub coverage: EvidenceCoverage,
}

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCheck {
    DefaultPrivilegeOwner,
    PredefinedRoleMembership,
    GrantorReachability,
    RevokeAclOwnership,
    PlanOrderAuthority,
    DropRoleSafety,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCoverageKind {
    Complete,
    Targeted,
}

#[derive(Debug, Clone, Serialize)]
pub struct PreflightFinding {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightCheck {
    ExecutorAuthority,
    RoleDropSafety,
    ServerCompatibility,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Passed,
    Failed,
    NotRun,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecordedReview {
    pub changes: Vec<RecordedChange>,
    pub phases: Vec<RecordedPhase>,
    pub findings: Vec<RecordedFinding>,
    pub visual: VisualGraph,
    pub sql_preview: SqlPreview,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omissions: Vec<ReviewOmission>,
    pub review_fingerprint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecordedChange {
    pub index: usize,
    pub priority: ReviewPriority,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<BundleChangeOwner>,
    pub change: ReviewChange,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omissions: Vec<ReviewOmission>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewOmission {
    pub field: String,
    pub reason: OmissionReason,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OmissionReason {
    SensitiveValue,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecordedPhase {
    pub phase: PlanPhase,
    pub change_indices: Vec<usize>,
    pub executor_reachability: Vec<RoleReachability>,
    pub executor_usage: Vec<RoleReachability>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecordedFinding {
    pub kind: FindingKind,
    pub severity: FindingSeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<PlanPhase>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SqlPreview {
    Available {
        sql: String,
    },
    Omitted {
        reason: SqlOmissionReason,
        sensitive_change_indices: Vec<usize>,
    },
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlOmissionReason {
    SensitiveChanges,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ReviewExploration {
    Omitted { reason: ExplorationOmissionReason },
}

#[derive(Debug, Clone, Copy, Serialize)]
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
        },
    );
    let changes: Vec<_> = input
        .changes
        .iter()
        .enumerate()
        .map(|(index, change)| {
            let (change, omissions) = ReviewChange::sanitize(change);
            RecordedChange {
                index,
                priority: priority(input.changes.get(index).expect("indexed change exists")),
                source: input
                    .change_sources
                    .and_then(|sources| sources.get(index))
                    .cloned(),
                change,
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
    let mut visual = analysis.visual;
    let visual_comment_omitted = visual.nodes.iter().any(|node| node.comment.is_some());
    for node in &mut visual.nodes {
        node.comment = None;
    }
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
    let recorded_omissions = visual_comment_omitted
        .then(|| ReviewOmission {
            field: "visual.nodes[].comment".to_string(),
            reason: OmissionReason::SensitiveValue,
        })
        .into_iter()
        .collect::<Vec<_>>();
    let fingerprint_bytes = serde_json::to_vec(&(
        REVIEW_ARTIFACT_SCHEMA_VERSION,
        &input.provenance.policy,
        &input.provenance.target_label,
        input.provenance.pg_major_version,
        &input.context,
        &input.preflight,
        &changes,
        &phases,
        &findings,
        &visual,
        &sql_preview,
        &recorded_omissions,
    ))?;
    let review_fingerprint = format!(
        "sha256:{}",
        hex_digest(Sha256::digest(fingerprint_bytes).as_slice())
    );
    let artifact = ReviewArtifact {
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
            omissions: recorded_omissions,
            review_fingerprint,
        },
        exploration: input.exploration,
    };
    let actual = serde_json::to_vec_pretty(&artifact)?.len();
    if actual > MAX_REVIEW_ARTIFACT_BYTES {
        return Err(ReviewArtifactError::TooLarge {
            actual,
            limit: MAX_REVIEW_ARTIFACT_BYTES,
        });
    }
    Ok(artifact)
}

fn recorded_phases(analysis: &PlanAnalysis) -> Vec<RecordedPhase> {
    let mut next_index = 0;
    analysis
        .phases
        .iter()
        .map(|phase| {
            let change_indices = (next_index..next_index + phase.changes.len()).collect();
            next_index += phase.changes.len();
            RecordedPhase {
                phase: phase.phase,
                change_indices,
                executor_reachability: phase.executor_reachability.clone(),
                executor_usage: phase.executor_usage.clone(),
            }
        })
        .collect()
}

impl From<&AuthorityFinding> for RecordedFinding {
    fn from(value: &AuthorityFinding) -> Self {
        Self {
            kind: value.kind,
            severity: value.severity,
            phase: value.phase,
            change_index: value.change_index,
            role: value.role.clone(),
            message: value.message.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
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
        role: Grantee,
        privileges: BTreeSet<Privilege>,
        object_type: ObjectType,
        schema: Option<String>,
        name: Option<String>,
    },
    Revoke {
        role: Grantee,
        privileges: BTreeSet<Privilege>,
        object_type: ObjectType,
        schema: Option<String>,
        name: Option<String>,
        grantor: Option<String>,
    },
    SetDefaultPrivilege {
        owner: String,
        scope: DefaultPrivilegeScope,
        on_type: ObjectType,
        grantee: Grantee,
        privileges: BTreeSet<Privilege>,
    },
    RevokeDefaultPrivilege {
        owner: String,
        scope: DefaultPrivilegeScope,
        on_type: ObjectType,
        grantee: Grantee,
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

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
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
                role: role.clone(),
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
                role: role.clone(),
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
                scope: scope.clone(),
                on_type: *on_type,
                grantee: grantee.clone(),
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
                scope: scope.clone(),
                on_type: *on_type,
                grantee: grantee.clone(),
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
    use crate::model::{GrantState, RoleState};
    use crate::report::ManagedOwnershipKey;
    use std::collections::BTreeMap;

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
            executor_facts: ExecutorFacts {
                role: "deployer".into(),
                superuser: false,
                memberships: Vec::new(),
                new_membership_set_role: Default::default(),
                new_role_set_role: Default::default(),
                new_role_inherit: Default::default(),
                new_role_admin_option: Default::default(),
            },
            sql_context,
            exploration: ReviewExploration::Omitted {
                reason: ExplorationOmissionReason::RecordedOnlyExport,
            },
        }
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
        let changes = vec![Change::DropRole {
            name: "retired".into(),
        }];
        let sources = vec![BundleChangeOwner {
            document: "retirements.yaml".into(),
            managed_key: ManagedOwnershipKey::Role {
                name: "retired".into(),
            },
        }];
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
    }
}
