//! Plan lifecycle management for `PostgresPolicyPlan` resources.
//!
//! Handles creating, deduplicating, approving, executing, and cleaning up
//! reconciliation plans. Plans represent computed SQL change sets that may
//! require explicit approval before execution against a database.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::time::Duration;

use flate2::Compression;
use flate2::write::GzEncoder;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::core::labels::{Expression, Selector};
use kube::{Client, Resource, ResourceExt};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::crd::{
    ChangeSummary, CrdReconciliationMode, LABEL_CANDIDATE, LABEL_DATABASE_IDENTITY, LABEL_PLAN,
    LABEL_POLICY, PlanOrigin, PlanPhase, PlanReference, PolicyCondition, PolicyPlanRef,
    PostgresPolicy, PostgresPolicyCandidate, PostgresPolicyPlan, PostgresPolicyPlanSpec,
    PostgresPolicyPlanStatus, SqlCompression, SqlRef, is_retention_exempt,
};
use crate::k8s_names::{LabelValue, truncate_name_prefix};
use crate::reconciler::ReconcileError;
use pgroles_core::approval::{APPROVAL_EFFECT_ENCODING_V3, TargetIdentity};

/// Diagnostic fingerprint; the approval digest remains the execution gate.
pub fn password_source_digest(versions: &BTreeMap<String, String>) -> String {
    compute_sql_hash(&serde_json::to_string(versions).expect("source versions serialize"))
}

pub fn password_source_changed(
    status: &PostgresPolicyPlanStatus,
    versions: &BTreeMap<String, String>,
) -> bool {
    status
        .password_source_digest
        .as_deref()
        .is_some_and(|old| old != password_source_digest(versions))
}

/// Result of plan creation — distinguishes genuinely new plans from
/// deduplication hits so callers can decide whether to emit events.
#[derive(Debug, Clone)]
pub enum PlanCreationResult {
    /// A new plan was created with the given name.
    Created(String),
    /// An existing pending plan with the same effects was found
    /// (deduplication). The returned plan is actionable: it is awaiting a
    /// decision and holds exactly the effects just computed.
    Deduplicated(String),
    /// A plan holding exactly these effects failed recently and is still
    /// inside its retry window, so no new plan was opened. The returned plan
    /// is *Failed*, not pending — nothing is awaiting approval, and callers
    /// must not report it as if it were.
    DeduplicatedFailed(String),
    /// A plan holding exactly these effects was *Applied* recently, yet the
    /// database still diffs to the same change set: the SQL executed without
    /// error but did not converge the inspected state. No new plan was opened;
    /// re-applying would repeat the same no-ops. The returned plan is the
    /// recently applied one.
    DeduplicatedNonConvergent(String),
}

impl PlanCreationResult {
    /// Return the plan name regardless of variant.
    pub fn plan_name(&self) -> &str {
        match self {
            PlanCreationResult::Created(name)
            | PlanCreationResult::Deduplicated(name)
            | PlanCreationResult::DeduplicatedFailed(name)
            | PlanCreationResult::DeduplicatedNonConvergent(name) => name,
        }
    }

    /// True when a new plan was actually created.
    pub fn is_created(&self) -> bool {
        matches!(self, PlanCreationResult::Created(_))
    }

    /// True when the identical change set recently failed and the referenced
    /// plan is in its backoff window rather than awaiting a decision.
    pub fn is_failed_backoff(&self) -> bool {
        matches!(self, PlanCreationResult::DeduplicatedFailed(_))
    }

    /// True when the identical change set was recently applied without
    /// converging the database, so the referenced plan is *Applied* and
    /// executing another copy of it would repeat the same silent no-ops.
    pub fn is_nonconvergent(&self) -> bool {
        matches!(self, PlanCreationResult::DeduplicatedNonConvergent(_))
    }
}

/// Maximum inline SQL size in plan status before spilling to a ConfigMap.
const MAX_INLINE_SQL_BYTES: usize = 16 * 1024;

/// ConfigMap binaryData key for gzip-compressed SQL content.
const SQL_CONFIGMAP_GZIP_KEY: &str = "plan.sql.gz";

/// Conservative stored-byte ceiling for SQL ConfigMaps. Kubernetes caps
/// ConfigMap data at 1 MiB; this leaves room for metadata and future labels.
const MAX_CONFIGMAP_SQL_BYTES: usize = 900 * 1024;

/// Stale status-less plan and orphan ConfigMap grace period.
const ORPHAN_GRACE_SECS: i64 = 60;

/// Best-effort cleanup should never block a fresh reconcile for long.
const CLEANUP_TIMEOUT_SECS: u64 = 5;

/// How many terminal plans of each kind retention keeps for one policy.
///
/// Split by phase rather than pooled, because the phases are not worth the
/// same and the cheapest one is the one generated fastest. `Superseded` is
/// churn: every replan supersedes its predecessor, so on an active policy a
/// single pool fills with records of plans that never ran and evicts the
/// `Applied` ones, which are the record of what did.
///
/// The bounds are operator-level configuration: each field can be overridden
/// by its `PLAN_RETENTION_*` environment variable (see [`Self::from_env`]).
/// They are deliberately not per-policy CRD fields — retention caps object
/// growth in the cluster, it is not policy intent, and the per-object need is
/// served by the `pgroles.io/keep=true` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanRetention {
    /// `Applied` plans kept once they are older than `applied_min_age_secs`.
    pub applied: usize,
    /// Hard ceiling on `Applied` plans, age floor notwithstanding. Without it
    /// a policy applying continuously would grow the count without limit for
    /// the whole floor period; the floor is a promise about history, not a
    /// licence to keep everything.
    pub applied_ceiling: usize,
    /// An `Applied` plan younger than this is kept whatever `applied` says,
    /// so the audit trail spans a stated period instead of however long the
    /// policy's churn rate happens to make it.
    pub applied_min_age_secs: i64,
    /// `Failed` and `Rejected` plans. Both are decisions worth reading back —
    /// why something did not run, and who declined it.
    pub decided: usize,
    /// `Superseded` plans. Deliberately small: it is the least informative
    /// terminal state and the one generating the pressure. A couple is enough
    /// to see what a replan replaced.
    pub superseded: usize,
}

impl Default for PlanRetention {
    fn default() -> Self {
        Self {
            applied: 25,
            applied_ceiling: 200,
            applied_min_age_secs: 30 * 24 * 60 * 60,
            decided: 10,
            superseded: 3,
        }
    }
}

impl PlanRetention {
    /// Overrides [`PlanRetention::applied`].
    pub const ENV_APPLIED: &'static str = "PLAN_RETENTION_APPLIED";
    /// Overrides [`PlanRetention::applied_ceiling`].
    pub const ENV_APPLIED_CEILING: &'static str = "PLAN_RETENTION_APPLIED_CEILING";
    /// Overrides [`PlanRetention::applied_min_age_secs`]. Takes the same
    /// `s`/`m`/`h` duration syntax as the `EPHEMERAL_ACCESS_*` ceilings.
    pub const ENV_APPLIED_MIN_AGE: &'static str = "PLAN_RETENTION_APPLIED_MIN_AGE";
    /// Overrides [`PlanRetention::decided`].
    pub const ENV_DECIDED: &'static str = "PLAN_RETENTION_DECIDED";
    /// Overrides [`PlanRetention::superseded`].
    pub const ENV_SUPERSEDED: &'static str = "PLAN_RETENTION_SUPERSEDED";

    /// Resolve the retention bounds from the process environment.
    ///
    /// Unset variables keep their defaults. An invalid value is an error, not
    /// a fallback: this is meant to be called once at startup, where refusing
    /// to start is the only failure mode an operator of the operator will
    /// actually see. Retention that silently ran with different bounds than
    /// the environment asked for would only be discovered when the plan
    /// someone wanted was already deleted.
    pub fn from_env() -> Result<Self, PlanRetentionConfigError> {
        let mut resolved = std::collections::BTreeMap::new();
        for variable in [
            Self::ENV_APPLIED,
            Self::ENV_APPLIED_CEILING,
            Self::ENV_APPLIED_MIN_AGE,
            Self::ENV_DECIDED,
            Self::ENV_SUPERSEDED,
        ] {
            if let Some(value) = env_read(variable, std::env::var(variable))? {
                resolved.insert(variable, value);
            }
        }
        Self::from_lookup(|variable| resolved.get(variable).cloned())
    }

    /// [`Self::from_env`] over an arbitrary lookup, so parsing and validation
    /// are testable without mutating process-global environment state.
    fn from_lookup(
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, PlanRetentionConfigError> {
        let defaults = Self::default();
        let retention = Self {
            applied: count_bound(&lookup, Self::ENV_APPLIED, defaults.applied)?,
            applied_ceiling: count_bound(
                &lookup,
                Self::ENV_APPLIED_CEILING,
                defaults.applied_ceiling,
            )?,
            applied_min_age_secs: age_bound(
                &lookup,
                Self::ENV_APPLIED_MIN_AGE,
                defaults.applied_min_age_secs,
            )?,
            decided: count_bound(&lookup, Self::ENV_DECIDED, defaults.decided)?,
            superseded: count_bound(&lookup, Self::ENV_SUPERSEDED, defaults.superseded)?,
        };
        // A ceiling below the count bound could never take effect — eviction
        // already stops at the count — so the configuration says one thing
        // and the operator would do another. Reject it instead.
        if retention.applied_ceiling < retention.applied {
            return Err(PlanRetentionConfigError::CeilingBelowCount {
                ceiling: retention.applied_ceiling,
                count: retention.applied,
            });
        }
        Ok(retention)
    }
}

/// Classify one raw environment read: present, absent, or refused.
///
/// `NotUnicode` is the one `VarError` that must not degrade to "unset": a
/// variable someone set, however malformed, silently taking the default is
/// exactly the failure mode this configuration's startup validation exists
/// to prevent.
fn env_read(
    variable: &'static str,
    read: Result<String, std::env::VarError>,
) -> Result<Option<String>, PlanRetentionConfigError> {
    match read {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(PlanRetentionConfigError::NotUnicode { variable })
        }
    }
}

/// A count bound from `lookup`, or `default` when the variable is unset.
fn count_bound(
    lookup: impl Fn(&str) -> Option<String>,
    variable: &'static str,
    default: usize,
) -> Result<usize, PlanRetentionConfigError> {
    match lookup(variable) {
        None => Ok(default),
        Some(value) => value
            .trim()
            .parse()
            .map_err(|_| PlanRetentionConfigError::InvalidCount { variable, value }),
    }
}

/// An age bound in seconds from `lookup`, or `default` when the variable is
/// unset. The value uses the same duration syntax as the `EPHEMERAL_ACCESS_*`
/// variables.
fn age_bound(
    lookup: impl Fn(&str) -> Option<String>,
    variable: &'static str,
    default: i64,
) -> Result<i64, PlanRetentionConfigError> {
    let Some(value) = lookup(variable) else {
        return Ok(default);
    };
    let invalid = |detail: String| PlanRetentionConfigError::InvalidDuration {
        variable,
        value: value.clone(),
        detail,
    };
    let duration = crate::ephemeral::parse_duration(&value).map_err(|error| {
        invalid(match error {
            crate::ephemeral::EphemeralError::Invalid(detail) => detail,
            other => other.to_string(),
        })
    })?;
    i64::try_from(duration.as_secs()).map_err(|_| invalid("duration is too large".to_string()))
}

/// Why [`PlanRetention::from_env`] refused the environment's values.
#[derive(Debug, thiserror::Error)]
pub enum PlanRetentionConfigError {
    #[error("{variable} must be a non-negative integer, got {value:?}")]
    InvalidCount {
        variable: &'static str,
        value: String,
    },
    #[error("{variable} is not a valid duration ({detail}), got {value:?}")]
    InvalidDuration {
        variable: &'static str,
        value: String,
        detail: String,
    },
    #[error(
        "PLAN_RETENTION_APPLIED_CEILING ({ceiling}) is below PLAN_RETENTION_APPLIED ({count}); \
         a ceiling under the count bound can never take effect"
    )]
    CeilingBelowCount { ceiling: usize, count: usize },
    #[error("{variable} is set to a value that is not valid Unicode")]
    NotUnicode { variable: &'static str },
}

/// How recently a Failed plan must have been created (in seconds) for the
/// dedup check to consider it a match. Plans older than this are ignored so
/// that retries after the user fixes the environment are not blocked.
const FAILED_PLAN_DEDUP_WINDOW_SECS: i64 = 120;

/// How recently an Applied plan must have been applied (in seconds) for the
/// non-convergence check to consider it a match. An identical change set
/// re-planned this soon after applying means the SQL ran without error but
/// changed nothing the inspector can see (for example a REVOKE of a privilege
/// granted by a grantor the executor cannot act as, which PostgreSQL accepts
/// silently). Re-applying would repeat the no-op — and, because every plan
/// status write wakes the policy's reconciler, do so in a hot loop.
const APPLIED_PLAN_NONCONVERGENT_WINDOW_SECS: i64 = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
enum PlanSqlArtifact {
    Inline(String),
    CompressedConfigMap {
        configmap_name: String,
        key: String,
        compressed_sql: Vec<u8>,
    },
    TruncatedInline(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedPlanSql {
    artifact: PlanSqlArtifact,
    redacted_sql_hash: String,
    original_bytes: usize,
    stored_bytes: usize,
}

impl PreparedPlanSql {
    fn sql_ref(&self) -> Option<SqlRef> {
        match &self.artifact {
            PlanSqlArtifact::CompressedConfigMap {
                configmap_name,
                key,
                ..
            } => Some(SqlRef {
                name: configmap_name.clone(),
                key: key.clone(),
                compression: Some(SqlCompression::Gzip),
            }),
            PlanSqlArtifact::Inline(_) | PlanSqlArtifact::TruncatedInline(_) => None,
        }
    }

    fn sql_inline(&self) -> Option<String> {
        match &self.artifact {
            PlanSqlArtifact::Inline(sql) | PlanSqlArtifact::TruncatedInline(sql) => {
                Some(sql.clone())
            }
            PlanSqlArtifact::CompressedConfigMap { .. } => None,
        }
    }

    fn is_truncated(&self) -> bool {
        matches!(self.artifact, PlanSqlArtifact::TruncatedInline(_))
    }
}

// ---------------------------------------------------------------------------
// Plan approval check
// ---------------------------------------------------------------------------

/// Why a plan is being retired.
///
/// The `Approved=False` condition a supersede writes is often the only record a
/// reviewer sees of why the plan they were looking at disappeared. A single
/// fixed message ("database state changed") named the least common cause and
/// misdescribed the rest — an effect-neutral policy edit, effects that vanished
/// before a decision, a moved target — so every call site names its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupersedeCause {
    /// The effects this plan described are not the effects the policy would
    /// produce now.
    EffectsChanged,
    /// A credential source version changed after planning.
    PasswordSourceChanged,
    /// The effects are gone entirely: applied out of band, or edited away.
    /// No replacement plan is opened.
    EffectsCleared,
    /// A newer plan holds the current effects; this one is redundant.
    ReplacedByNewerPlan,
    /// The database the plan was computed against is not the one it would now
    /// execute against. Carries the specific target-identity verdict.
    TargetChanged(pgroles_core::approval::TargetIdentityReason),
    /// The policy stopped pointing at this plan — it moved out of a planning
    /// state, or its pending changes were resolved another way.
    PolicyStoppedPlanning,
    /// A different candidate's content was promoted and executed. This plan
    /// was computed against a base that no longer exists, and its approval can
    /// never authorise anything.
    SupersededByPromotion,
    /// The policy's content moved after this candidate plan was computed
    /// against it. A candidate is a complete desired-state snapshot, so even
    /// effect-identical SQL does not prove the snapshot preserves what the
    /// base has come to manage since; the plan is replaced by one computed
    /// against — and pinned to — the current base.
    BaseContentChanged,
}

impl SupersedeCause {
    /// Condition `reason` string. Kept to the existing `Superseded` value for
    /// the generic causes so status consumers keep matching; a target change
    /// reports the identity reason, which is what an operator must act on.
    pub fn reason(self) -> &'static str {
        match self {
            SupersedeCause::TargetChanged(reason) => reason.as_str(),
            SupersedeCause::PasswordSourceChanged => "PasswordSourceChanged",
            // Promotion is the one supersede a reviewer can act on by filing a
            // successor candidate, so it names itself rather than hiding
            // behind the generic reason.
            SupersedeCause::SupersededByPromotion => {
                crate::crd::candidate_reason::SUPERSEDED_BY_PROMOTION
            }
            // A base change is likewise actionable — re-review the fresh
            // plan pinned to the current base — so it names itself too.
            SupersedeCause::BaseContentChanged => "SupersededByBaseChange",
            _ => "Superseded",
        }
    }

    /// Human-readable condition `message`.
    pub fn message(self) -> &'static str {
        match self {
            SupersedeCause::PasswordSourceChanged => {
                "password source versions changed after planning; review and approve the replacement plan"
            }
            SupersedeCause::EffectsChanged => {
                "the policy's effects changed since this plan was computed, so it no longer \
                 describes what would happen"
            }
            SupersedeCause::EffectsCleared => {
                "the changes this plan described are no longer pending, so there is nothing left \
                 to execute"
            }
            SupersedeCause::ReplacedByNewerPlan => {
                "a newer plan holds the current effects and replaces this one"
            }
            SupersedeCause::TargetChanged(reason) => reason.message(),
            SupersedeCause::PolicyStoppedPlanning => {
                "the policy no longer references this plan, so it will never be executed"
            }
            SupersedeCause::SupersededByPromotion => {
                "another candidate's content was promoted and executed, so this plan describes a \
                 change against a base that no longer exists"
            }
            SupersedeCause::BaseContentChanged => {
                "the policy's content changed after this candidate plan was computed against it; \
                 a fresh plan pinned to the current base replaces it and needs its own review"
            }
        }
    }
}

/// Result of checking a plan's approval annotations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanApprovalState {
    Pending,
    Approved,
    Rejected,
}

/// Identity recorded as the decider when `approval: auto` lets the operator
/// approve its own plan. It is not a Kubernetes user; it names the mechanism so
/// an audit trail never shows an unattributed approval.
pub const AUTO_APPROVAL_ACTOR: &str = "system:pgroles-operator(auto-approval)";

/// Read the decision recorded on a plan.
///
/// The decision lives in the status subresource as a terminal `Approved` or
/// `Denied` condition, alongside the `decidedBy` identity written in the same
/// admitted update. It replaced the `pgroles.io/approved` annotation, which any
/// holder of patch on the object could set, unset, or forge without trace.
///
/// `Denied` wins over `Approved` if both are somehow present. CEL rejects that
/// combination at admission, so reaching it means the rules were bypassed —
/// refusing to execute is the fail-closed reading.
pub fn check_plan_approval(plan: &PostgresPolicyPlan) -> PlanApprovalState {
    let Some(status) = plan.status.as_ref() else {
        return PlanApprovalState::Pending;
    };

    let decided = |condition_type: &str| {
        status
            .conditions
            .iter()
            .any(|c| c.condition_type == condition_type && c.status == "True")
    };

    if decided("Denied") {
        return PlanApprovalState::Rejected;
    }

    if decided("Approved") {
        return PlanApprovalState::Approved;
    }

    PlanApprovalState::Pending
}

// ---------------------------------------------------------------------------
// Plan creation
// ---------------------------------------------------------------------------

/// Binding that turns an ordinary policy plan into a candidate-origin plan.
///
/// A candidate plan is the reviewable artifact for a proposal that is not the
/// desired state yet, so it is owned by the candidate (ADR-001 Decision 3) and
/// carries the identity a later promotion is checked against: the candidate's
/// name and UID, its content digest and encoding, and the parent policy's UID.
/// The rest of the binding — reconciliation mode, target identity and the
/// semantic change digest — is what every plan already records.
#[derive(Debug, Clone, Copy)]
pub struct CandidatePlanBinding<'a> {
    pub candidate: &'a PostgresPolicyCandidate,
    pub content_digest: &'a str,
    pub content_digest_encoding: &'a str,
    /// Canonical digest of the policy content this plan was computed against.
    pub base_content_digest: &'a str,
}

/// The plan-identity binding a candidate-origin plan records.
///
/// Everything a later promotion has to be checked against that is not already
/// on the plan: which candidate produced it, that candidate's content digest
/// and the encoding it was computed under, and the parent policy's UID. The
/// remaining halves of the binding — reconciliation mode, target identity and
/// the approval-effect change digest — are plan fields every plan carries.
pub(crate) fn candidate_plan_origin(
    binding: CandidatePlanBinding<'_>,
    policy: &PostgresPolicy,
) -> PlanOrigin {
    PlanOrigin {
        kind: PostgresPolicyCandidate::kind(&()).to_string(),
        name: binding.candidate.name_any(),
        uid: binding.candidate.metadata.uid.clone().unwrap_or_default(),
        content_digest: Some(binding.content_digest.to_string()),
        content_digest_encoding: Some(binding.content_digest_encoding.to_string()),
        policy_uid: policy.metadata.uid.clone(),
        base_content_digest: Some(binding.base_content_digest.to_string()),
    }
}

/// Which object owns a plan and the artifacts beneath it.
///
/// Ownership is the exact filter for every list, dedup, supersede and delete
/// path in this module, so it is threaded as one value rather than re-derived
/// from the policy at each site.
#[derive(Debug, Clone, Copy)]
enum PlanOwner<'a> {
    Policy(&'a PostgresPolicy),
    Candidate(&'a PostgresPolicyCandidate),
}

impl PlanOwner<'_> {
    fn uid(&self) -> Option<&str> {
        match self {
            PlanOwner::Policy(policy) => policy.metadata.uid.as_deref(),
            PlanOwner::Candidate(candidate) => candidate.metadata.uid.as_deref(),
        }
    }

    fn name(&self) -> String {
        match self {
            PlanOwner::Policy(policy) => policy.name_any(),
            PlanOwner::Candidate(candidate) => candidate.name_any(),
        }
    }

    /// The `.metadata.generation` of the object whose spec defines this plan's
    /// effects. Revalidation provenance is keyed on the owner: a candidate's
    /// plan derives from the candidate's immutable content, so stamping the
    /// *policy's* generation on it would claim a confirmation against a spec
    /// the plan is not computed from.
    fn generation(&self) -> i64 {
        match self {
            PlanOwner::Policy(policy) => policy.metadata.generation.unwrap_or(0),
            PlanOwner::Candidate(candidate) => candidate.metadata.generation.unwrap_or(0),
        }
    }

    fn owner_reference(&self) -> OwnerReference {
        match self {
            PlanOwner::Policy(policy) => build_owner_reference(policy),
            PlanOwner::Candidate(candidate) => OwnerReference {
                api_version: PostgresPolicyCandidate::api_version(&()).to_string(),
                kind: PostgresPolicyCandidate::kind(&()).to_string(),
                name: candidate.name_any(),
                uid: candidate.metadata.uid.clone().unwrap_or_default(),
                controller: Some(true),
                block_owner_deletion: Some(true),
            },
        }
    }

    fn owns<K: Resource>(&self, resource: &K) -> bool {
        // An owner with no UID cannot prove ownership of anything; refuse to
        // match rather than treat an empty UID as a wildcard.
        let Some(uid) = self.uid() else {
            return false;
        };
        is_owned_by_uid(resource, uid)
    }
}

/// The base pin a candidate-origin plan records, if any.
fn plan_base_pin(plan: &PostgresPolicyPlan) -> Option<&str> {
    plan.spec
        .origin
        .as_ref()
        .and_then(|origin| origin.base_content_digest.as_deref())
}

/// Create or deduplicate a `PostgresPolicyPlan` for the given policy and changes.
///
/// Returns the name of the plan resource (either existing or newly created).
///
/// This function:
/// 1. Renders the full executable SQL from the changes
/// 2. Computes SHA-256 of the full SQL (before any redaction/truncation)
/// 3. Checks for an existing Pending plan with the same hash (dedup)
/// 4. Persists the SQL preview artifact, if needed
/// 5. Creates the new plan resource with ownerReferences
/// 6. Updates the plan status
/// 7. Marks any older Pending plans with a different hash as Superseded
#[allow(clippy::too_many_arguments)]
pub async fn create_or_update_plan(
    client: &Client,
    policy: &PostgresPolicy,
    changes: &[pgroles_core::diff::Change],
    sql_context: &pgroles_core::sql::SqlContext,
    inspect_config: &pgroles_inspect::InspectConfig,
    reconciliation_mode: CrdReconciliationMode,
    database_identity: &str,
    target_identity: &TargetIdentity,
    change_summary: &ChangeSummary,
    password_source_versions: &BTreeMap<String, String>,
    plan_retention: PlanRetention,
    candidate: Option<CandidatePlanBinding<'_>>,
    detect_nonconvergent_apply: bool,
) -> Result<PlanCreationResult, ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_name = policy.name_any();
    let generation = policy.metadata.generation.unwrap_or(0);
    // Everything below is keyed on the owner, not the policy: a candidate plan
    // is owned by its candidate so that deleting the proposal prunes the plan
    // and its SQL artifact with it.
    let owner = match candidate {
        Some(binding) => PlanOwner::Candidate(binding.candidate),
        None => PlanOwner::Policy(policy),
    };
    let owner_name = owner.name();
    // The base precondition for candidate plans. A plan pinned to a different
    // base than the content the policy carries now is superseded even when its
    // change digest is identical: same SQL does not prove the snapshot
    // preserves what the base has come to manage since. The one exception is
    // the base moving to the candidate's *own* content — the merge being
    // promoted is not a staleness event against itself, and treating it as
    // one would void every approval at the moment it is being used.
    let expected_base: Option<&str> = candidate.and_then(|binding| {
        (binding.base_content_digest != binding.content_digest)
            .then_some(binding.base_content_digest)
    });

    // 1. Render the full executable SQL (not redacted). This is a review
    //    artifact only — never an execution payload, and never the approval
    //    identity.
    let render_started = std::time::Instant::now();
    let full_sql = render_full_sql(changes, sql_context);

    // 2. Compute the approval identity: a canonical digest of the typed
    //    effects. Deduplication and approval both key off this rather than the
    //    SQL hash, which is unstable for password changes (fresh SCRAM salt on
    //    every render).
    let change_digest = compute_change_digest(
        changes,
        reconciliation_mode,
        database_identity,
        target_identity,
        password_source_versions,
        &inspect_config.managed_roles,
        &inspect_config.managed_schemas,
    )?;

    // 3. Hash the rendered SQL for preview diagnostics.
    let sql_hash = compute_sql_hash(&full_sql);

    // 4. Count SQL statements (after wildcard expansion).
    let sql_statement_count = full_sql.lines().filter(|l| !l.trim().is_empty()).count() as i64;

    // 5. Render redacted SQL for display (passwords masked).
    let redacted_sql = render_redacted_sql(changes, sql_context);
    tracing::debug!(
        phase = "plan_render",
        elapsed_ms = render_started.elapsed().as_secs_f64() * 1000.0,
        changes = changes.len(),
        sql_bytes = full_sql.len(),
        "plan processing phase"
    );

    // Candidate plans are pruned by candidate retention (their owner cascades),
    // never by the policy's plan retention, which would not see them anyway.
    if candidate.is_none() {
        cleanup_old_plans_best_effort(client, policy, plan_retention).await;
    }

    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);

    // 4. List existing plans for this owner.
    let selector = match candidate {
        Some(binding) => candidate_selector(&binding.candidate.name_any()),
        None => policy_selector(&policy_name),
    };
    // The label narrows server-side; owner UID is the exact filter.
    let existing_plans: Vec<PostgresPolicyPlan> = plans_api
        .list(&ListParams::default().labels_from(&selector))
        .await?
        .into_iter()
        .filter(|plan| owner.owns(plan))
        .collect();

    // 5. Check for duplicate pending plan with the same effects.
    for plan in &existing_plans {
        if let Some(ref status) = plan.status
            && status.phase == PlanPhase::Pending
            && plan_matches_digest(status, &change_digest)
            && expected_base.is_none_or(|base| plan_base_pin(plan) == Some(base))
        {
            // Identical plan already exists — return early (deduplicated).
            let plan_name = plan.name_any();
            info!(
                plan = %plan_name,
                policy = %policy_name,
                "existing pending plan has identical change digest, skipping creation"
            );
            // This pending plan *is* the replacement: it is already visible and
            // holds exactly these effects, so any stale approved plan can be
            // retired now without leaving the policy with nothing actionable.
            supersede_stale_plans(
                &plans_api,
                &existing_plans,
                &policy_name,
                &plan_name,
                &change_digest,
                expected_base,
                password_source_versions,
            )
            .await?;
            return Ok(PlanCreationResult::Deduplicated(plan_name));
        }
    }

    // 5b. Check for a recently-failed plan with the same change digest. If a
    // plan with these exact effects already failed within the dedup window,
    // creating another identical one is pointless — it would produce the same
    // error. The window ensures we don't block retries after the user fixes
    // the environment.
    //
    // Uses `status.failed_at` (not `creation_timestamp`) so that plans which
    // waited for approval before failing are measured from the failure time.
    let now_ts = now_epoch_secs();
    for plan in &existing_plans {
        if let Some(ref status) = plan.status
            && status.phase == PlanPhase::Failed
            && plan_matches_digest(status, &change_digest)
        {
            let failed_ts = status
                .failed_at
                .as_deref()
                .and_then(parse_rfc3339_epoch_secs)
                .unwrap_or(0);
            if failed_ts > 0 && now_ts - failed_ts < FAILED_PLAN_DEDUP_WINDOW_SECS {
                let plan_name = plan.name_any();
                info!(
                    plan = %plan_name,
                    policy = %policy_name,
                    age_secs = now_ts - failed_ts,
                    "recently-failed plan has identical change digest, skipping creation"
                );
                // Deliberately no supersede sweep here: nothing new became
                // visible, so retiring a still-actionable plan would leave the
                // policy holding neither a decision nor a plan to make one on.
                return Ok(PlanCreationResult::DeduplicatedFailed(plan_name));
            }
        }
    }

    // 5c. Non-convergence check for auto-applying callers. If a plan with
    // these exact effects was *Applied* moments ago and the diff still
    // produces them, the SQL ran without error but changed nothing the
    // inspector can see (e.g. a REVOKE of a privilege granted by a grantor
    // the executor cannot act as — PostgreSQL accepts it silently). Creating
    // and executing another identical plan would repeat the no-ops, and since
    // every plan status write wakes the policy's reconciler, do so in a hot
    // loop. Only auto-apply opts in: observe mode never executes and manual
    // mode has a human between replans, so neither can spin this way.
    if detect_nonconvergent_apply {
        for plan in &existing_plans {
            if let Some(ref status) = plan.status
                && plan_matches_digest(status, &change_digest)
                && applied_recently_without_converging(plan, now_ts)
            {
                let plan_name = plan.name_any();
                info!(
                    plan = %plan_name,
                    policy = %policy_name,
                    "recently-applied plan has identical change digest but the database \
                     still reports the same drift; not re-applying"
                );
                return Ok(PlanCreationResult::DeduplicatedNonConvergent(plan_name));
            }
        }
    }

    // 6. Generate a plan name using timestamp plus SQL hash. The hash suffix
    // makes same-second retries after content persistence failures idempotent.
    let plan_name = generate_plan_name(&owner_name, &sql_hash);
    let prepared_sql = prepare_plan_sql(&plan_name, &redacted_sql)?;

    // 7. Persist SQL content before materialising the visible plan resource.
    let sql_configmap_name = create_plan_sql_configmap(
        client,
        owner,
        &namespace,
        &policy_name,
        database_identity,
        &prepared_sql,
    )
    .await?;

    // 8. Build ownerReference pointing to the owning policy or candidate.
    let owner_ref = owner.owner_reference();

    // 9. Create the plan resource.
    let plan = PostgresPolicyPlan::new(
        &plan_name,
        PostgresPolicyPlanSpec {
            policy_ref: PolicyPlanRef {
                name: policy_name.clone(),
            },
            policy_generation: generation,
            reconciliation_mode,
            owned_roles: inspect_config.managed_roles.clone(),
            owned_schemas: inspect_config.managed_schemas.clone(),
            managed_database_identity: database_identity.to_string(),
            origin: candidate.map(|binding| candidate_plan_origin(binding, policy)),
            scope: None,
        },
    );
    let mut plan = plan;
    plan.metadata.namespace = Some(namespace.clone());
    plan.metadata.owner_references = Some(vec![owner_ref.clone()]);
    let mut plan_labels = BTreeMap::from([
        (LABEL_POLICY.to_string(), sanitize_label_value(&policy_name)),
        (
            LABEL_DATABASE_IDENTITY.to_string(),
            sanitize_label_value(database_identity),
        ),
    ]);
    if let Some(binding) = candidate {
        plan_labels.insert(
            LABEL_CANDIDATE.to_string(),
            sanitize_label_value(&binding.candidate.name_any()),
        );
    }
    plan.metadata.labels = Some(plan_labels);

    // Annotations for quick visibility in kubectl describe / Lens.
    let sql_preview = redacted_sql.lines().take(5).collect::<Vec<_>>().join("\n");
    let summary_text = format!(
        "{}R {}G {}D {}DP {}M",
        change_summary.roles_created + change_summary.roles_altered,
        change_summary.grants_added,
        change_summary.default_privileges_set,
        change_summary.roles_dropped,
        change_summary.members_added,
    );
    plan.metadata.annotations = Some(BTreeMap::from([
        ("pgroles.io/sql-preview".to_string(), sql_preview),
        ("pgroles.io/summary".to_string(), summary_text),
        (
            "pgroles.io/sql-hash".to_string(),
            sql_hash[..12].to_string(),
        ),
        (
            "pgroles.io/redacted-sql-hash".to_string(),
            prepared_sql.redacted_sql_hash[..12].to_string(),
        ),
        (
            "pgroles.io/sql-original-bytes".to_string(),
            prepared_sql.original_bytes.to_string(),
        ),
        (
            "pgroles.io/sql-stored-bytes".to_string(),
            prepared_sql.stored_bytes.to_string(),
        ),
    ]));

    let (created_plan, created_new_plan) = match plans_api
        .create(&PostParams::default(), &plan)
        .await
    {
        Ok(plan) => (plan, true),
        Err(kube::Error::Api(api_err)) if api_err.code == 409 => {
            let existing = plans_api.get(&plan_name).await?;
            // The name collided, which is normally our own retry. Confirm
            // ownership before patching anyone's status: plan names embed a
            // 215-byte-truncated policy prefix, so two policies sharing that
            // prefix can in principle collide, and this is otherwise the one
            // mutation site the owner-UID discipline does not cover.
            if !owner.owns(&existing) {
                // Roll back only the ConfigMap this reconcile created. The
                // orphan reaper would collect it eventually — it carries our
                // UID — but leaving it is a pointless transient orphan. One
                // we merely adopted belongs to an earlier reconcile.
                rollback_plan_sql_configmap(client, &namespace, sql_configmap_name.as_ref()).await;
                return Err(ReconcileError::PlanSqlStorage(format!(
                    "plan {plan_name} already exists and is owned by another object"
                )));
            }
            if !can_resume_plan_creation(&existing, &plan.spec) {
                // A completed or differently scoped plan with the same
                // second/SQL name is not this interrupted creation.
                // Retry after the naming window moves; never repoint the
                // policy to it or overwrite an existing decision.
                rollback_plan_sql_configmap(client, &namespace, sql_configmap_name.as_ref()).await;
                return Err(ReconcileError::PlanNameCollision(existing.name_any()));
            }
            (existing, false)
        }
        Err(err) => {
            rollback_plan_sql_configmap(client, &namespace, sql_configmap_name.as_ref()).await;
            return Err(err.into());
        }
    };
    let plan_name = created_plan.name_any();

    // 11. Update plan status.
    let computed_message = if prepared_sql.is_truncated() {
        format!(
            "Plan computed with {} change(s); SQL preview truncated because compressed SQL exceeded Kubernetes ConfigMap limits",
            change_summary.total
        )
    } else {
        format!("Plan computed with {} change(s)", change_summary.total)
    };
    let plan_status = PostgresPolicyPlanStatus {
        phase: PlanPhase::Pending,
        // No decision yet, so no deciding identity. The CEL rule pairing the
        // two means a plan is never born with one without the other.
        decided_by: None,
        conditions: vec![
            PolicyCondition {
                condition_type: "Computed".to_string(),
                status: "True".to_string(),
                reason: Some("PlanComputed".to_string()),
                message: Some(computed_message),
                last_transition_time: Some(crate::crd::now_rfc3339()),
            },
            PolicyCondition {
                condition_type: "Approved".to_string(),
                status: "False".to_string(),
                reason: Some("PendingApproval".to_string()),
                message: Some("Plan awaiting approval".to_string()),
                last_transition_time: Some(crate::crd::now_rfc3339()),
            },
        ],
        change_summary: Some(change_summary.clone()),
        sql_ref: prepared_sql.sql_ref(),
        sql_inline: prepared_sql.sql_inline(),
        sql_truncated: prepared_sql.is_truncated(),
        computed_at: Some(crate::crd::now_rfc3339()),
        applied_at: None,
        last_error: None,
        sql_hash: Some(sql_hash),
        change_digest: Some(change_digest.clone()),
        password_source_digest: Some(password_source_digest(password_source_versions)),
        change_digest_encoding: Some(APPROVAL_EFFECT_ENCODING_V3.to_string()),
        target_physical_identity: target_identity.physical.clone(),
        target_logical_fingerprint: target_identity.logical.clone(),
        physical_identity_available: Some(target_identity.has_physical()),
        revalidated_generation: Some(owner.generation()),
        revalidated_at: Some(crate::crd::now_rfc3339()),
        applying_since: None,
        failed_at: None,
        sql_statements: Some(sql_statement_count),
        redacted_sql_hash: Some(prepared_sql.redacted_sql_hash.clone()),
        sql_original_bytes: Some(prepared_sql.original_bytes as i64),
        sql_stored_bytes: Some(prepared_sql.stored_bytes as i64),
    };

    let status_patch = serde_json::json!({ "status": plan_status });
    if let Err(err) = plans_api
        .patch_status(
            &plan_name,
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&status_patch),
        )
        .await
    {
        if created_new_plan {
            delete_plan_best_effort(&plans_api, &plan_name).await;
        }
        rollback_plan_sql_configmap(client, &namespace, sql_configmap_name.as_ref()).await;
        return Err(err.into());
    }

    // 12. Retire the plans this one replaces, only now that the new plan is
    // fully visible. This avoids losing the current actionable plan if SQL
    // persistence fails before the replacement is materialised, which is why
    // no caller may supersede ahead of calling in here.
    supersede_stale_plans(
        &plans_api,
        &existing_plans,
        &owner_name,
        &plan_name,
        &change_digest,
        expected_base,
        password_source_versions,
    )
    .await?;

    info!(
        plan = %plan_name,
        policy = %policy_name,
        changes = change_summary.total,
        "created new plan"
    );

    Ok(PlanCreationResult::Created(plan_name))
}

/// Whether a pre-existing plan is retired by the plan that now holds
/// `new_digest`.
///
/// Pending plans are always retired: at most one plan may await a decision, and
/// the replacement is the one that describes what would happen now. Approved
/// plans are retired only when their effects differ from the replacement's —
/// an approval that still describes the current effects is a live decision and
/// is never discarded, while one that does not can no longer authorise
/// anything and must be voided rather than left looking actionable.
pub(crate) fn supersedes_after_create(status: &PostgresPolicyPlanStatus, new_digest: &str) -> bool {
    match status.phase {
        PlanPhase::Pending => true,
        PlanPhase::Approved => !plan_matches_digest(status, new_digest),
        _ => false,
    }
}

/// Retire the plans replaced by `new_plan_name`.
///
/// Called only once the replacement plan is visible with its status written —
/// crash safety for the whole plan pointer rests on that ordering, so callers
/// must never supersede ahead of creating.
async fn supersede_stale_plans(
    plans_api: &Api<PostgresPolicyPlan>,
    existing_plans: &[PostgresPolicyPlan],
    policy_name: &str,
    new_plan_name: &str,
    new_digest: &str,
    expected_base: Option<&str>,
    password_source_versions: &BTreeMap<String, String>,
) -> Result<(), ReconcileError> {
    for plan in existing_plans {
        let Some(ref status) = plan.status else {
            continue;
        };
        let old_plan_name = plan.name_any();
        // A live plan pinned to a different base is stale even when its
        // change digest still matches — see the base precondition in
        // `create_or_update_plan`.
        let base_stale = expected_base.is_some_and(|base| {
            matches!(status.phase, PlanPhase::Pending | PlanPhase::Approved)
                && plan_base_pin(plan) != Some(base)
        });
        if old_plan_name == new_plan_name
            || (!supersedes_after_create(status, new_digest) && !base_stale)
        {
            continue;
        }
        let cause = if base_stale {
            SupersedeCause::BaseContentChanged
        } else if password_source_changed(status, password_source_versions) {
            SupersedeCause::PasswordSourceChanged
        } else {
            SupersedeCause::ReplacedByNewerPlan
        };

        info!(
            plan = %old_plan_name,
            policy = %policy_name,
            phase = ?status.phase,
            "marking existing plan as Superseded"
        );
        // The plan is void along with its phase — but the decision on it is
        // terminal and write-once, so the record of who approved what is left
        // untouched. See `superseded_status`.
        let patch = serde_json::json!({ "status": superseded_status(status, cause) });
        plans_api
            .patch_status(
                &old_plan_name,
                &PatchParams::apply("pgroles-operator"),
                &Patch::Merge(&patch),
            )
            .await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Plan execution
// ---------------------------------------------------------------------------

/// Did this plan apply so recently that an identical replan proves the apply
/// changed nothing?
///
/// The caller has already established that the *current* diff has exactly this
/// plan's effects. If the plan is `Applied` and its `applied_at` is inside
/// [`APPLIED_PLAN_NONCONVERGENT_WINDOW_SECS`], then the SQL executed without
/// error moments ago and the inspector still sees the same drift: the changes
/// are silent no-ops (for example a REVOKE of a privilege granted by a grantor
/// the executor cannot act as, which PostgreSQL accepts without effect or
/// warning). Executing another copy repeats the no-ops — and, because the
/// policy controller wakes on its own plans' status writes, repeats them
/// several times a second.
///
/// The window keeps this a slow-down, never a stop: once it expires the
/// policy's interval retries the changes once (external drift genuinely
/// reintroduced in the window is also fixed then), and if they still do not
/// converge the next replan lands back here.
///
/// `applied_ts <= now_ts` mirrors [`retry_deferred_until_window_expires`]: a
/// future timestamp — a stepped clock, a skewed replica — would otherwise sit
/// inside the window until the wall clock catches up, turning the back-off
/// unbounded.
fn applied_recently_without_converging(plan: &PostgresPolicyPlan, now_ts: i64) -> bool {
    let Some(status) = plan.status.as_ref() else {
        return false;
    };
    if status.phase != PlanPhase::Applied {
        return false;
    }
    let applied_ts = status
        .applied_at
        .as_deref()
        .and_then(parse_rfc3339_epoch_secs)
        .unwrap_or(0);
    applied_ts > 0
        && applied_ts <= now_ts
        && now_ts - applied_ts < APPLIED_PLAN_NONCONVERGENT_WINDOW_SECS
}

/// Is this plan inside the retry back-off for a failure it already recorded?
///
/// The creation path already refuses to mint a second plan with the same
/// effects inside [`FAILED_PLAN_DEDUP_WINDOW_SECS`], on the grounds that it
/// would produce the same error. Re-*executing* the plan it kept is the same
/// bet, and left unbounded it costs far more than a wasted query: every
/// attempt writes the plan, the policy controller wakes on its own plans
/// (`reconcile_on(plan_triggers)`), and so each attempt schedules the next.
/// A permanently-failing policy then reconciles as fast as it can execute —
/// several times a second — taking the per-database advisory lock each time
/// and starving every other policy pointed at that database.
///
/// Retrying on the policy's own interval instead is the same behaviour the
/// user already gets after the window expires, minus the storm.
///
/// Keyed on the recorded failure, never on `phase`. Under `approval: auto`
/// the reconciler calls `mark_plan_approved` on the plan before executing it,
/// so a plan that failed milliseconds ago reads as `Approved` here.
/// `failed_at` survives that write; `phase` does not.
fn retry_deferred_until_window_expires(plan: &PostgresPolicyPlan, now_ts: i64) -> bool {
    let Some(status) = plan.status.as_ref() else {
        return false;
    };
    let failed_ts = status
        .failed_at
        .as_deref()
        .and_then(parse_rfc3339_epoch_secs)
        .unwrap_or(0);
    // `failed_ts <= now_ts` is not redundant. A timestamp in the future — a
    // clock stepped backwards, a status written by a skewed replica, a hand
    // patched plan — makes the subtraction negative, which is trivially inside
    // the window. Without the bound the retry is deferred until the wall clock
    // reaches that timestamp, so a bogus value turns a 120-second back-off into
    // an unbounded one and the policy never converges. This gate exists to slow
    // retries down, never to stop them.
    if !(failed_ts > 0 && failed_ts <= now_ts && now_ts - failed_ts < FAILED_PLAN_DEDUP_WINDOW_SECS)
    {
        return false;
    }
    // A plan that succeeded after that failure is not in back-off: `failed_at`
    // is left in place as history when a later attempt applies, so reading it
    // alone would hold a working plan back for two minutes after it recovered.
    //
    // Equal timestamps mean "ordering unknown", not "recovered". Both fields
    // are written by `now_rfc3339`, which is whole-second, so an apply and a
    // failure in the same second are indistinguishable here. Ties resolve to
    // deferring because the two mistakes are not the same size: deferring a
    // plan that did recover costs one interval, and it has nothing left to
    // execute anyway, while not deferring one that failed leaves the retry
    // unbounded — and the tie is sticky, so it would stay unbounded.
    let applied_ts = status
        .applied_at
        .as_deref()
        .and_then(parse_rfc3339_epoch_secs)
        .unwrap_or(0);
    applied_ts <= failed_ts
}

/// The error a plan recorded when it last failed, for reporting a deferred
/// retry without losing the cause.
///
/// A read, not a write: the point of deferring is to touch nothing the
/// controller watches. An unreadable plan degrades to a placeholder rather
/// than failing the reconcile with a second, less useful error.
pub async fn recorded_plan_failure(client: &Client, namespace: &str, plan_name: &str) -> String {
    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), namespace);
    plans_api
        .get(plan_name)
        .await
        .ok()
        .and_then(|plan| plan.status.and_then(|status| status.last_error))
        .unwrap_or_else(|| "no error recorded".to_string())
}

/// Execute an approved plan against the database.
///
/// Re-renders executable SQL from the reconciler's in-memory changes, executes
/// it in a transaction, and updates the plan status to Applied or Failed.
/// Persisted SQL on the plan is a redacted review artifact only; apply must not
/// read it because large plans may store only a truncated preview.
pub async fn execute_plan(
    client: &Client,
    plan: &PostgresPolicyPlan,
    pool: &sqlx::PgPool,
    sql_context: &pgroles_core::sql::SqlContext,
    changes: &[pgroles_core::diff::Change],
) -> Result<(), ReconcileError> {
    let namespace = plan.namespace().ok_or(ReconcileError::NoNamespace)?;
    let plan_name = plan.name_any();
    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);

    // Back off before touching anything: the phase write below is itself what
    // wakes this policy again, so an unbounded retry never reaches the
    // interval it is supposed to wait for.
    if retry_deferred_until_window_expires(plan, now_epoch_secs()) {
        let recorded = plan
            .status
            .as_ref()
            .and_then(|status| status.last_error.clone())
            .unwrap_or_else(|| "no error recorded".to_string());
        info!(
            plan = %plan_name,
            "plan failed recently, deferring retry to the policy interval"
        );
        return Err(ReconcileError::PlanRetryDeferred(plan_name, recorded));
    }

    // Update phase to Applying.
    update_plan_phase(&plans_api, &plan_name, PlanPhase::Applying).await?;

    // Execute the SQL in a transaction using the original changes (not stored SQL).
    // This ensures we use the actual executable SQL including real passwords,
    // not the redacted version stored in the plan.
    let result = execute_changes_in_transaction(pool, changes, sql_context).await;

    match result {
        Ok(statements_executed) => {
            // Update plan status to Applied.
            let mut applied_status = plan.status.clone().unwrap_or_default();
            applied_status.phase = PlanPhase::Applied;
            applied_status.applied_at = Some(crate::crd::now_rfc3339());
            applied_status.last_error = None;
            set_plan_condition(
                &mut applied_status.conditions,
                "Approved",
                "True",
                "Approved",
                "Plan approved and executed",
            );

            let patch = serde_json::json!({ "status": applied_status });
            plans_api
                .patch_status(
                    &plan_name,
                    &PatchParams::apply("pgroles-operator"),
                    &Patch::Merge(&patch),
                )
                .await?;

            info!(
                plan = %plan_name,
                statements = statements_executed,
                "plan executed successfully"
            );
            Ok(())
        }
        Err(err) => {
            // Update plan status to Failed.
            let error_message = err.to_string();
            let mut failed_status = plan.status.clone().unwrap_or_default();
            failed_status.phase = PlanPhase::Failed;
            failed_status.last_error = Some(error_message);
            failed_status.failed_at = Some(crate::crd::now_rfc3339());

            let patch = serde_json::json!({ "status": failed_status });
            if let Err(status_err) = plans_api
                .patch_status(
                    &plan_name,
                    &PatchParams::apply("pgroles-operator"),
                    &Patch::Merge(&patch),
                )
                .await
            {
                tracing::warn!(
                    plan = %plan_name,
                    %status_err,
                    "failed to update plan status to Failed"
                );
            }

            Err(err)
        }
    }
}

fn prepare_plan_sql(
    plan_name: &str,
    redacted_sql: &str,
) -> Result<PreparedPlanSql, ReconcileError> {
    let original_bytes = redacted_sql.len();
    let redacted_sql_hash = compute_sql_hash(redacted_sql);

    if original_bytes <= MAX_INLINE_SQL_BYTES {
        return Ok(PreparedPlanSql {
            artifact: PlanSqlArtifact::Inline(redacted_sql.to_string()),
            redacted_sql_hash,
            original_bytes,
            stored_bytes: original_bytes,
        });
    }

    let compressed_sql = gzip_bytes(redacted_sql.as_bytes())?;
    if compressed_sql.len() <= MAX_CONFIGMAP_SQL_BYTES {
        let stored_bytes = compressed_sql.len();
        return Ok(PreparedPlanSql {
            artifact: PlanSqlArtifact::CompressedConfigMap {
                configmap_name: format!("{plan_name}-sql"),
                key: SQL_CONFIGMAP_GZIP_KEY.to_string(),
                compressed_sql,
            },
            redacted_sql_hash,
            original_bytes,
            stored_bytes,
        });
    }

    let truncated = truncate_utf8(
        redacted_sql,
        MAX_INLINE_SQL_BYTES,
        "\n-- truncated: compressed SQL preview exceeded Kubernetes ConfigMap limits --",
    );
    let stored_bytes = truncated.len();
    Ok(PreparedPlanSql {
        artifact: PlanSqlArtifact::TruncatedInline(truncated),
        redacted_sql_hash,
        original_bytes,
        stored_bytes,
    })
}

fn gzip_bytes(bytes: &[u8]) -> Result<Vec<u8>, ReconcileError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(bytes)
        .map_err(|err| ReconcileError::PlanSqlStorage(err.to_string()))?;
    encoder
        .finish()
        .map_err(|err| ReconcileError::PlanSqlStorage(err.to_string()))
}

fn truncate_utf8(text: &str, max_bytes: usize, marker: &str) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }

    let target_len = max_bytes.saturating_sub(marker.len());
    let mut end = target_len.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }

    let mut truncated = text[..end].to_string();
    truncated.push_str(marker);
    truncated
}

/// A plan's SQL ConfigMap, and whether *this* reconcile is the one that created
/// it.
///
/// Rollback may only delete a ConfigMap this invocation created. One adopted
/// from a 409 was written by an earlier reconcile and may already back a plan
/// that is pending approval; deleting it would leave that plan unapplyable.
/// This mirrors the `created_new_plan` guard already used for the plan itself.
struct PlanSqlConfigMap {
    name: String,
    created: bool,
}

async fn create_plan_sql_configmap(
    client: &Client,
    owner: PlanOwner<'_>,
    namespace: &str,
    policy_name: &str,
    database_identity: &str,
    prepared_sql: &PreparedPlanSql,
) -> Result<Option<PlanSqlConfigMap>, ReconcileError> {
    let PlanSqlArtifact::CompressedConfigMap {
        configmap_name,
        key: _,
        compressed_sql: _,
    } = &prepared_sql.artifact
    else {
        return Ok(None);
    };

    let configmap = build_plan_sql_configmap_object(
        owner,
        namespace,
        policy_name,
        database_identity,
        prepared_sql,
    )?;

    let configmaps_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    match configmaps_api
        .create(&PostParams::default(), &configmap)
        .await
    {
        Ok(_) => Ok(Some(PlanSqlConfigMap {
            name: configmap_name.clone(),
            created: true,
        })),
        Err(kube::Error::Api(api_err)) if api_err.code == 409 => {
            let existing = configmaps_api.get(configmap_name).await?;
            // Ownership first, hash second. The ConfigMap name embeds a
            // truncated plan name, so two policies sharing that prefix can
            // collide here, and identical SQL makes the hash check agree —
            // adopting would then share one artifact between two policies,
            // whose lifetime is tied to the *other* policy's garbage
            // collection.
            if is_owned_by_another(&existing, owner) {
                return Err(ReconcileError::PlanSqlStorage(format!(
                    "plan SQL ConfigMap {configmap_name} is owned by another object"
                )));
            }
            validate_existing_sql_configmap(&existing, prepared_sql)?;
            Ok(Some(PlanSqlConfigMap {
                name: configmap_name.clone(),
                created: false,
            }))
        }
        Err(err) => Err(err.into()),
    }
}

fn build_plan_sql_configmap_object(
    owner: PlanOwner<'_>,
    namespace: &str,
    policy_name: &str,
    database_identity: &str,
    prepared_sql: &PreparedPlanSql,
) -> Result<ConfigMap, ReconcileError> {
    let PlanSqlArtifact::CompressedConfigMap {
        configmap_name,
        key,
        compressed_sql,
    } = &prepared_sql.artifact
    else {
        return Err(ReconcileError::PlanSqlStorage(
            "cannot build ConfigMap for inline plan SQL".to_string(),
        ));
    };

    Ok(ConfigMap {
        metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            name: Some(configmap_name.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner.owner_reference()]),
            labels: Some(BTreeMap::from([
                (LABEL_POLICY.to_string(), sanitize_label_value(policy_name)),
                (
                    LABEL_DATABASE_IDENTITY.to_string(),
                    sanitize_label_value(database_identity),
                ),
                (
                    LABEL_PLAN.to_string(),
                    plan_label_value(configmap_plan_name(configmap_name)),
                ),
            ])),
            annotations: Some(BTreeMap::from([
                ("pgroles.io/sql-compression".to_string(), "gzip".to_string()),
                (
                    "pgroles.io/redacted-sql-hash".to_string(),
                    prepared_sql.redacted_sql_hash.clone(),
                ),
                (
                    "pgroles.io/sql-original-bytes".to_string(),
                    prepared_sql.original_bytes.to_string(),
                ),
                (
                    "pgroles.io/sql-stored-bytes".to_string(),
                    prepared_sql.stored_bytes.to_string(),
                ),
            ])),
            ..Default::default()
        },
        binary_data: Some(BTreeMap::from([(
            key.clone(),
            ByteString(compressed_sql.clone()),
        )])),
        ..Default::default()
    })
}

fn configmap_plan_name(configmap_name: &str) -> &str {
    configmap_name
        .strip_suffix("-sql")
        .unwrap_or(configmap_name)
}

fn plan_label_value(plan_name: &str) -> String {
    compute_sql_hash(plan_name)[..32].to_string()
}

fn validate_existing_sql_configmap(
    configmap: &ConfigMap,
    prepared_sql: &PreparedPlanSql,
) -> Result<(), ReconcileError> {
    let Some(annotations) = configmap.metadata.annotations.as_ref() else {
        return Err(ReconcileError::PlanSqlStorage(format!(
            "existing ConfigMap {} is missing SQL storage annotations",
            configmap.name_any()
        )));
    };
    let hash_matches = annotations
        .get("pgroles.io/redacted-sql-hash")
        .map(|hash| hash == &prepared_sql.redacted_sql_hash)
        .unwrap_or(false);
    if hash_matches {
        Ok(())
    } else {
        Err(ReconcileError::PlanSqlStorage(format!(
            "existing ConfigMap {} does not match computed SQL preview hash",
            configmap.name_any()
        )))
    }
}

/// Execute SQL changes in a database transaction.
///
/// Returns the number of statements executed on success.
pub(crate) async fn execute_changes_in_transaction(
    pool: &sqlx::PgPool,
    changes: &[pgroles_core::diff::Change],
    sql_context: &pgroles_core::sql::SqlContext,
) -> Result<usize, ReconcileError> {
    let mut transaction = pool.begin().await?;
    let mut statements_executed = 0usize;

    for statement in pgroles_core::sql::render_batch_with_context(changes, sql_context) {
        tracing::debug!(sql = %statement.redacted_sql, "executing");
        sqlx::query(&statement.sql)
            .execute(transaction.as_mut())
            .await?;
        statements_executed += 1;
    }

    transaction.commit().await?;
    Ok(statements_executed)
}

// ---------------------------------------------------------------------------
// Plan cleanup / retention
// ---------------------------------------------------------------------------

/// Best-effort cleanup wrapper used on hot reconciliation paths. Cleanup should
/// reduce leaked resources, never block otherwise valid reconciliation.
pub async fn cleanup_old_plans_best_effort(
    client: &Client,
    policy: &PostgresPolicy,
    retention: PlanRetention,
) {
    match tokio::time::timeout(
        Duration::from_secs(CLEANUP_TIMEOUT_SECS),
        cleanup_old_plans(client, policy, retention),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::warn!(%err, "failed to clean up old plans"),
        Err(_) => tracing::warn!(
            timeout_secs = CLEANUP_TIMEOUT_SECS,
            "timed out cleaning up old plans"
        ),
    }
}

/// Clean up old plans for a policy under [`PlanRetention`].
///
/// Terminal plans — Applied, Failed, Superseded, Rejected — are bounded per
/// phase; Pending, Approved, and Applying plans are never evicted, because
/// they are still live. Status-less plans and SQL ConfigMaps older than a
/// short grace period are treated as stale orphans.
pub async fn cleanup_old_plans(
    client: &Client,
    policy: &PostgresPolicy,
    retention: PlanRetention,
) -> Result<(), ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_name = policy.name_any();

    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);
    let selector = policy_selector(&policy_name);
    let existing_plans: Vec<PostgresPolicyPlan> = plans_api
        .list(&ListParams::default().labels_from(&selector))
        .await?
        .into_iter()
        .filter(|plan| is_owned_by_policy(plan, policy))
        .collect();
    let now_ts = now_epoch_secs();

    for plan in existing_plans
        .iter()
        .filter(|plan| is_stale_statusless_plan(plan, now_ts))
    {
        let plan_name = plan.name_any();
        info!(
            plan = %plan_name,
            policy = %policy_name,
            "cleaning up stale status-less plan"
        );
        if let Err(err) = plans_api.delete(&plan_name, &DeleteParams::default()).await {
            tracing::warn!(
                plan = %plan_name,
                %err,
                "failed to delete stale status-less plan during cleanup"
            );
        }
    }

    for plan in plans_to_evict(&existing_plans, retention, now_ts) {
        let plan_name = plan.name_any();
        info!(
            plan = %plan_name,
            policy = %policy_name,
            phase = ?plan.status.as_ref().map(|status| &status.phase),
            "cleaning up old plan"
        );
        if let Err(err) = plans_api.delete(&plan_name, &DeleteParams::default()).await {
            tracing::warn!(
                plan = %plan_name,
                %err,
                "failed to delete old plan during cleanup"
            );
        }
    }

    cleanup_orphan_sql_configmaps(
        client,
        &namespace,
        policy,
        &policy_name,
        &existing_plans,
        now_ts,
    )
    .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn cleanup_orphan_sql_configmaps(
    client: &Client,
    namespace: &str,
    policy: &PostgresPolicy,
    policy_name: &str,
    existing_plans: &[PostgresPolicyPlan],
    now_ts: i64,
) -> Result<(), ReconcileError> {
    let configmaps_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let selector = policy_selector(policy_name);
    // Filtering by owner UID here is what makes this loop safe: `existing_plans`
    // is already restricted to this policy, so a colliding policy's ConfigMap
    // would otherwise have an unknown plan label and be deleted as an orphan.
    let configmaps: Vec<ConfigMap> = configmaps_api
        .list(&ListParams::default().labels_from(&selector))
        .await?
        .into_iter()
        .filter(|configmap| is_owned_by_policy(configmap, policy))
        .collect();
    let known_plan_labels: BTreeSet<String> = existing_plans
        .iter()
        .map(|plan| plan_label_value(&plan.name_any()))
        .collect();
    let known_plan_names: BTreeSet<String> =
        existing_plans.iter().map(ResourceExt::name_any).collect();

    for configmap in configmaps {
        if !is_orphan_sql_configmap(&configmap, &known_plan_names, &known_plan_labels, now_ts) {
            continue;
        }

        let configmap_name = configmap.name_any();
        info!(
            configmap = %configmap_name,
            policy = %policy_name,
            "cleaning up orphan plan SQL ConfigMap"
        );
        if let Err(err) = configmaps_api
            .delete(&configmap_name, &DeleteParams::default())
            .await
        {
            tracing::warn!(
                configmap = %configmap_name,
                %err,
                "failed to delete orphan plan SQL ConfigMap during cleanup"
            );
        }
    }

    Ok(())
}

fn is_orphan_sql_configmap(
    configmap: &ConfigMap,
    known_plan_names: &BTreeSet<String>,
    known_plan_labels: &BTreeSet<String>,
    now_ts: i64,
) -> bool {
    let Some(labels) = configmap.metadata.labels.as_ref() else {
        return false;
    };
    if !labels.contains_key(LABEL_POLICY) || !is_stale_object(configmap, now_ts) {
        return false;
    }
    if known_plan_names.contains(configmap_plan_name(&configmap.name_any())) {
        return false;
    }
    labels
        .get(LABEL_PLAN)
        .map(|plan_label| !known_plan_labels.contains(plan_label))
        .unwrap_or(true)
}

// SQL-equivalent changes can still have different scope, policy generations,
// or candidate base pins. Recover only the exact interrupted create: status
// for a new computation must never be attached to another persisted spec.
fn can_resume_plan_creation(
    existing: &PostgresPolicyPlan,
    intended_spec: &PostgresPolicyPlanSpec,
) -> bool {
    existing.spec == *intended_spec && should_patch_existing_plan_status(existing)
}

fn should_patch_existing_plan_status(plan: &PostgresPolicyPlan) -> bool {
    plan.status
        .as_ref()
        .map(|status| {
            status.phase == PlanPhase::Pending
                && status.change_digest.is_none()
                && status.computed_at.is_none()
                && status.sql_hash.is_none()
                && !has_terminal_decision(status)
        })
        .unwrap_or(true)
}

/// Which terminal plans retention evicts this pass.
///
/// Pure and takes `now` as an argument, so the policy is testable without a
/// cluster — the bounds are the part worth pinning, and they are invisible in
/// an integration test that would have to create hundreds of objects to reach
/// them.
///
/// `pgroles.io/keep=true` exempts an object from every bound: retention caps
/// unbounded growth, it is not a policy about what an operator may keep.
fn plans_to_evict(
    plans: &[PostgresPolicyPlan],
    retention: PlanRetention,
    now_ts: i64,
) -> Vec<&PostgresPolicyPlan> {
    let mut applied = Vec::new();
    let mut decided = Vec::new();
    let mut superseded = Vec::new();

    for plan in plans.iter().filter(|plan| !is_retention_exempt(*plan)) {
        let Some(phase) = plan.status.as_ref().map(|status| &status.phase) else {
            continue;
        };
        match phase {
            PlanPhase::Applied => applied.push(plan),
            PlanPhase::Failed | PlanPhase::Rejected => decided.push(plan),
            PlanPhase::Superseded => superseded.push(plan),
            // Still live. Never evicted, however old.
            PlanPhase::Pending | PlanPhase::Approved | PlanPhase::Applying => {}
        }
    }

    let mut evict = oldest_beyond(&mut decided, retention.decided);
    evict.extend(oldest_beyond(&mut superseded, retention.superseded));
    evict.extend(applied_plans_to_evict(applied, retention, now_ts));
    evict
}

/// Which `Applied` plans the retention bounds evict from `applied`.
///
/// Applied is the audit record of what actually ran, so its count bound
/// yields to the age floor. Walk oldest first and stop once the count bound
/// is met; spare anything still inside the floor along the way, unless the
/// survivors would breach the ceiling. Sparing is what makes the retained
/// span a promise rather than a function of how often the policy applies.
///
/// Both the order and the floor measure from [`applied_epoch_secs`] — one
/// notion of "when did this apply" drives the whole walk. Ordering by
/// creation instead would evict a plan created before a long review but
/// applied moments ago, ahead of older executions whose objects happen to be
/// newer.
///
/// Shared with terminal-candidate pruning: deleting a promoted candidate
/// cascades to the `Applied` plan it owns, so the candidate is held to these
/// same bounds (see `candidate::terminal_candidates_to_prune`).
pub(crate) fn applied_plans_to_evict(
    mut applied: Vec<&PostgresPolicyPlan>,
    retention: PlanRetention,
    now_ts: i64,
) -> Vec<&PostgresPolicyPlan> {
    applied.sort_by_key(|plan| applied_epoch_secs(plan));
    let mut evict = Vec::new();
    let mut remaining = applied.len();
    for plan in applied {
        if remaining <= retention.applied {
            break;
        }
        let inside_floor = applied_age_secs(plan, now_ts) < retention.applied_min_age_secs;
        if inside_floor && remaining <= retention.applied_ceiling {
            continue;
        }
        evict.push(plan);
        remaining -= 1;
    }
    evict
}

/// Sort oldest first and return everything past `keep`.
fn oldest_beyond<'a>(
    plans: &mut Vec<&'a PostgresPolicyPlan>,
    keep: usize,
) -> Vec<&'a PostgresPolicyPlan> {
    if plans.len() <= keep {
        return Vec::new();
    }
    sort_oldest_first(plans);
    plans[..plans.len() - keep].to_vec()
}

fn sort_oldest_first(plans: &mut [&PostgresPolicyPlan]) {
    plans.sort_by(|a, b| {
        a.metadata
            .creation_timestamp
            .as_ref()
            .cmp(&b.metadata.creation_timestamp.as_ref())
    });
}

/// When an `Applied` plan applied, as epoch seconds: `status.appliedAt`,
/// falling back to the creation timestamp when it is absent or unparseable so
/// plans recorded before it was set keep the creation-time behaviour rather
/// than reading as infinitely old. `None` when neither instant is known.
///
/// This is the single notion of "when did this apply" behind both the
/// retention floor and the eviction order — the floor promises
/// post-application history, and a plan can sit `Pending` or `Approved` for
/// arbitrarily long before a reviewer decides it, so measuring from creation
/// would read a plan approved late as already outside that promise.
fn applied_epoch_secs(plan: &PostgresPolicyPlan) -> Option<i64> {
    plan.status
        .as_ref()
        .and_then(|status| status.applied_at.as_deref())
        .and_then(parse_rfc3339_epoch_secs)
        .or_else(|| {
            plan.metadata
                .creation_timestamp
                .as_ref()
                .map(|timestamp| timestamp.0.as_second())
        })
}

/// Age of an `Applied` plan for the retention floor — see
/// [`applied_epoch_secs`]. An unknown instant is age 0: brand new is the safe
/// direction for a deletion decision.
fn applied_age_secs(plan: &PostgresPolicyPlan, now_ts: i64) -> i64 {
    applied_epoch_secs(plan)
        .map(|applied_ts| now_ts.saturating_sub(applied_ts))
        .unwrap_or(0)
}

fn is_stale_statusless_plan(plan: &PostgresPolicyPlan, now_ts: i64) -> bool {
    plan.status.is_none() && is_stale_object(plan, now_ts)
}

fn is_stale_object<K>(resource: &K, now_ts: i64) -> bool
where
    K: Resource,
{
    resource
        .meta()
        .creation_timestamp
        .as_ref()
        .map(|timestamp| now_ts.saturating_sub(timestamp.0.as_second()) > ORPHAN_GRACE_SECS)
        .unwrap_or(false)
}

async fn delete_plan_best_effort(plans_api: &Api<PostgresPolicyPlan>, plan_name: &str) {
    if let Err(err) = plans_api.delete(plan_name, &DeleteParams::default()).await {
        tracing::warn!(
            plan = %plan_name,
            %err,
            "failed to roll back plan after status update failure"
        );
    }
}

/// Undo this reconcile's plan-SQL ConfigMap write, if there was one.
///
/// A no-op for a ConfigMap that already existed and was adopted: that one backs
/// an earlier plan, and deleting it on our failure path would break it.
async fn rollback_plan_sql_configmap(
    client: &Client,
    namespace: &str,
    configmap: Option<&PlanSqlConfigMap>,
) {
    if let Some(configmap) = configmap
        && configmap.created
    {
        delete_configmap_best_effort(client, namespace, &configmap.name).await;
    }
}

async fn delete_configmap_best_effort(client: &Client, namespace: &str, configmap_name: &str) {
    let configmaps_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    if let Err(err) = configmaps_api
        .delete(configmap_name, &DeleteParams::default())
        .await
    {
        tracing::warn!(
            configmap = %configmap_name,
            %err,
            "failed to roll back plan SQL ConfigMap"
        );
    }
}

/// Render the full executable SQL from changes (including real passwords).
pub(crate) fn render_full_sql(
    changes: &[pgroles_core::diff::Change],
    sql_context: &pgroles_core::sql::SqlContext,
) -> String {
    pgroles_core::sql::render_all_with_context(changes, sql_context)
}

/// Render redacted SQL for display (passwords replaced with [REDACTED]).
fn render_redacted_sql(
    changes: &[pgroles_core::diff::Change],
    sql_context: &pgroles_core::sql::SqlContext,
) -> String {
    pgroles_core::sql::render_batch_with_context(changes, sql_context)
        .into_iter()
        .map(|statement| statement.redacted_sql)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Compute the canonical approval-effect digest for a set of changes.
///
/// This is the approval identity — see `pgroles_core::approval`. Unlike the
/// SQL hash it is stable across recomputation of unchanged effects, which is
/// what makes a password-bearing plan approvable at all.
#[allow(clippy::too_many_arguments)]
pub(crate) fn compute_change_digest(
    changes: &[pgroles_core::diff::Change],
    reconciliation_mode: CrdReconciliationMode,
    database_identity: &str,
    target_identity: &TargetIdentity,
    password_source_versions: &BTreeMap<String, String>,
    owned_roles: &[String],
    owned_schemas: &[String],
) -> Result<String, ReconcileError> {
    Ok(pgroles_core::approval::compute_change_digest(
        changes,
        &pgroles_core::approval::EffectDigestInputs {
            reconciliation_mode: reconciliation_mode.into(),
            target: database_identity,
            target_identity,
            password_source_versions,
            owned_roles,
            owned_schemas,
        },
    )?)
}

/// The target identity a stored plan was computed against.
///
/// A plan written before this field existed reports neither identity and no
/// availability marker; it cannot match anything observed now, and its digest
/// encoding is older too, so it supersedes rather than executing.
pub(crate) fn plan_target_identity(
    status: &crate::crd::PostgresPolicyPlanStatus,
) -> TargetIdentity {
    TargetIdentity {
        physical: status.target_physical_identity.clone(),
        logical: status.target_logical_fingerprint.clone(),
    }
}

/// Whether a stored plan status carries the given change digest under the
/// current encoding.
///
/// Digests from a different encoding version are never comparable, so a plan
/// written by an earlier operator (no digest, or an older encoding) never
/// matches. Such plans are superseded and re-reviewed rather than silently
/// accepted — the fail-closed direction.
pub(crate) fn plan_matches_digest(
    status: &crate::crd::PostgresPolicyPlanStatus,
    change_digest: &str,
) -> bool {
    status.change_digest_encoding.as_deref() == Some(APPROVAL_EFFECT_ENCODING_V3)
        && status.change_digest.as_deref() == Some(change_digest)
}

/// Compute SHA-256 hash of the SQL string as a hex digest.
pub(crate) fn compute_sql_hash(sql: &str) -> String {
    use std::fmt::Write as _;

    let mut hasher = Sha256::new();
    hasher.update(sql.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to a string should succeed");
    }
    hex
}

/// Generate a plan name from policy name, current timestamp, and SQL hash.
///
/// Format: `{policy-name}-plan-{YYYYMMDD-HHMMSS}-{hash-prefix}`
///
/// The hash suffix makes retries within the same second idempotent if SQL
/// content persistence succeeds but plan creation fails.
fn generate_plan_name(policy_name: &str, sql_hash: &str) -> String {
    let timestamp = format_timestamp_compact();
    // Freeze only the named test policy, allowing a live 409 without racing
    // the wall clock. Ordinary/released builds omit this branch entirely.
    #[cfg(feature = "e2e-fault-injection")]
    let timestamp = if std::env::var("PGROLES_E2E_FREEZE_PLAN_NAME_FOR")
        .ok()
        .as_deref()
        == Some(policy_name)
    {
        "20000101-000000".to_string()
    } else {
        timestamp
    };
    let suffix = &sql_hash[..12.min(sql_hash.len())];
    // Kubernetes names must be <= 253 chars and DNS-compatible.
    // Reserve 4 chars for the potential "-sql" ConfigMap suffix.
    let max_name_len = crate::k8s_names::MAX_RESOURCE_NAME_LENGTH - 4; // 249
    let max_prefix_len = max_name_len - "-plan-".len() - timestamp.len() - "-".len() - suffix.len();
    // Truncation can land on a `.` or `-`; appending `-plan-...` after a
    // trailing `.` would start a new DNS label with `-`, which the API server
    // rejects, so `truncate_name_prefix` trims the separators the cut exposes.
    let prefix = truncate_name_prefix(policy_name, max_prefix_len);
    format!("{prefix}-plan-{timestamp}-{suffix}")
}

/// Format the current UTC time as `YYYYMMDD-HHMMSS`.
fn format_timestamp_compact() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let (year, month, day) = crate::crd::days_to_date(secs / 86400);
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;
    format!("{year:04}{month:02}{day:02}-{hours:02}{minutes:02}{seconds:02}")
}

/// Sanitize a string for use as a Kubernetes label value.
///
/// See [`crate::k8s_names::LabelValue::sanitize`] for the rules. This is the
/// single builder for every label value the operator writes, and is also used
/// to build the selectors that read them back, so writes and lookups agree.
fn sanitize_label_value(value: &str) -> String {
    LabelValue::sanitize(value).into_string()
}

/// Label selector matching every object owned by `policy_name`.
///
/// This narrows server-side but is **not** an identity: the label value is
/// truncated at 63 characters, so two policies sharing a 63-character prefix
/// select each other's objects. Always pair it with [`is_owned_by_policy`].
fn policy_selector(policy_name: &str) -> Selector {
    Expression::Equal(LABEL_POLICY.to_string(), sanitize_label_value(policy_name)).into()
}

/// Label selector matching every plan produced for one candidate.
///
/// Lossy in exactly the way [`policy_selector`] is, and paired with the same
/// owner-UID check.
fn candidate_selector(candidate_name: &str) -> Selector {
    Expression::Equal(
        LABEL_CANDIDATE.to_string(),
        sanitize_label_value(candidate_name),
    )
    .into()
}

/// Is `resource` owned by `policy`, by controller-owner UID?
///
/// The exact ownership test. The `pgroles.io/policy` label is lossy, and a
/// truncated collision would otherwise let one policy adopt, supersede,
/// deduplicate against, or **delete** another policy's plans and plan-SQL
/// ConfigMaps. A UID is unique per object and per object lifetime, so this also
/// stops a same-named replacement policy from inheriting a deleted one's
/// objects.
///
/// Objects the operator did not create carry no matching owner reference and are
/// excluded, which is the safe direction for the deletion paths.
fn is_owned_by_policy<K: Resource>(resource: &K, policy: &PostgresPolicy) -> bool {
    let Some(policy_uid) = policy.metadata.uid.as_deref() else {
        // A policy with no UID cannot own anything; refuse to match rather than
        // treat an empty UID as a wildcard.
        return false;
    };
    is_owned_by_uid(resource, policy_uid)
}

/// Is `resource` controlled by the object with this UID?
pub(crate) fn is_owned_by_uid<K: Resource>(resource: &K, uid: &str) -> bool {
    resource
        .meta()
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|owner| owner.uid == uid && owner.controller.unwrap_or(false))
}

/// Does `resource` carry a controller owner that is *not* `policy`?
///
/// Deliberately not `!is_owned_by_policy`. An object with no controller owner at
/// all — an orphan left behind by `--cascade=orphan` — belongs to nobody, so it
/// stays adoptable and this returns false. Only a live claim by a *different*
/// policy blocks adoption.
///
/// Fails closed: a policy with no UID cannot prove ownership of anything, so
/// every owned object counts as another's.
fn is_owned_by_another<K: Resource>(resource: &K, owner_object: PlanOwner<'_>) -> bool {
    let policy_uid = owner_object.uid();
    resource
        .meta()
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|owner| owner.controller.unwrap_or(false) && Some(owner.uid.as_str()) != policy_uid)
}

/// Current time as Unix epoch seconds (for dedup window checks).
fn now_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Parse an RFC 3339 timestamp string to Unix epoch seconds.
/// Returns `None` if parsing fails.
fn parse_rfc3339_epoch_secs(rfc3339: &str) -> Option<i64> {
    // Use jiff (already a transitive dep via k8s-openapi) for RFC 3339 parsing.
    rfc3339
        .parse::<jiff::Timestamp>()
        .ok()
        .map(|t| t.as_second())
}

/// Build an OwnerReference pointing from a plan to its parent policy.
fn build_owner_reference(policy: &PostgresPolicy) -> OwnerReference {
    OwnerReference {
        api_version: PostgresPolicy::api_version(&()).to_string(),
        kind: PostgresPolicy::kind(&()).to_string(),
        name: policy.name_any(),
        uid: policy.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

/// Update the phase field on a plan's status.
///
/// When transitioning to `Applying`, also sets `applying_since` for stuck
/// plan detection.
async fn update_plan_phase(
    plans_api: &Api<PostgresPolicyPlan>,
    plan_name: &str,
    phase: PlanPhase,
) -> Result<(), ReconcileError> {
    let mut patch_value = serde_json::json!({ "status": { "phase": phase } });
    if phase == PlanPhase::Applying {
        patch_value["status"]["applying_since"] = serde_json::json!(crate::crd::now_rfc3339());
    }
    plans_api
        .patch_status(
            plan_name,
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&patch_value),
        )
        .await?;
    Ok(())
}

/// Set or update a condition in a conditions list.
///
/// Preserves `last_transition_time` when the status value is unchanged
/// (only reason/message changed), matching Kubernetes condition conventions.
fn set_plan_condition(
    conditions: &mut Vec<PolicyCondition>,
    condition_type: &str,
    status: &str,
    reason: &str,
    message: &str,
) {
    let transition_time = if let Some(existing) = conditions
        .iter()
        .find(|c| c.condition_type == condition_type)
    {
        if existing.status == status {
            existing.last_transition_time.clone()
        } else {
            Some(crate::crd::now_rfc3339())
        }
    } else {
        Some(crate::crd::now_rfc3339())
    };

    let condition = PolicyCondition {
        condition_type: condition_type.to_string(),
        status: status.to_string(),
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        last_transition_time: transition_time,
    };
    // Collapse to exactly one entry per condition type. Replacing only the
    // first match would leave a duplicate in place, and a second `Approved`
    // that this never touches makes the CRD's terminality rule see the
    // decision set grow — rejecting the operator's own writes and stranding
    // the plan. A malformed status should not be able to do that.
    conditions.retain(|c| c.condition_type != condition_type);
    conditions.push(condition);
}

/// Update the parent policy's `current_plan_ref` in status.
pub async fn update_policy_plan_ref(
    client: &Client,
    policy: &PostgresPolicy,
    plan_name: &str,
) -> Result<(), ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_api: Api<PostgresPolicy> = Api::namespaced(client.clone(), &namespace);

    let patch = serde_json::json!({
        "status": {
            "current_plan_ref": PlanReference {
                name: plan_name.to_string(),
            }
        }
    });

    policy_api
        .patch_status(
            &policy.name_any(),
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&patch),
        )
        .await?;

    Ok(())
}

/// Look up the current actionable plan for a policy, if any.
///
/// An actionable plan is one in `Pending` or `Approved` phase — i.e. a plan
/// that the reconciler should evaluate for approval/execution.
pub async fn get_current_actionable_plan(
    client: &Client,
    policy: &PostgresPolicy,
) -> Result<Option<PostgresPolicyPlan>, ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_name = policy.name_any();

    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);
    let selector = policy_selector(&policy_name);
    let existing_plans: Vec<PostgresPolicyPlan> = plans_api
        .list(&ListParams::default().labels_from(&selector))
        .await?
        .into_iter()
        .filter(|plan| is_owned_by_policy(plan, policy))
        .collect();

    // Find the most recent actionable plan (Pending or Approved, by creation time).
    let mut pending_plans: Vec<PostgresPolicyPlan> = existing_plans
        .into_iter()
        .filter(|plan| {
            plan.status
                .as_ref()
                .map(|s| matches!(s.phase, PlanPhase::Pending | PlanPhase::Approved))
                .unwrap_or(false)
        })
        .collect();

    pending_plans.sort_by(|a, b| {
        let a_time = a.metadata.creation_timestamp.as_ref();
        let b_time = b.metadata.creation_timestamp.as_ref();
        b_time.cmp(&a_time) // newest first
    });

    Ok(pending_plans.into_iter().next())
}

/// Look up the most recent plan for a policy in a given phase.
pub async fn get_plan_by_phase(
    client: &Client,
    policy: &PostgresPolicy,
    target_phase: PlanPhase,
) -> Result<Option<PostgresPolicyPlan>, ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_name = policy.name_any();

    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);
    let selector = policy_selector(&policy_name);
    let existing_plans: Vec<PostgresPolicyPlan> = plans_api
        .list(&ListParams::default().labels_from(&selector))
        .await?
        .into_iter()
        .filter(|plan| is_owned_by_policy(plan, policy))
        .collect();

    let mut matching_plans: Vec<PostgresPolicyPlan> = existing_plans
        .into_iter()
        .filter(|plan| {
            plan.status
                .as_ref()
                .map(|s| s.phase == target_phase)
                .unwrap_or(false)
        })
        .collect();

    matching_plans.sort_by(|a, b| {
        let a_time = a.metadata.creation_timestamp.as_ref();
        let b_time = b.metadata.creation_timestamp.as_ref();
        b_time.cmp(&a_time) // newest first
    });

    Ok(matching_plans.into_iter().next())
}

/// Mark a plan as Failed with a given error message.
pub async fn mark_plan_failed(
    client: &Client,
    plan: &PostgresPolicyPlan,
    error_message: &str,
) -> Result<(), ReconcileError> {
    let namespace = plan.namespace().ok_or(ReconcileError::NoNamespace)?;
    let plan_name = plan.name_any();
    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);

    let mut status = plan.status.clone().unwrap_or_default();
    status.phase = PlanPhase::Failed;
    status.last_error = Some(error_message.to_string());
    status.failed_at = Some(crate::crd::now_rfc3339());

    let patch = serde_json::json!({ "status": status });
    plans_api
        .patch_status(
            &plan_name,
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&patch),
        )
        .await?;

    info!(
        plan = %plan_name,
        "marked stuck Applying plan as Failed"
    );

    Ok(())
}

/// Mark a plan as Approved.
///
/// Callers provide `reason` and `message` to distinguish auto-approval from
/// manual approval in the plan's conditions.
///
/// When a terminal decision is already recorded — a reviewer approved this
/// plan, which is the whole of the manual path and of an adopted candidate
/// plan — only the phase advances. The decision, its reason and message, and
/// `decidedBy` are the reviewer's record: rewriting them would overwrite what
/// a human said with the operator's own boilerplate, and resending the whole
/// array from a watch-backed read could drop a decision that landed after that
/// read. This is the same reasoning as [`mark_plan_rejected`].
pub async fn mark_plan_approved(
    client: &Client,
    plan: &PostgresPolicyPlan,
    reason: &str,
    message: &str,
) -> Result<(), ReconcileError> {
    let namespace = plan.namespace().ok_or(ReconcileError::NoNamespace)?;
    let plan_name = plan.name_any();
    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);

    let existing = plan.status.clone().unwrap_or_default();
    if has_terminal_decision(&existing) {
        let patch = serde_json::json!({ "status": { "phase": PlanPhase::Approved } });
        plans_api
            .patch_status(
                &plan_name,
                &PatchParams::apply("pgroles-operator"),
                &Patch::Merge(&patch),
            )
            .await?;
        return Ok(());
    }

    let mut status = existing;
    status.phase = PlanPhase::Approved;
    set_plan_condition(&mut status.conditions, "Approved", "True", reason, message);
    // Under `approval: auto` the operator itself is the decider, and the CEL
    // rule requires the identity in the same write as the decision. Naming the
    // operator is also the honest record: no human reviewed this.
    if status.decided_by.is_none() {
        status.decided_by = Some(crate::crd::DecisionActor {
            username: AUTO_APPROVAL_ACTOR.to_string(),
            uid: None,
            groups: Vec::new(),
        });
    }

    let patch = serde_json::json!({ "status": status });
    plans_api
        .patch_status(
            &plan_name,
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&patch),
        )
        .await?;

    Ok(())
}

/// Mark a plan as Rejected.
pub async fn mark_plan_rejected(
    client: &Client,
    plan: &PostgresPolicyPlan,
) -> Result<(), ReconcileError> {
    let namespace = plan.namespace().ok_or(ReconcileError::NoNamespace)?;
    let plan_name = plan.name_any();
    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);

    // Patch the phase alone. The reviewer's `Denied=True` is the decision and
    // is terminal, so there is nothing here for the operator to add to the
    // conditions — and resending the whole array from a watch-backed read
    // could drop a decision that landed after that read.
    let patch = serde_json::json!({ "status": { "phase": PlanPhase::Rejected } });
    plans_api
        .patch_status(
            &plan_name,
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&patch),
        )
        .await?;

    Ok(())
}

/// Whether a terminal decision — `Approved=True` or `Denied=True` — is
/// recorded on this status.
///
/// This is exactly the predicate the CRD's CEL rules key off: once it is true,
/// the set of decisions that are true is frozen and `decidedBy` is write-once.
pub(crate) fn has_terminal_decision(status: &PostgresPolicyPlanStatus) -> bool {
    status.conditions.iter().any(|c| {
        (c.condition_type == "Approved" || c.condition_type == "Denied") && c.status == "True"
    })
}

/// The status a supersede writes: the plan is voided by its *phase*, and the
/// cause is recorded on a `Superseded` condition.
///
/// Voiding must never be expressed by flipping a recorded decision. The plan
/// CRD holds a decision terminal — the set of decision types that are `True`
/// may not change once non-empty — and pairs any terminal decision with a
/// write-once `decidedBy`. Writing `Approved=False` over a real approval
/// breaks both rules at once, so against a live API server the write is
/// rejected and the stale approved plan stays actionable. Execution gates on
/// phase (`get_current_actionable_plan` only considers `Pending`/`Approved`)
/// plus a digest match, so `Superseded` alone is what makes a plan
/// unexecutable; the decision record is left exactly as the reviewer left it.
///
/// A plan that was never decided has no decision to preserve, so the
/// retirement cause is also stamped on its already-`False` `Approved`
/// condition, where reviewers have always read it.
pub(crate) fn superseded_status(
    status: &PostgresPolicyPlanStatus,
    cause: SupersedeCause,
) -> PostgresPolicyPlanStatus {
    let mut next = status.clone();
    next.phase = PlanPhase::Superseded;
    set_plan_condition(
        &mut next.conditions,
        crate::crd::CONDITION_SUPERSEDED,
        "True",
        cause.reason(),
        cause.message(),
    );
    if !has_terminal_decision(status) {
        set_plan_condition(
            &mut next.conditions,
            "Approved",
            "False",
            cause.reason(),
            cause.message(),
        );
    }
    next
}

/// Mark a plan as Superseded, recording `cause` on a `Superseded` condition so
/// the reason the plan was retired survives on the object.
///
/// Safe to call on a plan carrying a human decision: see [`superseded_status`].
pub async fn mark_plan_superseded(
    client: &Client,
    plan: &PostgresPolicyPlan,
    cause: SupersedeCause,
) -> Result<(), ReconcileError> {
    let namespace = plan.namespace().ok_or(ReconcileError::NoNamespace)?;
    let plan_name = plan.name_any();
    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);

    let status = superseded_status(&plan.status.clone().unwrap_or_default(), cause);

    let patch = serde_json::json!({ "status": status });
    plans_api
        .patch_status(
            &plan_name,
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&patch),
        )
        .await?;

    Ok(())
}

/// Whether a pending plan needs its revalidation provenance refreshed.
///
/// The plan's effects have already been confirmed current by the caller; this
/// only decides whether the *record* of that confirmation is stale. Patching on
/// every reconcile would churn the object and its events for no information.
pub(crate) fn needs_revalidation_record(
    status: &crate::crd::PostgresPolicyPlanStatus,
    generation: Option<i64>,
) -> bool {
    status.revalidated_generation != generation
}

/// What to do with a plan that is still awaiting a manual decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingPlanDecision {
    /// The effects are unchanged. The plan, and any decision on it, stand.
    Retain,
    /// The effects moved. Supersede the plan and open a new one for review.
    Replace,
    /// The effects are gone. Supersede the plan and leave none in its place —
    /// a replacement would hold no changes yet still demand an approval, and
    /// the policy would report `Drifted=False` while blocked on it.
    Clear,
}

/// Decide the fate of a pending plan against the effects the policy would
/// produce right now.
///
/// `plan_status` is `None` for a plan whose status has not been written yet;
/// like a plan under an older digest encoding it cannot be shown to still hold
/// the current effects, so it is superseded rather than trusted.
pub(crate) fn decide_pending_plan(
    plan_status: Option<&crate::crd::PostgresPolicyPlanStatus>,
    fresh_digest: &str,
    has_changes: bool,
) -> PendingPlanDecision {
    // Nothing to execute means nothing to approve, whatever the plan holds.
    // A plan that still matches an empty change set is itself a no-op, so it
    // is cleared too rather than left blocking on a decision.
    if !has_changes {
        return PendingPlanDecision::Clear;
    }

    if plan_status.is_some_and(|status| plan_matches_digest(status, fresh_digest)) {
        PendingPlanDecision::Retain
    } else {
        PendingPlanDecision::Replace
    }
}

/// What to do with a plan that a reviewer has approved but that has not yet
/// executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApprovedPlanDecision {
    /// The approved effects are still the effects this policy would produce.
    /// Execute what was reviewed.
    Execute,
    /// The effects moved between the decision and this reconcile. The approval
    /// described something else, so it cannot authorise this — supersede and
    /// open a new plan for review.
    Replace,
    /// The effects moved to nothing. Supersede and leave no plan behind, for
    /// the same reason as `PendingPlanDecision::Clear`: a zero-change
    /// replacement would demand a second approval that buys nothing while the
    /// policy reports no drift beside it.
    Clear,
}

/// Decide the fate of an approved plan against the effects the policy would
/// produce right now.
///
/// This is the single gate between a recorded decision and executing DDL, so it
/// fails closed: a plan whose status is missing, or written under an older
/// digest encoding, cannot be shown to still hold the approved effects and is
/// never executed.
///
/// Unlike [`decide_pending_plan`], a matching digest executes even when the
/// change set is empty. An approved no-op plan is resolved by running it — that
/// marks it Applied and releases the policy — whereas an unapproved no-op plan
/// would sit waiting for a decision no one should have to make.
pub(crate) fn decide_approved_plan(
    plan_status: Option<&crate::crd::PostgresPolicyPlanStatus>,
    fresh_digest: &str,
    has_changes: bool,
) -> ApprovedPlanDecision {
    if plan_status.is_some_and(|status| plan_matches_digest(status, fresh_digest)) {
        return ApprovedPlanDecision::Execute;
    }

    if has_changes {
        ApprovedPlanDecision::Replace
    } else {
        ApprovedPlanDecision::Clear
    }
}

/// Record that a pending plan was re-confirmed against the current policy.
///
/// Called when the freshly computed effects still match what the plan holds, so
/// the plan and any decision on it survive a policy change that turned out to
/// be effect-neutral.
pub async fn record_plan_revalidation(
    client: &Client,
    plan: &PostgresPolicyPlan,
    generation: Option<i64>,
) -> Result<(), ReconcileError> {
    let namespace = plan.namespace().ok_or(ReconcileError::NoNamespace)?;
    let plan_name = plan.name_any();
    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(client.clone(), &namespace);

    let patch = serde_json::json!({
        "status": {
            "revalidatedGeneration": generation,
            "revalidatedAt": crate::crd::now_rfc3339(),
        }
    });
    plans_api
        .patch_status(
            &plan_name,
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&patch),
        )
        .await?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::CrdReconciliationMode;
    use crate::crd::{LocalObjectReference, PolicyContent, PostgresPolicyCandidateSpec};
    use base64::Engine as _;
    use flate2::read::GzDecoder;
    use std::io::Read;

    fn test_plan_spec() -> PostgresPolicyPlanSpec {
        PostgresPolicyPlanSpec {
            policy_ref: PolicyPlanRef {
                name: "orders".to_string(),
            },
            policy_generation: 1,
            reconciliation_mode: CrdReconciliationMode::Authoritative,
            owned_roles: Vec::new(),
            owned_schemas: Vec::new(),
            managed_database_identity: "default/db/DATABASE_URL".to_string(),
            origin: None,
            scope: None,
        }
    }

    fn test_candidate(name: &str, uid: &str) -> PostgresPolicyCandidate {
        let mut candidate = PostgresPolicyCandidate::new(
            name,
            PostgresPolicyCandidateSpec {
                policy_ref: LocalObjectReference {
                    name: "orders".to_string(),
                },
                replaces: None,
                target: None,
                content: PolicyContent::default(),
            },
        );
        candidate.metadata.namespace = Some("default".to_string());
        candidate.metadata.uid = Some(uid.to_string());
        candidate
    }

    #[test]
    fn a_candidate_plan_binds_the_candidate_the_content_and_the_policy() {
        let mut policy = PostgresPolicy::new("orders", test_policy_spec());
        policy.metadata.uid = Some("policy-uid".to_string());
        let candidate = test_candidate("orders-change-x7k2p", "candidate-uid");

        let origin = candidate_plan_origin(
            CandidatePlanBinding {
                candidate: &candidate,
                content_digest: "sha256:abc",
                content_digest_encoding: pgroles_core::candidate::CANDIDATE_CONTENT_ENCODING_V1,
                base_content_digest: "sha256:base",
            },
            &policy,
        );

        assert_eq!(origin.kind, "PostgresPolicyCandidate");
        assert_eq!(origin.name, "orders-change-x7k2p");
        assert_eq!(origin.uid, "candidate-uid");
        assert_eq!(origin.content_digest.as_deref(), Some("sha256:abc"));
        assert_eq!(
            origin.content_digest_encoding.as_deref(),
            Some(pgroles_core::candidate::CANDIDATE_CONTENT_ENCODING_V1)
        );
        // The policy's UID, not its name: a delete-and-recreate of the same
        // name is a different policy, and a plan reviewed against the old one
        // must not read as bound to the new one.
        assert_eq!(origin.policy_uid.as_deref(), Some("policy-uid"));
    }

    #[test]
    fn a_candidate_plan_is_owned_by_the_candidate_not_the_policy() {
        // ADR-001 Decision 3: plan pruning cascades from candidate deletion.
        let mut policy = PostgresPolicy::new("orders", test_policy_spec());
        policy.metadata.uid = Some("policy-uid".to_string());
        let candidate = test_candidate("orders-change-x7k2p", "candidate-uid");

        let owner = PlanOwner::Candidate(&candidate).owner_reference();
        assert_eq!(owner.kind, "PostgresPolicyCandidate");
        assert_eq!(owner.uid, "candidate-uid");
        assert_eq!(owner.controller, Some(true));
        assert_eq!(owner.block_owner_deletion, Some(true));

        let mut plan = PostgresPolicyPlan::new("plan", test_plan_spec());
        plan.metadata.owner_references = Some(vec![owner]);
        assert!(PlanOwner::Candidate(&candidate).owns(&plan));
        // The policy's own retention loop filters by its UID, so a candidate
        // plan is invisible to it — which is what keeps it alive for review.
        assert!(!is_owned_by_policy(&plan, &policy));
    }

    #[test]
    fn the_keep_label_exempts_a_terminal_object_from_retention() {
        let mut plan = PostgresPolicyPlan::new("plan", test_plan_spec());
        assert!(!crate::crd::is_retention_exempt(&plan));
        plan.metadata.labels = Some(BTreeMap::from([(
            crate::crd::LABEL_KEEP.to_string(),
            "true".to_string(),
        )]));
        assert!(crate::crd::is_retention_exempt(&plan));
    }

    /// Build a plan in `phase`, having recorded a failure `age_secs` ago.
    /// A terminal plan of `phase`, created `age_secs` ago.
    fn retained_plan(
        name: &str,
        phase: PlanPhase,
        age_secs: i64,
        now_ts: i64,
    ) -> PostgresPolicyPlan {
        let mut plan = PostgresPolicyPlan::new(name, test_plan_spec());
        plan.metadata.creation_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                jiff::Timestamp::from_second(now_ts - age_secs).expect("epoch second in range"),
            ));
        plan.status = Some(PostgresPolicyPlanStatus {
            phase,
            ..Default::default()
        });
        plan
    }

    fn evicted_names(
        plans: &[PostgresPolicyPlan],
        retention: PlanRetention,
        now_ts: i64,
    ) -> Vec<String> {
        let mut names: Vec<String> = plans_to_evict(plans, retention, now_ts)
            .into_iter()
            .map(|plan| plan.name_any())
            .collect();
        names.sort();
        names
    }

    /// The bug this split exists for: replan churn must not evict the record
    /// of what actually ran. Under one pooled bound the Superseded plans, being
    /// newer, kept every slot and the Applied ones were deleted.
    #[test]
    fn superseded_churn_does_not_evict_applied_plans() {
        let now = 1_700_000_000;
        let retention = PlanRetention::default();
        let year = 400 * 24 * 60 * 60;

        let mut plans = vec![retained_plan("applied-old", PlanPhase::Applied, year, now)];
        // Far more superseded plans than any pooled bound would have allowed,
        // all newer than the applied one.
        for i in 0..50 {
            plans.push(retained_plan(
                &format!("superseded-{i:03}"),
                PlanPhase::Superseded,
                1000 - i,
                now,
            ));
        }

        let evicted = evicted_names(&plans, retention, now);
        assert!(
            !evicted.contains(&"applied-old".to_string()),
            "an applied plan must survive any amount of replan churn"
        );
        assert_eq!(
            evicted.len(),
            50 - retention.superseded,
            "every superseded plan past the small bound is evicted"
        );
    }

    #[test]
    fn each_terminal_phase_is_bounded_separately() {
        let now = 1_700_000_000;
        let retention = PlanRetention::default();
        let year = 400 * 24 * 60 * 60;

        let mut plans = Vec::new();
        for (prefix, phase, count) in [
            ("applied", PlanPhase::Applied, retention.applied + 4),
            ("failed", PlanPhase::Failed, retention.decided + 4),
            (
                "superseded",
                PlanPhase::Superseded,
                retention.superseded + 4,
            ),
        ] {
            for i in 0..count {
                // Older than the age floor, so only the count bounds apply.
                plans.push(retained_plan(
                    &format!("{prefix}-{i:03}"),
                    phase.clone(),
                    year + count as i64 - i as i64,
                    now,
                ));
            }
        }

        let evicted = evicted_names(&plans, retention, now);
        for prefix in ["applied", "failed", "superseded"] {
            let count = evicted.iter().filter(|n| n.starts_with(prefix)).count();
            assert_eq!(count, 4, "{prefix} should lose exactly its 4 excess plans");
        }
    }

    /// Failed and Rejected share one bound, so a policy that fails repeatedly
    /// cannot bury the record of a plan a reviewer declined.
    #[test]
    fn failed_and_rejected_share_the_decided_bound() {
        let now = 1_700_000_000;
        let retention = PlanRetention::default();
        let year = 400 * 24 * 60 * 60;

        let mut plans = vec![retained_plan(
            "rejected",
            PlanPhase::Rejected,
            year * 2,
            now,
        )];
        for i in 0..retention.decided {
            plans.push(retained_plan(
                &format!("failed-{i:03}"),
                PlanPhase::Failed,
                year - i as i64,
                now,
            ));
        }

        // One over the shared bound, and the rejected plan is the oldest.
        assert_eq!(
            evicted_names(&plans, retention, now),
            vec!["rejected".to_string()]
        );
    }

    /// The age floor is what makes the retained span a promise rather than a
    /// function of how often the policy applies.
    #[test]
    fn the_age_floor_keeps_applied_plans_past_the_count_bound() {
        let now = 1_700_000_000;
        let retention = PlanRetention::default();

        let recent: Vec<PostgresPolicyPlan> = (0..retention.applied + 10)
            .map(|i| {
                retained_plan(
                    &format!("applied-{i:03}"),
                    PlanPhase::Applied,
                    retention.applied_min_age_secs - 1 - i as i64,
                    now,
                )
            })
            .collect();
        assert!(
            evicted_names(&recent, retention, now).is_empty(),
            "nothing inside the floor is evicted, even past the count bound"
        );

        // One second older and the same plan is outside the promise.
        let stale: Vec<PostgresPolicyPlan> = (0..retention.applied + 10)
            .map(|i| {
                retained_plan(
                    &format!("applied-{i:03}"),
                    PlanPhase::Applied,
                    retention.applied_min_age_secs + 1 + i as i64,
                    now,
                )
            })
            .collect();
        assert_eq!(evicted_names(&stale, retention, now).len(), 10);
    }

    /// The floor promises history; it does not license unbounded growth.
    #[test]
    fn the_ceiling_overrides_the_age_floor() {
        let now = 1_700_000_000;
        let retention = PlanRetention::default();

        let plans: Vec<PostgresPolicyPlan> = (0..retention.applied_ceiling + 40)
            .map(|i| {
                retained_plan(
                    &format!("applied-{i:04}"),
                    PlanPhase::Applied,
                    // All well inside the floor.
                    60 + i as i64,
                    now,
                )
            })
            .collect();

        assert_eq!(
            evicted_names(&plans, retention, now).len(),
            40,
            "the ceiling trims back to itself, not to the count bound"
        );
    }

    #[test]
    fn live_plans_and_kept_plans_are_never_evicted() {
        let now = 1_700_000_000;
        let retention = PlanRetention::default();
        let year = 400 * 24 * 60 * 60;

        let mut plans = Vec::new();
        for (i, phase) in [PlanPhase::Pending, PlanPhase::Approved, PlanPhase::Applying]
            .into_iter()
            .enumerate()
        {
            plans.push(retained_plan(&format!("live-{i}"), phase, year * 2, now));
        }
        // Enough superseded plans to blow past the bound many times over.
        for i in 0..40 {
            plans.push(retained_plan(
                &format!("superseded-{i:03}"),
                PlanPhase::Superseded,
                year,
                now,
            ));
        }
        let mut kept = retained_plan("kept", PlanPhase::Superseded, year * 3, now);
        kept.metadata
            .labels
            .get_or_insert_with(Default::default)
            .insert("pgroles.io/keep".to_string(), "true".to_string());
        plans.push(kept);

        let evicted = evicted_names(&plans, retention, now);
        assert!(!evicted.iter().any(|name| name.starts_with("live-")));
        assert!(!evicted.contains(&"kept".to_string()));
        assert_eq!(evicted.len(), 40 - retention.superseded);
    }

    /// [`PlanRetention::from_lookup`] over a fixed variable table.
    fn retention_from(vars: &[(&str, &str)]) -> Result<PlanRetention, PlanRetentionConfigError> {
        PlanRetention::from_lookup(|variable| {
            vars.iter()
                .find(|(name, _)| *name == variable)
                .map(|(_, value)| value.to_string())
        })
    }

    #[test]
    fn unset_retention_variables_keep_the_defaults() {
        assert_eq!(
            retention_from(&[]).expect("an empty environment is valid"),
            PlanRetention::default()
        );
    }

    #[test]
    fn each_retention_variable_overrides_its_bound() {
        let resolved = retention_from(&[
            (PlanRetention::ENV_APPLIED, "7"),
            (PlanRetention::ENV_APPLIED_CEILING, "70"),
            (PlanRetention::ENV_APPLIED_MIN_AGE, "36h"),
            (PlanRetention::ENV_DECIDED, "4"),
            (PlanRetention::ENV_SUPERSEDED, "1"),
        ])
        .expect("all five values are valid");

        let expected = PlanRetention {
            applied: 7,
            applied_ceiling: 70,
            applied_min_age_secs: 36 * 60 * 60,
            decided: 4,
            superseded: 1,
        };
        // Guard against this test going vacuous: if the fixture ever equalled
        // the defaults, a lookup that ignored the environment entirely would
        // still pass the assertion below.
        assert_ne!(expected, PlanRetention::default());
        assert_eq!(resolved, expected);
    }

    #[test]
    fn an_invalid_retention_count_is_rejected_naming_the_variable() {
        let error = retention_from(&[(PlanRetention::ENV_DECIDED, "many")])
            .expect_err("a non-numeric count must be rejected, not defaulted");
        assert!(
            error.to_string().contains(PlanRetention::ENV_DECIDED),
            "the error must name the variable to fix: {error}"
        );
    }

    #[test]
    fn an_invalid_retention_min_age_is_rejected_naming_the_variable() {
        // Days are deliberately not a unit — this is the same syntax as the
        // EPHEMERAL_ACCESS_* durations, and "30d" must fail loudly rather
        // than resolve to something else.
        let error = retention_from(&[(PlanRetention::ENV_APPLIED_MIN_AGE, "30d")])
            .expect_err("an unsupported duration unit must be rejected, not defaulted");
        assert!(
            error
                .to_string()
                .contains(PlanRetention::ENV_APPLIED_MIN_AGE),
            "the error must name the variable to fix: {error}"
        );
    }

    #[test]
    fn the_applied_floor_runs_from_when_the_plan_applied_not_when_it_was_created() {
        // A plan can sit Pending or Approved for longer than the entire floor
        // before a reviewer decides it. Measured from creation, such a plan is
        // already outside the floor the moment it executes, and the cleanup
        // that follows execution deletes it — the exact history the floor
        // promises to keep.
        let now = 1_700_000_000;
        let retention = PlanRetention::default();

        // Created far outside the floor, applied just now. Enough plans to
        // exceed the count bound, but well under the ceiling, so only the
        // floor can be what spares them.
        let excess = 10;
        assert!(
            retention.applied + excess <= retention.applied_ceiling,
            "this test must not lean on the ceiling to pass"
        );
        let plans: Vec<PostgresPolicyPlan> = (0..retention.applied + excess)
            .map(|i| {
                let mut plan = retained_plan(
                    &format!("applied-{i:03}"),
                    PlanPhase::Applied,
                    retention.applied_min_age_secs * 3 + i as i64,
                    now,
                );
                plan.status
                    .as_mut()
                    .expect("retained_plan always sets a status")
                    .applied_at = Some(
                    jiff::Timestamp::from_second(now - 60 - i as i64)
                        .expect("epoch second in range")
                        .to_string(),
                );
                plan
            })
            .collect();

        assert!(
            evicted_names(&plans, retention, now).is_empty(),
            "a plan applied inside the floor is kept, however old the object is"
        );
    }

    #[test]
    fn above_the_ceiling_eviction_order_follows_when_plans_applied_not_when_created() {
        // Above the ceiling the floor is overridden and the walk evicts from
        // the front, so the sort order decides who dies. Ordered by creation,
        // a plan created before a long review but applied moments ago sorts
        // first and is deleted by the cleanup right after it executes, while
        // older executions whose objects happen to be newer survive.
        let now = 1_700_000_000;
        let retention = PlanRetention::default();
        let excess = 5;
        let count = retention.applied_ceiling + excess;

        // Creation order is the exact reverse of applied order: plan 0 is the
        // oldest object but the most recent execution. All applied inside the
        // floor, so only the ceiling forces eviction.
        let plans: Vec<PostgresPolicyPlan> = (0..count)
            .map(|i| {
                let mut plan = retained_plan(
                    &format!("applied-{i:04}"),
                    PlanPhase::Applied,
                    retention.applied_min_age_secs * 3 + (count - i) as i64,
                    now,
                );
                plan.status
                    .as_mut()
                    .expect("retained_plan always sets a status")
                    .applied_at = Some(
                    jiff::Timestamp::from_second(now - 100 - i as i64)
                        .expect("epoch second in range")
                        .to_string(),
                );
                plan
            })
            .collect();

        let evicted = evicted_names(&plans, retention, now);
        assert_eq!(
            evicted.len(),
            excess,
            "the ceiling trims exactly the excess"
        );
        for i in 0..excess {
            let earliest_executed = format!("applied-{:04}", count - 1 - i);
            assert!(
                evicted.contains(&earliest_executed),
                "the earliest executions go first, whatever their objects' creation order"
            );
        }
        assert!(
            !evicted.contains(&"applied-0000".to_string()),
            "the most recent execution must survive even as the oldest object by creation"
        );
    }

    #[test]
    fn a_non_unicode_environment_value_is_rejected_not_defaulted() {
        use std::os::unix::ffi::OsStringExt;

        let read = Err(std::env::VarError::NotUnicode(
            std::ffi::OsString::from_vec(vec![b'2', b'5', 0xff]),
        ));
        let error = env_read(PlanRetention::ENV_APPLIED, read)
            .expect_err("a set-but-non-Unicode value must be rejected, not read as unset");
        assert!(
            error.to_string().contains(PlanRetention::ENV_APPLIED),
            "the error must name the variable to fix: {error}"
        );

        assert_eq!(
            env_read(
                PlanRetention::ENV_APPLIED,
                Err(std::env::VarError::NotPresent)
            )
            .expect("absent is not an error"),
            None
        );
        assert_eq!(
            env_read(PlanRetention::ENV_APPLIED, Ok("25".to_string()))
                .expect("a Unicode value is not an error"),
            Some("25".to_string())
        );
    }

    #[test]
    fn a_ceiling_below_the_applied_count_is_rejected() {
        // Eviction stops at the count bound before the ceiling is consulted,
        // so a smaller ceiling could never take effect; accepting it would
        // mean running with different bounds than the environment states.
        retention_from(&[
            (PlanRetention::ENV_APPLIED, "50"),
            (PlanRetention::ENV_APPLIED_CEILING, "10"),
        ])
        .expect_err("a ceiling below the count bound must be rejected");

        // Equal is the degenerate-but-coherent form: the floor never spares
        // anything, and that is exactly what the configuration says.
        retention_from(&[
            (PlanRetention::ENV_APPLIED, "50"),
            (PlanRetention::ENV_APPLIED_CEILING, "50"),
        ])
        .expect("a ceiling equal to the count bound is valid");
    }

    fn plan_failed_at(phase: PlanPhase, age_secs: i64, now_ts: i64) -> PostgresPolicyPlan {
        let mut plan = PostgresPolicyPlan::new("plan", test_plan_spec());
        plan.status = Some(PostgresPolicyPlanStatus {
            phase,
            last_error: Some("permission denied to create role".to_string()),
            failed_at: Some(
                jiff::Timestamp::from_second(now_ts - age_secs)
                    .expect("epoch second in range")
                    .to_string(),
            ),
            ..Default::default()
        });
        plan
    }

    fn plan_applied_at(phase: PlanPhase, age_secs: i64, now_ts: i64) -> PostgresPolicyPlan {
        let mut plan = PostgresPolicyPlan::new("plan", test_plan_spec());
        plan.status = Some(PostgresPolicyPlanStatus {
            phase,
            applied_at: Some(
                jiff::Timestamp::from_second(now_ts - age_secs)
                    .expect("epoch second in range")
                    .to_string(),
            ),
            ..Default::default()
        });
        plan
    }

    /// A plan whose SQL "succeeds" without changing anything the inspector can
    /// see (e.g. a REVOKE of a privilege granted by a grantor the executor
    /// cannot act as) replans identically forever. Under `approval: auto` each
    /// replan minted a fresh plan — the terminal Applied one never matched the
    /// Pending dedup — and every plan status write woke the policy controller,
    /// so the same no-ops re-applied about once a second.
    #[test]
    fn a_plan_that_just_applied_without_converging_is_not_reapplied_until_the_window_expires() {
        let now = 1_700_000_000;

        assert!(
            applied_recently_without_converging(&plan_applied_at(PlanPhase::Applied, 1, now), now),
            "an identical replan one second after applying means the apply was a no-op"
        );
        assert!(
            applied_recently_without_converging(
                &plan_applied_at(
                    PlanPhase::Applied,
                    APPLIED_PLAN_NONCONVERGENT_WINDOW_SECS - 1,
                    now
                ),
                now
            ),
            "still inside the window"
        );
        assert!(
            !applied_recently_without_converging(
                &plan_applied_at(
                    PlanPhase::Applied,
                    APPLIED_PLAN_NONCONVERGENT_WINDOW_SECS,
                    now
                ),
                now
            ),
            "the interval retries once the window expires"
        );
        assert!(
            !applied_recently_without_converging(&plan_applied_at(PlanPhase::Failed, 1, now), now),
            "only Applied plans prove a no-op apply; failures have their own back-off"
        );
        assert!(
            !applied_recently_without_converging(
                &plan_applied_at(PlanPhase::Applied, -30, now),
                now
            ),
            "a future applied_at (skewed clock) must not defer unboundedly"
        );
        let mut no_timestamp = plan_applied_at(PlanPhase::Applied, 1, now);
        no_timestamp.status.as_mut().unwrap().applied_at = None;
        assert!(
            !applied_recently_without_converging(&no_timestamp, now),
            "no applied_at means ordering unknown; do not defer"
        );
        let mut no_status = plan_applied_at(PlanPhase::Applied, 1, now);
        no_status.status = None;
        assert!(!applied_recently_without_converging(&no_status, now));
    }

    #[test]
    fn nonconvergent_creation_result_is_neither_created_nor_failed_backoff() {
        let result = PlanCreationResult::DeduplicatedNonConvergent("plan-x".to_string());
        assert!(result.is_nonconvergent());
        assert!(!result.is_created());
        assert!(!result.is_failed_backoff());
        assert_eq!(result.plan_name(), "plan-x");
    }

    /// Re-executing a plan that just failed is what made a permanently-failing
    /// policy reconcile ~9 times a second: each attempt moves the plan
    /// `Failed -> Applying -> Failed`, and the controller wakes on its own
    /// plans, so every attempt schedules the next one.
    #[test]
    fn a_plan_that_just_failed_is_not_retried_until_the_window_expires() {
        let now = 1_700_000_000;

        assert!(
            retry_deferred_until_window_expires(&plan_failed_at(PlanPhase::Failed, 1, now), now),
            "a failure one second old must not be retried immediately"
        );
        assert!(
            retry_deferred_until_window_expires(
                &plan_failed_at(PlanPhase::Failed, FAILED_PLAN_DEDUP_WINDOW_SECS - 1, now),
                now
            ),
            "still inside the window"
        );
        assert!(
            !retry_deferred_until_window_expires(
                &plan_failed_at(PlanPhase::Failed, FAILED_PLAN_DEDUP_WINDOW_SECS, now),
                now
            ),
            "the window must expire so a fixed environment recovers"
        );
    }

    /// A `failed_at` in the future must not defer the retry.
    ///
    /// The subtraction goes negative, which is inside the window by
    /// arithmetic, so without an explicit bound the plan would wait for the
    /// wall clock to reach that timestamp — turning a 120-second back-off into
    /// an unbounded one. The back-off may slow a retry down; it may never
    /// prevent one.
    #[test]
    fn a_failure_timestamp_in_the_future_does_not_defer_the_retry() {
        let now = 1_700_000_000;

        for skew in [1, 60, FAILED_PLAN_DEDUP_WINDOW_SECS, 86_400] {
            assert!(
                !retry_deferred_until_window_expires(
                    &plan_failed_at(PlanPhase::Failed, -skew, now),
                    now
                ),
                "a failure {skew}s in the future must not block execution"
            );
        }

        // The boundary the other direction still defers: now is inside it.
        assert!(retry_deferred_until_window_expires(
            &plan_failed_at(PlanPhase::Failed, 0, now),
            now
        ));
    }

    /// The back-off holds whatever the phase says.
    ///
    /// `mark_plan_approved` runs between the failure and the next execution
    /// attempt on the `approval: auto` path, so the phase reads Approved on a
    /// plan that failed milliseconds ago. Gating on `phase == Failed` would
    /// therefore never fire on the path that spins.
    #[test]
    fn the_backoff_survives_the_phase_being_rewritten() {
        let now = 1_700_000_000;

        for phase in [
            PlanPhase::Pending,
            PlanPhase::Approved,
            PlanPhase::Applying,
            PlanPhase::Failed,
        ] {
            assert!(
                retry_deferred_until_window_expires(&plan_failed_at(phase.clone(), 1, now), now),
                "{phase:?} with a one-second-old failure must still defer"
            );
        }
    }

    /// A plan that applied after its failure is not in back-off.
    ///
    /// `failed_at` is kept as history when a later attempt succeeds, so the
    /// gate has to compare the two timestamps rather than read the failure
    /// alone — otherwise recovering from a transient error would wedge the
    /// plan for the rest of the window.
    #[test]
    fn a_plan_that_applied_after_failing_is_not_deferred() {
        let now = 1_700_000_000;

        let mut recovered = plan_failed_at(PlanPhase::Applied, 30, now);
        recovered.status.as_mut().unwrap().applied_at =
            Some(jiff::Timestamp::from_second(now - 10).unwrap().to_string());
        assert!(!retry_deferred_until_window_expires(&recovered, now));

        // Applied *before* the failure is stale history and must not excuse
        // the failure that came after it.
        let mut failed_again = plan_failed_at(PlanPhase::Failed, 10, now);
        failed_again.status.as_mut().unwrap().applied_at =
            Some(jiff::Timestamp::from_second(now - 30).unwrap().to_string());
        assert!(retry_deferred_until_window_expires(&failed_again, now));
    }

    /// An apply and a failure in the same second still defer.
    ///
    /// `now_rfc3339` records whole seconds, so a plan that applied and then
    /// failed inside one second writes the same string to both fields and the
    /// ordering is not recoverable. Reading that as "recovered" would leave
    /// the retry unbounded, and because neither timestamp moves afterwards it
    /// would stay unbounded rather than self-correcting on the next pass.
    #[test]
    fn an_apply_and_a_failure_in_the_same_second_still_defer() {
        let now = 1_700_000_000;
        let same_second = jiff::Timestamp::from_second(now - 5).unwrap().to_string();

        let mut plan = plan_failed_at(PlanPhase::Failed, 5, now);
        let status = plan.status.as_mut().unwrap();
        status.applied_at = Some(same_second.clone());
        assert_eq!(status.failed_at.as_deref(), Some(same_second.as_str()));

        assert!(
            retry_deferred_until_window_expires(&plan, now),
            "an unorderable pair must resolve to the bounded side"
        );
    }

    #[test]
    fn a_plan_with_no_recorded_failure_runs() {
        let now = 1_700_000_000;

        // No status at all, and no recorded failure time, are both "run it".
        let bare = PostgresPolicyPlan::new("plan", test_plan_spec());
        assert!(!retry_deferred_until_window_expires(&bare, now));

        let mut no_timestamp = PostgresPolicyPlan::new("plan", test_plan_spec());
        no_timestamp.status = Some(PostgresPolicyPlanStatus {
            phase: PlanPhase::Failed,
            ..Default::default()
        });
        assert!(!retry_deferred_until_window_expires(&no_timestamp, now));
    }

    /// A minimal spec — the ownership tests only care about metadata.
    fn test_policy_spec() -> crate::crd::PostgresPolicySpec {
        crate::crd::PostgresPolicySpec {
            connection: crate::crd::ConnectionSpec {
                secret_ref: Some(crate::crd::SecretReference {
                    name: "db-credentials".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
                require_physical_identity: None,
            },
            interval: "5m".to_string(),
            suspend: false,
            mode: crate::crd::PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            allow_schema_owner_transfers: false,
            role_pattern: None,
            default_owner: None,
            profiles: Default::default(),
            schemas: Vec::new(),
            roles: Vec::new(),
            grants: Vec::new(),
            default_privileges: Vec::new(),
            memberships: Vec::new(),
            retirements: Vec::new(),
            approval: None,
        }
    }

    /// A policy with a known UID, for the ownership tests.
    fn policy_with_uid(name: &str, uid: &str) -> PostgresPolicy {
        let mut policy = PostgresPolicy::new(name, test_policy_spec());
        policy.metadata.namespace = Some("default".to_string());
        policy.metadata.uid = Some(uid.to_string());
        policy
    }

    /// Two policies whose names share a 63-character prefix collapse to the same
    /// `pgroles.io/policy` label, so the selector cannot tell them apart. Only
    /// the owner UID can — and the selector result drives deletion.
    #[test]
    fn colliding_label_values_are_separated_by_owner_uid() {
        let prefix = "a".repeat(63);
        let first = policy_with_uid(&format!("{prefix}-one"), "uid-one");
        let second = policy_with_uid(&format!("{prefix}-two"), "uid-two");

        // Precondition: the labels really are indistinguishable.
        assert_eq!(
            sanitize_label_value(&first.name_any()),
            sanitize_label_value(&second.name_any()),
        );

        let mut plan = test_plan("plan-1", PlanPhase::Pending, None);
        plan.metadata.owner_references = Some(vec![build_owner_reference(&first)]);

        assert!(is_owned_by_policy(&plan, &first));
        assert!(
            !is_owned_by_policy(&plan, &second),
            "a colliding policy must not claim another policy's plan"
        );
    }

    /// The adoption gate is narrower than `!is_owned_by_policy`: it blocks only
    /// a live claim by a *different* policy. An unowned orphan stays adoptable,
    /// so recovering from a `--cascade=orphan` delete still works.
    #[test]
    fn only_a_rival_controller_owner_blocks_adoption() {
        let mine = policy_with_uid("orders", "uid-mine");
        let theirs = policy_with_uid("orders-other", "uid-theirs");

        let mut ours = test_plan("plan-1", PlanPhase::Pending, None);
        ours.metadata.owner_references = Some(vec![build_owner_reference(&mine)]);
        assert!(!is_owned_by_another(&ours, PlanOwner::Policy(&mine)));

        let mut rival = test_plan("plan-2", PlanPhase::Pending, None);
        rival.metadata.owner_references = Some(vec![build_owner_reference(&theirs)]);
        assert!(is_owned_by_another(&rival, PlanOwner::Policy(&mine)));

        // An orphan belongs to nobody, so it does not block us.
        let orphan = test_plan("plan-3", PlanPhase::Pending, None);
        assert!(!is_owned_by_another(&orphan, PlanOwner::Policy(&mine)));

        // A non-controller owner reference is not a claim either.
        let mut non_controller = build_owner_reference(&theirs);
        non_controller.controller = Some(false);
        let mut referenced = test_plan("plan-4", PlanPhase::Pending, None);
        referenced.metadata.owner_references = Some(vec![non_controller]);
        assert!(!is_owned_by_another(&referenced, PlanOwner::Policy(&mine)));
    }

    /// Fail closed: without a UID we cannot prove anything is ours, so every
    /// claimed object must count as someone else's.
    #[test]
    fn a_policy_without_a_uid_can_adopt_nothing_owned() {
        let mut no_uid = policy_with_uid("orders", "uid-orders");
        no_uid.metadata.uid = None;
        let owner = policy_with_uid("orders", "uid-orders");

        let mut claimed = test_plan("plan-1", PlanPhase::Pending, None);
        claimed.metadata.owner_references = Some(vec![build_owner_reference(&owner)]);
        assert!(is_owned_by_another(&claimed, PlanOwner::Policy(&no_uid)));

        // ...but an orphan is still nobody's.
        let orphan = test_plan("plan-2", PlanPhase::Pending, None);
        assert!(!is_owned_by_another(&orphan, PlanOwner::Policy(&no_uid)));
    }

    #[test]
    fn ownership_requires_a_controller_owner_reference() {
        let policy = policy_with_uid("orders", "uid-orders");

        // No owner references at all — e.g. an object the operator did not create.
        let plan = test_plan("plan-1", PlanPhase::Pending, None);
        assert!(!is_owned_by_policy(&plan, &policy));

        // Right UID, but not marked as the controller.
        let mut non_controller = build_owner_reference(&policy);
        non_controller.controller = Some(false);
        let mut plan = test_plan("plan-2", PlanPhase::Pending, None);
        plan.metadata.owner_references = Some(vec![non_controller]);
        assert!(!is_owned_by_policy(&plan, &policy));
    }

    /// An empty UID must never act as a wildcard: a policy the API server has
    /// not assigned a UID to owns nothing.
    #[test]
    fn policy_without_uid_owns_nothing() {
        let mut policy = PostgresPolicy::new("orders", test_policy_spec());
        policy.metadata.namespace = Some("default".to_string());
        policy.metadata.uid = None;

        let mut plan = test_plan("plan-1", PlanPhase::Pending, None);
        // `build_owner_reference` defaults a missing UID to the empty string.
        plan.metadata.owner_references = Some(vec![build_owner_reference(&policy)]);

        assert!(!is_owned_by_policy(&plan, &policy));
    }

    /// A replacement policy with the same name is a different object, so it must
    /// not inherit the deleted one's plans.
    #[test]
    fn recreated_policy_does_not_inherit_previous_plans() {
        let original = policy_with_uid("orders", "uid-original");
        let recreated = policy_with_uid("orders", "uid-recreated");

        let mut plan = test_plan("plan-1", PlanPhase::Applied, None);
        plan.metadata.owner_references = Some(vec![build_owner_reference(&original)]);

        assert!(is_owned_by_policy(&plan, &original));
        assert!(!is_owned_by_policy(&plan, &recreated));
    }

    /// The ConfigMap cleanup path filters the same way, which is what stops it
    /// deleting a colliding policy's SQL ConfigMap as an "orphan".
    #[test]
    fn configmap_ownership_uses_owner_uid() {
        let prefix = "a".repeat(63);
        let mine = policy_with_uid(&format!("{prefix}-one"), "uid-one");
        let theirs = policy_with_uid(&format!("{prefix}-two"), "uid-two");

        let configmap = ConfigMap {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("plan-1-sql".to_string()),
                owner_references: Some(vec![build_owner_reference(&theirs)]),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(is_owned_by_policy(&configmap, &theirs));
        assert!(
            !is_owned_by_policy(&configmap, &mine),
            "cleanup must not treat another policy's ConfigMap as its own"
        );
    }

    /// Build a plan carrying the given terminal decision conditions.
    ///
    /// `decisions` are `(condition_type, status)` pairs written exactly as a
    /// reviewer's status patch would leave them.
    fn test_plan_with_decisions(
        name: &str,
        phase: PlanPhase,
        decisions: &[(&str, &str)],
    ) -> PostgresPolicyPlan {
        let mut plan = test_plan(name, phase, None);
        let status = plan.status.as_mut().expect("status");
        status.conditions = decisions
            .iter()
            .map(|(condition_type, condition_status)| PolicyCondition {
                condition_type: (*condition_type).to_string(),
                status: (*condition_status).to_string(),
                reason: Some("DecidedByReviewer".to_string()),
                message: None,
                last_transition_time: Some(crate::crd::now_rfc3339()),
            })
            .collect();
        if decisions.iter().any(|(_, s)| *s == "True") {
            status.decided_by = Some(crate::crd::DecisionActor {
                username: "reviewer@example.com".to_string(),
                uid: Some("uid-1".to_string()),
                groups: vec!["platform".to_string()],
            });
        }
        plan
    }

    fn test_plan(
        name: &str,
        phase: PlanPhase,
        annotations: Option<BTreeMap<String, String>>,
    ) -> PostgresPolicyPlan {
        let mut plan = PostgresPolicyPlan::new(
            name,
            PostgresPolicyPlanSpec {
                policy_ref: PolicyPlanRef {
                    name: "test-policy".to_string(),
                },
                policy_generation: 1,
                reconciliation_mode: CrdReconciliationMode::Authoritative,
                owned_roles: vec!["role-a".to_string()],
                owned_schemas: vec!["public".to_string()],
                managed_database_identity: "default/db/DATABASE_URL".to_string(),
                origin: None,
                scope: None,
            },
        );
        plan.metadata.namespace = Some("default".to_string());
        plan.metadata.annotations = annotations;
        plan.status = Some(PostgresPolicyPlanStatus {
            phase,
            ..Default::default()
        });
        plan
    }

    #[test]
    fn a_plan_with_no_recorded_decision_is_pending() {
        let plan = test_plan("plan-1", PlanPhase::Pending, None);
        assert_eq!(check_plan_approval(&plan), PlanApprovalState::Pending);

        // A plan with no status at all — freshly created, status not yet
        // written — must also read as undecided rather than panicking.
        let mut statusless = test_plan("plan-2", PlanPhase::Pending, None);
        statusless.status = None;
        assert_eq!(check_plan_approval(&statusless), PlanApprovalState::Pending);
    }

    #[test]
    fn a_decision_is_read_from_the_status_conditions() {
        let approved =
            test_plan_with_decisions("plan-1", PlanPhase::Pending, &[("Approved", "True")]);
        assert_eq!(check_plan_approval(&approved), PlanApprovalState::Approved);

        let denied = test_plan_with_decisions("plan-1", PlanPhase::Pending, &[("Denied", "True")]);
        assert_eq!(check_plan_approval(&denied), PlanApprovalState::Rejected);
    }

    /// A plan is created carrying `Approved=False`, which is the *absence* of a
    /// decision, not a denial. Reading it as either decision would auto-execute
    /// or auto-reject every freshly created plan.
    #[test]
    fn a_false_decision_condition_is_not_a_decision() {
        for conditions in [
            &[("Approved", "False")][..],
            &[("Denied", "False")][..],
            &[("Approved", "False"), ("Denied", "False")][..],
        ] {
            let plan = test_plan_with_decisions("plan-1", PlanPhase::Pending, conditions);
            assert_eq!(
                check_plan_approval(&plan),
                PlanApprovalState::Pending,
                "conditions {conditions:?} must not read as a decision"
            );
        }
    }

    /// CEL rejects Approved=True alongside Denied=True at admission, so this
    /// state is only reachable if the rules were bypassed. Refusing to execute
    /// is the fail-closed reading.
    #[test]
    fn a_contradictory_decision_never_executes() {
        let plan = test_plan_with_decisions(
            "plan-1",
            PlanPhase::Pending,
            &[("Approved", "True"), ("Denied", "True")],
        );
        assert_eq!(check_plan_approval(&plan), PlanApprovalState::Rejected);
    }

    /// The decision no longer lives in annotations. A plan annotated the old
    /// way carries no authority at all — otherwise removing the mechanism
    /// would have left a silent bypass behind.
    #[test]
    fn the_retired_approval_annotation_grants_nothing() {
        let annotations = BTreeMap::from([
            ("pgroles.io/approved".to_string(), "true".to_string()),
            ("pgroles.io/rejected".to_string(), "true".to_string()),
        ]);
        let plan = test_plan("plan-1", PlanPhase::Pending, Some(annotations));
        assert_eq!(check_plan_approval(&plan), PlanApprovalState::Pending);
    }

    #[test]
    fn diagnostic_source_digest_detects_secret_materialization_without_passwords() {
        let missing = BTreeMap::from([("app".into(), "credential:password:missing".into())]);
        let real = BTreeMap::from([("app".into(), "credential:password:42".into())]);
        let status = PostgresPolicyPlanStatus {
            password_source_digest: Some(password_source_digest(&missing)),
            ..Default::default()
        };
        assert!(!password_source_changed(&status, &missing));
        assert!(password_source_changed(&status, &real));
        assert!(!password_source_changed(
            &PostgresPolicyPlanStatus::default(),
            &real
        ));
        let status = PostgresPolicyPlanStatus {
            password_source_digest: Some(password_source_digest(&real)),
            ..Default::default()
        };
        assert!(!password_source_changed(&status, &real));
    }

    /// The supersede condition is often the only trace a reviewer sees of why
    /// the plan they were looking at vanished. Every cause must describe
    /// itself; the previous single message claimed the database had changed
    /// even when it was an effect-neutral policy edit that retired the plan.
    #[test]
    fn every_supersede_cause_names_its_own_reason() {
        use pgroles_core::approval::TargetIdentityReason;

        let causes = [
            SupersedeCause::EffectsChanged,
            SupersedeCause::PasswordSourceChanged,
            SupersedeCause::EffectsCleared,
            SupersedeCause::ReplacedByNewerPlan,
            SupersedeCause::PolicyStoppedPlanning,
            SupersedeCause::SupersededByPromotion,
            SupersedeCause::BaseContentChanged,
            SupersedeCause::TargetChanged(TargetIdentityReason::TargetChanged),
        ];
        // A new variant must be added to `causes` above or this stops
        // compiling — the coverage of this test is enforced, not remembered.
        for cause in causes {
            match cause {
                SupersedeCause::EffectsChanged
                | SupersedeCause::PasswordSourceChanged
                | SupersedeCause::EffectsCleared
                | SupersedeCause::ReplacedByNewerPlan
                | SupersedeCause::PolicyStoppedPlanning
                | SupersedeCause::SupersededByPromotion
                | SupersedeCause::BaseContentChanged
                | SupersedeCause::TargetChanged(_) => {}
            }
        }

        let mut messages = std::collections::BTreeSet::new();
        for cause in causes {
            let message = cause.message();
            assert!(!message.is_empty(), "{cause:?} has no message");
            assert!(
                messages.insert(message),
                "{cause:?} reuses another cause's message"
            );
            assert!(
                !message.contains("Database state changed since plan was approved"),
                "{cause:?} still carries the old catch-all message"
            );
        }
    }

    /// The generic causes keep reporting `Superseded` so status consumers and
    /// runbooks matching on that reason keep working. A target change is the
    /// exception: it is a distinct operational fault and reports the identity
    /// verdict a human has to act on.
    #[test]
    fn supersede_reasons_stay_stable_except_for_a_moved_target() {
        use pgroles_core::approval::TargetIdentityReason;

        for cause in [
            SupersedeCause::EffectsChanged,
            SupersedeCause::EffectsCleared,
            SupersedeCause::ReplacedByNewerPlan,
            SupersedeCause::PolicyStoppedPlanning,
        ] {
            assert_eq!(cause.reason(), "Superseded", "{cause:?}");
        }

        // Promotion names itself: it is the one supersede a reviewer resolves
        // by filing a successor candidate, not by re-reviewing this plan.
        assert_eq!(
            SupersedeCause::SupersededByPromotion.reason(),
            crate::crd::candidate_reason::SUPERSEDED_BY_PROMOTION
        );

        assert_eq!(
            SupersedeCause::TargetChanged(TargetIdentityReason::TargetIdentityUnavailable).reason(),
            "TargetIdentityUnavailable"
        );
    }

    /// Rust model of the two CRD CEL rules a supersede write has to satisfy,
    /// for a status update from `old` to `new`:
    ///
    /// * "plan decisions are terminal" — the decision types that are `True`
    ///   may not change once the old set is non-empty.
    /// * "a terminal plan decision and decidedBy identity must be recorded
    ///   together" — `decidedBy` is present exactly when a decision is `True`.
    ///
    /// Kept beside the code that produces the write, because there is no live
    /// API server in unit tests to reject it.
    fn cel_admits(
        old: &crate::crd::PostgresPolicyPlanStatus,
        new: &crate::crd::PostgresPolicyPlanStatus,
    ) -> Result<(), &'static str> {
        let true_decisions = |status: &crate::crd::PostgresPolicyPlanStatus| -> Vec<String> {
            status
                .conditions
                .iter()
                .filter(|c| {
                    (c.condition_type == "Approved" || c.condition_type == "Denied")
                        && c.status == "True"
                })
                .map(|c| c.condition_type.clone())
                .collect()
        };

        let old_decisions = true_decisions(old);
        if !old_decisions.is_empty() && old_decisions != true_decisions(new) {
            return Err("plan decisions are terminal");
        }
        if old.decided_by.is_some()
            && new.decided_by.as_ref().map(|d| &d.username)
                != old.decided_by.as_ref().map(|d| &d.username)
        {
            return Err("decision identity is write-once");
        }
        if true_decisions(new).is_empty() != new.decided_by.is_none() {
            return Err(
                "a terminal plan decision and decidedBy identity must be recorded together",
            );
        }
        Ok(())
    }

    /// Retiring a plan a human approved must not touch the decision. Voiding
    /// is expressed by the phase alone; `Approved=True` and `decidedBy` are
    /// terminal and write-once, and rewriting them is a write the API server
    /// rejects — leaving the stale plan actionable.
    #[test]
    fn superseding_an_approved_plan_preserves_the_decision() {
        let plan = test_plan_with_decisions("plan-1", PlanPhase::Approved, &[("Approved", "True")]);
        let old = plan.status.clone().expect("status");
        let new = superseded_status(&old, SupersedeCause::EffectsChanged);

        assert_eq!(new.phase, PlanPhase::Superseded);
        let approved = new
            .conditions
            .iter()
            .find(|c| c.condition_type == "Approved")
            .expect("Approved condition preserved");
        assert_eq!(approved.status, "True");
        assert_eq!(
            new.decided_by.as_ref().map(|d| d.username.as_str()),
            Some("reviewer@example.com")
        );
        let superseded = new
            .conditions
            .iter()
            .find(|c| c.condition_type == crate::crd::CONDITION_SUPERSEDED)
            .expect("Superseded condition recorded");
        assert_eq!(superseded.status, "True");
        assert_eq!(
            superseded.message.as_deref(),
            Some(SupersedeCause::EffectsChanged.message())
        );

        // And the write the API server would see is admissible.
        assert_eq!(cel_admits(&old, &new), Ok(()));
    }

    /// A denied plan is retired the same way: the `Denied=True` record stands.
    #[test]
    fn superseding_a_denied_plan_preserves_the_decision() {
        let plan = test_plan_with_decisions("plan-1", PlanPhase::Rejected, &[("Denied", "True")]);
        let old = plan.status.clone().expect("status");
        let new = superseded_status(&old, SupersedeCause::SupersededByPromotion);

        assert!(
            new.conditions
                .iter()
                .any(|c| c.condition_type == "Denied" && c.status == "True")
        );
        assert!(
            !new.conditions
                .iter()
                .any(|c| c.condition_type == "Approved")
        );
        assert_eq!(cel_admits(&old, &new), Ok(()));
    }

    /// A plan nobody decided has no decision to protect, so the cause still
    /// lands on the `Approved=False` condition reviewers read — and that write
    /// is admissible because the old decision set was empty.
    #[test]
    fn superseding_a_pending_plan_still_records_the_cause_on_approved() {
        let plan = test_plan_with_decisions("plan-1", PlanPhase::Pending, &[("Approved", "False")]);
        let old = plan.status.clone().expect("status");
        let new = superseded_status(&old, SupersedeCause::ReplacedByNewerPlan);

        let approved = new
            .conditions
            .iter()
            .find(|c| c.condition_type == "Approved")
            .expect("Approved condition");
        assert_eq!(approved.status, "False");
        assert_eq!(
            approved.message.as_deref(),
            Some(SupersedeCause::ReplacedByNewerPlan.message())
        );
        assert!(
            new.conditions
                .iter()
                .any(|c| c.condition_type == crate::crd::CONDITION_SUPERSEDED)
        );
        assert_eq!(cel_admits(&old, &new), Ok(()));
    }

    /// The regression this guards: the old supersede wrote `Approved=False`
    /// unconditionally, and the model rejects that write on an approved plan
    /// for exactly the reason a real API server does.
    #[test]
    fn voiding_an_approval_by_flipping_the_condition_is_rejected() {
        let plan = test_plan_with_decisions("plan-1", PlanPhase::Approved, &[("Approved", "True")]);
        let old = plan.status.clone().expect("status");
        let mut new = old.clone();
        new.phase = PlanPhase::Superseded;
        set_plan_condition(
            &mut new.conditions,
            "Approved",
            "False",
            SupersedeCause::EffectsChanged.reason(),
            SupersedeCause::EffectsChanged.message(),
        );

        assert_eq!(cel_admits(&old, &new), Err("plan decisions are terminal"));
    }

    /// A superseded plan is not executable even with its approval intact: the
    /// only way to reach execution is a plan the policy picks as actionable,
    /// and that selection is by phase.
    #[test]
    fn a_superseded_plan_is_not_actionable_even_when_approved() {
        let plan = test_plan_with_decisions("plan-1", PlanPhase::Approved, &[("Approved", "True")]);
        let superseded = superseded_status(
            &plan.status.clone().expect("status"),
            SupersedeCause::SupersededByPromotion,
        );

        // `check_plan_approval` still reads the preserved decision — that is
        // the record, not the gate.
        let mut retired = plan.clone();
        retired.status = Some(superseded.clone());
        assert_eq!(check_plan_approval(&retired), PlanApprovalState::Approved);

        // The gate is the phase, which `get_current_actionable_plan` filters on.
        assert!(!matches!(
            superseded.phase,
            PlanPhase::Pending | PlanPhase::Approved
        ));
        // And a replacement never re-retires it, so it cannot be resurrected.
        assert!(!supersedes_after_create(&superseded, "some-other-digest"));
    }

    #[test]
    fn compute_sql_hash_is_deterministic() {
        let sql = "CREATE ROLE test LOGIN;\nGRANT SELECT ON ALL TABLES IN SCHEMA public TO test;";
        let hash1 = compute_sql_hash(sql);
        let hash2 = compute_sql_hash(sql);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 hex digest is 64 chars
    }

    #[test]
    fn compute_sql_hash_differs_for_different_sql() {
        let hash1 = compute_sql_hash("CREATE ROLE a;");
        let hash2 = compute_sql_hash("CREATE ROLE b;");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn compute_sql_hash_matches_pinned_fixture() {
        assert_eq!(
            compute_sql_hash("CREATE ROLE app LOGIN;"),
            "12a9743285d98ce73cfa9c840e943fc627d1fcbce22c5206fda1b21c84c1ac9c"
        );
    }

    #[test]
    fn generate_plan_name_has_expected_format() {
        let hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let name = generate_plan_name("my-policy", hash);
        assert!(name.starts_with("my-policy-plan-"));
        assert!(name.ends_with("-abcdef012345"));
        let suffix = name.strip_prefix("my-policy-plan-").unwrap();
        // YYYYMMDD-HHMMSS-hashprefix = 15 + 1 + 12 = 28 chars
        assert_eq!(suffix.len(), 28);
        assert_eq!(&suffix[8..9], "-");
        assert_eq!(&suffix[15..16], "-");
    }

    #[test]
    fn generate_plan_name_is_idempotent_for_same_hash_in_same_second() {
        let hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let name1 = generate_plan_name("my-policy", hash);
        let name2 = generate_plan_name("my-policy", hash);
        assert_eq!(name1, name2);
    }

    #[test]
    fn generate_plan_name_truncates_on_utf8_boundary() {
        let hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let name = generate_plan_name(&"é".repeat(140), hash);
        assert!(name.len() <= 249);
        assert!(name.ends_with("-abcdef012345"));
    }

    /// The plan-SQL ConfigMap derives its name by appending `-sql` to the plan
    /// name and carries three label values, all from user-controlled input.
    /// `generate_plan_name` reserves exactly 4 bytes for that suffix, so a
    /// boundary-length policy name is where the reservation would be wrong.
    ///
    /// Covered here rather than end-to-end because the plan SQL only spills to a
    /// ConfigMap above `MAX_INLINE_SQL_BYTES`; forcing that in a cluster would
    /// mean generating 16 KiB of SQL to re-verify string composition.
    #[test]
    fn plan_sql_configmap_identifiers_are_valid_at_the_name_limit() {
        use crate::k8s_names::{is_valid_label_value, is_valid_resource_name};

        let hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        // A hostile database identity: NUL separators and `=` from identity_key.
        let identity = format!(
            "prod/params\0literal={}\0literal=appdb\05432",
            "h".repeat(80)
        );

        for policy_name in [
            "orders".to_string(),
            "a.very-long-policy.name-with-dots.and-dashes.at-the-limit.xxxxx".to_string(),
            format!("{}.{}", "a".repeat(214), "b".repeat(38)),
            "a".repeat(253),
        ] {
            let plan_name = generate_plan_name(&policy_name, hash);
            let configmap_name = format!("{plan_name}-sql");

            assert!(
                is_valid_resource_name(&configmap_name),
                "invalid ConfigMap name for policy {policy_name:?}: {configmap_name}"
            );
            assert!(
                configmap_name.len() <= crate::k8s_names::MAX_RESOURCE_NAME_LENGTH,
                "ConfigMap name over the limit: {} bytes",
                configmap_name.len()
            );
            // Round-trips back to the plan name the labels are keyed on.
            assert_eq!(configmap_plan_name(&configmap_name), plan_name);

            for label in [
                sanitize_label_value(&policy_name),
                sanitize_label_value(&identity),
                plan_label_value(&plan_name),
            ] {
                assert!(
                    is_valid_label_value(&label),
                    "invalid label value {label:?} for policy {policy_name:?}"
                );
            }
        }
    }

    #[test]
    fn plan_label_value_is_stable_and_label_safe_for_long_names() {
        let plan_name = "very-long-policy-name-".repeat(20);
        let label = plan_label_value(&plan_name);
        assert_eq!(label, plan_label_value(&plan_name));
        assert_eq!(label.len(), 32);
        assert!(label.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn existing_non_pending_plan_status_is_not_repatched_on_create_conflict() {
        let approved = test_plan("plan-1", PlanPhase::Approved, None);
        let applying = test_plan("plan-1", PlanPhase::Applying, None);
        let applied = test_plan("plan-1", PlanPhase::Applied, None);

        assert!(!should_patch_existing_plan_status(&approved));
        assert!(!should_patch_existing_plan_status(&applying));
        assert!(!should_patch_existing_plan_status(&applied));
    }

    #[test]
    fn computed_or_decided_pending_plans_cannot_be_rewritten_on_name_collision() {
        let mut computed = test_plan("same-second", PlanPhase::Pending, None);
        computed.status.as_mut().unwrap().change_digest = Some("old-effects".into());
        assert!(!should_patch_existing_plan_status(&computed));
        computed.status.as_mut().unwrap().change_digest = None;
        computed.status.as_mut().unwrap().sql_hash = Some("legacy-sql".into());
        assert!(!should_patch_existing_plan_status(&computed));
        computed.status.as_mut().unwrap().sql_hash = None;
        computed.status.as_mut().unwrap().computed_at = Some("2026-09-05T00:00:00Z".into());
        assert!(!should_patch_existing_plan_status(&computed));
        for decision in ["Approved", "Denied"] {
            let decided =
                test_plan_with_decisions("same-second", PlanPhase::Pending, &[(decision, "True")]);
            assert!(!should_patch_existing_plan_status(&decided));
        }
        for phase in [
            PlanPhase::Applied,
            PlanPhase::Rejected,
            PlanPhase::Superseded,
            PlanPhase::Failed,
        ] {
            assert!(!should_patch_existing_plan_status(&test_plan(
                "same-second",
                phase,
                None
            )));
        }
    }

    #[test]
    fn existing_pending_or_statusless_plan_can_be_patched_on_create_conflict() {
        let pending = test_plan("plan-1", PlanPhase::Pending, None);
        let mut statusless = pending.clone();
        statusless.status = None;

        assert!(should_patch_existing_plan_status(&pending));
        assert!(should_patch_existing_plan_status(&statusless));
    }

    #[test]
    fn interrupted_create_resumes_only_with_the_same_persisted_spec() {
        let mut interrupted = test_plan("same-second", PlanPhase::Pending, None);
        for statusless in [false, true] {
            if statusless {
                interrupted.status = None;
            }
            let intended = interrupted.spec.clone();
            assert!(can_resume_plan_creation(&interrupted, &intended));

            let mut next_generation = intended.clone();
            next_generation.policy_generation += 1;
            assert!(!can_resume_plan_creation(&interrupted, &next_generation));

            let mut next_scope = intended.clone();
            next_scope.owned_roles.push("newly-managed".into());
            assert!(!can_resume_plan_creation(&interrupted, &next_scope));

            let mut next_target = intended.clone();
            next_target.managed_database_identity = "other-db".into();
            assert!(!can_resume_plan_creation(&interrupted, &next_target));

            let mut candidate = intended.clone();
            candidate.origin = Some(crate::crd::PlanOrigin {
                kind: "PostgresPolicyCandidate".into(),
                name: "proposal".into(),
                uid: "proposal-uid".into(),
                content_digest: Some("content".into()),
                content_digest_encoding: Some("v1".into()),
                policy_uid: Some("policy-uid".into()),
                base_content_digest: Some("new-base".into()),
            });
            assert!(!can_resume_plan_creation(&interrupted, &candidate));
        }
    }

    #[test]
    fn prepare_plan_sql_keeps_small_sql_inline() {
        let prepared = prepare_plan_sql("plan-1", "CREATE ROLE app LOGIN;").unwrap();

        assert!(matches!(prepared.artifact, PlanSqlArtifact::Inline(_)));
        assert_eq!(
            prepared.sql_inline(),
            Some("CREATE ROLE app LOGIN;".to_string())
        );
        assert!(prepared.sql_ref().is_none());
        assert!(!prepared.is_truncated());
    }

    #[test]
    fn prepare_plan_sql_compresses_large_brownfield_sized_sql() {
        let sql = brownfield_sized_sql();
        assert!(sql.len() > 1_048_576);

        let prepared = prepare_plan_sql("policy-plan-20260506-000000-abcdef012345", &sql).unwrap();

        let PlanSqlArtifact::CompressedConfigMap {
            key,
            compressed_sql,
            ..
        } = &prepared.artifact
        else {
            panic!("expected compressed ConfigMap artifact");
        };
        assert_eq!(key, SQL_CONFIGMAP_GZIP_KEY);
        assert!(compressed_sql.len() < MAX_CONFIGMAP_SQL_BYTES);
        assert_eq!(gunzip(compressed_sql), sql);
        assert_eq!(
            prepared.sql_ref().unwrap().compression,
            Some(SqlCompression::Gzip)
        );
        assert_eq!(prepared.original_bytes, sql.len());
        assert_eq!(prepared.stored_bytes, compressed_sql.len());
    }

    #[test]
    fn configmap_binary_data_serializes_with_one_base64_layer() {
        let sql = brownfield_sized_sql();
        let prepared = prepare_plan_sql("policy-plan-20260506-000000-abcdef012345", &sql).unwrap();
        let PlanSqlArtifact::CompressedConfigMap {
            key,
            compressed_sql,
            ..
        } = &prepared.artifact
        else {
            panic!("expected compressed ConfigMap artifact");
        };
        let configmap = ConfigMap {
            binary_data: Some(BTreeMap::from([(
                key.clone(),
                ByteString(compressed_sql.clone()),
            )])),
            ..Default::default()
        };

        let encoded = serde_json::to_value(&configmap).unwrap()["binaryData"][key]
            .as_str()
            .unwrap()
            .to_string();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();

        assert_eq!(decoded, *compressed_sql);
        assert_eq!(gunzip(&decoded), sql);
    }

    #[test]
    fn prepare_plan_sql_truncates_when_compressed_sql_is_still_too_large() {
        let sql = deterministic_incompressible_sql(1_400_000);
        let prepared = prepare_plan_sql("policy-plan-20260506-000000-abcdef012345", &sql).unwrap();

        let PlanSqlArtifact::TruncatedInline(preview) = &prepared.artifact else {
            panic!("expected truncated inline artifact");
        };
        assert!(preview.len() <= MAX_INLINE_SQL_BYTES);
        assert!(preview.contains("truncated"));
        assert!(prepared.sql_ref().is_none());
        assert!(prepared.is_truncated());
    }

    #[test]
    fn sanitize_label_value_replaces_slashes() {
        let sanitized = sanitize_label_value("default/db-creds/DATABASE_URL");
        assert!(!sanitized.contains('/'));
        assert_eq!(sanitized, "default_db-creds_DATABASE_URL");
    }

    #[test]
    fn sanitize_label_value_truncates_to_63_chars() {
        let long_value = "a".repeat(100);
        let sanitized = sanitize_label_value(&long_value);
        assert!(sanitized.len() <= 63);
    }

    #[test]
    fn stale_policy_sql_configmap_without_plan_label_is_orphan() {
        let configmap = ConfigMap {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                labels: Some(BTreeMap::from([(
                    LABEL_POLICY.to_string(),
                    sanitize_label_value("test-policy"),
                )])),
                creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    jiff::Timestamp::from_second(0).unwrap(),
                )),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(is_orphan_sql_configmap(
            &configmap,
            &BTreeSet::new(),
            &BTreeSet::new(),
            ORPHAN_GRACE_SECS + 1
        ));
    }

    #[test]
    fn stale_policy_sql_configmap_with_current_plan_name_is_not_orphan() {
        let plan_name = "test-policy-plan-20260506-000000-abcdef012345";
        let configmap = ConfigMap {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(format!("{plan_name}-sql")),
                labels: Some(BTreeMap::from([
                    (
                        LABEL_POLICY.to_string(),
                        sanitize_label_value("test-policy"),
                    ),
                    (
                        LABEL_PLAN.to_string(),
                        sanitize_label_value("legacy-colliding-label"),
                    ),
                ])),
                creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    jiff::Timestamp::from_second(0).unwrap(),
                )),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(!is_orphan_sql_configmap(
            &configmap,
            &BTreeSet::from([plan_name.to_string()]),
            &BTreeSet::new(),
            ORPHAN_GRACE_SECS + 1
        ));
    }

    #[test]
    fn stale_policy_sql_configmap_with_known_hash_plan_label_is_not_orphan() {
        let plan_name = "test-policy-plan-20260506-000000-abcdef012345";
        let plan_label = plan_label_value(plan_name);
        let configmap = ConfigMap {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("different-plan-sql".to_string()),
                labels: Some(BTreeMap::from([
                    (
                        LABEL_POLICY.to_string(),
                        sanitize_label_value("test-policy"),
                    ),
                    (LABEL_PLAN.to_string(), plan_label.clone()),
                ])),
                creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    jiff::Timestamp::from_second(0).unwrap(),
                )),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(!is_orphan_sql_configmap(
            &configmap,
            &BTreeSet::new(),
            &BTreeSet::from([plan_label]),
            ORPHAN_GRACE_SECS + 1
        ));
    }

    #[test]
    fn stale_policy_sql_configmap_with_only_legacy_colliding_label_is_orphan() {
        let plan_name =
            "very-long-policy-name-that-would-have-collided-plan-20260506-000000-abcdef012345";
        let legacy_label = sanitize_label_value(plan_name);
        let configmap = ConfigMap {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("deleted-historical-plan-sql".to_string()),
                labels: Some(BTreeMap::from([
                    (
                        LABEL_POLICY.to_string(),
                        sanitize_label_value("test-policy"),
                    ),
                    (LABEL_PLAN.to_string(), legacy_label.clone()),
                ])),
                creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                    jiff::Timestamp::from_second(0).unwrap(),
                )),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(is_orphan_sql_configmap(
            &configmap,
            &BTreeSet::new(),
            &BTreeSet::new(),
            ORPHAN_GRACE_SECS + 1
        ));
    }

    #[tokio::test]
    #[ignore = "requires live PostgreSQL"]
    async fn batch_execution_restores_role_and_rolls_back_on_failure() {
        use pgroles_core::{
            diff::Change,
            manifest::{ObjectType, Privilege},
            model::Grantee,
        };
        use sqlx::{
            Executor,
            postgres::{PgConnectOptions, PgPoolOptions},
        };
        use std::str::FromStr;
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
        let admin = sqlx::PgPool::connect(&url).await.unwrap();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let login = format!("batch_login_{suffix}");
        let executor = format!("batch_exec_{suffix}");
        let owner = format!("batch_owner_{suffix}");
        let reader = format!("batch_reader_{suffix}");
        let schema = format!("batch_{suffix}");
        admin
            .execute(
                format!(
                    r#"
            CREATE ROLE "{login}" LOGIN NOINHERIT PASSWORD 'batch_password';
            CREATE ROLE "{executor}" NOINHERIT;
            CREATE ROLE "{owner}";
            CREATE ROLE "{reader}";
            GRANT "{executor}", "{owner}" TO "{login}";
            CREATE SCHEMA "{schema}" AUTHORIZATION "{owner}";
            CREATE TABLE "{schema}".a (id int);
            CREATE TABLE "{schema}".b (id int);
            ALTER TABLE "{schema}".a OWNER TO "{owner}";
            ALTER TABLE "{schema}".b OWNER TO "{owner}";
            SET ROLE "{owner}";
            GRANT SELECT ON "{schema}".a, "{schema}".b TO "{reader}";
            RESET ROLE;
        "#
                )
                .as_str(),
            )
            .await
            .unwrap();
        let hook_role = executor.clone();
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .after_connect(move |conn, _| {
                let stmt = format!("SET ROLE {};", pgroles_core::sql::quote_ident(&hook_role));
                Box::pin(async move {
                    conn.execute(stmt.as_str()).await?;
                    Ok(())
                })
            })
            .connect_with(
                PgConnectOptions::from_str(&url)
                    .unwrap()
                    .username(&login)
                    .password("batch_password"),
            )
            .await
            .unwrap();
        let revoke = |name: &str| Change::Revoke {
            role: Grantee::Role(reader.clone()),
            privileges: BTreeSet::from([Privilege::Select]),
            object_type: ObjectType::Table,
            schema: Some(schema.clone()),
            name: Some(name.into()),
            grantor: Some(owner.clone()),
        };
        let ctx =
            pgroles_core::sql::SqlContext::default().with_execution_role(Some(executor.clone()));
        let current = || sqlx::query_scalar::<_, String>("SELECT current_user::text");
        // The second statement fails inside the shared owner block: transaction
        // rollback must restore both the first ACL and the connection role.
        assert!(
            execute_changes_in_transaction(&pool, &[revoke("a"), revoke("missing")], &ctx)
                .await
                .is_err()
        );
        assert_eq!(current().fetch_one(&pool).await.unwrap(), executor);
        let check = format!(
            r#"SELECT has_table_privilege('{}', '"{}".a', 'SELECT')"#,
            reader, schema
        );
        assert!(
            sqlx::query_scalar::<_, bool>(&check)
                .fetch_one(&admin)
                .await
                .unwrap()
        );
        let changes = vec![revoke("a"), revoke("b")];
        assert_eq!(
            render_full_sql(&changes, &ctx),
            render_redacted_sql(&changes, &ctx)
        );
        assert_eq!(
            execute_changes_in_transaction(&pool, &changes, &ctx)
                .await
                .unwrap(),
            4
        );
        assert_eq!(current().fetch_one(&pool).await.unwrap(), executor);
        for table in ["a", "b"] {
            let check = format!(
                r#"SELECT has_table_privilege('{}', '"{}".{}', 'SELECT')"#,
                reader, schema, table
            );
            assert!(
                !sqlx::query_scalar::<_, bool>(&check)
                    .fetch_one(&admin)
                    .await
                    .unwrap()
            );
        }
        pool.close().await;
        admin.execute(format!(r#"DROP SCHEMA "{schema}" CASCADE; DROP ROLE "{login}", "{executor}", "{owner}", "{reader}";"#).as_str()).await.unwrap();
        admin.close().await;
    }

    #[test]
    fn render_redacted_sql_masks_passwords() {
        let changes = vec![
            pgroles_core::diff::Change::CreateRole {
                name: "app".to_string(),
                state: pgroles_core::model::RoleState {
                    login: true,
                    ..pgroles_core::model::RoleState::default()
                },
            },
            pgroles_core::diff::Change::SetPassword {
                name: "app".to_string(),
                password: "super_secret".to_string(),
            },
        ];
        let ctx = pgroles_core::sql::SqlContext::default();
        let redacted = render_redacted_sql(&changes, &ctx);

        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("super_secret"));
        assert!(redacted.contains("CREATE ROLE"));
    }

    #[test]
    fn render_redacted_sql_password_only_plan() {
        // A plan whose only change is a password rotation still has to redact:
        // there is no surrounding DDL to dilute a leak.
        let changes = vec![pgroles_core::diff::Change::SetPassword {
            name: "db-user".to_string(),
            password: "my_secret_pw".to_string(),
        }];
        let ctx = pgroles_core::sql::SqlContext::default();
        let redacted = render_redacted_sql(&changes, &ctx);

        assert!(redacted.contains("[REDACTED]"));
        assert!(!redacted.contains("my_secret_pw"));
    }

    #[test]
    fn render_full_sql_includes_passwords() {
        let changes = vec![pgroles_core::diff::Change::SetPassword {
            name: "app".to_string(),
            password: "super_secret".to_string(),
        }];
        let ctx = pgroles_core::sql::SqlContext::default();
        let full = render_full_sql(&changes, &ctx);

        assert!(full.contains("super_secret") || full.contains("SCRAM-SHA-256"));
    }

    #[test]
    fn now_epoch_secs_returns_plausible_value() {
        let now = now_epoch_secs();
        // Should be after 2025-01-01 and before 2100-01-01.
        let y2025 = 1_735_689_600_i64;
        let y2100 = 4_102_444_800_i64;
        assert!(
            now > y2025 && now < y2100,
            "epoch secs {now} should be between 2025 and 2100"
        );
    }

    fn brownfield_sized_sql() -> String {
        let mut sql = String::new();
        for schema in 0..33 {
            for profile in ["reader", "writer", "owner", "cdc"] {
                let role = format!("schema_{schema}_{profile}");
                sql.push_str(&format!(
                    "CREATE ROLE \"{role}\" LOGIN;\nCOMMENT ON ROLE \"{role}\" IS 'Generated from profile {profile} for brownfield migration schema {schema} with cdc ownership directives and review metadata';\n"
                ));
                for relkind in ["TABLES", "SEQUENCES", "FUNCTIONS"] {
                    sql.push_str(&format!(
                        "GRANT SELECT ON ALL {relkind} IN SCHEMA \"schema_{schema}\" TO \"{role}\";\n"
                    ));
                }
                for owner in 0..20 {
                    sql.push_str(&format!(
                        "ALTER DEFAULT PRIVILEGES FOR ROLE \"owner_{owner}\" IN SCHEMA \"schema_{schema}\" GRANT SELECT ON TABLES TO \"{role}\";\n"
                    ));
                }
            }
        }
        for member in 0..70 {
            sql.push_str(&format!(
                "GRANT \"group_{member}\" TO \"service_login_{}\";\n",
                member % 20
            ));
        }
        while sql.len() <= 1_100_000 {
            sql.push_str("-- brownfield migration padding for large plan regression\n");
        }
        sql
    }

    fn deterministic_incompressible_sql(target_bytes: usize) -> String {
        let mut state = 0x1234_5678_u64;
        let mut sql = String::with_capacity(target_bytes);
        while sql.len() < target_bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let value = (state % 62) as u8;
            let ch = match value {
                0..=9 => b'0' + value,
                10..=35 => b'a' + (value - 10),
                _ => b'A' + (value - 36),
            };
            sql.push(ch as char);
            if sql.len().is_multiple_of(120) {
                sql.push('\n');
            }
        }
        sql
    }

    fn gunzip(bytes: &[u8]) -> String {
        let mut decoder = GzDecoder::new(bytes);
        let mut decoded = String::new();
        decoder.read_to_string(&mut decoded).unwrap();
        decoded
    }

    // -----------------------------------------------------------------------
    // Approval identity (#174)
    // -----------------------------------------------------------------------

    fn password_versions(role: &str, version: &str) -> BTreeMap<String, String> {
        BTreeMap::from([(role.to_string(), version.to_string())])
    }

    fn set_password(name: &str, verifier: &str) -> pgroles_core::diff::Change {
        pgroles_core::diff::Change::SetPassword {
            name: name.to_string(),
            password: verifier.to_string(),
        }
    }

    fn grant_change(role: &str) -> pgroles_core::diff::Change {
        pgroles_core::diff::Change::Grant {
            role: pgroles_core::model::Grantee::parse(role),
            privileges: [pgroles_core::manifest::Privilege::Select]
                .into_iter()
                .collect(),
            object_type: pgroles_core::manifest::ObjectType::Table,
            schema: Some("inventory".to_string()),
            name: Some("orders".to_string()),
        }
    }

    fn test_target_identity() -> TargetIdentity {
        TargetIdentity {
            physical: Some("7412330000000000001".to_string()),
            logical: Some("sha256:endpoint".to_string()),
        }
    }

    fn digest_for(
        changes: &[pgroles_core::diff::Change],
        versions: &BTreeMap<String, String>,
    ) -> String {
        compute_change_digest(
            changes,
            CrdReconciliationMode::default(),
            "default/db-credentials:DATABASE_URL",
            &test_target_identity(),
            versions,
            &[],
            &[],
        )
        .expect("digest")
    }

    /// The #174 failure mode: a manually approved password plan could never
    /// execute, because each reconcile re-derived the SCRAM verifier with a
    /// fresh salt and the approval was bound to the rendered SQL.
    #[test]
    fn password_plans_keep_one_approval_identity_across_reconciles() {
        let versions = password_versions("app", "role-passwords:app:7");

        // Two reconciles of an unchanged password source, each with its own
        // randomly salted verifier.
        let first = digest_for(
            &[set_password("app", "SCRAM-SHA-256$4096:aaa$sA:vA")],
            &versions,
        );
        let second = digest_for(
            &[set_password("app", "SCRAM-SHA-256$4096:bbb$sB:vB")],
            &versions,
        );

        assert_eq!(first, second);

        // The SQL hash is what used to gate approval, and is still unstable —
        // which is exactly why it is no longer the approval identity.
        let ctx = pgroles_core::sql::SqlContext::default();
        assert_ne!(
            compute_sql_hash(&render_full_sql(
                &[set_password("app", "SCRAM-SHA-256$4096:aaa$sA:vA")],
                &ctx
            )),
            compute_sql_hash(&render_full_sql(
                &[set_password("app", "SCRAM-SHA-256$4096:bbb$sB:vB")],
                &ctx
            )),
        );
    }

    #[test]
    fn rotating_a_password_source_is_a_new_approval() {
        let change = [set_password("app", "SCRAM-SHA-256$4096:aaa$sA:vA")];

        assert_ne!(
            digest_for(&change, &password_versions("app", "role-passwords:app:7")),
            digest_for(&change, &password_versions("app", "role-passwords:app:8")),
        );
    }

    // -----------------------------------------------------------------------
    // Pending-plan revalidation (Phase 0.2)
    // -----------------------------------------------------------------------

    /// Provenance is refreshed only when the generation it records has moved,
    /// so an unchanged policy does not rewrite the plan on every reconcile.
    #[test]
    fn revalidation_is_recorded_once_per_generation() {
        let confirmed_at_3 = PostgresPolicyPlanStatus {
            revalidated_generation: Some(3),
            ..Default::default()
        };
        assert!(!needs_revalidation_record(&confirmed_at_3, Some(3)));
        assert!(needs_revalidation_record(&confirmed_at_3, Some(4)));
        // A plan recorded against a *newer* generation than the one being
        // reconciled — a stale watch-cache read — must also re-record, so the
        // provenance always names the generation actually confirmed. Without
        // this case the comparison could be `<` rather than `!=` and no test
        // would notice.
        assert!(needs_revalidation_record(&confirmed_at_3, Some(2)));

        // A plan from before this field existed gets its provenance filled in.
        let legacy = PostgresPolicyPlanStatus::default();
        assert!(needs_revalidation_record(&legacy, Some(1)));

        // A policy with no generation at all is consistent with itself.
        assert!(!needs_revalidation_record(&legacy, None));
    }

    /// The revalidation decision is exactly the digest comparison: a policy
    /// edit that leaves effects untouched must not cost a review round, and one
    /// that changes them must not leave a reviewable plan describing the old
    /// effects.
    #[test]
    fn a_pending_plan_is_retained_only_while_its_effects_hold() {
        let versions = password_versions("app", "role-passwords:app:7");
        let original = [grant_change("reporting")];
        let edited = [grant_change("analytics")];

        let planned = digest_for(&original, &versions);
        let pending = PostgresPolicyPlanStatus {
            phase: PlanPhase::Pending,
            change_digest: Some(planned.clone()),
            change_digest_encoding: Some(APPROVAL_EFFECT_ENCODING_V3.to_string()),
            revalidated_generation: Some(1),
            ..Default::default()
        };

        // Effect-neutral policy edit: same effects, later generation.
        assert!(plan_matches_digest(
            &pending,
            &digest_for(&original, &versions)
        ));
        assert!(needs_revalidation_record(&pending, Some(2)));

        // Effects changed: the plan can no longer be the one under review.
        assert!(!plan_matches_digest(
            &pending,
            &digest_for(&edited, &versions)
        ));
    }

    #[test]
    fn creating_a_replacement_retires_the_pending_plan_it_replaces() {
        // The retirement is what step 12 performs *after* the replacement is
        // visible; no caller may supersede ahead of it, so this predicate is
        // the only thing deciding which plans a create retires.
        let versions = password_versions("app", "role-passwords:app:1");
        let old_digest = digest_for(&[grant_change("app")], &versions);
        let new_digest = digest_for(&[grant_change("reporting")], &versions);

        let pending = PostgresPolicyPlanStatus {
            phase: PlanPhase::Pending,
            change_digest: Some(old_digest.clone()),
            change_digest_encoding: Some(APPROVAL_EFFECT_ENCODING_V3.to_string()),
            ..Default::default()
        };
        // At most one plan may await a decision, so a pending plan is retired
        // whether or not its effects moved.
        assert!(supersedes_after_create(&pending, &new_digest));
        assert!(supersedes_after_create(&pending, &old_digest));
    }

    #[test]
    fn creating_a_replacement_voids_an_approval_that_no_longer_describes_the_effects() {
        let versions = password_versions("app", "role-passwords:app:1");
        let approved_digest = digest_for(&[grant_change("app")], &versions);
        let fresh_digest = digest_for(&[grant_change("reporting")], &versions);

        let approved = PostgresPolicyPlanStatus {
            phase: PlanPhase::Approved,
            change_digest: Some(approved_digest.clone()),
            change_digest_encoding: Some(APPROVAL_EFFECT_ENCODING_V3.to_string()),
            ..Default::default()
        };

        // The decision described effects the policy no longer produces: void.
        assert!(supersedes_after_create(&approved, &fresh_digest));
        // Still the current effects — a live decision, never discarded by a
        // create that happens to run beside it.
        assert!(!supersedes_after_create(&approved, &approved_digest));
    }

    #[test]
    fn creating_a_plan_never_disturbs_a_settled_one() {
        for phase in [
            PlanPhase::Applied,
            PlanPhase::Failed,
            PlanPhase::Rejected,
            PlanPhase::Superseded,
            PlanPhase::Applying,
        ] {
            let status = PostgresPolicyPlanStatus {
                phase,
                ..Default::default()
            };
            assert!(!supersedes_after_create(&status, "any-digest"));
        }
    }

    #[test]
    fn a_recently_failed_identical_plan_is_reported_apart_from_a_pending_one() {
        // Callers word the policy status off these variants: one plan is
        // awaiting a decision, the other has already failed and is waiting out
        // its retry window.
        let pending = PlanCreationResult::Deduplicated("plan-a".to_string());
        assert_eq!(pending.plan_name(), "plan-a");
        assert!(!pending.is_created());
        assert!(!pending.is_failed_backoff());

        let failed = PlanCreationResult::DeduplicatedFailed("plan-b".to_string());
        assert_eq!(failed.plan_name(), "plan-b");
        assert!(!failed.is_created());
        assert!(failed.is_failed_backoff());

        let created = PlanCreationResult::Created("plan-c".to_string());
        assert!(created.is_created());
        assert!(!created.is_failed_backoff());
    }

    /// A candidate-origin plan's provenance names the candidate's generation,
    /// not the parent policy's: the candidate is the spec the plan derives
    /// from, and its immutability means the value is stamped once, honestly.
    #[test]
    fn a_candidate_plans_provenance_is_the_candidates_own_generation() {
        let mut policy = PostgresPolicy::new(
            "orders",
            serde_json::from_value(serde_json::json!({
                "connection": { "secretRef": { "name": "db" } },
            }))
            .expect("minimal policy spec"),
        );
        policy.metadata.generation = Some(5);
        let mut candidate = PostgresPolicyCandidate::new(
            "orders-change-x7k2p",
            crate::crd::PostgresPolicyCandidateSpec {
                policy_ref: crate::crd::LocalObjectReference {
                    name: "orders".to_string(),
                },
                replaces: None,
                target: None,
                content: Default::default(),
            },
        );
        candidate.metadata.generation = Some(1);

        assert_eq!(PlanOwner::Policy(&policy).generation(), 5);
        assert_eq!(PlanOwner::Candidate(&candidate).generation(), 1);
    }

    #[test]
    fn a_newly_created_plan_records_its_own_generation_as_confirmed() {
        // Guards the invariant that a plan is never born already looking stale,
        // which would make the first reconcile after creation patch it.
        let fresh = PostgresPolicyPlanStatus {
            revalidated_generation: Some(7),
            ..Default::default()
        };
        assert!(!needs_revalidation_record(&fresh, Some(7)));
    }

    #[test]
    fn a_plan_matches_only_its_own_digest_under_the_current_encoding() {
        let versions = password_versions("app", "role-passwords:app:7");
        let digest = digest_for(
            &[set_password("app", "SCRAM-SHA-256$4096:aaa$sA:vA")],
            &versions,
        );

        let current = PostgresPolicyPlanStatus {
            change_digest: Some(digest.clone()),
            change_digest_encoding: Some(APPROVAL_EFFECT_ENCODING_V3.to_string()),
            ..Default::default()
        };
        assert!(plan_matches_digest(&current, &digest));

        // A plan written before this encoding existed must never match, so it
        // is superseded and re-reviewed rather than silently accepted.
        let legacy = PostgresPolicyPlanStatus {
            sql_hash: Some("deadbeef".to_string()),
            ..Default::default()
        };
        assert!(!plan_matches_digest(&legacy, &digest));

        let other_encoding = PostgresPolicyPlanStatus {
            change_digest: Some(digest.clone()),
            change_digest_encoding: Some("pgroles.io/approval-effect/v0".to_string()),
            ..Default::default()
        };
        assert!(!plan_matches_digest(&other_encoding, &digest));

        let different_effects = PostgresPolicyPlanStatus {
            change_digest: Some("sha256:0000".to_string()),
            change_digest_encoding: Some(APPROVAL_EFFECT_ENCODING_V3.to_string()),
            ..Default::default()
        };
        assert!(!plan_matches_digest(&different_effects, &digest));

        // A plan carrying the same digest string under v2 encodes
        // default-privilege scope differently, so it is not comparable and
        // must supersede instead of being accepted.
        let previous_encoding = PostgresPolicyPlanStatus {
            change_digest: Some(digest.clone()),
            change_digest_encoding: Some(
                pgroles_core::approval::APPROVAL_EFFECT_ENCODING_V2.to_string(),
            ),
            ..Default::default()
        };
        assert!(!plan_matches_digest(&previous_encoding, &digest));
    }

    /// A pending plan whose effects disappear before anyone decides on it must
    /// leave no plan behind. Replacing it with an empty one would park the
    /// policy on an approval for nothing while it reports `Drifted=False`.
    #[test]
    fn a_pending_plan_whose_effects_vanish_is_cleared_not_replaced() {
        let versions = password_versions("app", "role-passwords:app:7");
        let planned = digest_for(&[grant_change("reporting")], &versions);
        let pending = PostgresPolicyPlanStatus {
            phase: PlanPhase::Pending,
            change_digest: Some(planned),
            change_digest_encoding: Some(APPROVAL_EFFECT_ENCODING_V3.to_string()),
            ..Default::default()
        };
        let empty_digest = digest_for(&[], &versions);

        assert_eq!(
            decide_pending_plan(Some(&pending), &empty_digest, false),
            PendingPlanDecision::Clear,
        );

        // Even a plan that legitimately matches an empty change set holds
        // nothing to approve, so it is cleared rather than retained.
        let empty_plan = PostgresPolicyPlanStatus {
            phase: PlanPhase::Pending,
            change_digest: Some(empty_digest.clone()),
            change_digest_encoding: Some(APPROVAL_EFFECT_ENCODING_V3.to_string()),
            ..Default::default()
        };
        assert_eq!(
            decide_pending_plan(Some(&empty_plan), &empty_digest, false),
            PendingPlanDecision::Clear,
        );
    }

    #[test]
    fn a_pending_plan_is_replaced_only_when_real_effects_moved() {
        let versions = password_versions("app", "role-passwords:app:7");
        let original = [grant_change("reporting")];
        let edited = [grant_change("analytics")];
        let pending = PostgresPolicyPlanStatus {
            phase: PlanPhase::Pending,
            change_digest: Some(digest_for(&original, &versions)),
            change_digest_encoding: Some(APPROVAL_EFFECT_ENCODING_V3.to_string()),
            ..Default::default()
        };

        assert_eq!(
            decide_pending_plan(Some(&pending), &digest_for(&original, &versions), true),
            PendingPlanDecision::Retain,
        );
        assert_eq!(
            decide_pending_plan(Some(&pending), &digest_for(&edited, &versions), true),
            PendingPlanDecision::Replace,
        );

        // A plan with no status yet, or one written under an older encoding,
        // cannot be shown to hold the current effects — fail closed.
        assert_eq!(
            decide_pending_plan(None, &digest_for(&original, &versions), true),
            PendingPlanDecision::Replace,
        );
        assert_eq!(
            decide_pending_plan(
                Some(&PostgresPolicyPlanStatus::default()),
                &digest_for(&original, &versions),
                true
            ),
            PendingPlanDecision::Replace,
        );
    }

    /// The gate between a recorded decision and executing DDL. Every case that
    /// is not a proven match must refuse to execute — this is the one check
    /// standing between an approval and running different SQL than was read.
    #[test]
    fn an_approval_executes_only_the_effects_it_was_given_for() {
        let versions = password_versions("app", "role-passwords:app:7");
        let approved_changes = [grant_change("reporting")];
        let approved_digest = digest_for(&approved_changes, &versions);
        let approved = PostgresPolicyPlanStatus {
            phase: PlanPhase::Approved,
            change_digest: Some(approved_digest.clone()),
            change_digest_encoding: Some(APPROVAL_EFFECT_ENCODING_V3.to_string()),
            ..Default::default()
        };

        assert_eq!(
            decide_approved_plan(Some(&approved), &approved_digest, true),
            ApprovedPlanDecision::Execute,
        );

        // Effects moved after the decision: the approval described something
        // else, so it must not authorise this.
        assert_eq!(
            decide_approved_plan(
                Some(&approved),
                &digest_for(&[grant_change("analytics")], &versions),
                true
            ),
            ApprovedPlanDecision::Replace,
        );

        // Fail closed on anything that cannot be proven to match: no status
        // yet, no digest at all, or a digest under an older encoding.
        for unprovable in [
            None,
            Some(&PostgresPolicyPlanStatus::default()),
            Some(&PostgresPolicyPlanStatus {
                change_digest: Some(approved_digest.clone()),
                change_digest_encoding: Some("pgroles.io/approval-effect/v0".to_string()),
                ..Default::default()
            }),
        ] {
            assert_ne!(
                decide_approved_plan(unprovable, &approved_digest, true),
                ApprovedPlanDecision::Execute,
            );
        }
    }

    /// Repointing the connection at a different database must invalidate the
    /// approval, even though every effect and the Kubernetes reference are
    /// unchanged. This is the #180 gap: `DatabaseIdentity` names a Secret and
    /// key, and both survive the repointing.
    #[test]
    fn an_approval_does_not_carry_over_to_a_moved_target() {
        let versions = BTreeMap::new();
        let changes = [grant_change("reporting")];

        let approved = PostgresPolicyPlanStatus {
            change_digest: Some(digest_for(&changes, &versions)),
            change_digest_encoding: Some(APPROVAL_EFFECT_ENCODING_V3.to_string()),
            target_physical_identity: test_target_identity().physical,
            target_logical_fingerprint: test_target_identity().logical,
            physical_identity_available: Some(true),
            ..Default::default()
        };

        // Same Secret, same key, same effects — different endpoint behind it.
        let moved = TargetIdentity {
            logical: Some("sha256:other-endpoint".to_string()),
            ..test_target_identity()
        };
        let fresh_digest = compute_change_digest(
            &changes,
            CrdReconciliationMode::default(),
            "default/db-credentials:DATABASE_URL",
            &moved,
            &versions,
            &[],
            &[],
        )
        .expect("digest");

        assert_eq!(
            decide_approved_plan(Some(&approved), &fresh_digest, true),
            ApprovedPlanDecision::Replace,
        );
        assert_eq!(
            pgroles_core::approval::evaluate_target_identity(
                &plan_target_identity(&approved),
                &moved,
                false,
            ),
            pgroles_core::approval::TargetIdentityVerdict::Superseded(
                pgroles_core::approval::TargetIdentityReason::TargetChanged
            ),
        );
    }

    /// A plan written before the identity fields existed reports neither, so
    /// it can never be shown to hold the current target — which is the
    /// fail-closed direction, and matches its older digest encoding.
    #[test]
    fn a_plan_without_recorded_identities_matches_nothing_observed() {
        let legacy = PostgresPolicyPlanStatus::default();

        assert_eq!(plan_target_identity(&legacy), TargetIdentity::default());
        assert_ne!(
            pgroles_core::approval::evaluate_target_identity(
                &plan_target_identity(&legacy),
                &test_target_identity(),
                false,
            ),
            pgroles_core::approval::TargetIdentityVerdict::Proceed,
        );
    }

    /// The same no-op trap as the pending arm: if the approved effects are
    /// applied by hand before the plan executes, superseding it must not leave
    /// a zero-change replacement demanding a second approval.
    #[test]
    fn an_approved_plan_whose_effects_vanish_is_cleared_not_replaced() {
        let versions = password_versions("app", "role-passwords:app:7");
        let approved = PostgresPolicyPlanStatus {
            phase: PlanPhase::Approved,
            change_digest: Some(digest_for(&[grant_change("reporting")], &versions)),
            change_digest_encoding: Some(APPROVAL_EFFECT_ENCODING_V3.to_string()),
            ..Default::default()
        };
        let empty_digest = digest_for(&[], &versions);

        assert_eq!(
            decide_approved_plan(Some(&approved), &empty_digest, false),
            ApprovedPlanDecision::Clear,
        );

        // An approved plan that genuinely holds nothing is resolved by running
        // it — that marks it Applied and releases the policy, rather than
        // superseding it into another decision no one should have to make.
        let approved_empty = PostgresPolicyPlanStatus {
            phase: PlanPhase::Approved,
            change_digest: Some(empty_digest.clone()),
            change_digest_encoding: Some(APPROVAL_EFFECT_ENCODING_V3.to_string()),
            ..Default::default()
        };
        assert_eq!(
            decide_approved_plan(Some(&approved_empty), &empty_digest, false),
            ApprovedPlanDecision::Execute,
        );
    }

    /// A status carrying a duplicate condition type must collapse to one.
    ///
    /// Replacing only the first match left the second in place, and a second
    /// `Approved=True` makes the terminality rule see the true-decision set
    /// grow — which rejects the operator's own write and strands the plan.
    #[test]
    fn setting_a_condition_leaves_exactly_one_of_that_type() {
        let mut conditions = vec![
            PolicyCondition {
                condition_type: "Computed".to_string(),
                status: "True".to_string(),
                reason: None,
                message: None,
                last_transition_time: None,
            },
            PolicyCondition {
                condition_type: "Approved".to_string(),
                status: "False".to_string(),
                reason: Some("PendingApproval".to_string()),
                message: None,
                last_transition_time: None,
            },
            PolicyCondition {
                condition_type: "Approved".to_string(),
                status: "True".to_string(),
                reason: Some("ApprovedByReviewer".to_string()),
                message: None,
                last_transition_time: None,
            },
        ];

        set_plan_condition(&mut conditions, "Approved", "True", "Reason", "Message");

        let approved: Vec<_> = conditions
            .iter()
            .filter(|c| c.condition_type == "Approved")
            .collect();
        assert_eq!(approved.len(), 1, "duplicate Approved conditions survived");
        assert_eq!(approved[0].status, "True");
        // Unrelated conditions are untouched.
        assert!(conditions.iter().any(|c| c.condition_type == "Computed"));
    }

    /// Planning must never persist password material, in any field.
    ///
    /// Asserted against the *pre-hash* canonical bytes, not the digest string.
    /// Checking that a SHA-256 hex string does not contain the verifier is true
    /// of any hash of any input, so it would pass even while the verifier was
    /// being hashed in — the same trap the core suite documents at
    /// `approval::the_digest_never_contains_password_material`.
    #[test]
    fn the_digest_carries_no_password_material() {
        let verifier = "SCRAM-SHA-256$4096:c2FsdA==$c3RvcmVk:c2VydmVy";
        let changes = [set_password("app", verifier)];
        let versions = password_versions("app", "role-passwords:app:7");

        let bytes = pgroles_core::approval::canonical_change_set_bytes(
            &changes,
            &pgroles_core::approval::EffectDigestInputs {
                reconciliation_mode: CrdReconciliationMode::default().into(),
                target: "default/db-credentials:DATABASE_URL",
                target_identity: &test_target_identity(),
                password_source_versions: &versions,
                owned_roles: &[],
                owned_schemas: &[],
            },
        )
        .expect("canonical bytes");
        let encoded = String::from_utf8(bytes).expect("canonical bytes are UTF-8");

        assert!(
            !encoded.contains(verifier),
            "verifier reached the digest input: {encoded}"
        );
        assert!(
            !encoded.contains("c3RvcmVk"),
            "stored key reached the digest input: {encoded}"
        );
        // The password *source version* is what the digest binds instead, so a
        // rotation is a new approval while a re-salted verifier is not.
        assert!(encoded.contains("role-passwords:app:7"));

        assert!(digest_for(&changes, &versions).starts_with("sha256:"));
    }
}
