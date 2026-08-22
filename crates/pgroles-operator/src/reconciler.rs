//! Reconciliation logic for `PostgresPolicy` custom resources.
//!
//! Implements the core reconcile loop: read desired state from the CR,
//! inspect current state from the database, compute diff, and apply changes.
//!
//! Reconciliation is serialized per database target to prevent overlapping
//! inspect/diff/apply cycles:
//!
//! 1. **In-process lock** — [`OperatorContext::try_lock_database`] prevents
//!    concurrent reconciles within the same operator replica.
//! 2. **PostgreSQL advisory lock** — [`crate::advisory::try_acquire`] prevents
//!    concurrent operations across multiple operator replicas.

use std::sync::Arc;
use std::time::Duration;

use crate::events::{PlanEventType, publish_plan_event, publish_status_events};
use kube::ResourceExt;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{self, Event as FinalizerEvent};
use tracing::info;

use crate::context::{ContextError, OperatorContext};
use crate::crd::{
    ChangeSummary, DatabaseIdentity, PolicyMode, PostgresPolicy, PostgresPolicyPlan,
    PostgresPolicyStatus, REQUESTED_RECONCILE_ANNOTATION, conflict_condition, degraded_condition,
    drifted_condition, paused_condition, ready_condition, reconciling_condition,
};

/// Finalizer name for PostgresPolicy resources.
const FINALIZER: &str = "pgroles.io/finalizer";

/// Default requeue interval when no interval is specified on the CR.
pub(crate) const DEFAULT_REQUEUE_SECS: u64 = 300; // 5 minutes

/// Base requeue delay when lock contention is detected.
const LOCK_CONTENTION_BASE_SECS: u64 = 10;

/// Maximum jitter added to the base requeue delay on lock contention.
const LOCK_CONTENTION_JITTER_SECS: u64 = 20;

/// Base requeue delay when transient operational failures occur.
const TRANSIENT_BACKOFF_BASE_SECS: u64 = 5;

/// Maximum requeue delay for transient operational failures.
const TRANSIENT_BACKOFF_MAX_SECS: u64 = 300;

/// SQLSTATE returned by PostgreSQL for insufficient privileges.
const SQLSTATE_INSUFFICIENT_PRIVILEGE: &str = "42501";
const SQLSTATE_INVALID_SCHEMA_NAME: &str = "3F000";
const SQLSTATE_UNDEFINED_TABLE: &str = "42P01";
const SQLSTATE_UNDEFINED_FUNCTION: &str = "42883";
const SQLSTATE_UNDEFINED_OBJECT: &str = "42704";

enum ReconcileOutcome {
    Reconciled,
    Planned,
    Suspended,
    Conflict,
    LockContention,
    /// The target cannot answer an identity the deployment requires. Nothing
    /// converges until that is fixed, so this is not a drift or a failure to
    /// retry into success.
    TargetIdentityBlocked,
}

impl ReconcileOutcome {
    fn result(&self) -> &'static str {
        match self {
            ReconcileOutcome::Reconciled => "success",
            ReconcileOutcome::Planned => "planned",
            ReconcileOutcome::Suspended => "suspended",
            ReconcileOutcome::Conflict => "conflict",
            ReconcileOutcome::TargetIdentityBlocked => "blocked",
            ReconcileOutcome::LockContention => "contention",
        }
    }

    fn reason(&self) -> &'static str {
        match self {
            ReconcileOutcome::Reconciled => "Reconciled",
            ReconcileOutcome::Planned => "Planned",
            ReconcileOutcome::Suspended => "Suspended",
            ReconcileOutcome::Conflict => "ConflictingPolicy",
            ReconcileOutcome::TargetIdentityBlocked => "PhysicalIdentityRequired",
            ReconcileOutcome::LockContention => "LockContention",
        }
    }

    fn marks_requested_reconcile_handled(&self) -> bool {
        matches!(
            self,
            ReconcileOutcome::Reconciled | ReconcileOutcome::Planned
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryClass {
    Slow,
    LockContention,
    CleanupPending,
    Transient,
}

/// Errors that can occur during reconciliation.
#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("context error: {0}")]
    Context(#[from] Box<ContextError>),

    #[error("manifest expansion error: {0}")]
    ManifestExpansion(#[from] pgroles_core::manifest::ManifestError),

    #[error("database inspection error: {0}")]
    Inspect(#[from] pgroles_inspect::InspectError),

    #[error("SQL execution error: {0}")]
    SqlExec(#[from] sqlx::Error),

    #[error("{0}")]
    UnsafeRoleDrops(String),

    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),

    #[error("resource has no namespace")]
    NoNamespace,

    #[error("ephemeral request index unavailable: {0}")]
    RequestIndexNotReady(#[from] crate::request_index::IndexNotReady),

    #[error("waiting for {0} attached ephemeral access policy/policies to be deleted")]
    PendingEphemeralAccessCleanup(usize),

    #[error("invalid interval \"{0}\": {1}")]
    InvalidInterval(String, String),

    #[error("invalid spec: {0}")]
    InvalidSpec(String),

    /// A plan that failed inside the retry window was not re-executed.
    ///
    /// Carries the error the plan recorded, so the policy's condition keeps
    /// describing the real problem rather than the back-off that deferred it.
    #[error("plan {0} failed recently and was not retried: {1}")]
    PlanRetryDeferred(String, String),

    #[error("approval digest error: {0}")]
    ApprovalDigest(#[from] pgroles_core::approval::ApprovalDigestError),

    #[error(
        "policy references objects that do not exist in target database: {0}. Either create \
         the missing objects, remove them from the policy, or verify the policy is pointing at \
         the intended database."
    )]
    MissingDatabaseObjects(String),

    #[error("{0}")]
    UnsatisfiableWildcardGrant(String),

    #[error("{0}")]
    ExecutorAuthority(String),

    #[error("{0}")]
    ConflictingPolicy(String),

    #[error("lock contention on database \"{0}\": {1}")]
    LockContention(String, String),

    #[error("Secret \"{secret}\" key \"{key}\" for role \"{role}\" password is empty")]
    EmptyPasswordSecret {
        role: String,
        secret: String,
        key: String,
    },

    #[error("password generation error: {0}")]
    PasswordGeneration(#[from] Box<crate::password::PasswordError>),

    #[error("plan SQL storage error: {0}")]
    PlanSqlStorage(String),

    #[error("Kubernetes API call \"{0}\" did not complete within {1:?}")]
    ApiStalled(&'static str, Duration),
}

/// Ceiling on a single Kubernetes API request made from the reconcile path.
///
/// kube-rs defaults its client to a 295-second read/write timeout, which is
/// sized for long-poll watches, not for the handful of point reads and status
/// patches a reconcile makes. That default is dangerous here for a reason
/// specific to the controller runtime: kube-rs never schedules two concurrent
/// reconciles for the same object, so *one* request that stalls holds that
/// object's only reconcile slot — every requeue, and every trigger a watch
/// fires at it, queues behind the stalled call and is silently deferred. A
/// stalled request must therefore become an ordinary transient error that the
/// error policy requeues, not a wedge.
///
/// Only calls made *before* either reconciliation lock is taken are bounded
/// this way: cancelling one of those is side-effect-free, whereas cancelling
/// work under the locks would abandon an in-flight DDL phase.
const K8S_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Run one pre-lock Kubernetes API call under [`K8S_CALL_TIMEOUT`].
///
/// `call` names the request in the log and in the resulting status condition,
/// so the next occurrence identifies which request stalled instead of leaving
/// a silent gap in the log.
async fn bounded_k8s_call<T, F>(call: &'static str, future: F) -> Result<T, ReconcileError>
where
    F: std::future::Future<Output = Result<T, kube::Error>>,
{
    match tokio::time::timeout(K8S_CALL_TIMEOUT, future).await {
        Ok(result) => result.map_err(ReconcileError::Kube),
        Err(_) => {
            tracing::error!(
                call,
                timeout_secs = K8S_CALL_TIMEOUT.as_secs(),
                "Kubernetes API call did not complete; failing this reconcile so the controller \
                 requeues instead of holding the object's only reconcile slot open"
            );
            Err(ReconcileError::ApiStalled(call, K8S_CALL_TIMEOUT))
        }
    }
}

/// What the policy's locked phase hands to candidate planning.
///
/// Candidates are planned after the policy's own work, in the policy's
/// execution context, so they need two things the locked phase computed and
/// nothing else: the target identity it resolved, and the ephemeral membership
/// overlay it composed. Passing them out rather than recomputing them keeps
/// candidate planning on exactly the state the policy just enforced against.
#[derive(Debug, Default)]
struct ParentHandoff {
    overlay_edges: Vec<pgroles_core::model::MembershipEdge>,
    target_identity: Option<pgroles_core::approval::TargetIdentity>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ResolvedPassword {
    pub(crate) cleartext: String,
    pub(crate) source_version: String,
    /// Set when the password was generated in memory because no Secret exists
    /// yet. The Secret is deliberately not written during planning — it is
    /// materialized only once the plan is about to execute, so a plan that is
    /// never approved leaves no credential behind (#181).
    pub(crate) pending_materialization: Option<PendingGeneratedSecret>,
}

// Manual so `{:?}` can never print the password: the derived form would.
impl std::fmt::Debug for ResolvedPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedPassword")
            .field("cleartext", &"[redacted]")
            .field("source_version", &self.source_version)
            .field("pending_materialization", &self.pending_materialization)
            .finish()
    }
}

impl ResolvedPassword {
    fn existing(cleartext: String, source_version: String) -> Self {
        Self {
            cleartext,
            source_version,
            pending_materialization: None,
        }
    }
}

/// Everything needed to create a generated-password Secret at execution time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingGeneratedSecret {
    pub(crate) role: String,
    pub(crate) spec: crate::crd::GeneratePasswordSpec,
}

/// Parse a duration string like "5m", "1h", "30s", "2h30m".
fn parse_interval(interval: &str) -> Result<Duration, ReconcileError> {
    let interval = interval.trim();
    if interval.is_empty() {
        return Ok(Duration::from_secs(DEFAULT_REQUEUE_SECS));
    }

    let mut total_secs: u64 = 0;
    let mut current_num = String::new();

    for ch in interval.chars() {
        if ch.is_ascii_digit() {
            current_num.push(ch);
        } else {
            let num: u64 = current_num.parse().map_err(|_| {
                ReconcileError::InvalidInterval(
                    interval.to_string(),
                    format!("invalid number before '{ch}'"),
                )
            })?;
            current_num.clear();

            match ch {
                'h' => total_secs += num * 3600,
                'm' => total_secs += num * 60,
                's' => total_secs += num,
                _ => {
                    return Err(ReconcileError::InvalidInterval(
                        interval.to_string(),
                        format!("unknown unit '{ch}'"),
                    ));
                }
            }
        }
    }

    // If there's a trailing number with no unit, treat as seconds.
    if !current_num.is_empty() {
        let num: u64 = current_num.parse().map_err(|_| {
            ReconcileError::InvalidInterval(interval.to_string(), "trailing number".to_string())
        })?;
        total_secs += num;
    }

    if total_secs == 0 {
        return Ok(Duration::from_secs(DEFAULT_REQUEUE_SECS));
    }

    Ok(Duration::from_secs(total_secs))
}

/// Top-level reconcile entry point called by the kube-rs controller runtime.
///
/// Uses the finalizer pattern for cleanup on deletion.
pub async fn reconcile(
    resource: Arc<PostgresPolicy>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, finalizer::Error<ReconcileError>> {
    let api: Api<PostgresPolicy> = Api::namespaced(
        ctx.kube_client.clone(),
        resource.namespace().as_deref().unwrap_or("default"),
    );

    finalizer::finalizer(&api, FINALIZER, resource, |event| async {
        match event {
            FinalizerEvent::Apply(resource) => reconcile_apply(&resource, &ctx).await,
            FinalizerEvent::Cleanup(resource) => reconcile_cleanup(&resource, &ctx).await,
        }
    })
    .await
}

/// Error handler — called when reconcile returns an error.
pub fn error_policy(
    resource: Arc<PostgresPolicy>,
    error: &finalizer::Error<ReconcileError>,
    _ctx: Arc<OperatorContext>,
) -> Action {
    retry_action(&resource, error)
}

fn retry_action(resource: &PostgresPolicy, error: &finalizer::Error<ReconcileError>) -> Action {
    match retry_class(error) {
        RetryClass::LockContention => {
            if let finalizer::Error::ApplyFailed(ReconcileError::LockContention(db, reason)) = error
            {
                tracing::info!(database = %db, reason = %reason, "requeuing due to lock contention");
            }
            requeue_with_jitter()
        }
        RetryClass::Slow => {
            let delay = slow_retry_delay(resource);
            tracing::info!(
                delay_secs = delay.as_secs(),
                error = %error,
                "requeuing on normal interval for non-transient failure"
            );
            Action::requeue(delay)
        }
        RetryClass::CleanupPending => {
            let delay = Duration::from_secs(10);
            tracing::info!(
                delay_secs = delay.as_secs(),
                error = %error,
                "waiting for ephemeral access finalizers"
            );
            Action::requeue(delay)
        }
        RetryClass::Transient => {
            let attempts = next_transient_failure_count(resource);
            let delay = transient_backoff_delay(attempts);
            tracing::warn!(
                attempts,
                delay_secs = delay.as_secs(),
                error = %error,
                "requeuing with exponential backoff after transient failure"
            );
            Action::requeue(delay)
        }
    }
}

/// Compute a requeue delay with jitter for lock contention back-off.
/// Should this reconcile announce `Reconciling` on the status?
///
/// Only when it is a genuinely new attempt. Every exit path strips the
/// condition again (see `set_failure_status` and the success paths), so on a
/// retry of a generation already attempted, announcing it would mutate the
/// status twice per reconcile for no net change. Each mutation is a watch
/// event that re-triggers the reconcile at once, pre-empting the back-off
/// `error_policy` returned — which is how a permanently-failing policy came to
/// spin at ~5 reconciles/second, holding the per-database advisory lock each
/// time and starving every other policy targeting that database.
///
/// A policy with no `Ready` condition has never completed a reconcile, so it
/// announces regardless of generation: that is the first-attempt signal, and
/// it is the case where an operator most wants to see progress.
fn should_announce_reconciling(status: &PostgresPolicyStatus, generation: Option<i64>) -> bool {
    let attempted_this_generation =
        generation.is_some() && status.last_attempted_generation == generation;
    let has_settled_before = status
        .conditions
        .iter()
        .any(|c| c.condition_type == "Ready");
    !(attempted_this_generation && has_settled_before)
}

fn requeue_with_jitter() -> Action {
    let delay = jitter_delay();
    tracing::debug!(delay_secs = delay.as_secs(), "requeue with jitter");
    Action::requeue(delay)
}

/// Compute a jittered delay for lock contention back-off.
///
/// Returns a [`Duration`] in the range
/// `[LOCK_CONTENTION_BASE_SECS, LOCK_CONTENTION_BASE_SECS + LOCK_CONTENTION_JITTER_SECS]`.
fn jitter_delay() -> Duration {
    // Simple jitter: base + pseudo-random portion of the jitter window.
    // We combine subsecond nanos with a hash of the thread ID for better
    // entropy when multiple reconciles hit contention simultaneously.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let thread_entropy = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::thread::current().id().hash(&mut hasher);
        hasher.finish() as u32
    };
    let jitter_secs = ((nanos ^ thread_entropy) as u64) % (LOCK_CONTENTION_JITTER_SECS + 1);
    Duration::from_secs(LOCK_CONTENTION_BASE_SECS + jitter_secs)
}

fn transient_backoff_delay(attempts: u32) -> Duration {
    let exponent = attempts.saturating_sub(1).min(10);
    let base_delay = TRANSIENT_BACKOFF_BASE_SECS
        .saturating_mul(1_u64 << exponent)
        .min(TRANSIENT_BACKOFF_MAX_SECS);
    let remaining_headroom = TRANSIENT_BACKOFF_MAX_SECS.saturating_sub(base_delay);
    let jitter_window = remaining_headroom.min((base_delay / 2).max(1));
    let jitter_secs = if jitter_window == 0 {
        0
    } else {
        pseudo_random_window(jitter_window)
    };
    Duration::from_secs((base_delay + jitter_secs).min(TRANSIENT_BACKOFF_MAX_SECS))
}

fn pseudo_random_window(window_secs: u64) -> u64 {
    if window_secs == 0 {
        return 0;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let thread_entropy = {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        std::thread::current().id().hash(&mut hasher);
        hasher.finish() as u32
    };
    ((nanos ^ thread_entropy) as u64) % (window_secs + 1)
}

fn retry_class(error: &finalizer::Error<ReconcileError>) -> RetryClass {
    match error {
        finalizer::Error::ApplyFailed(reconcile_error) => {
            retry_class_for_reconcile_error(reconcile_error)
        }
        finalizer::Error::CleanupFailed(ReconcileError::PendingEphemeralAccessCleanup(_)) => {
            RetryClass::CleanupPending
        }
        finalizer::Error::CleanupFailed(_)
        | finalizer::Error::AddFinalizer(_)
        | finalizer::Error::RemoveFinalizer(_)
        | finalizer::Error::UnnamedObject
        | finalizer::Error::InvalidFinalizer => RetryClass::Transient,
    }
}

fn retry_class_for_reconcile_error(error: &ReconcileError) -> RetryClass {
    match error {
        ReconcileError::LockContention(_, _) => RetryClass::LockContention,
        // The watch resyncs on its own, so this clears without operator action.
        ReconcileError::RequestIndexNotReady(_) => RetryClass::Transient,
        ReconcileError::PendingEphemeralAccessCleanup(_) => RetryClass::CleanupPending,
        // Waiting out the plan's retry window is exactly the normal interval:
        // requeuing sooner would re-enter the back-off and re-defer.
        ReconcileError::PlanRetryDeferred(_, _)
        | ReconcileError::ManifestExpansion(_)
        | ReconcileError::InvalidInterval(_, _)
        | ReconcileError::InvalidSpec(_)
        | ReconcileError::MissingDatabaseObjects(_)
        | ReconcileError::UnsatisfiableWildcardGrant(_)
        | ReconcileError::ExecutorAuthority(_)
        | ReconcileError::ConflictingPolicy(_)
        | ReconcileError::UnsafeRoleDrops(_)
        | ReconcileError::EmptyPasswordSecret { .. }
        | ReconcileError::NoNamespace
        | ReconcileError::ApprovalDigest(_)
        | ReconcileError::PlanSqlStorage(_) => RetryClass::Slow,
        ReconcileError::PasswordGeneration(err) => {
            if err.is_transient() {
                RetryClass::Transient
            } else {
                RetryClass::Slow
            }
        }
        ReconcileError::Context(context) => match context.as_ref() {
            ContextError::SecretMissing { .. } => RetryClass::Slow,
            ContextError::SecretFetch { .. } => {
                if context.is_secret_fetch_non_transient() {
                    RetryClass::Slow
                } else {
                    RetryClass::Transient
                }
            }
            ContextError::GcpAuthRejected { .. } | ContextError::GcpAuthInvalidResponse { .. } => {
                if context.is_gcp_auth_non_transient() {
                    RetryClass::Slow
                } else {
                    RetryClass::Transient
                }
            }
            ContextError::GcpAuthHttp { .. } => RetryClass::Transient,
            ContextError::DatabaseConnect { .. } => RetryClass::Transient,
            // `SET ROLE "<role>"` failing on a freshly-connected session is
            // a permission/config issue, not a transient connectivity blip.
            ContextError::SetRoleFailed { .. } => RetryClass::Slow,
            ContextError::EmptyResolvedValue { .. }
            | ContextError::InvalidDatabaseUrl { .. }
            | ContextError::InvalidResolvedPort { .. }
            | ContextError::InvalidResolvedSslMode { .. } => RetryClass::Slow,
        },
        ReconcileError::Inspect(error) => {
            if inspect_error_is_non_transient(error) {
                RetryClass::Slow
            } else {
                RetryClass::Transient
            }
        }
        ReconcileError::SqlExec(error) => {
            if sqlx_error_is_non_transient(error) {
                RetryClass::Slow
            } else {
                RetryClass::Transient
            }
        }
        ReconcileError::Kube(_) => RetryClass::Transient,
        // The API server or the path to it is not answering right now; the
        // next reconcile is the retry.
        ReconcileError::ApiStalled(_, _) => RetryClass::Transient,
    }
}

fn inspect_error_is_non_transient(error: &pgroles_inspect::InspectError) -> bool {
    match error {
        pgroles_inspect::InspectError::Database(error) => sqlx_error_is_non_transient(error),
        // A scope the shared snapshot never read: a programming error in the
        // caller, not something a retry can fix.
        pgroles_inspect::InspectError::ScopeNotCovered(_)
        | pgroles_inspect::InspectError::DatabaseTargetMismatch { .. } => true,
    }
}

/// Classification of a database-level SQL error for retry and status reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlErrorKind {
    /// Insufficient privileges (SQLSTATE 42501) — RBAC-style failure,
    /// won't fix itself.
    InsufficientPrivileges,
    /// A referenced schema, relation, function, or object does not exist
    /// (SQLSTATE 3F000, 42P01, 42883, 42704). Typically a policy/environment
    /// mismatch that needs operator action.
    MissingDatabaseObject,
    /// Everything else — retry with exponential backoff.
    Transient,
}

fn classify_sqlx_error(error: &sqlx::Error) -> SqlErrorKind {
    match error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .as_deref()
    {
        Some(SQLSTATE_INSUFFICIENT_PRIVILEGE) => SqlErrorKind::InsufficientPrivileges,
        Some(SQLSTATE_INVALID_SCHEMA_NAME)
        | Some(SQLSTATE_UNDEFINED_TABLE)
        | Some(SQLSTATE_UNDEFINED_FUNCTION)
        | Some(SQLSTATE_UNDEFINED_OBJECT) => SqlErrorKind::MissingDatabaseObject,
        _ => SqlErrorKind::Transient,
    }
}

fn sqlx_error_is_non_transient(error: &sqlx::Error) -> bool {
    !matches!(classify_sqlx_error(error), SqlErrorKind::Transient)
}

fn next_transient_failure_count(resource: &PostgresPolicy) -> u32 {
    resource
        .status
        .as_ref()
        .map(|status| status.transient_failure_count.max(0) as u32)
        .unwrap_or(0)
        .saturating_add(1)
}

fn slow_retry_delay(resource: &PostgresPolicy) -> Duration {
    parse_interval(&resource.spec.interval)
        .unwrap_or_else(|_| Duration::from_secs(DEFAULT_REQUEUE_SECS))
}

/// Collect every schema name referenced by an expanded manifest.
///
/// Covers schema-type grants (where the schema is in `object.name`), grants on
/// objects within a schema (where the schema is in `object.schema`), and
/// default privileges (which always carry a schema).
fn referenced_schema_names(
    expanded: &pgroles_core::manifest::ExpandedManifest,
) -> std::collections::BTreeSet<String> {
    let mut names: std::collections::BTreeSet<String> = expanded
        .schemas
        .iter()
        .map(|schema| schema.name.clone())
        .collect();
    for grant in &expanded.grants {
        if grant.object.object_type == pgroles_core::manifest::ObjectType::Schema
            && let Some(name) = &grant.object.name
        {
            names.insert(name.clone());
        }
        if let Some(schema) = &grant.object.schema {
            names.insert(schema.clone());
        }
    }
    for dp in &expanded.default_privileges {
        if let Some(schema) = &dp.schema {
            names.insert(schema.clone());
        }
        if let Some(spec) = &dp.scope
            && let Some(schema) = &spec.schema
        {
            names.insert(schema.clone());
        }
    }
    names
}

fn declared_schema_names(
    expanded: &pgroles_core::manifest::ExpandedManifest,
) -> std::collections::BTreeSet<String> {
    expanded
        .schemas
        .iter()
        .map(|schema| schema.name.clone())
        .collect()
}

/// Pre-flight check: ensure every schema referenced by the policy exists in
/// the target database. Returns [`ReconcileError::MissingDatabaseObjects`]
/// listing the missing schemas if any are absent.
/// Returns true for PostgreSQL system schemas that always exist but are
/// excluded from [`pgroles_inspect::fetch_existing_schemas`].
fn is_system_schema(name: &str) -> bool {
    name.starts_with("pg_") || name == "information_schema"
}

/// Pre-flight check: ensure every schema referenced by the policy exists in
/// the target database. Returns [`ReconcileError::MissingDatabaseObjects`]
/// listing the missing schemas if any are absent.
///
/// System schemas (`pg_*`, `information_schema`) are excluded from the check
/// since they always exist but are filtered out of the inspect query.
pub(crate) async fn validate_referenced_schemas_exist(
    pool: &sqlx::PgPool,
    expanded: &pgroles_core::manifest::ExpandedManifest,
) -> Result<(), ReconcileError> {
    let referenced = externally_required_schema_names(expanded);
    if referenced.is_empty() {
        return Ok(());
    }
    let existing = pgroles_inspect::fetch_existing_schemas(pool).await?;
    let missing: Vec<String> = referenced
        .into_iter()
        .filter(|name| !existing.contains(name))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        let formatted = missing
            .iter()
            .map(|name| format!("schema \"{name}\""))
            .collect::<Vec<_>>()
            .join(", ");
        Err(ReconcileError::MissingDatabaseObjects(formatted))
    }
}

fn externally_required_schema_names(
    expanded: &pgroles_core::manifest::ExpandedManifest,
) -> std::collections::BTreeSet<String> {
    let declared = declared_schema_names(expanded);
    referenced_schema_names(expanded)
        .into_iter()
        .filter(|name| !is_system_schema(name) && !declared.contains(name))
        .collect()
}

/// Apply reconciliation — the main "ensure desired state" logic.
///
/// The in-process per-database lock is acquired *inside* [`reconcile_apply_inner`],
/// after the connection probe succeeds. That way a bad-credentials,
/// secret-fetch, or spec-validation failure produces an ordinary error which
/// flows through the status-updating path below, instead of competing for
/// the lock with parallel reconciles for the same `database_identity`. With
/// three policies sharing one secret, a Secret rotation to bad credentials
/// would otherwise serialize them on the lock — each holding it for the full
/// `POOL_ACQUIRE_TIMEOUT_SECS` worth of pool-timeout — and an unlucky policy
/// could spend tens of seconds in lock-contention requeues without ever
/// updating its status condition (lock contention is silent by design).
async fn reconcile_apply(
    resource: &PostgresPolicy,
    ctx: &OperatorContext,
) -> Result<Action, ReconcileError> {
    let reconcile_guard = ctx.observability.start_reconcile();
    let requested_reconcile_at = requested_reconcile_at(resource);

    let namespace = resource.namespace().ok_or(ReconcileError::NoNamespace)?;
    let identity = DatabaseIdentity::from_connection(&namespace, &resource.spec.connection);

    match reconcile_apply_inner(resource, ctx, &identity).await {
        Ok((action, outcome)) => {
            if outcome.marks_requested_reconcile_handled() {
                mark_requested_reconcile_handled(ctx, resource, requested_reconcile_at.as_deref())
                    .await?;
            }
            reconcile_guard.record_result(outcome.result(), outcome.reason());
            Ok(action)
        }
        Err(ReconcileError::LockContention(db, reason)) => {
            // Lock contention is expected during normal multi-replica operation.
            // Re-raise without setting Degraded status to avoid false alarms.
            ctx.observability.record_lock_contention();
            reconcile_guard.record_result(
                ReconcileOutcome::LockContention.result(),
                ReconcileOutcome::LockContention.reason(),
            );
            tracing::info!(database = %db, %reason, "lock contention — will requeue");
            Err(ReconcileError::LockContention(db, reason))
        }
        Err(err) => {
            let error_message = err.to_string();
            let error_reason = err.reason();
            let is_transient_failure =
                retry_class_for_reconcile_error(&err) == RetryClass::Transient;
            // Unsatisfiable wildcards would regenerate the same impossible plan.
            // Other failures keep any plan ref so the same plan can be retried.
            let clear_current_plan_ref =
                matches!(&err, ReconcileError::UnsatisfiableWildcardGrant(_));
            match error_reason {
                "DatabaseConnectionFailed" => {
                    ctx.observability.record_database_connection_failure()
                }
                "InvalidSpec" => ctx.observability.record_invalid_spec(),
                "ConflictingPolicy" => ctx.observability.record_policy_conflict(),
                "ApplyFailed"
                | "MissingDatabaseObject"
                | "UnsatisfiableWildcardGrant"
                | "ExecutorAuthority" => ctx.observability.record_apply_result("error"),
                _ => {}
            }
            reconcile_guard.record_result("error", error_reason);
            if let Err(status_err) = update_status(ctx, resource, |status| {
                mark_reconcile_failure_status(
                    status,
                    error_reason,
                    &error_message,
                    is_transient_failure,
                    clear_current_plan_ref,
                );
            })
            .await
            {
                tracing::warn!(%status_err, "failed to update degraded status");
            }
            Err(err)
        }
    }
}

fn requested_reconcile_at(resource: &PostgresPolicy) -> Option<String> {
    resource
        .annotations()
        .get(REQUESTED_RECONCILE_ANNOTATION)
        .cloned()
}

async fn mark_requested_reconcile_handled(
    ctx: &OperatorContext,
    resource: &PostgresPolicy,
    requested_reconcile_at: Option<&str>,
) -> Result<(), ReconcileError> {
    let Some(requested_reconcile_at) = requested_reconcile_at else {
        return Ok(());
    };

    update_status(ctx, resource, |status| {
        status.last_handled_reconcile_at = Some(requested_reconcile_at.to_string());
    })
    .await
}

fn mark_reconcile_failure_status(
    status: &mut PostgresPolicyStatus,
    error_reason: &str,
    error_message: &str,
    is_transient_failure: bool,
    clear_current_plan_ref: bool,
) {
    status.set_condition(ready_condition(false, error_reason, error_message));
    status.set_condition(degraded_condition(error_reason, error_message));
    status.conditions.retain(|c| {
        c.condition_type != "Reconciling"
            && c.condition_type != "Paused"
            && c.condition_type != "Drifted"
            && c.condition_type != "Conflict"
    });
    status.change_summary = None;
    if clear_current_plan_ref {
        status.current_plan_ref = None;
    }
    status.last_error = Some(error_message.to_string());
    if is_transient_failure {
        status.transient_failure_count += 1;
    } else {
        status.transient_failure_count = 0;
    }
}

async fn reconcile_apply_inner(
    resource: &PostgresPolicy,
    ctx: &OperatorContext,
    identity: &DatabaseIdentity,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    let name = resource.name_any();
    let namespace = resource.namespace().ok_or(ReconcileError::NoNamespace)?;

    let spec = &resource.spec;
    let requeue_interval = parse_interval(&spec.interval)?;
    let generation = resource.metadata.generation;

    // If suspended, just requeue without doing anything.
    if spec.suspend {
        update_status(ctx, resource, |status| {
            status.set_condition(paused_condition("Reconciliation suspended by spec"));
            status.set_condition(ready_condition(
                false,
                "Suspended",
                "Reconciliation suspended by spec",
            ));
            status
                .conditions
                .retain(|c| c.condition_type != "Reconciling" && c.condition_type != "Drifted");
            status.last_attempted_generation = generation;
            status.last_error = None;
            status.transient_failure_count = 0;
        })
        .await?;
        info!(name, namespace, "reconciliation suspended, requeuing");
        return Ok((
            Action::requeue(requeue_interval),
            ReconcileOutcome::Suspended,
        ));
    }

    info!(name, namespace, "starting reconciliation");

    // Reported here, before any fallible work, so a policy that relies on the
    // deprecated inference is counted even when this reconcile later fails on
    // an unrelated problem — otherwise the remaining exposure looks smaller
    // than it is. The condition itself is applied in `update_status`.
    if resource.spec.approval.is_none() {
        let inferred = match resource.spec.effective_approval() {
            crate::crd::ApprovalMode::Auto => "auto",
            crate::crd::ApprovalMode::Manual => "manual",
        };
        tracing::warn!(
            name,
            namespace,
            inferred,
            "spec.approval is not set and is being inferred from spec.mode; this inference is \
             deprecated and will become an error in a future release"
        );
        ctx.observability.record_deprecated_approval_unset(inferred);
    }
    if resource.spec.mode.is_deprecated_spelling() {
        tracing::warn!(
            name,
            namespace,
            "spec.mode is `plan`, the deprecated spelling of `observe`; behaviour is identical, \
             and a future release removes the value — change the manifest to `mode: observe`"
        );
        ctx.observability.record_deprecated_mode_plan();
    }

    // Update status to "Reconciling".
    // Note: do NOT clear last_error here — it should persist until a successful
    // reconcile clears it. Clearing on every retry cycle would race with the
    // error handler that sets it.
    update_status(ctx, resource, |status| {
        if should_announce_reconciling(status, generation) {
            status.set_condition(reconciling_condition("Reconciliation in progress"));
        }
        status
            .conditions
            .retain(|c| c.condition_type != "Paused" && c.condition_type != "Drifted");
        status.last_attempted_generation = generation;
    })
    .await?;

    // Breadcrumbs across the pre-lock phase. Every step between here and the
    // in-process lock is a network call, and without them a stall in any of
    // them looks identical in the log: "starting reconciliation" and then
    // nothing.
    tracing::debug!(name, namespace, "status marked Reconciling");

    spec.validate_connection_spec()
        .map_err(|err| ReconcileError::InvalidSpec(err.to_string()))?;
    spec.validate_password_specs(&name)
        .map_err(|err| ReconcileError::InvalidSpec(err.to_string()))?;

    let ownership = spec.ownership_claims()?;
    update_status(ctx, resource, |status| {
        status.managed_database_identity = Some(identity.as_str().to_string());
        status.owned_roles = ownership.roles.iter().cloned().collect();
        status.owned_schemas = ownership.schemas.iter().cloned().collect();
    })
    .await?;

    tracing::debug!(name, namespace, "ownership claims recorded");

    if let Some(conflict_message) =
        detect_policy_conflict(ctx, resource, identity, &ownership).await?
    {
        update_status(ctx, resource, |status| {
            status.set_condition(ready_condition(
                false,
                "ConflictingPolicy",
                &conflict_message,
            ));
            status.set_condition(conflict_condition("ConflictingPolicy", &conflict_message));
            status.set_condition(degraded_condition("ConflictingPolicy", &conflict_message));
            status
                .conditions
                .retain(|c| c.condition_type != "Reconciling" && c.condition_type != "Drifted");
            status.change_summary = None;
            status.last_error = Some(conflict_message.clone());
            status.transient_failure_count = 0;
        })
        .await?;
        ctx.observability.record_policy_conflict();
        info!(name, namespace, %conflict_message, "reconciliation blocked by conflicting policy");
        return Ok((
            Action::requeue(requeue_interval),
            ReconcileOutcome::Conflict,
        ));
    }

    tracing::debug!(name, namespace, "no conflicting policy");

    // 1. Convert CRD spec to core manifest.
    let manifest = spec.to_policy_manifest();

    // 2. Expand the manifest (profiles × schemas → concrete roles/grants).
    let expanded = pgroles_core::manifest::expand_manifest(&manifest)?;

    // 3. Build desired RoleGraph from expanded manifest.
    let default_owner = manifest.default_owner.as_deref();
    if let Some(owner) = default_owner
        && !expanded.roles.iter().any(|role| role.name == owner)
    {
        tracing::warn!(
            name,
            namespace,
            "default_owner {owner} is not declared under roles; it will not be inspected or \
             converged, but every schema binding without an explicit owner resolves to it"
        );
    }
    let desired = pgroles_core::model::RoleGraph::from_expanded(&expanded, default_owner)?;

    // 4. Get a database pool.
    //
    // This is the connection probe: a bad URL, refused TCP connection, or
    // failed authentication surfaces here as `ContextError::DatabaseConnect`,
    // which the outer error handler in `reconcile_apply` translates into a
    // `Ready=False/DatabaseConnectionFailed` status update. We do this BEFORE
    // taking the in-process lock so multiple policies sharing the same
    // `database_identity` can all observe a connection failure in parallel,
    // instead of serializing on the lock and starving each other under
    // sustained bad-credentials conditions.
    let pool = ctx
        .get_or_create_pool(&namespace, &spec.connection)
        .await
        .map_err(Box::new)?;

    tracing::debug!(name, namespace, "database pool ready");

    // 5. Acquire the in-process per-database lock for the DDL phase.
    //
    // The lock serializes inspect+diff+apply against a single
    // `database_identity` within this replica, so two reconciles can't
    // compute conflicting plans and stack DDL on top of each other. It is
    // explicitly NOT held during the connection-probe phase above, since
    // that work is idempotent and side-effect-free against the database.
    //
    // `_db_lock` must outlive the advisory lock and `apply_under_lock`
    // call below; it is dropped at the end of this function.
    let _db_lock = match ctx.try_lock_database(identity.as_str()).await {
        Some(guard) => guard,
        None => {
            return Err(ReconcileError::LockContention(
                identity.as_str().to_string(),
                "in-process lock held by another reconcile".to_string(),
            ));
        }
    };

    // 6. Acquire PostgreSQL advisory lock for cross-replica safety.
    let advisory_lock = match crate::advisory::try_acquire(&pool, identity.as_str()).await {
        Ok(Some(lock)) => lock,
        Ok(None) => {
            return Err(ReconcileError::LockContention(
                identity.as_str().to_string(),
                "PostgreSQL advisory lock held by another session".to_string(),
            ));
        }
        Err(err) => {
            tracing::warn!(%err, "failed to acquire advisory lock — treating as connection error");
            return Err(ReconcileError::SqlExec(err));
        }
    };

    // Wrap the remaining work so the advisory lock is released on all paths.
    let mut handoff = ParentHandoff::default();
    let result = apply_under_lock(
        resource,
        ctx,
        &pool,
        &manifest,
        &expanded,
        &desired,
        generation,
        requeue_interval,
        &name,
        &namespace,
        identity,
        &mut handoff,
    )
    .await;

    // Candidates are planned here: after the active policy's own enforcement
    // or planning has completed, still inside both of its locks, against the
    // post-enforcement state rather than the drift the policy just removed.
    // A candidate is a proposal, so nothing it does may break enforcement —
    // failures are recorded on the candidate and swallowed here.
    if let Ok((_, outcome)) = &result
        && let Some(target_identity) = handoff.target_identity.as_ref()
    {
        let converged = matches!(
            outcome,
            ReconcileOutcome::Reconciled | ReconcileOutcome::Planned
        );
        // An API failure here is not "no plan": treating it as one would open
        // the gate while the parent may in fact hold an actionable plan, and
        // the candidate would be planned against a state the database is not
        // in yet. Skip candidate planning for this cycle instead.
        match crate::plan::get_current_actionable_plan(&ctx.kube_client, resource).await {
            Ok(actionable) => {
                let planning = crate::candidate::CandidatePlanning {
                    pool: &pool,
                    identity,
                    target_identity,
                    overlay_edges: &handoff.overlay_edges,
                    gate: crate::candidate::parent_gate(converged, actionable.is_some()),
                };
                if let Err(err) =
                    crate::candidate::reconcile_candidates(ctx, resource, &planning).await
                {
                    tracing::warn!(name, namespace, %err, "candidate planning failed");
                }
            }
            Err(err) => {
                tracing::warn!(
                    name,
                    namespace,
                    %err,
                    "could not read the policy's actionable plan; skipping candidate planning this cycle"
                );
            }
        }
    }

    // Release advisory lock (always, even on error).
    advisory_lock.release().await;

    crate::plan::cleanup_old_plans_best_effort(&ctx.kube_client, resource, ctx.plan_retention)
        .await;

    result
}

/// The membership edges an ephemeral overlay contributed.
///
/// Everything the composition added that the policy does not declare. This is
/// the overlay half of the candidate overlay-overlap rule (ADR-001 Decision 6),
/// and it is a set difference rather than a second read of the requests so that
/// the pairs a candidate is compared against are exactly the edges that entered
/// the graph the policy just enforced.
fn overlay_edges(
    declared: &pgroles_core::model::RoleGraph,
    effective: &pgroles_core::model::RoleGraph,
) -> Vec<pgroles_core::model::MembershipEdge> {
    effective
        .memberships
        .difference(&declared.memberships)
        .cloned()
        .collect()
}

/// Resolve both halves of the target's identity.
///
/// The physical half is read from the connection the reconcile already holds;
/// the logical half is resolved from the connection Secret, which is exactly
/// the fingerprint the ephemeral path computes and covers URL-mode
/// connections whose Kubernetes reference names only a Secret and key.
async fn resolve_target_identity(
    ctx: &OperatorContext,
    pool: &sqlx::PgPool,
    namespace: &str,
    resource: &PostgresPolicy,
) -> Result<pgroles_core::approval::TargetIdentity, ReconcileError> {
    let physical = pgroles_inspect::detect_system_identifier(pool).await?;
    let logical = ctx
        .resolve_database_target_fingerprint(namespace, &resource.spec.connection)
        .await
        .map_err(Box::new)?;
    Ok(pgroles_core::approval::TargetIdentity {
        physical,
        logical: Some(logical),
    })
}

/// Execute the inspect/diff/apply cycle while both locks are held.
///
/// Extracted to keep `reconcile_apply_inner` focused on lock acquisition.
#[allow(clippy::too_many_arguments)]
async fn apply_under_lock(
    resource: &PostgresPolicy,
    ctx: &OperatorContext,
    pool: &sqlx::PgPool,
    manifest: &pgroles_core::manifest::PolicyManifest,
    expanded: &pgroles_core::manifest::ExpandedManifest,
    desired: &pgroles_core::model::RoleGraph,
    generation: Option<i64>,
    requeue_interval: Duration,
    name: &str,
    namespace: &str,
    identity: &DatabaseIdentity,
    handoff: &mut ParentHandoff,
) -> Result<(Action, ReconcileOutcome), ReconcileError> {
    // 5a. Resolve the identity of the database actually on the other end of
    // the connection, under the lock and against the same pool everything
    // else uses. Both halves are bound into the approval digest, so an
    // approval made against one server cannot execute against another even
    // though the Kubernetes reference is unchanged.
    let target_identity = resolve_target_identity(ctx, pool, namespace, resource).await?;
    handoff.target_identity = Some(target_identity.clone());
    if resource.spec.connection.requires_physical_identity() && !target_identity.has_physical() {
        let reason = pgroles_core::approval::TargetIdentityReason::PhysicalIdentityRequired;
        let message = format!(
            "{} Reconciliation is blocked until the identifier is readable, or \
             connection.requirePhysicalIdentity is cleared.",
            reason.message()
        );
        emit_policy_warning(
            ctx,
            resource,
            reason.as_str(),
            "TargetIdentity",
            message.clone(),
        )
        .await;
        update_status(ctx, resource, |status| {
            status.set_condition(ready_condition(false, reason.as_str(), &message));
            status.set_condition(crate::crd::target_identity_blocked_condition(
                reason.as_str(),
                &message,
            ));
            status.set_condition(degraded_condition(reason.as_str(), &message));
            status
                .conditions
                .retain(|c| c.condition_type != "Reconciling" && c.condition_type != "Drifted");
            status.last_attempted_generation = generation;
            status.last_error = Some(message.clone());
            status.transient_failure_count = 0;
        })
        .await?;
        return Ok((
            Action::requeue(requeue_interval),
            ReconcileOutcome::TargetIdentityBlocked,
        ));
    }

    // 5b. Recover stuck Applying plans (operator may have crashed mid-apply).
    if let Some(stuck_plan) =
        crate::plan::get_plan_by_phase(&ctx.kube_client, resource, crate::crd::PlanPhase::Applying)
            .await?
    {
        let applying_since_secs = stuck_plan
            .status
            .as_ref()
            .and_then(|s| s.applying_since.as_deref())
            .and_then(parse_rfc3339_to_epoch_secs);
        if let Some(since_secs) = applying_since_secs {
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let elapsed_secs = now_secs.saturating_sub(since_secs);
            let stuck_threshold_secs = 5 * 60; // 5 minutes
            if elapsed_secs > stuck_threshold_secs {
                tracing::warn!(
                    plan = %stuck_plan.name_any(),
                    elapsed_secs,
                    "detected stuck Applying plan — marking as Failed"
                );
                crate::plan::mark_plan_failed(
                    &ctx.kube_client,
                    &stuck_plan,
                    "execution interrupted: operator restarted during apply",
                )
                .await?;
            }
        }
    }

    // Ephemeral overlays are deliberately resolved only after both database
    // locks are held. Resolving them before lock acquisition would allow an
    // activation or expiry transition to change membership ownership while an
    // ordinary reconcile waits for the lock.
    let mut effective_desired = desired.clone();
    let ephemeral_roles =
        crate::ephemeral::compose_effective_graph(ctx, resource, &mut effective_desired).await?;
    // The overlay itself, as edges: everything the composition added that the
    // policy does not declare. This is the input to the candidate
    // overlay-overlap rule (ADR-001 Decision 6).
    handoff.overlay_edges = overlay_edges(desired, &effective_desired);

    // 6. Inspect current state from the database.
    let has_database_grants = expanded
        .grants
        .iter()
        .any(|g| g.object.object_type == pgroles_core::manifest::ObjectType::Database);
    let inspect_config =
        pgroles_inspect::InspectConfig::from_expanded(expanded, has_database_grants)
            .with_additional_roles(
                manifest
                    .retirements
                    .iter()
                    .map(|retirement| retirement.role.clone()),
            )
            .with_additional_roles(ephemeral_roles);
    let inspection = pgroles_inspect::inspect_with_diagnostics(pool, &inspect_config).await?;
    ctx.observability.record_inspection(&inspection.stats);
    // Unsatisfiable wildcard grants mean the desired state cannot be reliably
    // computed, so they block reconciliation.
    if let Some(message) = inspection.diagnostics.blocking_message() {
        return Err(ReconcileError::UnsatisfiableWildcardGrant(message));
    }
    // Column-level grants are advisory only — pgroles doesn't manage them, but
    // reconciliation should still proceed. Log a warning instead of failing.
    for diagnostic in &inspection.diagnostics.column_level_grants {
        tracing::warn!(
            schema = %diagnostic.schema,
            relation = %diagnostic.relation,
            grantee = %diagnostic.grantee,
            columns = ?diagnostic.columns,
            "detected column-level grant pgroles does not manage"
        );
    }
    let current = inspection.graph;

    // 6b. Pre-flight: validate that every schema referenced by the policy
    // exists in the target database. This turns a mid-transaction
    // `schema "X" does not exist` failure into a clear spec/environment
    // mismatch error before we issue any DDL.
    validate_referenced_schemas_exist(pool, expanded).await?;

    // 7. Compute diff, filter by reconciliation mode, then inject password
    // changes resolved from Kubernetes Secrets.
    let reconciliation_mode: pgroles_core::diff::ReconciliationMode =
        resource.spec.reconciliation_mode.into();
    tracing::info!(%reconciliation_mode, "reconciliation mode");
    if pgroles_core::diff::additive_ignores_absence_assertions(
        &effective_desired,
        reconciliation_mode,
    ) {
        tracing::warn!(
            name,
            namespace,
            "additive reconciliation ignores every `ensure: absent` assertion; \
             use adopt or authoritative mode to enforce absence"
        );
    }
    let mut changes = pgroles_core::diff::filter_changes(
        pgroles_core::diff::apply_role_retirements(
            pgroles_core::diff::diff(&current, &effective_desired),
            &manifest.retirements,
        ),
        reconciliation_mode,
    );
    changes = pgroles_core::diff::filter_external_role_changes(changes, &expanded.roles);

    let resolved_passwords = resolve_passwords_from_secrets(ctx, resource, namespace).await?;
    let (password_changes, mut applied_password_source_versions) =
        select_password_changes(&changes, &resolved_passwords, resource.status.as_ref());
    if !password_changes.is_empty() {
        changes = pgroles_core::diff::inject_password_changes(changes, &password_changes);
    }
    let dropped_roles: Vec<String> = changes
        .iter()
        .filter_map(|change| match change {
            pgroles_core::diff::Change::DropRole { name } => Some(name.clone()),
            _ => None,
        })
        .collect();
    let drop_safety = pgroles_inspect::inspect_drop_role_safety(pool, &dropped_roles)
        .await?
        .assess(&manifest.retirements);
    if !drop_safety.warnings.is_empty() {
        tracing::info!(warnings = %drop_safety.warnings, "role-drop cleanup warnings");
    }
    if drop_safety.has_blockers() {
        return Err(ReconcileError::UnsafeRoleDrops(
            drop_safety.blockers.to_string(),
        ));
    }

    // Planned default-privilege changes and PUBLIC revokes need owner
    // authority the executor may lack; a PUBLIC revoke without it silently
    // no-ops and the controller would flap.
    //
    // Only executing is blocked. Producing and reviewing a plan needs no
    // authority, and failing here instead would leave an operator with a
    // Degraded policy and nothing to look at.
    let authority_issues =
        pgroles_inspect::preflight_authority_issues(pool, &changes, &current).await?;
    let authority_block: Option<String> = if authority_issues.is_empty() {
        None
    } else {
        let message = authority_issues
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        tracing::warn!(
            name,
            namespace,
            issues = %message,
            "executor lacks the authority to apply these changes; planning continues, execution is blocked"
        );
        Some(message)
    };

    let summary = summarize_changes(&changes);
    let sql_ctx = detect_sql_context(pool, &inspect_config).await?;

    let effective_approval = resource.spec.effective_approval();

    // Is this reconcile the promotion of a reviewed candidate? Recognition is
    // by content digest, computed over exactly the same canonical form a
    // candidate's digest uses, and it runs here — under both locks, on the
    // state just inspected — so that the plan it may hand back is checked
    // against fresh effects.
    //
    // A failure to look candidates up degrades to the ordinary flow rather
    // than failing the reconcile: the ordinary flow can only ever execute a
    // plan this policy owns and a human approved, so degrading cannot execute
    // anything unreviewed — while failing closed here would take enforcement
    // down whenever the candidate CRD is unavailable.
    let content_digest = resource.spec.content_digest();
    let promoted_plan = match crate::promotion::recognize(ctx, resource, &content_digest).await {
        Ok(plan) => plan,
        Err(err) => {
            tracing::warn!(
                name,
                namespace,
                %err,
                "could not evaluate candidate promotion; continuing with the ordinary flow"
            );
            None
        }
    };

    if resource.spec.mode.never_executes() {
        let drift_detected = !changes.is_empty();
        let ready_message = if drift_detected {
            format!("Plan computed; {} change(s) pending", summary.total)
        } else {
            "Plan computed; database already matches desired state".to_string()
        };
        let drift_reason = if drift_detected {
            "DriftDetected"
        } else {
            "InSync"
        };
        let drift_message = if drift_detected {
            format!("{} planned change(s) pending review", summary.total)
        } else {
            "No pending changes".to_string()
        };

        ctx.observability
            .record_plan_result(if drift_detected { "drift" } else { "clean" });
        ctx.observability
            .record_planned_changes(summary.total.max(0) as usize);

        // Create a PostgresPolicyPlan resource for changes (if any).
        let mut plan_ref_name = None;
        // Observe mode used to only ever *set* this reference. When drift went
        // away out of band the pending plan stayed Pending and the reference
        // stayed pointing at it, while the policy reported InSync beside it.
        let previous_plan_ref = resource
            .status
            .as_ref()
            .and_then(|status| status.current_plan_ref.clone());
        // Tracks a plan that someone approved even though this policy never
        // executes, so the pointless approval is reported rather than ignored.
        let mut ignored_approval_plan = None;
        if drift_detected {
            let creation_result = crate::plan::create_or_update_plan(
                &ctx.kube_client,
                resource,
                &changes,
                &sql_ctx,
                &inspect_config,
                resource.spec.reconciliation_mode,
                identity.as_str(),
                &target_identity,
                &summary,
                &applied_password_source_versions,
                ctx.plan_retention,
                None,
            )
            .await?;
            let plan_name = creation_result.plan_name().to_string();

            let plans_api: Api<PostgresPolicyPlan> =
                Api::namespaced(ctx.kube_client.clone(), namespace);
            let plan = plans_api.get(&plan_name).await?;

            // Only emit PlanCreated event for genuinely new plans, not dedup hits.
            if creation_result.is_created() {
                emit_plan_event(
                    ctx,
                    resource,
                    &plan,
                    PlanEventType::Created {
                        change_count: summary.total,
                    },
                )
                .await;
            }

            // Observe mode returns without ever consulting spec.approval, so an
            // approval annotation here is inert. Left unreported it looks like
            // the operator is stuck rather than working as designed.
            if matches!(
                crate::plan::check_plan_approval(&plan),
                crate::plan::PlanApprovalState::Approved
            ) {
                tracing::warn!(
                    name,
                    namespace,
                    plan = %plan_name,
                    "plan is approved but spec.mode is `observe`; approval has no effect and no SQL \
                     will run"
                );
                ignored_approval_plan = Some(plan_name.clone());
            }

            crate::plan::update_policy_plan_ref(&ctx.kube_client, resource, &plan_name).await?;

            plan_ref_name = Some(plan_name);
        }

        update_status(ctx, resource, |status| {
            match &ignored_approval_plan {
                Some(plan) => {
                    status.set_condition(crate::crd::approval_ignored_condition(plan));
                }
                None => status
                    .conditions
                    .retain(|c| c.condition_type != crate::crd::CONDITION_APPROVAL_IGNORED),
            }
            status.set_condition(ready_condition(true, "Planned", &ready_message));
            status.set_condition(drifted_condition(
                drift_detected,
                drift_reason,
                &drift_message,
            ));
            status.conditions.retain(|c| {
                c.condition_type != "Reconciling"
                    && c.condition_type != "Degraded"
                    && c.condition_type != "Conflict"
                    && c.condition_type != "Paused"
                    && c.condition_type != crate::crd::CONDITION_TARGET_IDENTITY_BLOCKED
            });
            status.observed_generation = generation;
            status.last_attempted_generation = generation;
            status.last_successful_reconcile_time = Some(crate::crd::now_rfc3339());
            status.change_summary = Some(summary.clone());
            status.last_reconcile_mode = Some(PolicyMode::Observe);
            status.last_error = None;
            status.transient_failure_count = 0;
            // Cleared, not left alone, when there is no drift: a reference is
            // a claim that a plan describes outstanding work, and with nothing
            // outstanding there is no such plan.
            status.current_plan_ref =
                plan_ref_name
                    .as_ref()
                    .map(|plan_name| crate::crd::PlanReference {
                        name: plan_name.clone(),
                    });
        })
        .await?;

        // Retire the plan the cleared reference pointed at. Ordered after the
        // status write so a crash in between leaves a Pending plan the next
        // reconcile finds and clears again, never a reference to nothing.
        if !drift_detected {
            supersede_referenced_plan_if_pending(ctx, resource, previous_plan_ref.as_ref()).await;
        }

        info!(
            name,
            namespace,
            total = summary.total,
            drift_detected,
            "plan reconciliation complete"
        );
        return Ok((Action::requeue(requeue_interval), ReconcileOutcome::Planned));
    }

    // Apply mode — behavior depends on effective approval mode.
    match effective_approval {
        crate::crd::ApprovalMode::Auto => {
            // Auto-approval: create plan -> immediately execute -> update status.
            // This wraps the existing apply behavior in the plan lifecycle.
            if !changes.is_empty() {
                let creation_result = crate::plan::create_or_update_plan(
                    &ctx.kube_client,
                    resource,
                    &changes,
                    &sql_ctx,
                    &inspect_config,
                    resource.spec.reconciliation_mode,
                    identity.as_str(),
                    &target_identity,
                    &summary,
                    &applied_password_source_versions,
                    ctx.plan_retention,
                    None,
                )
                .await?;
                let plan_name = creation_result.plan_name().to_string();

                // Stop before the first write when the plan handed back is one
                // that failed moments ago. Deferring inside `execute_plan` is
                // too late: `mark_plan_approved` and the apply-started event
                // both write to the plan first, and the controller wakes on
                // its own plans, so each write schedules the next reconcile.
                // A back-off that still writes is only a slower spin.
                if creation_result.is_failed_backoff() {
                    let recorded =
                        crate::plan::recorded_plan_failure(&ctx.kube_client, namespace, &plan_name)
                            .await;
                    info!(
                        name,
                        namespace,
                        plan = %plan_name,
                        "plan failed recently, deferring retry to the policy interval"
                    );
                    return Err(ReconcileError::PlanRetryDeferred(plan_name, recorded));
                }

                // Fetch the plan, mark it approved, and execute it.
                let plans_api: Api<PostgresPolicyPlan> =
                    Api::namespaced(ctx.kube_client.clone(), namespace);
                let plan = plans_api.get(&plan_name).await?;

                if creation_result.is_created() {
                    emit_plan_event(
                        ctx,
                        resource,
                        &plan,
                        PlanEventType::Created {
                            change_count: summary.total,
                        },
                    )
                    .await;
                }

                crate::plan::mark_plan_approved(
                    &ctx.kube_client,
                    &plan,
                    "AutoApproved",
                    "Plan auto-approved by policy approval mode",
                )
                .await?;

                // Re-fetch after approval status update.
                let plan = plans_api.get(&plan_name).await?;
                emit_plan_event(ctx, resource, &plan, PlanEventType::Approved).await;

                // The plan exists and is reviewable; this is the point past
                // which it would execute, so this is where missing authority
                // stops it.
                if let Some(message) = &authority_block {
                    return Err(ReconcileError::ExecutorAuthority(message.clone()));
                }

                emit_plan_event(ctx, resource, &plan, PlanEventType::ApplyStarted).await;

                // Generated Secrets are created here, after approval and before
                // any SQL runs. A failure aborts the apply with no DDL issued.
                if let Err(err) = materialize_pending_generated_secrets(
                    ctx,
                    resource,
                    namespace,
                    &resolved_passwords,
                    &mut changes,
                    &mut applied_password_source_versions,
                )
                .await
                {
                    let message = err.to_string();
                    if let Err(status_err) =
                        crate::plan::mark_plan_failed(&ctx.kube_client, &plan, &message).await
                    {
                        tracing::warn!(plan = %plan_name, %status_err, "failed to mark plan Failed");
                    }
                    emit_plan_event(
                        ctx,
                        resource,
                        &plan,
                        PlanEventType::ApplyFailed {
                            error: message.clone(),
                        },
                    )
                    .await;
                    return Err(err);
                }

                match crate::plan::execute_plan(&ctx.kube_client, &plan, pool, &sql_ctx, &changes)
                    .await
                {
                    Ok(()) => {
                        emit_plan_event(ctx, resource, &plan, PlanEventType::ApplySucceeded).await;
                    }
                    Err(err) => {
                        emit_plan_event(
                            ctx,
                            resource,
                            &plan,
                            PlanEventType::ApplyFailed {
                                error: err.to_string(),
                            },
                        )
                        .await;
                        return Err(err);
                    }
                }

                ctx.observability.record_apply_result("success");

                crate::plan::update_policy_plan_ref(&ctx.kube_client, resource, &plan_name).await?;

                info!(
                    name,
                    namespace,
                    total = summary.total,
                    plan = %plan_name,
                    "auto-approved plan applied"
                );
            } else {
                info!(name, namespace, "no changes needed");
            }

            // The database now holds this content, however it got there — an
            // auto-approved apply, or nothing to do because it was already
            // converged. Either way a candidate proposing exactly this content
            // has been promoted. Under `approval: auto` the gate is trivially
            // satisfied, and this is the whole of promotion's effect.
            record_promotion(ctx, resource, &content_digest).await;

            // Update status to Ready.
            update_status(ctx, resource, |status| {
                status.set_condition(ready_condition(true, "Reconciled", "All changes applied"));
                status.set_condition(drifted_condition(false, "InSync", "No pending changes"));
                status.conditions.retain(|c| {
                    c.condition_type != "Reconciling"
                        && c.condition_type != "Degraded"
                        && c.condition_type != "Conflict"
                        && c.condition_type != "Paused"
                        && c.condition_type != crate::crd::CONDITION_TARGET_IDENTITY_BLOCKED
                });
                status.observed_generation = generation;
                status.last_attempted_generation = generation;
                status.last_successful_reconcile_time = Some(crate::crd::now_rfc3339());
                status.change_summary = Some(summary);
                status.last_reconcile_mode = Some(PolicyMode::Apply);
                status.last_error = None;
                status.applied_password_source_versions = applied_password_source_versions;
                status.transient_failure_count = 0;
            })
            .await?;

            Ok((
                Action::requeue(requeue_interval),
                ReconcileOutcome::Reconciled,
            ))
        }
        crate::crd::ApprovalMode::Manual => {
            // Manual approval: check for an existing approved plan, or create one.

            // First, check if there is a current pending plan that has been
            // approved — or, when this reconcile is the promotion of an
            // approved candidate, that candidate's plan, which *is* this
            // policy's plan for this transition. Adopting it rather than
            // minting an approval on a fresh plan is what keeps promotion from
            // adding a trusted step: the plan below carries the human decision,
            // the `decidedBy`, the approved change digest and the bound target
            // identity, and it goes through the identical verification.
            let current_plan = match promoted_plan.clone() {
                Some(plan) => Some(plan),
                None => {
                    crate::plan::get_current_actionable_plan(&ctx.kube_client, resource).await?
                }
            };
            if let Some(current_plan) = current_plan {
                let approval_state = crate::plan::check_plan_approval(&current_plan);

                match approval_state {
                    crate::plan::PlanApprovalState::Approved => {
                        // Validate that nothing the approval bound has changed
                        // since the decision, by recomputing the canonical
                        // effect digest. Comparing rendered SQL here would
                        // supersede every password-bearing plan, because the
                        // SCRAM verifier is re-salted on each computation.
                        let fresh_digest = crate::plan::compute_change_digest(
                            &changes,
                            resource.spec.reconciliation_mode,
                            identity.as_str(),
                            &target_identity,
                            &applied_password_source_versions,
                            &inspect_config.managed_roles,
                            &inspect_config.managed_schemas,
                        )?;
                        // Before anything else, ask whether this is even the
                        // database the reviewer approved against. The identity
                        // is bound into the digest, so a moved target already
                        // fails the comparison below — this seam exists to say
                        // *why*, with a reason a human can act on, rather than
                        // reporting a target change as an effects change.
                        let approved_identity = current_plan
                            .status
                            .as_ref()
                            .map(crate::plan::plan_target_identity)
                            .unwrap_or_default();
                        let verdict = pgroles_core::approval::evaluate_target_identity(
                            &approved_identity,
                            &target_identity,
                            resource.spec.connection.requires_physical_identity(),
                        );
                        if let pgroles_core::approval::TargetIdentityVerdict::Superseded(reason)
                        | pgroles_core::approval::TargetIdentityVerdict::Blocked(reason) =
                            verdict
                        {
                            tracing::warn!(
                                plan = %current_plan.name_any(),
                                reason = reason.as_str(),
                                "approved plan will not execute: {}",
                                reason.message()
                            );
                            emit_plan_event(
                                ctx,
                                resource,
                                &current_plan,
                                PlanEventType::TargetIdentityChanged {
                                    reason: reason.as_str().to_string(),
                                    detail: reason.message().to_string(),
                                },
                            )
                            .await;
                        }

                        let mut decision = crate::plan::decide_approved_plan(
                            current_plan.status.as_ref(),
                            &fresh_digest,
                            !changes.is_empty(),
                        );
                        // Belt and braces: the digest already binds the
                        // identity, so this cannot currently disagree — but a
                        // future encoding that dropped the binding must not
                        // silently re-enable execution against a moved target.
                        if verdict != pgroles_core::approval::TargetIdentityVerdict::Proceed
                            && decision == crate::plan::ApprovedPlanDecision::Execute
                        {
                            decision = crate::plan::ApprovedPlanDecision::Replace;
                        }

                        if decision != crate::plan::ApprovedPlanDecision::Execute {
                            // Name the actual cause on the condition. A moved
                            // target reads as an effects change through the
                            // digest alone, and telling a reviewer their
                            // effects changed when the database moved sends
                            // them to inspect the wrong thing.
                            let supersede_cause = match verdict {
                                pgroles_core::approval::TargetIdentityVerdict::Superseded(
                                    reason,
                                )
                                | pgroles_core::approval::TargetIdentityVerdict::Blocked(reason) => {
                                    crate::plan::SupersedeCause::TargetChanged(reason)
                                }
                                pgroles_core::approval::TargetIdentityVerdict::Proceed => {
                                    if decision == crate::plan::ApprovedPlanDecision::Clear {
                                        crate::plan::SupersedeCause::EffectsCleared
                                    } else {
                                        crate::plan::SupersedeCause::EffectsChanged
                                    }
                                }
                            };
                            // The approved effects are no longer the effects
                            // this policy would produce.
                            let stored_digest = current_plan
                                .status
                                .as_ref()
                                .and_then(|s| s.change_digest.as_deref());
                            tracing::warn!(
                                plan = %current_plan.name_any(),
                                stored_digest = ?stored_digest,
                                fresh_digest = %fresh_digest,
                                reason = supersede_cause.reason(),
                                "approved plan superseded: {}",
                                supersede_cause.message()
                            );

                            // The effects did not just move, they vanished —
                            // someone applied them by hand, or an edit removed
                            // them. A replacement would hold nothing and still
                            // demand a second approval.
                            if decision == crate::plan::ApprovedPlanDecision::Clear {
                                info!(
                                    name,
                                    namespace,
                                    plan = %current_plan.name_any(),
                                    "approved plan superseded with no remaining changes"
                                );

                                // No replacement is created on this path, so
                                // this is the one place the supersede has to
                                // happen here rather than after a create. A
                                // crash between the two leaves the plan
                                // Superseded and the reference behind, which
                                // the next reconcile clears through the same
                                // helper.
                                crate::plan::mark_plan_superseded(
                                    &ctx.kube_client,
                                    &current_plan,
                                    supersede_cause,
                                )
                                .await?;

                                // The database already holds this content:
                                // a candidate proposing it has been promoted,
                                // even though this reconcile executed nothing.
                                record_promotion(ctx, resource, &content_digest).await;

                                mark_reconciled_no_changes(
                                    ctx,
                                    resource,
                                    generation,
                                    summary.clone(),
                                    applied_password_source_versions.clone(),
                                )
                                .await?;

                                return Ok((
                                    Action::requeue(requeue_interval),
                                    ReconcileOutcome::Reconciled,
                                ));
                            }

                            // Create a new plan with the fresh changes.
                            let new_creation_result = crate::plan::create_or_update_plan(
                                &ctx.kube_client,
                                resource,
                                &changes,
                                &sql_ctx,
                                &inspect_config,
                                resource.spec.reconciliation_mode,
                                identity.as_str(),
                                &target_identity,
                                &summary,
                                &applied_password_source_versions,
                                ctx.plan_retention,
                                None,
                            )
                            .await?;
                            let new_plan_name = new_creation_result.plan_name().to_string();

                            if new_creation_result.is_created() {
                                let plans_api: Api<PostgresPolicyPlan> =
                                    Api::namespaced(ctx.kube_client.clone(), namespace);
                                let new_plan = plans_api.get(&new_plan_name).await?;
                                emit_plan_event(
                                    ctx,
                                    resource,
                                    &new_plan,
                                    PlanEventType::Created {
                                        change_count: summary.total,
                                    },
                                )
                                .await;
                            }

                            crate::plan::update_policy_plan_ref(
                                &ctx.kube_client,
                                resource,
                                &new_plan_name,
                            )
                            .await?;

                            let report = planned_report(&new_creation_result, summary.total.into());
                            // The old plan is retired by `create_or_update_plan`
                            // once the replacement exists — except in the
                            // failed-backoff case, where nothing replaced it
                            // and claiming otherwise would misreport it.
                            let msg = if new_creation_result.is_failed_backoff() {
                                format!(
                                    "Plan {} can no longer be executed ({}); {}",
                                    current_plan.name_any(),
                                    supersede_cause.message(),
                                    report.message,
                                )
                            } else {
                                format!(
                                    "Plan {} superseded ({}); {}",
                                    current_plan.name_any(),
                                    supersede_cause.message(),
                                    report.message,
                                )
                            };
                            update_status(ctx, resource, |status| {
                                status.set_condition(ready_condition(true, report.reason, &msg));
                                status.set_condition(drifted_condition(
                                    true,
                                    "DriftDetected",
                                    &format!("{} planned change(s) pending review", summary.total),
                                ));
                                status.conditions.retain(|c| {
                                    c.condition_type != "Reconciling"
                                        && c.condition_type != "Degraded"
                                        && c.condition_type != "Conflict"
                                        && c.condition_type != "Paused"
                                        && c.condition_type
                                            != crate::crd::CONDITION_TARGET_IDENTITY_BLOCKED
                                });
                                status.last_attempted_generation = generation;
                                status.change_summary = Some(summary.clone());
                                status.last_reconcile_mode = Some(PolicyMode::Apply);
                                status.last_error = None;
                                status.transient_failure_count = 0;
                                status.current_plan_ref = Some(crate::crd::PlanReference {
                                    name: new_plan_name.clone(),
                                });
                            })
                            .await?;

                            return Ok((
                                Action::requeue(requeue_interval),
                                ReconcileOutcome::Planned,
                            ));
                        }

                        // The approved effects are still the effects this
                        // policy would produce — execute what was reviewed.
                        info!(
                            name,
                            namespace,
                            plan = %current_plan.name_any(),
                            "executing manually approved plan"
                        );

                        emit_plan_event(ctx, resource, &current_plan, PlanEventType::Approved)
                            .await;

                        crate::plan::mark_plan_approved(
                            &ctx.kube_client,
                            &current_plan,
                            // Only reached for a plan with no decision on it,
                            // which the manual path cannot produce — the
                            // reviewer's own decision is preserved instead.
                            "ManuallyApproved",
                            "Plan approved by a reviewer",
                        )
                        .await?;

                        let plans_api: Api<PostgresPolicyPlan> =
                            Api::namespaced(ctx.kube_client.clone(), namespace);
                        let plan = plans_api.get(&current_plan.name_any()).await?;

                        // The decision is recorded and the plan stays
                        // reviewable; this is the point past which it would
                        // execute, so this is where missing authority stops it.
                        if let Some(message) = &authority_block {
                            return Err(ReconcileError::ExecutorAuthority(message.clone()));
                        }

                        emit_plan_event(ctx, resource, &plan, PlanEventType::ApplyStarted).await;

                        // Generated Secrets are created here, after the human
                        // decision and before any SQL runs. A failure aborts the
                        // apply with no DDL issued.
                        if let Err(err) = materialize_pending_generated_secrets(
                            ctx,
                            resource,
                            namespace,
                            &resolved_passwords,
                            &mut changes,
                            &mut applied_password_source_versions,
                        )
                        .await
                        {
                            let message = err.to_string();
                            if let Err(status_err) =
                                crate::plan::mark_plan_failed(&ctx.kube_client, &plan, &message)
                                    .await
                            {
                                tracing::warn!(
                                    plan = %plan.name_any(),
                                    %status_err,
                                    "failed to mark plan Failed"
                                );
                            }
                            emit_plan_event(
                                ctx,
                                resource,
                                &plan,
                                PlanEventType::ApplyFailed {
                                    error: message.clone(),
                                },
                            )
                            .await;
                            return Err(err);
                        }

                        match crate::plan::execute_plan(
                            &ctx.kube_client,
                            &plan,
                            pool,
                            &sql_ctx,
                            &changes,
                        )
                        .await
                        {
                            Ok(()) => {
                                emit_plan_event(
                                    ctx,
                                    resource,
                                    &plan,
                                    PlanEventType::ApplySucceeded,
                                )
                                .await;
                            }
                            Err(err) => {
                                emit_plan_event(
                                    ctx,
                                    resource,
                                    &plan,
                                    PlanEventType::ApplyFailed {
                                        error: err.to_string(),
                                    },
                                )
                                .await;
                                return Err(err);
                            }
                        }

                        ctx.observability.record_apply_result("success");

                        // The approved effects executed. If they were a
                        // candidate's content, that candidate is now promoted —
                        // whether the approval came from the candidate's own
                        // plan (the gate) or from a fresh policy plan approved
                        // after a `PromotedWithoutApproval` fallback.
                        record_promotion(ctx, resource, &content_digest).await;

                        // Update status to Ready.
                        update_status(ctx, resource, |status| {
                            status.set_condition(ready_condition(
                                true,
                                "Reconciled",
                                "Approved plan applied",
                            ));
                            status.set_condition(drifted_condition(
                                false,
                                "InSync",
                                "No pending changes",
                            ));
                            status.conditions.retain(|c| {
                                c.condition_type != "Reconciling"
                                    && c.condition_type != "Degraded"
                                    && c.condition_type != "Conflict"
                                    && c.condition_type != "Paused"
                            });
                            status.observed_generation = generation;
                            status.last_attempted_generation = generation;
                            status.last_successful_reconcile_time = Some(crate::crd::now_rfc3339());
                            status.change_summary = Some(summary);
                            status.last_reconcile_mode = Some(PolicyMode::Apply);
                            status.last_error = None;
                            status.applied_password_source_versions =
                                applied_password_source_versions;
                            status.transient_failure_count = 0;
                        })
                        .await?;

                        return Ok((
                            Action::requeue(requeue_interval),
                            ReconcileOutcome::Reconciled,
                        ));
                    }
                    crate::plan::PlanApprovalState::Rejected => {
                        crate::plan::mark_plan_rejected(&ctx.kube_client, &current_plan).await?;
                        emit_plan_event(ctx, resource, &current_plan, PlanEventType::Rejected)
                            .await;
                        info!(
                            name,
                            namespace,
                            plan = %current_plan.name_any(),
                            "plan rejected by a terminal Denied decision"
                        );

                        // Update status to reflect rejection, but don't create a new plan
                        // in the same cycle to avoid tight reject-create loops.
                        update_status(ctx, resource, |status| {
                            status.set_condition(ready_condition(
                                true,
                                "Planned",
                                &format!(
                                    "Plan {} rejected; new plan will be created on next reconcile",
                                    current_plan.name_any()
                                ),
                            ));
                            status.last_attempted_generation = generation;
                            status.last_error = None;
                            status.transient_failure_count = 0;
                            status.current_plan_ref = None;
                        })
                        .await?;

                        return Ok((Action::requeue(requeue_interval), ReconcileOutcome::Planned));
                    }
                    crate::plan::PlanApprovalState::Pending => {
                        // Revalidate the pending plan against the effects the
                        // policy would produce right now. Without this the plan
                        // is frozen while awaiting a decision, so the policy can
                        // report a fresh change summary beside a plan holding
                        // different content — and a reviewer approves the stale
                        // one.
                        let fresh_digest = crate::plan::compute_change_digest(
                            &changes,
                            resource.spec.reconciliation_mode,
                            identity.as_str(),
                            &target_identity,
                            &applied_password_source_versions,
                            &inspect_config.managed_roles,
                            &inspect_config.managed_schemas,
                        )?;
                        let plan_status = current_plan.status.as_ref();
                        let decision = crate::plan::decide_pending_plan(
                            plan_status,
                            &fresh_digest,
                            !changes.is_empty(),
                        );

                        if decision != crate::plan::PendingPlanDecision::Retain {
                            // The effects moved. Supersede rather than leave a
                            // reviewable plan that no longer describes what
                            // would happen.
                            info!(
                                name,
                                namespace,
                                plan = %current_plan.name_any(),
                                ?decision,
                                "pending plan superseded while awaiting approval"
                            );

                            // The effects did not just move, they vanished. A
                            // replacement plan here would hold nothing and still
                            // demand a decision, so leave the policy with no
                            // pending plan at all.
                            if decision == crate::plan::PendingPlanDecision::Clear {
                                // Nothing replaces this plan, so it is retired
                                // here rather than after a create.
                                crate::plan::mark_plan_superseded(
                                    &ctx.kube_client,
                                    &current_plan,
                                    crate::plan::SupersedeCause::EffectsCleared,
                                )
                                .await?;

                                // The database already holds this content:
                                // a candidate proposing it has been promoted,
                                // even though this reconcile executed nothing.
                                record_promotion(ctx, resource, &content_digest).await;

                                mark_reconciled_no_changes(
                                    ctx,
                                    resource,
                                    generation,
                                    summary.clone(),
                                    applied_password_source_versions.clone(),
                                )
                                .await?;

                                return Ok((
                                    Action::requeue(requeue_interval),
                                    ReconcileOutcome::Reconciled,
                                ));
                            }

                            let creation_result = crate::plan::create_or_update_plan(
                                &ctx.kube_client,
                                resource,
                                &changes,
                                &sql_ctx,
                                &inspect_config,
                                resource.spec.reconciliation_mode,
                                identity.as_str(),
                                &target_identity,
                                &summary,
                                &applied_password_source_versions,
                                ctx.plan_retention,
                                None,
                            )
                            .await?;
                            let replacement = creation_result.plan_name().to_string();
                            let report = planned_report(&creation_result, summary.total.into());

                            update_status(ctx, resource, |status| {
                                let msg = report.message.clone();
                                status.set_condition(ready_condition(true, report.reason, &msg));
                                // Replace implies a non-empty change set; the
                                // empty case returned above as Clear.
                                status.set_condition(drifted_condition(
                                    true,
                                    "DriftDetected",
                                    &msg,
                                ));
                                status.conditions.retain(|c| {
                                    c.condition_type != "Reconciling"
                                        && c.condition_type != "Degraded"
                                        && c.condition_type != "Conflict"
                                        && c.condition_type != "Paused"
                                        && c.condition_type
                                            != crate::crd::CONDITION_TARGET_IDENTITY_BLOCKED
                                });
                                status.last_attempted_generation = generation;
                                status.change_summary = Some(summary.clone());
                                status.current_plan_ref = Some(crate::crd::PlanReference {
                                    name: replacement.clone(),
                                });
                                status.last_error = None;
                                status.transient_failure_count = 0;
                            })
                            .await?;

                            return Ok((
                                Action::requeue(requeue_interval),
                                ReconcileOutcome::Planned,
                            ));
                        }

                        // Effects unchanged — the plan, and any decision on it,
                        // stand. Record the generation it was confirmed against
                        // so an effect-neutral policy edit is visible as
                        // provenance rather than looking like a stale plan.
                        if plan_status
                            .is_some_and(|s| crate::plan::needs_revalidation_record(s, generation))
                        {
                            crate::plan::record_plan_revalidation(
                                &ctx.kube_client,
                                &current_plan,
                                generation,
                            )
                            .await?;
                        }

                        info!(
                            name,
                            namespace,
                            plan = %current_plan.name_any(),
                            "plan awaiting manual approval"
                        );

                        update_status(ctx, resource, |status| {
                            let msg = format!(
                                "Plan {} awaiting approval; {} change(s) pending",
                                current_plan.name_any(),
                                summary.total,
                            );
                            status.set_condition(ready_condition(true, "Planned", &msg));
                            status.set_condition(drifted_condition(
                                !changes.is_empty(),
                                if changes.is_empty() {
                                    "InSync"
                                } else {
                                    "DriftDetected"
                                },
                                &msg,
                            ));
                            status.conditions.retain(|c| {
                                c.condition_type != "Reconciling"
                                    && c.condition_type != "Degraded"
                                    && c.condition_type != "Conflict"
                                    && c.condition_type != "Paused"
                            });
                            status.last_attempted_generation = generation;
                            status.change_summary = Some(summary.clone());
                            // The summary and the plan reference must always
                            // describe the same effects; the plan was just
                            // confirmed to still hold them.
                            status.current_plan_ref = Some(crate::crd::PlanReference {
                                name: current_plan.name_any(),
                            });
                            status.last_error = None;
                            status.transient_failure_count = 0;
                        })
                        .await?;

                        return Ok((Action::requeue(requeue_interval), ReconcileOutcome::Planned));
                    }
                }
            }

            // No pending plan (or previous one was rejected) — create a new plan.
            if changes.is_empty() {
                info!(name, namespace, "no changes needed (manual approval mode)");

                // Reached only when no actionable plan exists, so the helper
                // clearing `current_plan_ref` is what this path always meant:
                // previously it left a reference to whatever plan had been
                // superseded, which outlived the plan itself once retention
                // pruned it.
                // Nothing to do because the content is already the
                // database's state — which promotes a candidate that proposed
                // exactly this content.
                record_promotion(ctx, resource, &content_digest).await;

                mark_reconciled_no_changes(
                    ctx,
                    resource,
                    generation,
                    summary,
                    applied_password_source_versions,
                )
                .await?;

                return Ok((
                    Action::requeue(requeue_interval),
                    ReconcileOutcome::Reconciled,
                ));
            }

            // Create a new plan and wait for approval.
            let creation_result = crate::plan::create_or_update_plan(
                &ctx.kube_client,
                resource,
                &changes,
                &sql_ctx,
                &inspect_config,
                resource.spec.reconciliation_mode,
                identity.as_str(),
                &target_identity,
                &summary,
                &applied_password_source_versions,
                ctx.plan_retention,
                None,
            )
            .await?;
            let plan_name = creation_result.plan_name().to_string();

            // Only emit PlanCreated event for genuinely new plans, not dedup hits.
            if creation_result.is_created() {
                let plans_api: Api<PostgresPolicyPlan> =
                    Api::namespaced(ctx.kube_client.clone(), namespace);
                let created_plan = plans_api.get(&plan_name).await?;
                emit_plan_event(
                    ctx,
                    resource,
                    &created_plan,
                    PlanEventType::Created {
                        change_count: summary.total,
                    },
                )
                .await;
            }

            crate::plan::update_policy_plan_ref(&ctx.kube_client, resource, &plan_name).await?;

            let report = planned_report(&creation_result, summary.total.into());
            let msg = report.message.clone();
            update_status(ctx, resource, |status| {
                status.set_condition(ready_condition(true, report.reason, &msg));
                status.set_condition(drifted_condition(
                    true,
                    "DriftDetected",
                    &format!("{} planned change(s) pending review", summary.total),
                ));
                status.conditions.retain(|c| {
                    c.condition_type != "Reconciling"
                        && c.condition_type != "Degraded"
                        && c.condition_type != "Conflict"
                        && c.condition_type != "Paused"
                        && c.condition_type != crate::crd::CONDITION_TARGET_IDENTITY_BLOCKED
                });
                status.last_attempted_generation = generation;
                status.change_summary = Some(summary.clone());
                status.last_reconcile_mode = Some(PolicyMode::Apply);
                status.last_error = None;
                status.transient_failure_count = 0;
                status.current_plan_ref = Some(crate::crd::PlanReference {
                    name: plan_name.clone(),
                });
            })
            .await?;

            info!(
                name,
                namespace,
                total = summary.total,
                plan = %plan_name,
                "plan created, awaiting manual approval"
            );

            Ok((Action::requeue(requeue_interval), ReconcileOutcome::Planned))
        }
    }
}

/// Resolve role passwords from Kubernetes Secrets or generate them.
///
/// For each role that declares a `password`:
/// - `PasswordSpec::SecretRef`: fetches the password from the referenced Secret.
/// - `PasswordSpec::Generate`: reads the generated Secret if it exists. If it
///   does not, an in-memory password is synthesized and the entry is marked for
///   materialization — resolution itself never writes, in any mode. The Secret
///   is created by [`materialize_pending_generated_secrets`] immediately before
///   the approved plan executes (#181).
///
/// Returns a map of role name → cleartext password string suitable for
/// [`pgroles_core::diff::inject_password_changes`] (which computes the
/// SCRAM-SHA-256 verifier before creating `SetPassword` changes).
async fn resolve_passwords_from_secrets(
    ctx: &OperatorContext,
    resource: &PostgresPolicy,
    namespace: &str,
) -> Result<std::collections::BTreeMap<String, ResolvedPassword>, ReconcileError> {
    resolve_passwords_for_roles(ctx, resource, namespace, &resource.spec.roles, true).await
}

/// Resolve passwords for an arbitrary role set in the parent policy's context.
///
/// Candidate planning uses this with the candidate's own roles: generated
/// Secret names are derived from the *parent policy* name, because that is
/// what promotion would produce, and `warn_on_missing` is off — a candidate
/// has no applied history of its own, so "the Secret disappeared" is not a
/// statement it can make.
pub(crate) async fn resolve_passwords_for_roles(
    ctx: &OperatorContext,
    resource: &PostgresPolicy,
    namespace: &str,
    role_specs: &[crate::crd::RoleSpec],
    warn_on_missing: bool,
) -> Result<std::collections::BTreeMap<String, ResolvedPassword>, ReconcileError> {
    use k8s_openapi::api::core::v1::Secret;

    let mut resolved = std::collections::BTreeMap::new();

    // Cache fetched Secrets by name to avoid duplicate API calls when
    // multiple roles reference different keys in the same Secret.
    let mut secret_cache: std::collections::BTreeMap<String, Secret> =
        std::collections::BTreeMap::new();

    let secrets_api: kube::Api<Secret> = kube::Api::namespaced(ctx.kube_client.clone(), namespace);

    // First pass: fetch all referenced Secrets for secretRef roles.
    for role_spec in role_specs {
        if role_spec.external {
            continue;
        }
        if let Some(pw) = &role_spec.password
            && let Some(secret_ref) = &pw.secret_ref
        {
            let secret_name = &secret_ref.name;
            if !secret_cache.contains_key(secret_name.as_str()) {
                let fetched = secrets_api.get(secret_name).await.map_err(|err| {
                    Box::new(crate::context::ContextError::SecretFetch {
                        name: secret_name.clone(),
                        namespace: namespace.to_string(),
                        source: err,
                    })
                })?;
                secret_cache.insert(secret_name.clone(), fetched);
            }
        }
    }

    // Second pass: resolve passwords from cache (secretRef) or generate.
    for role_spec in role_specs {
        if role_spec.external {
            continue;
        }
        if let Some(pw) = &role_spec.password {
            if let Some(gen_spec) = &pw.generate {
                // Resolution never writes: planning must not leave a credential
                // behind for a plan that is rejected or never approved. An
                // existing Secret is read; a missing one resolves to an
                // in-memory password plus the `:missing` sentinel version, and
                // the Secret is created just before the plan executes.
                let existing = crate::password::get_generated_secret(
                    ctx.kube_client.clone(),
                    namespace,
                    &resource.name_any(),
                    &role_spec.name,
                    gen_spec,
                )
                .await
                .map_err(Box::new)?;

                let entry = match existing {
                    Some(existing) => {
                        ResolvedPassword::existing(existing.password, existing.source_version)
                    }
                    None => {
                        let secret_name = crate::password::generated_secret_name(
                            &resource.name_any(),
                            &role_spec.name,
                            gen_spec,
                        );
                        let secret_key = crate::password::generated_secret_key(gen_spec);
                        let sentinel = crate::password::missing_generated_secret_source_version(
                            &secret_name,
                            &secret_key,
                        );

                        // A recorded version that is not the sentinel means a
                        // real Secret existed and has since been deleted. The
                        // next plan legitimately rotates the password, but that
                        // is worth saying out loud.
                        if warn_on_missing
                            && recorded_source_version_was_real(
                                resource,
                                &role_spec.name,
                                &sentinel,
                            )
                        {
                            emit_policy_warning(
                                ctx,
                                resource,
                                "GeneratedSecretMissing",
                                "PasswordGeneration",
                                format!(
                                    "generated Secret \"{secret_name}\" for role \
                                     \"{}\" disappeared; regenerating and rotating password",
                                    role_spec.name
                                ),
                            )
                            .await;
                        }

                        ResolvedPassword {
                            cleartext: crate::password::generate_password(
                                gen_spec
                                    .length
                                    .unwrap_or(crate::password::DEFAULT_PASSWORD_LENGTH),
                            ),
                            source_version: sentinel,
                            pending_materialization: Some(PendingGeneratedSecret {
                                role: role_spec.name.clone(),
                                spec: gen_spec.clone(),
                            }),
                        }
                    }
                };
                resolved.insert(role_spec.name.clone(), entry);
            } else if pw.secret_ref.is_some() {
                // SecretRef mode — read from an existing Secret.
                let password = resolve_password_from_cache(&role_spec.name, pw, &secret_cache)?;
                resolved.insert(role_spec.name.clone(), password);
            }
        }
    }

    Ok(resolved)
}

/// Extract a password from a pre-fetched Secret cache for a `secretRef` role.
fn resolve_password_from_cache(
    role_name: &str,
    password_spec: &crate::crd::PasswordSpec,
    secret_cache: &std::collections::BTreeMap<String, k8s_openapi::api::core::v1::Secret>,
) -> Result<ResolvedPassword, ReconcileError> {
    let secret_ref = password_spec.secret_ref.as_ref().ok_or_else(|| {
        Box::new(crate::context::ContextError::SecretMissing {
            name: "(no secretRef)".to_string(),
            key: role_name.to_string(),
        })
    })?;
    let secret_name = &secret_ref.name;
    let secret_key = password_spec.secret_key.as_deref().unwrap_or(role_name);

    let secret = secret_cache.get(secret_name.as_str()).ok_or_else(|| {
        Box::new(crate::context::ContextError::SecretMissing {
            name: secret_name.clone(),
            key: secret_key.to_string(),
        })
    })?;

    let data = secret.data.as_ref().ok_or_else(|| {
        Box::new(crate::context::ContextError::SecretMissing {
            name: secret_name.clone(),
            key: secret_key.to_string(),
        })
    })?;

    let value_bytes = data.get(secret_key).ok_or_else(|| {
        Box::new(crate::context::ContextError::SecretMissing {
            name: secret_name.clone(),
            key: secret_key.to_string(),
        })
    })?;

    let password = String::from_utf8(value_bytes.0.clone()).map_err(|_| {
        Box::new(crate::context::ContextError::SecretMissing {
            name: secret_name.clone(),
            key: secret_key.to_string(),
        })
    })?;

    if password.is_empty() {
        return Err(ReconcileError::EmptyPasswordSecret {
            role: role_name.to_string(),
            secret: secret_name.clone(),
            key: secret_key.to_string(),
        });
    }

    let resource_version = secret
        .metadata
        .resource_version
        .as_deref()
        .unwrap_or("unknown");
    Ok(ResolvedPassword::existing(
        password,
        format!("{secret_name}:{secret_key}:{resource_version}"),
    ))
}

/// Returns `true` when the policy previously recorded a real (non-sentinel)
/// source version for this role's generated password.
fn recorded_source_version_was_real(resource: &PostgresPolicy, role: &str, sentinel: &str) -> bool {
    resource
        .status
        .as_ref()
        .and_then(|status| status.applied_password_source_versions.get(role))
        .is_some_and(|recorded| recorded != sentinel)
}

/// Create the Kubernetes Secrets for generated passwords that planning left
/// unmaterialized, immediately before the approved plan executes.
///
/// Ordering is deliberate: the Secret is written *before* the SQL transaction.
/// A crash between the two leaves an unused Secret which the next reconcile
/// adopts and applies; the reverse order could commit a password to the
/// database that exists nowhere else.
///
/// `ensure_generated_secret` is create-or-read, so a Secret written concurrently
/// by another replica wins. When it does, the plan's `SetPassword` verifier is
/// rebuilt from the Secret's cleartext so the database matches what the Secret
/// hands to applications.
///
/// The returned source versions replace the planning-time `:missing` sentinels
/// in `applied_password_source_versions`, so the status records the version the
/// database was actually set from. Recording the sentinel instead would make
/// the very next reconcile see a changed source and emit a spurious plan.
async fn materialize_pending_generated_secrets(
    ctx: &OperatorContext,
    resource: &PostgresPolicy,
    namespace: &str,
    resolved_passwords: &std::collections::BTreeMap<String, ResolvedPassword>,
    changes: &mut [pgroles_core::diff::Change],
    applied_password_source_versions: &mut std::collections::BTreeMap<String, String>,
) -> Result<(), ReconcileError> {
    for resolved in resolved_passwords.values() {
        let Some(pending) = &resolved.pending_materialization else {
            continue;
        };

        let materialized = crate::password::ensure_generated_secret(
            ctx.kube_client.clone(),
            namespace,
            resource,
            &pending.role,
            &pending.spec,
        )
        .await
        .map_err(Box::new)?;

        applied_password_source_versions
            .insert(pending.role.clone(), materialized.source_version.clone());

        if materialized.password != resolved.cleartext {
            // Another writer created the Secret first. The plan's verifier was
            // computed from the password we generated, which nothing will ever
            // read — set the database from the Secret's password instead.
            tracing::info!(
                role = %pending.role,
                "generated Secret already existed at execution time; \
                 rebuilding password change from its contents"
            );
            let verifier = pgroles_core::scram::compute_verifier(
                &materialized.password,
                pgroles_core::scram::DEFAULT_ITERATIONS,
            );
            for change in changes.iter_mut() {
                if let pgroles_core::diff::Change::SetPassword { name, password } = change
                    && name == &pending.role
                {
                    *password = verifier.clone();
                }
            }
        }
    }

    Ok(())
}

/// Resolve passwords from a pre-populated cache (for unit testing without K8s).
#[cfg(test)]
fn resolve_passwords_from_cached_secrets(
    resource: &PostgresPolicy,
    secret_cache: &std::collections::BTreeMap<String, k8s_openapi::api::core::v1::Secret>,
) -> Result<std::collections::BTreeMap<String, ResolvedPassword>, ReconcileError> {
    let mut resolved = std::collections::BTreeMap::new();
    for role_spec in &resource.spec.roles {
        if role_spec.external {
            continue;
        }
        if let Some(pw) = &role_spec.password
            && pw.secret_ref.is_some()
        {
            let password = resolve_password_from_cache(&role_spec.name, pw, secret_cache)?;
            resolved.insert(role_spec.name.clone(), password);
        }
    }
    Ok(resolved)
}

pub(crate) fn select_password_changes(
    changes: &[pgroles_core::diff::Change],
    resolved_passwords: &std::collections::BTreeMap<String, ResolvedPassword>,
    status: Option<&PostgresPolicyStatus>,
) -> (
    std::collections::BTreeMap<String, String>,
    std::collections::BTreeMap<String, String>,
) {
    let created_roles: std::collections::BTreeSet<&str> = changes
        .iter()
        .filter_map(|change| match change {
            pgroles_core::diff::Change::CreateRole { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    let previous_versions = status
        .map(|status| &status.applied_password_source_versions)
        .cloned()
        .unwrap_or_default();

    let mut password_changes = std::collections::BTreeMap::new();
    let mut current_versions = std::collections::BTreeMap::new();

    for (role, resolved) in resolved_passwords {
        current_versions.insert(role.clone(), resolved.source_version.clone());
        // An unmaterialized generated password always needs applying: the
        // recorded version could only match the `:missing` sentinel if a
        // previous run recorded it, and no database ever received that
        // password.
        if created_roles.contains(role.as_str())
            || resolved.pending_materialization.is_some()
            || previous_versions.get(role) != Some(&resolved.source_version)
        {
            password_changes.insert(role.clone(), resolved.cleartext.clone());
        }
    }

    (password_changes, current_versions)
}

/// Cleanup on deletion — evict cached pool.
async fn reconcile_cleanup(
    resource: &PostgresPolicy,
    ctx: &OperatorContext,
) -> Result<Action, ReconcileError> {
    let name = resource.name_any();
    let namespace = resource.namespace().ok_or(ReconcileError::NoNamespace)?;

    info!(name, namespace, "cleaning up (resource deleted)");

    // A target policy must remain addressable until every attached access
    // policy has run its own finalizer and revoked its active requests. This
    // preserves the existing PostgresPolicy deletion contract (durable grants
    // are not revoked) while preventing ephemeral overlays from being stranded.
    let remaining = crate::ephemeral::delete_access_policies_for_target(resource, ctx).await?;
    if remaining > 0 {
        return Err(ReconcileError::PendingEphemeralAccessCleanup(remaining));
    }

    // Evict any cached pool for this resource's connection.
    ctx.evict_pool(&namespace, &resource.spec.connection).await;

    // Note: we do NOT revoke grants on deletion. The resource being deleted
    // means the user no longer wants pgroles to manage these roles — it does
    // NOT mean "revoke everything". This is the safe default.

    Ok(Action::await_change())
}

/// Accumulate change counts into the summary.
fn accumulate_summary(summary: &mut ChangeSummary, change: &pgroles_core::diff::Change) {
    use pgroles_core::diff::Change;
    match change {
        Change::CreateRole { .. } => summary.roles_created += 1,
        Change::CreateSchema { .. } => summary.schemas_created += 1,
        Change::AlterSchemaOwner { .. } => summary.schema_owners_altered += 1,
        Change::AlterRole { .. } => summary.roles_altered += 1,
        Change::SetComment { .. } => summary.roles_altered += 1,
        Change::DropRole { .. } => summary.roles_dropped += 1,
        Change::TerminateSessions { .. } => summary.sessions_terminated += 1,
        Change::ReassignOwned { .. } => {}
        Change::DropOwned { .. } => {}
        Change::Grant { .. } | Change::EnsureSchemaOwnerPrivileges { .. } => {
            summary.grants_added += 1
        }
        Change::Revoke { .. } => summary.grants_revoked += 1,
        Change::SetDefaultPrivilege { .. } => summary.default_privileges_set += 1,
        Change::RevokeDefaultPrivilege { .. } => summary.default_privileges_revoked += 1,
        Change::AddMember { .. } => summary.members_added += 1,
        Change::RemoveMember { .. } => summary.members_removed += 1,
        Change::SetPassword { .. } => summary.passwords_set += 1,
    }
}

pub(crate) fn summarize_changes(changes: &[pgroles_core::diff::Change]) -> ChangeSummary {
    let mut summary = ChangeSummary::default();
    for change in changes {
        accumulate_summary(&mut summary, change);
    }
    summary.total = summary.roles_created
        + summary.roles_altered
        + summary.schemas_created
        + summary.schema_owners_altered
        + summary.roles_dropped
        + summary.sessions_terminated
        + summary.grants_added
        + summary.grants_revoked
        + summary.default_privileges_set
        + summary.default_privileges_revoked
        + summary.members_added
        + summary.members_removed
        + summary.passwords_set;
    summary
}

/// Parse a simplified RFC 3339 / ISO 8601 timestamp (`YYYY-MM-DDTHH:MM:SSZ`)
/// into seconds since the Unix epoch.
///
/// Returns `None` if the string does not match the expected format.
fn parse_rfc3339_to_epoch_secs(timestamp: &str) -> Option<u64> {
    // Expected format: "2026-03-31T12:34:56Z"
    if timestamp.len() < 20 || !timestamp.ends_with('Z') {
        return None;
    }
    let year: u64 = timestamp.get(0..4)?.parse().ok()?;
    let month: u64 = timestamp.get(5..7)?.parse().ok()?;
    let day: u64 = timestamp.get(8..10)?.parse().ok()?;
    let hours: u64 = timestamp.get(11..13)?.parse().ok()?;
    let minutes: u64 = timestamp.get(14..16)?.parse().ok()?;
    let seconds: u64 = timestamp.get(17..19)?.parse().ok()?;

    // Convert to days since epoch using the inverse of the civil algorithm.
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days_since_epoch = era * 146097 + doe - 719468;

    Some(days_since_epoch * 86400 + hours * 3600 + minutes * 60 + seconds)
}

pub(crate) async fn detect_sql_context(
    pool: &sqlx::PgPool,
    inspect_config: &pgroles_inspect::InspectConfig,
) -> Result<pgroles_core::sql::SqlContext, ReconcileError> {
    let pg_version = pgroles_inspect::detect_pg_version(pool).await?;
    let privilege_schemas: Vec<&str> = inspect_config
        .privilege_schemas
        .iter()
        .map(|schema| schema.as_str())
        .collect();
    let relation_inventory =
        pgroles_inspect::fetch_relation_inventory(pool, &privilege_schemas).await?;
    Ok(
        pgroles_core::sql::SqlContext::from_version_num(pg_version.version_num)
            .with_relation_inventory(relation_inventory),
    )
}

/// Emit a Warning event on the policy, logging failures rather than failing the
/// reconcile — the event is a notification, not a control-flow step.
async fn emit_policy_warning(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
    reason: &str,
    action: &str,
    note: String,
) {
    tracing::warn!(policy = %policy.name_any(), reason, note = %note, "policy warning");
    if let Err(error) =
        crate::events::publish_policy_warning(&ctx.event_recorder, policy, reason, action, note)
            .await
    {
        tracing::warn!(
            policy = %policy.name_any(),
            %error,
            "failed to publish policy warning event"
        );
    }
}

/// Emit a plan lifecycle event on the parent policy, logging warnings on failure.
async fn emit_plan_event(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
    plan: &PostgresPolicyPlan,
    event_type: PlanEventType,
) {
    if let Err(error) = publish_plan_event(&ctx.event_recorder, policy, plan, event_type).await {
        let namespace = policy.namespace().unwrap_or_default();
        let name = policy.name_any();
        tracing::warn!(
            policy = %format!("{namespace}/{name}"),
            %error,
            "failed to publish plan lifecycle event"
        );
    }
}

/// Patch the status sub-resource of a PostgresPolicy.
/// Promotion bookkeeping after the database converged on the policy's content.
///
/// Never fatal. The SQL has already run (or was never needed), so failing the
/// reconcile here would retry an apply to fix a status write — and the next
/// reconcile re-recognises the same promotion and writes it anyway, because
/// recognition is by digest and not by a one-shot transition.
async fn record_promotion(ctx: &OperatorContext, resource: &PostgresPolicy, content_digest: &str) {
    if let Err(err) = crate::promotion::record_promotion(ctx, resource, content_digest).await {
        tracing::warn!(
            policy = %resource.name_any(),
            %err,
            "failed to record candidate promotion; will retry on the next reconcile"
        );
    }
}

/// Record that the policy is in sync with nothing left to do.
///
/// Three paths reach this state under manual approval — no plan and no changes,
/// a pending plan whose effects vanished, and an approved plan whose effects
/// vanished — and they must report it identically. Written once here so a field
/// added later cannot be added to two of the three.
async fn mark_reconciled_no_changes(
    ctx: &OperatorContext,
    resource: &PostgresPolicy,
    generation: Option<i64>,
    summary: crate::crd::ChangeSummary,
    applied_password_source_versions: std::collections::BTreeMap<String, String>,
) -> Result<(), ReconcileError> {
    let previous_plan_ref = resource
        .status
        .as_ref()
        .and_then(|status| status.current_plan_ref.clone());

    update_status(ctx, resource, |status| {
        status.set_condition(ready_condition(true, "Reconciled", "No changes needed"));
        status.set_condition(drifted_condition(false, "InSync", "No pending changes"));
        status.conditions.retain(|c| {
            c.condition_type != "Reconciling"
                && c.condition_type != "Degraded"
                && c.condition_type != "Conflict"
                && c.condition_type != "Paused"
        });
        status.observed_generation = generation;
        status.last_attempted_generation = generation;
        status.last_successful_reconcile_time = Some(crate::crd::now_rfc3339());
        status.change_summary = Some(summary);
        status.last_reconcile_mode = Some(PolicyMode::Apply);
        // Whatever plan was pointed at is gone; leaving the reference behind
        // strands it on a superseded or pruned object.
        status.current_plan_ref = None;
        status.last_error = None;
        status.applied_password_source_versions = applied_password_source_versions;
        status.transient_failure_count = 0;
    })
    .await?;

    // Only after the reference is gone: a crash here leaves a Pending plan
    // that the next reconcile still finds, whereas superseding first and
    // crashing would strand the reference on a plan nobody can act on.
    supersede_referenced_plan_if_pending(ctx, resource, previous_plan_ref.as_ref()).await;

    Ok(())
}

/// Retire a plan a just-cleared `current_plan_ref` pointed at, if it is still
/// Pending.
///
/// Best-effort by design: the reference is already gone, so a failure here
/// costs a stale Pending plan that the next reconcile or plan retention
/// collects — not a wedged reconcile.
async fn supersede_referenced_plan_if_pending(
    ctx: &OperatorContext,
    resource: &PostgresPolicy,
    plan_ref: Option<&crate::crd::PlanReference>,
) {
    let (Some(plan_ref), Some(namespace)) = (plan_ref, resource.namespace()) else {
        return;
    };

    let plans_api: Api<PostgresPolicyPlan> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    let plan = match plans_api.get_opt(&plan_ref.name).await {
        Ok(Some(plan)) => plan,
        Ok(None) => return,
        Err(err) => {
            tracing::warn!(
                plan = %plan_ref.name,
                error = %err,
                "could not read the plan a cleared reference pointed at"
            );
            return;
        }
    };

    if plan.status.as_ref().map(|s| &s.phase) != Some(&crate::crd::PlanPhase::Pending) {
        return;
    }

    if let Err(err) = crate::plan::mark_plan_superseded(
        &ctx.kube_client,
        &plan,
        crate::plan::SupersedeCause::PolicyStoppedPlanning,
    )
    .await
    {
        tracing::warn!(
            plan = %plan_ref.name,
            error = %err,
            "could not supersede the plan a cleared reference pointed at"
        );
    }
}

/// Ready-condition wording for a reconcile that just planned changes.
///
/// `create_or_update_plan` can answer with a plan that is *not* awaiting a
/// decision: when an identical change set failed recently, the failed plan is
/// held in its retry window instead of a new one being opened. Reporting that
/// as "awaiting approval" sends a reviewer to a Failed plan looking for a
/// decision to make.
struct PlannedReport {
    reason: &'static str,
    message: String,
}

fn planned_report(result: &crate::plan::PlanCreationResult, total: i64) -> PlannedReport {
    let plan_name = result.plan_name();
    if result.is_failed_backoff() {
        PlannedReport {
            reason: "PlanFailedRetryBackoff",
            message: format!(
                "Plan {plan_name} holds these exact {total} change(s) and failed recently; \
                 it is in its retry backoff window and no plan is awaiting approval"
            ),
        }
    } else {
        PlannedReport {
            reason: "Planned",
            message: format!("Plan {plan_name} created; {total} change(s) awaiting approval"),
        }
    }
}

async fn update_status<F>(
    ctx: &OperatorContext,
    resource: &PostgresPolicy,
    mutate: F,
) -> Result<(), ReconcileError>
where
    F: FnOnce(&mut PostgresPolicyStatus),
{
    let namespace = resource.namespace().ok_or(ReconcileError::NoNamespace)?;
    let name = resource.name_any();

    let api: Api<PostgresPolicy> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    let latest = bounded_k8s_call("get PostgresPolicy", api.get(&name)).await?;
    let old_status = latest.status.clone();
    let mut status = old_status.clone().unwrap_or_default();

    mutate(&mut status);
    // Applied centrally rather than at each caller: every status write passes
    // through here, so the condition cannot be missed on one path or go stale
    // once the field is finally set.
    // Read the spec from `latest`, not the reconcile's snapshot: if the field
    // was set while this reconcile ran, the snapshot would re-add a condition
    // that no longer applies.
    apply_approval_deprecation_condition(&latest, &mut status);
    apply_mode_deprecation_condition(&latest, &mut status);
    apply_additive_absence_condition(&latest, &mut status);
    clear_stale_approval_ignored_condition(&latest, &mut status);

    // A status write that changes nothing still bumps `resourceVersion`, and
    // the resulting watch event re-triggers this controller immediately —
    // discarding whatever back-off `error_policy` chose. That is not a
    // theoretical cost: a permanently-failing policy reconciles, writes status,
    // wakes itself, and spins as fast as it can reconcile (~5/second observed),
    // taking the per-database advisory lock every time and starving every other
    // policy pointed at the same database.
    //
    // Compared as serialized JSON rather than with `PartialEq`: the question is
    // whether the PATCH body differs from what is stored, and that is exactly a
    // JSON question. Serialization failure falls through to writing, which is
    // the pre-existing behaviour.
    let status_json = serde_json::to_value(&status).ok();
    let unchanged = match (&old_status, &status_json) {
        (Some(old), Some(new)) => serde_json::to_value(old).ok().as_ref() == Some(new),
        _ => false,
    };
    if unchanged {
        tracing::trace!(name, namespace, "status unchanged, skipping write");
        return Ok(());
    }

    let patch = serde_json::json!({
        "status": status
    });

    bounded_k8s_call(
        "patch PostgresPolicy status",
        api.patch_status(
            &name,
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&patch),
        ),
    )
    .await?;

    if let Err(error) =
        publish_status_events(&ctx.event_recorder, &latest, old_status.as_ref(), &status).await
    {
        tracing::warn!(policy = %format!("{namespace}/{name}"), %error, "failed to publish Kubernetes Events");
    }

    Ok(())
}

/// Report whether this policy relies on `spec.approval` being inferred from
/// `spec.mode`. The inference is deprecated and becomes an error in a future
/// release, so a policy depending on it carries a condition until the field is
/// written down. Setting the field clears the condition on the next write.
fn apply_approval_deprecation_condition(
    resource: &PostgresPolicy,
    status: &mut PostgresPolicyStatus,
) {
    if resource.spec.approval.is_some() {
        status
            .conditions
            .retain(|condition| condition.condition_type != crate::crd::CONDITION_APPROVAL_UNSET);
        return;
    }
    status.set_condition(crate::crd::approval_unset_condition(
        resource.spec.effective_approval(),
    ));
}

/// Carry a `ModeValueDeprecated` condition while `spec.mode` is spelled
/// `plan`; writing `observe` clears it on the next reconcile.
fn apply_mode_deprecation_condition(resource: &PostgresPolicy, status: &mut PostgresPolicyStatus) {
    if !resource.spec.mode.is_deprecated_spelling() {
        status.conditions.retain(|condition| {
            condition.condition_type != crate::crd::CONDITION_MODE_VALUE_DEPRECATED
        });
        return;
    }
    status.set_condition(crate::crd::mode_value_deprecated_condition());
}

/// Keep additive mode's ignored security assertions visible on every status
/// written for the policy, and clear the condition as soon as the combination
/// no longer applies.
fn apply_additive_absence_condition(resource: &PostgresPolicy, status: &mut PostgresPolicyStatus) {
    let declares_absence = resource
        .spec
        .grants
        .iter()
        .any(|grant| grant.ensure == pgroles_core::manifest::Ensure::Absent)
        || resource.spec.default_privileges.iter().any(|defaults| {
            defaults
                .grant
                .iter()
                .any(|grant| grant.ensure == pgroles_core::manifest::Ensure::Absent)
        });
    if resource.spec.reconciliation_mode == crate::crd::CrdReconciliationMode::Additive
        && declares_absence
    {
        status.set_condition(crate::crd::absence_assertions_ignored_condition());
    } else {
        status.conditions.retain(|condition| {
            condition.condition_type != crate::crd::CONDITION_ABSENCE_ASSERTIONS_IGNORED
        });
    }
}

/// Clear `ApprovalIgnored` for any policy that is not in observe mode. The observe
/// path maintains the condition itself; this only stops a stale one surviving a
/// switch to `mode: apply`, where an approval is no longer ignored.
fn clear_stale_approval_ignored_condition(
    resource: &PostgresPolicy,
    status: &mut PostgresPolicyStatus,
) {
    if !resource.spec.mode.never_executes() {
        status
            .conditions
            .retain(|condition| condition.condition_type != crate::crd::CONDITION_APPROVAL_IGNORED);
    }
}

async fn detect_policy_conflict(
    ctx: &OperatorContext,
    resource: &PostgresPolicy,
    identity: &DatabaseIdentity,
    ownership: &crate::crd::OwnershipClaims,
) -> Result<Option<String>, ReconcileError> {
    let api: Api<PostgresPolicy> = match &ctx.watch_namespace {
        Some(namespace) => Api::namespaced(ctx.kube_client.clone(), namespace),
        None => Api::all(ctx.kube_client.clone()),
    };
    let policies = bounded_k8s_call("list PostgresPolicy", api.list(&Default::default())).await?;

    Ok(detect_policy_conflict_in_list(
        resource,
        identity,
        ownership,
        policies.into_iter(),
    ))
}

fn detect_policy_conflict_in_list(
    resource: &PostgresPolicy,
    identity: &DatabaseIdentity,
    ownership: &crate::crd::OwnershipClaims,
    policies: impl IntoIterator<Item = PostgresPolicy>,
) -> Option<String> {
    let this_ns = resource.namespace()?;
    let this_name = resource.name_any();

    let mut conflicts = Vec::new();
    for other in policies {
        let other_ns = match other.namespace() {
            Some(ns) => ns,
            None => continue,
        };
        let other_name = other.name_any();
        if other_ns == this_ns && other_name == this_name {
            continue;
        }

        let other_identity = DatabaseIdentity::from_connection(&other_ns, &other.spec.connection);
        if &other_identity != identity {
            continue;
        }

        if let Err(error) = other.spec.validate_password_specs(&other_name) {
            tracing::warn!(
                policy = %format!("{other_ns}/{other_name}"),
                database = %identity.as_str(),
                %error,
                "skipping conflict detection for invalid peer policy"
            );
            continue;
        }

        let other_ownership = match other.spec.ownership_claims() {
            Ok(claims) => claims,
            Err(error) => {
                tracing::warn!(
                    policy = %format!("{other_ns}/{other_name}"),
                    database = %identity.as_str(),
                    %error,
                    "skipping conflict detection for invalid peer policy"
                );
                continue;
            }
        };
        if ownership.overlaps(&other_ownership) {
            let overlap = ownership.overlap_summary(&other_ownership);
            conflicts.push(format!("{other_ns}/{other_name} ({overlap})"));
        }
    }

    if conflicts.is_empty() {
        None
    } else {
        Some(format!(
            "policy ownership overlaps with {} on database target {}",
            conflicts.join(", "),
            identity.as_str()
        ))
    }
}

impl ReconcileError {
    fn reason(&self) -> &'static str {
        match self {
            ReconcileError::ManifestExpansion(_)
            | ReconcileError::InvalidInterval(_, _)
            | ReconcileError::InvalidSpec(_) => "InvalidSpec",
            // A distinct reason rather than the deferred failure's own: it
            // transitions once, when the back-off first engages, and then
            // stays put. Reusing a reason we cannot derive from the recorded
            // string would flip every pass, which is the write storm this
            // back-off exists to stop. The underlying cause is not lost — it
            // is carried verbatim in the message, and so in `last_error`.
            ReconcileError::PlanRetryDeferred(_, _) => "PlanRetryDeferred",
            ReconcileError::ApprovalDigest(_) => "ApprovalDigestFailed",
            ReconcileError::ConflictingPolicy(_) => "ConflictingPolicy",
            ReconcileError::UnsatisfiableWildcardGrant(_) => "UnsatisfiableWildcardGrant",
            ReconcileError::ExecutorAuthority(_) => "ExecutorAuthority",
            ReconcileError::LockContention(_, _) => "LockContention",
            ReconcileError::RequestIndexNotReady(_) => "RequestIndexNotReady",
            ReconcileError::Context(context) => match context.as_ref() {
                ContextError::SecretFetch { .. } => "SecretFetchFailed",
                ContextError::SecretMissing { .. } => "SecretMissing",
                ContextError::GcpAuthHttp { .. }
                | ContextError::GcpAuthRejected { .. }
                | ContextError::GcpAuthInvalidResponse { .. } => "GcpAuthFailed",
                ContextError::DatabaseConnect { .. } => "DatabaseConnectionFailed",
                ContextError::SetRoleFailed { .. } => "SetRoleFailed",
                ContextError::EmptyResolvedValue { .. } => "InvalidConnectionParams",
                ContextError::InvalidDatabaseUrl { .. }
                | ContextError::InvalidResolvedPort { .. } => "InvalidConnectionParams",
                ContextError::InvalidResolvedSslMode { .. } => "InvalidConnectionParams",
            },
            ReconcileError::Inspect(error) => match error {
                pgroles_inspect::InspectError::Database(sql_err) => {
                    match classify_sqlx_error(sql_err) {
                        SqlErrorKind::InsufficientPrivileges => "InsufficientPrivileges",
                        SqlErrorKind::MissingDatabaseObject => "MissingDatabaseObject",
                        SqlErrorKind::Transient => "DatabaseInspectionFailed",
                    }
                }
                pgroles_inspect::InspectError::ScopeNotCovered(_) => "DatabaseInspectionFailed",
                pgroles_inspect::InspectError::DatabaseTargetMismatch { .. } => {
                    "InvalidDatabaseTarget"
                }
            },
            ReconcileError::SqlExec(error) => match classify_sqlx_error(error) {
                SqlErrorKind::InsufficientPrivileges => "InsufficientPrivileges",
                SqlErrorKind::MissingDatabaseObject => "MissingDatabaseObject",
                SqlErrorKind::Transient => "ApplyFailed",
            },
            ReconcileError::UnsafeRoleDrops(_) => "UnsafeRoleDrops",
            ReconcileError::EmptyPasswordSecret { .. } => "InvalidSpec",
            ReconcileError::MissingDatabaseObjects(_) => "MissingDatabaseObject",
            ReconcileError::PasswordGeneration(_) => "SecretFetchFailed",
            ReconcileError::PlanSqlStorage(_) => "PlanSqlStorageFailed",
            ReconcileError::Kube(_) => "KubernetesApiError",
            ReconcileError::ApiStalled(_, _) => "KubernetesApiStalled",
            ReconcileError::NoNamespace => "InvalidResource",
            ReconcileError::PendingEphemeralAccessCleanup(_) => "EphemeralAccessCleanupPending",
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        ConnectionSpec, CrdReconciliationMode, PasswordSpec, PolicyMode, PostgresPolicySpec,
        RoleSpec, SecretReference,
    };
    use k8s_openapi::{
        ByteString, api::core::v1::Secret, apimachinery::pkg::apis::meta::v1::ObjectMeta,
    };
    use sqlx::error::{DatabaseError, ErrorKind};
    use std::borrow::Cow;
    use std::collections::BTreeMap;
    use std::error::Error as StdError;
    use std::fmt;

    fn edge(role: &str, member: &str) -> pgroles_core::model::MembershipEdge {
        pgroles_core::model::MembershipEdge {
            role: role.to_string(),
            member: member.to_string(),
            inherit: true,
            admin: false,
        }
    }

    #[test]
    fn the_overlay_handed_to_candidates_is_only_what_the_overlay_added() {
        let mut declared = pgroles_core::model::RoleGraph::default();
        declared.memberships.insert(edge("app_rw", "service"));

        let mut effective = declared.clone();
        effective.memberships.insert(edge("oncall_admin", "carol"));

        assert_eq!(
            overlay_edges(&declared, &effective),
            vec![edge("oncall_admin", "carol")]
        );
        // A durable membership the policy declares is not an overlay, even
        // though an ephemeral request may also want it — attributing it to the
        // overlay would force fresh review of every candidate that touches it.
        assert!(overlay_edges(&declared, &declared).is_empty());
    }

    #[test]
    fn a_failed_plan_held_in_backoff_is_not_reported_as_awaiting_approval() {
        // Pointing a reviewer at a Failed plan with "awaiting approval" is the
        // bug: there is no decision to make, only a retry window to wait out.
        let backoff = planned_report(
            &crate::plan::PlanCreationResult::DeduplicatedFailed("plan-old".to_string()),
            3,
        );
        assert_eq!(backoff.reason, "PlanFailedRetryBackoff");
        assert!(backoff.message.contains("plan-old"));
        assert!(backoff.message.contains("failed recently"));
        assert!(backoff.message.contains("retry backoff window"));
        assert!(!backoff.message.contains("created;"));

        for result in [
            crate::plan::PlanCreationResult::Created("plan-new".to_string()),
            crate::plan::PlanCreationResult::Deduplicated("plan-new".to_string()),
        ] {
            let report = planned_report(&result, 3);
            assert_eq!(report.reason, "Planned");
            assert!(report.message.contains("plan-new"));
            assert!(report.message.contains("3 change(s) awaiting approval"));
        }
    }

    #[derive(Debug)]
    struct TestDatabaseError {
        message: String,
        code: Option<&'static str>,
    }

    impl fmt::Display for TestDatabaseError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.message)
        }
    }

    impl StdError for TestDatabaseError {}

    impl DatabaseError for TestDatabaseError {
        fn message(&self) -> &str {
            &self.message
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            self.code.map(Cow::Borrowed)
        }

        fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> ErrorKind {
            ErrorKind::Other
        }
    }

    fn insufficient_privilege_sqlx_error() -> sqlx::Error {
        sqlx::Error::Database(Box::new(TestDatabaseError {
            message: "permission denied to create role".to_string(),
            code: Some(SQLSTATE_INSUFFICIENT_PRIVILEGE),
        }))
    }

    fn missing_schema_sqlx_error() -> sqlx::Error {
        sqlx::Error::Database(Box::new(TestDatabaseError {
            message: "schema \"etl\" does not exist".to_string(),
            code: Some(SQLSTATE_INVALID_SCHEMA_NAME),
        }))
    }

    fn missing_table_sqlx_error() -> sqlx::Error {
        sqlx::Error::Database(Box::new(TestDatabaseError {
            message: "relation \"foo\" does not exist".to_string(),
            code: Some(SQLSTATE_UNDEFINED_TABLE),
        }))
    }

    fn missing_function_sqlx_error() -> sqlx::Error {
        sqlx::Error::Database(Box::new(TestDatabaseError {
            message: "function foo() does not exist".to_string(),
            code: Some(SQLSTATE_UNDEFINED_FUNCTION),
        }))
    }

    fn missing_object_sqlx_error() -> sqlx::Error {
        sqlx::Error::Database(Box::new(TestDatabaseError {
            message: "role \"nope\" does not exist".to_string(),
            code: Some(SQLSTATE_UNDEFINED_OBJECT),
        }))
    }

    fn transient_sqlx_error() -> sqlx::Error {
        sqlx::Error::Database(Box::new(TestDatabaseError {
            message: "connection timed out".to_string(),
            code: Some("08006"),
        }))
    }

    fn test_policy(interval: &str, transient_failure_count: i32) -> Arc<PostgresPolicy> {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "db-credentials".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
                require_physical_identity: None,
            },
            interval: interval.to_string(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            default_owner: None,
            profiles: Default::default(),
            schemas: Vec::new(),
            roles: Vec::new(),
            grants: Vec::new(),
            default_privileges: Vec::new(),
            memberships: Vec::new(),
            retirements: Vec::new(),
            approval: None,
        };
        let mut resource = PostgresPolicy::new("example", spec);
        resource.metadata.namespace = Some("default".to_string());
        resource.status = Some(PostgresPolicyStatus {
            transient_failure_count,
            ..Default::default()
        });
        Arc::new(resource)
    }

    fn test_policy_with_spec(name: &str, spec: PostgresPolicySpec) -> PostgresPolicy {
        let mut resource = PostgresPolicy::new(name, spec);
        resource.metadata.namespace = Some("default".to_string());
        resource
    }

    fn valid_role_policy(name: &str, role_name: &str, secret_name: &str) -> PostgresPolicy {
        test_policy_with_spec(
            name,
            PostgresPolicySpec {
                connection: ConnectionSpec {
                    secret_ref: Some(SecretReference {
                        name: secret_name.to_string(),
                    }),
                    secret_key: Some("DATABASE_URL".to_string()),
                    params: None,
                    require_physical_identity: None,
                },
                interval: "5m".to_string(),
                suspend: false,
                mode: PolicyMode::Apply,
                reconciliation_mode: CrdReconciliationMode::default(),
                default_owner: None,
                profiles: Default::default(),
                schemas: Vec::new(),
                roles: vec![RoleSpec {
                    name: role_name.to_string(),
                    external: false,
                    login: Some(true),
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
                    config: Default::default(),
                }],
                grants: Vec::new(),
                default_privileges: Vec::new(),
                memberships: Vec::new(),
                retirements: Vec::new(),
                approval: None,
            },
        )
    }

    fn approval_condition(status: &PostgresPolicyStatus) -> Option<&crate::crd::PolicyCondition> {
        status
            .conditions
            .iter()
            .find(|c| c.condition_type == crate::crd::CONDITION_APPROVAL_UNSET)
    }

    #[test]
    fn approval_deprecation_condition_reports_inference_per_mode() {
        for (mode, expected) in [(PolicyMode::Apply, "auto"), (PolicyMode::Observe, "manual")] {
            let mut policy = valid_role_policy("p", "app", "s");
            policy.spec.mode = mode;
            policy.spec.approval = None;

            let mut status = PostgresPolicyStatus::default();
            apply_approval_deprecation_condition(&policy, &mut status);

            let cond = approval_condition(&status)
                .unwrap_or_else(|| panic!("{mode:?} without approval should set the condition"));
            assert_eq!(cond.status, "True");
            assert!(
                cond.message
                    .as_deref()
                    .is_some_and(|m| m.contains(&format!("inferred as {expected}"))),
                "condition should name the mode-specific inference for {mode:?}"
            );
        }
    }

    #[test]
    fn approval_deprecation_condition_absent_when_field_is_explicit() {
        for approval in [
            crate::crd::ApprovalMode::Auto,
            crate::crd::ApprovalMode::Manual,
        ] {
            let mut policy = valid_role_policy("p", "app", "s");
            policy.spec.approval = Some(approval);

            let mut status = PostgresPolicyStatus::default();
            apply_approval_deprecation_condition(&policy, &mut status);

            assert!(
                approval_condition(&status).is_none(),
                "an explicit approval mode must not be reported as unset"
            );
        }
    }

    #[test]
    fn approval_deprecation_condition_is_cleared_once_the_field_is_set() {
        // The condition is written by an earlier reconcile and must not linger
        // on the object after the user acts on it.
        let mut policy = valid_role_policy("p", "app", "s");
        policy.spec.approval = None;
        let mut status = PostgresPolicyStatus::default();
        apply_approval_deprecation_condition(&policy, &mut status);
        assert!(approval_condition(&status).is_some());

        policy.spec.approval = Some(crate::crd::ApprovalMode::Auto);
        apply_approval_deprecation_condition(&policy, &mut status);
        assert!(
            approval_condition(&status).is_none(),
            "stale condition should be removed when approval becomes explicit"
        );
    }

    #[test]
    fn stale_approval_ignored_condition_cleared_when_leaving_observe_mode() {
        let mut policy = valid_role_policy("p", "app", "s");
        policy.spec.mode = PolicyMode::Observe;
        let mut status = PostgresPolicyStatus::default();
        status.set_condition(crate::crd::approval_ignored_condition("p-plan-1"));

        // Still in observe mode: the observe path owns the condition, leave it alone.
        clear_stale_approval_ignored_condition(&policy, &mut status);
        assert!(
            status
                .conditions
                .iter()
                .any(|c| c.condition_type == crate::crd::CONDITION_APPROVAL_IGNORED),
            "observe mode must keep the condition the observe path maintains"
        );

        // Switched to apply: an approval is honoured now, so the warning is wrong.
        policy.spec.mode = PolicyMode::Apply;
        clear_stale_approval_ignored_condition(&policy, &mut status);
        assert!(
            !status
                .conditions
                .iter()
                .any(|c| c.condition_type == crate::crd::CONDITION_APPROVAL_IGNORED),
            "leaving observe mode must clear the stale warning"
        );
    }

    #[test]
    fn additive_absence_condition_is_set_and_cleared_with_the_unsafe_combination() {
        let mut policy = valid_role_policy("p", "app", "s");
        policy.spec.reconciliation_mode = crate::crd::CrdReconciliationMode::Additive;
        policy.spec.grants.push(pgroles_core::manifest::Grant {
            role: "PUBLIC".to_string(),
            privileges: vec![pgroles_core::manifest::Privilege::Execute],
            object: pgroles_core::manifest::ObjectTarget {
                object_type: pgroles_core::manifest::ObjectType::Function,
                schema: Some("api".to_string()),
                name: Some("*".to_string()),
            },
            ensure: pgroles_core::manifest::Ensure::Absent,
        });
        let mut status = PostgresPolicyStatus::default();

        apply_additive_absence_condition(&policy, &mut status);
        let condition = status
            .conditions
            .iter()
            .find(|condition| {
                condition.condition_type == crate::crd::CONDITION_ABSENCE_ASSERTIONS_IGNORED
            })
            .expect("additive absence assertions should be visible on status");
        assert_eq!(
            condition.reason.as_deref(),
            Some("AdditiveModeNeverRevokes")
        );

        policy.spec.reconciliation_mode = crate::crd::CrdReconciliationMode::Adopt;
        apply_additive_absence_condition(&policy, &mut status);
        assert!(
            status.conditions.iter().all(|condition| {
                condition.condition_type != crate::crd::CONDITION_ABSENCE_ASSERTIONS_IGNORED
            }),
            "leaving additive mode must clear the warning condition"
        );
    }

    #[test]
    fn approval_deprecation_condition_preserves_other_conditions() {
        let mut policy = valid_role_policy("p", "app", "s");
        policy.spec.approval = Some(crate::crd::ApprovalMode::Auto);
        let mut status = PostgresPolicyStatus::default();
        status.set_condition(ready_condition(true, "Reconciled", "All changes applied"));

        apply_approval_deprecation_condition(&policy, &mut status);

        assert!(
            status
                .conditions
                .iter()
                .any(|c| c.condition_type == "Ready"),
            "clearing the deprecation condition must not disturb other conditions"
        );
    }

    fn invalid_profile_policy(name: &str, secret_name: &str) -> PostgresPolicy {
        test_policy_with_spec(
            name,
            PostgresPolicySpec {
                connection: ConnectionSpec {
                    secret_ref: Some(SecretReference {
                        name: secret_name.to_string(),
                    }),
                    secret_key: Some("DATABASE_URL".to_string()),
                    params: None,
                    require_physical_identity: None,
                },
                interval: "5m".to_string(),
                suspend: false,
                mode: PolicyMode::Apply,
                reconciliation_mode: CrdReconciliationMode::default(),
                default_owner: None,
                profiles: Default::default(),
                schemas: vec![pgroles_core::manifest::SchemaBinding {
                    name: "reporting".to_string(),
                    profiles: vec!["missing-profile".to_string()],
                    role_pattern: "{schema}-{profile}".to_string(),
                    owner: None,
                }],
                roles: Vec::new(),
                grants: Vec::new(),
                default_privileges: Vec::new(),
                memberships: Vec::new(),
                retirements: Vec::new(),
                approval: None,
            },
        )
    }

    fn password_role_policy() -> PostgresPolicy {
        test_policy_with_spec(
            "password-policy",
            PostgresPolicySpec {
                connection: ConnectionSpec {
                    secret_ref: Some(SecretReference {
                        name: "db-credentials".to_string(),
                    }),
                    secret_key: Some("DATABASE_URL".to_string()),
                    params: None,
                    require_physical_identity: None,
                },
                interval: "5m".to_string(),
                suspend: false,
                mode: PolicyMode::Apply,
                reconciliation_mode: CrdReconciliationMode::default(),
                default_owner: None,
                profiles: Default::default(),
                schemas: Vec::new(),
                roles: vec![
                    RoleSpec {
                        name: "app".to_string(),
                        external: false,
                        login: Some(true),
                        superuser: None,
                        createdb: None,
                        createrole: None,
                        inherit: None,
                        replication: None,
                        bypassrls: None,
                        connection_limit: None,
                        comment: None,
                        password: Some(PasswordSpec {
                            secret_ref: Some(SecretReference {
                                name: "role-passwords".to_string(),
                            }),
                            secret_key: None,
                            generate: None,
                        }),
                        password_valid_until: None,
                        config: Default::default(),
                    },
                    RoleSpec {
                        name: "reporter".to_string(),
                        external: false,
                        login: Some(true),
                        superuser: None,
                        createdb: None,
                        createrole: None,
                        inherit: None,
                        replication: None,
                        bypassrls: None,
                        connection_limit: None,
                        comment: None,
                        password: Some(PasswordSpec {
                            secret_ref: Some(SecretReference {
                                name: "role-passwords".to_string(),
                            }),
                            secret_key: Some("reporter-password".to_string()),
                            generate: None,
                        }),
                        password_valid_until: None,
                        config: Default::default(),
                    },
                ],
                grants: Vec::new(),
                default_privileges: Vec::new(),
                memberships: Vec::new(),
                retirements: Vec::new(),
                approval: None,
            },
        )
    }

    fn secret_with_keys(name: &str, entries: &[(&str, &str)]) -> Secret {
        secret_with_keys_and_version(name, "1", entries)
    }

    fn secret_with_keys_and_version(
        name: &str,
        resource_version: &str,
        entries: &[(&str, &str)],
    ) -> Secret {
        Secret {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                resource_version: Some(resource_version.to_string()),
                ..Default::default()
            },
            data: Some(
                entries
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), ByteString(value.as_bytes().to_vec())))
                    .collect(),
            ),
            ..Default::default()
        }
    }

    #[test]
    fn parse_interval_minutes() {
        let d = parse_interval("5m").unwrap();
        assert_eq!(d, Duration::from_secs(300));
    }

    #[test]
    fn parse_interval_hours() {
        let d = parse_interval("1h").unwrap();
        assert_eq!(d, Duration::from_secs(3600));
    }

    #[test]
    fn parse_interval_seconds() {
        let d = parse_interval("30s").unwrap();
        assert_eq!(d, Duration::from_secs(30));
    }

    #[test]
    fn parse_interval_compound() {
        let d = parse_interval("1h30m").unwrap();
        assert_eq!(d, Duration::from_secs(5400));
    }

    #[test]
    fn parse_interval_empty_uses_default() {
        let d = parse_interval("").unwrap();
        assert_eq!(d, Duration::from_secs(DEFAULT_REQUEUE_SECS));
    }

    #[test]
    fn parse_interval_bare_number_treated_as_seconds() {
        let d = parse_interval("120").unwrap();
        assert_eq!(d, Duration::from_secs(120));
    }

    #[test]
    fn parse_interval_invalid_unit() {
        let result = parse_interval("5x");
        assert!(result.is_err());
    }

    #[test]
    fn accumulate_summary_counts() {
        use pgroles_core::diff::Change;
        use pgroles_core::model::RoleState;

        let mut summary = ChangeSummary::default();

        accumulate_summary(
            &mut summary,
            &Change::CreateRole {
                name: "test".to_string(),
                state: RoleState {
                    login: true,
                    ..RoleState::default()
                },
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::Grant {
                role: "test".into(),
                object_type: pgroles_core::manifest::ObjectType::Schema,
                schema: None,
                name: Some("public".to_string()),
                privileges: [pgroles_core::manifest::Privilege::Usage]
                    .into_iter()
                    .collect(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::TerminateSessions {
                role: "test".to_string(),
            },
        );

        assert_eq!(summary.roles_created, 1);
        assert_eq!(summary.grants_added, 1);
        assert_eq!(summary.sessions_terminated, 1);
    }

    #[test]
    fn accumulate_summary_counts_schema_changes_separately() {
        use pgroles_core::diff::Change;

        let mut summary = ChangeSummary::default();

        accumulate_summary(
            &mut summary,
            &Change::CreateSchema {
                name: "inventory".to_string(),
                owner: Some("inventory_owner".to_string()),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::AlterSchemaOwner {
                name: "catalog".to_string(),
                owner: "catalog_owner".to_string(),
            },
        );

        assert_eq!(summary.schemas_created, 1);
        assert_eq!(summary.schema_owners_altered, 1);
        assert_eq!(summary.grants_added, 0);
    }

    #[test]
    fn summarize_changes_sets_total() {
        use pgroles_core::diff::Change;
        use pgroles_core::model::RoleState;

        let changes = vec![
            Change::CreateRole {
                name: "test".to_string(),
                state: RoleState::default(),
            },
            Change::CreateSchema {
                name: "inventory".to_string(),
                owner: Some("inventory_owner".to_string()),
            },
            Change::Grant {
                role: "test".into(),
                object_type: pgroles_core::manifest::ObjectType::Schema,
                schema: None,
                name: Some("public".to_string()),
                privileges: [pgroles_core::manifest::Privilege::Usage]
                    .into_iter()
                    .collect(),
            },
        ];

        let summary = summarize_changes(&changes);
        assert_eq!(summary.roles_created, 1);
        assert_eq!(summary.schemas_created, 1);
        assert_eq!(summary.grants_added, 1);
        assert_eq!(summary.total, 3);
    }

    #[test]
    fn accumulate_summary_all_change_types() {
        use pgroles_core::diff::Change;
        use pgroles_core::model::RoleState;

        let mut summary = ChangeSummary::default();

        accumulate_summary(
            &mut summary,
            &Change::CreateRole {
                name: "r1".to_string(),
                state: RoleState::default(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::AlterRole {
                name: "r1".to_string(),
                attributes: vec![pgroles_core::model::RoleAttribute::Login(true)],
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::CreateSchema {
                name: "schema1".to_string(),
                owner: Some("owner1".to_string()),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::AlterSchemaOwner {
                name: "schema2".to_string(),
                owner: "owner2".to_string(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::SetComment {
                name: "r1".to_string(),
                comment: Some("comment".to_string()),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::DropRole {
                name: "r1".to_string(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::TerminateSessions {
                role: "r1".to_string(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::ReassignOwned {
                from_role: "r1".to_string(),
                to_role: "r2".to_string(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::DropOwned {
                role: "r1".to_string(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::Grant {
                role: "r1".into(),
                object_type: pgroles_core::manifest::ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
                privileges: [pgroles_core::manifest::Privilege::Select]
                    .into_iter()
                    .collect(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::Revoke {
                role: "r1".into(),
                object_type: pgroles_core::manifest::ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
                privileges: [pgroles_core::manifest::Privilege::Select]
                    .into_iter()
                    .collect(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::SetDefaultPrivilege {
                scope: pgroles_core::model::DefaultPrivilegeScope::Schema {
                    schema: "public".to_string(),
                },
                owner: "owner".to_string(),
                grantee: "r1".into(),
                on_type: pgroles_core::manifest::ObjectType::Table,
                privileges: [pgroles_core::manifest::Privilege::Select]
                    .into_iter()
                    .collect(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::RevokeDefaultPrivilege {
                scope: pgroles_core::model::DefaultPrivilegeScope::Schema {
                    schema: "public".to_string(),
                },
                owner: "owner".to_string(),
                grantee: "r1".into(),
                on_type: pgroles_core::manifest::ObjectType::Table,
                privileges: [pgroles_core::manifest::Privilege::Select]
                    .into_iter()
                    .collect(),
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::AddMember {
                role: "r1".to_string(),
                member: "r2".to_string(),
                inherit: true,
                admin: false,
            },
        );
        accumulate_summary(
            &mut summary,
            &Change::RemoveMember {
                role: "r1".to_string(),
                member: "r2".to_string(),
            },
        );

        assert_eq!(summary.roles_created, 1);
        // AlterRole + SetComment both increment roles_altered
        assert_eq!(summary.roles_altered, 2);
        assert_eq!(summary.schemas_created, 1);
        assert_eq!(summary.schema_owners_altered, 1);
        assert_eq!(summary.roles_dropped, 1);
        assert_eq!(summary.sessions_terminated, 1);
        assert_eq!(summary.grants_added, 1);
        assert_eq!(summary.grants_revoked, 1);
        assert_eq!(summary.default_privileges_set, 1);
        assert_eq!(summary.default_privileges_revoked, 1);
        assert_eq!(summary.members_added, 1);
        assert_eq!(summary.members_removed, 1);
    }

    #[test]
    fn error_reason_invalid_spec_for_manifest_expansion() {
        let err = ReconcileError::ManifestExpansion(
            pgroles_core::manifest::ManifestError::UndefinedProfile("bad".into(), "schema1".into()),
        );
        assert_eq!(err.reason(), "InvalidSpec");
    }

    #[test]
    fn error_reason_invalid_spec_for_invalid_interval() {
        let err = ReconcileError::InvalidInterval("5x".into(), "unknown unit 'x'".into());
        assert_eq!(err.reason(), "InvalidSpec");
    }

    #[test]
    fn error_reason_invalid_spec_for_password_validation() {
        let err = ReconcileError::InvalidSpec("role password must set exactly one mode".into());
        assert_eq!(err.reason(), "InvalidSpec");
    }

    #[test]
    fn error_reason_missing_database_objects() {
        let err = ReconcileError::MissingDatabaseObjects("schema \"etl\"".into());
        assert_eq!(err.reason(), "MissingDatabaseObject");
    }

    #[test]
    fn error_reason_unsatisfiable_wildcard_grant() {
        let err = ReconcileError::UnsatisfiableWildcardGrant(
            "UnsatisfiableWildcardGrant: function f2() is not grantable".into(),
        );
        assert_eq!(err.reason(), "UnsatisfiableWildcardGrant");
        assert!(err.to_string().contains("UnsatisfiableWildcardGrant"));
    }

    #[test]
    fn unsatisfiable_wildcard_status_is_degraded_without_plan_reference() {
        let message = "UnsatisfiableWildcardGrant: cannot fully satisfy wildcard grant EXECUTE ON function * IN SCHEMA \"app\" TO \"reader\" as executor \"app_owner\"; 1 matching object(s) are missing the desired privilege and are not grantable (examples: \"f2()\" owned by \"definer\" missing [EXECUTE])";
        let mut status = PostgresPolicyStatus {
            conditions: vec![
                ready_condition(true, "Planned", "Plan computed"),
                conflict_condition("ConflictingPolicy", "Policy overlaps another policy"),
                reconciling_condition("Reconciliation in progress"),
                drifted_condition(true, "DriftDetected", "1 planned change pending"),
            ],
            change_summary: Some(ChangeSummary {
                grants_added: 1,
                total: 1,
                ..Default::default()
            }),
            last_error: None,
            transient_failure_count: 3,
            current_plan_ref: Some(crate::crd::PlanReference {
                name: "example-plan".into(),
            }),
            ..Default::default()
        };

        mark_reconcile_failure_status(
            &mut status,
            "UnsatisfiableWildcardGrant",
            message,
            false,
            true,
        );

        let ready = status
            .conditions
            .iter()
            .find(|condition| condition.condition_type == "Ready")
            .expect("Ready condition should be present");
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason.as_deref(), Some("UnsatisfiableWildcardGrant"));
        assert_eq!(ready.message.as_deref(), Some(message));

        let degraded = status
            .conditions
            .iter()
            .find(|condition| condition.condition_type == "Degraded")
            .expect("Degraded condition should be present");
        assert_eq!(degraded.status, "True");
        assert_eq!(
            degraded.reason.as_deref(),
            Some("UnsatisfiableWildcardGrant")
        );
        assert_eq!(degraded.message.as_deref(), Some(message));

        assert!(
            status.conditions.iter().all(|condition| {
                condition.condition_type != "Reconciling"
                    && condition.condition_type != "Drifted"
                    && condition.condition_type != "Conflict"
            }),
            "transient planning and stale conflict conditions should be cleared on degraded status"
        );
        assert!(status.change_summary.is_none());
        assert!(status.current_plan_ref.is_none());
        assert_eq!(status.last_error.as_deref(), Some(message));
        assert_eq!(status.transient_failure_count, 0);
    }

    #[test]
    fn reconcile_failure_status_preserves_plan_reference_when_requested() {
        let mut status = PostgresPolicyStatus {
            current_plan_ref: Some(crate::crd::PlanReference {
                name: "approved-plan".into(),
            }),
            transient_failure_count: 2,
            ..Default::default()
        };

        mark_reconcile_failure_status(
            &mut status,
            "ApplyFailed",
            "SQL execution error: connection closed",
            true,
            false,
        );

        assert_eq!(
            status
                .current_plan_ref
                .as_ref()
                .map(|plan| plan.name.as_str()),
            Some("approved-plan")
        );
        assert_eq!(
            status.last_error.as_deref(),
            Some("SQL execution error: connection closed")
        );
        assert_eq!(status.transient_failure_count, 3);
    }

    #[test]
    fn error_display_missing_database_objects_lists_schemas() {
        let err = ReconcileError::MissingDatabaseObjects("schema \"etl\", schema \"jobs\"".into());
        let msg = err.to_string();
        assert!(msg.contains("schema \"etl\""));
        assert!(msg.contains("schema \"jobs\""));
        assert!(
            msg.contains("pointing at the intended database"),
            "message should include remediation hint"
        );
    }

    #[test]
    fn referenced_schema_names_from_schema_grants() {
        use pgroles_core::manifest::{
            ExpandedManifest, Grant, ObjectTarget, ObjectType, Privilege,
        };
        let expanded = ExpandedManifest {
            schemas: Vec::new(),
            roles: Vec::new(),
            grants: vec![Grant {
                ensure: pgroles_core::manifest::Ensure::Present,
                role: "app".into(),
                privileges: vec![Privilege::Usage],
                object: ObjectTarget {
                    object_type: ObjectType::Schema,
                    schema: None,
                    name: Some("etl".into()),
                },
            }],
            default_privileges: Vec::new(),
            memberships: Vec::new(),
        };
        let names = referenced_schema_names(&expanded);
        assert!(names.contains("etl"));
    }

    #[test]
    fn referenced_schema_names_from_table_grants() {
        use pgroles_core::manifest::{
            ExpandedManifest, Grant, ObjectTarget, ObjectType, Privilege,
        };
        let expanded = ExpandedManifest {
            schemas: Vec::new(),
            roles: Vec::new(),
            grants: vec![Grant {
                ensure: pgroles_core::manifest::Ensure::Present,
                role: "app".into(),
                privileges: vec![Privilege::Select],
                object: ObjectTarget {
                    object_type: ObjectType::Table,
                    schema: Some("analytics".into()),
                    name: Some("*".into()),
                },
            }],
            default_privileges: Vec::new(),
            memberships: Vec::new(),
        };
        let names = referenced_schema_names(&expanded);
        assert!(names.contains("analytics"));
    }

    #[test]
    fn referenced_schema_names_from_default_privileges() {
        use pgroles_core::manifest::{
            DefaultPrivilege, DefaultPrivilegeGrant, ExpandedManifest, ObjectType, Privilege,
        };
        let expanded = ExpandedManifest {
            schemas: Vec::new(),
            roles: Vec::new(),
            grants: Vec::new(),
            default_privileges: vec![DefaultPrivilege {
                scope: None,
                owner: Some("app_owner".into()),
                schema: Some("reporting".to_string()),
                grant: vec![DefaultPrivilegeGrant {
                    ensure: pgroles_core::manifest::Ensure::Present,
                    role: Some("app".into()),
                    privileges: vec![Privilege::Select],
                    on_type: ObjectType::Table,
                }],
            }],
            memberships: Vec::new(),
        };
        let names = referenced_schema_names(&expanded);
        assert!(names.contains("reporting"));
    }

    #[test]
    fn referenced_schema_names_deduplicates_across_sources() {
        use pgroles_core::manifest::{
            DefaultPrivilege, DefaultPrivilegeGrant, ExpandedManifest, Grant, ObjectTarget,
            ObjectType, Privilege,
        };
        let expanded = ExpandedManifest {
            schemas: Vec::new(),
            roles: Vec::new(),
            grants: vec![
                Grant {
                    ensure: pgroles_core::manifest::Ensure::Present,
                    role: "app".into(),
                    privileges: vec![Privilege::Usage],
                    object: ObjectTarget {
                        object_type: ObjectType::Schema,
                        schema: None,
                        name: Some("shared".into()),
                    },
                },
                Grant {
                    ensure: pgroles_core::manifest::Ensure::Present,
                    role: "app".into(),
                    privileges: vec![Privilege::Select],
                    object: ObjectTarget {
                        object_type: ObjectType::Table,
                        schema: Some("shared".into()),
                        name: Some("*".into()),
                    },
                },
            ],
            default_privileges: vec![DefaultPrivilege {
                scope: None,
                owner: Some("app_owner".into()),
                schema: Some("shared".to_string()),
                grant: vec![DefaultPrivilegeGrant {
                    ensure: pgroles_core::manifest::Ensure::Present,
                    role: Some("app".into()),
                    privileges: vec![Privilege::Select],
                    on_type: ObjectType::Table,
                }],
            }],
            memberships: Vec::new(),
        };
        let names = referenced_schema_names(&expanded);
        // BTreeSet deduplicates so a schema referenced three ways appears once.
        assert_eq!(names.len(), 1);
        assert!(names.contains("shared"));
    }

    #[test]
    fn referenced_schema_names_skips_database_and_roleless_grants() {
        use pgroles_core::manifest::{
            ExpandedManifest, Grant, ObjectTarget, ObjectType, Privilege,
        };
        let expanded = ExpandedManifest {
            schemas: Vec::new(),
            roles: Vec::new(),
            grants: vec![Grant {
                ensure: pgroles_core::manifest::Ensure::Present,
                role: "app".into(),
                privileges: vec![Privilege::Connect],
                object: ObjectTarget {
                    object_type: ObjectType::Database,
                    schema: None,
                    name: Some("mydb".into()),
                },
            }],
            default_privileges: Vec::new(),
            memberships: Vec::new(),
        };
        let names = referenced_schema_names(&expanded);
        assert!(
            names.is_empty(),
            "database-level grants should not contribute schema names"
        );
    }

    #[test]
    fn is_system_schema_identifies_pg_and_information_schema() {
        assert!(is_system_schema("pg_catalog"));
        assert!(is_system_schema("pg_toast"));
        assert!(is_system_schema("pg_temp_1"));
        assert!(is_system_schema("information_schema"));
        assert!(!is_system_schema("public"));
        assert!(!is_system_schema("etl"));
        assert!(!is_system_schema("analytics"));
    }

    #[test]
    fn referenced_schema_names_include_declared_schemas() {
        use pgroles_core::manifest::{ExpandedManifest, ExpandedSchema};

        let expanded = ExpandedManifest {
            schemas: vec![ExpandedSchema {
                name: "cdc".into(),
                owner: Some("cdc_owner".into()),
            }],
            roles: Vec::new(),
            grants: Vec::new(),
            default_privileges: Vec::new(),
            memberships: Vec::new(),
        };

        let names = referenced_schema_names(&expanded);
        assert!(names.contains("cdc"));
    }

    #[test]
    fn declared_schema_names_returns_declared_only() {
        use pgroles_core::manifest::{ExpandedManifest, ExpandedSchema};

        let expanded = ExpandedManifest {
            schemas: vec![ExpandedSchema {
                name: "cdc".into(),
                owner: Some("cdc_owner".into()),
            }],
            roles: Vec::new(),
            grants: Vec::new(),
            default_privileges: Vec::new(),
            memberships: Vec::new(),
        };

        let names = declared_schema_names(&expanded);
        assert_eq!(names.len(), 1);
        assert!(names.contains("cdc"));
    }

    #[test]
    fn externally_required_schema_names_excludes_declared_schemas() {
        use pgroles_core::manifest::{
            ExpandedManifest, ExpandedSchema, Grant, ObjectTarget, ObjectType, Privilege,
        };

        let expanded = ExpandedManifest {
            schemas: vec![ExpandedSchema {
                name: "managed".into(),
                owner: Some("managed_owner".into()),
            }],
            roles: Vec::new(),
            grants: vec![
                Grant {
                    ensure: pgroles_core::manifest::Ensure::Present,
                    role: "app".into(),
                    privileges: vec![Privilege::Usage],
                    object: ObjectTarget {
                        object_type: ObjectType::Schema,
                        schema: None,
                        name: Some("managed".into()),
                    },
                },
                Grant {
                    ensure: pgroles_core::manifest::Ensure::Present,
                    role: "app".into(),
                    privileges: vec![Privilege::Select],
                    object: ObjectTarget {
                        object_type: ObjectType::Table,
                        schema: Some("external".into()),
                        name: Some("*".into()),
                    },
                },
            ],
            default_privileges: Vec::new(),
            memberships: Vec::new(),
        };

        let names = externally_required_schema_names(&expanded);
        assert_eq!(names.len(), 1);
        assert!(names.contains("external"));
        assert!(!names.contains("managed"));
    }

    #[test]
    fn error_reason_conflicting_policy() {
        let err = ReconcileError::ConflictingPolicy("overlaps with other".into());
        assert_eq!(err.reason(), "ConflictingPolicy");
    }

    #[test]
    fn requested_reconcile_is_handled_only_after_successful_outcomes() {
        assert!(ReconcileOutcome::Reconciled.marks_requested_reconcile_handled());
        assert!(ReconcileOutcome::Planned.marks_requested_reconcile_handled());
        assert!(!ReconcileOutcome::Suspended.marks_requested_reconcile_handled());
        assert!(!ReconcileOutcome::Conflict.marks_requested_reconcile_handled());
        assert!(!ReconcileOutcome::LockContention.marks_requested_reconcile_handled());
    }

    #[test]
    fn error_reason_unsafe_role_drops() {
        let err = ReconcileError::UnsafeRoleDrops("role owns objects".into());
        assert_eq!(err.reason(), "UnsafeRoleDrops");
    }

    #[test]
    fn error_reason_no_namespace() {
        let err = ReconcileError::NoNamespace;
        assert_eq!(err.reason(), "InvalidResource");
    }

    #[test]
    fn error_reason_context_secret_missing() {
        let err = ReconcileError::Context(Box::new(crate::context::ContextError::SecretMissing {
            name: "pg-secret".into(),
            key: "DATABASE_URL".into(),
        }));
        assert_eq!(err.reason(), "SecretMissing");
    }

    #[test]
    fn error_reason_sql_exec_insufficient_privileges() {
        let err = ReconcileError::SqlExec(insufficient_privilege_sqlx_error());
        assert_eq!(err.reason(), "InsufficientPrivileges");
    }

    #[test]
    fn error_reason_inspect_insufficient_privileges() {
        let err = ReconcileError::Inspect(pgroles_inspect::InspectError::Database(
            insufficient_privilege_sqlx_error(),
        ));
        assert_eq!(err.reason(), "InsufficientPrivileges");
    }

    #[test]
    fn database_target_mismatch_is_a_slow_invalid_target_error() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Inspect(
            pgroles_inspect::InspectError::DatabaseTargetMismatch {
                target: "other".to_string(),
                connected: "current".to_string(),
            },
        ));
        assert_eq!(retry_class(&error), RetryClass::Slow);
        let finalizer::Error::ApplyFailed(error) = error else {
            unreachable!()
        };
        assert_eq!(error.reason(), "InvalidDatabaseTarget");
    }

    #[test]
    fn error_display_includes_details() {
        let err = ReconcileError::InvalidInterval("5x".into(), "unknown unit 'x'".into());
        let msg = err.to_string();
        assert!(msg.contains("5x"), "error display should contain interval");
        assert!(
            msg.contains("unknown unit"),
            "error display should contain reason"
        );
    }

    #[test]
    fn error_reason_lock_contention() {
        let err = ReconcileError::LockContention(
            "prod/db-creds/DATABASE_URL".into(),
            "in-process lock held".into(),
        );
        assert_eq!(err.reason(), "LockContention");
    }

    #[test]
    fn error_display_lock_contention_includes_database() {
        let err = ReconcileError::LockContention(
            "prod/db-creds/DATABASE_URL".into(),
            "advisory lock held by another session".into(),
        );
        let msg = err.to_string();
        assert!(
            msg.contains("prod/db-creds/DATABASE_URL"),
            "lock contention error should include database identity"
        );
        assert!(
            msg.contains("advisory lock"),
            "lock contention error should include reason"
        );
    }

    /// A settled policy retrying the same generation must not re-announce
    /// `Reconciling`.
    ///
    /// This is the self-wake loop that starved the E2E: the exit paths strip
    /// the condition, so announcing it on every retry mutates status twice per
    /// reconcile with no net change, and each mutation is a watch event that
    /// discards the back-off `error_policy` chose.
    #[test]
    fn a_retry_of_a_settled_generation_does_not_re_announce_reconciling() {
        let mut status = PostgresPolicyStatus {
            last_attempted_generation: Some(7),
            ..Default::default()
        };
        status.set_condition(ready_condition(
            false,
            "InsufficientPrivileges",
            "permission denied to create role",
        ));

        assert!(
            !should_announce_reconciling(&status, Some(7)),
            "a retry of an already-attempted generation must not churn the status"
        );
        assert!(
            should_announce_reconciling(&status, Some(8)),
            "a new generation is a new attempt and must announce"
        );
    }

    #[test]
    fn a_policy_that_has_never_settled_always_announces_reconciling() {
        // No Ready condition: the object has never completed a reconcile, so
        // the first-attempt signal is exactly what an operator wants to see.
        let fresh = PostgresPolicyStatus {
            last_attempted_generation: Some(3),
            ..Default::default()
        };
        assert!(should_announce_reconciling(&fresh, Some(3)));

        // A generation the API server never assigned must not be mistaken for
        // "already attempted" against a status that also carries none.
        let unknown_generation = PostgresPolicyStatus::default();
        assert!(should_announce_reconciling(&unknown_generation, None));
    }

    #[test]
    fn requeue_with_jitter_produces_bounded_delay() {
        // Run multiple times to exercise the jitter distribution.
        let base = LOCK_CONTENTION_BASE_SECS;
        let max = LOCK_CONTENTION_BASE_SECS + LOCK_CONTENTION_JITTER_SECS;
        for _ in 0..20 {
            let delay = jitter_delay();
            let secs = delay.as_secs();
            assert!(
                secs >= base,
                "jitter delay {secs}s should be at least base {base}s",
            );
            assert!(
                secs <= max,
                "jitter delay {secs}s should not exceed base+jitter {max}s",
            );
        }
    }

    #[test]
    fn lock_contention_constants_are_reasonable() {
        // Use variables to avoid clippy::assertions_on_constants.
        let base = LOCK_CONTENTION_BASE_SECS;
        let jitter = LOCK_CONTENTION_JITTER_SECS;
        assert!(base > 0, "base delay must be positive");
        assert!(jitter > 0, "jitter window must be positive");
        assert!(
            base + jitter <= 60,
            "total max contention delay should not exceed error_policy's 60s"
        );
    }

    #[test]
    fn transient_backoff_delay_is_bounded_and_caps() {
        for _ in 0..20 {
            let first = transient_backoff_delay(1).as_secs();
            assert!((TRANSIENT_BACKOFF_BASE_SECS..=7).contains(&first));

            let fourth = transient_backoff_delay(4).as_secs();
            assert!((40..=60).contains(&fourth));

            let capped = transient_backoff_delay(10).as_secs();
            assert_eq!(capped, TRANSIENT_BACKOFF_MAX_SECS);
        }
    }

    #[test]
    fn slow_retry_delay_uses_policy_interval() {
        let resource = test_policy("7m", 0);
        assert_eq!(slow_retry_delay(&resource), Duration::from_secs(420));
    }

    #[test]
    fn slow_retry_delay_falls_back_on_invalid_interval() {
        let resource = test_policy("nope", 0);
        assert_eq!(
            slow_retry_delay(&resource),
            Duration::from_secs(DEFAULT_REQUEUE_SECS)
        );
    }

    #[test]
    fn retry_classifies_lock_contention_separately() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::LockContention(
            "default/db-credentials/DATABASE_URL".into(),
            "lock held".into(),
        ));
        assert_eq!(retry_class(&error), RetryClass::LockContention);
    }

    /// A stalled API call must requeue rather than wedge: kube-rs runs at most
    /// one reconcile per object, so an unbounded call holds that object's only
    /// slot and every later trigger — including a plan approval — queues behind
    /// it forever.
    #[test]
    fn a_stalled_api_call_is_a_transient_retry_with_its_own_reason() {
        let error = ReconcileError::ApiStalled("get PostgresPolicy", K8S_CALL_TIMEOUT);
        assert_eq!(error.reason(), "KubernetesApiStalled");
        assert_eq!(
            retry_class(&finalizer::Error::ApplyFailed(error)),
            RetryClass::Transient
        );
    }

    #[tokio::test(start_paused = true)]
    async fn bounded_k8s_call_gives_up_instead_of_waiting_out_the_client_timeout() {
        let stalled = bounded_k8s_call::<(), _>("get PostgresPolicy", async {
            std::future::pending::<Result<(), kube::Error>>().await
        })
        .await;
        assert!(matches!(
            stalled,
            Err(ReconcileError::ApiStalled("get PostgresPolicy", _))
        ));
    }

    #[test]
    fn retry_classifies_invalid_spec_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::InvalidInterval(
            "oops".into(),
            "bad interval".into(),
        ));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_missing_database_objects_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::MissingDatabaseObjects(
            "schema \"etl\"".into(),
        ));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_unsatisfiable_wildcard_grant_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::UnsatisfiableWildcardGrant(
            "UnsatisfiableWildcardGrant: function f2() is not grantable".into(),
        ));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_plan_sql_storage_as_slow() {
        let error =
            finalizer::Error::ApplyFailed(ReconcileError::PlanSqlStorage("gzip failed".into()));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_secret_missing_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::SecretMissing {
                name: "db-credentials".into(),
                key: "DATABASE_URL".into(),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_secret_fetch_not_found_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::SecretFetch {
                name: "db-credentials".into(),
                namespace: "default".into(),
                source: kube::Error::Api(
                    kube::core::Status::failure("secrets \"db-credentials\" not found", "NotFound")
                        .with_code(404)
                        .boxed(),
                ),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_secret_fetch_transport_errors_as_transient() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::SecretFetch {
                name: "db-credentials".into(),
                namespace: "default".into(),
                source: kube::Error::Api(
                    kube::core::Status::failure("internal error", "InternalError")
                        .with_code(500)
                        .boxed(),
                ),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Transient);
    }

    #[test]
    fn retry_classifies_secret_fetch_forbidden_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::SecretFetch {
                name: "db-credentials".into(),
                namespace: "default".into(),
                source: kube::Error::Api(
                    kube::core::Status::failure("forbidden", "Forbidden")
                        .with_code(403)
                        .boxed(),
                ),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_database_connect_as_transient() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::DatabaseConnect {
                source: sqlx::Error::PoolTimedOut,
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Transient);
    }

    #[test]
    fn retry_classifies_set_role_failed_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::SetRoleFailed {
                role: "cloudsqlsuperuser".to_string(),
                source: sqlx::Error::Protocol("permission denied".to_string()),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_sql_exec_insufficient_privilege_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::SqlExec(
            insufficient_privilege_sqlx_error(),
        ));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_inspect_insufficient_privilege_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Inspect(
            pgroles_inspect::InspectError::Database(insufficient_privilege_sqlx_error()),
        ));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn classify_sqlx_error_categories() {
        assert_eq!(
            classify_sqlx_error(&insufficient_privilege_sqlx_error()),
            SqlErrorKind::InsufficientPrivileges
        );
        assert_eq!(
            classify_sqlx_error(&missing_schema_sqlx_error()),
            SqlErrorKind::MissingDatabaseObject
        );
        assert_eq!(
            classify_sqlx_error(&missing_table_sqlx_error()),
            SqlErrorKind::MissingDatabaseObject
        );
        assert_eq!(
            classify_sqlx_error(&missing_function_sqlx_error()),
            SqlErrorKind::MissingDatabaseObject
        );
        assert_eq!(
            classify_sqlx_error(&missing_object_sqlx_error()),
            SqlErrorKind::MissingDatabaseObject
        );
        assert_eq!(
            classify_sqlx_error(&transient_sqlx_error()),
            SqlErrorKind::Transient
        );
    }

    #[test]
    fn retry_classifies_sql_exec_missing_schema_as_slow() {
        let error =
            finalizer::Error::ApplyFailed(ReconcileError::SqlExec(missing_schema_sqlx_error()));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_sql_exec_missing_table_as_slow() {
        let error =
            finalizer::Error::ApplyFailed(ReconcileError::SqlExec(missing_table_sqlx_error()));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_inspect_missing_schema_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Inspect(
            pgroles_inspect::InspectError::Database(missing_schema_sqlx_error()),
        ));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn error_reason_sql_exec_missing_database_object() {
        let err = ReconcileError::SqlExec(missing_schema_sqlx_error());
        assert_eq!(err.reason(), "MissingDatabaseObject");
    }

    #[test]
    fn error_reason_inspect_missing_database_object() {
        let err = ReconcileError::Inspect(pgroles_inspect::InspectError::Database(
            missing_table_sqlx_error(),
        ));
        assert_eq!(err.reason(), "MissingDatabaseObject");
    }

    #[test]
    fn retry_classifies_empty_resolved_value_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::EmptyResolvedValue {
                field: "password".to_string(),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn error_reason_empty_resolved_value() {
        let err =
            ReconcileError::Context(Box::new(crate::context::ContextError::EmptyResolvedValue {
                field: "host".to_string(),
            }));
        assert_eq!(err.reason(), "InvalidConnectionParams");
    }

    #[test]
    fn retry_classifies_invalid_resolved_ssl_mode_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::InvalidResolvedSslMode {
                value: "bogus".to_string(),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn error_reason_invalid_resolved_ssl_mode() {
        let err = ReconcileError::Context(Box::new(
            crate::context::ContextError::InvalidResolvedSslMode {
                value: "bogus".to_string(),
            },
        ));
        assert_eq!(err.reason(), "InvalidConnectionParams");
    }

    #[test]
    fn retry_classifies_gcp_auth_permission_error_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::GcpAuthRejected {
                endpoint: "metadata".to_string(),
                status: 403,
                body: "forbidden".to_string(),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[tokio::test]
    async fn retry_classifies_gcp_auth_http_error_as_transient() {
        let source = reqwest::Client::new()
            .get("http://")
            .send()
            .await
            .expect_err("invalid URL should produce a reqwest error");
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::GcpAuthHttp {
                endpoint: "metadata",
                source,
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Transient);
    }

    #[test]
    fn error_reason_gcp_auth_failure() {
        let err =
            ReconcileError::Context(Box::new(crate::context::ContextError::GcpAuthRejected {
                endpoint: "metadata".to_string(),
                status: 403,
                body: "forbidden".to_string(),
            }));
        assert_eq!(err.reason(), "GcpAuthFailed");
    }

    #[test]
    fn error_reason_sql_exec_transient_is_apply_failed() {
        let err = ReconcileError::SqlExec(transient_sqlx_error());
        assert_eq!(err.reason(), "ApplyFailed");
    }

    #[test]
    fn error_reason_plan_sql_storage_failed() {
        let err = ReconcileError::PlanSqlStorage("gzip failed".into());
        assert_eq!(err.reason(), "PlanSqlStorageFailed");
    }

    #[test]
    fn error_policy_uses_normal_interval_for_invalid_spec() {
        let resource = test_policy("11m", 0);
        let error = finalizer::Error::ApplyFailed(ReconcileError::InvalidInterval(
            "oops".into(),
            "bad interval".into(),
        ));
        assert_eq!(
            retry_action(&resource, &error),
            Action::requeue(Duration::from_secs(660))
        );
    }

    #[test]
    fn error_policy_uses_exponential_backoff_for_transient_failures() {
        let resource = test_policy("5m", 3);
        let error = finalizer::Error::ApplyFailed(ReconcileError::Context(Box::new(
            crate::context::ContextError::DatabaseConnect {
                source: sqlx::Error::PoolTimedOut,
            },
        )));
        let action = retry_action(&resource, &error);
        assert!(
            (40..=60).any(|secs| action == Action::requeue(Duration::from_secs(secs))),
            "expected transient retry between 40s and 60s, got {action:?}"
        );
    }

    #[test]
    fn cleanup_pending_keeps_finalizer_and_uses_bounded_retry() {
        let resource = test_policy("2s", 0);
        let error =
            finalizer::Error::CleanupFailed(ReconcileError::PendingEphemeralAccessCleanup(1));
        assert_eq!(retry_class(&error), RetryClass::CleanupPending);
        assert_eq!(
            retry_action(&resource, &error),
            Action::requeue(Duration::from_secs(10))
        );
    }

    #[test]
    fn error_reason_empty_password_secret() {
        let err = ReconcileError::EmptyPasswordSecret {
            role: "app-svc".to_string(),
            secret: "pg-passwords".to_string(),
            key: "app-svc".to_string(),
        };
        assert_eq!(err.reason(), "InvalidSpec");
    }

    #[test]
    fn retry_classifies_empty_password_secret_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::EmptyPasswordSecret {
            role: "app-svc".to_string(),
            secret: "pg-passwords".to_string(),
            key: "app-svc".to_string(),
        });
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn error_reason_password_generation() {
        let err = ReconcileError::PasswordGeneration(Box::new(
            crate::password::PasswordError::MissingKey {
                secret: "my-secret".to_string(),
                key: "password".to_string(),
            },
        ));
        assert_eq!(err.reason(), "SecretFetchFailed");
    }

    #[test]
    fn retry_classifies_password_generation_missing_key_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::PasswordGeneration(Box::new(
            crate::password::PasswordError::MissingKey {
                secret: "my-secret".to_string(),
                key: "password".to_string(),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn retry_classifies_password_generation_kube_server_error_as_transient() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::PasswordGeneration(Box::new(
            crate::password::PasswordError::KubeApi {
                secret: "my-secret".to_string(),
                source: Box::new(kube::Error::Api(
                    kube::core::Status::failure("internal error", "InternalError")
                        .with_code(500)
                        .boxed(),
                )),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Transient);
    }

    #[test]
    fn retry_classifies_password_generation_kube_forbidden_as_slow() {
        let error = finalizer::Error::ApplyFailed(ReconcileError::PasswordGeneration(Box::new(
            crate::password::PasswordError::KubeApi {
                secret: "my-secret".to_string(),
                source: Box::new(kube::Error::Api(
                    kube::core::Status::failure("forbidden", "Forbidden")
                        .with_code(403)
                        .boxed(),
                )),
            },
        )));
        assert_eq!(retry_class(&error), RetryClass::Slow);
    }

    #[test]
    fn accumulate_summary_counts_passwords() {
        use pgroles_core::diff::Change;

        let mut summary = ChangeSummary::default();
        accumulate_summary(
            &mut summary,
            &Change::SetPassword {
                name: "app-svc".to_string(),
                password: "secret".to_string(),
            },
        );
        assert_eq!(summary.passwords_set, 1);
    }

    #[test]
    fn conflict_detection_ignores_invalid_peer_policies() {
        let resource = valid_role_policy("valid-policy", "analytics", "shared-db-secret");
        let identity = DatabaseIdentity::from_connection("default", &resource.spec.connection);
        let ownership = resource.spec.ownership_claims().unwrap();
        let invalid_peer = invalid_profile_policy("invalid-peer", "shared-db-secret");

        let conflict =
            detect_policy_conflict_in_list(&resource, &identity, &ownership, vec![invalid_peer]);

        assert_eq!(conflict, None);
    }

    #[test]
    fn resolve_passwords_from_cached_secrets_supports_default_and_explicit_keys() {
        let resource = password_role_policy();
        let cache = BTreeMap::from([(
            "role-passwords".to_string(),
            secret_with_keys(
                "role-passwords",
                &[
                    ("app", "app-secret"),
                    ("reporter-password", "reporter-secret"),
                ],
            ),
        )]);

        let resolved =
            resolve_passwords_from_cached_secrets(&resource, &cache).expect("should resolve");

        assert_eq!(
            resolved
                .get("app")
                .map(|password| password.cleartext.as_str()),
            Some("app-secret")
        );
        assert_eq!(
            resolved
                .get("reporter")
                .map(|password| password.cleartext.as_str()),
            Some("reporter-secret")
        );
    }

    #[test]
    fn resolve_passwords_from_cached_secrets_skips_external_roles() {
        let mut resource = password_role_policy();
        resource.spec.roles[1].external = true;
        let cache = BTreeMap::from([(
            "role-passwords".to_string(),
            secret_with_keys("role-passwords", &[("app", "app-secret")]),
        )]);

        let resolved =
            resolve_passwords_from_cached_secrets(&resource, &cache).expect("should resolve");

        assert_eq!(
            resolved
                .get("app")
                .map(|password| password.cleartext.as_str()),
            Some("app-secret")
        );
        assert!(!resolved.contains_key("reporter"));
    }

    #[test]
    fn resolve_passwords_from_cached_secrets_reports_missing_key() {
        let resource = password_role_policy();
        let cache = BTreeMap::from([(
            "role-passwords".to_string(),
            secret_with_keys("role-passwords", &[("app", "app-secret")]),
        )]);

        let err = resolve_passwords_from_cached_secrets(&resource, &cache).unwrap_err();
        let context = match err {
            ReconcileError::Context(context) => context,
            other => panic!("expected context error, got {other:?}"),
        };
        assert!(matches!(
            *context,
            crate::context::ContextError::SecretMissing { ref name, ref key }
            if name == "role-passwords" && key == "reporter-password"
        ));
    }

    #[test]
    fn resolve_passwords_from_cached_secrets_reports_empty_password() {
        let resource = password_role_policy();
        let cache = BTreeMap::from([(
            "role-passwords".to_string(),
            secret_with_keys(
                "role-passwords",
                &[("app", ""), ("reporter-password", "ok")],
            ),
        )]);

        let err = resolve_passwords_from_cached_secrets(&resource, &cache).unwrap_err();
        assert!(matches!(
            err,
            ReconcileError::EmptyPasswordSecret { ref role, ref secret, ref key }
            if role == "app" && secret == "role-passwords" && key == "app"
        ));
    }

    #[test]
    fn resolve_passwords_from_cached_secrets_allows_whitespace_passwords() {
        let resource = password_role_policy();
        let cache = BTreeMap::from([(
            "role-passwords".to_string(),
            secret_with_keys(
                "role-passwords",
                &[("app", "   "), ("reporter-password", "\tsecret")],
            ),
        )]);

        let resolved =
            resolve_passwords_from_cached_secrets(&resource, &cache).expect("should resolve");

        assert_eq!(
            resolved
                .get("app")
                .map(|password| password.cleartext.as_str()),
            Some("   ")
        );
        assert_eq!(
            resolved
                .get("reporter")
                .map(|password| password.cleartext.as_str()),
            Some("\tsecret")
        );
    }

    #[test]
    fn select_password_changes_skips_unchanged_password_sources() {
        let resolved = BTreeMap::from([(
            "app".to_string(),
            ResolvedPassword::existing(
                "app-secret".to_string(),
                "role-passwords:app:7".to_string(),
            ),
        )]);
        let status = PostgresPolicyStatus {
            applied_password_source_versions: BTreeMap::from([(
                "app".to_string(),
                "role-passwords:app:7".to_string(),
            )]),
            ..Default::default()
        };

        let (password_changes, current_versions) =
            select_password_changes(&[], &resolved, Some(&status));

        assert!(password_changes.is_empty());
        assert_eq!(
            current_versions.get("app").map(String::as_str),
            Some("role-passwords:app:7")
        );
    }

    #[test]
    fn select_password_changes_applies_on_source_version_change() {
        let resolved = BTreeMap::from([(
            "app".to_string(),
            ResolvedPassword::existing(
                "new-secret".to_string(),
                "role-passwords:app:8".to_string(),
            ),
        )]);
        let status = PostgresPolicyStatus {
            applied_password_source_versions: BTreeMap::from([(
                "app".to_string(),
                "role-passwords:app:7".to_string(),
            )]),
            ..Default::default()
        };

        let (password_changes, _) = select_password_changes(&[], &resolved, Some(&status));

        assert_eq!(
            password_changes.get("app").map(String::as_str),
            Some("new-secret")
        );
    }

    #[test]
    fn select_password_changes_applies_for_newly_created_role() {
        use pgroles_core::diff::Change;
        use pgroles_core::model::RoleState;

        let resolved = BTreeMap::from([(
            "app".to_string(),
            ResolvedPassword::existing(
                "new-secret".to_string(),
                "role-passwords:app:7".to_string(),
            ),
        )]);
        let status = PostgresPolicyStatus {
            applied_password_source_versions: BTreeMap::from([(
                "app".to_string(),
                "role-passwords:app:7".to_string(),
            )]),
            ..Default::default()
        };
        let changes = vec![Change::CreateRole {
            name: "app".to_string(),
            state: RoleState {
                login: true,
                ..RoleState::default()
            },
        }];

        let (password_changes, _) = select_password_changes(&changes, &resolved, Some(&status));

        assert_eq!(
            password_changes.get("app").map(String::as_str),
            Some("new-secret")
        );
    }

    #[test]
    fn select_password_changes_applies_all_on_first_reconcile() {
        // When status is None (first reconcile), all passwords should be applied
        // since there are no previous source versions to compare against.
        let resolved = BTreeMap::from([
            (
                "app".to_string(),
                ResolvedPassword::existing(
                    "secret-a".to_string(),
                    "role-passwords:app:1".to_string(),
                ),
            ),
            (
                "reporter".to_string(),
                ResolvedPassword::existing(
                    "secret-b".to_string(),
                    "role-passwords:reporter:1".to_string(),
                ),
            ),
        ]);
        let changes: Vec<pgroles_core::diff::Change> = vec![];

        let (password_changes, versions) = select_password_changes(&changes, &resolved, None);

        assert_eq!(
            password_changes.len(),
            2,
            "all passwords should be applied on first reconcile"
        );
        assert_eq!(
            password_changes.get("app").map(String::as_str),
            Some("secret-a")
        );
        assert_eq!(
            password_changes.get("reporter").map(String::as_str),
            Some("secret-b")
        );
        assert_eq!(versions.len(), 2, "all source versions should be tracked");
    }

    fn pending_generated(cleartext: &str, secret: &str) -> ResolvedPassword {
        ResolvedPassword {
            cleartext: cleartext.to_string(),
            source_version: crate::password::missing_generated_secret_source_version(
                secret, "password",
            ),
            pending_materialization: Some(PendingGeneratedSecret {
                role: "app".to_string(),
                spec: crate::crd::GeneratePasswordSpec {
                    length: None,
                    secret_name: Some(secret.to_string()),
                    secret_key: None,
                },
            }),
        }
    }

    #[test]
    fn select_password_changes_always_applies_unmaterialized_generated_passwords() {
        // Deferred materialization records a `:missing` sentinel while the plan
        // is pending. If a sentinel ever survives into status, the password it
        // stood for was never written to any database, so re-seeing the same
        // sentinel must still apply — not be treated as "unchanged".
        let resolved = BTreeMap::from([(
            "app".to_string(),
            pending_generated("in-memory", "policy-pgr-app"),
        )]);
        let status = PostgresPolicyStatus {
            applied_password_source_versions: BTreeMap::from([(
                "app".to_string(),
                crate::password::missing_generated_secret_source_version(
                    "policy-pgr-app",
                    "password",
                ),
            )]),
            ..Default::default()
        };

        let (password_changes, _) = select_password_changes(&[], &resolved, Some(&status));

        assert_eq!(
            password_changes.get("app").map(String::as_str),
            Some("in-memory"),
            "an unmaterialized generated password must always be applied"
        );
    }

    #[test]
    fn materialized_source_version_suppresses_the_next_password_change() {
        // The regression this guards: planning records the `:missing` sentinel,
        // execution creates the Secret. If status kept the sentinel, the next
        // reconcile would see a different (now real) source version, emit a
        // spurious SetPassword, and demand a second approval. Recording the
        // post-materialization version instead makes the next reconcile quiet.
        let mut versions = BTreeMap::from([(
            "app".to_string(),
            crate::password::missing_generated_secret_source_version("policy-pgr-app", "password"),
        )]);
        // Stand-in for `materialize_pending_generated_secrets` overwriting the
        // sentinel with what the created Secret reported.
        versions.insert("app".to_string(), "policy-pgr-app:password:512".to_string());

        let status = PostgresPolicyStatus {
            applied_password_source_versions: versions,
            ..Default::default()
        };
        // Next reconcile: the Secret now exists, so resolution reads it.
        let resolved = BTreeMap::from([(
            "app".to_string(),
            ResolvedPassword::existing(
                "from-secret".to_string(),
                "policy-pgr-app:password:512".to_string(),
            ),
        )]);

        let (password_changes, _) = select_password_changes(&[], &resolved, Some(&status));

        assert!(
            password_changes.is_empty(),
            "recording the materialized version must not re-emit SetPassword"
        );
    }

    #[test]
    fn recorded_real_source_version_is_detected_for_disappeared_secret() {
        let mut resource = valid_role_policy("policy", "app", "shared-db-secret");
        let sentinel =
            crate::password::missing_generated_secret_source_version("policy-pgr-app", "password");
        resource.status = Some(PostgresPolicyStatus {
            applied_password_source_versions: BTreeMap::from([(
                "app".to_string(),
                "policy-pgr-app:password:41".to_string(),
            )]),
            ..Default::default()
        });
        assert!(
            recorded_source_version_was_real(&resource, "app", &sentinel),
            "a real recorded version plus a missing Secret means the Secret disappeared"
        );

        resource
            .status
            .as_mut()
            .unwrap()
            .applied_password_source_versions
            .insert("app".to_string(), sentinel.clone());
        assert!(
            !recorded_source_version_was_real(&resource, "app", &sentinel),
            "a recorded sentinel is not a disappeared Secret"
        );
    }

    #[test]
    fn conflict_detection_still_reports_overlapping_valid_peers() {
        let resource = valid_role_policy("valid-policy", "analytics", "shared-db-secret");
        let identity = DatabaseIdentity::from_connection("default", &resource.spec.connection);
        let ownership = resource.spec.ownership_claims().unwrap();
        let overlapping_peer =
            valid_role_policy("overlapping-peer", "analytics", "shared-db-secret");
        let invalid_peer = invalid_profile_policy("invalid-peer", "shared-db-secret");

        let conflict = detect_policy_conflict_in_list(
            &resource,
            &identity,
            &ownership,
            vec![invalid_peer, overlapping_peer],
        );

        let conflict = conflict.expect("expected overlapping peer to be reported");
        assert!(conflict.contains("overlapping-peer"));
        assert!(conflict.contains("roles: analytics"));
    }

    #[test]
    fn parse_rfc3339_to_epoch_secs_known_timestamp() {
        // 2024-01-01T00:00:00Z = 1704067200
        let result = parse_rfc3339_to_epoch_secs("2024-01-01T00:00:00Z");
        assert_eq!(result, Some(1704067200));
    }

    #[test]
    fn parse_rfc3339_to_epoch_secs_with_time() {
        // 2024-01-01T12:30:45Z = 1704067200 + 12*3600 + 30*60 + 45 = 1704112245
        let result = parse_rfc3339_to_epoch_secs("2024-01-01T12:30:45Z");
        assert_eq!(result, Some(1704112245));
    }

    #[test]
    fn parse_rfc3339_to_epoch_secs_invalid_returns_none() {
        assert_eq!(parse_rfc3339_to_epoch_secs("not-a-date"), None);
        assert_eq!(parse_rfc3339_to_epoch_secs(""), None);
    }

    #[test]
    fn parse_rfc3339_roundtrips_with_now_rfc3339() {
        let timestamp = crate::crd::now_rfc3339();
        let parsed = parse_rfc3339_to_epoch_secs(&timestamp);
        assert!(parsed.is_some(), "should parse our own timestamps");
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Should be within 2 seconds of now.
        let diff = now_secs.abs_diff(parsed.unwrap());
        assert!(diff <= 2, "parsed time should be close to now, diff={diff}");
    }
}
