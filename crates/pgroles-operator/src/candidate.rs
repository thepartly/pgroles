//! `PostgresPolicyCandidate` lifecycle: planning, revalidation, retention.
//!
//! A candidate is a one-shot, immutable proposal of policy content. The
//! operator plans it **inside the parent policy's reconcile**, under the same
//! locks and with the same credentials, after the policy's own enforcement or
//! planning has completed — so the candidate is compared against
//! post-enforcement reality rather than against drift the policy was about to
//! remove anyway.
//!
//! Two properties shape everything here.
//!
//! **Planning writes nothing.** A candidate never issues SQL and never
//! materialises a generated-password Secret: `password.generate` resolves
//! through the same read-only path the policy uses (#181), so an unmaterialised
//! generated password contributes the `:missing` sentinel to the plan's digest
//! and the Secret itself is created only when a *policy* executes. The only
//! writes candidate planning performs are to the candidate's own status and to
//! the plan it owns. [`candidate_password_changes`] is the seam that holds this
//! line, and `candidate_planning_never_materialises_secrets` tests it.
//!
//! **Candidates never open their own connections.** They plan on the pool the
//! parent's reconcile already holds. The single exception is an explicit
//! `spec.target` override, which is a *preview* of a migration destination:
//! credentials, locking and the plan's bound target identity all follow the
//! override, which is exactly why such a plan can never be promoted onto the
//! current target.
//!
//! **One inspection per target per reconcile.** Planning N candidates used to
//! cost N full database inspections, all inside the parent's critical section,
//! so enforcement latency for the *live* policy degraded in proportion to how
//! many people were proposing changes to it. It now costs one: every
//! candidate's inspection scope is computed up front (purely, from its content
//! — see [`candidate_inputs`]), the scopes are unioned, the database is read
//! once, and each candidate derives its own scoped inspection from that read
//! in memory. Deriving is *not* reusing the parent's snapshot: a candidate's
//! scope, wildcard expansion and diagnostics are its own, and
//! `RawInspection::derive` refuses a scope the read does not cover rather than
//! answering narrowly. Candidates with a `spec.target` override are a
//! different database and still inspect for themselves.
//!
//! See `docs/src/pages/docs/operator-candidates.md` for the behaviour and
//! `docs/design/adr-001-candidate-api.md` (Decisions 3 and 6) for the
//! ownership and overlay-overlap rules.

use std::collections::{BTreeMap, BTreeSet};

use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
// Re-exported by k8s-openapi, which is where `creation_timestamp` gets its
// type from — so comparing against it needs no new dependency.
use k8s_openapi::jiff::{SignedDuration, Timestamp};
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams};
use kube::{Resource, ResourceExt};
use tracing::info;

use pgroles_core::model::MembershipEdge;
use pgroles_core::overlap::{
    EffectPair, describe_pair, effect_pairs, intersecting_pairs, membership_overlay_pairs,
};

use crate::context::OperatorContext;
use crate::crd::{
    CandidatePhase, CandidateTarget, ConnectionSpec, DatabaseIdentity, PlanPhase, PlanReference,
    PolicyCondition, PostgresPolicy, PostgresPolicyCandidate, PostgresPolicyCandidateStatus,
    PostgresPolicyPlan, SecretReference, candidate_reason, is_retention_exempt, ready_condition,
    set_condition_in, superseded_condition,
};
use crate::plan::{CandidatePlanBinding, SupersedeCause};
use crate::reconciler::{ReconcileError, ResolvedPassword};

/// Maximum terminal candidates retained per policy before the oldest are
/// pruned. Deleting a candidate cascades to the plan it owns and to that
/// plan's SQL ConfigMap — which is why this flat bound governs only
/// candidates whose plans never executed. A candidate owning an `Applied`
/// plan is held to [`crate::plan::PlanRetention`]'s applied bounds instead,
/// so proposal churn cannot delete execution history through the owner
/// object (see [`terminal_candidates_to_prune`]).
const DEFAULT_MAX_TERMINAL_CANDIDATES: usize = 10;

/// Maximum *open* candidates per policy that are planned in one pass.
///
/// Distinct from [`DEFAULT_MAX_TERMINAL_CANDIDATES`], which prunes what is
/// already finished. This bounds work that has not happened yet: a CI loop
/// filing a candidate per push can otherwise unbound the planning the parent
/// does under its locks. Candidates past the budget are not deleted — they are
/// somebody's proposal — they are left unplanned with a `Ready=False` reason
/// that says so.
const DEFAULT_MAX_OPEN_CANDIDATES: usize = 32;

/// How long an undecided candidate stays open before it is treated as
/// abandoned rather than under review.
///
/// Deliberately measured from creation and nothing else. Consulting each
/// candidate's plan for a decision would reintroduce per-candidate I/O in the
/// parent's critical section, which is the cost this whole area exists to
/// bound. Two weeks is long enough that an approved-but-unmerged proposal has
/// stopped being in flight; `pgroles.io/keep=true` is the escape hatch for one
/// that genuinely is.
const DEFAULT_OPEN_CANDIDATE_TTL: SignedDuration = SignedDuration::from_hours(14 * 24);

// ---------------------------------------------------------------------------
// The parent gate
// ---------------------------------------------------------------------------

/// Why the parent policy is not in a state a candidate can be planned against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockCause {
    /// The policy has changes of its own that have not executed — it is
    /// awaiting a decision, or in `mode: observe` where it never executes.
    AwaitingDecision,
    /// The policy's reconcile did not converge: failing, suspended, in
    /// conflict, or blocked on target identity.
    Unstable,
}

impl BlockCause {
    fn message(self) -> &'static str {
        match self {
            BlockCause::AwaitingDecision => {
                "the active policy has changes of its own awaiting a decision, so this candidate \
                 would be planned against a state the database is not in yet"
            }
            BlockCause::Unstable => {
                "the active policy is not converging, so there is no post-enforcement state to \
                 plan this candidate against"
            }
        }
    }
}

/// Whether the parent's just-finished reconcile permits candidate planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentGate {
    Stable,
    Blocked(BlockCause),
}

/// Decide the gate from the two facts the parent's reconcile leaves behind.
///
/// The spec says a candidate is blocked when the parent "is failing or awaiting
/// its own approval". That maps onto two observable facts and nothing else:
/// the reconcile reached a converged outcome, and no plan of the policy's own
/// is still actionable. `mode: observe` therefore blocks candidates exactly
/// while it holds pending changes, and lets them through when it is in sync —
/// which is the honest reading, since an observe-mode policy never executes
/// and its "post-enforcement state" is simply the database as it stands.
pub fn parent_gate(converged: bool, has_actionable_plan: bool) -> ParentGate {
    if !converged {
        ParentGate::Blocked(BlockCause::Unstable)
    } else if has_actionable_plan {
        ParentGate::Blocked(BlockCause::AwaitingDecision)
    } else {
        ParentGate::Stable
    }
}

// ---------------------------------------------------------------------------
// Planning inputs
// ---------------------------------------------------------------------------

/// Everything candidate planning borrows from the parent's reconcile.
pub struct CandidatePlanning<'a> {
    /// The pool the parent's reconcile holds, under both of its locks.
    pub pool: &'a sqlx::PgPool,
    pub identity: &'a DatabaseIdentity,
    pub target_identity: &'a pgroles_core::approval::TargetIdentity,
    /// Membership edges contributed by active ephemeral overlays — the
    /// difference between the policy's effective and declared desired graphs.
    pub overlay_edges: &'a [MembershipEdge],
    pub gate: ParentGate,
}

/// What planning one candidate produced.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CandidateOutcome {
    /// A plan exists (fresh or deduplicated) holding these effects.
    Planned { plan_name: String, changes: i32 },
    /// The content produces no changes at all — nothing to review.
    NoEffects,
    /// A plan exists, but an ephemeral overlay touches the same
    /// `(role, object)` pairs, so it must be reviewed afresh.
    OverlayOverlap {
        plan_name: String,
        changes: i32,
        overlapping: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// Open-candidate admission: TTL and budget
// ---------------------------------------------------------------------------

/// Why an open candidate is not being planned this pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotPlanned {
    /// Undecided past the TTL: abandoned, not under review. Terminal.
    Expired,
    /// Past the open-candidate budget. Not terminal: it plans as soon as
    /// enough of its elders finish.
    OverBudget,
}

/// Decide, for every candidate, whether it is planned this pass.
///
/// Pure — takes `now` rather than reading the clock — so the policy is
/// unit-testable without a cluster, and computed before the shared inspection
/// so that a candidate which will not be planned does not widen the read.
///
/// TTL is applied first: expiring an abandoned proposal frees budget for a
/// live one. The budget then keeps the *oldest* survivors, which is the
/// deliberate choice — the failure this bounds is a runaway loop filing new
/// candidates, and evicting the newest protects proposals already under review
/// from being pushed out by the flood. A candidate labelled
/// `pgroles.io/keep=true` is exempt from both, and is still counted against
/// the budget so the exemption cannot be used to enlarge it.
fn classify_open_candidates(
    candidates: &[PostgresPolicyCandidate],
    now: Timestamp,
) -> BTreeMap<String, NotPlanned> {
    let mut verdicts = BTreeMap::new();
    let mut budget_remaining = DEFAULT_MAX_OPEN_CANDIDATES;

    // `candidates` is already sorted oldest-first by the caller, which is what
    // makes "keep the oldest" a single pass.
    for candidate in candidates {
        if candidate_phase(candidate).is_terminal() {
            continue;
        }
        let exempt = is_retention_exempt(candidate);

        let expired = !exempt
            && candidate
                .metadata
                .creation_timestamp
                .as_ref()
                .is_some_and(|created| {
                    // `Timestamp - Timestamp` yields a calendar `Span`;
                    // `duration_since` is the fixed-length difference, which is
                    // what a TTL wants.
                    now.duration_since(created.0) > DEFAULT_OPEN_CANDIDATE_TTL
                });
        if expired {
            verdicts.insert(candidate.name_any(), NotPlanned::Expired);
            continue;
        }

        if budget_remaining > 0 {
            budget_remaining -= 1;
        } else {
            // The keep label exempts a candidate from the TTL, not from the
            // budget. Exempting it here would make the label a way to opt out
            // of the bound entirely — 40 kept candidates would plan all 40 —
            // which is the cost this function exists to hold down.
            verdicts.insert(candidate.name_any(), NotPlanned::OverBudget);
        }
    }

    verdicts
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Plan every non-terminal candidate of `policy`, then run candidate retention.
///
/// Called from the parent's reconcile while its locks are still held. Failures
/// planning one candidate are recorded on that candidate and never abort the
/// parent's reconcile: a proposal is not allowed to break enforcement.
pub async fn reconcile_candidates(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
    planning: &CandidatePlanning<'_>,
) -> Result<(), ReconcileError> {
    let namespace = policy.namespace().ok_or(ReconcileError::NoNamespace)?;
    let policy_name = policy.name_any();
    let candidates_api: Api<PostgresPolicyCandidate> =
        Api::namespaced(ctx.kube_client.clone(), &namespace);

    let mut candidates: Vec<PostgresPolicyCandidate> = candidates_api
        .list(&ListParams::default())
        .await?
        .into_iter()
        .filter(|candidate| candidate_belongs_to(candidate, policy))
        .collect();
    if candidates.is_empty() {
        return Ok(());
    }
    // Oldest first, so `spec.replaces` chains settle in the order they were
    // filed rather than in whatever order the API server returned.
    candidates.sort_by(|a, b| {
        a.metadata
            .creation_timestamp
            .cmp(&b.metadata.creation_timestamp)
            .then_with(|| a.name_any().cmp(&b.name_any()))
    });

    let overlay_pairs = membership_overlay_pairs(planning.overlay_edges);

    // Which candidates are not planned this pass — abandoned past the TTL, or
    // past the open-candidate budget. Decided before the shared read so an
    // unplanned candidate does not widen it.
    let not_planned = classify_open_candidates(&candidates, Timestamp::now());

    // One database read for the whole pass, over the union of every
    // candidate's scope, taken before the loop so N candidates cost one
    // inspection instead of N while the parent's locks are held.
    let shared = shared_inspection(planning, &candidates, &not_planned).await;

    for candidate in &mut candidates {
        // First touch: adopt the candidate and stamp the identity everything
        // downstream is compared against, before any planning can fail.
        if let Err(err) = adopt_candidate(ctx, policy, candidate).await {
            tracing::warn!(
                candidate = %candidate.name_any(),
                %err,
                "failed to adopt candidate; skipping this cycle"
            );
            continue;
        }

        if candidate_phase(candidate).is_terminal() {
            continue;
        }

        // Not planned this pass: abandoned, or queued behind its elders.
        match not_planned.get(&candidate.name_any()) {
            Some(NotPlanned::Expired) => {
                mark_superseded(
                    ctx,
                    candidate,
                    candidate_reason::EXPIRED,
                    &format!(
                        "no decision within {} days of being filed, so this proposal is \
                         treated as abandoned; file a successor to revive it, or label \
                         it pgroles.io/keep=true to exempt it",
                        DEFAULT_OPEN_CANDIDATE_TTL.as_hours() / 24
                    ),
                )
                .await?;
                continue;
            }
            Some(NotPlanned::OverBudget) => {
                mark_over_budget(ctx, candidate).await?;
                continue;
            }
            None => {}
        }

        // A denied plan is terminal for the candidate too: it has no other
        // plan coming, and the revision is a successor object. A failure to
        // *read* the plans is handled like a failed adoption — logged, this
        // candidate skipped — because a proposal must never abort the parent's
        // pass over its siblings.
        let denied = match plan_was_denied(ctx, candidate, &namespace).await {
            Ok(denied) => denied,
            Err(err) => {
                tracing::warn!(
                    candidate = %candidate.name_any(),
                    %err,
                    "failed to read this candidate's plans; skipping this cycle"
                );
                continue;
            }
        };
        if denied {
            mark_superseded(
                ctx,
                candidate,
                candidate_reason::PLAN_DENIED,
                "the plan for this candidate was denied; file a successor to propose a revision",
            )
            .await?;
            continue;
        }

        if let ParentGate::Blocked(cause) = planning.gate {
            block_candidate(ctx, candidate, cause).await?;
            continue;
        }

        let planning_started_at = std::time::Instant::now();
        let outcome =
            plan_candidate(ctx, policy, candidate, planning, &overlay_pairs, &shared).await;
        ctx.observability
            .record_candidate_planning(planning_started_at.elapsed());
        match outcome {
            Ok(outcome) => {
                record_outcome(ctx, candidate, outcome).await?;
            }
            Err(err) => {
                let message = err.to_string();
                tracing::warn!(
                    candidate = %candidate.name_any(),
                    policy = %policy_name,
                    %message,
                    "failed to plan candidate"
                );
                write_status(ctx, candidate, |status| {
                    set_condition_in(
                        &mut status.conditions,
                        ready_condition(false, candidate_reason::PLANNING_FAILED, &message),
                    );
                })
                .await?;
                crate::events::publish_candidate_event(
                    &ctx.event_recorder,
                    candidate,
                    true,
                    candidate_reason::PLANNING_FAILED,
                    message,
                )
                .await
                .ok();
            }
        }
    }

    ctx.observability.record_candidate_inspections(
        shared
            .inspections
            .load(std::sync::atomic::Ordering::Relaxed),
        shared.plannable,
    );

    // Supersession is explicit and only takes effect once the successor has a
    // plan of its own: marking the predecessor earlier would leave a reviewer
    // with neither a live proposal nor a reviewable replacement.
    apply_replacements(ctx, &candidates).await?;

    cleanup_terminal_candidates(ctx, &namespace, &candidates).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// Planning one candidate
// ---------------------------------------------------------------------------

/// Everything planning one candidate derives from its content alone.
///
/// Pure: no I/O, no clock, no Kubernetes. That is what lets the candidate pass
/// compute every candidate's inspection scope up front, union them, and read
/// the database once — see [`shared_inspection`].
struct CandidateInputs {
    manifest: pgroles_core::manifest::PolicyManifest,
    expanded: pgroles_core::manifest::ExpandedManifest,
    desired: pgroles_core::model::RoleGraph,
    inspect_config: pgroles_inspect::InspectConfig,
}

fn candidate_inputs(
    candidate: &PostgresPolicyCandidate,
    overlay_edges: &[MembershipEdge],
) -> Result<CandidateInputs, ReconcileError> {
    let manifest = candidate.spec.content.to_policy_manifest();
    let expanded = pgroles_core::manifest::expand_manifest(&manifest)?;
    let mut desired = pgroles_core::model::RoleGraph::from_expanded(
        &expanded,
        manifest.default_owner.as_deref(),
    )?;

    // Compose the same ephemeral overlay the policy composed. Without it an
    // authoritative candidate would propose revoking every live ephemeral
    // membership — noise that is not the candidate's content. Edges whose
    // roles the candidate does not declare are left out: the candidate is
    // removing that role, which the pair intersection below reports as an
    // overlap rather than silently planning around.
    let mut overlay_roles: BTreeSet<String> = BTreeSet::new();
    for edge in overlay_edges {
        if !desired.roles.contains_key(&edge.role) || !desired.roles.contains_key(&edge.member) {
            continue;
        }
        if desired
            .memberships
            .iter()
            .any(|existing| existing.role == edge.role && existing.member == edge.member)
        {
            continue;
        }
        overlay_roles.insert(edge.role.clone());
        overlay_roles.insert(edge.member.clone());
        desired.memberships.insert(edge.clone());
    }

    // The candidate's own inspection scope: its expanded content, plus the
    // roles it retires and the overlay roles it inherited. It is deliberately
    // NOT the policy's scope — a candidate proposing a new role has a role in
    // scope the policy does not, and the wildcard patterns it carries drive a
    // different expansion and different diagnostics.
    let has_database_grants = expanded
        .grants
        .iter()
        .any(|g| g.object.object_type == pgroles_core::manifest::ObjectType::Database);
    let inspect_config =
        pgroles_inspect::InspectConfig::from_expanded(&expanded, has_database_grants)
            .with_additional_roles(
                manifest
                    .retirements
                    .iter()
                    .map(|retirement| retirement.role.clone()),
            )
            .with_additional_roles(overlay_roles);

    Ok(CandidateInputs {
        manifest,
        expanded,
        desired,
        inspect_config,
    })
}

/// The one database read the whole candidate pass shares, plus how many reads
/// the pass actually performed.
struct SharedInspection {
    /// `None` when there was nothing to share (no plannable candidate on the
    /// parent's own target) or when the shared read failed — in which case
    /// every candidate falls back to inspecting for itself, exactly as before.
    raw: Option<std::sync::Arc<pgroles_inspect::RawInspection>>,
    /// Database inspections performed during this pass: the shared read counts
    /// as one, and each fallback adds another. This is the number the issue
    /// asks to bound, so it is measured rather than assumed. (The at-most-one
    /// lazy grantability query a derivation may trigger is part of the shared
    /// read, not a further inspection.)
    inspections: std::sync::atomic::AtomicUsize,
    /// How many candidates the shared read was taken for — the denominator
    /// that says whether `inspections` is flat in the candidate count.
    plannable: usize,
}

impl SharedInspection {
    fn none() -> Self {
        Self {
            raw: None,
            inspections: std::sync::atomic::AtomicUsize::new(0),
            plannable: 0,
        }
    }

    /// Inspect `config` against `target`: from the shared snapshot when it
    /// covers the scope and the target is the parent's own connection,
    /// otherwise with a full inspection of its own.
    ///
    /// An override target has a different pool and therefore a different
    /// database; a scope the snapshot never read would be silently
    /// under-reported. Both fall back rather than approximate.
    async fn inspect(
        &self,
        target: &CandidateTargetContext<'_>,
        config: &pgroles_inspect::InspectConfig,
    ) -> Result<pgroles_inspect::InspectionResult, ReconcileError> {
        if let CandidateTargetContext::Parent(_) = target
            && let Some(raw) = self.raw.as_ref()
            && raw.covers(config)
        {
            return Ok(raw.derive_bounded(target.pool(), config).await?);
        }

        self.inspections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(pgroles_inspect::inspect_with_diagnostics(target.pool(), config).await?)
    }
}

/// Read the database once for every candidate that will plan against the
/// parent's own target.
///
/// The union of the candidates' scopes is read in one pass; each candidate
/// then derives its own scoped inspection from it in memory. Candidates with a
/// `spec.target` override are excluded: they are a different database, and
/// resolving which one is itself I/O.
///
/// A failure here is not fatal — it degrades to the previous behaviour of one
/// inspection per candidate, because a shared read is an optimisation and a
/// proposal must never break enforcement.
async fn shared_inspection(
    planning: &CandidatePlanning<'_>,
    candidates: &[PostgresPolicyCandidate],
    not_planned: &BTreeMap<String, NotPlanned>,
) -> SharedInspection {
    if !matches!(planning.gate, ParentGate::Stable) {
        return SharedInspection::none();
    }

    let configs: Vec<pgroles_inspect::InspectConfig> = candidates
        .iter()
        .filter(|candidate| {
            !candidate_phase(candidate).is_terminal()
                && candidate.spec.target.is_none()
                // An expired or over-budget candidate is never planned, so
                // letting its scope into the union would make the read wider
                // than the work — the opposite of the point of the budget.
                && !not_planned.contains_key(&candidate.name_any())
        })
        .filter_map(|candidate| {
            candidate_inputs(candidate, planning.overlay_edges)
                .ok()
                .map(|inputs| inputs.inspect_config)
        })
        .collect();
    if configs.is_empty() {
        return SharedInspection::none();
    }

    let plannable = configs.len();
    let union = pgroles_inspect::InspectConfig::union_of(configs.iter());
    match pgroles_inspect::RawInspection::read(planning.pool, &union).await {
        Ok(raw) => SharedInspection {
            raw: Some(std::sync::Arc::new(raw)),
            inspections: std::sync::atomic::AtomicUsize::new(1),
            plannable,
        },
        Err(err) => {
            tracing::warn!(
                %err,
                "shared candidate inspection failed; falling back to one inspection per candidate"
            );
            SharedInspection {
                raw: None,
                inspections: std::sync::atomic::AtomicUsize::new(0),
                plannable,
            }
        }
    }
}

async fn plan_candidate(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
    candidate: &PostgresPolicyCandidate,
    planning: &CandidatePlanning<'_>,
    overlay_pairs: &BTreeSet<EffectPair>,
    shared: &SharedInspection,
) -> Result<CandidateOutcome, ReconcileError> {
    let namespace = candidate.namespace().ok_or(ReconcileError::NoNamespace)?;
    let inputs = candidate_inputs(candidate, planning.overlay_edges)?;

    // Resolve the execution context. Everything after this point runs against
    // `target`, which is the parent's connection unless `spec.target` overrides
    // it — in which case the plan binds that database's identity and can never
    // be promoted onto the current one.
    let target = resolve_target(ctx, policy, candidate, planning, &namespace).await?;
    let result = plan_against_target(
        ctx,
        policy,
        candidate,
        overlay_pairs,
        &target,
        &inputs,
        &namespace,
        shared,
    )
    .await;
    // An override holds its own advisory lock; release it on every path.
    target.release().await;
    result
}

#[allow(clippy::too_many_arguments)]
async fn plan_against_target(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
    candidate: &PostgresPolicyCandidate,
    overlay_pairs: &BTreeSet<EffectPair>,
    target: &CandidateTargetContext<'_>,
    inputs: &CandidateInputs,
    namespace: &str,
    shared: &SharedInspection,
) -> Result<CandidateOutcome, ReconcileError> {
    let content = &candidate.spec.content;
    let CandidateInputs {
        manifest,
        expanded,
        desired,
        inspect_config,
    } = inputs;
    let inspection = shared.inspect(target, inspect_config).await?;
    if let Some(message) = inspection.diagnostics.blocking_message() {
        return Err(ReconcileError::UnsatisfiableWildcardGrant(message));
    }
    let current = inspection.graph;

    crate::reconciler::validate_referenced_schemas_exist(target.pool(), expanded).await?;

    let reconciliation_mode: pgroles_core::diff::ReconciliationMode =
        content.reconciliation_mode.into();
    if pgroles_core::diff::additive_ignores_absence_assertions(desired, reconciliation_mode) {
        tracing::warn!(
            candidate = %candidate.name_any(),
            "additive reconciliation ignores every absence assertion \
             (`ensure: absent` and `exclusive: true` memberships); \
             use adopt or authoritative mode to enforce absence"
        );
    }
    let mut changes = crate::reconciler::policy_changes(
        &current,
        desired,
        manifest,
        expanded,
        reconciliation_mode,
    );

    // Read-only password resolution. Generated Secrets are named for the
    // parent policy because that is what promotion would create; nothing is
    // written here in any state.
    let resolved_passwords = crate::reconciler::resolve_passwords_for_roles(
        ctx,
        policy,
        namespace,
        &content.roles,
        false,
    )
    .await?;
    let (password_changes, password_source_versions) =
        candidate_password_changes(&changes, &resolved_passwords, policy);
    if !password_changes.is_empty() {
        changes = pgroles_core::diff::inject_password_changes(changes, &password_changes);
    }

    let summary = crate::reconciler::summarize_changes(&changes);

    if changes.is_empty() {
        // The effects vanished (or never existed): the content is already the
        // database's state. Retire any plan rather than leave a reviewable
        // artifact describing nothing.
        supersede_candidate_plan(ctx, candidate, namespace, SupersedeCause::EffectsCleared).await?;
        return Ok(CandidateOutcome::NoEffects);
    }

    let candidate_pairs = effect_pairs(&changes);
    let overlapping = intersecting_pairs(&candidate_pairs, overlay_pairs);

    let sql_ctx = crate::reconciler::detect_sql_context(target.pool(), inspect_config).await?;
    let content_digest = content_digest(candidate);
    // The base pin: the policy content this plan is being computed against.
    // Promotion refuses to adopt a plan pinned to any other base, so an
    // approval can never authorise replacing desired state its reviewer did
    // not see.
    let base_content_digest = policy.spec.content_digest();

    // `create_or_update_plan` is the whole revalidation rule: an identical
    // change digest deduplicates onto the existing plan, keeping it and any
    // decision recorded on it; a changed digest creates a replacement and
    // supersedes the old one with a cause. Candidates get exactly the policy's
    // Phase 0 semantics because they go through exactly the same function.
    let creation = crate::plan::create_or_update_plan(
        &ctx.kube_client,
        policy,
        &changes,
        &sql_ctx,
        inspect_config,
        content.reconciliation_mode,
        target.identity(),
        target.target_identity(),
        &summary,
        &password_source_versions,
        ctx.plan_retention,
        Some(CandidatePlanBinding {
            candidate,
            content_digest: &content_digest,
            content_digest_encoding: pgroles_core::candidate::CANDIDATE_CONTENT_ENCODING_V1,
            base_content_digest: &base_content_digest,
        }),
        false,
    )
    .await?;
    let plan_name = creation.plan_name().to_string();

    if creation.is_created() {
        crate::events::publish_candidate_event(
            &ctx.event_recorder,
            candidate,
            false,
            candidate_reason::PLANNED,
            format!("Plan {plan_name} created with {} change(s)", summary.total),
        )
        .await
        .ok();
    }

    if !overlapping.is_empty() {
        return Ok(CandidateOutcome::OverlayOverlap {
            plan_name,
            changes: summary.total,
            overlapping: overlapping.iter().map(describe_pair).collect(),
        });
    }

    Ok(CandidateOutcome::Planned {
        plan_name,
        changes: summary.total,
    })
}

/// The execution context a candidate is planned in.
enum CandidateTargetContext<'a> {
    /// The parent's pool, identity and target identity, unchanged.
    Parent(&'a CandidatePlanning<'a>),
    /// An explicit `spec.target` override, with its own locks held for the
    /// duration of the plan.
    Override {
        pool: sqlx::PgPool,
        identity: DatabaseIdentity,
        target_identity: pgroles_core::approval::TargetIdentity,
        _db_lock: crate::context::DatabaseLockGuard,
        advisory_lock: Option<crate::advisory::AdvisoryLock>,
    },
}

impl CandidateTargetContext<'_> {
    fn pool(&self) -> &sqlx::PgPool {
        match self {
            CandidateTargetContext::Parent(planning) => planning.pool,
            CandidateTargetContext::Override { pool, .. } => pool,
        }
    }

    fn identity(&self) -> &str {
        match self {
            CandidateTargetContext::Parent(planning) => planning.identity.as_str(),
            CandidateTargetContext::Override { identity, .. } => identity.as_str(),
        }
    }

    fn target_identity(&self) -> &pgroles_core::approval::TargetIdentity {
        match self {
            CandidateTargetContext::Parent(planning) => planning.target_identity,
            CandidateTargetContext::Override {
                target_identity, ..
            } => target_identity,
        }
    }

    async fn release(self) {
        if let CandidateTargetContext::Override {
            advisory_lock: Some(lock),
            ..
        } = self
        {
            lock.release().await;
        }
    }
}

/// Build the `ConnectionSpec` an override target resolves through.
///
/// The override is URL mode only, so it maps onto the same `ConnectionSpec`
/// the policy uses and therefore resolves, fingerprints and locks by exactly
/// the same code — including the #180 dual target identity.
pub(crate) fn override_connection_spec(target: &CandidateTarget) -> ConnectionSpec {
    ConnectionSpec {
        secret_ref: Some(SecretReference {
            name: target.connection_ref.secret_name.clone(),
        }),
        secret_key: Some(target.connection_ref.key.clone()),
        params: None,
        require_physical_identity: None,
    }
}

async fn resolve_target<'a>(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
    candidate: &PostgresPolicyCandidate,
    planning: &'a CandidatePlanning<'a>,
    namespace: &str,
) -> Result<CandidateTargetContext<'a>, ReconcileError> {
    let Some(target) = candidate.spec.target.as_ref() else {
        return Ok(CandidateTargetContext::Parent(planning));
    };

    let connection = override_connection_spec(target);
    let identity = DatabaseIdentity::from_connection(namespace, &connection);
    if identity.as_str() == planning.identity.as_str() {
        // The override resolves to the parent's own target. Reusing the
        // parent's context is not an optimisation — taking the same lock twice
        // in one reconcile would deadlock against ourselves.
        return Ok(CandidateTargetContext::Parent(planning));
    }

    let pool = ctx
        .get_or_create_pool(namespace, &connection)
        .await
        .map_err(Box::new)?;

    // Identity lookup runs BEFORE any lock is taken: reading
    // pg_control_system and resolving the fingerprint are read-only, so they
    // are safe without the lock, and no lock is held yet so lookup errors
    // need no release path. Doing it here lets us recognise an override that
    // merely aliases the parent's own database (a different Secret pointing
    // at the same server) before we contend on the advisory lock — with the
    // canonical server-side key, such an alias would otherwise collide with
    // the parent's own held lock on every reconcile, forever.
    let physical = pgroles_inspect::detect_system_identifier(&pool).await?;
    let logical = ctx
        .resolve_database_target_fingerprint(namespace, &connection)
        .await
        .map_err(Box::new)?;

    // The override aliases the parent's own database only on proof of
    // *endpoint* identity: the resolved host, port and database fingerprint.
    // The physical identity deliberately plays no part here — it names a
    // storage lineage, not an endpoint, so a streaming replica or a restored
    // clone shares it (and the database name) with the parent while being
    // exactly the different endpoint the override exists to preview. When the
    // fingerprints match, the parent already holds both locks for this
    // database, so reuse its context — like the string-identity fast path.
    let same_logical_fingerprint =
        planning.target_identity.logical.as_deref() == Some(logical.as_str());
    if same_logical_fingerprint {
        tracing::info!(
            candidate = %candidate.name_any(),
            policy = %policy.name_any(),
            target = %identity.as_str(),
            "candidate target override aliases the parent's own database; \
             reusing the parent's context and locks"
        );
        return Ok(CandidateTargetContext::Parent(planning));
    }

    // Residual: an alias this detection cannot prove — a different hostname
    // (a CNAME, a pooler) resolving to the parent's own primary — fails
    // closed as LockContention against the parent's held advisory lock
    // instead of silently running an inspect/diff cycle concurrently with
    // it. The contention message below names this case so the failure mode
    // is diagnosable. A streaming replica does not hit this: its advisory
    // lock table is local to the standby.
    //
    // Locking follows the target: the override is a different database, so it
    // has its own advisory and in-process locks and cannot share the parent's.
    let db_lock = ctx
        .try_lock_database(identity.as_str())
        .await
        .ok_or_else(|| {
            ReconcileError::LockContention(
                identity.as_str().to_string(),
                "candidate target override lock held by another reconcile".to_string(),
            )
        })?;
    let advisory_lock = match crate::advisory::try_acquire(&pool, identity.as_str()).await {
        Ok(Some(lock)) => Some(lock),
        Ok(None) => {
            return Err(ReconcileError::LockContention(
                identity.as_str().to_string(),
                "candidate target override advisory lock held by another session — this is also \
                 what an unrecognized alias of a locked database (including the parent's own) \
                 looks like"
                    .to_string(),
            ));
        }
        Err(err) => return Err(ReconcileError::SqlExec(err)),
    };

    tracing::info!(
        candidate = %candidate.name_any(),
        policy = %policy.name_any(),
        target = %identity.as_str(),
        "planning candidate against an explicit target override"
    );

    Ok(CandidateTargetContext::Override {
        pool,
        identity,
        target_identity: pgroles_core::approval::TargetIdentity {
            physical,
            logical: Some(logical),
        },
        _db_lock: db_lock,
        advisory_lock,
    })
}

// ---------------------------------------------------------------------------
// The no-write seam
// ---------------------------------------------------------------------------

/// Select the password changes a candidate plan describes.
///
/// The policy's [`crate::reconciler::select_password_changes`] compares against
/// the parent's `status.appliedPasswordSourceVersions`, which is the right
/// baseline for a candidate too: the candidate is asking what would happen if
/// its content became the policy's.
///
/// What this function structurally cannot do is materialise anything. It takes
/// resolved passwords by reference and returns only strings, so the
/// `pending_materialization` marker — the sole route to
/// `password::ensure_generated_secret` — is dropped here and can never reach a
/// writer. An unmaterialised generated password still contributes its
/// `:missing` sentinel to the digest, so the plan's identity says plainly that
/// the credential does not exist yet.
pub(crate) fn candidate_password_changes(
    changes: &[pgroles_core::diff::Change],
    resolved: &BTreeMap<String, ResolvedPassword>,
    policy: &PostgresPolicy,
) -> (BTreeMap<String, String>, BTreeMap<String, String>) {
    crate::reconciler::select_password_changes(changes, resolved, policy.status.as_ref())
}

// ---------------------------------------------------------------------------
// Status transitions
// ---------------------------------------------------------------------------

fn candidate_phase(candidate: &PostgresPolicyCandidate) -> CandidatePhase {
    candidate
        .status
        .as_ref()
        .map(|status| status.phase)
        .unwrap_or_default()
}

fn content_digest(candidate: &PostgresPolicyCandidate) -> String {
    pgroles_core::candidate::compute_content_digest(&candidate.spec.content)
}

/// The controller ownerReference from a candidate to its parent policy.
///
/// ADR-001 Decision 3: a controller reference, so deleting the policy
/// garbage-collects its candidates — a candidate has no meaning without its
/// base. Cross-namespace refs are impossible, which is why `spec.policyRef`
/// resolves in the candidate's own namespace.
pub(crate) fn policy_owner_reference(policy: &PostgresPolicy) -> OwnerReference {
    OwnerReference {
        api_version: PostgresPolicy::api_version(&()).to_string(),
        kind: PostgresPolicy::kind(&()).to_string(),
        name: policy.name_any(),
        uid: policy.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

/// Does this candidate already carry the controller reference to `policy`?
pub(crate) fn has_policy_owner_reference(
    candidate: &PostgresPolicyCandidate,
    policy_uid: &str,
) -> bool {
    crate::plan::is_owned_by_uid(candidate, policy_uid)
}

/// Does this candidate belong to `policy`?
///
/// The name in `spec.policyRef` is the author's declaration; the controller
/// ownerReference is the discipline. A candidate that has already been adopted
/// belongs only to the policy with that UID, so a same-named policy that was
/// deleted and recreated never inherits the old policy's candidates while they
/// await garbage collection — matching them by name alone would let planning
/// and, worse, promotion recognition read proposals reviewed against an object
/// that no longer exists. An unadopted candidate (no controller reference yet)
/// matches by name and is bound to a UID on first touch by [`adopt_candidate`].
pub(crate) fn candidate_belongs_to(
    candidate: &PostgresPolicyCandidate,
    policy: &PostgresPolicy,
) -> bool {
    if candidate.spec.policy_ref.name != policy.name_any() {
        return false;
    }
    let controller_uid = candidate
        .metadata
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|owner| owner.controller.unwrap_or(false))
        .map(|owner| owner.uid.as_str());
    match (controller_uid, policy.metadata.uid.as_deref()) {
        // Adopted: only the recorded controller may claim it. A policy with no
        // UID (only constructible in tests) can prove ownership of nothing.
        (Some(owned_by), live_uid) => live_uid == Some(owned_by),
        // Not yet adopted: the name is all there is, and first touch binds it.
        (None, _) => true,
    }
}

/// First-touch bookkeeping: ownerReference, content digest, observedGeneration.
///
/// All three are stamped before anything can fail, so a candidate that never
/// plans successfully still shows what it is and what it is bound to.
async fn adopt_candidate(
    ctx: &OperatorContext,
    policy: &PostgresPolicy,
    candidate: &mut PostgresPolicyCandidate,
) -> Result<(), ReconcileError> {
    let namespace = candidate.namespace().ok_or(ReconcileError::NoNamespace)?;
    let api: Api<PostgresPolicyCandidate> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    let name = candidate.name_any();

    let policy_uid = policy.metadata.uid.as_deref().unwrap_or_default();
    if !policy_uid.is_empty() && !has_policy_owner_reference(candidate, policy_uid) {
        let mut owner_references = candidate
            .metadata
            .owner_references
            .clone()
            .unwrap_or_default();
        owner_references.retain(|owner| !owner.controller.unwrap_or(false));
        owner_references.push(policy_owner_reference(policy));
        let patch = serde_json::json!({ "metadata": { "ownerReferences": owner_references } });
        // A merge patch, so no `.force()`: kube validates that `force` is only
        // legal on `Patch::Apply` and would reject this call client-side.
        *candidate = api
            .patch(
                &name,
                &PatchParams::apply("pgroles-operator"),
                &Patch::Merge(&patch),
            )
            .await?;
        info!(candidate = %name, policy = %policy.name_any(), "adopted candidate");
    }

    let digest = content_digest(candidate);
    let generation = candidate.metadata.generation;
    let status = candidate.status.clone().unwrap_or_default();
    if status.content_digest.as_deref() != Some(digest.as_str())
        || status.observed_generation != generation
    {
        write_status(ctx, candidate, |status| {
            status.content_digest = Some(digest.clone());
            status.observed_generation = generation;
        })
        .await?;
    }
    Ok(())
}

/// Apply a status mutation to a candidate and write it back.
async fn write_status<F>(
    ctx: &OperatorContext,
    candidate: &mut PostgresPolicyCandidate,
    mutate: F,
) -> Result<(), ReconcileError>
where
    F: FnOnce(&mut PostgresPolicyCandidateStatus),
{
    let namespace = candidate.namespace().ok_or(ReconcileError::NoNamespace)?;
    let api: Api<PostgresPolicyCandidate> = Api::namespaced(ctx.kube_client.clone(), &namespace);
    let mut status = candidate.status.clone().unwrap_or_default();
    mutate(&mut status);
    let patch = serde_json::json!({ "status": status });
    let updated = api
        .patch_status(
            &candidate.name_any(),
            &PatchParams::apply("pgroles-operator"),
            &Patch::Merge(&patch),
        )
        .await?;
    *candidate = updated;
    Ok(())
}

async fn record_outcome(
    ctx: &OperatorContext,
    candidate: &mut PostgresPolicyCandidate,
    outcome: CandidateOutcome,
) -> Result<(), ReconcileError> {
    match outcome {
        CandidateOutcome::Planned { plan_name, changes } => {
            let message = format!("Plan {plan_name} holds {changes} change(s) for review");
            write_status(ctx, candidate, |status| {
                status.phase = CandidatePhase::Planned;
                status.plan_ref = Some(PlanReference {
                    name: plan_name.clone(),
                });
                set_condition_in(
                    &mut status.conditions,
                    ready_condition(true, candidate_reason::PLANNED, &message),
                );
            })
            .await
        }
        CandidateOutcome::NoEffects => {
            let message =
                "this candidate's content is already the database's state; nothing to review"
                    .to_string();
            write_status(ctx, candidate, |status| {
                status.phase = CandidatePhase::Planned;
                status.plan_ref = None;
                set_condition_in(
                    &mut status.conditions,
                    ready_condition(true, candidate_reason::NO_EFFECTS, &message),
                );
            })
            .await
        }
        CandidateOutcome::OverlayOverlap {
            plan_name,
            changes,
            overlapping,
        } => {
            let message = format!(
                "an active ephemeral grant touches {} of this candidate's effects ({}); plan \
                 {plan_name} holds {changes} change(s) and requires fresh review",
                overlapping.len(),
                overlapping.join(", "),
            );
            write_status(ctx, candidate, |status| {
                status.phase = CandidatePhase::Planned;
                status.plan_ref = Some(PlanReference {
                    name: plan_name.clone(),
                });
                set_condition_in(
                    &mut status.conditions,
                    ready_condition(false, candidate_reason::OVERLAY_OVERLAP, &message),
                );
            })
            .await?;
            crate::events::publish_candidate_event(
                &ctx.event_recorder,
                candidate,
                true,
                candidate_reason::OVERLAY_OVERLAP,
                message,
            )
            .await
            .ok();
            Ok(())
        }
    }
}

/// Report that a candidate is queued behind the open-candidate budget.
///
/// Nothing is deleted and the candidate is not terminal: it is planned as soon
/// as enough older proposals are decided or expire. Like [`block_candidate`],
/// a candidate can sit here for many cycles, so the Event is published once per
/// transition rather than once per pass.
async fn mark_over_budget(
    ctx: &OperatorContext,
    candidate: &mut PostgresPolicyCandidate,
) -> Result<(), ReconcileError> {
    let message = format!(
        "this policy already has {DEFAULT_MAX_OPEN_CANDIDATES} open candidates being \
         planned; this one is planned once older proposals are decided or expire"
    );
    let already_over_budget = candidate.status.as_ref().is_some_and(|status| {
        status.conditions.iter().any(|c| {
            c.condition_type == "Ready"
                && c.status == "False"
                && c.reason.as_deref() == Some(candidate_reason::OVER_BUDGET)
        })
    });
    write_status(ctx, candidate, |status| {
        set_condition_in(
            &mut status.conditions,
            ready_condition(false, candidate_reason::OVER_BUDGET, &message),
        );
    })
    .await?;
    if !already_over_budget {
        crate::events::publish_candidate_event(
            &ctx.event_recorder,
            candidate,
            true,
            candidate_reason::OVER_BUDGET,
            message,
        )
        .await
        .ok();
    }
    Ok(())
}

async fn block_candidate(
    ctx: &OperatorContext,
    candidate: &mut PostgresPolicyCandidate,
    cause: BlockCause,
) -> Result<(), ReconcileError> {
    let already_blocked = candidate.status.as_ref().is_some_and(|status| {
        status.conditions.iter().any(|c| {
            c.condition_type == "Ready"
                && c.status == "False"
                && c.reason.as_deref() == Some(candidate_reason::BLOCKED_BY_ACTIVE_POLICY)
        })
    });
    write_status(ctx, candidate, |status| {
        set_condition_in(
            &mut status.conditions,
            ready_condition(
                false,
                candidate_reason::BLOCKED_BY_ACTIVE_POLICY,
                cause.message(),
            ),
        );
    })
    .await?;
    // The parent can stay blocked for many cycles; one Event per transition is
    // the point of Events, a stream of identical ones is noise.
    if !already_blocked {
        crate::events::publish_candidate_event(
            &ctx.event_recorder,
            candidate,
            true,
            candidate_reason::BLOCKED_BY_ACTIVE_POLICY,
            cause.message().to_string(),
        )
        .await
        .ok();
    }
    Ok(())
}

pub(crate) async fn mark_superseded(
    ctx: &OperatorContext,
    candidate: &mut PostgresPolicyCandidate,
    reason: &str,
    message: &str,
) -> Result<(), ReconcileError> {
    if candidate_phase(candidate) == CandidatePhase::Superseded {
        return Ok(());
    }
    write_status(ctx, candidate, |status| {
        status.phase = CandidatePhase::Superseded;
        set_condition_in(
            &mut status.conditions,
            superseded_condition(reason, message),
        );
        set_condition_in(
            &mut status.conditions,
            ready_condition(false, reason, message),
        );
    })
    .await?;
    crate::events::publish_candidate_event(
        &ctx.event_recorder,
        candidate,
        true,
        reason,
        message.to_string(),
    )
    .await
    .ok();
    Ok(())
}

/// Mark predecessors named in `spec.replaces` as superseded.
///
/// Only once the successor actually has a plan: an unplanned successor has
/// proved nothing, and retiring the predecessor first would leave a reviewer
/// with nothing at all.
async fn apply_replacements(
    ctx: &OperatorContext,
    candidates: &[PostgresPolicyCandidate],
) -> Result<(), ReconcileError> {
    let planned: BTreeMap<String, String> = candidates
        .iter()
        .filter(|candidate| {
            candidate
                .status
                .as_ref()
                .is_some_and(|status| status.plan_ref.is_some())
        })
        .filter_map(|candidate| {
            candidate
                .spec
                .replaces
                .clone()
                .map(|replaced| (replaced, candidate.name_any()))
        })
        .collect();
    if planned.is_empty() {
        return Ok(());
    }

    for candidate in candidates {
        let Some(successor) = planned.get(&candidate.name_any()) else {
            continue;
        };
        if candidate_phase(candidate).is_terminal() {
            continue;
        }
        let mut candidate = candidate.clone();
        mark_superseded(
            ctx,
            &mut candidate,
            candidate_reason::REPLACED,
            &format!("replaced by candidate {successor}"),
        )
        .await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Plan lookups and retention
// ---------------------------------------------------------------------------

/// The plans owned by one candidate.
async fn candidate_plans(
    ctx: &OperatorContext,
    candidate: &PostgresPolicyCandidate,
    namespace: &str,
) -> Result<Vec<PostgresPolicyPlan>, ReconcileError> {
    let Some(uid) = candidate.metadata.uid.as_deref() else {
        return Ok(Vec::new());
    };
    let plans: Api<PostgresPolicyPlan> = Api::namespaced(ctx.kube_client.clone(), namespace);
    Ok(plans
        .list(&ListParams::default())
        .await?
        .into_iter()
        .filter(|plan| crate::plan::is_owned_by_uid(plan, uid))
        .collect())
}

async fn plan_was_denied(
    ctx: &OperatorContext,
    candidate: &PostgresPolicyCandidate,
    namespace: &str,
) -> Result<bool, ReconcileError> {
    Ok(candidate_plans(ctx, candidate, namespace)
        .await?
        .iter()
        .any(|plan| {
            matches!(
                crate::plan::check_plan_approval(plan),
                crate::plan::PlanApprovalState::Rejected
            ) || plan
                .status
                .as_ref()
                .is_some_and(|status| status.phase == PlanPhase::Rejected)
        }))
}

/// Retire a candidate's live plan when its effects are gone.
async fn supersede_candidate_plan(
    ctx: &OperatorContext,
    candidate: &PostgresPolicyCandidate,
    namespace: &str,
    cause: SupersedeCause,
) -> Result<(), ReconcileError> {
    for plan in candidate_plans(ctx, candidate, namespace).await? {
        let is_live = plan
            .status
            .as_ref()
            .is_some_and(|status| matches!(status.phase, PlanPhase::Pending | PlanPhase::Approved));
        if !is_live {
            continue;
        }
        crate::plan::mark_plan_superseded(&ctx.kube_client, &plan, cause).await?;
        crate::events::publish_candidate_event(
            &ctx.event_recorder,
            candidate,
            false,
            "PlanSuperseded",
            format!("Plan {} superseded: {}", plan.name_any(), cause.message()),
        )
        .await
        .ok();
    }
    Ok(())
}

/// Prune terminal candidates beyond the retention bounds.
///
/// Plans cascade: each is owned by its candidate, so deleting the candidate
/// takes the plan and its SQL ConfigMap with it. That cascade is why pruning
/// reads the plans first — see [`terminal_candidates_to_prune`] for the
/// decision. Best-effort throughout: retention must never block planning, and
/// when the plans cannot be read this pass prunes nothing rather than prune
/// blind and cascade away an `Applied` plan retention promises to keep.
async fn cleanup_terminal_candidates(
    ctx: &OperatorContext,
    namespace: &str,
    candidates: &[PostgresPolicyCandidate],
) {
    let terminal: Vec<&PostgresPolicyCandidate> = candidates
        .iter()
        .filter(|candidate| candidate_phase(candidate).is_terminal())
        .collect();
    let retention = ctx.plan_retention;
    // The buckets below partition the terminal set, so when the whole set
    // fits inside every count bound nothing can be pruned — skip the plan
    // read on that common path.
    if terminal.len() <= DEFAULT_MAX_TERMINAL_CANDIDATES && terminal.len() <= retention.applied {
        return;
    }

    let plans: Vec<PostgresPolicyPlan> =
        match Api::<PostgresPolicyPlan>::namespaced(ctx.kube_client.clone(), namespace)
            .list(&ListParams::default())
            .await
        {
            Ok(list) => list.items,
            Err(err) => {
                tracing::warn!(%err, "could not read plans; skipping terminal-candidate pruning");
                return;
            }
        };
    let records: Vec<(&PostgresPolicyCandidate, Vec<&PostgresPolicyPlan>)> = terminal
        .into_iter()
        .map(|candidate| {
            let uid = candidate.metadata.uid.clone().unwrap_or_default();
            let owned: Vec<&PostgresPolicyPlan> = plans
                .iter()
                .filter(|plan| !uid.is_empty() && crate::plan::is_owned_by_uid(*plan, &uid))
                .collect();
            (candidate, owned)
        })
        .collect();

    let api: Api<PostgresPolicyCandidate> = Api::namespaced(ctx.kube_client.clone(), namespace);
    let now_ts = Timestamp::now().as_second();
    for candidate in terminal_candidates_to_prune(&records, retention, now_ts) {
        let name = candidate.name_any();
        info!(candidate = %name, "pruning terminal candidate");
        if let Err(err) = api.delete(&name, &DeleteParams::default()).await {
            tracing::warn!(candidate = %name, %err, "failed to prune terminal candidate");
        }
    }
}

/// Which terminal candidates to prune, given the plans each one owns.
///
/// Deleting a candidate cascades to every plan it owns, so the decision is
/// made per candidate-and-plans pair:
///
/// - `pgroles.io/keep=true` on the candidate **or on any plan it owns**
///   exempts the pair. The cascade cannot honour a keep on the child if the
///   parent goes, so a kept child must protect its parent.
/// - A candidate owning an `Applied` plan is the provenance of an execution
///   record, so it is held to the [`crate::plan::PlanRetention`] bounds for
///   `Applied` plans — same count, age floor and ceiling, ordered by when the plan
///   applied — not to the flat terminal bound, which proposal churn would
///   otherwise use to delete fresh execution history through the owner
///   object.
/// - Every other terminal candidate is proposal churn — nothing it owns ever
///   ran — bounded by [`DEFAULT_MAX_TERMINAL_CANDIDATES`], oldest first by
///   creation.
fn terminal_candidates_to_prune<'a>(
    records: &[(&'a PostgresPolicyCandidate, Vec<&'a PostgresPolicyPlan>)],
    retention: crate::plan::PlanRetention,
    now_ts: i64,
) -> Vec<&'a PostgresPolicyCandidate> {
    let mut churn: Vec<&PostgresPolicyCandidate> = Vec::new();
    let mut applied: Vec<(&PostgresPolicyCandidate, &PostgresPolicyPlan)> = Vec::new();
    for (candidate, plans) in records {
        if is_retention_exempt(*candidate) || plans.iter().any(|plan| is_retention_exempt(*plan)) {
            continue;
        }
        let applied_plan = plans.iter().find(|plan| {
            plan.status
                .as_ref()
                .is_some_and(|status| status.phase == PlanPhase::Applied)
        });
        match applied_plan {
            Some(plan) => applied.push((candidate, plan)),
            None => churn.push(candidate),
        }
    }

    let mut prune: Vec<&PostgresPolicyCandidate> = Vec::new();
    if churn.len() > DEFAULT_MAX_TERMINAL_CANDIDATES {
        churn.sort_by(|a, b| {
            a.metadata
                .creation_timestamp
                .cmp(&b.metadata.creation_timestamp)
        });
        let excess = churn.len() - DEFAULT_MAX_TERMINAL_CANDIDATES;
        prune.extend(churn.into_iter().take(excess));
    }

    // Plan names are unique within the namespace, so they key the way back
    // from an evicted plan to the candidate that owns it.
    let evicted_plans: BTreeSet<String> = crate::plan::applied_plans_to_evict(
        applied.iter().map(|(_, plan)| *plan).collect(),
        retention,
        now_ts,
    )
    .into_iter()
    .map(|plan| plan.name_any())
    .collect();
    prune.extend(
        applied
            .into_iter()
            .filter(|(_, plan)| evicted_plans.contains(&plan.name_any()))
            .map(|(candidate, _)| candidate),
    );
    prune
}

/// Read the `Ready` condition reason from a candidate status, for tests and
/// status consumers that only care about the current verdict.
pub fn ready_reason(status: &PostgresPolicyCandidateStatus) -> Option<&str> {
    status
        .conditions
        .iter()
        .find(|c: &&PolicyCondition| c.condition_type == "Ready")
        .and_then(|c| c.reason.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{
        GeneratePasswordSpec, LocalObjectReference, PolicyContent, PostgresPolicyCandidateSpec,
        PostgresPolicySpec, RoleSpec,
    };

    fn policy(name: &str) -> PostgresPolicy {
        let spec: PostgresPolicySpec = serde_json::from_value(serde_json::json!({
            "connection": { "secretRef": { "name": "db" } },
        }))
        .expect("minimal policy spec");
        let mut policy = PostgresPolicy::new(name, spec);
        policy.metadata.uid = Some(format!("{name}-uid"));
        policy.metadata.namespace = Some("default".to_string());
        policy
    }

    fn role(name: &str) -> RoleSpec {
        serde_json::from_value(serde_json::json!({ "name": name, "login": true }))
            .expect("minimal role spec")
    }

    fn candidate(name: &str, content: PolicyContent) -> PostgresPolicyCandidate {
        PostgresPolicyCandidate::new(
            name,
            PostgresPolicyCandidateSpec {
                policy_ref: LocalObjectReference {
                    name: "orders".to_string(),
                },
                replaces: None,
                target: None,
                content,
            },
        )
    }

    // -----------------------------------------------------------------
    // Open-candidate admission: TTL and budget
    // -----------------------------------------------------------------

    /// An open candidate `age_hours` old, in the order
    /// `classify_open_candidates` expects (oldest first).
    fn open_candidate(name: &str, now: Timestamp, age_hours: i64) -> PostgresPolicyCandidate {
        let mut candidate = candidate(name, PolicyContent::default());
        candidate.metadata.creation_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                now - SignedDuration::from_hours(age_hours),
            ));
        candidate
    }

    /// The TTL in hours, so fixtures can sit either side of it precisely.
    const TTL_HOURS: i64 = DEFAULT_OPEN_CANDIDATE_TTL.as_hours();

    // -----------------------------------------------------------------
    // Terminal-candidate pruning
    // -----------------------------------------------------------------

    /// A terminal candidate created `age_secs` ago.
    fn terminal_candidate(
        name: &str,
        phase: CandidatePhase,
        age_secs: i64,
        now_ts: i64,
    ) -> PostgresPolicyCandidate {
        let mut candidate = candidate(name, PolicyContent::default());
        candidate.metadata.uid = Some(format!("{name}-uid"));
        candidate.metadata.creation_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                jiff::Timestamp::from_second(now_ts - age_secs).expect("epoch second in range"),
            ));
        candidate.status = Some(PostgresPolicyCandidateStatus {
            phase,
            ..Default::default()
        });
        candidate
    }

    /// An `Applied` plan that executed `applied_age_secs` ago.
    fn applied_plan(name: &str, applied_age_secs: i64, now_ts: i64) -> PostgresPolicyPlan {
        let spec = crate::crd::PostgresPolicyPlanSpec {
            policy_ref: crate::crd::PolicyPlanRef {
                name: "orders".to_string(),
            },
            policy_generation: 1,
            reconciliation_mode: crate::crd::CrdReconciliationMode::Authoritative,
            owned_roles: Vec::new(),
            owned_schemas: Vec::new(),
            managed_database_identity: "default/db/DATABASE_URL".to_string(),
            origin: None,
            scope: None,
        };
        let mut plan = PostgresPolicyPlan::new(name, spec);
        plan.status = Some(crate::crd::PostgresPolicyPlanStatus {
            phase: PlanPhase::Applied,
            applied_at: Some(
                jiff::Timestamp::from_second(now_ts - applied_age_secs)
                    .expect("epoch second in range")
                    .to_string(),
            ),
            ..Default::default()
        });
        plan
    }

    fn keep_plan(mut plan: PostgresPolicyPlan) -> PostgresPolicyPlan {
        plan.metadata
            .labels
            .get_or_insert_with(Default::default)
            .insert("pgroles.io/keep".to_string(), "true".to_string());
        plan
    }

    fn pruned_names(
        records: &[(&PostgresPolicyCandidate, Vec<&PostgresPolicyPlan>)],
        retention: crate::plan::PlanRetention,
        now_ts: i64,
    ) -> Vec<String> {
        let mut names: Vec<String> = terminal_candidates_to_prune(records, retention, now_ts)
            .into_iter()
            .map(|candidate| candidate.name_any())
            .collect();
        names.sort();
        names
    }

    /// The recommended workflow's failure mode: every change lands as a
    /// candidate, so terminal proposals accumulate fast, and under one flat
    /// creation-time bound the eleventh proposal deletes the oldest terminal
    /// candidate — cascading to the Applied plan it owns, straight through
    /// the retention promise made for Applied plans.
    #[test]
    fn proposal_churn_cannot_prune_a_promoted_candidate_with_a_fresh_applied_plan() {
        let now = 1_700_000_000;
        let retention = crate::plan::PlanRetention::default();

        // The promoted candidate is the oldest object in the set by a wide
        // margin, and its plan applied a minute ago.
        let promoted = terminal_candidate("promoted", CandidatePhase::Promoted, 100_000, now);
        let promoted_plan = applied_plan("promoted-plan", 60, now);

        let churn: Vec<PostgresPolicyCandidate> = (0..DEFAULT_MAX_TERMINAL_CANDIDATES + 2)
            .map(|i| {
                terminal_candidate(
                    &format!("churn-{i:03}"),
                    CandidatePhase::Superseded,
                    1_000 - i as i64,
                    now,
                )
            })
            .collect();

        let mut records: Vec<(&PostgresPolicyCandidate, Vec<&PostgresPolicyPlan>)> =
            vec![(&promoted, vec![&promoted_plan])];
        records.extend(
            churn
                .iter()
                .map(|candidate| (candidate, Vec::<&PostgresPolicyPlan>::new())),
        );

        // Guard against a vacuous pass: the promoted candidate must be the
        // oldest by creation, so a flat creation-time bound over the whole
        // set — the behaviour this test exists to reject — would prune it
        // first.
        assert!(
            churn
                .iter()
                .all(|c| c.metadata.creation_timestamp > promoted.metadata.creation_timestamp),
            "the fixture must make the promoted candidate the oldest object"
        );

        let pruned = pruned_names(&records, retention, now);
        assert_eq!(
            pruned,
            vec!["churn-000".to_string(), "churn-001".to_string()],
            "exactly the excess churn goes, oldest first"
        );
        assert!(
            !pruned.contains(&"promoted".to_string()),
            "a promoted candidate with a fresh Applied plan is execution history, not churn"
        );
    }

    /// Deleting the candidate cascades to its plans, so `pgroles.io/keep=true`
    /// on the child plan has to protect the pair — a keep the cascade would
    /// ignore is not a keep.
    #[test]
    fn a_keep_label_on_the_child_plan_protects_the_candidate() {
        let now = 1_700_000_000;
        // A floor of zero and a bound of one, so the applied bucket must
        // evict — only exemptions can spare anything here.
        let retention = crate::plan::PlanRetention {
            applied: 1,
            applied_ceiling: 1,
            applied_min_age_secs: 0,
            ..Default::default()
        };

        let oldest = terminal_candidate("p-old", CandidatePhase::Promoted, 900, now);
        let oldest_plan = keep_plan(applied_plan("p-old-plan", 300, now));
        let middle = terminal_candidate("p-mid", CandidatePhase::Promoted, 800, now);
        let middle_plan = applied_plan("p-mid-plan", 200, now);
        let newest = terminal_candidate("p-new", CandidatePhase::Promoted, 700, now);
        let newest_plan = applied_plan("p-new-plan", 100, now);

        let records: Vec<(&PostgresPolicyCandidate, Vec<&PostgresPolicyPlan>)> = vec![
            (&oldest, vec![&oldest_plan]),
            (&middle, vec![&middle_plan]),
            (&newest, vec![&newest_plan]),
        ];

        // p-old's plan is the earliest execution, so without the keep it is
        // the first eviction; pruning the *younger* p-mid instead is what
        // proves the child's label protected its parent.
        assert_eq!(
            pruned_names(&records, retention, now),
            vec!["p-mid".to_string()]
        );
    }

    fn keep(mut candidate: PostgresPolicyCandidate) -> PostgresPolicyCandidate {
        candidate
            .metadata
            .labels
            .get_or_insert_with(Default::default)
            .insert("pgroles.io/keep".to_string(), "true".to_string());
        candidate
    }

    #[test]
    fn an_undecided_candidate_expires_once_it_is_past_the_ttl() {
        let now = Timestamp::now();
        let candidates = vec![
            open_candidate("abandoned", now, TTL_HOURS + 1),
            // Exactly at the TTL is not yet past it.
            open_candidate("borderline", now, TTL_HOURS),
            open_candidate("fresh", now, 1),
        ];

        let verdicts = classify_open_candidates(&candidates, now);
        assert_eq!(verdicts.get("abandoned"), Some(&NotPlanned::Expired));
        assert_eq!(verdicts.get("borderline"), None);
        assert_eq!(verdicts.get("fresh"), None);
    }

    #[test]
    fn the_budget_keeps_the_oldest_and_queues_the_rest() {
        let now = Timestamp::now();
        // Oldest first, as the caller sorts them.
        let candidates: Vec<PostgresPolicyCandidate> = (0..DEFAULT_MAX_OPEN_CANDIDATES + 3)
            .map(|i| {
                // All well inside the TTL, so this test isolates the budget.
                open_candidate(
                    &format!("candidate-{i:03}"),
                    now,
                    (DEFAULT_MAX_OPEN_CANDIDATES + 3 - i) as i64,
                )
            })
            .collect();

        let verdicts = classify_open_candidates(&candidates, now);
        assert_eq!(verdicts.len(), 3, "exactly the excess is queued");
        for i in 0..DEFAULT_MAX_OPEN_CANDIDATES {
            assert_eq!(
                verdicts.get(&format!("candidate-{i:03}")),
                None,
                "the oldest proposals keep planning — a flood of new ones must not \
                 evict what is already under review"
            );
        }
        for i in DEFAULT_MAX_OPEN_CANDIDATES..DEFAULT_MAX_OPEN_CANDIDATES + 3 {
            assert_eq!(
                verdicts.get(&format!("candidate-{i:03}")),
                Some(&NotPlanned::OverBudget)
            );
        }
    }

    #[test]
    fn an_expired_candidate_does_not_consume_a_budget_slot() {
        let now = Timestamp::now();
        // Every budget slot is filled by an abandoned proposal, with one live
        // candidate behind them: if expiry still spent a slot, the live one
        // would be queued behind a wall of proposals nobody is reviewing.
        //
        // Note this is *not* a test of TTL-before-budget ordering, which is
        // unobservable: the caller sorts oldest-first and expiry is by age, so
        // every expired candidate already precedes every live one.
        let mut candidates: Vec<PostgresPolicyCandidate> = (0..DEFAULT_MAX_OPEN_CANDIDATES)
            .map(|i| open_candidate(&format!("stale-{i:03}"), now, TTL_HOURS + 10))
            .collect();
        candidates.push(open_candidate("live", now, 1));

        let verdicts = classify_open_candidates(&candidates, now);
        assert_eq!(
            verdicts.get("live"),
            None,
            "a live candidate must not be queued behind abandoned ones"
        );
        assert_eq!(verdicts.get("stale-000"), Some(&NotPlanned::Expired));
    }

    #[test]
    fn a_kept_candidate_is_exempt_from_both_but_still_occupies_a_slot() {
        let now = Timestamp::now();
        let ancient = keep(open_candidate("ancient", now, TTL_HOURS + 100));
        assert_eq!(
            classify_open_candidates(std::slice::from_ref(&ancient), now).get("ancient"),
            None,
            "pgroles.io/keep=true exempts a candidate from the TTL"
        );

        // The exemption must not be a way to enlarge the budget: a kept
        // candidate still consumes a slot, so the one behind it is queued.
        let mut candidates: Vec<PostgresPolicyCandidate> = (0..DEFAULT_MAX_OPEN_CANDIDATES - 1)
            .map(|i| open_candidate(&format!("live-{i:03}"), now, 5))
            .collect();
        candidates.push(keep(open_candidate("kept", now, 4)));
        candidates.push(open_candidate("queued", now, 3));

        let verdicts = classify_open_candidates(&candidates, now);
        assert_eq!(verdicts.get("kept"), None);
        assert_eq!(verdicts.get("queued"), Some(&NotPlanned::OverBudget));
    }

    #[test]
    fn the_keep_label_cannot_be_used_to_exceed_the_budget() {
        let now = Timestamp::now();
        // The case above only shows a kept candidate spending a slot while one
        // is left. The bound is only real if the label also fails to buy a slot
        // once they are gone — otherwise labelling every candidate `keep` plans
        // every candidate, and the budget bounds nothing.
        let mut candidates: Vec<PostgresPolicyCandidate> = (0..DEFAULT_MAX_OPEN_CANDIDATES)
            .map(|i| open_candidate(&format!("live-{i:03}"), now, 5))
            .collect();
        candidates.push(keep(open_candidate("kept-over", now, 4)));

        let verdicts = classify_open_candidates(&candidates, now);
        assert_eq!(
            verdicts.get("kept-over"),
            Some(&NotPlanned::OverBudget),
            "keep exempts from the TTL, not from the budget"
        );

        // The strong form: an entire fleet of kept candidates is still bounded,
        // and the survivors are the oldest, exactly as for unlabelled ones.
        let all_kept: Vec<PostgresPolicyCandidate> = (0..DEFAULT_MAX_OPEN_CANDIDATES + 8)
            .map(|i| keep(open_candidate(&format!("k-{i:03}"), now, 5)))
            .collect();
        let verdicts = classify_open_candidates(&all_kept, now);
        assert_eq!(
            verdicts.len(),
            8,
            "everything past the budget must be queued however it is labelled"
        );
        assert_eq!(verdicts.get("k-000"), None);
        assert_eq!(
            verdicts.get(&format!("k-{:03}", DEFAULT_MAX_OPEN_CANDIDATES)),
            Some(&NotPlanned::OverBudget)
        );
    }

    #[test]
    fn terminal_candidates_are_neither_expired_nor_counted_against_the_budget() {
        let now = Timestamp::now();
        // Terminal candidates are retention's business, not the budget's;
        // counting them would let finished work crowd out live proposals.
        let mut candidates: Vec<PostgresPolicyCandidate> = (0..DEFAULT_MAX_OPEN_CANDIDATES)
            .map(|i| {
                let mut c = open_candidate(&format!("done-{i:03}"), now, TTL_HOURS + 5);
                c.status = Some(PostgresPolicyCandidateStatus {
                    phase: CandidatePhase::Promoted,
                    ..Default::default()
                });
                c
            })
            .collect();
        candidates.push(open_candidate("live", now, 1));

        let verdicts = classify_open_candidates(&candidates, now);
        assert!(
            verdicts.is_empty(),
            "terminal candidates are invisible to both the TTL and the budget"
        );
    }

    #[test]
    fn the_gate_blocks_only_a_parent_that_has_not_finished_its_own_work() {
        assert_eq!(parent_gate(true, false), ParentGate::Stable);
        assert_eq!(
            parent_gate(true, true),
            ParentGate::Blocked(BlockCause::AwaitingDecision)
        );
        assert_eq!(
            parent_gate(false, false),
            ParentGate::Blocked(BlockCause::Unstable)
        );
        // A failing parent is blocked whether or not a plan of its own is open;
        // "unstable" is the cause a reviewer needs to see first.
        assert_eq!(
            parent_gate(false, true),
            ParentGate::Blocked(BlockCause::Unstable)
        );
    }

    #[test]
    fn candidate_planning_never_materialises_secrets() {
        // A generated password with no Secret yet: the sole route to
        // `ensure_generated_secret` is the `pending_materialization` marker,
        // and the candidate seam returns strings only, so it cannot survive.
        let resolved = BTreeMap::from([(
            "reporting_reader".to_string(),
            ResolvedPassword {
                cleartext: "in-memory".to_string(),
                source_version: "orders-reporting-reader:password:missing".to_string(),
                pending_materialization: Some(crate::reconciler::PendingGeneratedSecret {
                    role: "reporting_reader".to_string(),
                    spec: GeneratePasswordSpec {
                        length: None,
                        secret_name: None,
                        secret_key: None,
                    },
                }),
            },
        )]);
        let changes = vec![pgroles_core::diff::Change::CreateRole {
            name: "reporting_reader".to_string(),
            state: Default::default(),
        }];

        let (passwords, versions) =
            candidate_password_changes(&changes, &resolved, &policy("orders"));

        assert_eq!(
            passwords.get("reporting_reader").map(String::as_str),
            Some("in-memory")
        );
        // The sentinel is what reaches the digest, so the plan's identity says
        // out loud that the credential does not exist yet.
        assert_eq!(
            versions.get("reporting_reader").map(String::as_str),
            Some("orders-reporting-reader:password:missing")
        );
    }

    /// The safety property in structural form: nothing on the candidate
    /// planning path may call a writer. A unit test cannot observe the absence
    /// of an API call without a fake API server, but it *can* observe that the
    /// module never names the two functions that perform the writes — Secret
    /// materialisation and SQL execution — which is the property this phase
    /// promises, and it fails the moment someone reaches for one.
    #[test]
    fn the_candidate_module_calls_no_writer() {
        let source = include_str!("candidate.rs");
        // This test's own body names them, and so does the prose explaining
        // why they are absent; neither is a call.
        let body: String = source
            .split_once("mod tests {")
            .map(|(before, _)| before)
            .expect("this module has a test module")
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//")
            })
            .collect::<Vec<_>>()
            .join("\n");
        for writer in [
            "ensure_generated_secret",
            "materialize_pending_generated_secrets",
            "execute_changes_in_transaction",
            "execute_plan",
        ] {
            assert!(
                !body.contains(&format!("{writer}(")),
                "candidate planning must not call {writer}: planning adds no writes beyond the \
                 active policy's own reconcile"
            );
        }
    }

    /// Exercise the same effect pipeline used by both planners with candidate
    /// content: undeclared ACLs are adoption state, not proposed revocations.
    #[test]
    fn candidate_preservation_filters_effects_before_sql_and_approval_digest() {
        use pgroles_core::diff::Change;
        use pgroles_core::manifest::{ObjectType, Privilege};
        use pgroles_core::model::{GrantKey, GrantState};

        for preserve in [false, true] {
            let content: PolicyContent = serde_json::from_value(serde_json::json!({
                "reconciliationMode": "authoritative",
                "roles": [{ "name": "app_reader", "preserve_undeclared_grants": preserve }],
                "grants": [{
                    "role": "app_reader", "privileges": ["DELETE"], "ensure": "absent",
                    "object": { "type": "table", "schema": "app", "name": "records" }
                }]
            }))
            .expect("content");
            let proposal = candidate("reader-change", content);
            let inputs = candidate_inputs(&proposal, &[]).expect("inputs");
            let mut current = inputs.desired.clone();
            current.grant_absences.clear();
            current.grants.insert(
                GrantKey {
                    role: "app_reader".into(),
                    object_type: ObjectType::Table,
                    schema: Some("app".into()),
                    name: Some("records".into()),
                },
                GrantState {
                    privileges: BTreeSet::from([Privilege::Select, Privilege::Delete]),
                },
            );
            let changes = crate::reconciler::policy_changes(
                &current,
                &inputs.desired,
                &inputs.manifest,
                &inputs.expanded,
                pgroles_core::diff::ReconciliationMode::Authoritative,
            );
            let expected = vec![Change::Revoke {
                role: "app_reader".into(),
                object_type: ObjectType::Table,
                schema: Some("app".into()),
                name: Some("records".into()),
                grantor: None,
                privileges: if preserve {
                    BTreeSet::from([Privilege::Delete])
                } else {
                    BTreeSet::from([Privilege::Select, Privilege::Delete])
                },
            }];
            assert_eq!(changes, expected, "preserve={preserve}");
            let sql = pgroles_core::sql::render_batch_with_context(
                &changes,
                &pgroles_core::sql::SqlContext::default(),
            )
            .into_iter()
            .map(|statement| statement.redacted_sql)
            .collect::<Vec<_>>()
            .join("\n");
            assert!(sql.contains("DELETE"));
            assert_eq!(sql.contains("SELECT"), !preserve);
            let digest = |effects: &[Change]| {
                crate::plan::compute_change_digest(
                    effects,
                    crate::crd::CrdReconciliationMode::Authoritative,
                    "default/database:DATABASE_URL",
                    &pgroles_core::approval::TargetIdentity {
                        physical: Some("7412330000000000001".into()),
                        logical: None,
                    },
                    &BTreeMap::new(),
                    &[],
                    &[],
                )
                .expect("digest")
            };
            assert_eq!(digest(&changes), digest(&expected));
            if preserve {
                assert_ne!(
                    digest(&changes),
                    digest(&pgroles_core::diff::diff(&current, &inputs.desired))
                );
                // Once the explicit absence is satisfied, the remaining
                // undeclared grant produces NoEffects, hence no approval plan.
                current
                    .grants
                    .values_mut()
                    .next()
                    .unwrap()
                    .privileges
                    .remove(&Privilege::Delete);
                assert!(
                    crate::reconciler::policy_changes(
                        &current,
                        &inputs.desired,
                        &inputs.manifest,
                        &inputs.expanded,
                        pgroles_core::diff::ReconciliationMode::Authoritative,
                    )
                    .is_empty()
                );
            }
        }
    }

    #[test]
    fn candidate_preservation_keeps_default_and_membership_revocations() {
        use pgroles_core::diff::{Change, ReconciliationMode};
        use pgroles_core::manifest::{ObjectType, Privilege};
        use pgroles_core::model::{DefaultPrivKey, DefaultPrivState, DefaultPrivilegeScope};

        let content: PolicyContent = serde_json::from_value(serde_json::json!({
            "roles": [{ "name": "reader", "preserve_undeclared_grants": true },
                      { "name": "owner" }]
        }))
        .expect("content");
        let inputs = candidate_inputs(&candidate("reader-change", content), &[]).expect("inputs");
        let mut current = inputs.desired.clone();
        current.memberships.insert(MembershipEdge {
            role: "owner".into(),
            member: "reader".into(),
            inherit: true,
            admin: false,
        });
        current.default_privileges.insert(
            DefaultPrivKey {
                owner: "owner".into(),
                grantee: "reader".into(),
                scope: DefaultPrivilegeScope::Schema {
                    schema: "app".into(),
                },
                on_type: ObjectType::Table,
            },
            DefaultPrivState {
                privileges: BTreeSet::from([Privilege::Select]),
            },
        );
        let changes = crate::reconciler::policy_changes(
            &current,
            &inputs.desired,
            &inputs.manifest,
            &inputs.expanded,
            ReconciliationMode::Authoritative,
        );
        assert_eq!(changes.len(), 2);
        assert!(
            changes
                .iter()
                .any(|change| matches!(change, Change::RevokeDefaultPrivilege { .. }))
        );
        assert!(
            changes
                .iter()
                .any(|change| matches!(change, Change::RemoveMember { .. }))
        );
        assert!(
            crate::reconciler::policy_changes(
                &current,
                &inputs.desired,
                &inputs.manifest,
                &inputs.expanded,
                ReconciliationMode::Additive,
            )
            .is_empty()
        );
    }

    /// The inspection scope of a candidate is the candidate's own — its
    /// content, the roles it retires, and the overlay roles it inherited — and
    /// nothing of the policy's. This is what makes the shared snapshot a union
    /// rather than a reuse of the parent's read.
    #[test]
    fn a_candidates_inspection_scope_is_its_own_content_plus_retirements_and_overlay() {
        let content: PolicyContent = serde_json::from_value(serde_json::json!({
            "roles": [{ "name": "reporting_reader" }, { "name": "app_owner" }],
            "grants": [{
                "role": "reporting_reader",
                "privileges": ["SELECT"],
                "object": { "type": "table", "schema": "reporting", "name": "*" },
            }],
            "retirements": [{ "role": "legacy_reader" }],
            "memberships": [{ "role": "app_owner", "members": [{ "name": "reporting_reader" }] }],
        }))
        .expect("candidate content");
        let candidate = candidate("orders-change-x7k2p", content);

        // An overlay edge between two roles the candidate declares is composed
        // in, so both of its roles enter the inspection scope.
        let overlay = vec![MembershipEdge {
            role: "app_owner".to_string(),
            member: "grafana".to_string(),
            inherit: true,
            admin: false,
        }];
        let inputs = candidate_inputs(&candidate, &overlay).expect("inputs");

        assert!(
            inputs
                .inspect_config
                .managed_roles
                .contains(&"reporting_reader".to_string())
        );
        assert!(
            inputs
                .inspect_config
                .managed_roles
                .contains(&"legacy_reader".to_string()),
            "a retired role must stay in scope or its drop cannot be planned"
        );
        assert!(
            !inputs
                .inspect_config
                .managed_roles
                .contains(&"grafana".to_string()),
            "an overlay edge whose member the candidate does not declare is left out"
        );
        assert_eq!(
            inputs.inspect_config.privilege_schemas,
            vec!["reporting".to_string()]
        );
    }

    /// The union of two candidates' scopes contains both, which is exactly the
    /// property that lets one read serve both derivations.
    #[test]
    fn the_union_of_candidate_scopes_contains_every_candidates_scope() {
        let make = |role: &str, schema: &str| {
            let content: PolicyContent = serde_json::from_value(serde_json::json!({
                "roles": [{ "name": role }],
                "grants": [{
                    "role": role,
                    "privileges": ["SELECT"],
                    "object": { "type": "table", "schema": schema, "name": "*" },
                }],
            }))
            .expect("candidate content");
            candidate_inputs(&candidate("orders-change-x7k2p", content), &[])
                .expect("inputs")
                .inspect_config
        };

        let first = make("reporting_reader", "reporting");
        let second = make("billing_reader", "billing");
        let union = pgroles_inspect::InspectConfig::union_of([&first, &second]);

        for config in [&first, &second] {
            for role in &config.managed_roles {
                assert!(union.managed_roles.contains(role));
            }
            for schema in &config.privilege_schemas {
                assert!(union.privilege_schemas.contains(schema));
            }
        }
        // Wildcard pattern merging itself is covered by the inspect crate's
        // `union_merges_wildcard_privileges_for_the_same_pattern`.
    }

    #[test]
    fn an_override_target_resolves_through_the_ordinary_connection_spec() {
        let spec = override_connection_spec(&CandidateTarget {
            connection_ref: crate::crd::CandidateConnectionRef {
                secret_name: "orders-new-postgres".to_string(),
                key: "url".to_string(),
            },
        });
        assert_eq!(
            spec.secret_ref.as_ref().map(|r| r.name.as_str()),
            Some("orders-new-postgres")
        );
        assert_eq!(spec.effective_secret_key(), "url");
        assert!(spec.params.is_none());
        // Identity, fingerprint and locking all derive from this spec, which is
        // what makes the override bind the destination's identity rather than
        // the parent's.
        assert!(!spec.requires_physical_identity());
    }

    #[test]
    fn the_owner_reference_is_a_controller_reference_to_the_policy() {
        let policy = policy("orders");
        let owner = policy_owner_reference(&policy);
        assert_eq!(owner.kind, "PostgresPolicy");
        assert_eq!(owner.uid, "orders-uid");
        assert_eq!(owner.controller, Some(true));

        let mut candidate = candidate("orders-change-x7k2p", PolicyContent::default());
        assert!(!has_policy_owner_reference(&candidate, "orders-uid"));
        candidate.metadata.owner_references = Some(vec![owner]);
        assert!(has_policy_owner_reference(&candidate, "orders-uid"));
        // A same-named policy that was deleted and recreated must not inherit
        // the old one's candidates.
        assert!(!has_policy_owner_reference(&candidate, "orders-uid-2"));
    }

    /// Ownership by UID, declaration by name. A recreated same-name policy
    /// must not inherit — and above all must not promote through — candidates
    /// adopted by its deleted predecessor.
    #[test]
    fn a_candidate_belongs_only_to_the_policy_that_adopted_it() {
        let orders = policy("orders");
        let mut unadopted = candidate("orders-change-x7k2p", PolicyContent::default());

        // Wrong name never matches, adopted or not.
        assert!(!candidate_belongs_to(&unadopted, &policy("billing")));

        // Right name, no controller reference yet: belongs, pending adoption.
        assert!(candidate_belongs_to(&unadopted, &orders));

        // Adopted by this policy: still belongs.
        unadopted.metadata.owner_references = Some(vec![policy_owner_reference(&orders)]);
        let adopted = unadopted;
        assert!(candidate_belongs_to(&adopted, &orders));

        // Same name, different UID — the deleted-and-recreated policy. The
        // candidate is the predecessor's, awaiting garbage collection.
        let mut recreated = policy("orders");
        recreated.metadata.uid = Some("orders-uid-2".to_string());
        assert!(!candidate_belongs_to(&adopted, &recreated));

        // A policy that cannot prove its identity claims nothing it has not
        // merely been named by.
        let mut anonymous = policy("orders");
        anonymous.metadata.uid = None;
        assert!(!candidate_belongs_to(&adopted, &anonymous));
        // ...though an unadopted candidate still matches by name alone.
        let fresh = candidate("orders-change-a1b2c", PolicyContent::default());
        assert!(candidate_belongs_to(&fresh, &anonymous));
    }

    #[test]
    fn phases_are_terminal_exactly_where_the_docs_say() {
        assert!(CandidatePhase::Promoted.is_terminal());
        assert!(CandidatePhase::Superseded.is_terminal());
        assert!(!CandidatePhase::Pending.is_terminal());
        assert!(!CandidatePhase::Planned.is_terminal());
        assert!(!CandidatePhase::Stale.is_terminal());
    }

    #[test]
    fn a_blocked_cause_says_which_half_of_the_rule_fired() {
        assert!(
            BlockCause::AwaitingDecision
                .message()
                .contains("awaiting a decision")
        );
        assert!(BlockCause::Unstable.message().contains("not converging"));
    }

    #[test]
    fn the_content_digest_is_the_phase_1a_digest() {
        let candidate = candidate(
            "orders-change-x7k2p",
            PolicyContent {
                roles: vec![role("reporting_reader")],
                ..Default::default()
            },
        );
        assert_eq!(
            content_digest(&candidate),
            pgroles_core::candidate::compute_content_digest(&candidate.spec.content)
        );
        assert!(content_digest(&candidate).starts_with("sha256:"));
    }
}
