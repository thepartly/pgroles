//! Operator scenarios against a live cluster.
//!
//! They run against the kind cluster `.github/actions/setup-e2e` creates: the
//! operator in `pgroles-system`, PostgreSQL as `postgres-0` in `default`, and
//! the `postgres-credentials` Secret. Run them with
//!
//! ```text
//! cargo test -p pgroles-operator --features cluster-e2e --test cluster_e2e -- --test-threads=1
//! ```
//!
//! No step sleeps for a period and assumes the operator acted within it. A
//! wait follows a watch until the cluster shows the state it names. A check
//! that something did *not* change first requests a reconcile and waits for
//! the operator to acknowledge that it ran
//! (`status.lastAttemptedReconcileAt`), so the check describes a reconcile
//! that happened rather than a guess at one. Timeouts only bound a failure.
//!
//! Scenarios share one database, so they run one at a time, name every role
//! and resource with their own prefix, and clean up even when they fail.

mod candidate_authority;
mod candidate_guards;
mod harness;
mod membership_options;
mod plan_authority;
