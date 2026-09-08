//! pgroles-operator — Kubernetes operator for PostgresPolicy CRDs.
//!
//! Watches `PostgresPolicy` custom resources and reconciles PostgreSQL roles,
//! grants, default privileges, and memberships against live databases.

pub mod advisory;
pub mod candidate;
pub mod concurrency;
pub mod context;
pub mod controller_health;
pub mod crd;
pub mod ephemeral;
pub mod events;
pub mod k8s_names;
pub mod observability;
pub mod password;
pub mod plan;
pub mod promotion;
pub mod reconciler;
pub mod request_index;

mod telemetry_resource;
