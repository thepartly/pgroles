//! Custom Resource Definition for `PostgresPolicy`.
//!
//! Defines the `pgroles.io/v1alpha1` CRD that the operator watches.
//! The spec mirrors the CLI manifest schema with additional fields for
//! database connection and reconciliation scheduling.

use kube::{CustomResource, KubeSchema};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use pgroles_core::bounds::*;
use pgroles_core::manifest::{
    DefaultPrivilege, Ensure, Grant, Membership, ObjectType, Privilege, RoleRetirement,
    SchemaBinding,
};

/// Valid PostgreSQL SSL modes for connection params.
pub const VALID_SSL_MODES: &[&str] = &[
    "disable",
    "allow",
    "prefer",
    "require",
    "verify-ca",
    "verify-full",
];

// ---------------------------------------------------------------------------
// CRD spec
// ---------------------------------------------------------------------------

/// Spec for a `PostgresPolicy` custom resource.
///
/// Defines the desired state of PostgreSQL roles, grants, default privileges,
/// and memberships for a single database connection.
#[derive(CustomResource, KubeSchema, Debug, Clone, Serialize, Deserialize)]
#[kube(
    group = "pgroles.io",
    version = "v1alpha1",
    kind = "PostgresPolicy",
    namespaced,
    status = "PostgresPolicyStatus",
    shortname = "pgr",
    category = "pgroles",
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type==\"Ready\")].status"}"#,
    printcolumn = r#"{"name":"Mode","type":"string","jsonPath":".spec.mode"}"#,
    printcolumn = r#"{"name":"Recon","type":"string","jsonPath":".spec.reconciliation_mode","priority":1}"#,
    printcolumn = r#"{"name":"Drift","type":"string","jsonPath":".status.conditions[?(@.type==\"Drifted\")].status"}"#,
    printcolumn = r#"{"name":"Changes","type":"integer","jsonPath":".status.change_summary.total"}"#,
    printcolumn = r#"{"name":"Last Reconcile","type":"date","jsonPath":".status.last_successful_reconcile_time"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
pub struct PostgresPolicySpec {
    /// Database connection configuration.
    pub connection: ConnectionSpec,

    /// Reconciliation interval (e.g. "5m", "1h"). Defaults to "5m".
    #[serde(default = "default_interval")]
    pub interval: String,

    /// Suspend reconciliation when true. Defaults to false.
    #[serde(default)]
    pub suspend: bool,

    /// Reconciliation mode: `apply` executes SQL, `observe` computes drift only.
    #[serde(default)]
    pub mode: PolicyMode,

    /// Convergence strategy: how aggressively to converge the database.
    ///
    /// - `authoritative` (default): full convergence — anything not in the
    ///   manifest is revoked/dropped.
    /// - `additive`: only grant, never revoke — safe for incremental adoption;
    ///   `ensure: absent` assertions are ignored with a warning condition.
    /// - `adopt`: manage declared roles fully, but never drop undeclared roles.
    #[serde(default)]
    pub reconciliation_mode: CrdReconciliationMode,

    /// Default owner for ALTER DEFAULT PRIVILEGES (e.g. "app_owner").
    #[serde(default)]
    #[schemars(length(min = 1, max = MAX_IDENTIFIER))]
    pub default_owner: Option<String>,

    /// Reusable privilege profiles.
    #[serde(default)]
    #[schemars(extend("maxProperties" = MAX_PROFILES))]
    pub profiles: std::collections::HashMap<String, ProfileSpec>,

    /// Schema bindings that expand profiles into concrete roles/grants.
    ///
    /// Keyed by `name` so server-side apply merges entries per schema instead
    /// of replacing the whole list. The API server also rejects duplicate keys.
    #[serde(default)]
    #[schemars(length(max = MAX_SCHEMAS))]
    #[x_kube(merge_strategy = ListMerge::Map(vec!["name".into()]))]
    pub schemas: Vec<SchemaBinding>,

    /// One-off role definitions.
    ///
    /// Keyed by `name`; see `schemas`.
    #[serde(default)]
    #[schemars(length(max = MAX_ROLES))]
    #[x_kube(merge_strategy = ListMerge::Map(vec!["name".into()]))]
    pub roles: Vec<RoleSpec>,

    /// One-off grants.
    #[serde(default)]
    #[schemars(length(max = MAX_GRANTS))]
    pub grants: Vec<Grant>,

    /// One-off default privileges.
    #[serde(default)]
    #[schemars(length(max = MAX_DEFAULT_PRIVILEGES))]
    pub default_privileges: Vec<DefaultPrivilege>,

    /// Membership edges.
    #[serde(default)]
    #[schemars(length(max = MAX_MEMBERSHIPS))]
    pub memberships: Vec<Membership>,

    /// Explicit role-retirement workflows for roles that should be removed.
    ///
    /// Keyed by `role`, which is this list's unique identifier rather than
    /// `name`. Retiring one role twice was never meaningful, so the key is
    /// unambiguous.
    #[serde(default)]
    #[schemars(length(max = MAX_RETIREMENTS))]
    #[x_kube(merge_strategy = ListMerge::Map(vec!["role".into()]))]
    pub retirements: Vec<RoleRetirement>,

    /// Approval mode for plans: `auto` or `manual`.
    /// When `manual`, plans require explicit approval before execution.
    /// When `auto`, plans are approved and applied immediately.
    ///
    /// Omitting this is deprecated. It is still inferred from `mode`
    /// (`apply` → `auto`, `observe` → `manual`) so existing policies keep working,
    /// but the policy reports an `ApprovalUnset` condition until the field is
    /// set, and a future release will reject a policy that omits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalMode>,
}

fn default_interval() -> String {
    "5m".to_string()
}

/// Policy reconcile mode.
///
/// Deliberately not `PartialEq`: `plan` is a deprecated spelling of `observe`
/// that must behave identically everywhere, and an `==` comparison is exactly
/// the kind of site that forgets one of the two. Compare through
/// [`PolicyMode::never_executes`] and [`PolicyMode::is_deprecated_spelling`],
/// or match exhaustively.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    #[default]
    Apply,
    /// Compute and publish plans, never execute. The current name: "plan"
    /// should name exactly one artifact, the `PostgresPolicyPlan` (ADR-001).
    Observe,
    /// Deprecated spelling of `observe`, kept as an accepted schema value so
    /// existing manifests — including ones a GitOps controller re-applies on
    /// every sync — keep working across the rename. Behaviour is identical to
    /// `observe` in every path; policies using it report a
    /// `ModeValueDeprecated` condition and count toward
    /// `pgroles.deprecated.mode_plan`. A future release removes the value.
    Plan,
}

impl PolicyMode {
    /// Whether this mode never executes SQL — `observe`, under either
    /// spelling.
    pub fn never_executes(self) -> bool {
        matches!(self, PolicyMode::Observe | PolicyMode::Plan)
    }

    /// Whether this is the deprecated `plan` spelling of `observe`.
    pub fn is_deprecated_spelling(self) -> bool {
        matches!(self, PolicyMode::Plan)
    }
}

/// Convergence strategy for how aggressively to converge the database.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CrdReconciliationMode {
    /// Full convergence — the manifest is the entire truth.
    #[default]
    Authoritative,
    /// Only grant, never revoke — safe for incremental adoption.
    Additive,
    /// Manage declared roles fully, but never drop undeclared roles.
    Adopt,
}

/// Approval mode for plans generated by this policy.
///
/// Set this explicitly. When omitted it is currently inferred from `spec.mode`
/// (`apply` implies `auto`, `observe` implies `manual`), which leaves a policy's
/// execution gate invisible on the object. That inference is deprecated: a
/// policy relying on it reports an `ApprovalUnset` status condition, and a
/// future release will reject a policy that omits this field.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum ApprovalMode {
    /// Plans require an explicit terminal `Approved` decision on the plan's
    /// status subresource before execution.
    #[serde(rename = "manual")]
    Manual,
    /// Plans are approved and applied automatically.
    #[serde(rename = "auto")]
    Auto,
}

impl PostgresPolicySpec {
    /// Resolve the effective approval mode, inferring from `mode` when not set.
    /// `apply` → `Auto` (backward compat), `observe` → `Manual`.
    pub fn effective_approval(&self) -> ApprovalMode {
        match &self.approval {
            Some(mode) => mode.clone(),
            None => match self.mode {
                PolicyMode::Apply => ApprovalMode::Auto,
                PolicyMode::Observe | PolicyMode::Plan => ApprovalMode::Manual,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Well-known annotations and labels
// ---------------------------------------------------------------------------

/// Annotation key used to request an immediate `PostgresPolicy` reconcile.
pub const REQUESTED_RECONCILE_ANNOTATION: &str = "reconcile.pgroles.io/requestedAt";

/// Label key for the parent policy name on plan resources.
pub const LABEL_POLICY: &str = "pgroles.io/policy";

/// Label key for the managed database identity on plan resources.
pub const LABEL_DATABASE_IDENTITY: &str = "pgroles.io/database-identity";

/// Label key for the plan name on SQL storage resources.
pub const LABEL_PLAN: &str = "pgroles.io/plan";
/// Label key for the parent candidate name on candidate-origin plans.
pub const LABEL_CANDIDATE: &str = "pgroles.io/candidate";
/// Label exempting an object from bounded retention. Set to `"true"` on a
/// terminal candidate (or plan) to keep it past the retention bound.
pub const LABEL_KEEP: &str = "pgroles.io/keep";

/// Is this object exempt from bounded retention?
pub fn is_retention_exempt<K: kube::Resource>(resource: &K) -> bool {
    resource
        .meta()
        .labels
        .as_ref()
        .and_then(|labels| labels.get(LABEL_KEEP))
        .is_some_and(|value| value == "true")
}
/// Routing hint for requests resolved from one access-policy UID.
pub const LABEL_ACCESS_POLICY_UID: &str = "pgroles.io/access-policy-uid";
/// Routing hint for requests resolved against one target-policy UID.
pub const LABEL_TARGET_POLICY_UID: &str = "pgroles.io/target-policy-uid";

impl From<CrdReconciliationMode> for pgroles_core::diff::ReconciliationMode {
    fn from(crd: CrdReconciliationMode) -> Self {
        match crd {
            CrdReconciliationMode::Authoritative => {
                pgroles_core::diff::ReconciliationMode::Authoritative
            }
            CrdReconciliationMode::Additive => pgroles_core::diff::ReconciliationMode::Additive,
            CrdReconciliationMode::Adopt => pgroles_core::diff::ReconciliationMode::Adopt,
        }
    }
}

/// Database connection configuration.
///
/// Supports two mutually exclusive modes:
///
/// **Mode 1 — Single URL** (backward-compatible):
/// ```yaml
/// connection:
///   secretRef: { name: my-secret }
///   secretKey: DATABASE_URL        # optional, defaults to DATABASE_URL
/// ```
///
/// **Mode 2 — Structured params** (for Zalando/CNPG/PGO secrets):
/// ```yaml
/// connection:
///   params:
///     host: my-cluster-postgres
///     port: 5432
///     dbname: mydb
///     usernameSecret: { name: zalando-creds, key: username }
///     passwordSecret: { name: zalando-creds, key: password }
/// ```
///
/// Params mode can also use provider-backed authentication instead of a static
/// password, for example GKE Workload Identity to Cloud SQL IAM.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionSpec {
    /// Reference to a Kubernetes Secret containing a connection URL.
    /// Mutually exclusive with `params`.
    #[serde(default)]
    pub secret_ref: Option<SecretReference>,

    /// Key within the Secret to read. Defaults to `DATABASE_URL`.
    /// Only used with `secretRef`.
    #[serde(default)]
    pub secret_key: Option<String>,

    /// Structured connection parameters. Each field is either a plain string
    /// or a reference to a Secret key. Mutually exclusive with `secretRef`.
    #[serde(default)]
    pub params: Option<ConnectionParams>,

    /// Refuse to plan or execute unless the target's *physical* identity —
    /// `pg_control_system().system_identifier` — can be read.
    ///
    /// Off by default: every mainstream managed PostgreSQL exposes the
    /// identifier, but PostgreSQL-protocol engines that are not PostgreSQL
    /// (CockroachDB, Spanner's PostgreSQL interface, Redshift, Aurora DSQL) do
    /// not implement it, and those targets run on the logical identity alone.
    /// Set it where a real PostgreSQL is expected and losing the strongest
    /// half of the target binding should stop reconciliation rather than
    /// silently weaken it.
    #[serde(default)]
    pub require_physical_identity: Option<bool>,
}

impl ConnectionSpec {
    /// Whether the physical target identity is mandatory for this connection.
    pub fn requires_physical_identity(&self) -> bool {
        self.require_physical_identity.unwrap_or(false)
    }
    /// Effective secret key for URL mode. Defaults to `DATABASE_URL`.
    pub fn effective_secret_key(&self) -> &str {
        self.secret_key.as_deref().unwrap_or("DATABASE_URL")
    }

    /// Collect all Secret names referenced by this connection spec.
    pub fn collect_secret_names(&self, names: &mut BTreeSet<String>) {
        if let Some(ref secret_ref) = self.secret_ref {
            names.insert(secret_ref.name.clone());
        }
        if let Some(ref params) = self.params {
            for sel in [
                &params.host_secret,
                &params.port_secret,
                &params.dbname_secret,
                &params.username_secret,
                &params.password_secret,
                &params.ssl_mode_secret,
            ]
            .into_iter()
            .flatten()
            {
                names.insert(sel.name.clone());
            }
        }
    }

    /// Deterministic identity key for per-database locking and conflict
    /// detection.
    ///
    /// - URL mode: `{secret_ref.name}/{secret_key}`
    /// - Params mode: canonical representation of the params
    ///
    /// Uses `\0` as field separator since null bytes cannot appear in K8s names
    /// or secret values, avoiding ambiguity from colons in literal values.
    ///
    /// This is a *Kubernetes-level* key, not a database identity. In URL mode
    /// it names only the Secret and key, so repointing that Secret at a
    /// different server leaves it unchanged; in params mode it covers host,
    /// port and dbname only when those are literals, and covers the Secret
    /// reference (not its value) when they are not. Two policies targeting the
    /// same database with different credentials do share it, which is what
    /// locking and overlap checks need. What the database actually *is* comes
    /// from the resolved target identity bound into the approval digest — see
    /// `pgroles_core::approval::TargetIdentity`.
    pub fn identity_key(&self) -> String {
        if let Some(ref secret_ref) = self.secret_ref {
            format!("{}/{}", secret_ref.name, self.effective_secret_key())
        } else if let Some(ref params) = self.params {
            let port_part = params
                .port
                .as_ref()
                .map(|p| format!("literal={p}"))
                .or_else(|| {
                    params
                        .port_secret
                        .as_ref()
                        .map(|s| format!("secret={}\0{}", s.name, s.key))
                })
                .unwrap_or_else(|| "5432".to_string());
            format!(
                "params\0{}\0{}\0{}",
                field_identity_repr(&params.host, &params.host_secret),
                field_identity_repr(&params.dbname, &params.dbname_secret),
                port_part,
            )
        } else {
            "invalid-connection".to_string()
        }
    }

    /// Cache key for pool lookup. Includes ALL connection params so that any
    /// configuration change (credentials, sslMode, host, etc.) invalidates
    /// the cached pool. This is strictly more specific than `identity_key`.
    pub fn cache_key(&self, namespace: &str) -> String {
        if let Some(ref params) = self.params {
            let user_part = field_identity_repr(&params.username, &params.username_secret);
            let pass_part = field_identity_repr(&params.password, &params.password_secret);
            let auth_part = params
                .auth
                .as_ref()
                .map(ConnectionAuth::cache_key)
                .unwrap_or_default();
            let ssl_part = params
                .ssl_mode
                .as_ref()
                .map(|v| format!("literal={v}"))
                .or_else(|| {
                    params
                        .ssl_mode_secret
                        .as_ref()
                        .map(|s| format!("secret={}\0{}", s.name, s.key))
                })
                .unwrap_or_default();
            let role_part = params.set_role.as_deref().unwrap_or("");
            format!(
                "{namespace}/{}\0user={user_part}\0pass={pass_part}\0auth={auth_part}\0ssl={ssl_part}\0role={role_part}",
                self.identity_key()
            )
        } else {
            format!("{namespace}/{}", self.identity_key())
        }
    }
}

/// Deterministic string representation for a literal/secret field pair.
///
/// Uses a `literal=` / `secret=` prefix scheme so that a literal value
/// can never collide with a secret reference representation.
fn field_identity_repr(literal: &Option<String>, secret: &Option<SecretKeySelector>) -> String {
    if let Some(value) = literal {
        format!("literal={value}")
    } else if let Some(sel) = secret {
        format!("secret={}\0{}", sel.name, sel.key)
    } else {
        String::new()
    }
}

/// Default OAuth scope used for Cloud SQL IAM database login tokens.
pub const DEFAULT_GCP_CLOUD_SQL_LOGIN_SCOPE: &str =
    "https://www.googleapis.com/auth/sqlservice.login";

/// Structured connection parameters for building a PostgreSQL connection URL.
///
/// Each field supports either a literal value or a reference to a Kubernetes
/// Secret key. For each parameter, set either the literal field or the
/// corresponding `*Secret` field — not both.
///
/// ```yaml
/// # Zalando pattern — literals for non-sensitive, secrets for credentials
/// params:
///   host: my-cluster-postgres
///   port: 5432
///   dbname: mydb
///   sslMode: require
///   usernameSecret:
///     name: pg-creds
///     key: username
///   passwordSecret:
///     name: pg-creds
///     key: password
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionParams {
    /// PostgreSQL host as a literal value.
    #[serde(default)]
    pub host: Option<String>,
    /// PostgreSQL host from a Secret key.
    #[serde(default)]
    pub host_secret: Option<SecretKeySelector>,

    /// Port as a literal value. Defaults to 5432 if neither port nor portSecret is set.
    #[serde(default)]
    pub port: Option<u16>,
    /// Port from a Secret key.
    #[serde(default)]
    pub port_secret: Option<SecretKeySelector>,

    /// Database name as a literal value.
    #[serde(default)]
    pub dbname: Option<String>,
    /// Database name from a Secret key.
    #[serde(default)]
    pub dbname_secret: Option<SecretKeySelector>,

    /// Username as a literal value.
    #[serde(default)]
    pub username: Option<String>,
    /// Username from a Secret key.
    #[serde(default)]
    pub username_secret: Option<SecretKeySelector>,

    /// Password as a literal value (not recommended for production).
    #[serde(default)]
    pub password: Option<String>,
    /// Password from a Secret key (recommended).
    #[serde(default)]
    pub password_secret: Option<SecretKeySelector>,

    /// Provider-backed authentication for connections that use short-lived
    /// credentials instead of a static PostgreSQL password.
    #[serde(default)]
    pub auth: Option<ConnectionAuth>,

    /// SSL mode as a literal value.
    #[serde(default)]
    pub ssl_mode: Option<String>,
    /// SSL mode from a Secret key.
    #[serde(default)]
    pub ssl_mode_secret: Option<SecretKeySelector>,

    /// Run `SET ROLE "<value>"` once on every pooled connection. Useful when
    /// the operator authenticates as a low-privilege identity (e.g. a Cloud
    /// SQL IAM user) that has been granted membership in a privileged role
    /// like `cloudsqlsuperuser` — PostgreSQL does not inherit role
    /// *attributes* (`CREATEROLE`, `CREATEDB`, …) through `GRANT … TO …`, so
    /// `SET ROLE` is required for the connection to act with the parent
    /// role's attributes.
    ///
    /// Must be a simple PostgreSQL identifier matching
    /// `^[A-Za-z_][A-Za-z0-9_$-]*$`. The pattern intentionally excludes `@`
    /// and `.` — `setRole` is for switching to a privileged *group* role
    /// (e.g. `cloudsqlsuperuser`), not an IAM-style principal like
    /// `pgroles-operator@project.iam`, which has no extra attributes to
    /// inherit via `SET ROLE`.
    #[serde(default)]
    #[schemars(regex(pattern = SET_ROLE_PATTERN))]
    pub set_role: Option<String>,
}

/// Provider-backed authentication for `connection.params`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum ConnectionAuth {
    /// Fetch a Cloud SQL IAM database login token using the GKE metadata
    /// server. `username` must be the Cloud SQL PostgreSQL IAM role name
    /// (for service accounts, the email without `.gserviceaccount.com`).
    #[serde(rename = "gcp_workload_identity", rename_all = "camelCase")]
    GcpWorkloadIdentity {
        /// Target Google service account to impersonate before requesting the
        /// Cloud SQL login token. Omit to use the pod's bound identity.
        #[serde(default)]
        impersonate_service_account: Option<String>,
        /// OAuth scope requested for the access token.
        #[serde(default)]
        scope: Option<String>,
    },
}

impl ConnectionAuth {
    pub fn gcp_scope(&self) -> &str {
        match self {
            Self::GcpWorkloadIdentity { scope, .. } => scope
                .as_deref()
                .unwrap_or(DEFAULT_GCP_CLOUD_SQL_LOGIN_SCOPE),
        }
    }

    pub fn gcp_impersonate_service_account(&self) -> Option<&str> {
        match self {
            Self::GcpWorkloadIdentity {
                impersonate_service_account,
                ..
            } => impersonate_service_account.as_deref(),
        }
    }

    fn cache_key(&self) -> String {
        match self {
            Self::GcpWorkloadIdentity {
                impersonate_service_account,
                scope,
            } => format!(
                "gcp_workload_identity\0impersonate={}\0scope={}",
                impersonate_service_account.as_deref().unwrap_or_default(),
                scope
                    .as_deref()
                    .unwrap_or(DEFAULT_GCP_CLOUD_SQL_LOGIN_SCOPE)
            ),
        }
    }
}

/// Reference to a specific key within a Kubernetes Secret.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SecretKeySelector {
    /// Name of the Secret.
    #[schemars(length(min = 1, max = MAX_K8S_NAME))]
    pub name: String,
    /// Key within the Secret.
    #[schemars(length(min = 1, max = MAX_SECRET_KEY))]
    pub key: String,
}

/// Reference to a Kubernetes Secret in the same namespace.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SecretReference {
    /// Name of the Secret.
    #[schemars(length(min = 1, max = MAX_K8S_NAME))]
    pub name: String,
}

/// A reusable privilege profile (CRD-compatible version).
///
/// This mirrors `pgroles_core::manifest::Profile` but derives `JsonSchema`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProfileSpec {
    #[serde(default)]
    pub login: Option<bool>,

    #[serde(default)]
    pub inherit: Option<bool>,

    #[serde(default)]
    #[schemars(length(max = MAX_PROFILE_GRANTS))]
    pub grants: Vec<ProfileGrantSpec>,

    #[serde(default)]
    #[schemars(length(max = MAX_PROFILE_DEFAULT_PRIVILEGES))]
    pub default_privileges: Vec<DefaultPrivilegeGrantSpec>,

    /// Role-level configuration parameter defaults for generated roles,
    /// applied via `ALTER ROLE ... SET parameter = value`. Values support the
    /// `{schema}` and `{profile}` placeholders, substituted per `schema x
    /// profile` expansion (e.g. `search_path: "{schema}"`).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    #[schemars(extend("maxProperties" = MAX_CONFIG_ENTRIES))]
    pub config: std::collections::BTreeMap<String, pgroles_core::manifest::ConfigValue>,
}

/// Grant template within a profile.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProfileGrantSpec {
    #[schemars(length(min = 1, max = MAX_PRIVILEGES))]
    pub privileges: Vec<Privilege>,
    #[serde(alias = "on")]
    pub object: ProfileObjectTargetSpec,
    /// Whether the privilege must be present or absent. Matches the top-level
    /// `grants` entries, which carry the same field. Profiles are additive
    /// templates, so validation rejects `absent`; the schema accepts it so the
    /// API server does not prune the value before that check can name it.
    #[serde(default, skip_serializing_if = "Ensure::is_present")]
    pub ensure: Ensure,
}

/// Object target within a profile.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProfileObjectTargetSpec {
    #[serde(rename = "type")]
    pub object_type: ObjectType,
    #[serde(default)]
    #[schemars(length(min = 1, max = MAX_OBJECT_NAME))]
    pub name: Option<String>,
}

/// Default privilege grant within a profile.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DefaultPrivilegeGrantSpec {
    #[serde(default)]
    #[schemars(length(min = 1, max = MAX_IDENTIFIER))]
    pub role: Option<String>,
    #[schemars(length(min = 1, max = MAX_PRIVILEGES))]
    pub privileges: Vec<Privilege>,
    pub on_type: ObjectType,
    /// Whether the privilege must be present or absent. Matches the
    /// top-level `default_privileges` entries, which carry the same field.
    #[serde(default, skip_serializing_if = "Ensure::is_present")]
    pub ensure: Ensure,
}

/// A concrete role definition (CRD-compatible version).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RoleSpec {
    #[schemars(length(min = 1, max = MAX_IDENTIFIER))]
    pub name: String,
    /// Treat this role as externally managed. The operator may reference it in
    /// grants, ownership, and memberships, but will not create, alter, drop,
    /// password-manage, or manage memberships granted from this role.
    #[serde(default)]
    pub external: bool,
    /// Preserve this role's undeclared in-scope object grants during
    /// convergence. Revokes against the role are skipped unless the revoked
    /// privileges are explicitly asserted absent (`ensure: absent`).
    #[serde(default)]
    pub preserve_undeclared_grants: bool,
    #[serde(default)]
    pub login: Option<bool>,
    #[serde(default)]
    pub superuser: Option<bool>,
    #[serde(default)]
    pub createdb: Option<bool>,
    #[serde(default)]
    pub createrole: Option<bool>,
    #[serde(default)]
    pub inherit: Option<bool>,
    #[serde(default)]
    pub replication: Option<bool>,
    #[serde(default)]
    pub bypassrls: Option<bool>,
    #[serde(default)]
    pub connection_limit: Option<i32>,
    #[serde(default)]
    #[schemars(length(max = MAX_OBJECT_NAME))]
    pub comment: Option<String>,
    /// Password source for this role. Either a reference to an existing Secret
    /// or a request for the operator to generate one.
    #[serde(default)]
    pub password: Option<PasswordSpec>,
    /// Password expiration timestamp (ISO 8601, e.g. "2025-12-31T00:00:00Z").
    #[serde(default)]
    #[schemars(length(max = MAX_TIMESTAMP))]
    pub password_valid_until: Option<String>,
    /// Role-level configuration parameter defaults, applied via
    /// `ALTER ROLE ... SET parameter = value` (e.g. `role: combined`,
    /// `search_path: app`). Settings present on the role in the database but
    /// absent here are RESET in authoritative mode.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    #[schemars(extend("maxProperties" = MAX_CONFIG_ENTRIES))]
    pub config: std::collections::BTreeMap<String, pgroles_core::manifest::ConfigValue>,
}

/// Password configuration: either reference an existing Secret or have the
/// operator generate a password and create a Secret.
///
/// Exactly one of `secretRef` or `generate` must be set.
///
/// ```yaml
/// # Read from existing Secret:
/// password:
///   secretRef: { name: role-passwords }
///   secretKey: password-user
///
/// # Operator generates and manages a Secret:
/// password:
///   generate:
///     length: 48
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PasswordSpec {
    /// Reference to an existing Kubernetes Secret containing the password.
    /// Mutually exclusive with `generate`.
    #[serde(default)]
    pub secret_ref: Option<SecretReference>,
    /// Key within the referenced Secret. Defaults to the role name.
    /// Only used with `secretRef`.
    #[serde(default)]
    #[schemars(length(min = 1, max = MAX_SECRET_KEY))]
    pub secret_key: Option<String>,
    /// Generate a random password and store it in a new Kubernetes Secret.
    /// Mutually exclusive with `secretRef`.
    #[serde(default)]
    pub generate: Option<GeneratePasswordSpec>,
}

impl PasswordSpec {
    /// Returns true if this is a reference to an existing Secret.
    pub fn is_secret_ref(&self) -> bool {
        self.secret_ref.is_some()
    }

    /// Returns true if this is a request to generate a password.
    pub fn is_generate(&self) -> bool {
        self.generate.is_some()
    }
}

/// Configuration for operator-generated passwords.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GeneratePasswordSpec {
    /// Password length. Defaults to 32. Minimum 16, maximum 128.
    #[serde(default)]
    pub length: Option<u32>,
    /// Override the generated Secret name. Defaults to `{policy}-pgr-{role}`.
    #[serde(default)]
    #[schemars(length(min = 1, max = MAX_K8S_NAME))]
    pub secret_name: Option<String>,
    /// Key within the generated Secret. Defaults to `password`.
    #[serde(default)]
    #[schemars(length(min = 1, max = MAX_SECRET_KEY))]
    pub secret_key: Option<String>,
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum PasswordValidationError {
    #[error("role \"{role}\" has a password but login is not enabled")]
    PasswordWithoutLogin { role: String },

    #[error("role \"{role}\" password must set exactly one of secretRef or generate")]
    InvalidPasswordMode { role: String },

    #[error("role \"{role}\" password.generate.length must be between {min} and {max}")]
    InvalidGeneratedLength { role: String, min: u32, max: u32 },

    #[error(
        "role \"{role}\" password.generate.secretName \"{name}\" is not a valid Kubernetes Secret name"
    )]
    InvalidGeneratedSecretName { role: String, name: String },

    #[error("role \"{role}\" password {field} \"{key}\" is not a valid Kubernetes Secret data key")]
    InvalidSecretKey {
        role: String,
        field: &'static str,
        key: String,
    },

    #[error(
        "role \"{role}\" password.generate.secretKey \"{key}\" is reserved for the SCRAM verifier"
    )]
    ReservedGeneratedSecretKey { role: String, key: String },
}

/// Errors from connection spec validation.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConnectionValidationError {
    #[error("connection: exactly one of secretRef or params must be set, but both were provided")]
    BothModesSet,

    #[error("connection: exactly one of secretRef or params must be set, but neither was provided")]
    NeitherModeSet,

    #[error("connection.params.{field}: secret {detail}")]
    EmptySecretKeyRef { field: String, detail: String },

    #[error(
        "connection.params.sslMode: \"{value}\" is not valid (expected one of: disable, allow, prefer, require, verify-ca, verify-full)"
    )]
    InvalidSslMode { value: String },

    #[error("connection.params.{field}: literal value must not be empty or whitespace-only")]
    EmptyLiteral { field: String },

    #[error("connection.params: exactly one of {field} or {field}Secret must be set")]
    NeitherFieldSet { field: String },

    #[error(
        "connection.params: only one of {field} or {field}Secret may be set, but both were provided"
    )]
    BothFieldsSet { field: String },

    #[error("connection.params.auth: {field} must not be empty or whitespace-only")]
    EmptyAuthField { field: String },

    #[error("connection.params: password/passwordSecret are mutually exclusive with auth")]
    AuthWithPassword,

    #[error(
        "connection.params.setRole: \"{value}\" is not a valid PostgreSQL role identifier (must match {pattern})",
        pattern = SET_ROLE_PATTERN,
    )]
    InvalidRoleName { value: String },
}

/// Regex pattern restricting `connection.params.setRole` values.
///
/// Single source of truth: used by the `#[schemars(...)]` attribute on the
/// field (emitted into the CRD's OpenAPI schema), referenced by the
/// `InvalidRoleName` error message, and pinned by `is_valid_set_role_identifier`
/// via unit tests.
///
/// Intentionally rejects `@` and `.`, so IAM-email-style identifiers
/// (e.g. `pgroles-operator@project.iam`) cannot be a `setRole` target.
/// `SET ROLE` is meant for switching to a privileged *group* role like
/// `cloudsqlsuperuser`; IAM principals don't carry role attributes worth
/// switching to.
pub(crate) const SET_ROLE_PATTERN: &str = "^[A-Za-z_][A-Za-z0-9_$-]*$";

/// Returns true if `s` is a simple PostgreSQL role identifier matching
/// [`SET_ROLE_PATTERN`].
///
/// `SET ROLE` does not accept bind parameters, so any value reaching the
/// connection-pool hook is interpolated into the SQL string. Restricting
/// identifiers at admission time is defence in depth on top of the
/// double-quoting in the `after_connect` callback.
pub(crate) fn is_valid_set_role_identifier(s: &str) -> bool {
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_alphabetic() || b == b'_' => {}
        _ => return false,
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b == b'-')
}

/// Validate a Kubernetes Secret name per RFC 1123 DNS subdomain rules.
///
/// Delegates to [`crate::k8s_names::is_valid_resource_name`] so Secret names
/// are held to the same rules as every other resource name the operator builds.
fn is_valid_secret_name(name: &str) -> bool {
    crate::k8s_names::is_valid_resource_name(name)
}

fn is_valid_secret_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

// ---------------------------------------------------------------------------
// CRD status
// ---------------------------------------------------------------------------

/// Status of a `PostgresPolicy` resource.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct PostgresPolicyStatus {
    /// Standard Kubernetes conditions.
    #[serde(default)]
    pub conditions: Vec<PolicyCondition>,

    /// The `.metadata.generation` that was last successfully reconciled.
    #[serde(default)]
    pub observed_generation: Option<i64>,

    /// The `.metadata.generation` that was last attempted.
    #[serde(default)]
    pub last_attempted_generation: Option<i64>,

    /// ISO 8601 timestamp of the last successful reconciliation.
    #[serde(default)]
    pub last_successful_reconcile_time: Option<String>,

    /// Last force-reconcile annotation value handled by the operator.
    #[serde(default, rename = "lastHandledReconcileAt")]
    pub last_handled_reconcile_at: Option<String>,

    /// Summary of changes applied in the last reconciliation.
    #[serde(default)]
    pub change_summary: Option<ChangeSummary>,

    /// Advisory warnings from the last reconciliation's computed plan — for
    /// example adopt-mode schema ownership transfers or an undeclared
    /// `default_owner`. Populated even when the plan applied cleanly.
    #[serde(default)]
    pub plan_warnings: Vec<String>,

    /// The reconciliation mode used for the last successful reconcile.
    #[serde(default)]
    pub last_reconcile_mode: Option<PolicyMode>,

    /// Canonical identity of the managed database target.
    #[serde(default)]
    pub managed_database_identity: Option<String>,

    /// Roles claimed by this policy's declared ownership scope.
    #[serde(default)]
    pub owned_roles: Vec<String>,

    /// Schemas claimed by this policy's declared ownership scope.
    #[serde(default)]
    pub owned_schemas: Vec<String>,

    /// Last reconcile error message, if any.
    #[serde(default)]
    pub last_error: Option<String>,

    /// Last applied password source version for each password-managed role.
    #[serde(default)]
    pub applied_password_source_versions: BTreeMap<String, String>,

    /// Consecutive transient operational failures used for exponential backoff.
    #[serde(default)]
    pub transient_failure_count: i32,

    /// Reference to the current/latest plan for this policy.
    #[serde(default)]
    pub current_plan_ref: Option<PlanReference>,

    /// Canonical digest of this policy's own content, computed by exactly the
    /// same function as a candidate's `status.contentDigest` (note the wire
    /// names differ: this status object serialises snake_case, so the field is
    /// `status.content_digest` here).
    ///
    /// Promotion is recognised by comparing the two. The value is also the
    /// operator's memory of what the content was on the previous reconcile,
    /// which is how an edited-after-approval promotion is distinguished from a
    /// policy that simply has not changed while a candidate is under review.
    #[serde(default)]
    pub content_digest: Option<String>,
}

/// A condition on the `PostgresPolicy` resource.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicyCondition {
    /// Type of condition: "Ready", "Reconciling", "Degraded".
    #[serde(rename = "type")]
    pub condition_type: String,

    /// Status: "True", "False", or "Unknown".
    pub status: String,

    /// Human-readable reason for the condition.
    #[serde(default)]
    pub reason: Option<String>,

    /// Human-readable message.
    #[serde(default)]
    pub message: Option<String>,

    /// Last time the condition transitioned.
    #[serde(default)]
    pub last_transition_time: Option<String>,
}

/// Reference to a `PostgresPolicyPlan` resource.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PlanReference {
    pub name: String,
}

/// Summary of changes applied during reconciliation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct ChangeSummary {
    #[serde(default)]
    pub roles_created: i32,
    #[serde(default)]
    pub roles_altered: i32,
    #[serde(default)]
    pub schemas_created: i32,
    #[serde(default)]
    pub schema_owners_altered: i32,
    #[serde(default)]
    pub roles_dropped: i32,
    #[serde(default)]
    pub sessions_terminated: i32,
    #[serde(default)]
    pub grants_added: i32,
    #[serde(default)]
    pub grants_revoked: i32,
    #[serde(default)]
    pub default_privileges_set: i32,
    #[serde(default)]
    pub default_privileges_revoked: i32,
    #[serde(default)]
    pub members_added: i32,
    #[serde(default)]
    pub members_removed: i32,
    #[serde(default)]
    pub passwords_set: i32,
    #[serde(default)]
    pub total: i32,
}

// ---------------------------------------------------------------------------
// PostgresPolicyPlan CRD
// ---------------------------------------------------------------------------

/// Spec for a `PostgresPolicyPlan` custom resource.
///
/// Represents a computed reconciliation plan for a `PostgresPolicy`. Plans are
/// created by the operator and may require explicit approval before execution.
#[derive(CustomResource, KubeSchema, Debug, Clone, Serialize, Deserialize)]
#[kube(
    group = "pgroles.io",
    version = "v1alpha1",
    kind = "PostgresPolicyPlan",
    namespaced,
    status = "PostgresPolicyPlanStatus",
    shortname = "pgplan",
    category = "pgroles",
    printcolumn = r#"{"name":"Policy","type":"string","jsonPath":".spec.policyRef.name"}"#,
    printcolumn = r#"{"name":"Mode","type":"string","jsonPath":".spec.reconciliationMode"}"#,
    printcolumn = r#"{"name":"Approved","type":"string","jsonPath":".status.conditions[?(@.type==\"Approved\")].status"}"#,
    printcolumn = r#"{"name":"Changes","type":"integer","jsonPath":".status.changeSummary.total"}"#,
    printcolumn = r#"{"name":"SQL Stmts","type":"integer","jsonPath":".status.sqlStatements","priority":1}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"SQL","type":"string","jsonPath":".status.sqlRef.name","priority":1}"#,
    printcolumn = r#"{"name":"Digest","type":"string","jsonPath":".status.changeDigest","priority":1}"#,
    printcolumn = r#"{"name":"Hash","type":"string","jsonPath":".status.sqlHash","priority":1}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
// Promotion trusts `spec.origin` — the candidate identity, its content
// digest, and the base pin — so it must not be editable by anyone holding
// plan `patch`. Origin equality is cheap to estimate because every origin
// field is a bounded string; the rest of the spec stays mutable (it is
// operator-written bookkeeping, and `owned_roles` is unbounded, which would
// sink a whole-spec rule at the CEL cost gate).
#[x_kube(validation = Rule::new(
    "!has(oldSelf.origin) || (has(self.origin) && self.origin == oldSelf.origin)"
)
.message("plan origin is immutable once set"))]
#[serde(rename_all = "camelCase")]
pub struct PostgresPolicyPlanSpec {
    /// Reference to the policy that generated this plan.
    pub policy_ref: PolicyPlanRef,
    /// The policy's `.metadata.generation` at plan time.
    pub policy_generation: i64,
    /// Reconciliation mode used for this plan.
    pub reconciliation_mode: CrdReconciliationMode,
    /// Roles that this plan covers.
    #[serde(default)]
    pub owned_roles: Vec<String>,
    /// Schemas that this plan covers.
    #[serde(default)]
    pub owned_schemas: Vec<String>,
    /// Database identity string for disambiguation in multi-db setups.
    pub managed_database_identity: String,
    /// Origin of this plan. Omitted for ordinary durable reconciliation plans.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<PlanOrigin>,
    /// Narrow execution scope for a non-durable plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<PlanScope>,
}

/// Immutable identity of the resource that caused a scoped plan.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlanOrigin {
    #[schemars(length(max = 63))]
    pub kind: String,
    #[schemars(length(max = 253))]
    pub name: String,
    #[schemars(length(max = 63))]
    pub uid: String,
    /// Canonical content digest of the originating candidate, and the encoding
    /// it was computed under.
    ///
    /// This is what binds the reviewed plan to the content that will later be
    /// promoted. It lives on the origin rather than in an annotation because a
    /// promotion check that can be edited by anyone holding `patch` is not a
    /// binding at all. Both fields are absent for non-candidate origins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 128))]
    pub content_digest: Option<String>,
    /// Version tag of the encoding `contentDigest` was computed under.
    /// Digests from different encodings are never comparable, so promotion
    /// recognition only matches digests carrying the same tag. Absent for
    /// non-candidate origins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 64))]
    pub content_digest_encoding: Option<String>,
    /// UID of the `PostgresPolicy` the candidate proposes content for. The
    /// plan's `spec.policyRef` names it; the UID is what survives a
    /// delete-and-recreate of the same name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 63))]
    pub policy_uid: Option<String>,
    /// Canonical content digest of the *policy* content this candidate plan
    /// was computed against — the applied base. A candidate is a complete
    /// desired-state snapshot, so an approval is only meaningful against the
    /// base it was reviewed on: identical SQL effects do not prove the
    /// snapshot still preserves everything the base has come to manage since.
    /// Promotion refuses to adopt a plan whose base pin no longer matches the
    /// content the policy carried before the merge, and planning supersedes
    /// the plan as soon as the base moves. Absent for non-candidate origins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 128))]
    pub base_content_digest: Option<String>,
}

/// Scope enforced when executing a non-durable plan.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlanScope {
    pub kind: String,
    pub operation: ScopedPlanOperation,
    pub bundle_hash: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum ScopedPlanOperation {
    Activate,
    Revoke,
}

/// Reference to the parent `PostgresPolicy` that generated a plan.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicyPlanRef {
    pub name: String,
}

/// Status of a `PostgresPolicyPlan` resource.
///
/// The decision rules below are the same grammar `EphemeralAccessRequest`
/// uses: a decision is terminal, `Approved` and `Denied` cannot both be true,
/// and the deciding identity is recorded in the same admitted write. What CEL
/// cannot do is check *who* is writing — see [`DecisionActor`].
#[derive(KubeSchema, Debug, Clone, Default, Serialize, Deserialize)]
#[x_kube(
    validation = Rule::new(
        "!(self.conditions.exists(c, c.type == 'Approved' && c.status == 'True') && self.conditions.exists(c, c.type == 'Denied' && c.status == 'True'))"
    ).message("Approved=True and Denied=True are mutually exclusive"),
    // Compares the *decision types* that are true, not whole condition
    // objects. The operator rewrites this array on every status write, so
    // comparing objects would reject a later write that only refreshed a
    // timestamp or message — while the decision itself was unchanged. What
    // must not change is which decisions are true.
    validation = Rule::new(
        "oldSelf.conditions.filter(c, (c.type == 'Approved' || c.type == 'Denied') && c.status == 'True').map(c, c.type) == self.conditions.filter(c, (c.type == 'Approved' || c.type == 'Denied') && c.status == 'True').map(c, c.type) || oldSelf.conditions.filter(c, (c.type == 'Approved' || c.type == 'Denied') && c.status == 'True').size() == 0"
    ).message("plan decisions are terminal"),
    validation = Rule::new(
        "!has(oldSelf.decidedBy) || (has(self.decidedBy) && self.decidedBy == oldSelf.decidedBy)"
    ).message("decision identity is write-once"),
    validation = Rule::new(
        "self.conditions.exists(c, (c.type == 'Approved' || c.type == 'Denied') && c.status == 'True') == has(self.decidedBy)"
    ).message("a terminal plan decision and decidedBy identity must be recorded together"),
    // The approval-binding fields are write-once. Execution gates on the
    // recorded digest matching freshly recomputed effects, and the identity
    // downgrade check reads these values — so anyone holding plans/status
    // patch (every plan approver does) who could rewrite them could point an
    // existing approval at different effects or a different server. The
    // operator writes each of these exactly once, when it first materialises
    // the plan's status; a legitimate rewrite repeats the same value, which
    // equality admits.
    validation = Rule::new(
        "!has(oldSelf.changeDigest) || (has(self.changeDigest) && self.changeDigest == oldSelf.changeDigest)"
    ).message("changeDigest is write-once"),
    validation = Rule::new(
        "!has(oldSelf.changeDigestEncoding) || (has(self.changeDigestEncoding) && self.changeDigestEncoding == oldSelf.changeDigestEncoding)"
    ).message("changeDigestEncoding is write-once"),
    validation = Rule::new(
        "!has(oldSelf.targetPhysicalIdentity) || (has(self.targetPhysicalIdentity) && self.targetPhysicalIdentity == oldSelf.targetPhysicalIdentity)"
    ).message("targetPhysicalIdentity is write-once"),
    validation = Rule::new(
        "!has(oldSelf.targetLogicalFingerprint) || (has(self.targetLogicalFingerprint) && self.targetLogicalFingerprint == oldSelf.targetLogicalFingerprint)"
    ).message("targetLogicalFingerprint is write-once"),
    validation = Rule::new(
        "!has(oldSelf.physicalIdentityAvailable) || (has(self.physicalIdentityAvailable) && self.physicalIdentityAvailable == oldSelf.physicalIdentityAvailable)"
    ).message("physicalIdentityAvailable is write-once")
)]
#[serde(rename_all = "camelCase")]
pub struct PostgresPolicyPlanStatus {
    /// Phase: Pending, Approved, Applying, Applied, Failed, Superseded.
    #[serde(default)]
    pub phase: PlanPhase,
    /// Standard conditions: Computed, Applied, and the terminal decision
    /// conditions `Approved` / `Denied`.
    #[serde(default)]
    #[schemars(length(max = 16))]
    pub conditions: Vec<PolicyCondition>,
    /// Kubernetes identity which approved or denied this plan.
    ///
    /// Written in the same status update as the terminal decision, and
    /// write-once thereafter. The supplied Kyverno reference policy overwrites
    /// it from authenticated admission `userInfo`; without that admission layer
    /// it is an assertion by whoever wrote the status, not a verified identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<DecisionActor>,
    /// Summary of changes in this plan.
    #[serde(default)]
    pub change_summary: Option<ChangeSummary>,
    /// Reference to ConfigMap containing the full SQL (for large plans).
    #[serde(default)]
    pub sql_ref: Option<SqlRef>,
    /// Inline SQL for small plans (below a size threshold).
    #[serde(default)]
    pub sql_inline: Option<String>,
    /// True when the SQL preview was truncated because the full redacted SQL
    /// could not be persisted within Kubernetes object limits.
    #[serde(default)]
    pub sql_truncated: bool,
    /// Timestamp when the plan was computed.
    #[serde(default)]
    pub computed_at: Option<String>,
    /// Timestamp when the plan was applied (if applicable).
    #[serde(default)]
    pub applied_at: Option<String>,
    /// Error message if apply failed.
    #[serde(default)]
    pub last_error: Option<String>,
    /// SHA-256 hash of the planned SQL. Retained as a diagnostic for the
    /// preview artifact; it is **not** the approval identity, because rendered
    /// SQL embeds a freshly salted SCRAM verifier for every password change.
    /// Use `change_digest` for approval and deduplication.
    #[serde(default)]
    pub sql_hash: Option<String>,
    /// Canonical semantic digest of the plan's typed effects, bound to the
    /// reconciliation mode and target database identity.
    ///
    /// This is the approval identity: a decision approves these effects, and
    /// execution proceeds only when the recomputed digest still matches. It is
    /// stable across recomputation of unchanged effects — notably for password
    /// changes, which bind the password *source* rather than the derived
    /// verifier. See `pgroles_core::approval`.
    #[serde(default)]
    pub change_digest: Option<String>,
    /// Version tag of the encoding `change_digest` was computed under. Digests
    /// from different encodings are never comparable.
    #[serde(default)]
    pub change_digest_encoding: Option<String>,
    /// `pg_control_system().system_identifier` as read from the target when
    /// this plan was computed — the storage lineage the approval is bound to.
    /// Absent on engines that do not expose it.
    #[serde(default)]
    pub target_physical_identity: Option<String>,
    /// Fingerprint of the resolved connection endpoint (host, port, database)
    /// this plan was computed against.
    #[serde(default)]
    pub target_logical_fingerprint: Option<String>,
    /// Whether the physical identity was readable when this plan was computed.
    ///
    /// Recorded explicitly rather than inferred from
    /// `target_physical_identity` being set, so that "the identifier could not
    /// be read" is distinguishable from "this plan predates the field". The
    /// difference matters at execution: a plan that had the identifier and now
    /// does not is a downgrade and fails closed.
    #[serde(default)]
    pub physical_identity_available: Option<bool>,
    /// The owning object's `.metadata.generation` this plan was most recently
    /// confirmed current against — the policy's for an ordinary plan, the
    /// candidate's for a candidate-origin plan.
    ///
    /// A pending policy plan is revalidated on every reconcile. When the policy
    /// changes but the resulting effects do not, the plan — and any decision
    /// recorded on it — is retained and this advances to the new generation.
    /// A candidate's spec is immutable, so a candidate plan's provenance is
    /// stamped once at creation; its ongoing revalidation is the digest
    /// deduplication itself. It is provenance, never approval identity:
    /// `change_digest` is what a decision binds.
    #[serde(default)]
    pub revalidated_generation: Option<i64>,
    /// When the plan was most recently confirmed current.
    #[serde(default)]
    pub revalidated_at: Option<String>,
    /// Timestamp when the plan entered Applying phase (for stuck detection).
    #[serde(default)]
    pub applying_since: Option<String>,
    /// Timestamp when the plan entered Failed phase (for dedup window).
    #[serde(default)]
    pub failed_at: Option<String>,
    /// Number of SQL statements in the plan (after wildcard expansion).
    /// May be significantly larger than `changeSummary.total` when wildcard
    /// grants expand to many per-object statements.
    #[serde(default)]
    pub sql_statements: Option<i64>,
    /// SHA-256 hash of the redacted SQL preview bytes. This is for storage
    /// integrity only; approval and deduplication use `change_digest`.
    #[serde(default)]
    pub redacted_sql_hash: Option<String>,
    /// Uncompressed byte length of the redacted SQL preview.
    #[serde(default)]
    pub sql_original_bytes: Option<i64>,
    /// Stored byte length of the SQL preview after inline/truncation/compression.
    #[serde(default)]
    pub sql_stored_bytes: Option<i64>,
}

/// Reference to a ConfigMap containing SQL for a plan.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SqlRef {
    pub name: String,
    pub key: String,
    /// Compression used for the referenced SQL content. Missing means older
    /// uncompressed ConfigMap data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression: Option<SqlCompression>,
}

/// Compression format used for persisted plan SQL previews.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SqlCompression {
    Gzip,
}

/// Phase of a `PostgresPolicyPlan`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum PlanPhase {
    #[default]
    Pending,
    Approved,
    Applying,
    Applied,
    Failed,
    Superseded,
    Rejected,
}

impl std::fmt::Display for PlanPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanPhase::Pending => write!(f, "Pending"),
            PlanPhase::Approved => write!(f, "Approved"),
            PlanPhase::Applying => write!(f, "Applying"),
            PlanPhase::Applied => write!(f, "Applied"),
            PlanPhase::Failed => write!(f, "Failed"),
            PlanPhase::Superseded => write!(f, "Superseded"),
            PlanPhase::Rejected => write!(f, "Rejected"),
        }
    }
}

// ---------------------------------------------------------------------------
// Ephemeral access CRDs
// ---------------------------------------------------------------------------

pub const EPHEMERAL_BUNDLE_ENCODING_V1: &str = "pgroles.io/ephemeral-membership-bundle-v1";
pub const EPHEMERAL_MEMBERSHIP_SEMANTICS_V1: &str =
    "postgres-membership-v1-admin-false-set-server-default";
/// A GitOps-managed bundle of PostgreSQL memberships that may be requested.
#[derive(CustomResource, KubeSchema, Debug, Clone, Serialize, Deserialize)]
#[kube(
    group = "pgroles.io",
    version = "v1alpha1",
    kind = "EphemeralAccessPolicy",
    namespaced,
    status = "EphemeralAccessPolicyStatus",
    shortname = "pgeap",
    category = "pgroles",
    printcolumn = r#"{"name":"Target","type":"string","jsonPath":".spec.postgresPolicyRef.name"}"#,
    printcolumn = r#"{"name":"Accepted","type":"string","jsonPath":".status.conditions[?(@.type==\"Accepted\")].status"}"#,
    printcolumn = r#"{"name":"Suspended","type":"boolean","jsonPath":".spec.suspend"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct EphemeralAccessPolicySpec {
    pub postgres_policy_ref: LocalObjectReference,
    #[schemars(length(min = 1, max = 32))]
    pub memberships: Vec<EphemeralMembership>,
    #[schemars(length(max = 64), regex(pattern = r"^([0-9]+[smh])+$"))]
    pub maximum_duration: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 64), regex(pattern = r"^([0-9]+[smh])+$"))]
    pub default_duration: Option<String>,
    #[serde(rename = "pendingRequestTTL", default = "default_pending_request_ttl")]
    #[schemars(length(max = 64), regex(pattern = r"^([0-9]+[smh])+$"))]
    pub pending_request_ttl: String,
    pub justification: EphemeralJustificationPolicy,
    pub approval: EphemeralApprovalPolicy,
    #[serde(default)]
    pub suspend: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 128))]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 2048))]
    pub description: Option<String>,
}

fn default_pending_request_ttl() -> String {
    "15m".to_string()
}

#[derive(KubeSchema, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalObjectReference {
    #[schemars(length(min = 1, max = 253))]
    pub name: String,
}

#[derive(KubeSchema, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EphemeralMembership {
    #[schemars(length(min = 1, max = 63))]
    pub role: String,
    pub inherit: bool,
}

#[derive(KubeSchema, Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralJustificationPolicy {
    pub required: bool,
}

#[derive(KubeSchema, Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralApprovalPolicy {
    pub mode: EphemeralApprovalMode,
}

#[derive(JsonSchema, Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EphemeralApprovalMode {
    Automatic,
    Required,
}

#[derive(KubeSchema, Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EphemeralAccessPolicyStatus {
    #[serde(default)]
    pub observed_generation: Option<i64>,
    #[serde(default)]
    #[schemars(length(max = 16))]
    pub conditions: Vec<EphemeralAccessCondition>,
    #[serde(default)]
    #[schemars(length(max = 32), inner(length(min = 1, max = 63)))]
    pub resolved_roles: Vec<String>,
}

/// One immutable runtime request for a bounded access bundle.
#[derive(CustomResource, KubeSchema, Debug, Clone, Serialize, Deserialize)]
#[kube(
    group = "pgroles.io",
    version = "v1alpha1",
    kind = "EphemeralAccessRequest",
    namespaced,
    status = "EphemeralAccessRequestStatus",
    shortname = "pgear",
    category = "pgroles",
    printcolumn = r#"{"name":"Access Policy","type":"string","jsonPath":".spec.accessPolicyRef.name"}"#,
    printcolumn = r#"{"name":"Subject","type":"string","jsonPath":".spec.subject.role"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Expires","type":"date","jsonPath":".status.expiresAt"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[x_kube(
    validation = Rule::new("self == oldSelf").message("request spec is immutable")
)]
#[serde(rename_all = "camelCase")]
pub struct EphemeralAccessRequestSpec {
    pub access_policy_ref: LocalObjectReference,
    pub subject: EphemeralAccessSubject,
    /// Kubernetes identity which created the request. The supplied Kyverno
    /// reference policy overwrites this from authenticated admission `userInfo`.
    pub requested_by: DecisionActor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 64), regex(pattern = r"^([0-9]+[smh])+$"))]
    pub requested_duration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 2048))]
    pub justification: Option<String>,
}

#[derive(KubeSchema, Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralAccessSubject {
    #[schemars(length(min = 1, max = 63))]
    pub role: String,
}

/// Authenticated Kubernetes identity associated with a decision or request.
///
/// Shared by `EphemeralAccessRequest` and `PostgresPolicyPlan` so both
/// lifecycles record who decided in one vocabulary.
///
/// **This is only as trustworthy as the admission layer.** CEL validation
/// cannot see `request.userInfo`, so the API server alone cannot tell a real
/// identity from an asserted one. The supplied Kyverno reference policy
/// overwrites these values from the admission request's authenticated
/// `userInfo`; without it, they are whatever the client claimed.
#[derive(KubeSchema, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DecisionActor {
    #[schemars(length(min = 1, max = 512))]
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 128))]
    pub uid: Option<String>,
    #[serde(default)]
    #[schemars(length(max = 64), inner(length(min = 1, max = 256)))]
    pub groups: Vec<String>,
}

#[derive(KubeSchema, Debug, Clone, Default, Serialize, Deserialize)]
#[x_kube(
    validation = Rule::new(
        "!has(oldSelf.resolvedAccess) || (has(self.resolvedAccess) && self.resolvedAccess == oldSelf.resolvedAccess)"
    ).message("resolvedAccess is write-once"),
    validation = Rule::new(
        "!(self.conditions.exists(c, c.type == 'Approved' && c.status == 'True') && self.conditions.exists(c, c.type == 'Denied' && c.status == 'True'))"
    ).message("Approved=True and Denied=True are mutually exclusive"),
    validation = Rule::new(
        "oldSelf.conditions.filter(c, (c.type == 'Approved' || c.type == 'Denied') && c.status == 'True').size() == 0 || self.conditions.filter(c, (c.type == 'Approved' || c.type == 'Denied') && c.status == 'True') == oldSelf.conditions.filter(c, (c.type == 'Approved' || c.type == 'Denied') && c.status == 'True')"
    ).message("approval decisions are terminal"),
    validation = Rule::new(
        "!has(oldSelf.decidedBy) || (has(self.decidedBy) && self.decidedBy == oldSelf.decidedBy)"
    ).message("decision identity is write-once"),
    validation = Rule::new(
        "self.conditions.exists(c, (c.type == 'Approved' || c.type == 'Denied') && c.status == 'True') == has(self.decidedBy)"
    ).message("a terminal approval decision and decidedBy identity must be recorded together"),
    validation = Rule::new(
        "self.conditions.all(c, c.type in ['Approved', 'Denied', 'Resolved', 'Ready', 'Applied'])"
    ).message("request conditions must use a declared lifecycle or decision type")
)]
#[serde(rename_all = "camelCase")]
pub struct EphemeralAccessRequestStatus {
    #[serde(default)]
    pub phase: EphemeralAccessRequestPhase,
    #[serde(default)]
    #[schemars(length(max = 8))]
    pub conditions: Vec<EphemeralAccessCondition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_access: Option<ResolvedEphemeralAccess>,
    /// Kubernetes identity which approved or denied the request. The supplied
    /// Kyverno reference policy overwrites this from authenticated admission
    /// `userInfo` in the same status update as the terminal decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<DecisionActor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 64))]
    pub approval_expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 64))]
    pub activated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 64))]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 64))]
    pub ended_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 4096))]
    pub last_error: Option<String>,
    #[serde(default)]
    #[schemars(length(max = 32))]
    pub retained_memberships: Vec<ResolvedEphemeralMembership>,
}

#[derive(JsonSchema, Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum EphemeralAccessRequestPhase {
    #[default]
    Pending,
    PendingApproval,
    Applying,
    Active,
    Revoking,
    Ended,
    Revoked,
    Cancelled,
    Denied,
    ApprovalExpired,
    Failed,
}

impl std::fmt::Display for EphemeralAccessRequestPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(KubeSchema, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EphemeralAccessCondition {
    #[serde(rename = "type")]
    #[schemars(length(min = 1, max = 32))]
    pub condition_type: String,
    #[schemars(length(min = 1, max = 16))]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 128))]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 2048))]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 64))]
    pub last_transition_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 71))]
    pub bundle_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 64))]
    pub granted_duration: Option<String>,
}

#[derive(KubeSchema, Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedEphemeralAccess {
    #[schemars(length(max = 128))]
    pub access_policy_uid: String,
    pub access_policy_generation: i64,
    #[schemars(length(max = 128))]
    pub target_policy_uid: String,
    pub target_policy_generation: i64,
    /// SHA-256 fingerprint of resolved host, port, and database name. It binds
    /// activation and revocation to one database without persisting secrets.
    #[schemars(length(max = 71))]
    pub target_database_fingerprint: String,
    #[schemars(length(max = 64))]
    pub granted_duration: String,
    #[schemars(length(max = 128))]
    pub bundle_encoding: String,
    #[schemars(length(max = 71))]
    pub bundle_hash: String,
    #[schemars(length(max = 32))]
    pub memberships: Vec<ResolvedEphemeralMembership>,
}

#[derive(KubeSchema, Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedEphemeralMembership {
    #[schemars(length(min = 1, max = 63))]
    pub role: String,
    #[schemars(length(min = 1, max = 63))]
    pub member: String,
    pub inherit: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalEphemeralBundle<'a> {
    bundle_encoding: &'a str,
    membership_semantics: &'a str,
    target_database_fingerprint: &'a str,
    memberships: &'a [ResolvedEphemeralMembership],
}

impl ResolvedEphemeralAccess {
    pub fn canonical_bundle_bytes(&self) -> Vec<u8> {
        let mut memberships = self.memberships.clone();
        memberships.sort();
        serde_json::to_vec(&CanonicalEphemeralBundle {
            bundle_encoding: EPHEMERAL_BUNDLE_ENCODING_V1,
            membership_semantics: EPHEMERAL_MEMBERSHIP_SEMANTICS_V1,
            target_database_fingerprint: &self.target_database_fingerprint,
            memberships: &memberships,
        })
        .expect("canonical ephemeral bundle is serializable")
    }

    pub fn compute_bundle_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        use std::fmt::Write;

        let digest = Sha256::digest(self.canonical_bundle_bytes());
        let mut hash = String::with_capacity(7 + digest.len() * 2);
        hash.push_str("sha256:");
        for byte in digest {
            write!(&mut hash, "{byte:02x}").expect("writing to a String cannot fail");
        }
        hash
    }

    pub fn has_valid_bundle_hash(&self) -> bool {
        self.bundle_encoding == EPHEMERAL_BUNDLE_ENCODING_V1
            && self.bundle_hash == self.compute_bundle_hash()
    }
}

// ---------------------------------------------------------------------------
// Conflict detection
// ---------------------------------------------------------------------------

/// Canonical target identity for conflict detection between policies.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DatabaseIdentity(String);

impl DatabaseIdentity {
    /// Create a database identity from the namespace and connection spec's identity key.
    pub fn from_connection(namespace: &str, connection: &ConnectionSpec) -> Self {
        Self(format!("{namespace}/{}", connection.identity_key()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Conservative ownership claims for a policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnershipClaims {
    pub roles: BTreeSet<String>,
    pub schemas: BTreeSet<String>,
    /// Databases whose PUBLIC privileges this policy asserts.
    ///
    /// A database-level rule names no schema, and PUBLIC cannot be claimed as
    /// a role, so such a rule would otherwise claim nothing at all. PUBLIC is
    /// one shared surface per database, so two policies writing it conflict
    /// even when their roles and schemas are disjoint. Database grants to a
    /// named role are already covered by the role claim, and are deliberately
    /// not claimed here — two teams granting CONNECT to their own roles on a
    /// shared database do not conflict.
    pub public_databases: BTreeSet<String>,
}

impl OwnershipClaims {
    pub fn overlaps(&self, other: &Self) -> bool {
        !self.roles.is_disjoint(&other.roles)
            || !self.schemas.is_disjoint(&other.schemas)
            || !self.public_databases.is_disjoint(&other.public_databases)
    }

    pub fn overlap_summary(&self, other: &Self) -> String {
        let overlapping_roles: Vec<_> = self.roles.intersection(&other.roles).cloned().collect();
        let overlapping_schemas: Vec<_> =
            self.schemas.intersection(&other.schemas).cloned().collect();
        let overlapping_databases: Vec<_> = self
            .public_databases
            .intersection(&other.public_databases)
            .cloned()
            .collect();

        let mut parts = Vec::new();
        if !overlapping_roles.is_empty() {
            parts.push(format!("roles: {}", overlapping_roles.join(", ")));
        }
        if !overlapping_schemas.is_empty() {
            parts.push(format!("schemas: {}", overlapping_schemas.join(", ")));
        }
        if !overlapping_databases.is_empty() {
            parts.push(format!(
                "PUBLIC on databases: {}",
                overlapping_databases.join(", ")
            ));
        }

        parts.join("; ")
    }
}

// ---------------------------------------------------------------------------
// Secret name helpers
// ---------------------------------------------------------------------------

impl PostgresPolicySpec {
    pub fn validate_password_specs(
        &self,
        policy_name: &str,
    ) -> Result<(), PasswordValidationError> {
        for role in &self.roles {
            let Some(password) = &role.password else {
                continue;
            };

            if role.login != Some(true) {
                return Err(PasswordValidationError::PasswordWithoutLogin {
                    role: role.name.clone(),
                });
            }

            match (&password.secret_ref, &password.generate) {
                (Some(_), None) => {
                    let secret_key = password.secret_key.as_deref().unwrap_or(&role.name);
                    if !is_valid_secret_key(secret_key) {
                        return Err(PasswordValidationError::InvalidSecretKey {
                            role: role.name.clone(),
                            field: "secretKey",
                            key: secret_key.to_string(),
                        });
                    }
                }
                (None, Some(generate)) => {
                    if let Some(length) = generate.length
                        && !(crate::password::MIN_PASSWORD_LENGTH
                            ..=crate::password::MAX_PASSWORD_LENGTH)
                            .contains(&length)
                    {
                        return Err(PasswordValidationError::InvalidGeneratedLength {
                            role: role.name.clone(),
                            min: crate::password::MIN_PASSWORD_LENGTH,
                            max: crate::password::MAX_PASSWORD_LENGTH,
                        });
                    }

                    let secret_name =
                        crate::password::generated_secret_name(policy_name, &role.name, generate);
                    if !is_valid_secret_name(&secret_name) {
                        return Err(PasswordValidationError::InvalidGeneratedSecretName {
                            role: role.name.clone(),
                            name: secret_name,
                        });
                    }

                    let secret_key = crate::password::generated_secret_key(generate);
                    if !is_valid_secret_key(&secret_key) {
                        return Err(PasswordValidationError::InvalidSecretKey {
                            role: role.name.clone(),
                            field: "generate.secretKey",
                            key: secret_key,
                        });
                    }
                    if secret_key == crate::password::GENERATED_VERIFIER_KEY {
                        return Err(PasswordValidationError::ReservedGeneratedSecretKey {
                            role: role.name.clone(),
                            key: secret_key,
                        });
                    }
                }
                _ => {
                    return Err(PasswordValidationError::InvalidPasswordMode {
                        role: role.name.clone(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validate the connection spec.
    ///
    /// Ensures exactly one of `secretRef` or `params` is set, and that params
    /// mode has all required fields with valid values.
    pub fn validate_connection_spec(&self) -> Result<(), ConnectionValidationError> {
        let conn = &self.connection;
        match (&conn.secret_ref, &conn.params) {
            (Some(_), None) => {
                // URL mode — valid.
                Ok(())
            }
            (None, Some(params)) => {
                // Validate a required field pair: exactly one must be set.
                fn validate_required_field(
                    field: &str,
                    literal: &Option<String>,
                    secret: &Option<SecretKeySelector>,
                ) -> Result<(), ConnectionValidationError> {
                    match (literal, secret) {
                        (Some(_), Some(_)) => {
                            return Err(ConnectionValidationError::BothFieldsSet {
                                field: field.to_string(),
                            });
                        }
                        (None, None) => {
                            return Err(ConnectionValidationError::NeitherFieldSet {
                                field: field.to_string(),
                            });
                        }
                        (Some(s), None) => {
                            if s.trim().is_empty() {
                                return Err(ConnectionValidationError::EmptyLiteral {
                                    field: field.to_string(),
                                });
                            }
                        }
                        (None, Some(sel)) => {
                            validate_secret_selector(field, sel)?;
                        }
                    }
                    Ok(())
                }

                // Validate an optional field pair: at most one may be set.
                fn validate_optional_field(
                    field: &str,
                    literal: &Option<impl AsRef<str>>,
                    secret: &Option<SecretKeySelector>,
                ) -> Result<(), ConnectionValidationError> {
                    let has_literal = literal.is_some();
                    if has_literal && secret.is_some() {
                        return Err(ConnectionValidationError::BothFieldsSet {
                            field: field.to_string(),
                        });
                    }
                    if let Some(s) = literal
                        && s.as_ref().trim().is_empty()
                    {
                        return Err(ConnectionValidationError::EmptyLiteral {
                            field: field.to_string(),
                        });
                    }
                    if let Some(sel) = secret {
                        validate_secret_selector(field, sel)?;
                    }
                    Ok(())
                }

                fn validate_secret_selector(
                    field: &str,
                    sel: &SecretKeySelector,
                ) -> Result<(), ConnectionValidationError> {
                    if sel.name.trim().is_empty() {
                        return Err(ConnectionValidationError::EmptySecretKeyRef {
                            field: field.to_string(),
                            detail: "name must not be empty".to_string(),
                        });
                    }
                    if sel.key.trim().is_empty() {
                        return Err(ConnectionValidationError::EmptySecretKeyRef {
                            field: field.to_string(),
                            detail: "key must not be empty".to_string(),
                        });
                    }
                    Ok(())
                }

                // Required fields: host, dbname, username. Password is only
                // required for static-password auth.
                validate_required_field("host", &params.host, &params.host_secret)?;
                validate_required_field("dbname", &params.dbname, &params.dbname_secret)?;
                validate_required_field("username", &params.username, &params.username_secret)?;
                if let Some(auth) = &params.auth {
                    if params.password.is_some() || params.password_secret.is_some() {
                        return Err(ConnectionValidationError::AuthWithPassword);
                    }
                    match auth {
                        ConnectionAuth::GcpWorkloadIdentity {
                            impersonate_service_account,
                            scope,
                        } => {
                            if let Some(value) = impersonate_service_account
                                && value.trim().is_empty()
                            {
                                return Err(ConnectionValidationError::EmptyAuthField {
                                    field: "impersonateServiceAccount".to_string(),
                                });
                            }
                            if let Some(value) = scope
                                && value.trim().is_empty()
                            {
                                return Err(ConnectionValidationError::EmptyAuthField {
                                    field: "scope".to_string(),
                                });
                            }
                        }
                    }
                } else {
                    validate_required_field("password", &params.password, &params.password_secret)?;
                }

                // Optional fields: port, sslMode.
                // Port is u16 so we wrap it for the generic check.
                let port_str = params.port.map(|p| p.to_string());
                validate_optional_field("port", &port_str, &params.port_secret)?;

                validate_optional_field("sslMode", &params.ssl_mode, &params.ssl_mode_secret)?;

                // Validate sslMode value if it's a literal.
                if let Some(value) = &params.ssl_mode
                    && !VALID_SSL_MODES.contains(&value.as_str())
                {
                    return Err(ConnectionValidationError::InvalidSslMode {
                        value: value.clone(),
                    });
                }

                // Validate setRole identifier. `SET ROLE` does not accept bind
                // params, so the identifier is restricted at admission time.
                if let Some(value) = &params.set_role {
                    if value.trim().is_empty() {
                        return Err(ConnectionValidationError::EmptyLiteral {
                            field: "setRole".to_string(),
                        });
                    }
                    if !is_valid_set_role_identifier(value) {
                        return Err(ConnectionValidationError::InvalidRoleName {
                            value: value.clone(),
                        });
                    }
                }

                Ok(())
            }
            (Some(_), Some(_)) => Err(ConnectionValidationError::BothModesSet),
            (None, None) => Err(ConnectionValidationError::NeitherModeSet),
        }
    }

    /// All Kubernetes Secret names referenced by this spec.
    ///
    /// Includes the connection Secret, password `secretRef` Secrets, and
    /// generated password Secrets. Used by the controller to trigger
    /// reconciliation when any of these Secrets change (or are deleted).
    pub fn referenced_secret_names(&self, policy_name: &str) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        // Connection secrets — either URL mode or structured params.
        self.connection.collect_secret_names(&mut names);
        for role in &self.roles {
            if let Some(pw) = &role.password {
                if let Some(secret_ref) = &pw.secret_ref {
                    names.insert(secret_ref.name.clone());
                }
                if let Some(gen_spec) = &pw.generate {
                    let secret_name =
                        crate::password::generated_secret_name(policy_name, &role.name, gen_spec);
                    names.insert(secret_name);
                }
            }
        }
        names
    }
}

// ---------------------------------------------------------------------------
// Conversion: CRD spec → core manifest types
// ---------------------------------------------------------------------------

/// Build a core `PolicyManifest` from the shared policy-content fields.
///
/// `PostgresPolicySpec` and `PolicyContent` carry the same content by
/// construction (ADR-001 Decision 1 keeps promotion a pure content copy), so
/// they must also convert identically — a divergence here would mean a
/// candidate is planned as something other than what promoting it produces.
#[allow(clippy::too_many_arguments)]
fn build_policy_manifest<'a>(
    default_owner: Option<&str>,
    profiles: impl Iterator<Item = (&'a String, &'a ProfileSpec)>,
    schemas: &[SchemaBinding],
    roles: &[RoleSpec],
    grants: &[Grant],
    default_privileges: &[DefaultPrivilege],
    memberships: &[Membership],
    retirements: &[RoleRetirement],
) -> pgroles_core::manifest::PolicyManifest {
    use pgroles_core::manifest::{
        DefaultPrivilegeGrant, MemberSpec, PolicyManifest, Profile, ProfileGrant,
        ProfileObjectTarget, RoleDefinition,
    };

    let profiles = profiles
        .map(|(name, spec)| {
            let profile = Profile {
                login: spec.login,
                inherit: spec.inherit,
                grants: spec
                    .grants
                    .iter()
                    .map(|g| ProfileGrant {
                        privileges: g.privileges.clone(),
                        object: ProfileObjectTarget {
                            object_type: g.object.object_type,
                            name: g.object.name.clone(),
                        },
                        ensure: g.ensure,
                    })
                    .collect(),
                default_privileges: spec
                    .default_privileges
                    .iter()
                    .map(|dp| DefaultPrivilegeGrant {
                        role: dp.role.clone(),
                        privileges: dp.privileges.clone(),
                        on_type: dp.on_type,
                        ensure: dp.ensure,
                    })
                    .collect(),
                config: spec.config.clone(),
            };
            (name.clone(), profile)
        })
        .collect();

    let roles = roles
        .iter()
        .map(|r| RoleDefinition {
            name: r.name.clone(),
            external: r.external,
            preserve_undeclared_grants: r.preserve_undeclared_grants,
            login: r.login,
            superuser: r.superuser,
            createdb: r.createdb,
            createrole: r.createrole,
            inherit: r.inherit,
            replication: r.replication,
            bypassrls: r.bypassrls,
            connection_limit: r.connection_limit,
            comment: r.comment.clone(),
            password: None, // K8s passwords are resolved separately via Secret refs
            password_valid_until: r.password_valid_until.clone(),
            config: r.config.clone(),
        })
        .collect();

    let memberships = memberships
        .iter()
        .map(|m| pgroles_core::manifest::Membership {
            role: m.role.clone(),
            members: m
                .members
                .iter()
                .map(|ms| MemberSpec {
                    name: ms.name.clone(),
                    inherit: ms.inherit,
                    admin: ms.admin,
                })
                .collect(),
        })
        .collect();

    PolicyManifest {
        default_owner: default_owner.map(str::to_string),
        auth_providers: Vec::new(),
        profiles,
        schemas: schemas.to_vec(),
        roles,
        grants: grants.to_vec(),
        default_privileges: default_privileges.to_vec(),
        memberships,
        retirements: retirements.to_vec(),
    }
}

impl PolicyContent {
    /// Convert candidate content into a `PolicyManifest`.
    ///
    /// Identical to [`PostgresPolicySpec::to_policy_manifest`] by construction
    /// — see [`build_policy_manifest`].
    pub fn to_policy_manifest(&self) -> pgroles_core::manifest::PolicyManifest {
        build_policy_manifest(
            self.default_owner.as_deref(),
            self.profiles.iter(),
            &self.schemas,
            &self.roles,
            &self.grants,
            &self.default_privileges,
            &self.memberships,
            &self.retirements,
        )
    }

    /// The canonical content digest of this content.
    ///
    /// The single entry point, so a policy and a candidate can never be
    /// digested through different code.
    pub fn content_digest(&self) -> String {
        pgroles_core::candidate::compute_content_digest(self)
    }
}

impl PostgresPolicySpec {
    /// Project the policy's content fields into [`PolicyContent`].
    ///
    /// The inverse of promotion: promotion copies `candidate.spec.content`
    /// into `policy.spec`, and this reads that content back out. Both
    /// directions are pure field moves — [`PolicyContent`] exists precisely so
    /// that the projection is total and lossless — which is what lets the same
    /// content produce the same digest on either kind.
    pub fn policy_content(&self) -> PolicyContent {
        PolicyContent {
            reconciliation_mode: self.reconciliation_mode,
            default_owner: self.default_owner.clone(),
            profiles: self
                .profiles
                .iter()
                .map(|(name, spec)| (name.clone(), spec.clone()))
                .collect(),
            schemas: self.schemas.clone(),
            roles: self.roles.clone(),
            grants: self.grants.clone(),
            default_privileges: self.default_privileges.clone(),
            memberships: self.memberships.clone(),
            retirements: self.retirements.clone(),
        }
    }

    /// The canonical content digest of this policy's content.
    ///
    /// Computed over [`PolicyContent`], not over the spec, so promoting a
    /// candidate byte-for-byte yields the identical digest — the property
    /// `promoting_candidate_content_yields_the_candidates_digest` pins.
    pub fn content_digest(&self) -> String {
        self.policy_content().content_digest()
    }

    /// Convert the CRD spec into a `PolicyManifest` for use with the core library.
    pub fn to_policy_manifest(&self) -> pgroles_core::manifest::PolicyManifest {
        build_policy_manifest(
            self.default_owner.as_deref(),
            self.profiles.iter(),
            &self.schemas,
            &self.roles,
            &self.grants,
            &self.default_privileges,
            &self.memberships,
            &self.retirements,
        )
    }

    /// Derive a conservative ownership claim set from the policy spec.
    ///
    /// This intentionally claims all declared/expanded roles and all referenced
    /// schemas so overlapping policies are rejected safely.
    pub fn ownership_claims(
        &self,
    ) -> Result<OwnershipClaims, pgroles_core::manifest::ManifestError> {
        let manifest = self.to_policy_manifest();
        let expanded = pgroles_core::manifest::expand_manifest(&manifest)?;

        let mut roles: BTreeSet<String> = expanded.roles.into_iter().map(|r| r.name).collect();
        let mut schemas: BTreeSet<String> = self.schemas.iter().map(|s| s.name.clone()).collect();
        // A database-level PUBLIC rule names no schema and no claimable role.
        let public_databases: BTreeSet<String> = manifest
            .grants
            .iter()
            .filter(|g| g.object.object_type == ObjectType::Database && g.role == "PUBLIC")
            .filter_map(|g| g.object.name.clone())
            .collect();

        roles.extend(manifest.retirements.into_iter().map(|r| r.role));
        // PUBLIC is a pseudo-role, not a role this policy may claim.
        roles.extend(
            manifest
                .grants
                .iter()
                .map(|g| g.role.clone())
                .filter(|role| role != "PUBLIC"),
        );
        roles.extend(
            manifest
                .default_privileges
                .iter()
                .flat_map(|dp| dp.grant.iter().filter_map(|grant| grant.role.clone()))
                .filter(|role| role != "PUBLIC"),
        );
        roles.extend(manifest.memberships.iter().map(|m| m.role.clone()));
        roles.extend(
            manifest
                .memberships
                .iter()
                .flat_map(|m| m.members.iter().map(|member| member.name.clone())),
        );

        schemas.extend(
            manifest
                .grants
                .iter()
                .filter_map(|g| match g.object.object_type {
                    ObjectType::Database => None,
                    ObjectType::Schema => g.object.name.clone(),
                    _ => g.object.schema.clone(),
                }),
        );
        // Global-scope entries have no schema; their claim is the owner role.
        for dp in &manifest.default_privileges {
            match dp.resolved_scope() {
                Ok(scope) => match scope.schema() {
                    Some(schema) => {
                        schemas.insert(schema.to_string());
                    }
                    // An entry that omits `owner` still resolves to one, so it
                    // has to claim the same role the reconcile will act as.
                    None => {
                        if let Some(owner) = dp.owner.as_ref().or(manifest.default_owner.as_ref()) {
                            roles.insert(owner.clone());
                        }
                    }
                },
                // expand_manifest above already rejected invalid scopes.
                Err(_) => continue,
            }
        }

        Ok(OwnershipClaims {
            roles,
            schemas,
            public_databases,
        })
    }
}

// ---------------------------------------------------------------------------
// Status helpers
// ---------------------------------------------------------------------------

impl PostgresPolicyStatus {
    /// Set a condition, replacing any existing condition of the same type.
    ///
    /// If the condition's `status` value has not changed, the existing
    /// `last_transition_time` is preserved (per Kubernetes condition conventions).
    pub fn set_condition(&mut self, new: PolicyCondition) {
        if let Some(existing) = self
            .conditions
            .iter()
            .find(|c| c.condition_type == new.condition_type)
            && existing.status == new.status
        {
            // Status unchanged — preserve the existing transition time.
            let mut updated = new;
            updated.last_transition_time = existing.last_transition_time.clone();
            self.conditions
                .retain(|c| c.condition_type != updated.condition_type);
            self.conditions.push(updated);
            return;
        }
        // New condition or status changed — use the new timestamp.
        self.conditions
            .retain(|c| c.condition_type != new.condition_type);
        self.conditions.push(new);
    }
}

/// Create a timestamp string in ISO 8601 / RFC 3339 format.
pub fn now_rfc3339() -> String {
    // Use k8s-openapi's chrono re-export or manual formatting.
    // For simplicity, use the system time.
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    // Format as simplified ISO 8601
    let secs = now.as_secs();
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // Convert days since epoch to date (simplified — good enough for status)
    let (year, month, day) = days_to_date(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert days since Unix epoch to (year, month, day).
pub fn days_to_date(days_since_epoch: u64) -> (u64, u64, u64) {
    // Civil calendar algorithm from Howard Hinnant
    let z = days_since_epoch + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Helper to create a "Ready" condition.
pub fn ready_condition(status: bool, reason: &str, message: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: "Ready".to_string(),
        status: if status { "True" } else { "False" }.to_string(),
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(now_rfc3339()),
    }
}

/// Helper to create a "Reconciling" condition.
pub fn reconciling_condition(message: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: "Reconciling".to_string(),
        status: "True".to_string(),
        reason: Some("Reconciling".to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(now_rfc3339()),
    }
}

/// Helper to create a "Degraded" condition.
pub fn degraded_condition(reason: &str, message: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: "Degraded".to_string(),
        status: "True".to_string(),
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(now_rfc3339()),
    }
}

/// Helper to create a "Paused" condition.
pub fn paused_condition(message: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: "Paused".to_string(),
        status: "True".to_string(),
        reason: Some("Suspended".to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(now_rfc3339()),
    }
}

/// Condition type set when the target's identity stops the policy dead.
///
/// Distinct from `Drifted`/`Degraded`: nothing here is retried into
/// convergence. Either the deployment requires an identity the target cannot
/// answer with, or the target is not the one the operator was pointed at.
pub const CONDITION_TARGET_IDENTITY_BLOCKED: &str = "TargetIdentityBlocked";

/// Helper to create a `TargetIdentityBlocked` condition.
pub fn target_identity_blocked_condition(reason: &str, message: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: CONDITION_TARGET_IDENTITY_BLOCKED.to_string(),
        status: "True".to_string(),
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(now_rfc3339()),
    }
}

/// Helper to create a "Conflict" condition.
pub fn conflict_condition(reason: &str, message: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: "Conflict".to_string(),
        status: "True".to_string(),
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(now_rfc3339()),
    }
}

/// Condition type reporting that `spec.approval` is absent and therefore
/// inferred from `spec.mode`. Removed once the field becomes required.
pub const CONDITION_APPROVAL_UNSET: &str = "ApprovalUnset";

/// Condition type for `spec.mode: plan`, the deprecated spelling of `observe`.
pub const CONDITION_MODE_VALUE_DEPRECATED: &str = "ModeValueDeprecated";

/// Condition type reporting that additive reconciliation cannot enforce
/// declarative absence assertions present in the policy.
pub const CONDITION_ABSENCE_ASSERTIONS_IGNORED: &str = "AbsenceAssertionsIgnored";

/// Condition type reporting that a plan carries an approval annotation which
/// cannot take effect, because `spec.mode: observe` never executes.
pub const CONDITION_APPROVAL_IGNORED: &str = "ApprovalIgnored";

/// Helper to create an `AbsenceAssertionsIgnored` condition.
pub fn absence_assertions_ignored_condition() -> PolicyCondition {
    PolicyCondition {
        condition_type: CONDITION_ABSENCE_ASSERTIONS_IGNORED.to_string(),
        status: "True".to_string(),
        reason: Some("AdditiveModeNeverRevokes".to_string()),
        message: Some(
            "spec.reconciliation_mode is `additive`, so every `ensure: absent` assertion is \
             ignored. Use `adopt` or `authoritative` to enforce absence."
                .to_string(),
        ),
        last_transition_time: Some(now_rfc3339()),
    }
}

/// Helper to create an "ApprovalIgnored" condition.
///
/// Approving a plan under `spec.mode: observe` is accepted by the API server and
/// then does nothing at all, which is indistinguishable from an operator that
/// has stalled. Say so on the object, and name the combination that does gate
/// an apply.
pub fn approval_ignored_condition(plan_name: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: CONDITION_APPROVAL_IGNORED.to_string(),
        status: "True".to_string(),
        reason: Some("ObserveModeNeverExecutes".to_string()),
        message: Some(format!(
            "Plan {plan_name} is approved, but spec.mode is `observe`, so it will never execute and \
             no SQL will run. For a reviewed apply use `mode: apply` with `approval: manual`."
        )),
        last_transition_time: Some(now_rfc3339()),
    }
}

/// Helper to create an "ApprovalUnset" condition naming the inferred mode.
///
/// The message states the resolved value rather than only the deprecation, so
/// an operator reading `kubectl describe` learns what the policy does *now* as
/// well as what to write down to keep it doing that.
pub fn approval_unset_condition(inferred: ApprovalMode) -> PolicyCondition {
    let inferred = match inferred {
        ApprovalMode::Auto => "auto",
        ApprovalMode::Manual => "manual",
    };
    PolicyCondition {
        condition_type: CONDITION_APPROVAL_UNSET.to_string(),
        status: "True".to_string(),
        reason: Some("InferredFromMode".to_string()),
        message: Some(format!(
            "spec.approval is not set and is currently inferred as {inferred} from spec.mode. \
             This inference is deprecated and will become an error in a future release: set \
             `approval: {inferred}` explicitly to keep the current behaviour."
        )),
        last_transition_time: Some(now_rfc3339()),
    }
}

/// Helper to create a "ModeValueDeprecated" condition.
pub fn mode_value_deprecated_condition() -> PolicyCondition {
    PolicyCondition {
        condition_type: CONDITION_MODE_VALUE_DEPRECATED.to_string(),
        status: "True".to_string(),
        reason: Some("PlanSpelledObserve".to_string()),
        message: Some(
            "spec.mode is `plan`, the deprecated spelling of `observe`. Behaviour is identical: \
             plans are computed and published, nothing executes. Change the manifest to \
             `mode: observe` — a future release removes the `plan` value."
                .to_string(),
        ),
        last_transition_time: Some(now_rfc3339()),
    }
}

/// Helper to create a "Drifted" condition.
pub fn drifted_condition(status: bool, reason: &str, message: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: "Drifted".to_string(),
        status: if status { "True" } else { "False" }.to_string(),
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(now_rfc3339()),
    }
}

// ---------------------------------------------------------------------------
// PostgresPolicyCandidate CRD
// ---------------------------------------------------------------------------

/// The policy-content subset of `PostgresPolicySpec`.
///
/// This is everything a policy *declares about PostgreSQL* and nothing about
/// how or when it is executed: no connection, interval, mode, approval or
/// suspend. Those always come from the parent `PostgresPolicy` (a candidate
/// may override only the connection, via `spec.target`).
///
/// Promotion is a pure content copy — `candidate.spec.content` becomes
/// `policy.spec` with no conversion — so the field names, types and bounds
/// here must stay identical to their `PostgresPolicySpec` counterparts. The
/// `candidate_content_matches_policy_content` test holds that line.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct PolicyContent {
    /// Convergence strategy: how aggressively to converge the database.
    #[serde(default)]
    pub reconciliation_mode: CrdReconciliationMode,

    /// Default owner for ALTER DEFAULT PRIVILEGES (e.g. "app_owner").
    #[serde(default)]
    #[schemars(length(min = 1, max = MAX_IDENTIFIER))]
    pub default_owner: Option<String>,

    /// Reusable privilege profiles.
    ///
    /// A `BTreeMap` rather than the policy's `HashMap`: the content digest is
    /// computed over a canonical serialization, and deterministic iteration
    /// order is one less thing that has to be normalised later.
    #[serde(default)]
    #[schemars(extend("maxProperties" = MAX_PROFILES))]
    pub profiles: std::collections::BTreeMap<String, ProfileSpec>,

    /// Schema bindings that expand profiles into concrete roles/grants.
    #[serde(default)]
    #[schemars(length(max = MAX_SCHEMAS))]
    pub schemas: Vec<SchemaBinding>,

    /// One-off role definitions.
    #[serde(default)]
    #[schemars(length(max = MAX_ROLES))]
    pub roles: Vec<RoleSpec>,

    /// One-off grants.
    #[serde(default)]
    #[schemars(length(max = MAX_GRANTS))]
    pub grants: Vec<Grant>,

    /// One-off default privileges.
    #[serde(default)]
    #[schemars(length(max = MAX_DEFAULT_PRIVILEGES))]
    pub default_privileges: Vec<DefaultPrivilege>,

    /// Membership edges.
    #[serde(default)]
    #[schemars(length(max = MAX_MEMBERSHIPS))]
    pub memberships: Vec<Membership>,

    /// Explicit role-retirement workflows for roles that should be removed.
    #[serde(default)]
    #[schemars(length(max = MAX_RETIREMENTS))]
    pub retirements: Vec<RoleRetirement>,
}

/// A one-shot, immutable proposal of policy content.
///
/// The operator plans a candidate in its parent policy's execution context and
/// publishes a `PostgresPolicyPlan` for review; the active policy keeps
/// enforcing throughout. A candidate never executes SQL in any state, and its
/// spec cannot be edited — revising a proposal means creating a successor that
/// names the earlier one in `spec.replaces`.
///
/// See `docs/src/pages/docs/operator-candidates.md` for the behaviour and
/// `docs/design/adr-001-candidate-api.md` for the API mechanics.
#[derive(CustomResource, KubeSchema, Debug, Clone, Serialize, Deserialize)]
#[kube(
    group = "pgroles.io",
    version = "v1alpha1",
    kind = "PostgresPolicyCandidate",
    namespaced,
    status = "PostgresPolicyCandidateStatus",
    shortname = "pgcand",
    category = "pgroles",
    printcolumn = r#"{"name":"Policy","type":"string","jsonPath":".spec.policyRef.name"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Plan","type":"string","jsonPath":".status.planRef.name"}"#,
    printcolumn = r#"{"name":"Digest","type":"string","jsonPath":".status.contentDigest","priority":1}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
// Whole-spec immutability, the same rule `EphemeralAccessRequest` carries. It
// is only admissible because every string, list and map reachable from here is
// bounded — see `pgroles_core::bounds` and ADR-001 Decision 1. Transition
// rules skip CREATE, so this evaluates only on an attempted edit.
#[x_kube(validation = Rule::new("self == oldSelf").message("candidate spec is immutable"))]
#[serde(rename_all = "camelCase")]
pub struct PostgresPolicyCandidateSpec {
    /// The `PostgresPolicy` this candidate proposes content for. Resolved in
    /// the candidate's own namespace: an owner reference cannot cross
    /// namespaces, so neither can this.
    pub policy_ref: LocalObjectReference,

    /// Name of an earlier candidate this one supersedes.
    ///
    /// Supersession is always explicit. The operator never infers it from
    /// creator identity, because CI typically files every team's candidates
    /// under one service account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = MAX_K8S_NAME))]
    pub replaces: Option<String>,

    /// Preview the content against a different connection than the parent
    /// policy's. Credentials, locking and the plan's bound target identity all
    /// follow the override, which is why such a plan is a preview and never a
    /// migration step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<CandidateTarget>,

    /// The proposed policy content.
    pub content: PolicyContent,
}

/// Connection override for a candidate.
#[derive(KubeSchema, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateTarget {
    pub connection_ref: CandidateConnectionRef,
}

/// Reference to a Secret carrying the override connection URL.
///
/// Mirrors `ConnectionSpec`'s URL mode (`secretRef.name` + `secretKey`) in one
/// flattened object: a candidate previews a single destination, so the
/// structured-params mode has nothing to add here.
#[derive(KubeSchema, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateConnectionRef {
    /// Name of the Secret in the candidate's namespace.
    #[schemars(length(min = 1, max = MAX_K8S_NAME))]
    pub secret_name: String,
    /// Key within the Secret holding the connection URL.
    #[schemars(length(min = 1, max = MAX_SECRET_KEY))]
    pub key: String,
}

/// Status of a `PostgresPolicyCandidate`.
///
/// `phase` is a printable summary; conditions are the source of truth.
#[derive(KubeSchema, Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostgresPolicyCandidateStatus {
    #[serde(default)]
    pub phase: CandidatePhase,

    /// Canonical digest of `spec.content`, computed by
    /// `pgroles_core::candidate::compute_content_digest`. This is what
    /// promotion is verified against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 128))]
    pub content_digest: Option<String>,

    /// The `PostgresPolicyPlan` produced for this candidate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_ref: Option<PlanReference>,

    #[serde(default)]
    #[schemars(length(max = 16))]
    pub conditions: Vec<PolicyCondition>,

    /// The `.metadata.generation` that was last observed. A candidate spec is
    /// immutable, so this advances at most once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// Printable lifecycle summary for a candidate.
#[derive(JsonSchema, Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum CandidatePhase {
    /// Filed, not yet planned.
    #[default]
    Pending,
    /// A current plan exists for this candidate.
    Planned,
    /// This candidate's content was promoted and executed.
    Promoted,
    /// Replaced by a successor, or its plan was denied.
    Superseded,
    /// The plan it was reviewed against no longer describes its effects.
    Stale,
}

impl CandidatePhase {
    /// A terminal candidate is never planned again.
    ///
    /// `Stale` is deliberately *not* terminal: it names a plan that no longer
    /// describes the candidate's effects, and the next reconcile replans it.
    /// The docs express supersession-by-replacement and plan denial as
    /// `Superseded`, which is where terminality lives.
    pub fn is_terminal(self) -> bool {
        matches!(self, CandidatePhase::Promoted | CandidatePhase::Superseded)
    }
}

/// Condition reasons for a `PostgresPolicyCandidate`.
///
/// These are the strings in the conditions table of
/// `docs/src/pages/docs/operator-candidates.md`; status consumers match on
/// them, so they are constants rather than literals at each call site.
pub mod candidate_reason {
    /// `Ready=True` — a current plan exists for this candidate.
    pub const PLANNED: &str = "Planned";
    /// `Ready=True` — the content is already the database's state, so there is
    /// nothing to review. Not terminal: the content may diverge again.
    pub const NO_EFFECTS: &str = "NoEffects";
    /// `Ready=False` — the parent is failing or awaiting its own approval.
    pub const BLOCKED_BY_ACTIVE_POLICY: &str = "BlockedByActivePolicy";
    /// `Ready=False` — an ephemeral overlay overlaps this candidate's effects.
    pub const OVERLAY_OVERLAP: &str = "OverlayOverlap";
    /// `Ready=False` — the candidate could not be planned at all.
    pub const PLANNING_FAILED: &str = "PlanningFailed";
    /// `Ready=False` — the policy already has as many open candidates as it
    /// plans in one pass, and older ones are ahead of this in the queue. Not
    /// terminal and nothing is deleted: it plans once its elders finish.
    pub const OVER_BUDGET: &str = "CandidateBudgetExceeded";
    /// `Superseded=True` — nobody decided this candidate inside the open-
    /// candidate TTL, so it is abandoned rather than under review (terminal).
    /// Label a candidate `pgroles.io/keep=true` to exempt it.
    pub const EXPIRED: &str = "Expired";
    /// `Superseded=True` — a successor named this candidate in `spec.replaces`.
    pub const REPLACED: &str = "Replaced";
    /// `Superseded=True` — replanning produced a different change digest.
    pub const EFFECTS_CHANGED: &str = "EffectsChanged";
    /// `Superseded=True` — the candidate's plan was denied (terminal).
    pub const PLAN_DENIED: &str = "PlanDenied";
    /// `Promoted=True` — this candidate's content became the policy's and
    /// executed (terminal).
    pub const PROMOTED: &str = "Promoted";
    /// `Ready=False` — this candidate's content was promoted into the policy
    /// while its plan held no approval, so the promotion executes nothing on
    /// the approval it never had: the policy falls back to its ordinary
    /// manual-plan flow.
    pub const PROMOTED_WITHOUT_APPROVAL: &str = "PromotedWithoutApproval";
    /// `Ready=False` — the policy's content changed to something that is *not*
    /// this approved candidate: edited after approval, or rebased.
    pub const PROMOTION_DIGEST_MISMATCH: &str = "PromotionDigestMismatch";
    /// `Ready=False` — the policy's content *is* this approved candidate, but
    /// the base moved between planning and merge, so the approval reviewed a
    /// snapshot of a desired state that no longer exists. Nothing executes on
    /// it; the ordinary manual flow takes over.
    pub const PROMOTION_BASE_CHANGED: &str = "PromotionBaseChanged";
    /// `Ready=False` — the content was promoted but the policy never executes
    /// (`mode: observe`), so the candidate cannot reach `Promoted`.
    pub const PROMOTION_NOT_EXECUTED: &str = "PromotionNotExecuted";
    /// `Superseded=True` on a *plan* — another candidate's content was
    /// promoted and executed, so this plan's approval can never be used.
    pub const SUPERSEDED_BY_PROMOTION: &str = "SupersededByPromotion";
}

/// Condition type recording that a candidate is terminal.
pub const CONDITION_SUPERSEDED: &str = "Superseded";

/// Condition type carrying everything promotion has to say about a candidate.
///
/// `Promoted=True` is terminal: the content was promoted and executed.
/// `Promoted=False` reports a promotion that did *not* complete — merged
/// without approval, merged edited, or merged into a policy that never
/// executes — and is deliberately a separate condition from `Ready`, which
/// belongs to the planning lifecycle and is rewritten on every cycle.
pub const CONDITION_PROMOTED: &str = "Promoted";

/// Helper to create a candidate `Promoted` condition.
pub fn promoted_condition(promoted: bool, reason: &str, message: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: CONDITION_PROMOTED.to_string(),
        status: if promoted { "True" } else { "False" }.to_string(),
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(now_rfc3339()),
    }
}

/// Set a condition on a bare condition list, preserving the transition time
/// when the status value is unchanged.
///
/// The same rule [`PostgresPolicyStatus::set_condition`] applies, lifted to the
/// list so candidate and plan statuses share it.
pub fn set_condition_in(conditions: &mut Vec<PolicyCondition>, new: PolicyCondition) {
    if let Some(existing) = conditions
        .iter()
        .find(|c| c.condition_type == new.condition_type)
        && existing.status == new.status
    {
        let mut updated = new;
        updated.last_transition_time = existing.last_transition_time.clone();
        conditions.retain(|c| c.condition_type != updated.condition_type);
        conditions.push(updated);
        return;
    }
    conditions.retain(|c| c.condition_type != new.condition_type);
    conditions.push(new);
}

/// Helper to create a candidate `Superseded` condition.
pub fn superseded_condition(reason: &str, message: &str) -> PolicyCondition {
    PolicyCondition {
        condition_type: CONDITION_SUPERSEDED.to_string(),
        status: "True".to_string(),
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        last_transition_time: Some(now_rfc3339()),
    }
}

impl std::fmt::Display for CandidatePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            CandidatePhase::Pending => "Pending",
            CandidatePhase::Planned => "Planned",
            CandidatePhase::Promoted => "Promoted",
            CandidatePhase::Superseded => "Superseded",
            CandidatePhase::Stale => "Stale",
        };
        f.write_str(name)
    }
}

/// The generated `PostgresPolicyCandidate` CRD, with every OpenAPI `default`
/// removed from under `spec.content`.
///
/// **Always use this instead of `PostgresPolicyCandidate::crd()`** — the raw
/// derive emits schema defaults, which candidates must not have (ADR-001,
/// Decision 2): a schema default is materialised into the stored object at
/// write time, so if a default value ever changed, a stored candidate would
/// keep the old value while the identical source manifest now means the new
/// one. `self == oldSelf` would fail on byte-identical input, and — worse —
/// the content digest of the stored object would no longer match the digest
/// computed from the YAML it came from.
///
/// This is a post-processor rather than a per-field schemars attribute because
/// the content types are shared with the CLI and with `PostgresPolicy`:
/// `#[serde(default)]` is what makes deserialisation work and is exactly what
/// schemars reads to emit `default`, and schemars offers no way to keep one
/// without the other. Stripping the emitted schema afterwards keeps serde
/// defaults fully intact — they are a deserialisation concern and never
/// reached the schema's semantics anyway — and leaves `PostgresPolicy`'s own
/// defaults untouched, as the ADR requires for now.
pub fn postgres_policy_candidate_crd()
-> k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition {
    use kube::CustomResourceExt;

    let mut crd = PostgresPolicyCandidate::crd();
    for version in &mut crd.spec.versions {
        let Some(content) = version
            .schema
            .as_mut()
            .and_then(|s| s.open_api_v3_schema.as_mut())
            .and_then(|s| s.properties.as_mut())
            .and_then(|p| p.get_mut("spec"))
            .and_then(|s| s.properties.as_mut())
            .and_then(|p| p.get_mut("content"))
        else {
            continue;
        };
        strip_schema_defaults(content);
    }
    crd
}

/// Remove `default` from a schema and everything beneath it.
fn strip_schema_defaults(
    schema: &mut k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::JSONSchemaProps,
) {
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::{
        JSONSchemaPropsOrArray, JSONSchemaPropsOrBool,
    };

    schema.default = None;

    if let Some(properties) = schema.properties.as_mut() {
        for child in properties.values_mut() {
            strip_schema_defaults(child);
        }
    }
    if let Some(JSONSchemaPropsOrBool::Schema(child)) = schema.additional_properties.as_mut() {
        strip_schema_defaults(child);
    }
    match schema.items.as_mut() {
        Some(JSONSchemaPropsOrArray::Schema(child)) => strip_schema_defaults(child),
        Some(JSONSchemaPropsOrArray::Schemas(children)) => {
            children.iter_mut().for_each(strip_schema_defaults)
        }
        None => {}
    }
    for branch in [
        schema.all_of.as_mut(),
        schema.any_of.as_mut(),
        schema.one_of.as_mut(),
    ]
    .into_iter()
    .flatten()
    {
        branch.iter_mut().for_each(strip_schema_defaults);
    }
    if let Some(child) = schema.not.as_mut() {
        strip_schema_defaults(child);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    /// Named spec arrays must carry key-aware list semantics so server-side
    /// apply merges per entry instead of replacing the whole list, and so the
    /// API server rejects duplicate keys.
    ///
    /// `memberships`, `grants`, and `default_privileges` are deliberately left
    /// as plain arrays: the same role may legitimately appear in several
    /// membership entries, and the natural keys for the other two are
    /// composite. Keying them needs duplicate-merge semantics designed first.
    #[test]
    fn named_spec_arrays_declare_list_map_keys() {
        let crd = PostgresPolicy::crd();
        let schema = crd.spec.versions[0]
            .schema
            .as_ref()
            .and_then(|s| s.open_api_v3_schema.as_ref())
            .expect("CRD should carry an OpenAPI schema");
        let spec_props = schema
            .properties
            .as_ref()
            .and_then(|p| p.get("spec"))
            .and_then(|s| s.properties.as_ref())
            .expect("spec should have properties");

        for (field, key) in [
            ("schemas", "name"),
            ("roles", "name"),
            ("retirements", "role"),
        ] {
            let prop = spec_props
                .get(field)
                .unwrap_or_else(|| panic!("spec.{field} should exist"));
            assert_eq!(
                prop.x_kubernetes_list_type.as_deref(),
                Some("map"),
                "spec.{field} should be a map-list"
            );
            assert_eq!(
                prop.x_kubernetes_list_map_keys.as_deref(),
                Some([key.to_string()].as_slice()),
                "spec.{field} should be keyed by {key}"
            );
        }

        for field in ["memberships", "grants", "default_privileges"] {
            let prop = spec_props
                .get(field)
                .unwrap_or_else(|| panic!("spec.{field} should exist"));
            assert!(
                prop.x_kubernetes_list_type.is_none(),
                "spec.{field} should stay a plain array until its merge semantics are designed"
            );
        }
    }

    #[test]
    fn crd_generates_valid_schema() {
        let crd = PostgresPolicy::crd();
        let yaml = serde_yaml::to_string(&crd).expect("CRD should serialize to YAML");
        assert!(yaml.contains("pgroles.io"), "group should be pgroles.io");
        assert!(yaml.contains("v1alpha1"), "version should be v1alpha1");
        assert!(
            yaml.contains("PostgresPolicy"),
            "kind should be PostgresPolicy"
        );
        assert!(
            yaml.contains("\"mode\"") || yaml.contains(" mode:"),
            "schema should declare spec.mode"
        );
        assert!(
            yaml.contains("\"object\"") || yaml.contains(" object:"),
            "schema should declare grant object targets using object"
        );
    }

    #[test]
    fn spec_to_policy_manifest_roundtrip() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-secret".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
                require_physical_identity: None,
            },
            interval: "5m".to_string(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            default_owner: Some("app_owner".to_string()),
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![RoleSpec {
                name: "analytics".to_string(),
                external: true,
                preserve_undeclared_grants: false,
                login: Some(true),
                superuser: None,
                createdb: None,
                createrole: None,
                inherit: None,
                replication: None,
                bypassrls: None,
                connection_limit: None,
                comment: Some("test role".to_string()),
                password: None,
                password_valid_until: None,
                config: Default::default(),
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![RoleRetirement {
                role: "legacy-app".to_string(),
                reassign_owned_to: Some("app_owner".to_string()),
                drop_owned: true,
                terminate_sessions: true,
            }],
            approval: None,
        };

        let manifest = spec.to_policy_manifest();
        assert_eq!(manifest.default_owner, Some("app_owner".to_string()));
        assert_eq!(manifest.roles.len(), 1);
        assert_eq!(manifest.roles[0].name, "analytics");
        assert!(manifest.roles[0].external);
        assert_eq!(manifest.roles[0].login, Some(true));
        assert_eq!(manifest.roles[0].comment, Some("test role".to_string()));
        assert_eq!(manifest.retirements.len(), 1);
        assert_eq!(manifest.retirements[0].role, "legacy-app");
        assert_eq!(
            manifest.retirements[0].reassign_owned_to.as_deref(),
            Some("app_owner")
        );
        assert!(manifest.retirements[0].drop_owned);
        assert!(manifest.retirements[0].terminate_sessions);
    }

    #[test]
    fn spec_to_policy_manifest_preserves_profile_inherit() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-secret".to_string(),
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
            profiles: std::collections::HashMap::from([(
                "editor".to_string(),
                ProfileSpec {
                    login: Some(false),
                    inherit: Some(false),
                    grants: vec![],
                    default_privileges: vec![],
                    config: Default::default(),
                },
            )]),
            schemas: vec![],
            roles: vec![],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        let manifest = spec.to_policy_manifest();
        assert_eq!(manifest.profiles["editor"].login, Some(false));
        assert_eq!(manifest.profiles["editor"].inherit, Some(false));
    }

    #[test]
    fn status_set_condition_replaces_existing() {
        let mut status = PostgresPolicyStatus::default();

        status.set_condition(ready_condition(false, "Pending", "Initial"));
        assert_eq!(status.conditions.len(), 1);
        assert_eq!(status.conditions[0].status, "False");

        status.set_condition(ready_condition(true, "Reconciled", "All good"));
        assert_eq!(status.conditions.len(), 1);
        assert_eq!(status.conditions[0].status, "True");
        assert_eq!(status.conditions[0].reason.as_deref(), Some("Reconciled"));
    }

    #[test]
    fn status_set_condition_adds_new_type() {
        let mut status = PostgresPolicyStatus::default();

        status.set_condition(ready_condition(true, "OK", "ready"));
        status.set_condition(degraded_condition("Error", "something broke"));

        assert_eq!(status.conditions.len(), 2);
    }

    #[test]
    fn paused_condition_has_expected_shape() {
        let paused = paused_condition("paused by spec");
        assert_eq!(paused.condition_type, "Paused");
        assert_eq!(paused.status, "True");
        assert_eq!(paused.reason.as_deref(), Some("Suspended"));
    }

    #[test]
    fn ownership_claims_include_expanded_roles_and_schemas() {
        let mut profiles = std::collections::HashMap::new();
        profiles.insert(
            "editor".to_string(),
            ProfileSpec {
                login: Some(false),
                inherit: None,
                grants: vec![],
                default_privileges: vec![],
                config: Default::default(),
            },
        );

        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-secret".to_string(),
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
            profiles,
            schemas: vec![SchemaBinding {
                name: "inventory".to_string(),
                profiles: vec!["editor".to_string()],
                role_pattern: "{schema}-{profile}".to_string(),
                owner: None,
            }],
            roles: vec![RoleSpec {
                name: "app-service".to_string(),
                external: false,
                preserve_undeclared_grants: false,
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
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![RoleRetirement {
                role: "legacy-app".to_string(),
                reassign_owned_to: None,
                drop_owned: false,
                terminate_sessions: false,
            }],
            approval: None,
        };

        let claims = spec.ownership_claims().unwrap();
        assert!(claims.roles.contains("inventory-editor"));
        assert!(claims.roles.contains("app-service"));
        assert!(claims.roles.contains("legacy-app"));
        assert!(claims.schemas.contains("inventory"));
    }

    #[test]
    fn a_global_default_privilege_claims_the_implicit_default_owner() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-secret".to_string(),
                }),
                secret_key: Some("DATABASE_URL".to_string()),
                params: None,
                require_physical_identity: None,
            },
            interval: "5m".to_string(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            default_owner: Some("app_owner".to_string()),
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![],
            grants: vec![],
            // No `owner`, so the claim has to come from `default_owner`.
            default_privileges: vec![DefaultPrivilege {
                owner: None,
                schema: None,
                scope: Some(pgroles_core::manifest::DefaultPrivilegeScopeSpec {
                    scope_type: pgroles_core::manifest::DefaultPrivilegeScopeType::Global,
                    schema: None,
                }),
                grant: vec![pgroles_core::manifest::DefaultPrivilegeGrant {
                    role: Some("reader".to_string()),
                    privileges: vec![pgroles_core::manifest::Privilege::Select],
                    on_type: ObjectType::Table,
                    ensure: pgroles_core::manifest::Ensure::Present,
                }],
            }],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        let claims = spec.ownership_claims().unwrap();
        assert!(
            claims.roles.contains("app_owner"),
            "expected the resolved default owner to be claimed, got {:?}",
            claims.roles
        );
    }

    #[test]
    fn ownership_overlap_summary_reports_roles_and_schemas() {
        let mut left = OwnershipClaims::default();
        left.roles.insert("analytics".to_string());
        left.schemas.insert("reporting".to_string());

        let mut right = OwnershipClaims::default();
        right.roles.insert("analytics".to_string());
        right.schemas.insert("reporting".to_string());
        right.schemas.insert("other".to_string());

        assert!(left.overlaps(&right));
        let summary = left.overlap_summary(&right);
        assert!(summary.contains("roles: analytics"));
        assert!(summary.contains("schemas: reporting"));
    }

    #[test]
    fn database_identity_uses_namespace_and_identity_key() {
        let conn = ConnectionSpec {
            secret_ref: Some(SecretReference {
                name: "db-creds".to_string(),
            }),
            secret_key: Some("DATABASE_URL".to_string()),
            params: None,
            require_physical_identity: None,
        };
        let identity = DatabaseIdentity::from_connection("prod", &conn);
        assert_eq!(identity.as_str(), "prod/db-creds/DATABASE_URL");
    }

    #[test]
    fn identity_key_same_database_different_users_are_equal() {
        // Two policies targeting the same database but with different users
        // should have the SAME identity key (for locking/conflict detection).
        let user_a = ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("my-host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("mydb".into()),
                dbname_secret: None,
                username: Some("alice".into()),
                username_secret: None,
                password: Some("pass-a".into()),
                password_secret: None,
                auth: None,
                ssl_mode: None,
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        };
        let user_b = ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("my-host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("mydb".into()),
                dbname_secret: None,
                username: Some("bob".into()),
                username_secret: None,
                password: Some("pass-b".into()),
                password_secret: None,
                auth: None,
                ssl_mode: None,
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        };

        assert_eq!(
            user_a.identity_key(),
            user_b.identity_key(),
            "same database with different users should have the same identity key"
        );
        // But cache keys should differ (different credentials = different pool).
        assert_ne!(
            user_a.cache_key("default"),
            user_b.cache_key("default"),
            "different credentials should produce different cache keys"
        );
    }

    #[test]
    fn cache_key_no_collision_between_literal_and_secret_username() {
        // A literal username containing "secret=" should not collide with a
        // real secret reference in the cache key.
        let literal_conn = ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("my-host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("mydb".into()),
                dbname_secret: None,
                username: Some("secret=creds\0password".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                auth: None,
                ssl_mode: None,
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        };
        let secret_conn = ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("my-host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("mydb".into()),
                dbname_secret: None,
                username: None,
                username_secret: Some(SecretKeySelector {
                    name: "creds".into(),
                    key: "password".into(),
                }),
                password: Some("pass".into()),
                password_secret: None,
                auth: None,
                ssl_mode: None,
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        };

        assert_ne!(
            literal_conn.cache_key("default"),
            secret_conn.cache_key("default"),
            "literal and secret ref should produce different cache keys"
        );
    }

    #[test]
    fn cache_key_includes_ssl_mode() {
        let conn_no_ssl = ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("db".into()),
                dbname_secret: None,
                username: Some("user".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                auth: None,
                ssl_mode: None,
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        };
        let conn_with_ssl = ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("db".into()),
                dbname_secret: None,
                username: Some("user".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                auth: None,
                ssl_mode: Some("require".into()),
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        };

        assert_ne!(
            conn_no_ssl.cache_key("ns"),
            conn_with_ssl.cache_key("ns"),
            "cache key should differ when sslMode is present"
        );
    }

    #[test]
    fn validate_connection_rejects_empty_literal_host() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("mydb".into()),
                dbname_secret: None,
                username: Some("user".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                auth: None,
                ssl_mode: None,
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        });

        let err = spec.validate_connection_spec().unwrap_err();
        assert!(
            matches!(err, ConnectionValidationError::EmptyLiteral { ref field } if field == "host"),
            "expected EmptyLiteral for host, got: {err}"
        );
    }

    #[test]
    fn validate_connection_rejects_whitespace_literal_dbname() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("  ".into()),
                dbname_secret: None,
                username: Some("user".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                auth: None,
                ssl_mode: None,
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        });

        let err = spec.validate_connection_spec().unwrap_err();
        assert!(
            matches!(err, ConnectionValidationError::EmptyLiteral { ref field } if field == "dbname"),
            "expected EmptyLiteral for dbname, got: {err}"
        );
    }

    /// Helper to build a minimal spec with the given connection and no roles/grants.
    fn spec_with_connection(connection: ConnectionSpec) -> PostgresPolicySpec {
        PostgresPolicySpec {
            connection,
            interval: "5m".into(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::default(),
            default_owner: None,
            profiles: Default::default(),
            schemas: vec![],
            roles: vec![],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        }
    }

    fn url_mode_connection() -> ConnectionSpec {
        ConnectionSpec {
            secret_ref: Some(SecretReference {
                name: "pg-creds".into(),
            }),
            secret_key: Some("DATABASE_URL".into()),
            params: None,
            require_physical_identity: None,
        }
    }

    fn params_mode_connection() -> ConnectionSpec {
        ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("my-postgres".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("mydb".into()),
                dbname_secret: None,
                username: None,
                username_secret: Some(SecretKeySelector {
                    name: "pg-creds".into(),
                    key: "username".into(),
                }),
                password: None,
                password_secret: Some(SecretKeySelector {
                    name: "pg-creds".into(),
                    key: "password".into(),
                }),
                auth: None,
                ssl_mode: None,
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        }
    }

    // -- Connection validation tests -----------------------------------------

    #[test]
    fn validate_connection_accepts_url_mode() {
        let spec = spec_with_connection(url_mode_connection());
        assert!(spec.validate_connection_spec().is_ok());
    }

    #[test]
    fn validate_connection_accepts_params_mode() {
        let spec = spec_with_connection(params_mode_connection());
        assert!(spec.validate_connection_spec().is_ok());
    }

    #[test]
    fn validate_connection_rejects_both_modes_set() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: Some(SecretReference {
                name: "pg-creds".into(),
            }),
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("db".into()),
                dbname_secret: None,
                username: Some("user".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                auth: None,
                ssl_mode: None,
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        });
        assert!(matches!(
            spec.validate_connection_spec(),
            Err(ConnectionValidationError::BothModesSet)
        ));
    }

    #[test]
    fn validate_connection_rejects_neither_mode_set() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: None,
            require_physical_identity: None,
        });
        assert!(spec.validate_connection_spec().is_err());
    }

    #[test]
    fn validate_connection_rejects_invalid_ssl_mode() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("db".into()),
                dbname_secret: None,
                username: Some("user".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                auth: None,
                ssl_mode: Some("invalid-mode".into()),
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        });
        assert!(spec.validate_connection_spec().is_err());
    }

    fn params_with_set_role(set_role: Option<String>) -> ConnectionParams {
        ConnectionParams {
            host: Some("host".into()),
            host_secret: None,
            port: None,
            port_secret: None,
            dbname: Some("db".into()),
            dbname_secret: None,
            username: Some("user".into()),
            username_secret: None,
            password: Some("pass".into()),
            password_secret: None,
            auth: None,
            ssl_mode: None,
            ssl_mode_secret: None,
            set_role,
        }
    }

    #[test]
    fn validate_connection_accepts_valid_set_role() {
        for role in [
            "cloudsqlsuperuser",
            "_underscore_start",
            "role-with-dash",
            "role_with$dollar",
            "Mixed_Case_Role",
            "r2d2",
        ] {
            let spec = spec_with_connection(ConnectionSpec {
                secret_ref: None,
                secret_key: None,
                params: Some(params_with_set_role(Some(role.into()))),
                require_physical_identity: None,
            });
            assert!(
                spec.validate_connection_spec().is_ok(),
                "expected {role} to be accepted"
            );
        }
    }

    #[test]
    fn validate_connection_rejects_invalid_set_role() {
        for role in [
            "1leading_digit",
            "has space",
            "has\"quote",
            "has;semicolon",
            "has'singlequote",
            "ünicode",
        ] {
            let spec = spec_with_connection(ConnectionSpec {
                secret_ref: None,
                secret_key: None,
                params: Some(params_with_set_role(Some(role.into()))),
                require_physical_identity: None,
            });
            let err = spec
                .validate_connection_spec()
                .expect_err(&format!("expected {role} to be rejected"));
            assert!(
                matches!(err, ConnectionValidationError::InvalidRoleName { ref value } if value == role),
                "unexpected error for {role}: {err:?}",
            );
        }
    }

    #[test]
    fn validate_connection_rejects_empty_set_role() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(params_with_set_role(Some("   ".into()))),
            require_physical_identity: None,
        });
        assert!(matches!(
            spec.validate_connection_spec(),
            Err(ConnectionValidationError::EmptyLiteral { ref field }) if field == "setRole"
        ));
    }

    #[test]
    fn cache_key_includes_set_role() {
        let conn_no_role = ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(params_with_set_role(None)),
            require_physical_identity: None,
        };
        let conn_with_role = ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(params_with_set_role(Some("cloudsqlsuperuser".into()))),
            require_physical_identity: None,
        };
        assert_ne!(
            conn_no_role.cache_key("ns"),
            conn_with_role.cache_key("ns"),
            "cache key should differ when setRole is present"
        );
    }

    #[test]
    fn validate_connection_accepts_gcp_workload_identity_without_password() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("10.0.0.5".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("discovery".into()),
                dbname_secret: None,
                username: Some("pgroles-operator@my-project.iam".into()),
                username_secret: None,
                password: None,
                password_secret: None,
                auth: Some(ConnectionAuth::GcpWorkloadIdentity {
                    impersonate_service_account: None,
                    scope: None,
                }),
                ssl_mode: None,
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        });

        assert!(spec.validate_connection_spec().is_ok());
        assert!(spec.referenced_secret_names("policy").is_empty());
    }

    #[test]
    fn validate_connection_rejects_gcp_workload_identity_with_password() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("10.0.0.5".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("discovery".into()),
                dbname_secret: None,
                username: Some("pgroles-operator@my-project.iam".into()),
                username_secret: None,
                password: Some("static-password".into()),
                password_secret: None,
                auth: Some(ConnectionAuth::GcpWorkloadIdentity {
                    impersonate_service_account: None,
                    scope: None,
                }),
                ssl_mode: None,
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        });

        assert!(matches!(
            spec.validate_connection_spec(),
            Err(ConnectionValidationError::AuthWithPassword)
        ));
    }

    #[test]
    fn validate_connection_rejects_empty_gcp_auth_fields() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("10.0.0.5".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("discovery".into()),
                dbname_secret: None,
                username: Some("pgroles-operator@my-project.iam".into()),
                username_secret: None,
                password: None,
                password_secret: None,
                auth: Some(ConnectionAuth::GcpWorkloadIdentity {
                    impersonate_service_account: Some(" ".into()),
                    scope: None,
                }),
                ssl_mode: None,
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        });

        assert!(matches!(
            spec.validate_connection_spec(),
            Err(ConnectionValidationError::EmptyAuthField { ref field })
                if field == "impersonateServiceAccount"
        ));
    }

    #[test]
    fn validate_connection_accepts_valid_ssl_modes() {
        for mode in &[
            "disable",
            "allow",
            "prefer",
            "require",
            "verify-ca",
            "verify-full",
        ] {
            let spec = spec_with_connection(ConnectionSpec {
                secret_ref: None,
                secret_key: None,
                params: Some(ConnectionParams {
                    host: Some("host".into()),
                    host_secret: None,
                    port: None,
                    port_secret: None,
                    dbname: Some("db".into()),
                    dbname_secret: None,
                    username: Some("user".into()),
                    username_secret: None,
                    password: Some("pass".into()),
                    password_secret: None,
                    auth: None,
                    ssl_mode: Some((*mode).into()),
                    ssl_mode_secret: None,
                    set_role: None,
                }),
                require_physical_identity: None,
            });
            assert!(
                spec.validate_connection_spec().is_ok(),
                "sslMode '{mode}' should be accepted"
            );
        }
    }

    #[test]
    fn validate_connection_rejects_empty_secret_name() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("host".into()),
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("db".into()),
                dbname_secret: None,
                username: None,
                username_secret: Some(SecretKeySelector {
                    name: "".into(),
                    key: "username".into(),
                }),
                password: Some("pass".into()),
                password_secret: None,
                auth: None,
                ssl_mode: None,
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        });
        assert!(spec.validate_connection_spec().is_err());
    }

    #[test]
    fn validate_connection_rejects_both_literal_and_secret_for_same_field() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: Some("host".into()),
                host_secret: Some(SecretKeySelector {
                    name: "s".into(),
                    key: "k".into(),
                }),
                port: None,
                port_secret: None,
                dbname: Some("db".into()),
                dbname_secret: None,
                username: Some("user".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                auth: None,
                ssl_mode: None,
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        });
        assert!(matches!(
            spec.validate_connection_spec(),
            Err(ConnectionValidationError::BothFieldsSet { ref field }) if field == "host"
        ));
    }

    #[test]
    fn validate_connection_rejects_neither_literal_nor_secret_for_required_field() {
        let spec = spec_with_connection(ConnectionSpec {
            secret_ref: None,
            secret_key: None,
            params: Some(ConnectionParams {
                host: None,
                host_secret: None,
                port: None,
                port_secret: None,
                dbname: Some("db".into()),
                dbname_secret: None,
                username: Some("user".into()),
                username_secret: None,
                password: Some("pass".into()),
                password_secret: None,
                auth: None,
                ssl_mode: None,
                ssl_mode_secret: None,
                set_role: None,
            }),
            require_physical_identity: None,
        });
        assert!(matches!(
            spec.validate_connection_spec(),
            Err(ConnectionValidationError::NeitherFieldSet { ref field }) if field == "host"
        ));
    }

    // -- ConnectionSpec backward compatibility --------------------------------

    #[test]
    fn connection_spec_backward_compat_url_mode() {
        // The old format with required secretRef should still deserialize.
        let yaml = r#"
secretRef:
  name: pg-creds
secretKey: DATABASE_URL
"#;
        let conn: ConnectionSpec = serde_yaml::from_str(yaml).unwrap();
        assert!(conn.secret_ref.is_some());
        assert_eq!(conn.effective_secret_key(), "DATABASE_URL");
        assert!(conn.params.is_none());
    }

    #[test]
    fn connection_spec_backward_compat_default_secret_key() {
        let yaml = r#"
secretRef:
  name: pg-creds
"#;
        let conn: ConnectionSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(conn.effective_secret_key(), "DATABASE_URL");
    }

    #[test]
    fn connection_spec_params_mode_deserializes_keycloak_style() {
        let yaml = r#"
params:
  host: my-postgres
  port: 5432
  dbname: mydb
  usernameSecret:
    name: creds
    key: username
  passwordSecret:
    name: creds
    key: password
  sslMode: require
"#;
        let conn: ConnectionSpec = serde_yaml::from_str(yaml).unwrap();
        assert!(conn.secret_ref.is_none());
        let params = conn.params.unwrap();
        assert_eq!(params.host.as_deref(), Some("my-postgres"));
        assert_eq!(params.port, Some(5432));
        assert!(params.username_secret.is_some());
        assert_eq!(params.username_secret.as_ref().unwrap().name, "creds");
        assert_eq!(params.ssl_mode.as_deref(), Some("require"));
    }

    #[test]
    fn connection_spec_params_mode_deserializes_gcp_workload_identity_auth() {
        let yaml = r#"
params:
  host: 10.0.0.5
  port: 5432
  dbname: discovery
  username: pgroles-operator@my-project.iam
  auth:
    type: gcp_workload_identity
    impersonateServiceAccount: target@other-project.iam.gserviceaccount.com
    scope: https://example.com/custom-scope
"#;
        let conn: ConnectionSpec = serde_yaml::from_str(yaml).unwrap();
        let params = conn.params.as_ref().unwrap();
        let auth = params.auth.as_ref().expect("auth should deserialize");

        assert!(params.password.is_none());
        assert_eq!(auth.gcp_scope(), "https://example.com/custom-scope");
        assert_eq!(
            auth.gcp_impersonate_service_account(),
            Some("target@other-project.iam.gserviceaccount.com")
        );
        assert!(conn.cache_key("prod").contains("gcp_workload_identity"));

        let spec = spec_with_connection(conn);
        assert!(spec.validate_connection_spec().is_ok());
    }

    #[test]
    fn connection_spec_params_mode_all_secrets() {
        // CNPG/PGO pattern — everything from one secret.
        let yaml = r#"
params:
  hostSecret:
    name: cluster-app
    key: host
  portSecret:
    name: cluster-app
    key: port
  dbnameSecret:
    name: cluster-app
    key: dbname
  usernameSecret:
    name: cluster-app
    key: user
  passwordSecret:
    name: cluster-app
    key: password
"#;
        let conn: ConnectionSpec = serde_yaml::from_str(yaml).unwrap();
        let params = conn.params.unwrap();
        assert!(params.host.is_none());
        assert!(params.host_secret.is_some());
        assert_eq!(params.host_secret.as_ref().unwrap().name, "cluster-app");
        assert!(params.port.is_none());
        assert!(params.port_secret.is_some());
    }

    // -- referenced_secret_names with params mode ----------------------------

    #[test]
    fn referenced_secret_names_includes_params_secrets() {
        let spec = spec_with_connection(params_mode_connection());
        let names = spec.referenced_secret_names("test-policy");
        assert!(
            names.contains("pg-creds"),
            "should include the credential secret from params"
        );
    }

    #[test]
    fn referenced_secret_names_deduplicates_across_modes() {
        // Same secret name used in both connection and password secretRef.
        let mut spec = spec_with_connection(params_mode_connection());
        spec.roles = vec![RoleSpec {
            name: "app".into(),
            external: false,
            preserve_undeclared_grants: false,
            login: Some(true),
            password: Some(PasswordSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-creds".into(),
                }),
                secret_key: Some("app-password".into()),
                generate: None,
            }),
            password_valid_until: None,
            config: Default::default(),
            superuser: None,
            createdb: None,
            createrole: None,
            inherit: None,
            replication: None,
            bypassrls: None,
            connection_limit: None,
            comment: None,
        }];
        let names = spec.referenced_secret_names("test-policy");
        // pg-creds appears in both connection params and password — should be deduped.
        assert_eq!(
            names.iter().filter(|n| *n == "pg-creds").count(),
            1,
            "BTreeSet should deduplicate"
        );
    }

    // -- ConnectionParams port default ---------------------------------------

    #[test]
    fn connection_params_port_defaults_to_none() {
        let yaml = r#"
params:
  host: my-host
  dbname: mydb
  username: user
  password: pass
"#;
        let conn: ConnectionSpec = serde_yaml::from_str(yaml).unwrap();
        let params = conn.params.unwrap();
        assert!(
            params.port.is_none(),
            "port should default to None (resolved as 5432 at runtime)"
        );
        assert!(
            params.port_secret.is_none(),
            "portSecret should also default to None"
        );
    }

    #[test]
    fn now_rfc3339_produces_valid_format() {
        let ts = now_rfc3339();
        // Should match YYYY-MM-DDTHH:MM:SSZ
        assert!(ts.len() == 20, "expected 20 chars, got {}: {ts}", ts.len());
        assert!(ts.ends_with('Z'), "should end with Z: {ts}");
        assert_eq!(&ts[4..5], "-", "should have dash at pos 4: {ts}");
        assert_eq!(&ts[10..11], "T", "should have T at pos 10: {ts}");
    }

    #[test]
    fn ready_condition_true_has_expected_shape() {
        let cond = ready_condition(true, "Reconciled", "All changes applied");
        assert_eq!(cond.condition_type, "Ready");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason.as_deref(), Some("Reconciled"));
        assert_eq!(cond.message.as_deref(), Some("All changes applied"));
        assert!(cond.last_transition_time.is_some());
    }

    #[test]
    fn ready_condition_false_has_expected_shape() {
        let cond = ready_condition(false, "InvalidSpec", "bad manifest");
        assert_eq!(cond.condition_type, "Ready");
        assert_eq!(cond.status, "False");
        assert_eq!(cond.reason.as_deref(), Some("InvalidSpec"));
        assert_eq!(cond.message.as_deref(), Some("bad manifest"));
    }

    #[test]
    fn degraded_condition_has_expected_shape() {
        let cond = degraded_condition("InvalidSpec", "expansion failed");
        assert_eq!(cond.condition_type, "Degraded");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason.as_deref(), Some("InvalidSpec"));
        assert_eq!(cond.message.as_deref(), Some("expansion failed"));
        assert!(cond.last_transition_time.is_some());
    }

    #[test]
    fn reconciling_condition_has_expected_shape() {
        let cond = reconciling_condition("Reconciliation in progress");
        assert_eq!(cond.condition_type, "Reconciling");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason.as_deref(), Some("Reconciling"));
        assert_eq!(cond.message.as_deref(), Some("Reconciliation in progress"));
        assert!(cond.last_transition_time.is_some());
    }

    #[test]
    fn conflict_condition_has_expected_shape() {
        let cond = conflict_condition("ConflictingPolicy", "overlaps with ns/other");
        assert_eq!(cond.condition_type, "Conflict");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.reason.as_deref(), Some("ConflictingPolicy"));
        assert_eq!(cond.message.as_deref(), Some("overlaps with ns/other"));
        assert!(cond.last_transition_time.is_some());
    }

    #[test]
    fn approval_unset_condition_names_the_inferred_mode() {
        for (mode, expected) in [
            (ApprovalMode::Auto, "auto"),
            (ApprovalMode::Manual, "manual"),
        ] {
            let cond = approval_unset_condition(mode);
            assert_eq!(cond.condition_type, CONDITION_APPROVAL_UNSET);
            assert_eq!(cond.status, "True");
            assert_eq!(cond.reason.as_deref(), Some("InferredFromMode"));
            assert!(cond.last_transition_time.is_some());

            let message = cond.message.expect("condition should carry a message");
            // The message has to state both what the policy does now and the
            // exact line to add, since that is the whole remediation path.
            assert!(
                message.contains(&format!("inferred as {expected}")),
                "message should name the inferred mode, got: {message}"
            );
            assert!(
                message.contains(&format!("`approval: {expected}`")),
                "message should show the fix to apply, got: {message}"
            );
            assert!(
                message.contains("deprecated"),
                "message should say the inference is deprecated, got: {message}"
            );
        }
    }

    #[test]
    fn ownership_claims_no_overlap() {
        let mut left = OwnershipClaims::default();
        left.roles.insert("analytics".to_string());
        left.schemas.insert("reporting".to_string());

        let mut right = OwnershipClaims::default();
        right.roles.insert("billing".to_string());
        right.schemas.insert("payments".to_string());

        assert!(!left.overlaps(&right));
        let summary = left.overlap_summary(&right);
        assert!(summary.is_empty());
    }

    /// Build a spec whose only content is one database-level PUBLIC grant.
    fn public_connect_spec(
        database: &str,
        ensure: pgroles_core::manifest::Ensure,
    ) -> PostgresPolicySpec {
        PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-secret".to_string(),
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
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![],
            grants: vec![Grant {
                role: "PUBLIC".to_string(),
                privileges: vec![pgroles_core::manifest::Privilege::Connect],
                object: pgroles_core::manifest::ObjectTarget {
                    object_type: ObjectType::Database,
                    schema: None,
                    name: Some(database.to_string()),
                },
                ensure,
            }],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        }
    }

    #[test]
    fn contradictory_public_database_rules_are_detected_as_conflicting() {
        use pgroles_core::manifest::Ensure;
        // Disjoint in roles and schemas: both claim nothing but PUBLIC on the
        // same database, and they assert opposite states for it.
        let present = public_connect_spec("mydb", Ensure::Present)
            .ownership_claims()
            .unwrap();
        let absent = public_connect_spec("mydb", Ensure::Absent)
            .ownership_claims()
            .unwrap();

        assert!(present.roles.is_disjoint(&absent.roles));
        assert!(present.schemas.is_disjoint(&absent.schemas));
        assert!(
            present.overlaps(&absent),
            "two policies writing PUBLIC on the same database must conflict"
        );
        assert!(present.overlap_summary(&absent).contains("mydb"));
    }

    #[test]
    fn public_rules_on_different_databases_do_not_conflict() {
        use pgroles_core::manifest::Ensure;
        let left = public_connect_spec("orders", Ensure::Present)
            .ownership_claims()
            .unwrap();
        let right = public_connect_spec("billing", Ensure::Present)
            .ownership_claims()
            .unwrap();
        assert!(!left.overlaps(&right));
    }

    #[test]
    fn ownership_claims_partial_role_overlap() {
        let mut left = OwnershipClaims::default();
        left.roles.insert("analytics".to_string());
        left.roles.insert("reporting-viewer".to_string());

        let mut right = OwnershipClaims::default();
        right.roles.insert("analytics".to_string());
        right.roles.insert("other-role".to_string());

        assert!(left.overlaps(&right));
        let summary = left.overlap_summary(&right);
        assert!(summary.contains("roles: analytics"));
        assert!(!summary.contains("schemas"));
    }

    #[test]
    fn ownership_claims_empty_is_disjoint() {
        let left = OwnershipClaims::default();
        let right = OwnershipClaims::default();
        assert!(!left.overlaps(&right));
    }

    #[test]
    fn database_identity_equality() {
        let conn_a = ConnectionSpec {
            secret_ref: Some(SecretReference {
                name: "db-creds".to_string(),
            }),
            secret_key: Some("DATABASE_URL".to_string()),
            params: None,
            require_physical_identity: None,
        };
        let a = DatabaseIdentity::from_connection("prod", &conn_a);
        let b = DatabaseIdentity::from_connection("prod", &conn_a);
        let c = DatabaseIdentity::from_connection("staging", &conn_a);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn database_identity_different_key() {
        let conn_a = ConnectionSpec {
            secret_ref: Some(SecretReference {
                name: "db-creds".to_string(),
            }),
            secret_key: Some("DATABASE_URL".to_string()),
            params: None,
            require_physical_identity: None,
        };
        let conn_b = ConnectionSpec {
            secret_ref: Some(SecretReference {
                name: "db-creds".to_string(),
            }),
            secret_key: Some("CUSTOM_URL".to_string()),
            params: None,
            require_physical_identity: None,
        };
        let a = DatabaseIdentity::from_connection("prod", &conn_a);
        let b = DatabaseIdentity::from_connection("prod", &conn_b);
        assert_ne!(a, b);
    }

    #[test]
    fn status_default_has_empty_conditions() {
        let status = PostgresPolicyStatus::default();
        assert!(status.conditions.is_empty());
        assert!(status.observed_generation.is_none());
        assert!(status.last_attempted_generation.is_none());
        assert!(status.last_successful_reconcile_time.is_none());
        assert!(status.change_summary.is_none());
        assert!(status.managed_database_identity.is_none());
        assert!(status.owned_roles.is_empty());
        assert!(status.owned_schemas.is_empty());
        assert!(status.last_error.is_none());
        assert!(status.applied_password_source_versions.is_empty());
    }

    #[test]
    fn status_degraded_workflow_sets_ready_false_and_degraded_true() {
        let mut status = PostgresPolicyStatus::default();

        // Simulate a failed reconciliation: Ready=False + Degraded=True
        status.set_condition(ready_condition(false, "InvalidSpec", "bad manifest"));
        status.set_condition(degraded_condition("InvalidSpec", "bad manifest"));
        status
            .conditions
            .retain(|c| c.condition_type != "Reconciling" && c.condition_type != "Paused");
        status.change_summary = None;
        status.last_error = Some("bad manifest".to_string());

        // Verify Ready=False
        let ready = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Ready")
            .expect("should have Ready condition");
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason.as_deref(), Some("InvalidSpec"));

        // Verify Degraded=True
        let degraded = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Degraded")
            .expect("should have Degraded condition");
        assert_eq!(degraded.status, "True");
        assert_eq!(degraded.reason.as_deref(), Some("InvalidSpec"));

        // Verify last_error is set
        assert_eq!(status.last_error.as_deref(), Some("bad manifest"));
    }

    #[test]
    fn status_conflict_workflow() {
        let mut status = PostgresPolicyStatus::default();

        // Simulate a conflict
        let msg = "policy ownership overlaps with staging/other on database target prod/db/URL";
        status.set_condition(ready_condition(false, "ConflictingPolicy", msg));
        status.set_condition(conflict_condition("ConflictingPolicy", msg));
        status.set_condition(degraded_condition("ConflictingPolicy", msg));
        status
            .conditions
            .retain(|c| c.condition_type != "Reconciling");
        status.last_error = Some(msg.to_string());

        // Verify Conflict=True
        let conflict = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Conflict")
            .expect("should have Conflict condition");
        assert_eq!(conflict.status, "True");
        assert_eq!(conflict.reason.as_deref(), Some("ConflictingPolicy"));

        // Verify Ready=False
        let ready = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Ready")
            .expect("should have Ready condition");
        assert_eq!(ready.status, "False");

        // Verify Degraded=True
        let degraded = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Degraded")
            .expect("should have Degraded condition");
        assert_eq!(degraded.status, "True");
    }

    #[test]
    fn status_successful_reconcile_records_generation_and_time() {
        let mut status = PostgresPolicyStatus::default();
        let generation = Some(3_i64);
        let summary = ChangeSummary {
            roles_created: 2,
            total: 2,
            ..Default::default()
        };

        // Simulate a successful reconciliation
        status.set_condition(ready_condition(true, "Reconciled", "All changes applied"));
        status.conditions.retain(|c| {
            c.condition_type != "Reconciling"
                && c.condition_type != "Degraded"
                && c.condition_type != "Conflict"
                && c.condition_type != "Paused"
        });
        status.observed_generation = generation;
        status.last_attempted_generation = generation;
        status.last_successful_reconcile_time = Some(now_rfc3339());
        status.change_summary = Some(summary);
        status.last_error = None;

        // Verify Ready=True
        let ready = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Ready")
            .expect("should have Ready condition");
        assert_eq!(ready.status, "True");
        assert_eq!(ready.reason.as_deref(), Some("Reconciled"));

        // Verify generation recorded
        assert_eq!(status.observed_generation, Some(3));
        assert_eq!(status.last_attempted_generation, Some(3));

        // Verify timestamps set
        assert!(status.last_successful_reconcile_time.is_some());

        // Verify summary
        let summary = status.change_summary.as_ref().unwrap();
        assert_eq!(summary.roles_created, 2);
        assert_eq!(summary.total, 2);

        // Verify no error
        assert!(status.last_error.is_none());

        // Verify no Degraded/Conflict/Paused/Reconciling conditions
        assert!(
            status
                .conditions
                .iter()
                .all(|c| c.condition_type != "Degraded"
                    && c.condition_type != "Conflict"
                    && c.condition_type != "Paused"
                    && c.condition_type != "Reconciling")
        );
    }

    #[test]
    fn status_suspended_workflow() {
        let mut status = PostgresPolicyStatus::default();
        let generation = Some(2_i64);

        // Simulate a suspended reconciliation
        status.set_condition(paused_condition("Reconciliation suspended by spec"));
        status.set_condition(ready_condition(
            false,
            "Suspended",
            "Reconciliation suspended by spec",
        ));
        status
            .conditions
            .retain(|c| c.condition_type != "Reconciling");
        status.last_attempted_generation = generation;
        status.last_error = None;

        // Verify Paused=True
        let paused = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Paused")
            .expect("should have Paused condition");
        assert_eq!(paused.status, "True");

        // Verify Ready=False with Suspended reason
        let ready = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Ready")
            .expect("should have Ready condition");
        assert_eq!(ready.status, "False");
        assert_eq!(ready.reason.as_deref(), Some("Suspended"));

        // Verify no Reconciling condition
        assert!(
            !status
                .conditions
                .iter()
                .any(|c| c.condition_type == "Reconciling")
        );
    }

    #[test]
    fn status_transitions_from_degraded_to_ready() {
        let mut status = PostgresPolicyStatus::default();

        // First, set degraded state
        status.set_condition(ready_condition(false, "InvalidSpec", "error"));
        status.set_condition(degraded_condition("InvalidSpec", "error"));
        status.last_error = Some("error".to_string());

        assert_eq!(status.conditions.len(), 2);

        // Then, resolve to ready
        status.set_condition(ready_condition(true, "Reconciled", "All changes applied"));
        status.conditions.retain(|c| {
            c.condition_type != "Reconciling"
                && c.condition_type != "Degraded"
                && c.condition_type != "Conflict"
                && c.condition_type != "Paused"
        });
        status.last_error = None;

        // Verify Ready=True
        let ready = status
            .conditions
            .iter()
            .find(|c| c.condition_type == "Ready")
            .expect("should have Ready condition");
        assert_eq!(ready.status, "True");

        // Verify Degraded removed
        assert!(
            !status
                .conditions
                .iter()
                .any(|c| c.condition_type == "Degraded")
        );

        // Verify only Ready condition remains
        assert_eq!(status.conditions.len(), 1);

        // Verify error cleared
        assert!(status.last_error.is_none());
    }

    #[test]
    fn change_summary_default_is_all_zero() {
        let summary = ChangeSummary::default();
        assert_eq!(summary.roles_created, 0);
        assert_eq!(summary.roles_altered, 0);
        assert_eq!(summary.roles_dropped, 0);
        assert_eq!(summary.sessions_terminated, 0);
        assert_eq!(summary.grants_added, 0);
        assert_eq!(summary.grants_revoked, 0);
        assert_eq!(summary.default_privileges_set, 0);
        assert_eq!(summary.default_privileges_revoked, 0);
        assert_eq!(summary.members_added, 0);
        assert_eq!(summary.members_removed, 0);
        assert_eq!(summary.total, 0);
    }

    #[test]
    fn status_serializes_to_json() {
        let mut status = PostgresPolicyStatus::default();
        status.set_condition(ready_condition(true, "Reconciled", "done"));
        status.observed_generation = Some(5);
        status.managed_database_identity = Some("ns/secret/key".to_string());
        status.owned_roles = vec!["role-a".to_string(), "role-b".to_string()];
        status.owned_schemas = vec!["public".to_string()];
        status.change_summary = Some(ChangeSummary {
            roles_created: 1,
            total: 1,
            ..Default::default()
        });

        let json = serde_json::to_string(&status).expect("should serialize");
        assert!(json.contains("\"Reconciled\""));
        assert!(json.contains("\"observed_generation\":5"));
        assert!(json.contains("\"role-a\""));
        assert!(json.contains("\"ns/secret/key\""));
    }

    #[test]
    fn crd_spec_deserializes_from_yaml() {
        let yaml = r#"
connection:
  secretRef:
    name: pg-credentials
interval: "10m"
default_owner: app_owner
profiles:
  editor:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        object: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT, UPDATE, DELETE]
        on_type: table
schemas:
  - name: inventory
    profiles: [editor]
roles:
  - name: analytics
    login: true
grants:
  - role: analytics
    privileges: [CONNECT]
    object: { type: database, name: mydb }
memberships:
  - role: inventory-editor
    members:
      - name: analytics
retirements:
  - role: legacy-app
    reassign_owned_to: app_owner
    drop_owned: true
    terminate_sessions: true
"#;
        let spec: PostgresPolicySpec = serde_yaml::from_str(yaml).expect("should deserialize");
        assert_eq!(spec.interval, "10m");
        assert_eq!(spec.default_owner, Some("app_owner".to_string()));
        assert_eq!(spec.profiles.len(), 1);
        assert!(spec.profiles.contains_key("editor"));
        assert_eq!(spec.schemas.len(), 1);
        assert_eq!(spec.roles.len(), 1);
        assert_eq!(spec.grants.len(), 1);
        assert_eq!(spec.memberships.len(), 1);
        assert_eq!(spec.retirements.len(), 1);
        assert_eq!(spec.retirements[0].role, "legacy-app");
        assert!(spec.retirements[0].terminate_sessions);
    }

    #[test]
    fn referenced_secret_names_includes_connection_secret() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
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
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        let names = spec.referenced_secret_names("test-policy");
        assert!(names.contains("pg-conn"));
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn referenced_secret_names_includes_password_secrets() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
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
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![
                RoleSpec {
                    name: "role-a".to_string(),
                    external: false,
                    preserve_undeclared_grants: false,
                    login: Some(true),
                    password: Some(PasswordSpec {
                        secret_ref: Some(SecretReference {
                            name: "role-passwords".to_string(),
                        }),
                        secret_key: Some("role-a".to_string()),
                        generate: None,
                    }),
                    password_valid_until: None,
                    config: Default::default(),
                    superuser: None,
                    createdb: None,
                    createrole: None,
                    inherit: None,
                    replication: None,
                    bypassrls: None,
                    connection_limit: None,
                    comment: None,
                },
                RoleSpec {
                    name: "role-b".to_string(),
                    external: false,
                    preserve_undeclared_grants: false,
                    login: Some(true),
                    password: Some(PasswordSpec {
                        secret_ref: Some(SecretReference {
                            name: "other-secret".to_string(),
                        }),
                        secret_key: None,
                        generate: None,
                    }),
                    password_valid_until: None,
                    config: Default::default(),
                    superuser: None,
                    createdb: None,
                    createrole: None,
                    inherit: None,
                    replication: None,
                    bypassrls: None,
                    connection_limit: None,
                    comment: None,
                },
                RoleSpec {
                    name: "role-c".to_string(),
                    external: false,
                    preserve_undeclared_grants: false,
                    login: None,
                    password: None,
                    password_valid_until: None,
                    config: Default::default(),
                    superuser: None,
                    createdb: None,
                    createrole: None,
                    inherit: None,
                    replication: None,
                    bypassrls: None,
                    connection_limit: None,
                    comment: None,
                },
            ],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        let names = spec.referenced_secret_names("test-policy");
        assert!(
            names.contains("pg-conn"),
            "should include connection secret"
        );
        assert!(
            names.contains("role-passwords"),
            "should include role-a password secret"
        );
        assert!(
            names.contains("other-secret"),
            "should include role-b password secret"
        );
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn validate_password_specs_rejects_password_without_login() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
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
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![RoleSpec {
                name: "app-user".to_string(),
                external: false,
                preserve_undeclared_grants: false,
                login: Some(false),
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
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        assert!(matches!(
            spec.validate_password_specs("test-policy"),
            Err(PasswordValidationError::PasswordWithoutLogin { ref role }) if role == "app-user"
        ));
    }

    #[test]
    fn validate_password_specs_rejects_password_with_login_omitted() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
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
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![RoleSpec {
                name: "app-user".to_string(),
                external: false,
                preserve_undeclared_grants: false,
                login: None, // omitted, not explicitly false
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
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        assert!(matches!(
            spec.validate_password_specs("test-policy"),
            Err(PasswordValidationError::PasswordWithoutLogin { ref role }) if role == "app-user"
        ));
    }

    #[test]
    fn validate_password_specs_rejects_invalid_password_mode() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
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
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![RoleSpec {
                name: "app-user".to_string(),
                external: false,
                preserve_undeclared_grants: false,
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
                    generate: Some(GeneratePasswordSpec {
                        length: Some(32),
                        secret_name: None,
                        secret_key: None,
                    }),
                }),
                password_valid_until: None,
                config: Default::default(),
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        assert!(matches!(
            spec.validate_password_specs("test-policy"),
            Err(PasswordValidationError::InvalidPasswordMode { ref role }) if role == "app-user"
        ));
    }

    #[test]
    fn validate_password_specs_rejects_invalid_generated_length() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
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
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![RoleSpec {
                name: "app-user".to_string(),
                external: false,
                preserve_undeclared_grants: false,
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
                    secret_ref: None,
                    secret_key: None,
                    generate: Some(GeneratePasswordSpec {
                        length: Some(8),
                        secret_name: None,
                        secret_key: None,
                    }),
                }),
                password_valid_until: None,
                config: Default::default(),
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        assert!(matches!(
            spec.validate_password_specs("test-policy"),
            Err(PasswordValidationError::InvalidGeneratedLength { ref role, .. }) if role == "app-user"
        ));
    }

    #[test]
    fn validate_password_specs_rejects_invalid_generated_secret_key() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
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
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![RoleSpec {
                name: "app-user".to_string(),
                external: false,
                preserve_undeclared_grants: false,
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
                    secret_ref: None,
                    secret_key: None,
                    generate: Some(GeneratePasswordSpec {
                        length: Some(32),
                        secret_name: None,
                        secret_key: Some("bad/key".to_string()),
                    }),
                }),
                password_valid_until: None,
                config: Default::default(),
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        assert!(matches!(
            spec.validate_password_specs("test-policy"),
            Err(PasswordValidationError::InvalidSecretKey { ref role, field, .. })
                if role == "app-user" && field == "generate.secretKey"
        ));
    }

    #[test]
    fn validate_password_specs_rejects_invalid_generated_secret_name() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
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
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![RoleSpec {
                name: "app-user".to_string(),
                external: false,
                preserve_undeclared_grants: false,
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
                    secret_ref: None,
                    secret_key: None,
                    generate: Some(GeneratePasswordSpec {
                        length: Some(32),
                        secret_name: Some("Bad_Name".to_string()),
                        secret_key: None,
                    }),
                }),
                password_valid_until: None,
                config: Default::default(),
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        assert!(matches!(
            spec.validate_password_specs("test-policy"),
            Err(PasswordValidationError::InvalidGeneratedSecretName { ref role, .. }) if role == "app-user"
        ));
    }

    #[test]
    fn validate_password_specs_rejects_reserved_generated_secret_key() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "pg-conn".to_string(),
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
            profiles: std::collections::HashMap::new(),
            schemas: vec![],
            roles: vec![RoleSpec {
                name: "app-user".to_string(),
                external: false,
                preserve_undeclared_grants: false,
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
                    secret_ref: None,
                    secret_key: None,
                    generate: Some(GeneratePasswordSpec {
                        length: Some(32),
                        secret_name: None,
                        secret_key: Some("verifier".to_string()),
                    }),
                }),
                password_valid_until: None,
                config: Default::default(),
            }],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        assert!(matches!(
            spec.validate_password_specs("test-policy"),
            Err(PasswordValidationError::ReservedGeneratedSecretKey { ref role, ref key })
                if role == "app-user" && key == "verifier"
        ));
    }

    #[test]
    fn plan_crd_generates_valid_schema() {
        let crd = PostgresPolicyPlan::crd();
        let yaml = serde_yaml::to_string(&crd).expect("CRD should serialize to YAML");
        assert!(yaml.contains("pgroles.io"), "group should be pgroles.io");
        assert!(yaml.contains("v1alpha1"), "version should be v1alpha1");
        assert!(
            yaml.contains("PostgresPolicyPlan"),
            "kind should be PostgresPolicyPlan"
        );
        assert!(yaml.contains("pgplan"), "should have shortname pgplan");
    }

    #[test]
    fn plan_phase_display() {
        assert_eq!(PlanPhase::Pending.to_string(), "Pending");
        assert_eq!(PlanPhase::Approved.to_string(), "Approved");
        assert_eq!(PlanPhase::Applying.to_string(), "Applying");
        assert_eq!(PlanPhase::Applied.to_string(), "Applied");
        assert_eq!(PlanPhase::Failed.to_string(), "Failed");
        assert_eq!(PlanPhase::Superseded.to_string(), "Superseded");
    }

    #[test]
    fn plan_phase_default_is_pending() {
        assert_eq!(PlanPhase::default(), PlanPhase::Pending);
    }

    #[test]
    fn effective_approval_infers_from_mode() {
        let base = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "test".into(),
                }),
                secret_key: Some("DATABASE_URL".into()),
                params: None,
                require_physical_identity: None,
            },
            interval: "5m".into(),
            suspend: false,
            mode: PolicyMode::Apply,
            reconciliation_mode: CrdReconciliationMode::Authoritative,
            default_owner: None,
            profiles: Default::default(),
            schemas: vec![],
            roles: vec![],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: None,
        };

        // apply mode with no explicit approval → Auto
        assert_eq!(base.effective_approval(), ApprovalMode::Auto);

        // observe mode with no explicit approval → Manual
        let plan = PostgresPolicySpec {
            mode: PolicyMode::Observe,
            ..base.clone()
        };
        assert_eq!(plan.effective_approval(), ApprovalMode::Manual);

        // explicit Manual overrides apply mode
        let explicit = PostgresPolicySpec {
            approval: Some(ApprovalMode::Manual),
            ..base.clone()
        };
        assert_eq!(explicit.effective_approval(), ApprovalMode::Manual);
    }

    #[test]
    fn approval_mode_serde_roundtrip() {
        // Deserialize
        let manual: ApprovalMode = serde_json::from_str("\"manual\"").unwrap();
        assert_eq!(manual, ApprovalMode::Manual);
        let auto: ApprovalMode = serde_json::from_str("\"auto\"").unwrap();
        assert_eq!(auto, ApprovalMode::Auto);

        // Serialize back
        let manual_json = serde_json::to_value(&ApprovalMode::Manual).unwrap();
        assert_eq!(manual_json, serde_json::Value::String("manual".to_string()));
        let auto_json = serde_json::to_value(&ApprovalMode::Auto).unwrap();
        assert_eq!(auto_json, serde_json::Value::String("auto".to_string()));
    }

    /// The deprecation window for the `plan` → `observe` rename: the legacy
    /// value stays an accepted schema value (a GitOps controller re-applies
    /// the manifest on every sync, so rejecting it on write would break the
    /// policy at upgrade time), and it behaves as `observe` in every path
    /// while identifying itself as the deprecated spelling. Removal is a
    /// later release's breaking change.
    #[test]
    fn the_legacy_plan_mode_value_is_accepted_and_behaves_as_observe() {
        let legacy: PolicyMode = serde_json::from_str("\"plan\"").unwrap();
        assert!(legacy.never_executes());
        assert!(legacy.is_deprecated_spelling());
        assert!(PolicyMode::Observe.never_executes());
        assert!(!PolicyMode::Observe.is_deprecated_spelling());
        assert!(!PolicyMode::Apply.never_executes());

        // The deprecated spelling round-trips: the operator must not rewrite
        // a user's spec value, and `lastReconcileMode` reports what the spec
        // says.
        assert_eq!(
            serde_json::to_value(PolicyMode::Plan).unwrap(),
            serde_json::Value::String("plan".to_string())
        );

        let schema = serde_json::to_value(schemars::schema_for!(PolicyMode)).unwrap();
        let rendered = schema.to_string();
        assert!(rendered.contains("observe"));
        assert!(
            rendered.contains("\"plan\""),
            "the schema must keep accepting the deprecated value during the \
             deprecation window: {rendered}"
        );
    }

    #[test]
    fn plan_status_default_is_empty() {
        let status = PostgresPolicyPlanStatus::default();
        assert_eq!(status.phase, PlanPhase::Pending);
        assert!(status.conditions.is_empty());
        assert!(status.change_summary.is_none());
        assert!(status.sql_ref.is_none());
        assert!(status.sql_inline.is_none());
        assert!(status.computed_at.is_none());
        assert!(status.applied_at.is_none());
        assert!(status.last_error.is_none());
    }

    #[test]
    fn spec_without_approval_field_deserializes_as_none() {
        let json = serde_json::json!({
            "connection": {
                "secretRef": { "name": "pg-secret" },
                "secretKey": "DATABASE_URL"
            },
            "interval": "5m",
            "suspend": false,
            "mode": "apply",
            "reconciliation_mode": "authoritative"
        });

        let spec: PostgresPolicySpec =
            serde_json::from_value(json).expect("should deserialize without approval field");
        assert!(
            spec.approval.is_none(),
            "approval should be None when omitted"
        );
        assert_eq!(
            spec.effective_approval(),
            ApprovalMode::Auto,
            "effective_approval should infer Auto from apply mode"
        );
    }

    #[test]
    fn status_without_current_plan_ref_deserializes_as_none() {
        let json = serde_json::json!({
            "conditions": [],
            "owned_roles": [],
            "owned_schemas": []
        });

        let status: PostgresPolicyStatus =
            serde_json::from_value(json).expect("should deserialize without current_plan_ref");
        assert!(
            status.current_plan_ref.is_none(),
            "current_plan_ref should be None when omitted"
        );
    }

    #[test]
    fn effective_approval_explicit_auto_overrides_plan_mode() {
        let spec = PostgresPolicySpec {
            connection: ConnectionSpec {
                secret_ref: Some(SecretReference {
                    name: "test".into(),
                }),
                secret_key: Some("DATABASE_URL".into()),
                params: None,
                require_physical_identity: None,
            },
            interval: "5m".into(),
            suspend: false,
            mode: PolicyMode::Observe,
            reconciliation_mode: CrdReconciliationMode::Authoritative,
            default_owner: None,
            profiles: Default::default(),
            schemas: vec![],
            roles: vec![],
            grants: vec![],
            default_privileges: vec![],
            memberships: vec![],
            retirements: vec![],
            approval: Some(ApprovalMode::Auto),
        };

        assert_eq!(
            spec.effective_approval(),
            ApprovalMode::Auto,
            "explicit Auto should override Observe mode's default of Manual"
        );
    }

    #[test]
    fn plan_phase_rejected_display() {
        assert_eq!(PlanPhase::Rejected.to_string(), "Rejected");
    }

    #[test]
    fn plan_phase_all_variants_display() {
        let variants = [
            PlanPhase::Pending,
            PlanPhase::Approved,
            PlanPhase::Applying,
            PlanPhase::Applied,
            PlanPhase::Failed,
            PlanPhase::Superseded,
            PlanPhase::Rejected,
        ];
        for variant in &variants {
            let display = variant.to_string();
            assert!(
                !display.is_empty(),
                "PlanPhase::{variant:?} should have non-empty Display output"
            );
        }
    }

    #[test]
    fn plan_status_defaults() {
        let status = PostgresPolicyPlanStatus::default();
        assert_eq!(status.phase, PlanPhase::Pending);
        assert!(status.conditions.is_empty());
        assert!(status.sql_ref.is_none());
        assert!(status.sql_hash.is_none());
        assert!(status.sql_inline.is_none());
        assert!(!status.sql_truncated);
        assert!(status.redacted_sql_hash.is_none());
        assert!(status.sql_original_bytes.is_none());
        assert!(status.sql_stored_bytes.is_none());
        assert!(status.change_summary.is_none());
        assert!(status.computed_at.is_none());
        assert!(status.applied_at.is_none());
        assert!(status.last_error.is_none());
    }

    #[test]
    fn sql_ref_missing_compression_deserializes_as_uncompressed_legacy_shape() {
        let json = serde_json::json!({
            "name": "legacy-plan-sql",
            "key": "plan.sql"
        });

        let sql_ref: SqlRef = serde_json::from_value(json).expect("legacy SqlRef should decode");

        assert_eq!(sql_ref.name, "legacy-plan-sql");
        assert_eq!(sql_ref.key, "plan.sql");
        assert_eq!(sql_ref.compression, None);
    }

    #[test]
    fn plan_spec_camel_case_serialization() {
        let spec = PostgresPolicyPlanSpec {
            policy_ref: PolicyPlanRef {
                name: "my-policy".into(),
            },
            policy_generation: 3,
            reconciliation_mode: CrdReconciliationMode::Authoritative,
            owned_roles: vec!["role-a".into()],
            owned_schemas: vec!["public".into()],
            managed_database_identity: "ns/secret/key".into(),
            origin: None,
            scope: None,
        };

        let json = serde_json::to_value(&spec).expect("should serialize to JSON");
        let obj = json.as_object().expect("should be a JSON object");

        assert!(
            obj.contains_key("policyRef"),
            "should use camelCase: policyRef"
        );
        assert!(
            obj.contains_key("policyGeneration"),
            "should use camelCase: policyGeneration"
        );
        assert!(
            obj.contains_key("reconciliationMode"),
            "should use camelCase: reconciliationMode"
        );
        assert!(
            obj.contains_key("ownedRoles"),
            "should use camelCase: ownedRoles"
        );
        assert!(
            obj.contains_key("ownedSchemas"),
            "should use camelCase: ownedSchemas"
        );
        assert!(
            obj.contains_key("managedDatabaseIdentity"),
            "should use camelCase: managedDatabaseIdentity"
        );
    }

    fn resolved_bundle(memberships: Vec<ResolvedEphemeralMembership>) -> ResolvedEphemeralAccess {
        ResolvedEphemeralAccess {
            access_policy_uid: "access-uid".into(),
            access_policy_generation: 1,
            target_policy_uid: "target-uid".into(),
            target_policy_generation: 2,
            target_database_fingerprint: "sha256:database".into(),
            granted_duration: "1800s".into(),
            bundle_encoding: EPHEMERAL_BUNDLE_ENCODING_V1.into(),
            bundle_hash: String::new(),
            memberships,
        }
    }

    #[test]
    fn ephemeral_bundle_hash_is_order_independent_and_uid_independent() {
        let first = ResolvedEphemeralMembership {
            role: "editor".into(),
            member: "alice@example.com".into(),
            inherit: false,
        };
        let second = ResolvedEphemeralMembership {
            role: "auditor".into(),
            member: "alice@example.com".into(),
            inherit: true,
        };
        let original = resolved_bundle(vec![first.clone(), second.clone()]);
        let mut reordered = resolved_bundle(vec![second, first]);
        reordered.access_policy_uid = "replacement-uid".into();
        reordered.target_policy_generation = 99;

        assert_eq!(
            original.compute_bundle_hash(),
            reordered.compute_bundle_hash()
        );
    }

    #[test]
    fn ephemeral_bundle_hash_covers_membership_options() {
        let original = resolved_bundle(vec![ResolvedEphemeralMembership {
            role: "editor".into(),
            member: "alice@example.com".into(),
            inherit: false,
        }]);
        let changed = resolved_bundle(vec![ResolvedEphemeralMembership {
            role: "editor".into(),
            member: "alice@example.com".into(),
            inherit: true,
        }]);
        assert_ne!(
            original.compute_bundle_hash(),
            changed.compute_bundle_hash()
        );
    }

    #[test]
    fn ephemeral_bundle_hash_covers_database_target() {
        let original = resolved_bundle(Vec::new());
        let mut retargeted = original.clone();
        retargeted.target_database_fingerprint = "sha256:other-database".into();

        assert_ne!(
            original.compute_bundle_hash(),
            retargeted.compute_bundle_hash()
        );
    }

    #[test]
    fn ephemeral_request_crd_contains_immutability_rules() {
        let json = serde_json::to_string(&EphemeralAccessRequest::crd())
            .expect("request CRD should serialize");
        assert!(json.contains("request spec is immutable"));
        assert!(json.contains("resolvedAccess is write-once"));
        assert!(json.contains("approval decisions are terminal"));
        assert!(json.contains("decision identity is write-once"));
        assert!(json.contains(
            "a terminal approval decision and decidedBy identity must be recorded together"
        ));
        assert!(json.contains(r#""requestedBy""#));
        assert!(json.contains(r#""decidedBy""#));
        assert!(json.contains(r#""maxItems":8"#));
        assert!(json.contains(r#""pattern":"^([0-9]+[smh])+$""#));
    }

    fn assert_bounded_strings_and_collections(schema: &serde_json::Value, path: &str) {
        match schema {
            serde_json::Value::Object(object) => {
                match object.get("type").and_then(serde_json::Value::as_str) {
                    Some("string") if !object.contains_key("enum") => {
                        assert!(
                            object.contains_key("maxLength"),
                            "unbounded string schema at {path}"
                        );
                    }
                    Some("array") => {
                        assert!(
                            object.contains_key("maxItems"),
                            "unbounded collection schema at {path}"
                        );
                    }
                    _ => {}
                }
                for (name, child) in object {
                    assert_bounded_strings_and_collections(child, &format!("{path}.{name}"));
                }
            }
            serde_json::Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    assert_bounded_strings_and_collections(child, &format!("{path}[{index}]"));
                }
            }
            _ => {}
        }
    }

    #[test]
    fn ephemeral_crds_bound_every_string_and_collection() {
        for (kind, crd) in [
            ("EphemeralAccessPolicy", EphemeralAccessPolicy::crd()),
            ("EphemeralAccessRequest", EphemeralAccessRequest::crd()),
        ] {
            let value = serde_json::to_value(crd).expect("CRD should serialize");
            let schema = &value["spec"]["versions"][0]["schema"]["openAPIV3Schema"];
            assert_bounded_strings_and_collections(schema, kind);
        }
    }

    /// Every string, list and map reachable from `spec` must be bounded: the
    /// whole-spec `self == oldSelf` rule is only admissible to the API server
    /// if its static cost estimate is finite, and an unbounded collection
    /// makes that estimate unbounded. This is the local half of the ship gate
    /// in ADR-001 Decision 1 — the other half applies the CRD to a real
    /// apiserver in CI.
    #[test]
    fn candidate_spec_bounds_every_string_collection_and_map() {
        let value =
            serde_json::to_value(postgres_policy_candidate_crd()).expect("CRD should serialize");
        let spec = &value["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"];
        assert_bounded_strings_and_collections(spec, "PostgresPolicyCandidate.spec");
        assert_bounded_maps(spec, "PostgresPolicyCandidate.spec");
    }

    fn assert_bounded_maps(schema: &serde_json::Value, path: &str) {
        if let serde_json::Value::Object(object) = schema {
            if object.get("type").and_then(serde_json::Value::as_str) == Some("object")
                && object.contains_key("additionalProperties")
            {
                assert!(
                    object.contains_key("maxProperties"),
                    "unbounded map schema at {path}"
                );
            }
            for (name, child) in object {
                assert_bounded_maps(child, &format!("{path}.{name}"));
            }
        }
    }

    /// The golden test for ADR-001 Decision 2: no `default` key may occur
    /// anywhere under `spec.properties.content` in the generated CRD.
    ///
    /// A schema default is written into the stored object at admission time.
    /// If a default value ever changed, every already-stored candidate would
    /// keep the old value while the identical source YAML would now mean the
    /// new one — breaking `self == oldSelf` on byte-identical input, and
    /// detaching the stored object's content digest from the digest CI
    /// computed for the same content.
    #[test]
    fn candidate_content_emits_no_openapi_defaults() {
        let value =
            serde_json::to_value(postgres_policy_candidate_crd()).expect("CRD should serialize");
        let content = &value["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]
            ["properties"]["content"];
        assert!(content.is_object(), "spec.content should be in the schema");

        fn find_default(schema: &serde_json::Value, path: &str, found: &mut Vec<String>) {
            match schema {
                serde_json::Value::Object(object) => {
                    if object.contains_key("default") {
                        found.push(path.to_string());
                    }
                    for (name, child) in object {
                        find_default(child, &format!("{path}.{name}"), found);
                    }
                }
                serde_json::Value::Array(items) => {
                    for (index, child) in items.iter().enumerate() {
                        find_default(child, &format!("{path}[{index}]"), found);
                    }
                }
                _ => {}
            }
        }

        let mut found = Vec::new();
        find_default(content, "spec.content", &mut found);
        assert!(
            found.is_empty(),
            "spec.content must emit no OpenAPI defaults, found: {found:?}"
        );
    }

    /// Serde defaults must survive the schema stripping: the operator still
    /// resolves omitted content fields, it just does not let the API server do
    /// it. Stripping the *schema* cannot affect this — the assertion is here
    /// so that a future switch to some other suppression mechanism cannot
    /// quietly take deserialisation with it.
    #[test]
    fn candidate_content_keeps_serde_defaults() {
        let content: PolicyContent =
            serde_json::from_str("{}").expect("empty content should deserialize");
        assert_eq!(
            content.reconciliation_mode,
            CrdReconciliationMode::default()
        );
        assert!(content.roles.is_empty());
        assert!(content.grants.is_empty());
        assert!(content.profiles.is_empty());
    }

    /// The property the whole promotion gate rests on: promoting a candidate's
    /// content into a policy produces the *identical* digest, so recognition
    /// is exact rather than approximate. If this ever fails, promotion of a
    /// reviewed candidate silently degrades to the manual-plan flow and no
    /// approval is ever honoured.
    #[test]
    fn promoting_candidate_content_yields_the_candidates_digest() {
        let content: PolicyContent = serde_json::from_value(serde_json::json!({
            "reconciliation_mode": "additive",
            "default_owner": "app_owner",
            "profiles": { "reader": { "grants": [] } },
            "schemas": [{ "name": "app", "profiles": ["reader"] }],
            "roles": [{ "name": "reporting-reader", "login": true }],
            "grants": [{
                "role": "reporting-reader",
                "privileges": ["CONNECT"],
                "object": { "type": "database", "name": "orders" }
            }],
            "memberships": [{ "role": "reporting-reader", "members": [{ "name": "app_owner" }] }],
        }))
        .expect("content fixture");

        // The GitOps promotion: the same content, pasted into a policy spec
        // beside the execution fields, which the digest must ignore.
        let mut spec_json = serde_json::to_value(&content).expect("content serializes");
        let object = spec_json.as_object_mut().expect("content is an object");
        object.insert(
            "connection".to_string(),
            serde_json::json!({ "secretRef": { "name": "db" } }),
        );
        object.insert("interval".to_string(), serde_json::json!("30s"));
        object.insert("mode".to_string(), serde_json::json!("apply"));
        object.insert("approval".to_string(), serde_json::json!("manual"));
        object.insert("suspend".to_string(), serde_json::json!(false));
        let spec: PostgresPolicySpec =
            serde_json::from_value(spec_json).expect("promoted policy spec");

        assert_eq!(spec.content_digest(), content.content_digest());
        assert_eq!(
            spec.content_digest(),
            pgroles_core::candidate::compute_content_digest(&content),
        );

        // And the execution fields are genuinely outside the digest: changing
        // one must not move it, or every interval bump would break promotion.
        let mut other = spec.clone();
        other.interval = "1h".to_string();
        other.suspend = true;
        assert_eq!(other.content_digest(), spec.content_digest());

        // While a content edit must move it — that is the whole mechanism.
        let mut edited = spec.clone();
        edited.roles[0].login = Some(false);
        assert_ne!(edited.content_digest(), spec.content_digest());
    }

    /// Promotion copies `candidate.spec.content` into `policy.spec` verbatim,
    /// so the two schemas must describe the same fields with the same types.
    /// A field added to one and not the other turns promotion into a lossy
    /// conversion at the exact moment the content digest must be trusted.
    #[test]
    fn candidate_content_matches_policy_content() {
        let policy = serde_json::to_value(PostgresPolicy::crd()).expect("CRD should serialize");
        let policy_spec = &policy["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]
            ["spec"]["properties"];
        let candidate =
            serde_json::to_value(postgres_policy_candidate_crd()).expect("CRD should serialize");
        let content = &candidate["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]
            ["spec"]["properties"]["content"]["properties"];

        // Execution fields belong to the policy alone: a candidate carries no
        // connection (unless `spec.target` overrides it), interval, mode,
        // suspend or approval.
        let execution = ["connection", "interval", "mode", "suspend", "approval"];
        let policy_content: Vec<&String> = policy_spec
            .as_object()
            .expect("policy spec has properties")
            .keys()
            .filter(|k| !execution.contains(&k.as_str()))
            .collect();
        let mut candidate_content: Vec<&String> = content
            .as_object()
            .expect("candidate content has properties")
            .keys()
            .collect();
        candidate_content.sort();
        let mut policy_content = policy_content;
        policy_content.sort();
        assert_eq!(policy_content, candidate_content);

        for field in &candidate_content {
            let policy_field = &policy_spec[field.as_str()];
            let candidate_field = &content[field.as_str()];
            assert_eq!(
                policy_field["type"], candidate_field["type"],
                "spec.{field} and spec.content.{field} must have the same type"
            );
            assert_eq!(
                policy_field["items"]["properties"]
                    .as_object()
                    .map(|o| o.keys().collect::<Vec<_>>()),
                candidate_field["items"]["properties"]
                    .as_object()
                    .map(|o| o.keys().collect::<Vec<_>>()),
                "spec.{field} and spec.content.{field} must have the same item fields"
            );
        }
    }

    #[test]
    fn candidate_crd_exposes_operational_columns() {
        let crd = postgres_policy_candidate_crd();
        let columns: Vec<&str> = crd.spec.versions[0]
            .additional_printer_columns
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(columns, ["Policy", "Phase", "Plan", "Digest", "Age"]);
        assert_eq!(
            crd.spec.names.short_names.as_deref(),
            Some(["pgcand".to_string()].as_slice())
        );
        assert_eq!(
            crd.spec.names.categories.as_deref(),
            Some(["pgroles".to_string()].as_slice())
        );
        assert!(
            crd.spec.versions[0]
                .subresources
                .as_ref()
                .and_then(|s| s.status.as_ref())
                .is_some()
        );
    }

    #[test]
    fn ephemeral_policy_crd_exposes_operational_columns() {
        let json = serde_json::to_string(&EphemeralAccessPolicy::crd())
            .expect("policy CRD should serialize");
        assert!(json.contains("postgresPolicyRef"));
        assert!(json.contains("maximumDuration"));
        assert!(json.contains("Accepted"));
        assert!(json.contains(r#""minItems":1"#));
        assert!(json.contains(r#""pattern":"^([0-9]+[smh])+$""#));
    }
}
