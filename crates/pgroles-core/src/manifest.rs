use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::bounds::*;
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("duplicate role name: \"{0}\"")]
    DuplicateRole(String),

    #[error("duplicate schema name: \"{0}\"")]
    DuplicateSchema(String),

    #[error("profile \"{0}\" referenced by schema \"{1}\" is not defined")]
    UndefinedProfile(String, String),

    #[error("role_pattern must contain {{profile}} placeholder, got: \"{0}\"")]
    InvalidRolePattern(String),

    #[error("top-level default privilege for {scope} must specify grant.role")]
    MissingDefaultPrivilegeRole { scope: String },

    #[error("duplicate retirement entry for role: \"{0}\"")]
    DuplicateRetirement(String),

    #[error("retirement entry for role \"{0}\" conflicts with a desired role of the same name")]
    RetirementRoleStillDesired(String),

    #[error("retirement entry for role \"{role}\" cannot reassign ownership to itself")]
    RetirementSelfReassign { role: String },

    #[error(
        "role \"{role}\" has a password but login is not enabled — password will have no effect"
    )]
    PasswordWithoutLogin { role: String },

    #[error(
        "role \"{role}\" has an invalid password_valid_until value \"{value}\": expected ISO 8601 timestamp (e.g. \"2025-12-31T00:00:00Z\")"
    )]
    InvalidValidUntil { role: String, value: String },

    #[error(
        "role \"{role}\" has an invalid config parameter name \"{parameter}\": expected a PostgreSQL setting name (letters, digits, underscores, optionally dot-qualified)"
    )]
    InvalidConfigParameter { role: String, parameter: String },

    #[error(
        "role \"{role}\" sets config `role: {target}` but declares no membership in \"{target}\" — the setting would fail at login; add \"{role}\" to the members of \"{target}\""
    )]
    SetRoleWithoutMembership { role: String, target: String },

    #[error("{collection} has {actual} entries, which exceeds the limit of {limit}")]
    TooManyEntries {
        collection: String,
        actual: usize,
        limit: u32,
    },

    #[error("{context} \"{value}\" is {actual} characters, which exceeds the limit of {limit}")]
    ValueTooLong {
        context: String,
        value: String,
        actual: usize,
        limit: u32,
    },

    #[error(
        "\"PUBLIC\" is reserved for the PostgreSQL PUBLIC pseudo-role and cannot be used as {context}"
    )]
    ReservedPublicName { context: String },

    // The conflict variants describe their assertion in one preformatted
    // `target` string. Keeping each field count low matters: `ManifestError`
    // travels inside `CompositionError`, whose size clippy polices.
    #[error("grant {target} declares privilege {privilege} as both present and absent")]
    ConflictingGrantEnsure { target: String, privilege: String },

    #[error(
        "grants {target} declare privilege {privilege} as present for one object selector and absent for another — grants apply before revokes, so the plan could never converge"
    )]
    ConflictingWildcardEnsure { target: String, privilege: String },

    #[error("default privileges {target} declare privilege {privilege} as both present and absent")]
    ConflictingDefaultPrivilegeEnsure { target: String, privilege: String },

    #[error(
        "default privilege entry for owner \"{owner}\" sets both `schema` and `scope` — use exactly one"
    )]
    DefaultPrivilegeScopeConflict { owner: String },

    #[error("default privilege entry for owner \"{owner}\" needs either `schema` or `scope`")]
    DefaultPrivilegeScopeMissing { owner: String },

    #[error("default privilege scope of type `schema` needs a `schema` name")]
    DefaultPrivilegeScopeSchemaMissing,

    #[error("default privilege scope of type `global` must not name a schema (got \"{schema}\")")]
    DefaultPrivilegeScopeSchemaForbidden { schema: String },

    // `scope` renders its own noun, so the template must not add one.
    #[error("default privileges cannot target on_type `{on_type}` in {scope}")]
    InvalidDefaultPrivilegeOnType { on_type: String, scope: String },

    #[error(
        "profile \"{profile}\" declares an `ensure: absent` default privilege — profiles are additive templates and cannot assert absence"
    )]
    ProfileAbsentDefaultPrivilege { profile: String },

    #[error(
        "profile \"{profile}\" declares an `ensure: absent` grant — profiles are additive templates and cannot assert absence"
    )]
    ProfileAbsentGrant { profile: String },

    #[error("database grant targets must name the connected database explicitly")]
    DatabaseGrantMissingName,
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// PostgreSQL object types that can have privileges granted on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObjectType {
    Table,
    View,
    #[serde(alias = "materialized_view")]
    MaterializedView,
    Sequence,
    Function,
    Schema,
    Database,
    Type,
}

impl std::fmt::Display for ObjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectType::Table => write!(f, "table"),
            ObjectType::View => write!(f, "view"),
            ObjectType::MaterializedView => write!(f, "materialized_view"),
            ObjectType::Sequence => write!(f, "sequence"),
            ObjectType::Function => write!(f, "function"),
            ObjectType::Schema => write!(f, "schema"),
            ObjectType::Database => write!(f, "database"),
            ObjectType::Type => write!(f, "type"),
        }
    }
}

/// PostgreSQL privilege types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "UPPERCASE")]
pub enum Privilege {
    Select,
    Insert,
    Update,
    Delete,
    Truncate,
    References,
    Trigger,
    Execute,
    Usage,
    Create,
    Connect,
    Temporary,
}

impl std::fmt::Display for Privilege {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Privilege::Select => write!(f, "SELECT"),
            Privilege::Insert => write!(f, "INSERT"),
            Privilege::Update => write!(f, "UPDATE"),
            Privilege::Delete => write!(f, "DELETE"),
            Privilege::Truncate => write!(f, "TRUNCATE"),
            Privilege::References => write!(f, "REFERENCES"),
            Privilege::Trigger => write!(f, "TRIGGER"),
            Privilege::Execute => write!(f, "EXECUTE"),
            Privilege::Usage => write!(f, "USAGE"),
            Privilege::Create => write!(f, "CREATE"),
            Privilege::Connect => write!(f, "CONNECT"),
            Privilege::Temporary => write!(f, "TEMPORARY"),
        }
    }
}

/// Whether the listed privileges must exist or must not exist.
///
/// `absent` asserts one ACL edge only. It plans a REVOKE when the privilege is
/// found live, and it says nothing about access the grantee may still have
/// through role membership or ownership.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Ensure {
    #[default]
    Present,
    Absent,
}

impl Ensure {
    pub fn is_present(&self) -> bool {
        matches!(self, Ensure::Present)
    }
}

// ---------------------------------------------------------------------------
// YAML manifest types
// ---------------------------------------------------------------------------

/// Top-level policy manifest — the YAML file that users write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyManifest {
    /// Default owner for ALTER DEFAULT PRIVILEGES (e.g. "app_owner").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_owner: Option<String>,

    /// Cloud auth provider configurations for IAM-mapped role awareness.
    #[serde(default)]
    pub auth_providers: Vec<AuthProvider>,

    /// Reusable privilege profiles. Stored as a `BTreeMap` so YAML
    /// serialization is deterministic — two `pgroles generate` runs against
    /// the same database produce byte-identical output.
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,

    /// Schema bindings that expand profiles into concrete roles/grants.
    #[serde(default)]
    pub schemas: Vec<SchemaBinding>,

    /// One-off role definitions (not from profiles).
    #[serde(default)]
    pub roles: Vec<RoleDefinition>,

    /// One-off grants (not from profiles).
    #[serde(default)]
    pub grants: Vec<Grant>,

    /// One-off default privileges (not from profiles).
    #[serde(default)]
    pub default_privileges: Vec<DefaultPrivilege>,

    /// Membership edges (opt-in).
    #[serde(default)]
    pub memberships: Vec<Membership>,

    /// Explicit role-retirement workflows for roles that should be removed.
    #[serde(default)]
    pub retirements: Vec<RoleRetirement>,
}

/// Cloud authentication provider configuration.
///
/// Declares awareness of cloud IAM-mapped roles so pgroles can correctly
/// reference auto-created role names in grants and memberships.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthProvider {
    /// Google Cloud SQL IAM authentication.
    /// Service accounts map to PG roles like `user@project.iam`.
    CloudSqlIam {
        /// GCP project ID (for documentation/validation).
        #[serde(default)]
        project: Option<String>,
    },
    /// Google AlloyDB IAM authentication.
    /// IAM users and groups map to PostgreSQL roles managed by AlloyDB.
    #[serde(rename = "alloydb_iam")]
    AlloyDbIam {
        /// GCP project ID (for documentation/validation).
        #[serde(default)]
        project: Option<String>,
        /// AlloyDB cluster name (for documentation/validation).
        #[serde(default)]
        cluster: Option<String>,
    },
    /// AWS RDS IAM authentication.
    /// IAM users authenticate via token; the PG role must have `rds_iam` granted.
    RdsIam {
        /// AWS region (for documentation/validation).
        #[serde(default)]
        region: Option<String>,
    },
    /// Azure Entra ID (AAD) authentication for Azure Database for PostgreSQL.
    AzureAd {
        /// Azure tenant ID (for documentation/validation).
        #[serde(default)]
        tenant_id: Option<String>,
    },
    /// Supabase-managed PostgreSQL authentication.
    Supabase {
        /// Supabase project ref (for documentation/validation).
        #[serde(default)]
        project_ref: Option<String>,
    },
    /// PlanetScale PostgreSQL authentication metadata.
    PlanetScale {
        /// PlanetScale organization (for documentation/validation).
        #[serde(default)]
        organization: Option<String>,
    },
}

/// A reusable privilege profile — defines what grants a role should have.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default)]
    pub login: Option<bool>,

    #[serde(default)]
    pub inherit: Option<bool>,

    #[serde(default)]
    pub grants: Vec<ProfileGrant>,

    #[serde(default)]
    pub default_privileges: Vec<DefaultPrivilegeGrant>,

    /// Role-level configuration parameter defaults for generated roles,
    /// applied via `ALTER ROLE ... SET parameter = value`. Values support the
    /// `{schema}` and `{profile}` placeholders (the same two `role_pattern`
    /// supports), substituted per `schema x profile` expansion — e.g.
    /// `search_path: "{schema}"` becomes `search_path: inventory` on the role
    /// generated for the `inventory` schema. Keys are literal PostgreSQL
    /// parameter names; placeholders are not substituted in keys (a `{schema}`
    /// key is rejected by [`is_valid_config_parameter_name`], same as any
    /// other invalid parameter name). Values are always strings — see
    /// [`ConfigValue`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, ConfigValue>,
}

/// A grant template within a profile (schema is filled in during expansion).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileGrant {
    pub privileges: Vec<Privilege>,
    #[serde(alias = "on")]
    pub object: ProfileObjectTarget,
    /// Whether the privilege must be present or absent. Expansion rejects
    /// `absent`, because a profile is an additive template. The field exists
    /// so that rejection can name the offending profile, instead of the value
    /// being dropped as an unknown key and the grant expanding to its
    /// opposite.
    #[serde(default, skip_serializing_if = "Ensure::is_present")]
    pub ensure: Ensure,
}

/// Object target within a profile — schema is omitted (filled during expansion).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileObjectTarget {
    #[serde(rename = "type")]
    pub object_type: ObjectType,
    /// Object name, or "*" for all objects of this type. Omit for schema-level grants.
    #[serde(default)]
    pub name: Option<String>,
}

/// A schema binding — associates a schema with one or more profiles.
///
/// Field bounds come from [`crate::bounds`]; see that module for why they
/// exist and where else they are enforced.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SchemaBinding {
    #[schemars(length(min = 1, max = MAX_IDENTIFIER))]
    pub name: String,

    #[serde(default)]
    #[schemars(length(max = MAX_SCHEMA_PROFILES), inner(length(min = 1, max = MAX_IDENTIFIER)))]
    pub profiles: Vec<String>,

    /// Role naming pattern. Supports `{schema}` and `{profile}` placeholders.
    /// Defaults to `"{schema}-{profile}"`.
    #[serde(default = "default_role_pattern")]
    #[schemars(length(min = 1, max = MAX_ROLE_PATTERN))]
    pub role_pattern: String,

    /// Override default_owner for this schema's default privileges.
    #[serde(default)]
    #[schemars(length(min = 1, max = MAX_IDENTIFIER))]
    pub owner: Option<String>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SchemaBindingFacet {
    Owner,
    Bindings,
}

impl std::fmt::Display for SchemaBindingFacet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaBindingFacet::Owner => write!(f, "owner"),
            SchemaBindingFacet::Bindings => write!(f, "bindings"),
        }
    }
}

pub(crate) fn default_role_pattern() -> String {
    "{schema}-{profile}".to_string()
}

/// Substitute the `{schema}` and `{profile}` placeholders in a profile
/// `config` value — the same two placeholders `role_pattern` supports.
/// Values without either placeholder are returned unchanged.
fn substitute_placeholders(value: &str, schema: &str, profile: &str) -> String {
    value
        .replace("{schema}", schema)
        .replace("{profile}", profile)
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// A concrete role definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDefinition {
    pub name: String,

    /// Treat this role as managed by another system. pgroles may reference it
    /// in grants, ownership, and memberships, but will not create, alter, drop,
    /// password-manage, or manage memberships granted from this role.
    #[serde(default, skip_serializing_if = "is_false")]
    pub external: bool,

    /// Preserve this role's undeclared in-scope object grants during
    /// convergence. Revokes against the role are skipped unless the revoked
    /// privileges are explicitly asserted absent (`ensure: absent`), so a
    /// brownfield role can be brought under pgroles management before its
    /// full grant surface is declared. Declared grants still converge and
    /// owner-inherent privileges are unaffected.
    #[serde(default, skip_serializing_if = "is_false")]
    pub preserve_undeclared_grants: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superuser: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub createdb: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub createrole: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherit: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replication: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bypassrls: Option<bool>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_limit: Option<i32>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// Password source for this role. Passwords are never stored in the manifest
    /// directly — only a reference to an environment variable is allowed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<PasswordSource>,

    /// Password expiration timestamp (ISO 8601, e.g. "2025-12-31T00:00:00Z").
    /// Maps to PostgreSQL's `VALID UNTIL` clause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_valid_until: Option<String>,

    /// Role-level configuration parameter defaults, applied via
    /// `ALTER ROLE ... SET parameter = value`. Keys are PostgreSQL setting
    /// names (e.g. `role`, `search_path`, `statement_timeout`); values are
    /// applied as string literals. Settings present on the role in the
    /// database but absent here are `RESET` in authoritative mode.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, ConfigValue>,
}

/// A role configuration parameter value.
///
/// Values are always strings — quote numbers and booleans (e.g.
/// `statement_timeout: "30000"`, `jit: "off"`). The Kubernetes CRD schema
/// types config values as strings, and the CLI enforces the same rule so a
/// manifest means the same thing whether it is applied with `pgroles` or
/// `kubectl`. PostgreSQL coerces the string to the parameter's type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct ConfigValue(#[schemars(length(max = MAX_CONFIG_VALUE))] pub String);

impl<'de> Deserialize<'de> for ConfigValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ConfigValueVisitor;

        impl serde::de::Visitor<'_> for ConfigValueVisitor {
            type Value = ConfigValue;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(ConfigValue(v.to_string()))
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(ConfigValue(v))
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Err(E::custom(format!(
                    "config values must be quoted strings: write \"{v}\" instead of {v}"
                )))
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Err(E::custom(format!(
                    "config values must be quoted strings: write \"{v}\" instead of {v}"
                )))
            }

            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                Err(E::custom(format!(
                    "config values must be quoted strings: write \"{v}\" instead of {v}"
                )))
            }

            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                let suggestion = if v { "on" } else { "off" };
                Err(E::custom(format!(
                    "config values must be quoted strings: write \"{suggestion}\" (or \"{v}\") instead of {v}"
                )))
            }
        }

        deserializer.deserialize_any(ConfigValueVisitor)
    }
}

/// Validate a PostgreSQL configuration parameter name: one or more
/// letter/underscore-led identifier segments separated by dots (custom GUCs
/// like `app.tenant` are dot-qualified).
pub fn is_valid_config_parameter_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('.').all(|segment| {
            let mut chars = segment.chars();
            matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

/// Source for a role password. Passwords are never stored in YAML manifests.
///
/// This follows the same security model as `DATABASE_URL` — secrets come from
/// the runtime environment, not from configuration files.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PasswordSource {
    /// Name of the environment variable containing the password.
    pub from_env: String,
}

/// A concrete grant on a specific object or wildcard.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Grant {
    /// The grantee. The exact-uppercase value `PUBLIC` means the PostgreSQL
    /// PUBLIC pseudo-role; any other value is an ordinary role name.
    #[schemars(length(min = 1, max = MAX_IDENTIFIER))]
    pub role: String,
    #[schemars(length(min = 1, max = MAX_PRIVILEGES))]
    pub privileges: Vec<Privilege>,
    #[serde(alias = "on")]
    pub object: ObjectTarget,
    #[serde(default, skip_serializing_if = "Ensure::is_present")]
    pub ensure: Ensure,
}

/// Target object for a grant.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(extend("x-kubernetes-validations" = [serde_json::json!({
    "rule": "self.type != 'database' || has(self.name)",
    "message": "database grant targets must set `name`"
})]))]
pub struct ObjectTarget {
    #[serde(rename = "type")]
    pub object_type: ObjectType,

    /// Schema name. Required for most object types except database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = MAX_IDENTIFIER))]
    pub schema: Option<String>,

    /// Object name, or "*" for all objects. Omit for schema-level grants;
    /// required for database grants, where it names the connected database.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = MAX_OBJECT_NAME))]
    pub name: Option<String>,
}

/// Default privilege configuration.
///
/// The scope rules are also expressed as CEL so the API server rejects a bad
/// entry at apply time. `resolved_scope` enforces the same rules for the CLI,
/// which has no admission step.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(extend("x-kubernetes-validations" = [serde_json::json!({
    "rule": "has(self.schema) != has(self.scope)",
    "message": "exactly one of `schema` and `scope` must be set"
})]))]
pub struct DefaultPrivilege {
    /// The role that owns newly created objects. If omitted, uses manifest's default_owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = MAX_IDENTIFIER))]
    pub owner: Option<String>,

    /// Schema shorthand, equivalent to `scope: {type: schema, schema: ...}`.
    /// Exactly one of `schema` and `scope` must be set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = MAX_IDENTIFIER))]
    pub schema: Option<String>,

    /// Where the defaults apply: one schema, or owner-wide (global). Global
    /// scope renders `ALTER DEFAULT PRIVILEGES` without an `IN SCHEMA` clause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<DefaultPrivilegeScopeSpec>,

    #[schemars(length(max = MAX_DEFAULT_PRIVILEGE_GRANTS))]
    pub grant: Vec<DefaultPrivilegeGrant>,
}

/// Scope selector for a default-privileges entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(extend("x-kubernetes-validations" = [serde_json::json!({
    "rule": "has(self.schema) == (self.type == 'schema')",
    "message": "`schema` is required when type is `schema` and forbidden when type is `global`"
})]))]
pub struct DefaultPrivilegeScopeSpec {
    #[serde(rename = "type")]
    pub scope_type: DefaultPrivilegeScopeType,

    /// Schema name. Required for `type: schema`, forbidden for `type: global`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = MAX_IDENTIFIER))]
    pub schema: Option<String>,
}

/// The kind of default-privilege scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPrivilegeScopeType {
    Global,
    Schema,
}

impl DefaultPrivilege {
    /// Resolve the `schema` shorthand and the `scope` field into one scope.
    pub fn resolved_scope(&self) -> Result<crate::model::DefaultPrivilegeScope, ManifestError> {
        use crate::model::DefaultPrivilegeScope;

        let owner_context = || {
            self.owner
                .clone()
                .unwrap_or_else(|| "(default owner)".to_string())
        };

        match (&self.schema, &self.scope) {
            (Some(_), Some(_)) => Err(ManifestError::DefaultPrivilegeScopeConflict {
                owner: owner_context(),
            }),
            (None, None) => Err(ManifestError::DefaultPrivilegeScopeMissing {
                owner: owner_context(),
            }),
            (Some(schema), None) => Ok(DefaultPrivilegeScope::Schema {
                schema: schema.clone(),
            }),
            (None, Some(spec)) => match (spec.scope_type, &spec.schema) {
                (DefaultPrivilegeScopeType::Global, None) => Ok(DefaultPrivilegeScope::Global),
                (DefaultPrivilegeScopeType::Global, Some(schema)) => {
                    Err(ManifestError::DefaultPrivilegeScopeSchemaForbidden {
                        schema: schema.clone(),
                    })
                }
                (DefaultPrivilegeScopeType::Schema, Some(schema)) => {
                    Ok(DefaultPrivilegeScope::Schema {
                        schema: schema.clone(),
                    })
                }
                (DefaultPrivilegeScopeType::Schema, None) => {
                    Err(ManifestError::DefaultPrivilegeScopeSchemaMissing)
                }
            },
        }
    }
}

/// A single default privilege grant entry.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DefaultPrivilegeGrant {
    /// The role receiving the default privilege. Only used in top-level default_privileges
    /// (in profiles, the role is determined by expansion). The exact-uppercase
    /// value `PUBLIC` means the PostgreSQL PUBLIC pseudo-role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = MAX_IDENTIFIER))]
    pub role: Option<String>,

    #[schemars(length(min = 1, max = MAX_PRIVILEGES))]
    pub privileges: Vec<Privilege>,
    pub on_type: ObjectType,

    #[serde(default, skip_serializing_if = "Ensure::is_present")]
    pub ensure: Ensure,
}

/// A membership declaration — which members belong to a role.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Membership {
    #[schemars(length(min = 1, max = MAX_IDENTIFIER))]
    pub role: String,
    #[schemars(length(max = MAX_MEMBERS))]
    pub members: Vec<MemberSpec>,
}

/// A single member of a role.
///
/// Both `inherit` and `admin` are optional. When omitted, they default to
/// `inherit: true` and `admin: false` at resolution time (in `RoleGraph`
/// construction). Keeping them optional in the CRD avoids Kubernetes
/// injecting default values into the stored resource, which causes
/// perpetual diffs in GitOps tools like ArgoCD.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemberSpec {
    #[schemars(length(min = 1, max = MAX_IDENTIFIER))]
    pub name: String,

    /// Whether the member inherits the role's privileges. Defaults to `true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherit: Option<bool>,

    /// Whether the member can administer the role. Defaults to `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<bool>,
}

impl MemberSpec {
    /// Resolve `inherit` with its default (true).
    pub fn inherit(&self) -> bool {
        self.inherit.unwrap_or(true)
    }

    /// Resolve `admin` with its default (false).
    pub fn admin(&self) -> bool {
        self.admin.unwrap_or(false)
    }
}

/// Declarative workflow for retiring an existing role.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RoleRetirement {
    /// The role to retire and ultimately drop.
    #[schemars(length(min = 1, max = MAX_IDENTIFIER))]
    pub role: String,

    /// Optional successor role for `REASSIGN OWNED BY ... TO ...`.
    #[serde(default)]
    #[schemars(length(min = 1, max = MAX_IDENTIFIER))]
    pub reassign_owned_to: Option<String>,

    /// Whether to run `DROP OWNED BY` before dropping the role.
    #[serde(default)]
    pub drop_owned: bool,

    /// Whether to terminate other active sessions for the role before drop.
    #[serde(default)]
    pub terminate_sessions: bool,
}

// ---------------------------------------------------------------------------
// Content bounds
// ---------------------------------------------------------------------------

/// Reject content that exceeds the bounds in [`crate::bounds`].
///
/// The CRD schemas carry these same limits as `maxLength` / `maxItems` /
/// `maxProperties`, so a manifest the API server would refuse must be refused
/// here too: a user who validates with the CLI and applies with `kubectl`
/// should never learn about a limit from the second command.
///
/// Lengths are counted in characters, matching OpenAPI `maxLength` (and
/// therefore the API server) — except that identifier-bounded values are
/// additionally held to PostgreSQL's byte-counted `NAMEDATALEN - 1 = 63`,
/// which the schema cannot express: a 63-character multibyte name would pass
/// admission and then be silently truncated by the server. Expanded role
/// names (`role_pattern` output) get the same byte check at expansion time.
///
/// One bound has no schema counterpart and is enforced only here: `config`
/// keys are held to [`MAX_IDENTIFIER`], because Kubernetes structural schemas
/// have no way to express `propertyNames`.
pub fn validate_bounds(manifest: &PolicyManifest) -> Result<(), ManifestError> {
    fn entries(collection: &str, actual: usize, limit: u32) -> Result<(), ManifestError> {
        if actual > limit as usize {
            return Err(ManifestError::TooManyEntries {
                collection: collection.to_string(),
                actual,
                limit,
            });
        }
        Ok(())
    }

    fn text(context: &str, value: &str, limit: u32) -> Result<(), ManifestError> {
        let actual = value.chars().count();
        if actual > limit as usize {
            return Err(ManifestError::ValueTooLong {
                context: context.to_string(),
                value: value.to_string(),
                actual,
                limit,
            });
        }
        // PostgreSQL's NAMEDATALEN limit is 63 *bytes*, not characters: a
        // 63-character multibyte identifier passes the schema (OpenAPI
        // `maxLength` counts characters) but the server silently truncates it,
        // which is precisely the surprise these bounds exist to prevent. For
        // identifier-bounded values, enforce the byte form too.
        if limit == MAX_IDENTIFIER && value.len() > limit as usize {
            return Err(ManifestError::ValueTooLong {
                context: format!(
                    "{context} (bytes; PostgreSQL identifiers are limited to 63 bytes)"
                ),
                value: value.to_string(),
                actual: value.len(),
                limit,
            });
        }
        Ok(())
    }

    fn config(context: &str, config: &BTreeMap<String, ConfigValue>) -> Result<(), ManifestError> {
        entries(
            &format!("{context}.config"),
            config.len(),
            MAX_CONFIG_ENTRIES,
        )?;
        for (key, value) in config {
            text(&format!("{context}.config key"), key, MAX_IDENTIFIER)?;
            text(
                &format!("{context}.config[{key}]"),
                &value.0,
                MAX_CONFIG_VALUE,
            )?;
        }
        Ok(())
    }

    entries("profiles", manifest.profiles.len(), MAX_PROFILES)?;
    for (name, profile) in &manifest.profiles {
        text("profile name", name, MAX_IDENTIFIER)?;
        entries(
            &format!("profiles.{name}.grants"),
            profile.grants.len(),
            MAX_PROFILE_GRANTS,
        )?;
        for grant in &profile.grants {
            entries(
                &format!("profiles.{name}.grants[].privileges"),
                grant.privileges.len(),
                MAX_PRIVILEGES,
            )?;
            if let Some(object_name) = &grant.object.name {
                text("grant object name", object_name, MAX_OBJECT_NAME)?;
            }
        }
        entries(
            &format!("profiles.{name}.default_privileges"),
            profile.default_privileges.len(),
            MAX_PROFILE_DEFAULT_PRIVILEGES,
        )?;
        for grant in &profile.default_privileges {
            entries(
                &format!("profiles.{name}.default_privileges[].privileges"),
                grant.privileges.len(),
                MAX_PRIVILEGES,
            )?;
            if let Some(role) = &grant.role {
                text("default privilege role", role, MAX_IDENTIFIER)?;
            }
        }
        config(&format!("profiles.{name}"), &profile.config)?;
    }

    entries("schemas", manifest.schemas.len(), MAX_SCHEMAS)?;
    for binding in &manifest.schemas {
        text("schema name", &binding.name, MAX_IDENTIFIER)?;
        entries(
            &format!("schemas.{}.profiles", binding.name),
            binding.profiles.len(),
            MAX_SCHEMA_PROFILES,
        )?;
        for profile in &binding.profiles {
            text("profile reference", profile, MAX_IDENTIFIER)?;
        }
        text("role_pattern", &binding.role_pattern, MAX_ROLE_PATTERN)?;
        if let Some(owner) = &binding.owner {
            text("schema owner", owner, MAX_IDENTIFIER)?;
        }
    }

    if let Some(owner) = &manifest.default_owner {
        text("default_owner", owner, MAX_IDENTIFIER)?;
    }

    entries("roles", manifest.roles.len(), MAX_ROLES)?;
    for role in &manifest.roles {
        text("role name", &role.name, MAX_IDENTIFIER)?;
        if let Some(comment) = &role.comment {
            text(
                &format!("roles.{}.comment", role.name),
                comment,
                MAX_OBJECT_NAME,
            )?;
        }
        if let Some(valid_until) = &role.password_valid_until {
            text(
                &format!("roles.{}.password_valid_until", role.name),
                valid_until,
                MAX_TIMESTAMP,
            )?;
        }
        config(&format!("roles.{}", role.name), &role.config)?;
    }

    entries("grants", manifest.grants.len(), MAX_GRANTS)?;
    for grant in &manifest.grants {
        text("grant role", &grant.role, MAX_IDENTIFIER)?;
        entries(
            "grants[].privileges",
            grant.privileges.len(),
            MAX_PRIVILEGES,
        )?;
        if let Some(schema) = &grant.object.schema {
            text("grant object schema", schema, MAX_IDENTIFIER)?;
        }
        if let Some(name) = &grant.object.name {
            text("grant object name", name, MAX_OBJECT_NAME)?;
        }
    }

    entries(
        "default_privileges",
        manifest.default_privileges.len(),
        MAX_DEFAULT_PRIVILEGES,
    )?;
    for default_privilege in &manifest.default_privileges {
        if let Some(schema) = &default_privilege.schema {
            text("default privilege schema", schema, MAX_IDENTIFIER)?;
        }
        if let Some(schema) = default_privilege
            .scope
            .as_ref()
            .and_then(|s| s.schema.as_ref())
        {
            text("default privilege scope schema", schema, MAX_IDENTIFIER)?;
        }
        if let Some(owner) = &default_privilege.owner {
            text("default privilege owner", owner, MAX_IDENTIFIER)?;
        }
        entries(
            "default_privileges[].grant",
            default_privilege.grant.len(),
            MAX_DEFAULT_PRIVILEGE_GRANTS,
        )?;
        for grant in &default_privilege.grant {
            entries(
                "default_privileges[].grant[].privileges",
                grant.privileges.len(),
                MAX_PRIVILEGES,
            )?;
            if let Some(role) = &grant.role {
                text("default privilege role", role, MAX_IDENTIFIER)?;
            }
        }
    }

    entries("memberships", manifest.memberships.len(), MAX_MEMBERSHIPS)?;
    for membership in &manifest.memberships {
        text("membership role", &membership.role, MAX_IDENTIFIER)?;
        entries(
            &format!("memberships.{}.members", membership.role),
            membership.members.len(),
            MAX_MEMBERS,
        )?;
        for member in &membership.members {
            text("member name", &member.name, MAX_IDENTIFIER)?;
        }
    }

    entries("retirements", manifest.retirements.len(), MAX_RETIREMENTS)?;
    for retirement in &manifest.retirements {
        text("retirement role", &retirement.role, MAX_IDENTIFIER)?;
        if let Some(successor) = &retirement.reassign_owned_to {
            text("reassign_owned_to", successor, MAX_IDENTIFIER)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Expanded manifest — the result of profile expansion
// ---------------------------------------------------------------------------

/// The fully expanded policy — all profiles resolved into concrete roles, grants,
/// default privileges, and memberships. Ready to be converted into a `RoleGraph`.
#[derive(Debug, Clone)]
pub struct ExpandedManifest {
    pub schemas: Vec<ExpandedSchema>,
    pub roles: Vec<RoleDefinition>,
    pub grants: Vec<Grant>,
    pub default_privileges: Vec<DefaultPrivilege>,
    pub memberships: Vec<Membership>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpandedSchema {
    pub name: String,
    pub owner: Option<String>,
}

// ---------------------------------------------------------------------------
// Expansion logic
// ---------------------------------------------------------------------------

/// Parse a YAML string into a `PolicyManifest`.
///
/// Accepts both bare manifests and Kubernetes CustomResource wrappers.
/// If the YAML contains an `apiVersion` and `spec` field, the `spec` is
/// extracted and parsed as a `PolicyManifest`.
pub fn parse_manifest(yaml: &str) -> Result<PolicyManifest, ManifestError> {
    // Check if this looks like a Kubernetes CR wrapper.
    let value: serde_yaml::Value = serde_yaml::from_str(yaml)?;
    if let serde_yaml::Value::Mapping(ref map) = value {
        let api_version_key = serde_yaml::Value::String("apiVersion".into());
        let spec_key = serde_yaml::Value::String("spec".into());
        if map.contains_key(&api_version_key) && map.contains_key(&spec_key) {
            let spec = map.get(&spec_key).ok_or_else(|| {
                ManifestError::Yaml(serde::de::Error::custom("missing spec in CR"))
            })?;
            let manifest: PolicyManifest = serde_yaml::from_value(spec.clone())?;
            return Ok(manifest);
        }
    }
    let manifest: PolicyManifest = serde_yaml::from_value(value)?;
    Ok(manifest)
}

/// Expand a `PolicyManifest` by resolving all `profiles × schemas` into concrete
/// roles, grants, and default privileges. Merges with one-off definitions.
/// Validates no duplicate role names.
pub fn expand_manifest(manifest: &PolicyManifest) -> Result<ExpandedManifest, ManifestError> {
    validate_bounds(manifest)?;

    let mut seen_schemas: HashSet<String> = HashSet::new();
    for schema_binding in &manifest.schemas {
        if !seen_schemas.insert(schema_binding.name.clone()) {
            return Err(ManifestError::DuplicateSchema(schema_binding.name.clone()));
        }
    }

    let schemas: Vec<ExpandedSchema> = manifest
        .schemas
        .iter()
        .map(|schema_binding| ExpandedSchema {
            name: schema_binding.name.clone(),
            owner: schema_binding
                .owner
                .clone()
                .or(manifest.default_owner.clone()),
        })
        .collect();
    let mut roles: Vec<RoleDefinition> = Vec::new();
    let mut grants: Vec<Grant> = Vec::new();
    let mut default_privileges: Vec<DefaultPrivilege> = Vec::new();

    // Expand each schema × profile combination
    for schema_binding in &manifest.schemas {
        for profile_name in &schema_binding.profiles {
            let profile = manifest.profiles.get(profile_name).ok_or_else(|| {
                ManifestError::UndefinedProfile(profile_name.clone(), schema_binding.name.clone())
            })?;

            // Validate pattern contains {profile}
            if !schema_binding.role_pattern.contains("{profile}") {
                return Err(ManifestError::InvalidRolePattern(
                    schema_binding.role_pattern.clone(),
                ));
            }

            // Generate role name from pattern
            let role_name = schema_binding
                .role_pattern
                .replace("{schema}", &schema_binding.name)
                .replace("{profile}", profile_name);

            // The inputs are bounded, but their *composition* is only checked
            // here: a pattern, schema and profile that each fit can expand to
            // a name PostgreSQL would silently truncate at 63 bytes — and a
            // truncated name is a different role than the one reviewed.
            if role_name.len() > 63 {
                return Err(ManifestError::ValueTooLong {
                    context: format!(
                        "role name expanded from role_pattern \"{}\" for schema \"{}\" (bytes; \
                         PostgreSQL identifiers are limited to 63 bytes)",
                        schema_binding.role_pattern, schema_binding.name
                    ),
                    value: role_name.clone(),
                    actual: role_name.len(),
                    limit: 63,
                });
            }

            // Expand profile config — substitute {schema}/{profile} in VALUES
            // only. Keys are literal PostgreSQL parameter names; a `{schema}`
            // or `{profile}` key is not a valid identifier and is rejected by
            // the parameter-name validation below, which is the desired
            // outcome (placeholders only make sense in values).
            let config: BTreeMap<String, ConfigValue> = profile
                .config
                .iter()
                .map(|(parameter, value)| {
                    let substituted =
                        substitute_placeholders(&value.0, &schema_binding.name, profile_name);
                    (parameter.clone(), ConfigValue(substituted))
                })
                .collect();

            // Create role definition
            roles.push(RoleDefinition {
                name: role_name.clone(),
                external: false,
                preserve_undeclared_grants: false,
                login: profile.login,
                superuser: None,
                createdb: None,
                createrole: None,
                inherit: profile.inherit,
                replication: None,
                bypassrls: None,
                connection_limit: None,
                comment: Some(format!(
                    "Generated from profile '{profile_name}' for schema '{}'",
                    schema_binding.name
                )),
                password: None,
                password_valid_until: None,
                config,
            });

            // Expand profile grants — fill in schema
            for profile_grant in &profile.grants {
                let object_target = match profile_grant.object.object_type {
                    ObjectType::Schema => ObjectTarget {
                        object_type: ObjectType::Schema,
                        schema: None,
                        name: Some(schema_binding.name.clone()),
                    },
                    _ => ObjectTarget {
                        object_type: profile_grant.object.object_type,
                        schema: Some(schema_binding.name.clone()),
                        name: profile_grant.object.name.clone(),
                    },
                };

                if profile_grant.ensure == Ensure::Absent {
                    return Err(ManifestError::ProfileAbsentGrant {
                        profile: profile_name.clone(),
                    });
                }

                grants.push(Grant {
                    role: role_name.clone(),
                    privileges: profile_grant.privileges.clone(),
                    object: object_target,
                    ensure: Ensure::Present,
                });
            }

            // Expand profile default privileges
            if !profile.default_privileges.is_empty() {
                let owner = schema_binding
                    .owner
                    .clone()
                    .or(manifest.default_owner.clone());

                let expanded_grants: Vec<DefaultPrivilegeGrant> = profile
                    .default_privileges
                    .iter()
                    .map(|dp| {
                        if dp.ensure == Ensure::Absent {
                            return Err(ManifestError::ProfileAbsentDefaultPrivilege {
                                profile: profile_name.clone(),
                            });
                        }
                        Ok(DefaultPrivilegeGrant {
                            role: Some(role_name.clone()),
                            privileges: dp.privileges.clone(),
                            on_type: dp.on_type,
                            ensure: Ensure::Present,
                        })
                    })
                    .collect::<Result<_, _>>()?;

                default_privileges.push(DefaultPrivilege {
                    owner,
                    schema: Some(schema_binding.name.clone()),
                    scope: None,
                    grant: expanded_grants,
                });
            }
        }
    }

    // Top-level default privileges must always identify the grantee role.
    for default_priv in &manifest.default_privileges {
        for grant in &default_priv.grant {
            if grant.role.is_none() {
                return Err(ManifestError::MissingDefaultPrivilegeRole {
                    scope: default_priv.resolved_scope()?.to_string(),
                });
            }
        }
    }

    // Merge one-off definitions
    roles.extend(manifest.roles.clone());
    grants.extend(manifest.grants.clone());
    default_privileges.extend(manifest.default_privileges.clone());
    let memberships = manifest.memberships.clone();

    // Normalize the owner fallback here so every consumer of the expanded
    // manifest (model, inspection scoping, composition) sees the same owner
    // without re-deriving it from default_owner.
    for default_priv in &mut default_privileges {
        if default_priv.owner.is_none() {
            default_priv.owner = manifest.default_owner.clone();
        }
    }

    validate_public_reservation(
        manifest,
        &roles,
        &schemas,
        &default_privileges,
        &memberships,
    )?;
    validate_database_grant_targets(&grants)?;
    validate_default_privilege_scopes(&default_privileges)?;
    validate_ensure_conflicts(
        manifest.default_owner.as_deref(),
        &grants,
        &default_privileges,
    )?;

    // Validate no duplicate role names
    let mut seen_roles: HashSet<String> = HashSet::new();
    for role in &roles {
        if seen_roles.contains(&role.name) {
            return Err(ManifestError::DuplicateRole(role.name.clone()));
        }
        seen_roles.insert(role.name.clone());
    }

    let desired_role_names: HashSet<String> = roles.iter().map(|role| role.name.clone()).collect();
    let mut seen_retirements: HashSet<String> = HashSet::new();
    for retirement in &manifest.retirements {
        if seen_retirements.contains(&retirement.role) {
            return Err(ManifestError::DuplicateRetirement(retirement.role.clone()));
        }
        if desired_role_names.contains(&retirement.role) {
            return Err(ManifestError::RetirementRoleStillDesired(
                retirement.role.clone(),
            ));
        }
        if retirement.reassign_owned_to.as_deref() == Some(retirement.role.as_str()) {
            return Err(ManifestError::RetirementSelfReassign {
                role: retirement.role.clone(),
            });
        }
        seen_retirements.insert(retirement.role.clone());
    }

    // Validate: password on a non-login role is an error.
    // We require login to be explicitly true — if login is None (defaults to false)
    // a password would be useless.
    for role in &roles {
        if role.password.is_some() && role.login != Some(true) {
            return Err(ManifestError::PasswordWithoutLogin {
                role: role.name.clone(),
            });
        }
    }

    // Validate: password_valid_until must be a valid ISO 8601 timestamp.
    for role in &roles {
        if let Some(value) = &role.password_valid_until
            && !is_valid_iso8601_timestamp(value)
        {
            return Err(ManifestError::InvalidValidUntil {
                role: role.name.clone(),
                value: value.clone(),
            });
        }
    }

    // Validate: config parameter names must be well-formed. A `role` setting
    // whose target is declared in this manifest must be backed by a declared
    // membership, otherwise PostgreSQL rejects the setting at login time
    // ("permission denied to set role"). Targets not declared here may be
    // externally managed, so we only enforce what we can see.
    for role in &roles {
        for (parameter, value) in &role.config {
            if !is_valid_config_parameter_name(parameter) {
                return Err(ManifestError::InvalidConfigParameter {
                    role: role.name.clone(),
                    parameter: parameter.clone(),
                });
            }
            if parameter.eq_ignore_ascii_case("role") {
                let target = value.0.as_str();
                let target_declared = desired_role_names.contains(target);
                let membership_declared = memberships.iter().any(|membership| {
                    membership.role == target
                        && membership
                            .members
                            .iter()
                            .any(|member| member.name == role.name)
                });
                if target_declared && !membership_declared {
                    return Err(ManifestError::SetRoleWithoutMembership {
                        role: role.name.clone(),
                        target: target.to_string(),
                    });
                }
            }
        }
    }

    Ok(ExpandedManifest {
        schemas,
        roles,
        grants,
        default_privileges,
        memberships,
    })
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// The exact-uppercase `PUBLIC` is reserved for the PostgreSQL pseudo-role.
/// It may appear as a grantee, but nowhere that names a real role.
fn validate_public_reservation(
    manifest: &PolicyManifest,
    roles: &[RoleDefinition],
    schemas: &[ExpandedSchema],
    default_privileges: &[DefaultPrivilege],
    memberships: &[Membership],
) -> Result<(), ManifestError> {
    let reserved = |value: Option<&str>, context: &str| -> Result<(), ManifestError> {
        if value == Some("PUBLIC") {
            return Err(ManifestError::ReservedPublicName {
                context: context.to_string(),
            });
        }
        Ok(())
    };

    reserved(manifest.default_owner.as_deref(), "default_owner")?;
    for role in roles {
        reserved(Some(&role.name), "a role name")?;
    }
    for schema in schemas {
        reserved(schema.owner.as_deref(), "a schema owner")?;
    }
    for default_priv in default_privileges {
        reserved(default_priv.owner.as_deref(), "a default privilege owner")?;
    }
    for membership in memberships {
        reserved(Some(&membership.role), "a membership role")?;
        for member in &membership.members {
            reserved(Some(&member.name), "a membership member")?;
        }
    }
    for retirement in &manifest.retirements {
        reserved(Some(&retirement.role), "a retirement role")?;
        reserved(
            retirement.reassign_owned_to.as_deref(),
            "a retirement ownership target",
        )?;
    }
    Ok(())
}

/// Database ACLs are reconciled only for the database the connection targets.
/// Requiring a name keeps desired state, inspection, SQL rendering, and
/// operator ownership claims on one concrete identity; runtime inspection
/// additionally verifies that this name is `current_database()`.
fn validate_database_grant_targets(grants: &[Grant]) -> Result<(), ManifestError> {
    if grants.iter().any(|grant| {
        grant.object.object_type == ObjectType::Database && grant.object.name.is_none()
    }) {
        return Err(ManifestError::DatabaseGrantMissingName);
    }
    Ok(())
}

/// Resolve every default-privilege scope and check the on_type matrix.
///
/// Database defaults do not exist in PostgreSQL. Schema defaults exist only in
/// global scope because schemas are not contained in another schema. Views and
/// materialized views are rejected because `pg_default_acl` stores them as
/// plain relations ('r'), so a view-typed key could never converge — declare
/// `on_type: table` instead, which is what PostgreSQL actually applies.
fn validate_default_privilege_scopes(
    default_privileges: &[DefaultPrivilege],
) -> Result<(), ManifestError> {
    use crate::model::DefaultPrivilegeScope;

    for default_priv in default_privileges {
        let scope = default_priv.resolved_scope()?;
        for grant in &default_priv.grant {
            let allowed = !matches!(
                (&scope, grant.on_type),
                (_, ObjectType::Database)
                    | (_, ObjectType::View | ObjectType::MaterializedView)
                    | (DefaultPrivilegeScope::Schema { .. }, ObjectType::Schema)
            );
            if !allowed {
                return Err(ManifestError::InvalidDefaultPrivilegeOnType {
                    on_type: grant.on_type.to_string(),
                    scope: scope.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn describe_object_target(target: &ObjectTarget) -> String {
    match (&target.schema, &target.name) {
        (Some(schema), Some(name)) => {
            format!("{} \"{}\".\"{}\"", target.object_type, schema, name)
        }
        (Some(schema), None) => format!("{} in schema \"{}\"", target.object_type, schema),
        (None, Some(name)) => format!("{} \"{}\"", target.object_type, name),
        (None, None) => target.object_type.to_string(),
    }
}

/// Reject the same assertion key declared both present and absent.
///
/// Grants are keyed per privilege on (grantee, object type, schema, name);
/// defaults on (resolved owner, scope, grantee, on_type). A wildcard and a
/// named selector with opposite ensure for the same privilege are also
/// rejected: grants apply before revokes, so such a pair re-grants or
/// re-revokes itself every reconcile and never converges.
fn validate_ensure_conflicts(
    default_owner: Option<&str>,
    grants: &[Grant],
    default_privileges: &[DefaultPrivilege],
) -> Result<(), ManifestError> {
    type GrantAssertionKey = (
        String,
        ObjectType,
        Option<String>,
        Option<String>,
        Privilege,
    );
    let mut grant_assertions: BTreeMap<GrantAssertionKey, Ensure> = BTreeMap::new();
    // (grantee, object_type, schema, privilege) -> ensures seen on wildcard
    // and on named selectors, for the cross-selector rule.
    let mut selector_ensures: BTreeMap<(String, ObjectType, String, Privilege), [bool; 4]> =
        BTreeMap::new();

    for grant in grants {
        for privilege in &grant.privileges {
            let key = (
                grant.role.clone(),
                grant.object.object_type,
                grant.object.schema.clone(),
                grant.object.name.clone(),
                *privilege,
            );
            if let Some(existing) = grant_assertions.insert(key, grant.ensure)
                && existing != grant.ensure
            {
                return Err(ManifestError::ConflictingGrantEnsure {
                    target: format!(
                        "for \"{}\" on {}",
                        grant.role,
                        describe_object_target(&grant.object)
                    ),
                    privilege: privilege.to_string(),
                });
            }

            if let (Some(schema), Some(name)) = (&grant.object.schema, &grant.object.name) {
                let flags = selector_ensures
                    .entry((
                        grant.role.clone(),
                        grant.object.object_type,
                        schema.clone(),
                        *privilege,
                    ))
                    .or_default();
                let index = match (name == "*", grant.ensure) {
                    (true, Ensure::Present) => 0,
                    (true, Ensure::Absent) => 1,
                    (false, Ensure::Present) => 2,
                    (false, Ensure::Absent) => 3,
                };
                flags[index] = true;
                let (wild_present, wild_absent, named_present, named_absent) =
                    (flags[0], flags[1], flags[2], flags[3]);
                if (wild_present && named_absent) || (wild_absent && named_present) {
                    return Err(ManifestError::ConflictingWildcardEnsure {
                        target: format!(
                            "for \"{}\" on {} in schema \"{schema}\"",
                            grant.role, grant.object.object_type
                        ),
                        privilege: privilege.to_string(),
                    });
                }
            }
        }
    }

    type DefaultAssertionKey = (
        String,
        crate::model::DefaultPrivilegeScope,
        String,
        ObjectType,
        Privilege,
    );
    let mut default_assertions: BTreeMap<DefaultAssertionKey, Ensure> = BTreeMap::new();

    for default_priv in default_privileges {
        let owner = default_priv
            .owner
            .as_deref()
            .or(default_owner)
            .unwrap_or("postgres")
            .to_string();
        let scope = default_priv.resolved_scope()?;
        for grant in &default_priv.grant {
            let Some(grantee) = &grant.role else { continue };
            for privilege in &grant.privileges {
                let key = (
                    owner.clone(),
                    scope.clone(),
                    grantee.clone(),
                    grant.on_type,
                    *privilege,
                );
                if let Some(existing) = default_assertions.insert(key, grant.ensure)
                    && existing != grant.ensure
                {
                    return Err(ManifestError::ConflictingDefaultPrivilegeEnsure {
                        target: format!(
                            "for owner \"{owner}\" ({scope}, {} to \"{grantee}\")",
                            grant.on_type
                        ),
                        privilege: privilege.to_string(),
                    });
                }
            }
        }
    }

    Ok(())
}

/// Validate that a string is a plausible ISO 8601 timestamp.
///
/// Accepts formats like:
/// - `2025-12-31T00:00:00Z`
/// - `2025-12-31T00:00:00+00:00`
/// - `2025-12-31T00:00:00-05:00`
/// - `2025-12-31T00:00:00.123Z`
///
/// This validates structure and numeric ranges (month 01-12, day 01-31,
/// hour 00-23, minute/second 00-59). It does not check calendar validity
/// (e.g. Feb 30 passes). PostgreSQL itself will reject truly invalid dates.
fn is_valid_iso8601_timestamp(value: &str) -> bool {
    // Minimum valid: "YYYY-MM-DDTHH:MM:SSZ" = 20 chars
    if value.len() < 20 {
        return false;
    }

    let bytes = value.as_bytes();

    // Check date part: YYYY-MM-DD
    if bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return false;
    }

    let year = &value[0..4];
    let month = &value[5..7];
    let day = &value[8..10];

    let Ok(y) = year.parse::<u16>() else {
        return false;
    };
    let Ok(m) = month.parse::<u8>() else {
        return false;
    };
    let Ok(d) = day.parse::<u8>() else {
        return false;
    };

    if y < 1970 || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return false;
    }

    // Check time part: HH:MM:SS
    if bytes[13] != b':' || bytes[16] != b':' {
        return false;
    }

    let hour = &value[11..13];
    let minute = &value[14..16];
    let second = &value[17..19];

    let Ok(h) = hour.parse::<u8>() else {
        return false;
    };
    let Ok(min) = minute.parse::<u8>() else {
        return false;
    };
    let Ok(sec) = second.parse::<u8>() else {
        return false;
    };

    if h > 23 || min > 59 || sec > 59 {
        return false;
    }

    // Remaining suffix must be a valid timezone indicator.
    let suffix = &value[19..];

    // Handle optional fractional seconds: .NNN
    let tz_part = if let Some(rest) = suffix.strip_prefix('.') {
        // Skip digits after the decimal point
        let frac_end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if frac_end == 0 {
            return false; // "." with no digits
        }
        &rest[frac_end..]
    } else {
        suffix
    };

    // Valid timezone indicators: "Z", "+HH:MM", "-HH:MM"
    match tz_part {
        "Z" => true,
        s if (s.starts_with('+') || s.starts_with('-'))
            && s.len() == 6
            && s.as_bytes()[3] == b':' =>
        {
            let Ok(tz_h) = s[1..3].parse::<u8>() else {
                return false;
            };
            let Ok(tz_m) = s[4..6].parse::<u8>() else {
                return false;
            };
            tz_h <= 14 && tz_m <= 59
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The CLI must reject exactly what the CRD schema rejects, so a user
    /// never learns about a limit for the first time from `kubectl`.
    #[test]
    fn bounds_reject_an_over_long_identifier() {
        let yaml = format!("roles:\n  - name: {}\n", "r".repeat(64));
        let manifest = parse_manifest(&yaml).expect("manifest parses");
        assert!(matches!(
            expand_manifest(&manifest),
            Err(ManifestError::ValueTooLong { limit, actual, .. }) if limit == 63 && actual == 64
        ));
    }

    #[test]
    fn bounds_accept_an_identifier_at_the_limit() {
        let yaml = format!("roles:\n  - name: {}\n", "r".repeat(63));
        let manifest = parse_manifest(&yaml).expect("manifest parses");
        assert!(expand_manifest(&manifest).is_ok());
    }

    /// PostgreSQL truncates identifiers at 63 *bytes*. A 32-character name of
    /// two-byte characters passes the schema's character count and must still
    /// be rejected here, or the server would silently create a different role
    /// than the one reviewed.
    #[test]
    fn bounds_reject_an_identifier_over_63_bytes_even_under_63_characters() {
        let name = "é".repeat(32); // 32 chars, 64 bytes
        let yaml = format!("roles:\n  - name: {name}\n");
        let manifest = parse_manifest(&yaml).expect("manifest parses");
        assert!(matches!(
            expand_manifest(&manifest),
            Err(ManifestError::ValueTooLong { actual, limit, .. }) if actual == 64 && limit == 63
        ));
    }

    /// Each input fits, the composition does not: the expanded role name is
    /// what PostgreSQL sees, so it is what the byte limit is checked against.
    #[test]
    fn bounds_reject_an_expanded_role_name_over_63_bytes() {
        let schema = "s".repeat(40);
        let yaml = format!(
            "profiles:\n  editor:\n    grants: []\nschemas:\n  - name: {schema}\n    profiles: [editor]\n    role_pattern: '{{schema}}-very-long-suffix-{{profile}}'\n"
        );
        let manifest = parse_manifest(&yaml).expect("manifest parses");
        assert!(matches!(
            expand_manifest(&manifest),
            Err(ManifestError::ValueTooLong { limit, .. }) if limit == 63
        ));
    }

    #[test]
    fn bounds_reject_an_over_long_collection() {
        let roles: String = (0..1025).map(|i| format!("  - name: role{i}\n")).collect();
        let manifest = parse_manifest(&format!("roles:\n{roles}")).expect("manifest parses");
        assert!(matches!(
            expand_manifest(&manifest),
            Err(ManifestError::TooManyEntries { collection, limit, .. })
                if collection == "roles" && limit == 1024
        ));
    }

    #[test]
    fn parse_minimal_role() {
        let yaml = r#"
roles:
  - name: test-role
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert_eq!(manifest.roles.len(), 1);
        assert_eq!(manifest.roles[0].name, "test-role");
        assert!(manifest.roles[0].login.is_none());
    }

    #[test]
    fn parse_role_config_accepts_strings() {
        let yaml = r#"
roles:
  - name: blue
    login: true
    config:
      role: combined
      statement_timeout: "30000"
      jit: "off"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let config = &manifest.roles[0].config;
        assert_eq!(config["role"].0, "combined");
        assert_eq!(config["statement_timeout"].0, "30000");
        assert_eq!(config["jit"].0, "off");
    }

    #[test]
    fn parse_role_config_rejects_unquoted_number() {
        // The CRD schema types config values as strings, so the CLI enforces
        // the same rule — the same manifest must be valid in both paths.
        let yaml = r#"
roles:
  - name: blue
    config:
      statement_timeout: 30000
"#;
        let err = parse_manifest(yaml).unwrap_err();
        assert!(
            err.to_string().contains("write \"30000\" instead of 30000"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_role_config_rejects_unquoted_boolean() {
        let yaml = r#"
roles:
  - name: blue
    config:
      jit: false
"#;
        let err = parse_manifest(yaml).unwrap_err();
        assert!(
            err.to_string().contains("write \"off\""),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn expand_rejects_invalid_config_parameter_name() {
        let yaml = r#"
roles:
  - name: blue
    config:
      "bad name; DROP TABLE": x
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let err = expand_manifest(&manifest).unwrap_err();
        assert!(matches!(err, ManifestError::InvalidConfigParameter { .. }));
    }

    #[test]
    fn expand_rejects_set_role_without_declared_membership() {
        let yaml = r#"
roles:
  - name: blue
    login: true
    config:
      role: combined
  - name: combined
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let err = expand_manifest(&manifest).unwrap_err();
        assert!(matches!(
            err,
            ManifestError::SetRoleWithoutMembership { role, target }
                if role == "blue" && target == "combined"
        ));
    }

    #[test]
    fn expand_accepts_set_role_with_declared_membership() {
        let yaml = r#"
roles:
  - name: blue
    login: true
    config:
      role: combined
  - name: combined

memberships:
  - role: combined
    members:
      - name: blue
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert!(expand_manifest(&manifest).is_ok());
    }

    #[test]
    fn expand_accepts_set_role_to_undeclared_target() {
        // Target role not declared in the manifest — assumed externally
        // managed, so no membership can be verified.
        let yaml = r#"
roles:
  - name: blue
    login: true
    config:
      role: external_combined
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert!(expand_manifest(&manifest).is_ok());
    }

    #[test]
    fn config_parameter_name_validation() {
        assert!(is_valid_config_parameter_name("role"));
        assert!(is_valid_config_parameter_name("search_path"));
        assert!(is_valid_config_parameter_name("app.tenant"));
        assert!(is_valid_config_parameter_name("_x.y2"));
        assert!(!is_valid_config_parameter_name(""));
        assert!(!is_valid_config_parameter_name("2bad"));
        assert!(!is_valid_config_parameter_name("bad name"));
        assert!(!is_valid_config_parameter_name("bad;name"));
        assert!(!is_valid_config_parameter_name("trailing."));
        assert!(!is_valid_config_parameter_name(".leading"));
    }

    #[test]
    fn parse_full_policy() {
        let yaml = r#"
default_owner: app_owner

profiles:
  editor:
    login: false
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER]
        object: { type: table, name: "*" }
      - privileges: [USAGE, SELECT, UPDATE]
        object: { type: sequence, name: "*" }
      - privileges: [EXECUTE]
        object: { type: function, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT, UPDATE, DELETE, REFERENCES, TRIGGER]
        on_type: table
      - privileges: [USAGE, SELECT, UPDATE]
        on_type: sequence
      - privileges: [EXECUTE]
        on_type: function

schemas:
  - name: inventory
    profiles: [editor]
  - name: catalog
    profiles: [editor]

roles:
  - name: analytics-readonly
    login: true

memberships:
  - role: inventory-editor
    members:
      - name: "alice@example.com"
        inherit: true
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert_eq!(manifest.profiles.len(), 1);
        assert_eq!(manifest.schemas.len(), 2);
        assert_eq!(manifest.roles.len(), 1);
        assert_eq!(manifest.memberships.len(), 1);
        assert_eq!(manifest.default_owner, Some("app_owner".to_string()));
    }

    #[test]
    fn reject_invalid_yaml() {
        let yaml = "not: [valid: yaml: {{";
        assert!(parse_manifest(yaml).is_err());
    }

    #[test]
    fn expand_profiles_basic() {
        let yaml = r#"
profiles:
  editor:
    login: false
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT, INSERT]
        object: { type: table, name: "*" }

schemas:
  - name: myschema
    profiles: [editor]
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();

        assert_eq!(expanded.roles.len(), 1);
        assert_eq!(expanded.roles[0].name, "myschema-editor");
        assert_eq!(expanded.roles[0].login, Some(false));
        assert_eq!(expanded.roles[0].inherit, None);

        // Schema usage grant + table grant
        assert_eq!(expanded.grants.len(), 2);
        assert_eq!(expanded.grants[0].role, "myschema-editor");
        assert_eq!(expanded.grants[0].object.object_type, ObjectType::Schema);
        assert_eq!(expanded.grants[0].object.name, Some("myschema".to_string()));

        assert_eq!(expanded.grants[1].object.object_type, ObjectType::Table);
        assert_eq!(
            expanded.grants[1].object.schema,
            Some("myschema".to_string())
        );
        assert_eq!(expanded.grants[1].object.name, Some("*".to_string()));
    }

    #[test]
    fn expand_schema_owner_overrides_default_owner() {
        let yaml = r#"
default_owner: app_owner

profiles:
  editor:
    default_privileges:
      - privileges: [SELECT]
        on_type: table

schemas:
  - name: inventory
    owner: inventory_owner
    profiles: [editor]
  - name: catalog
    profiles: [editor]
"#;

        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();

        assert_eq!(
            expanded.schemas,
            vec![
                ExpandedSchema {
                    name: "inventory".to_string(),
                    owner: Some("inventory_owner".to_string()),
                },
                ExpandedSchema {
                    name: "catalog".to_string(),
                    owner: Some("app_owner".to_string()),
                },
            ]
        );
    }

    #[test]
    fn expand_profiles_preserves_generated_role_inherit() {
        let yaml = r#"
profiles:
  editor:
    login: false
    inherit: false
    grants:
      - privileges: [USAGE]
        object: { type: schema }

schemas:
  - name: myschema
    profiles: [editor]
"#;

        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();

        assert_eq!(expanded.roles.len(), 1);
        assert_eq!(expanded.roles[0].name, "myschema-editor");
        assert_eq!(expanded.roles[0].login, Some(false));
        assert_eq!(expanded.roles[0].inherit, Some(false));
    }

    #[test]
    fn expand_declared_schema_with_no_profiles() {
        let yaml = r#"
schemas:
  - name: cdc
    owner: cdc_owner
    profiles: []
"#;

        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();

        assert_eq!(expanded.schemas.len(), 1);
        assert_eq!(expanded.schemas[0].name, "cdc");
        assert_eq!(expanded.schemas[0].owner.as_deref(), Some("cdc_owner"));
        assert!(expanded.roles.is_empty());
        assert!(expanded.grants.is_empty());
        assert!(expanded.default_privileges.is_empty());
    }

    #[test]
    fn expand_profiles_multi_schema() {
        let yaml = r#"
profiles:
  editor:
    grants:
      - privileges: [SELECT]
        object: { type: table, name: "*" }
  viewer:
    grants:
      - privileges: [SELECT]
        object: { type: table, name: "*" }

schemas:
  - name: alpha
    profiles: [editor, viewer]
  - name: beta
    profiles: [editor, viewer]
  - name: gamma
    profiles: [editor]
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();

        // 2 + 2 + 1 = 5 roles
        assert_eq!(expanded.roles.len(), 5);
        let role_names: Vec<&str> = expanded.roles.iter().map(|r| r.name.as_str()).collect();
        assert!(role_names.contains(&"alpha-editor"));
        assert!(role_names.contains(&"alpha-viewer"));
        assert!(role_names.contains(&"beta-editor"));
        assert!(role_names.contains(&"beta-viewer"));
        assert!(role_names.contains(&"gamma-editor"));
    }

    #[test]
    fn expand_custom_role_pattern() {
        let yaml = r#"
profiles:
  viewer:
    grants:
      - privileges: [SELECT]
        object: { type: table, name: "*" }

schemas:
  - name: legacy_data
    profiles: [viewer]
    role_pattern: "legacy-{profile}"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();

        assert_eq!(expanded.roles.len(), 1);
        assert_eq!(expanded.roles[0].name, "legacy-viewer");
    }

    #[test]
    fn expand_rejects_duplicate_role_name() {
        let yaml = r#"
profiles:
  editor:
    grants: []

schemas:
  - name: inventory
    profiles: [editor]

roles:
  - name: inventory-editor
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("duplicate role name")
        );
    }

    #[test]
    fn expand_rejects_duplicate_schema_name() {
        let yaml = r#"
schemas:
  - name: inventory
    profiles: []
  - name: inventory
    owner: inventory_owner
    profiles: []
"#;

        let manifest = parse_manifest(yaml).unwrap();
        let error = expand_manifest(&manifest).unwrap_err();
        assert!(error.to_string().contains("duplicate schema name"));
    }

    #[test]
    fn expand_rejects_undefined_profile() {
        let yaml = r#"
profiles: {}

schemas:
  - name: inventory
    profiles: [nonexistent]
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not defined"));
    }

    #[test]
    fn expand_rejects_invalid_pattern() {
        let yaml = r#"
profiles:
  editor:
    grants: []

schemas:
  - name: inventory
    profiles: [editor]
    role_pattern: "static-name"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("{profile} placeholder")
        );
    }

    #[test]
    fn expand_rejects_top_level_default_privilege_without_role() {
        let yaml = r#"
default_privileges:
  - schema: public
    grant:
      - privileges: [SELECT]
        on_type: table
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must specify grant.role")
        );
    }

    #[test]
    fn expand_default_privileges_with_owner_override() {
        let yaml = r#"
default_owner: app_owner

profiles:
  editor:
    grants: []
    default_privileges:
      - privileges: [SELECT]
        on_type: table

schemas:
  - name: inventory
    profiles: [editor]
  - name: legacy
    profiles: [editor]
    owner: legacy_admin
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();

        assert_eq!(expanded.default_privileges.len(), 2);

        // inventory uses default_owner
        assert_eq!(
            expanded.default_privileges[0].owner,
            Some("app_owner".to_string())
        );
        assert_eq!(
            expanded.default_privileges[0].schema.as_deref(),
            Some("inventory")
        );

        // legacy uses override
        assert_eq!(
            expanded.default_privileges[1].owner,
            Some("legacy_admin".to_string())
        );
        assert_eq!(
            expanded.default_privileges[1].schema.as_deref(),
            Some("legacy")
        );
    }

    #[test]
    fn expand_merges_oneoff_roles_and_grants() {
        let yaml = r#"
profiles:
  editor:
    grants:
      - privileges: [SELECT]
        object: { type: table, name: "*" }

schemas:
  - name: inventory
    profiles: [editor]

roles:
  - name: analytics
    login: true

grants:
  - role: analytics
    privileges: [SELECT]
    on:
      type: table
      schema: inventory
      name: "*"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();

        assert_eq!(expanded.roles.len(), 2);
        assert_eq!(expanded.grants.len(), 2); // 1 from profile + 1 one-off
    }

    #[test]
    fn parse_manifest_accepts_legacy_on_alias() {
        let yaml = r#"
grants:
  - role: analytics
    privileges: [SELECT]
    on:
      type: table
      schema: public
      name: "*"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert_eq!(manifest.grants.len(), 1);
        assert_eq!(manifest.grants[0].object.object_type, ObjectType::Table);
        assert_eq!(manifest.grants[0].object.schema.as_deref(), Some("public"));
        assert_eq!(manifest.grants[0].object.name.as_deref(), Some("*"));
    }

    #[test]
    fn parse_membership_with_email_roles() {
        let yaml = r#"
memberships:
  - role: inventory-editor
    members:
      - name: "alice@example.com"
        inherit: true
      - name: "engineering@example.com"
        admin: true
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert_eq!(manifest.memberships.len(), 1);
        assert_eq!(manifest.memberships[0].members.len(), 2);
        assert_eq!(manifest.memberships[0].members[0].name, "alice@example.com");
        assert_eq!(manifest.memberships[0].members[0].inherit, Some(true));
        assert_eq!(manifest.memberships[0].members[1].admin, Some(true));
    }

    #[test]
    fn member_spec_defaults() {
        let yaml = r#"
memberships:
  - role: some-role
    members:
      - name: user1
"#;
        let manifest = parse_manifest(yaml).unwrap();
        // When omitted, both fields are None (defaults applied at resolution time).
        assert_eq!(manifest.memberships[0].members[0].inherit, None);
        assert_eq!(manifest.memberships[0].members[0].admin, None);
        // Accessor methods still return the expected defaults.
        assert!(manifest.memberships[0].members[0].inherit());
        assert!(!manifest.memberships[0].members[0].admin());
    }

    #[test]
    fn expand_rejects_duplicate_retirements() {
        let yaml = r#"
retirements:
  - role: old-app
  - role: old-app
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(matches!(
            result,
            Err(ManifestError::DuplicateRetirement(role)) if role == "old-app"
        ));
    }

    #[test]
    fn expand_rejects_retirement_for_desired_role() {
        let yaml = r#"
roles:
  - name: old-app

retirements:
  - role: old-app
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(matches!(
            result,
            Err(ManifestError::RetirementRoleStillDesired(role)) if role == "old-app"
        ));
    }

    #[test]
    fn expand_rejects_self_reassign_retirement() {
        let yaml = r#"
retirements:
  - role: old-app
    reassign_owned_to: old-app
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(matches!(
            result,
            Err(ManifestError::RetirementSelfReassign { role }) if role == "old-app"
        ));
    }

    #[test]
    fn parse_auth_providers() {
        let yaml = r#"
auth_providers:
  - type: cloud_sql_iam
    project: my-gcp-project
  - type: alloydb_iam
    project: my-gcp-project
    cluster: analytics-prod
  - type: rds_iam
    region: us-east-1
  - type: azure_ad
    tenant_id: "abc-123"
  - type: supabase
    project_ref: myprojref
  - type: planet_scale
    organization: my-org

roles:
  - name: app-service
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert_eq!(manifest.auth_providers.len(), 6);
        assert!(matches!(
            &manifest.auth_providers[0],
            AuthProvider::CloudSqlIam { project: Some(p) } if p == "my-gcp-project"
        ));
        assert!(matches!(
            &manifest.auth_providers[1],
            AuthProvider::AlloyDbIam {
                project: Some(p),
                cluster: Some(c)
            } if p == "my-gcp-project" && c == "analytics-prod"
        ));
        assert!(matches!(
            &manifest.auth_providers[2],
            AuthProvider::RdsIam { region: Some(r) } if r == "us-east-1"
        ));
        assert!(matches!(
            &manifest.auth_providers[3],
            AuthProvider::AzureAd { tenant_id: Some(t) } if t == "abc-123"
        ));
        assert!(matches!(
            &manifest.auth_providers[4],
            AuthProvider::Supabase { project_ref: Some(r) } if r == "myprojref"
        ));
        assert!(matches!(
            &manifest.auth_providers[5],
            AuthProvider::PlanetScale { organization: Some(o) } if o == "my-org"
        ));
    }

    #[test]
    fn parse_manifest_without_auth_providers() {
        let yaml = r#"
roles:
  - name: test-role
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert!(manifest.auth_providers.is_empty());
    }

    #[test]
    fn parse_role_with_password_source() {
        let yaml = r#"
roles:
  - name: app-service
    login: true
    password:
      from_env: APP_SERVICE_PASSWORD
    password_valid_until: "2025-12-31T00:00:00Z"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert_eq!(manifest.roles.len(), 1);
        let role = &manifest.roles[0];
        assert!(role.password.is_some());
        assert_eq!(
            role.password.as_ref().unwrap().from_env,
            "APP_SERVICE_PASSWORD"
        );
        assert_eq!(
            role.password_valid_until,
            Some("2025-12-31T00:00:00Z".to_string())
        );
    }

    #[test]
    fn parse_role_without_password() {
        let yaml = r#"
roles:
  - name: app-service
    login: true
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert!(manifest.roles[0].password.is_none());
        assert!(manifest.roles[0].password_valid_until.is_none());
    }

    #[test]
    fn reject_password_on_nologin_role() {
        let yaml = r#"
roles:
  - name: nologin-role
    login: false
    password:
      from_env: SOME_PASSWORD
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("login is not enabled")
        );
    }

    #[test]
    fn reject_password_on_default_login_role() {
        // login is None (defaults to NOLOGIN) — password should still be rejected
        let yaml = r#"
roles:
  - name: implicit-nologin-role
    password:
      from_env: SOME_PASSWORD
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("login is not enabled")
        );
    }

    #[test]
    fn reject_invalid_password_valid_until() {
        let yaml = r#"
roles:
  - name: bad-date
    login: true
    password_valid_until: "not-a-date"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid password_valid_until")
        );
    }

    #[test]
    fn reject_date_only_valid_until() {
        let yaml = r#"
roles:
  - name: bad-date
    login: true
    password_valid_until: "2025-12-31"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let result = expand_manifest(&manifest);
        assert!(result.is_err());
    }

    #[test]
    fn accept_valid_iso8601_timestamps() {
        // UTC with Z
        assert!(is_valid_iso8601_timestamp("2025-12-31T00:00:00Z"));
        // With timezone offset
        assert!(is_valid_iso8601_timestamp("2025-06-15T14:30:00+05:30"));
        assert!(is_valid_iso8601_timestamp("2025-06-15T14:30:00-05:00"));
        // With fractional seconds
        assert!(is_valid_iso8601_timestamp("2025-12-31T23:59:59.999Z"));
    }

    #[test]
    fn reject_invalid_iso8601_timestamps() {
        assert!(!is_valid_iso8601_timestamp("not-a-date"));
        assert!(!is_valid_iso8601_timestamp("2025-12-31")); // date only
        assert!(!is_valid_iso8601_timestamp("2025-13-31T00:00:00Z")); // month 13
        assert!(!is_valid_iso8601_timestamp("2025-12-31T25:00:00Z")); // hour 25
        assert!(!is_valid_iso8601_timestamp("2025-12-31T00:00:00")); // no timezone
        assert!(!is_valid_iso8601_timestamp("")); // empty
    }

    #[test]
    fn parse_manifest_from_kubernetes_cr() {
        let yaml = r#"
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata:
  name: staging-policy
  namespace: pgroles-system
spec:
  connection:
    secretRef:
      name: pgroles-db-credentials
  interval: "5m"
  mode: observe
  roles:
    - name: app_analytics
      login: true
    - name: app_billing
      login: true
  schemas:
    - name: analytics
      profiles: [editor, viewer]
  profiles:
    editor:
      grants:
        - object: { type: schema }
          privileges: [USAGE]
        - object: { type: table, name: "*" }
          privileges: [SELECT, INSERT, UPDATE, DELETE]
    viewer:
      grants:
        - object: { type: schema }
          privileges: [USAGE]
        - object: { type: table, name: "*" }
          privileges: [SELECT]
  memberships:
    - role: analytics-editor
      members:
        - { name: app_analytics }
    - role: analytics-viewer
      members:
        - { name: app_billing }
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert_eq!(manifest.roles.len(), 2);
        assert_eq!(manifest.roles[0].name, "app_analytics");
        assert_eq!(manifest.schemas.len(), 1);
        assert_eq!(manifest.memberships.len(), 2);
        assert_eq!(manifest.profiles.len(), 2);
    }

    #[test]
    fn profile_config_substitutes_schema_and_profile_placeholders_in_values() {
        let yaml = r#"
profiles:
  editor:
    login: true
    config:
      search_path: "{schema}"
      statement_timeout: "30s"
      app.profile_name: "{profile}"
      app.combo: "{schema}-{profile}-{schema}"
      app.literal: "no placeholders here"

schemas:
  - name: inventory
    profiles: [editor]
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();

        assert_eq!(expanded.roles.len(), 1);
        let role = &expanded.roles[0];
        assert_eq!(role.name, "inventory-editor");
        assert_eq!(role.config["search_path"].0, "inventory");
        assert_eq!(role.config["statement_timeout"].0, "30s");
        assert_eq!(role.config["app.profile_name"].0, "editor");
        assert_eq!(role.config["app.combo"].0, "inventory-editor-inventory");
        assert_eq!(role.config["app.literal"].0, "no placeholders here");
    }

    #[test]
    fn profile_config_empty_when_not_declared() {
        let yaml = r#"
profiles:
  editor:
    login: true

schemas:
  - name: inventory
    profiles: [editor]
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        assert!(expanded.roles[0].config.is_empty());
    }

    #[test]
    fn profile_config_rejects_invalid_parameter_name() {
        // {schema} substitution only applies to values, never to keys — a
        // literal `{schema}` key is not a valid PostgreSQL parameter name and
        // is rejected the same way any other malformed key would be.
        let yaml = r#"
profiles:
  editor:
    config:
      "{schema}": inventory

schemas:
  - name: inventory
    profiles: [editor]
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let err = expand_manifest(&manifest).unwrap_err();
        assert!(matches!(err, ManifestError::InvalidConfigParameter { .. }));
    }

    #[test]
    fn profile_config_rejects_unquoted_number() {
        let yaml = r#"
profiles:
  editor:
    config:
      statement_timeout: 30000

schemas:
  - name: inventory
    profiles: [editor]
"#;
        let err = parse_manifest(yaml).unwrap_err();
        assert!(
            err.to_string().contains("write \"30000\" instead of 30000"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn profile_config_role_membership_validation_fires() {
        // A profile `config: { role: <group> }` pointing at a manifest role
        // without a declared membership must fail the same way a hand-written
        // role's `config.role` would — the cross-check applies to generated
        // roles because they land in the same `roles` vec before validation.
        let yaml = r#"
profiles:
  editor:
    login: true
    config:
      role: combined

schemas:
  - name: inventory
    profiles: [editor]

roles:
  - name: combined
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let err = expand_manifest(&manifest).unwrap_err();
        assert!(matches!(
            err,
            ManifestError::SetRoleWithoutMembership { role, target }
                if role == "inventory-editor" && target == "combined"
        ));
    }

    #[test]
    fn profile_config_role_membership_validation_passes_with_declared_membership() {
        let yaml = r#"
profiles:
  editor:
    login: true
    config:
      role: combined

schemas:
  - name: inventory
    profiles: [editor]

roles:
  - name: combined

memberships:
  - role: combined
    members:
      - name: inventory-editor
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert!(expand_manifest(&manifest).is_ok());
    }

    #[test]
    fn parse_manifest_bare_and_cr_produce_same_result() {
        let bare = r#"
roles:
  - name: test_role
    login: true
schemas:
  - name: public
    profiles: [viewer]
profiles:
  viewer:
    grants:
      - object: { type: schema }
        privileges: [USAGE]
"#;
        let cr = r#"
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata:
  name: test
spec:
  roles:
    - name: test_role
      login: true
  schemas:
    - name: public
      profiles: [viewer]
  profiles:
    viewer:
      grants:
        - object: { type: schema }
          privileges: [USAGE]
"#;
        let from_bare = parse_manifest(bare).unwrap();
        let from_cr = parse_manifest(cr).unwrap();
        assert_eq!(from_bare.roles.len(), from_cr.roles.len());
        assert_eq!(from_bare.schemas.len(), from_cr.schemas.len());
        assert_eq!(from_bare.profiles.len(), from_cr.profiles.len());
    }

    // -----------------------------------------------------------------------
    // ensure / PUBLIC / default-privilege scopes
    // -----------------------------------------------------------------------

    fn expand(yaml: &str) -> Result<ExpandedManifest, ManifestError> {
        expand_manifest(&parse_manifest(yaml).unwrap())
    }

    #[test]
    fn legacy_manifest_defaults_to_present_and_schema_scope() {
        let expanded = expand(
            r#"
grants:
  - role: reader
    privileges: [SELECT]
    object: { type: table, schema: app, name: "*" }
default_privileges:
  - owner: app_owner
    schema: app
    grant:
      - role: reader
        privileges: [SELECT]
        on_type: table
"#,
        )
        .unwrap();

        assert_eq!(expanded.grants[0].ensure, Ensure::Present);
        assert_eq!(
            expanded.default_privileges[0].grant[0].ensure,
            Ensure::Present
        );
        assert_eq!(
            expanded.default_privileges[0].resolved_scope().unwrap(),
            crate::model::DefaultPrivilegeScope::Schema {
                schema: "app".to_string()
            }
        );
    }

    #[test]
    fn ensure_and_scope_round_trip_through_yaml() {
        let yaml = r#"
grants:
  - role: PUBLIC
    ensure: absent
    privileges: [EXECUTE]
    object: { type: function, schema: api, name: "*" }
default_privileges:
  - owner: api_owner
    scope: { type: global }
    grant:
      - role: PUBLIC
        ensure: absent
        privileges: [EXECUTE]
        on_type: function
"#;
        let manifest = parse_manifest(yaml).unwrap();
        assert_eq!(manifest.grants[0].ensure, Ensure::Absent);
        assert_eq!(
            manifest.default_privileges[0].resolved_scope().unwrap(),
            crate::model::DefaultPrivilegeScope::Global
        );

        // Present/schema entries stay out of the serialized form so existing
        // manifests keep their shape.
        let reserialized = serde_yaml::to_string(&manifest).unwrap();
        assert!(reserialized.contains("ensure: absent"));
        assert!(!reserialized.contains("ensure: present"));
    }

    #[test]
    fn public_is_reserved_everywhere_a_real_role_is_named() {
        let cases = [
            "roles:\n  - name: PUBLIC\n",
            "memberships:\n  - role: PUBLIC\n    members:\n      - name: app\n",
            "memberships:\n  - role: app\n    members:\n      - name: PUBLIC\n",
            "retirements:\n  - role: PUBLIC\n",
            "default_owner: PUBLIC\n",
            "schemas:\n  - name: app\n    owner: PUBLIC\n    profiles: []\n",
            "default_privileges:\n  - owner: PUBLIC\n    schema: app\n    grant:\n      - role: r\n        privileges: [SELECT]\n        on_type: table\n",
        ];
        for yaml in cases {
            assert!(
                matches!(expand(yaml), Err(ManifestError::ReservedPublicName { .. })),
                "expected PUBLIC to be rejected in: {yaml}"
            );
        }
    }

    #[test]
    fn public_is_allowed_as_a_grantee_and_lowercase_public_is_an_ordinary_role() {
        expand(
            r#"
roles:
  - name: public
grants:
  - role: PUBLIC
    ensure: absent
    privileges: [EXECUTE]
    object: { type: function, schema: api, name: "*" }
  - role: public
    privileges: [USAGE]
    object: { type: schema, name: api }
"#,
        )
        .unwrap();
    }

    #[test]
    fn database_grants_require_an_explicit_name() {
        let result = expand(
            r#"
grants:
  - role: PUBLIC
    ensure: absent
    privileges: [CONNECT]
    object: { type: database }
"#,
        );
        assert!(matches!(
            result,
            Err(ManifestError::DatabaseGrantMissingName)
        ));
    }

    #[test]
    fn default_privilege_scope_must_be_specified_exactly_once() {
        let both = expand(
            r#"
default_privileges:
  - owner: o
    schema: app
    scope: { type: global }
    grant:
      - role: r
        privileges: [SELECT]
        on_type: table
"#,
        );
        assert!(matches!(
            both,
            Err(ManifestError::DefaultPrivilegeScopeConflict { .. })
        ));

        let neither = expand(
            r#"
default_privileges:
  - owner: o
    grant:
      - role: r
        privileges: [SELECT]
        on_type: table
"#,
        );
        assert!(matches!(
            neither,
            Err(ManifestError::DefaultPrivilegeScopeMissing { .. })
        ));

        let schema_scope_without_name = expand(
            r#"
default_privileges:
  - owner: o
    scope: { type: schema }
    grant:
      - role: r
        privileges: [SELECT]
        on_type: table
"#,
        );
        assert!(matches!(
            schema_scope_without_name,
            Err(ManifestError::DefaultPrivilegeScopeSchemaMissing)
        ));

        let global_with_name = expand(
            r#"
default_privileges:
  - owner: o
    scope: { type: global, schema: app }
    grant:
      - role: r
        privileges: [SELECT]
        on_type: table
"#,
        );
        assert!(matches!(
            global_with_name,
            Err(ManifestError::DefaultPrivilegeScopeSchemaForbidden { .. })
        ));
    }

    #[test]
    fn default_privilege_on_type_matrix_is_enforced_per_scope() {
        let dp = |scope: &str, on_type: &str| {
            expand(&format!(
                r#"
default_privileges:
  - owner: o
    {scope}
    grant:
      - role: r
        privileges: [USAGE]
        on_type: {on_type}
"#
            ))
        };

        // Schemas are not contained in a schema, so they are global-only.
        assert!(dp("scope: { type: global }", "schema").is_ok());
        assert!(matches!(
            dp("schema: app", "schema"),
            Err(ManifestError::InvalidDefaultPrivilegeOnType { .. })
        ));

        // PostgreSQL has no database-level default privileges.
        for scope in ["scope: { type: global }", "schema: app"] {
            assert!(matches!(
                dp(scope, "database"),
                Err(ManifestError::InvalidDefaultPrivilegeOnType { .. })
            ));
            // pg_default_acl stores views as plain relations, so a view-typed
            // key could never converge.
            assert!(matches!(
                dp(scope, "view"),
                Err(ManifestError::InvalidDefaultPrivilegeOnType { .. })
            ));
            for on_type in ["table", "sequence", "function", "type"] {
                assert!(dp(scope, on_type).is_ok(), "{scope} / {on_type}");
            }
        }
    }

    #[test]
    fn same_assertion_declared_present_and_absent_is_rejected() {
        let grants = expand(
            r#"
grants:
  - role: PUBLIC
    privileges: [EXECUTE]
    object: { type: function, schema: api, name: f() }
  - role: PUBLIC
    ensure: absent
    privileges: [EXECUTE]
    object: { type: function, schema: api, name: f() }
"#,
        );
        assert!(matches!(
            grants,
            Err(ManifestError::ConflictingGrantEnsure { .. })
        ));

        let defaults = expand(
            r#"
default_privileges:
  - owner: o
    schema: app
    grant:
      - role: r
        privileges: [SELECT]
        on_type: table
      - role: r
        ensure: absent
        privileges: [SELECT]
        on_type: table
"#,
        );
        assert!(matches!(
            defaults,
            Err(ManifestError::ConflictingDefaultPrivilegeEnsure { .. })
        ));
    }

    #[test]
    fn disjoint_privileges_on_one_target_may_mix_present_and_absent() {
        expand(
            r#"
grants:
  - role: reader
    privileges: [SELECT]
    object: { type: table, schema: app, name: t }
  - role: reader
    ensure: absent
    privileges: [DELETE]
    object: { type: table, schema: app, name: t }
"#,
        )
        .unwrap();
    }

    #[test]
    fn wildcard_and_named_selectors_may_not_disagree_on_ensure() {
        // Grants run before revokes, so this pair would never converge.
        let conflicting = expand(
            r#"
grants:
  - role: PUBLIC
    privileges: [EXECUTE]
    object: { type: function, schema: api, name: "*" }
  - role: PUBLIC
    ensure: absent
    privileges: [EXECUTE]
    object: { type: function, schema: api, name: f() }
"#,
        );
        assert!(matches!(
            conflicting,
            Err(ManifestError::ConflictingWildcardEnsure { .. })
        ));

        // A different privilege on each selector is fine.
        expand(
            r#"
grants:
  - role: reader
    privileges: [SELECT]
    object: { type: table, schema: app, name: "*" }
  - role: reader
    ensure: absent
    privileges: [DELETE]
    object: { type: table, schema: app, name: t }
"#,
        )
        .unwrap();
    }

    #[test]
    fn profiles_may_not_assert_absence() {
        let result = expand(
            r#"
profiles:
  editor:
    default_privileges:
      - ensure: absent
        privileges: [SELECT]
        on_type: table
schemas:
  - name: app
    profiles: [editor]
"#,
        );
        assert!(matches!(
            result,
            Err(ManifestError::ProfileAbsentDefaultPrivilege { .. })
        ));
    }

    #[test]
    fn profile_grants_may_not_assert_absence() {
        let result = expand(
            r#"
roles:
  - name: reader
    profiles: [editor]
profiles:
  editor:
    grants:
      - ensure: absent
        privileges: [SELECT]
        object: { type: table, name: "*" }
schemas:
  - name: app
    profiles: [editor]
"#,
        );
        assert!(
            matches!(result, Err(ManifestError::ProfileAbsentGrant { .. })),
            "a profile grant asserting absence must be rejected, got: {result:?}"
        );
    }
}
