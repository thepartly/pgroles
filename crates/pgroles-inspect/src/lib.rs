//! Database introspection for pgroles.
//!
//! Queries `pg_catalog` tables to build a [`pgroles_core::model::RoleGraph`]
//! representing the current state of roles, grants, default privileges, and
//! memberships in a PostgreSQL database.

pub mod cloud;
mod defaults;
mod identity;
mod memberships;
mod preflight;
mod privileges;
mod public_grants;
mod roles;
mod safety;
mod snapshot;
mod version;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use sqlx::PgPool;
use thiserror::Error;
use tracing::debug;

use pgroles_core::manifest::{ObjectType, Privilege};
use pgroles_core::model::RoleGraph;
use pgroles_core::ownership::ManagedScope;

// Re-export the sub-modules' public items for testing / advanced use.
pub use cloud::{CloudProvider, PrivilegeLevel, detect_privilege_level};
pub use identity::detect_system_identifier;
pub use memberships::fetch_memberships;
pub use preflight::{AuthorityIssue, preflight_authority_issues};
pub use privileges::{
    fetch_column_level_grants, fetch_database_privileges, fetch_object_inventory, fetch_privileges,
    fetch_relation_inventory,
};
pub use public_grants::{PublicGrants, fetch_public_grants, format_public_grants};
pub use roles::fetch_roles;
pub use safety::{
    DropRoleSafetyAssessment, DropRoleSafetyIssue, DropRoleSafetyReport, inspect_drop_role_safety,
};
pub use snapshot::RawInspection;
pub use version::{PgVersion, detect_pg_version};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum InspectError {
    #[error("database query error: {0}")]
    Database(#[from] sqlx::Error),
    /// A [`RawInspection`] was asked to derive an [`InspectConfig`] whose
    /// scope it never read. Deriving anyway would silently under-report —
    /// missing roles, schemas or wildcard objects the caller asked about — so
    /// this is a hard error, not a narrower answer.
    #[error("inspection scope not covered by the shared snapshot: {0}")]
    ScopeNotCovered(String),
    #[error(
        "database grant target {target:?} does not match connected database {connected:?}; \
         pgroles reconciles database ACLs only for the connected database"
    )]
    DatabaseTargetMismatch { target: String, connected: String },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InspectionDiagnostics {
    pub unsatisfiable_wildcard_grants: Vec<UnsatisfiableWildcardGrant>,
    /// Column-level ACL entries (`GRANT ... (column) ON table TO role`) found
    /// on relations inside managed schemas. pgroles does not manage
    /// column-level privileges — these are surfaced as an advisory warning
    /// during `diff`/`apply`, not a blocking error: unlike
    /// [`unsatisfiable_wildcard_grants`](Self::unsatisfiable_wildcard_grants),
    /// their presence never stops inspection or reconciliation from
    /// proceeding.
    pub column_level_grants: Vec<ColumnLevelGrantDiagnostic>,
}

impl InspectionDiagnostics {
    pub fn is_empty(&self) -> bool {
        self.unsatisfiable_wildcard_grants.is_empty() && self.column_level_grants.is_empty()
    }

    /// Render the blocking diagnostics (unsatisfiable wildcard grants) as the
    /// error message `diff`/`apply` and the operator fail with, one per line.
    /// Returns `None` when nothing blocks reconciliation. Advisory
    /// diagnostics ([`column_level_grants`](Self::column_level_grants)) are
    /// deliberately excluded — callers surface those as warnings separately.
    pub fn blocking_message(&self) -> Option<String> {
        if self.unsatisfiable_wildcard_grants.is_empty() {
            return None;
        }
        Some(
            self.unsatisfiable_wildcard_grants
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }
}

/// Combined rendering of all diagnostics, blocking and advisory alike.
///
/// NOTE: production paths do NOT use this impl — the CLI and operator render
/// [`InspectionDiagnostics::blocking_message`] for the failure path and
/// iterate `column_level_grants` for the warning path separately, so severity
/// stays visible. This impl exists for logging/debugging convenience.
impl std::fmt::Display for InspectionDiagnostics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut wrote_any = false;
        for diagnostic in &self.unsatisfiable_wildcard_grants {
            if wrote_any {
                writeln!(f)?;
            }
            write!(f, "{diagnostic}")?;
            wrote_any = true;
        }
        for diagnostic in &self.column_level_grants {
            if wrote_any {
                writeln!(f)?;
            }
            write!(f, "{diagnostic}")?;
            wrote_any = true;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsatisfiableWildcardGrant {
    pub role: String,
    pub object_type: ObjectType,
    pub schema: String,
    pub privileges: std::collections::BTreeSet<Privilege>,
    pub executor: String,
    pub skipped_count: usize,
    pub examples: Vec<UnsatisfiableWildcardObject>,
}

impl std::fmt::Display for UnsatisfiableWildcardGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let privileges = self
            .privileges
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let examples = self
            .examples
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        write!(
            f,
            "UnsatisfiableWildcardGrant: cannot fully satisfy wildcard grant \
             {privileges} ON {} * IN SCHEMA \"{}\" TO \"{}\" as executor \"{}\"; \
             {} matching object(s) are missing the desired privilege and are not grantable",
            self.object_type, self.schema, self.role, self.executor, self.skipped_count
        )?;
        if !examples.is_empty() {
            write!(f, " (examples: {examples})")?;
        }
        Ok(())
    }
}

/// A column-level grant detected on a relation inside a managed schema,
/// aggregated by `(schema, relation, grantee)`.
///
/// pgroles only manages table/view/etc.-level ACLs (`pg_class.relacl`); it
/// never reads or writes `pg_attribute.attacl`. When column-level grants
/// exist, the manifest is not the whole truth for that relation — this
/// diagnostic surfaces that gap without attempting to manage it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnLevelGrantDiagnostic {
    pub schema: String,
    pub relation: String,
    /// The grantee role name, or the literal string `"PUBLIC"` for grants to
    /// the PUBLIC pseudo-role (ACL grantee OID 0).
    pub grantee: String,
    /// Up to [`COLUMN_LEVEL_GRANT_EXAMPLE_LIMIT`] affected column names,
    /// sorted; the overflow count lives in `skipped_columns`. Capped at
    /// construction (like `UnsatisfiableWildcardGrant::examples`) so a wide
    /// table doesn't keep thousands of names resident per diagnostic.
    pub columns: Vec<String>,
    /// Number of additional affected columns beyond `columns`.
    pub skipped_columns: usize,
    pub privileges: std::collections::BTreeSet<Privilege>,
}

/// Maximum number of column names carried by a [`ColumnLevelGrantDiagnostic`];
/// the remainder is summarized as `skipped_columns` at aggregation time.
pub(crate) const COLUMN_LEVEL_GRANT_EXAMPLE_LIMIT: usize = 8;

impl std::fmt::Display for ColumnLevelGrantDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let privileges = self
            .privileges
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let mut columns = self.columns.join(", ");
        if self.skipped_columns > 0 {
            columns.push_str(&format!(", … (+{} more)", self.skipped_columns));
        }
        write!(
            f,
            "ColumnLevelGrant: \"{}\".\"{}\" has column-level grant(s) [{privileges}] to \"{}\" \
             on column(s) [{columns}]; pgroles does not manage column-level privileges — they are \
             not diffed, revoked, or included in `generate` output. See \
             https://thepartly.github.io/pgroles/docs/limitations/ for details.",
            self.schema, self.relation, self.grantee
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsatisfiableWildcardObject {
    pub name: String,
    pub owner: String,
    pub privileges: std::collections::BTreeSet<Privilege>,
}

impl std::fmt::Display for UnsatisfiableWildcardObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let privileges = self
            .privileges
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        write!(
            f,
            "\"{}\" owned by \"{}\" missing [{}]",
            self.name, self.owner, privileges
        )
    }
}

#[derive(Debug, Clone)]
pub struct InspectionResult {
    pub graph: RoleGraph,
    pub diagnostics: InspectionDiagnostics,
    pub stats: InspectionStats,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InspectionStats {
    pub roles: usize,
    pub memberships: usize,
    pub schemas: usize,
    pub grants: usize,
    pub default_privileges: usize,
    pub phase_durations: BTreeMap<&'static str, Duration>,
    pub wildcard: WildcardInspectionStats,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WildcardInspectionStats {
    pub configured_grants: usize,
    pub configured_scopes: usize,
    pub inventory_objects: usize,
    pub unsatisfied_grants: usize,
    pub unsatisfied_scopes: usize,
    pub grantability_queries: usize,
    pub grantability_objects: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct WildcardGrantPattern {
    /// Grantee name. The reserved value `PUBLIC` means the pseudo-role;
    /// key construction parses it via `Grantee::parse`.
    pub role: String,
    pub object_type: pgroles_core::manifest::ObjectType,
    pub schema: String,
    /// The desired privileges for this wildcard grant. Used to construct a
    /// vacuously-satisfied wildcard when no objects of this type exist in the
    /// schema, so the diff engine sees exact parity and produces no change.
    pub privileges: std::collections::BTreeSet<pgroles_core::manifest::Privilege>,
}

/// An object scope for which the manifest declares PUBLIC rules (present or
/// absent). PUBLIC ACL rows enter the current graph only inside these scopes,
/// and only for the privileges the rules mention — pgroles never manages a
/// PUBLIC edge the manifest doesn't name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PublicObjectScope {
    pub object_type: pgroles_core::manifest::ObjectType,
    /// Schema containing the objects. `None` for schema- and database-typed
    /// targets (which put the schema/database name in `name`).
    pub schema: Option<String>,
    /// Object name, `"*"` for every object of the type in the schema, `None`
    /// for database targets.
    pub name: Option<String>,
    /// Union of the privileges named by rules for this scope; rows are
    /// filtered to this set.
    pub privileges: std::collections::BTreeSet<pgroles_core::manifest::Privilege>,
}

/// A default-privileges entry scope from the manifest, used to decide which
/// `pg_default_acl` layers to fetch and which PUBLIC rows to keep.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DefaultPrivScopePattern {
    /// The resolved owner (entry owner, or the manifest default_owner, or
    /// "postgres").
    pub owner: String,
    /// `None` means global scope (`pg_default_acl.defaclnamespace = 0`).
    pub schema: Option<String>,
    pub on_type: pgroles_core::manifest::ObjectType,
    /// Union of privileges from rules whose grantee is PUBLIC; empty when the
    /// entry has no PUBLIC rules, in which case PUBLIC rows are skipped.
    pub public_privileges: std::collections::BTreeSet<pgroles_core::manifest::Privilege>,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for what to inspect from the database.
///
/// Scoped to only the roles and schemas that the manifest manages, so we
/// don't pull in the entire pg_catalog.
#[derive(Debug, Clone)]
pub struct InspectConfig {
    /// The role names that the manifest manages (created by pgroles).
    /// Privileges and memberships are filtered to only include these roles.
    pub managed_roles: Vec<String>,

    /// The schema names that the manifest manages for schema-owner inspection.
    pub managed_schemas: Vec<String>,

    /// The schema names whose grants/default privileges are managed.
    pub privilege_schemas: Vec<String>,

    /// Whether to also inspect database-level privileges (CONNECT, CREATE, TEMPORARY).
    /// Usually only needed if the manifest includes database-level grants.
    pub include_database_privileges: bool,

    /// Concrete database names referenced by database-level grant rules.
    /// Inspection rejects any name other than `current_database()` so the
    /// per-database lock and ownership boundary cover every rendered change.
    pub(crate) database_targets: Vec<String>,

    /// Wildcard grant selectors from the desired manifest (present-ensure
    /// only — absence assertions must stay per-object).
    pub(crate) wildcard_grants: Vec<WildcardGrantPattern>,

    /// Object scopes with declared PUBLIC rules.
    pub(crate) public_object_scopes: Vec<PublicObjectScope>,

    /// Default-privilege entry scopes from the manifest.
    pub(crate) default_priv_scopes: Vec<DefaultPrivScopePattern>,
}

impl InspectConfig {
    /// Create an `InspectConfig` from an expanded manifest by extracting
    /// the unique set of managed role names and schema names.
    pub fn from_expanded(
        expanded: &pgroles_core::manifest::ExpandedManifest,
        include_database_privileges: bool,
    ) -> Self {
        use pgroles_core::manifest::{Ensure, ObjectType};

        let mut managed_roles: BTreeSet<String> = BTreeSet::new();
        let mut managed_schemas: BTreeSet<String> = BTreeSet::new();
        let mut database_targets: BTreeSet<String> = BTreeSet::new();
        // Key for deduplicating wildcard grants: (role, object_type, schema).
        type WildcardKey = (String, ObjectType, String);
        let mut wildcard_map: BTreeMap<WildcardKey, BTreeSet<pgroles_core::manifest::Privilege>> =
            BTreeMap::new();
        // Keyed by (object_type, schema, name) with privileges unioned across
        // present and absent rules.
        type PublicScopeKey = (ObjectType, Option<String>, Option<String>);
        let mut public_scope_map: BTreeMap<
            PublicScopeKey,
            BTreeSet<pgroles_core::manifest::Privilege>,
        > = BTreeMap::new();
        type DefaultScopeKey = (String, Option<String>, ObjectType);
        let mut default_scope_map: BTreeMap<
            DefaultScopeKey,
            BTreeSet<pgroles_core::manifest::Privilege>,
        > = BTreeMap::new();

        // Collect role names
        for role_def in &expanded.roles {
            managed_roles.insert(role_def.name.clone());
        }

        // Collect schema names from grants
        for grant in &expanded.grants {
            if grant.object.object_type == ObjectType::Database
                && let Some(name) = &grant.object.name
            {
                database_targets.insert(name.clone());
            }
            if let Some(ref schema) = grant.object.schema {
                managed_schemas.insert(schema.clone());
            }
            // Schema-level grants use the name field as the schema name
            if grant.object.object_type == ObjectType::Schema
                && let Some(ref name) = grant.object.name
            {
                managed_schemas.insert(name.clone());
            }
            // Absence assertions must stay per-object for the diff's
            // range-scan, so only present wildcards become patterns.
            if grant.object.name.as_deref() == Some("*")
                && grant.ensure == Ensure::Present
                && !matches!(
                    grant.object.object_type,
                    ObjectType::Schema | ObjectType::Database
                )
                && let Some(schema) = &grant.object.schema
            {
                let key = (grant.role.clone(), grant.object.object_type, schema.clone());
                wildcard_map
                    .entry(key)
                    .or_default()
                    .extend(grant.privileges.iter().copied());
            }
            if grant.role == "PUBLIC" {
                let key = (
                    grant.object.object_type,
                    grant.object.schema.clone(),
                    grant.object.name.clone(),
                );
                public_scope_map
                    .entry(key)
                    .or_default()
                    .extend(grant.privileges.iter().copied());
            }
        }

        // Collect schema names and scope patterns from default privileges
        for dp in &expanded.default_privileges {
            // expand_manifest validated the scope already; ignore entries it
            // would have rejected.
            let Ok(scope) = dp.resolved_scope() else {
                continue;
            };
            let schema = scope.schema().map(str::to_string);
            if let Some(schema) = &schema {
                managed_schemas.insert(schema.clone());
            }
            // Expansion has already resolved `default_owner` into every entry,
            // so a still-missing owner means the manifest set neither. That is
            // the same fallback the desired-state build applies.
            let owner = dp.owner.clone().unwrap_or_else(|| "postgres".to_string());
            for grant in &dp.grant {
                let entry = default_scope_map
                    .entry((owner.clone(), schema.clone(), grant.on_type))
                    .or_default();
                if grant.role.as_deref() == Some("PUBLIC") {
                    entry.extend(grant.privileges.iter().copied());
                }
            }
        }

        for schema in &expanded.schemas {
            managed_schemas.insert(schema.name.clone());
        }

        Self {
            managed_roles: managed_roles.into_iter().collect(),
            managed_schemas: managed_schemas.clone().into_iter().collect(),
            privilege_schemas: managed_schemas.into_iter().collect(),
            include_database_privileges,
            database_targets: database_targets.into_iter().collect(),
            wildcard_grants: wildcard_map
                .into_iter()
                .map(
                    |((role, object_type, schema), privileges)| WildcardGrantPattern {
                        role,
                        object_type,
                        schema,
                        privileges,
                    },
                )
                .collect(),
            public_object_scopes: public_scope_map
                .into_iter()
                .map(
                    |((object_type, schema, name), privileges)| PublicObjectScope {
                        object_type,
                        schema,
                        name,
                        privileges,
                    },
                )
                .collect(),
            default_priv_scopes: default_scope_map
                .into_iter()
                .map(
                    |((owner, schema, on_type), public_privileges)| DefaultPrivScopePattern {
                        owner,
                        schema,
                        on_type,
                        public_privileges,
                    },
                )
                .collect(),
        }
    }

    /// Create an `InspectConfig` from a managed scope plus an expanded desired
    /// manifest so current-state inspection can be restricted to composed policy
    /// boundaries.
    pub fn from_managed_scope(
        scope: &ManagedScope,
        expanded: &pgroles_core::manifest::ExpandedManifest,
        include_database_privileges: bool,
    ) -> Self {
        let base = Self::from_expanded(expanded, include_database_privileges);

        let has_bindings = |schema: &str| {
            scope
                .schemas
                .get(schema)
                .is_some_and(|managed| managed.bindings)
        };

        Self {
            managed_roles: scope.roles.iter().cloned().collect(),
            managed_schemas: scope.schemas.keys().cloned().collect(),
            privilege_schemas: scope
                .schemas
                .iter()
                .filter_map(|(schema, managed)| managed.bindings.then_some(schema.clone()))
                .collect(),
            include_database_privileges,
            database_targets: base.database_targets,
            wildcard_grants: base
                .wildcard_grants
                .into_iter()
                .filter(|pattern| has_bindings(&pattern.schema))
                .collect(),
            public_object_scopes: base
                .public_object_scopes
                .into_iter()
                .filter(|public_scope| match &public_scope.schema {
                    Some(schema) => has_bindings(schema),
                    // Schema-typed targets carry the schema in `name`;
                    // database targets pass through.
                    None => match public_scope.object_type {
                        pgroles_core::manifest::ObjectType::Schema => {
                            public_scope.name.as_deref().is_some_and(has_bindings)
                        }
                        _ => true,
                    },
                })
                .collect(),
            default_priv_scopes: base
                .default_priv_scopes
                .into_iter()
                .filter(|pattern| match &pattern.schema {
                    Some(schema) => has_bindings(schema),
                    // Global defaults belong to whoever owns the owner role.
                    // Composition already rejects a fragment declaring one for
                    // a role outside its scope, so reaching this branch means
                    // the owner was named in `scope.roles` without being
                    // defined. Dropping it silently would leave the rule
                    // planning nothing forever, so say so.
                    None => {
                        let owned = scope.roles.contains(&pattern.owner);
                        if !owned {
                            tracing::warn!(
                                owner = %pattern.owner,
                                on_type = %pattern.on_type,
                                "global default privileges declared for a role this policy does \
                                 not manage; the rule will not be inspected or reconciled"
                            );
                        }
                        owned
                    }
                })
                .collect(),
        }
    }

    /// The narrowest scope containing every one of `configs`.
    ///
    /// A [`RawInspection`] read over this scope covers each member, so one
    /// read can serve every config in the set. Wildcard patterns are merged
    /// per `(role, object_type, schema)` so a pattern's privileges are the
    /// union of what the members ask for; `include_database_privileges` is a
    /// logical OR, since a read that includes them serves a config that does
    /// not want them (the derivation drops them).
    pub fn union_of<'a, I>(configs: I) -> Self
    where
        I: IntoIterator<Item = &'a InspectConfig>,
    {
        let mut managed_roles: BTreeSet<String> = BTreeSet::new();
        let mut managed_schemas: BTreeSet<String> = BTreeSet::new();
        let mut privilege_schemas: BTreeSet<String> = BTreeSet::new();
        let mut include_database_privileges = false;
        let mut database_targets: BTreeSet<String> = BTreeSet::new();
        type WildcardKey = (String, pgroles_core::manifest::ObjectType, String);
        let mut wildcard_map: BTreeMap<WildcardKey, BTreeSet<pgroles_core::manifest::Privilege>> =
            BTreeMap::new();
        let mut default_priv_scopes: BTreeSet<DefaultPrivScopePattern> = BTreeSet::new();
        type PublicScopeKey = (
            pgroles_core::manifest::ObjectType,
            Option<String>,
            Option<String>,
        );
        let mut public_scope_map: BTreeMap<
            PublicScopeKey,
            BTreeSet<pgroles_core::manifest::Privilege>,
        > = BTreeMap::new();

        for config in configs {
            managed_roles.extend(config.managed_roles.iter().cloned());
            managed_schemas.extend(config.managed_schemas.iter().cloned());
            privilege_schemas.extend(config.privilege_schemas.iter().cloned());
            include_database_privileges |= config.include_database_privileges;
            database_targets.extend(config.database_targets.iter().cloned());
            for pattern in &config.wildcard_grants {
                wildcard_map
                    .entry((
                        pattern.role.clone(),
                        pattern.object_type,
                        pattern.schema.clone(),
                    ))
                    .or_default()
                    .extend(pattern.privileges.iter().copied());
            }
            default_priv_scopes.extend(config.default_priv_scopes.iter().cloned());
            for public_scope in &config.public_object_scopes {
                public_scope_map
                    .entry((
                        public_scope.object_type,
                        public_scope.schema.clone(),
                        public_scope.name.clone(),
                    ))
                    .or_default()
                    .extend(public_scope.privileges.iter().copied());
            }
        }

        Self {
            managed_roles: managed_roles.into_iter().collect(),
            managed_schemas: managed_schemas.into_iter().collect(),
            privilege_schemas: privilege_schemas.into_iter().collect(),
            include_database_privileges,
            database_targets: database_targets.into_iter().collect(),
            wildcard_grants: wildcard_map
                .into_iter()
                .map(
                    |((role, object_type, schema), privileges)| WildcardGrantPattern {
                        role,
                        object_type,
                        schema,
                        privileges,
                    },
                )
                .collect(),
            default_priv_scopes: default_priv_scopes.into_iter().collect(),
            public_object_scopes: public_scope_map
                .into_iter()
                .map(
                    |((object_type, schema, name), privileges)| PublicObjectScope {
                        object_type,
                        schema,
                        name,
                        privileges,
                    },
                )
                .collect(),
        }
    }

    /// Extend the managed role scope with additional explicit role names.
    pub fn with_additional_roles<I>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        let mut managed_roles: BTreeSet<String> = self.managed_roles.into_iter().collect();
        managed_roles.extend(roles);
        self.managed_roles = managed_roles.into_iter().collect();
        self
    }
}

// ---------------------------------------------------------------------------
// Top-level inspect function
// ---------------------------------------------------------------------------

/// Configuration for unscoped inspection (used by `generate` command).
#[derive(Debug, Clone)]
pub struct InspectAllConfig {
    /// Whether to exclude PostgreSQL system roles (pg_*, postgres).
    pub exclude_system_roles: bool,
}

/// Inspect all non-system roles and their privileges for manifest generation.
///
/// Unlike [`inspect`], this does not require a manifest to scope the query.
/// It discovers all user-defined roles, schemas they have access to, and
/// reconstructs the full RoleGraph.
pub async fn inspect_all(
    pool: &PgPool,
    config: &InspectAllConfig,
) -> Result<RoleGraph, InspectError> {
    let mut graph = RoleGraph::default();

    // Fetch all non-system roles.
    // fetch_roles(None) already excludes pg_* and postgres system roles.
    // The exclude_system_roles flag is reserved for future use with broader filtering.
    let _ = config.exclude_system_roles;
    let role_rows = fetch_roles(pool, None).await?;
    for row in &role_rows {
        graph.roles.insert(row.rolname.clone(), row.to_role_state());
    }
    debug!(found = graph.roles.len(), "roles discovered for generation");

    let role_names: Vec<String> = graph.roles.keys().cloned().collect();
    let role_refs: Vec<&str> = role_names.iter().map(|s| s.as_str()).collect();

    // Discover schemas these roles have access to
    let schema_rows: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT nspname::text FROM pg_namespace
        WHERE nspname NOT LIKE 'pg_%'
          AND nspname <> 'information_schema'
        ORDER BY nspname
        "#,
    )
    .fetch_all(pool)
    .await?;
    let schema_names: Vec<String> = schema_rows.into_iter().map(|r| r.0).collect();
    let schema_refs: Vec<&str> = schema_names.iter().map(|s| s.as_str()).collect();

    // Memberships
    let membership_rows = fetch_memberships(pool, Some(&role_refs)).await?;
    for row in &membership_rows {
        graph.memberships.insert(row.to_membership_edge());
    }

    // Schemas
    let schema_rows = fetch_schemas(pool, &schema_refs).await?;
    for row in &schema_rows {
        graph.schemas.insert(
            row.schema_name.clone(),
            pgroles_core::model::SchemaState {
                owner: Some(row.owner_name.clone()),
                owner_privileges: row.owner_privileges(),
            },
        );
    }

    if graph.roles.is_empty() && graph.schemas.is_empty() {
        return Ok(graph);
    }

    // Object privileges (no wildcard patterns for unscoped inspection)
    if !schema_refs.is_empty() {
        // No wildcard patterns and no PUBLIC scopes: `generate` reads only
        // explicit managed-role state and never invents PUBLIC or absence
        // policy from what it finds.
        let privileges =
            privileges::fetch_privileges_with_wildcards(pool, &schema_refs, &role_refs, &[], &[])
                .await?;
        for (key, state) in privileges.grants {
            graph.grants.insert(key, state);
        }
        // Owner-inherent entries are never exported: nobody granted them.
        graph.inherent_grants.extend(privileges.inherent);
        remove_redundant_schema_owner_grants(&mut graph);
    }

    // Database privileges
    let (db_grants, db_inherent) = fetch_database_privileges(pool, &role_refs).await?;
    for (key, state) in db_grants {
        graph.grants.insert(key, state);
    }
    graph.inherent_grants.extend(db_inherent);

    // Default privileges (schema layer only — no declared scopes, so no
    // global rows and no PUBLIC rows)
    if !schema_refs.is_empty() {
        let default_privs =
            defaults::fetch_default_privileges(pool, &schema_refs, &role_refs, &[]).await?;
        for (key, state) in default_privs {
            graph.default_privileges.insert(key, state);
        }
    }

    Ok(graph)
}

/// Inspect the current state of the database and build a `RoleGraph`.
///
/// Queries roles, memberships, object privileges, and default privileges,
/// scoped to the managed set defined by `config`.
pub async fn inspect(pool: &PgPool, config: &InspectConfig) -> Result<RoleGraph, InspectError> {
    Ok(inspect_with_diagnostics(pool, config).await?.graph)
}

/// Inspect the current database state and return diagnostics for desired-state
/// intent that cannot be satisfied by the current executor.
///
/// Read-then-derive over a single config: exactly the shared path
/// ([`RawInspection`]) with a scope of one, so a caller inspecting one config
/// and a caller deriving it from a wider snapshot run the same code.
pub async fn inspect_with_diagnostics(
    pool: &PgPool,
    config: &InspectConfig,
) -> Result<InspectionResult, InspectError> {
    let raw = RawInspection::read(pool, config).await?;
    raw.derive(pool, config).await
}

/// Fetch the names of all non-system schemas in the target database.
///
/// Used for pre-flight validation — the operator checks that every schema
/// referenced by a policy exists before rendering GRANT statements that would
/// otherwise fail mid-transaction with `schema "X" does not exist`.
///
/// Returns a [`BTreeSet`] for efficient membership lookup. Excludes
/// `pg_catalog`, `pg_toast`, other `pg_*` schemas, and `information_schema`.
pub async fn fetch_existing_schemas(
    pool: &PgPool,
) -> Result<std::collections::BTreeSet<String>, InspectError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        r#"
        SELECT nspname::text FROM pg_namespace
        WHERE nspname NOT LIKE 'pg_%'
          AND nspname <> 'information_schema'
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

#[derive(Debug, sqlx::FromRow)]
pub struct SchemaRow {
    pub schema_name: String,
    pub owner_name: String,
    pub owner_has_create: bool,
    pub owner_has_usage: bool,
}

impl SchemaRow {
    fn owner_privileges(&self) -> BTreeSet<Privilege> {
        let mut privileges = BTreeSet::new();
        if self.owner_has_create {
            privileges.insert(Privilege::Create);
        }
        if self.owner_has_usage {
            privileges.insert(Privilege::Usage);
        }
        privileges
    }
}

pub async fn fetch_schemas(
    pool: &PgPool,
    managed_schemas: &[&str],
) -> Result<Vec<SchemaRow>, InspectError> {
    let rows = sqlx::query_as::<_, SchemaRow>(
        r#"
        SELECT
            n.nspname AS schema_name,
            owner_role.rolname AS owner_name,
            has_schema_privilege(owner_role.rolname, n.nspname, 'CREATE') AS owner_has_create,
            has_schema_privilege(owner_role.rolname, n.nspname, 'USAGE') AS owner_has_usage
        FROM pg_namespace n
        JOIN pg_roles owner_role ON owner_role.oid = n.nspowner
        WHERE n.nspname = ANY($1)
        ORDER BY n.nspname
        "#,
    )
    .bind(managed_schemas)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub(crate) fn remove_redundant_schema_owner_grants(graph: &mut RoleGraph) {
    // Keep ordinary owner CREATE/USAGE management in SchemaState instead of the
    // grants map. This avoids noisy self-grants while still preserving drift
    // when the owner's ordinary privileges have been revoked.
    graph.grants.retain(|key, _| {
        if key.object_type != pgroles_core::manifest::ObjectType::Schema {
            return true;
        }

        let Some(schema_name) = key.name.as_deref() else {
            return true;
        };

        let Some(schema_state) = graph.schemas.get(schema_name) else {
            return true;
        };

        schema_state.owner.as_deref() != Some(key.role.as_str())
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pgroles_core::manifest::{expand_manifest, parse_manifest};
    use pgroles_core::ownership::ManagedSchemaScope;

    #[test]
    fn inspect_config_from_expanded_manifest() {
        let yaml = r#"
default_owner: app_owner

profiles:
  editor:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT, INSERT]
        object: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT, INSERT]
        on_type: table

schemas:
  - name: inventory
    profiles: [editor]
  - name: catalog
    profiles: [editor]

roles:
  - name: analytics
    login: true

grants:
  - role: analytics
    privileges: [CONNECT]
    object: { type: database, name: mydb }
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let config = InspectConfig::from_expanded(&expanded, true);

        // Managed roles: inventory-editor, catalog-editor, analytics
        assert_eq!(config.managed_roles.len(), 3);
        assert!(
            config
                .managed_roles
                .contains(&"inventory-editor".to_string())
        );
        assert!(config.managed_roles.contains(&"catalog-editor".to_string()));
        assert!(config.managed_roles.contains(&"analytics".to_string()));

        // Managed schemas: inventory, catalog
        assert_eq!(config.managed_schemas.len(), 2);
        assert!(config.managed_schemas.contains(&"inventory".to_string()));
        assert!(config.managed_schemas.contains(&"catalog".to_string()));

        assert!(config.include_database_privileges);
        assert_eq!(config.database_targets, vec!["mydb"]);
        assert_eq!(config.privilege_schemas.len(), 2);
        assert_eq!(config.wildcard_grants.len(), 2);
    }

    #[test]
    fn inspect_config_can_include_retired_roles() {
        let yaml = r#"
roles:
  - name: analytics
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let config = InspectConfig::from_expanded(&expanded, false)
            .with_additional_roles(vec!["legacy-app".to_string(), "analytics".to_string()]);

        assert_eq!(config.managed_roles.len(), 2);
        assert!(config.managed_roles.contains(&"analytics".to_string()));
        assert!(config.managed_roles.contains(&"legacy-app".to_string()));
    }

    #[test]
    fn inspect_config_from_managed_scope_limits_privileges_to_binding_schemas() {
        let yaml = r#"
default_owner: app_owner

profiles:
  editor:
    grants:
      - privileges: [USAGE]
        object: { type: schema }

schemas:
  - name: inventory
    owner: app_owner
    profiles: [editor]

roles:
  - name: app_owner
    login: false
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let scope = ManagedScope {
            roles: BTreeSet::from(["app_owner".to_string(), "inventory-editor".to_string()]),
            schemas: BTreeMap::from([(
                "inventory".to_string(),
                ManagedSchemaScope {
                    owner: true,
                    bindings: false,
                },
            )]),
        };

        let config = InspectConfig::from_managed_scope(&scope, &expanded, false);

        assert_eq!(config.managed_schemas, vec!["inventory".to_string()]);
        assert!(config.privilege_schemas.is_empty());
        assert!(config.wildcard_grants.is_empty());
    }

    #[test]
    fn remove_redundant_schema_owner_grants_keeps_only_non_owner_schema_grants() {
        let mut graph = RoleGraph::default();
        graph.schemas.insert(
            "inventory".to_string(),
            pgroles_core::model::SchemaState {
                owner: Some("inventory_owner".to_string()),
                owner_privileges: [pgroles_core::manifest::Privilege::Create]
                    .into_iter()
                    .collect(),
            },
        );
        graph.grants.insert(
            pgroles_core::model::GrantKey {
                role: "inventory_owner".into(),
                object_type: pgroles_core::manifest::ObjectType::Schema,
                schema: None,
                name: Some("inventory".to_string()),
            },
            pgroles_core::model::GrantState {
                privileges: [pgroles_core::manifest::Privilege::Usage]
                    .into_iter()
                    .collect(),
            },
        );
        graph.grants.insert(
            pgroles_core::model::GrantKey {
                role: "inventory_reader".into(),
                object_type: pgroles_core::manifest::ObjectType::Schema,
                schema: None,
                name: Some("inventory".to_string()),
            },
            pgroles_core::model::GrantState {
                privileges: [pgroles_core::manifest::Privilege::Usage]
                    .into_iter()
                    .collect(),
            },
        );

        remove_redundant_schema_owner_grants(&mut graph);

        assert_eq!(graph.grants.len(), 1);
        assert!(
            graph
                .grants
                .keys()
                .all(|key| key.role.as_str() == "inventory_reader")
        );
    }

    fn sample_column_level_grant(grantee: &str, columns: &[&str]) -> ColumnLevelGrantDiagnostic {
        ColumnLevelGrantDiagnostic {
            schema: "inventory".to_string(),
            relation: "widgets".to_string(),
            grantee: grantee.to_string(),
            columns: columns.iter().map(|c| c.to_string()).collect(),
            skipped_columns: 0,
            privileges: BTreeSet::from([Privilege::Select]),
        }
    }

    #[test]
    fn column_level_grant_display_names_schema_relation_and_grantee() {
        let diagnostic = sample_column_level_grant("analytics", &["secret"]);
        let rendered = diagnostic.to_string();

        assert!(rendered.contains("ColumnLevelGrant"));
        assert!(rendered.contains("\"inventory\".\"widgets\""));
        assert!(rendered.contains("\"analytics\""));
        assert!(rendered.contains("SELECT"));
        assert!(rendered.contains("secret"));
        assert!(rendered.contains("does not manage column-level privileges"));
        assert!(rendered.contains("https://thepartly.github.io/pgroles/docs/limitations/"));
    }

    #[test]
    fn column_level_grant_display_renders_public_grantee_explicitly() {
        let diagnostic = sample_column_level_grant("PUBLIC", &["secret"]);
        let rendered = diagnostic.to_string();

        assert!(rendered.contains("\"PUBLIC\""));
    }

    #[test]
    fn column_level_grant_display_summarizes_skipped_columns() {
        // Capping happens at aggregation time (see privileges.rs tests);
        // Display just renders the carried examples plus the overflow count.
        let mut diagnostic = sample_column_level_grant("analytics", &["col_a", "col_b"]);
        diagnostic.skipped_columns = 4;

        let rendered = diagnostic.to_string();
        assert!(rendered.contains("col_a, col_b, … (+4 more)"));
    }

    #[test]
    fn inspection_diagnostics_is_empty_requires_both_fields_empty() {
        let mut diagnostics = InspectionDiagnostics::default();
        assert!(diagnostics.is_empty());

        diagnostics
            .column_level_grants
            .push(sample_column_level_grant("analytics", &["secret"]));
        assert!(!diagnostics.is_empty());
    }

    #[test]
    fn inspection_diagnostics_display_includes_column_level_grants() {
        let mut diagnostics = InspectionDiagnostics::default();
        diagnostics
            .column_level_grants
            .push(sample_column_level_grant("analytics", &["secret"]));

        let rendered = diagnostics.to_string();
        assert!(rendered.contains("ColumnLevelGrant"));
    }

    #[test]
    fn inspection_diagnostics_display_joins_wildcard_and_column_level_diagnostics() {
        let mut diagnostics = InspectionDiagnostics::default();
        diagnostics
            .unsatisfiable_wildcard_grants
            .push(UnsatisfiableWildcardGrant {
                role: "reader".to_string(),
                object_type: ObjectType::Table,
                schema: "inventory".to_string(),
                privileges: BTreeSet::from([Privilege::Select]),
                executor: "app_owner".to_string(),
                skipped_count: 1,
                examples: vec![],
            });
        diagnostics
            .column_level_grants
            .push(sample_column_level_grant("analytics", &["secret"]));

        let rendered = diagnostics.to_string();
        let wildcard_pos = rendered.find("UnsatisfiableWildcardGrant").unwrap();
        let column_pos = rendered.find("ColumnLevelGrant").unwrap();
        assert!(
            wildcard_pos < column_pos,
            "wildcard diagnostics should render before column-level diagnostics"
        );
        // Both diagnostics must be on their own line.
        assert_eq!(rendered.lines().count(), 2);
    }
}
