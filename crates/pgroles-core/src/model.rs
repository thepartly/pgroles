//! Normalized role-graph model.
//!
//! These types represent the **desired state** or the **current state** of a
//! PostgreSQL cluster's roles, privileges, default privileges, and memberships.
//! Both the manifest expansion and the database inspector produce these types,
//! and the diff engine compares two `RoleGraph` instances.

use std::collections::{BTreeMap, BTreeSet};

use crate::manifest::{Ensure, ExpandedManifest, Grant, ObjectType, Privilege, RoleDefinition};

// ---------------------------------------------------------------------------
// Role attributes
// ---------------------------------------------------------------------------

/// The set of PostgreSQL role attributes we manage.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RoleState {
    pub login: bool,
    pub superuser: bool,
    pub createdb: bool,
    pub createrole: bool,
    pub inherit: bool,
    pub replication: bool,
    pub bypassrls: bool,
    pub connection_limit: i32,
    pub comment: Option<String>,
    /// Password expiration timestamp (ISO 8601). Maps to PostgreSQL `VALID UNTIL`.
    /// `None` means no expiration (PostgreSQL default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_valid_until: Option<String>,
    /// Role-level configuration parameter defaults (`ALTER ROLE ... SET`),
    /// keyed by lowercase parameter name. Mirrors the cluster-wide entries in
    /// `pg_roles.rolconfig` (per-database `ALTER ROLE ... IN DATABASE` settings
    /// are not managed).
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub config: BTreeMap<String, String>,
}

impl Default for RoleState {
    fn default() -> Self {
        Self {
            login: false,
            superuser: false,
            createdb: false,
            createrole: false,
            inherit: true, // PostgreSQL default
            replication: false,
            bypassrls: false,
            connection_limit: -1, // unlimited
            comment: None,
            password_valid_until: None,
            config: BTreeMap::new(),
        }
    }
}

impl RoleState {
    /// Build a `RoleState` from a manifest `RoleDefinition`, using PostgreSQL
    /// defaults for any unspecified attribute.
    pub fn from_definition(definition: &RoleDefinition) -> Self {
        let defaults = Self::default();
        Self {
            login: definition.login.unwrap_or(defaults.login),
            superuser: definition.superuser.unwrap_or(defaults.superuser),
            createdb: definition.createdb.unwrap_or(defaults.createdb),
            createrole: definition.createrole.unwrap_or(defaults.createrole),
            inherit: definition.inherit.unwrap_or(defaults.inherit),
            replication: definition.replication.unwrap_or(defaults.replication),
            bypassrls: definition.bypassrls.unwrap_or(defaults.bypassrls),
            connection_limit: definition
                .connection_limit
                .unwrap_or(defaults.connection_limit),
            comment: definition.comment.clone(),
            password_valid_until: definition.password_valid_until.clone(),
            // GUC names are case-insensitive; normalize to lowercase so the
            // desired state compares cleanly against pg_roles.rolconfig.
            // List-quoted parameters (search_path, ...) are canonicalized
            // element-wise so quoting and spacing differences don't diff.
            config: definition
                .config
                .iter()
                .map(|(name, value)| {
                    let name = name.to_ascii_lowercase();
                    let value = if crate::guc::is_list_quote_parameter(&name) {
                        crate::guc::canonicalize_list_guc_value(&value.0)
                    } else {
                        value.0.clone()
                    };
                    (name, value)
                })
                .collect(),
        }
    }

    /// Return a list of attribute names that differ between `self` and `other`.
    pub fn changed_attributes(&self, other: &RoleState) -> Vec<RoleAttribute> {
        let mut changes = Vec::new();
        if self.login != other.login {
            changes.push(RoleAttribute::Login(other.login));
        }
        if self.superuser != other.superuser {
            changes.push(RoleAttribute::Superuser(other.superuser));
        }
        if self.createdb != other.createdb {
            changes.push(RoleAttribute::Createdb(other.createdb));
        }
        if self.createrole != other.createrole {
            changes.push(RoleAttribute::Createrole(other.createrole));
        }
        if self.inherit != other.inherit {
            changes.push(RoleAttribute::Inherit(other.inherit));
        }
        if self.replication != other.replication {
            changes.push(RoleAttribute::Replication(other.replication));
        }
        if self.bypassrls != other.bypassrls {
            changes.push(RoleAttribute::Bypassrls(other.bypassrls));
        }
        if self.connection_limit != other.connection_limit {
            changes.push(RoleAttribute::ConnectionLimit(other.connection_limit));
        }
        if self.password_valid_until != other.password_valid_until {
            changes.push(RoleAttribute::ValidUntil(
                other.password_valid_until.clone(),
            ));
        }
        for (parameter, value) in &other.config {
            if self.config.get(parameter) != Some(value) {
                changes.push(RoleAttribute::SetConfig(parameter.clone(), value.clone()));
            }
        }
        for parameter in self.config.keys() {
            if !other.config.contains_key(parameter) {
                changes.push(RoleAttribute::ResetConfig(parameter.clone()));
            }
        }
        changes
    }
}

/// A single attribute change on a role, used by `AlterRole`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum RoleAttribute {
    Login(bool),
    Superuser(bool),
    Createdb(bool),
    Createrole(bool),
    Inherit(bool),
    Replication(bool),
    Bypassrls(bool),
    ConnectionLimit(i32),
    /// Password expiration change. `None` removes the expiration (`VALID UNTIL 'infinity'`).
    ValidUntil(Option<String>),
    /// Set a role-level configuration default (`ALTER ROLE ... SET name = value`).
    SetConfig(String, String),
    /// Remove a role-level configuration default (`ALTER ROLE ... RESET name`).
    ResetConfig(String),
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

/// The schema state managed by pgroles.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SchemaState {
    /// Desired owner for the schema. `None` means ensure existence only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// The schema owner's ordinary privileges on the schema itself.
    ///
    /// PostgreSQL lets owners revoke their own CREATE/USAGE privileges, so we
    /// track the effective state separately from grant rows.
    #[serde(skip_serializing_if = "BTreeSet::is_empty", default)]
    pub owner_privileges: BTreeSet<Privilege>,
}

// ---------------------------------------------------------------------------
// Grantees and scopes
// ---------------------------------------------------------------------------

/// A privilege grantee: either an ordinary role or the PostgreSQL PUBLIC
/// pseudo-role (ACL grantee OID 0).
///
/// PUBLIC is typed rather than spelled as a magic string so that SQL rendering
/// can never quote it (`"PUBLIC"` would name a real role) and so a role
/// literally named `PUBLIC` can never be confused with the pseudo-role.
/// `Public` sorts before every role name, which keeps BTreeMap output
/// deterministic.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Grantee {
    Public,
    Role(String),
}

/// How the PUBLIC pseudo-role spells itself wherever a grantee is carried as a
/// bare string.
pub const PUBLIC_ROLE: &str = "PUBLIC";

impl Grantee {
    /// Parse a manifest grantee string. The exact-uppercase `PUBLIC` is the
    /// pseudo-role; everything else is a role name.
    pub fn parse(s: &str) -> Self {
        if s == PUBLIC_ROLE {
            Grantee::Public
        } else {
            Grantee::Role(s.to_string())
        }
    }

    pub fn is_public(&self) -> bool {
        matches!(self, Grantee::Public)
    }

    pub fn as_str(&self) -> &str {
        match self {
            Grantee::Public => PUBLIC_ROLE,
            Grantee::Role(name) => name,
        }
    }
}

impl std::fmt::Display for Grantee {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&str> for Grantee {
    fn from(s: &str) -> Self {
        Grantee::parse(s)
    }
}

// Serialized as a plain string so plan JSON keeps the shape it had when the
// grantee was a `String`.
impl serde::Serialize for Grantee {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Where a default-privilege rule applies.
///
/// `Global` is the owner-wide layer (`pg_default_acl.defaclnamespace = 0`),
/// which affects every schema in the database and renders without an
/// `IN SCHEMA` clause. `Global` sorts before `Schema` so the global layer
/// appears first in deterministic output.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DefaultPrivilegeScope {
    Global,
    Schema { schema: String },
}

impl DefaultPrivilegeScope {
    pub fn schema(&self) -> Option<&str> {
        match self {
            DefaultPrivilegeScope::Global => None,
            DefaultPrivilegeScope::Schema { schema } => Some(schema),
        }
    }
}

impl std::fmt::Display for DefaultPrivilegeScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DefaultPrivilegeScope::Global => write!(f, "global scope"),
            DefaultPrivilegeScope::Schema { schema } => write!(f, "schema \"{schema}\""),
        }
    }
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

/// Unique key identifying a grant target — (grantee, object_type, schema, name).
///
/// We use `Ord` so these can live in a `BTreeMap` for deterministic output.
/// The field order also matters for the diff engine: absence assertions with a
/// wildcard name range-scan all keys sharing the (role, object_type, schema)
/// prefix, which needs `name` to be the last field.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct GrantKey {
    /// The grantee receiving the privilege.
    pub role: Grantee,
    /// The kind of object.
    pub object_type: ObjectType,
    /// Schema name. `None` for schema-level and database-level grants.
    pub schema: Option<String>,
    /// Object name, `"*"` for all-objects wildcard, `None` for schema-level grants.
    pub name: Option<String>,
}

/// The privilege set on a particular grant target.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GrantState {
    pub privileges: BTreeSet<Privilege>,
}

// ---------------------------------------------------------------------------
// Default privileges
// ---------------------------------------------------------------------------

/// Unique key identifying a default privilege rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct DefaultPrivKey {
    /// The owner role context (whose newly-created objects get these defaults).
    pub owner: String,
    /// Where the default applies: one schema, or owner-wide.
    pub scope: DefaultPrivilegeScope,
    /// The type of object affected.
    pub on_type: ObjectType,
    /// The grantee.
    pub grantee: Grantee,
}

/// The privilege set for a default privilege rule.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DefaultPrivState {
    pub privileges: BTreeSet<Privilege>,
}

// ---------------------------------------------------------------------------
// Memberships
// ---------------------------------------------------------------------------

/// A membership edge — "member belongs to role".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
pub struct MembershipEdge {
    /// The group role.
    pub role: String,
    /// The member role (may be external, e.g. an email address).
    pub member: String,
    /// Whether the member inherits the role's privileges.
    pub inherit: bool,
    /// Whether the member can administer the role.
    pub admin: bool,
}

// ---------------------------------------------------------------------------
// RoleGraph — the top-level state container
// ---------------------------------------------------------------------------

/// Complete state of managed roles, grants, default privileges, and memberships.
///
/// Both the manifest expander and the database inspector produce this type.
/// The diff engine compares two `RoleGraph` instances to compute changes.
#[derive(Debug, Clone, Default)]
pub struct RoleGraph {
    /// Managed roles, keyed by role name.
    pub roles: BTreeMap<String, RoleState>,
    /// Managed schemas, keyed by schema name.
    pub schemas: BTreeMap<String, SchemaState>,
    /// Object privilege grants, keyed by grant target.
    pub grants: BTreeMap<GrantKey, GrantState>,
    /// Default privilege rules, keyed by (owner, scope, type, grantee).
    pub default_privileges: BTreeMap<DefaultPrivKey, DefaultPrivState>,
    /// Membership edges.
    pub memberships: BTreeSet<MembershipEdge>,
    /// Privileges asserted absent per grant target (`ensure: absent`).
    /// Only the desired graph populates this; inspection leaves it empty.
    pub grant_absences: BTreeMap<GrantKey, BTreeSet<Privilege>>,
    /// Privileges asserted absent per default-privilege rule.
    /// Only the desired graph populates this; inspection leaves it empty.
    pub default_privilege_absences: BTreeMap<DefaultPrivKey, BTreeSet<Privilege>>,
    /// Grant targets whose current ACL entry belongs to the object's owner.
    ///
    /// PostgreSQL records a grantee==owner entry carrying the owner's
    /// inherent privileges as soon as any grant materializes an object's
    /// ACL. Inspection keeps those entries here rather than in `grants`
    /// semantics alone: the diff engine never revokes them (the privilege
    /// is intrinsic and revoking breaks owner DML and FK key-share checks)
    /// and treats them as covering any declared grant on the same target,
    /// so declaring privileges on an owner's own objects still converges.
    /// Only populated by inspection.
    pub inherent_grants: BTreeSet<GrantKey>,
}

impl RoleGraph {
    /// Build a `RoleGraph` from an `ExpandedManifest`.
    ///
    /// This converts the manifest's user-facing types into the normalized model
    /// that the diff engine operates on.
    pub fn from_expanded(
        expanded: &ExpandedManifest,
        default_owner: Option<&str>,
    ) -> Result<Self, crate::manifest::ManifestError> {
        let mut graph = Self::default();

        // --- Roles ---
        for role_def in &expanded.roles {
            let state = RoleState::from_definition(role_def);
            graph.roles.insert(role_def.name.clone(), state);
        }

        // --- Schemas ---
        for schema in &expanded.schemas {
            let owner = schema.owner.clone();
            graph.schemas.insert(
                schema.name.clone(),
                SchemaState {
                    owner_privileges: owner
                        .as_deref()
                        .map(default_schema_owner_privileges)
                        .unwrap_or_default(),
                    owner,
                },
            );
        }

        // --- Grants ---
        for grant in &expanded.grants {
            let key = grant_key_from_manifest(grant);
            let privileges = match grant.ensure {
                Ensure::Present => {
                    &mut graph
                        .grants
                        .entry(key)
                        .or_insert_with(|| GrantState {
                            privileges: BTreeSet::new(),
                        })
                        .privileges
                }
                Ensure::Absent => graph.grant_absences.entry(key).or_default(),
            };
            for privilege in &grant.privileges {
                privileges.insert(*privilege);
            }
        }

        // --- Default privileges ---
        for default_priv in &expanded.default_privileges {
            let owner = default_priv
                .owner
                .as_deref()
                .or(default_owner)
                .unwrap_or("postgres")
                .to_string();
            let scope = default_priv.resolved_scope()?;

            for grant in &default_priv.grant {
                let grantee = grant.role.as_deref().map(Grantee::parse).ok_or_else(|| {
                    crate::manifest::ManifestError::MissingDefaultPrivilegeRole {
                        scope: scope.to_string(),
                    }
                })?;

                let key = DefaultPrivKey {
                    owner: owner.clone(),
                    scope: scope.clone(),
                    on_type: grant.on_type,
                    grantee,
                };

                let privileges = match grant.ensure {
                    Ensure::Present => {
                        &mut graph
                            .default_privileges
                            .entry(key)
                            .or_insert_with(|| DefaultPrivState {
                                privileges: BTreeSet::new(),
                            })
                            .privileges
                    }
                    Ensure::Absent => graph.default_privilege_absences.entry(key).or_default(),
                };
                for privilege in &grant.privileges {
                    privileges.insert(*privilege);
                }
            }
        }

        // --- Memberships ---
        for membership in &expanded.memberships {
            for member_spec in &membership.members {
                graph.memberships.insert(MembershipEdge {
                    role: membership.role.clone(),
                    member: member_spec.name.clone(),
                    inherit: member_spec.inherit(),
                    admin: member_spec.admin(),
                });
            }
        }

        Ok(graph)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn grant_key_from_manifest(grant: &Grant) -> GrantKey {
    GrantKey {
        role: Grantee::parse(&grant.role),
        object_type: grant.object.object_type,
        schema: grant.object.schema.clone(),
        name: grant.object.name.clone(),
    }
}

pub fn default_schema_owner_privileges(_owner: &str) -> BTreeSet<Privilege> {
    [Privilege::Create, Privilege::Usage].into_iter().collect()
}

// ---------------------------------------------------------------------------
// Implement Ord for ObjectType and Privilege so we can use them in BTreeSet/BTreeMap
// ---------------------------------------------------------------------------

impl PartialOrd for ObjectType {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ObjectType {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

impl PartialOrd for Privilege {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Privilege {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{expand_manifest, parse_manifest};

    #[test]
    fn role_state_defaults_match_postgres() {
        let state = RoleState::default();
        assert!(!state.login);
        assert!(!state.superuser);
        assert!(!state.createdb);
        assert!(!state.createrole);
        assert!(state.inherit); // PG default is INHERIT
        assert!(!state.replication);
        assert!(!state.bypassrls);
        assert_eq!(state.connection_limit, -1);
    }

    #[test]
    fn role_state_from_definition_applies_overrides() {
        let definition = RoleDefinition {
            name: "test".to_string(),
            external: false,
            preserve_undeclared_grants: false,
            login: Some(true),
            superuser: None,
            createdb: Some(true),
            createrole: None,
            inherit: Some(false),
            replication: None,
            bypassrls: None,
            connection_limit: Some(10),
            comment: Some("test role".to_string()),
            password: None,
            password_valid_until: Some("2025-12-31T00:00:00Z".to_string()),
            config: Default::default(),
        };
        let state = RoleState::from_definition(&definition);
        assert!(state.login);
        assert!(!state.superuser); // default
        assert!(state.createdb);
        assert!(!state.createrole); // default
        assert!(!state.inherit); // overridden
        assert_eq!(state.connection_limit, 10);
        assert_eq!(state.comment, Some("test role".to_string()));
        assert_eq!(
            state.password_valid_until,
            Some("2025-12-31T00:00:00Z".to_string())
        );
    }

    #[test]
    fn changed_attributes_detects_differences() {
        let current = RoleState::default();
        let desired = RoleState {
            login: true,
            connection_limit: 5,
            ..RoleState::default()
        };
        let changes = current.changed_attributes(&desired);
        assert_eq!(changes.len(), 2);
        assert!(changes.contains(&RoleAttribute::Login(true)));
        assert!(changes.contains(&RoleAttribute::ConnectionLimit(5)));
    }

    #[test]
    fn changed_attributes_empty_when_equal() {
        let state = RoleState::default();
        assert!(state.changed_attributes(&state.clone()).is_empty());
    }

    #[test]
    fn changed_attributes_detects_config_set_change_and_reset() {
        let current = RoleState {
            config: [
                ("role".to_string(), "combined".to_string()),
                ("statement_timeout".to_string(), "30s".to_string()),
            ]
            .into_iter()
            .collect(),
            ..RoleState::default()
        };
        let desired = RoleState {
            config: [
                ("role".to_string(), "combined".to_string()),
                ("search_path".to_string(), "app".to_string()),
            ]
            .into_iter()
            .collect(),
            ..RoleState::default()
        };
        let changes = current.changed_attributes(&desired);
        assert_eq!(changes.len(), 2);
        assert!(changes.contains(&RoleAttribute::SetConfig(
            "search_path".to_string(),
            "app".to_string()
        )));
        assert!(changes.contains(&RoleAttribute::ResetConfig("statement_timeout".to_string())));
        // Unchanged `role` setting produces no change.
        assert!(
            !changes
                .iter()
                .any(|c| matches!(c, RoleAttribute::SetConfig(p, _) if p == "role"))
        );
    }

    #[test]
    fn profile_config_flows_through_to_generated_role_state() {
        // The generated role's `config` comes entirely from `expand_manifest`
        // substituting the profile's config — `RoleState::from_definition`
        // and `RoleGraph::from_expanded` need no changes to support it, since
        // generated roles are ordinary `RoleDefinition`s by the time they
        // reach this layer. This test is the proof, not an assumption.
        let yaml = r#"
profiles:
  editor:
    login: true
    config:
      search_path: "{schema}"
      statement_timeout: "30s"

schemas:
  - name: inventory
    profiles: [editor]
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let graph = RoleGraph::from_expanded(&expanded, None).unwrap();

        let role = graph
            .roles
            .get("inventory-editor")
            .expect("generated role should be present");
        assert_eq!(
            role.config.get("search_path").map(String::as_str),
            Some("inventory")
        );
        assert_eq!(
            role.config.get("statement_timeout").map(String::as_str),
            Some("30s")
        );
    }

    #[test]
    fn from_definition_lowercases_config_parameter_names() {
        let yaml = r#"
roles:
  - name: blue
    login: true
    config:
      Role: combined
      statement_timeout: "30000"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let graph = RoleGraph::from_expanded(&expand_manifest(&manifest).unwrap(), None).unwrap();
        let config = &graph.roles["blue"].config;
        assert_eq!(config.get("role").map(String::as_str), Some("combined"));
        assert_eq!(
            config.get("statement_timeout").map(String::as_str),
            Some("30000")
        );
    }

    #[test]
    fn role_graph_from_expanded_manifest() {
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

roles:
  - name: analytics
    login: true

memberships:
  - role: inventory-editor
    members:
      - name: "user@example.com"
        inherit: true
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let graph = RoleGraph::from_expanded(&expanded, manifest.default_owner.as_deref()).unwrap();

        // Two roles: inventory-editor (from profile) + analytics (one-off)
        assert_eq!(graph.roles.len(), 2);
        assert!(graph.roles.contains_key("inventory-editor"));
        assert!(graph.roles.contains_key("analytics"));

        // Managed schema state includes the declared schema and resolved owner.
        assert_eq!(graph.schemas.len(), 1);
        assert_eq!(
            graph.schemas["inventory"].owner.as_deref(),
            Some("app_owner")
        );

        // inventory-editor is NOLOGIN, analytics is LOGIN
        assert!(!graph.roles["inventory-editor"].login);
        assert!(graph.roles["analytics"].login);

        // Two grant targets: schema USAGE + table SELECT,INSERT
        assert_eq!(graph.grants.len(), 2);

        // One default privilege entry: SELECT,INSERT on tables for inventory-editor
        assert_eq!(graph.default_privileges.len(), 1);
        let dp_key = graph.default_privileges.keys().next().unwrap();
        assert_eq!(dp_key.owner, "app_owner");
        assert_eq!(
            dp_key.scope,
            DefaultPrivilegeScope::Schema {
                schema: "inventory".to_string()
            }
        );
        assert_eq!(dp_key.on_type, ObjectType::Table);
        assert_eq!(dp_key.grantee.as_str(), "inventory-editor");
        let dp_privs = &graph.default_privileges.values().next().unwrap().privileges;
        assert!(dp_privs.contains(&Privilege::Select));
        assert!(dp_privs.contains(&Privilege::Insert));

        // One membership edge
        assert_eq!(graph.memberships.len(), 1);
        let edge = graph.memberships.iter().next().unwrap();
        assert_eq!(edge.role, "inventory-editor");
        assert_eq!(edge.member, "user@example.com");
        assert!(edge.inherit);
        assert!(!edge.admin);
    }

    #[test]
    fn grant_privileges_merge_for_same_target() {
        let yaml = r#"
roles:
  - name: testrole

grants:
  - role: testrole
    privileges: [SELECT]
    object: { type: table, schema: public, name: "*" }
  - role: testrole
    privileges: [INSERT, UPDATE]
    object: { type: table, schema: public, name: "*" }
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let graph = RoleGraph::from_expanded(&expanded, None).unwrap();

        // Both grants target the same key, so privileges should merge
        assert_eq!(graph.grants.len(), 1);
        let grant_state = graph.grants.values().next().unwrap();
        assert_eq!(grant_state.privileges.len(), 3);
        assert!(grant_state.privileges.contains(&Privilege::Select));
        assert!(grant_state.privileges.contains(&Privilege::Insert));
        assert!(grant_state.privileges.contains(&Privilege::Update));
    }
}
