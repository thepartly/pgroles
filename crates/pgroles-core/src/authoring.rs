//! Snapshot-free policy authoring primitives.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::manifest::{
    Ensure, ExpandedManifest, ManifestError, ObjectType, PasswordSource, PolicyManifest, Privilege,
    expand_manifest, parse_manifest,
};
use crate::model::{DefaultPrivilegeScope, RoleGraph};

pub const POLICY_SCHEMA_VERSION: &str = "pgroles.policy.v1";
pub const MAX_POLICY_YAML_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyRequest {
    pub schema_version: String,
    pub desired_yaml: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ValidateResponse {
    pub schema_version: String,
    pub valid: bool,
    pub diagnostics: Vec<PolicyDiagnostic>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CompileResponse {
    pub schema_version: String,
    pub diagnostics: Vec<PolicyDiagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<CompiledPolicy>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct PolicyDiagnostic {
    pub code: String,
    pub severity: DiagnosticSeverity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<SourceRange>,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SourceRange {
    pub start_byte: usize,
    pub end_byte: usize,
}

/// The shared parse, expansion, and normalization result used by every caller.
#[derive(Debug, Clone)]
pub struct PreparedPolicy {
    pub manifest: PolicyManifest,
    pub expanded: ExpandedManifest,
    pub desired: RoleGraph,
}

pub fn prepare_policy(yaml: &str) -> Result<PreparedPolicy, ManifestError> {
    if yaml.len() > MAX_POLICY_YAML_BYTES {
        return Err(ManifestError::YamlTooLarge {
            actual: yaml.len(),
            limit: MAX_POLICY_YAML_BYTES,
        });
    }
    let manifest = parse_manifest(yaml)?;
    let expanded = expand_manifest(&manifest)?;
    let desired = RoleGraph::from_expanded(&expanded, manifest.default_owner.as_deref())?;
    Ok(PreparedPolicy {
        manifest,
        expanded,
        desired,
    })
}

pub fn validate_policy(request: PolicyRequest) -> ValidateResponse {
    match validate_request(&request) {
        Ok(_) => ValidateResponse {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            valid: true,
            diagnostics: Vec::new(),
        },
        Err(diagnostic) => ValidateResponse {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            valid: false,
            diagnostics: vec![diagnostic],
        },
    }
}

pub fn compile_policy(request: PolicyRequest) -> CompileResponse {
    match validate_request(&request) {
        Ok(prepared) => CompileResponse {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            diagnostics: Vec::new(),
            policy: Some(CompiledPolicy::from_prepared(&prepared)),
        },
        Err(diagnostic) => CompileResponse {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            diagnostics: vec![diagnostic],
            policy: None,
        },
    }
}

fn validate_request(request: &PolicyRequest) -> Result<PreparedPolicy, PolicyDiagnostic> {
    if request.schema_version != POLICY_SCHEMA_VERSION {
        return Err(PolicyDiagnostic {
            code: "unsupported_schema_version".to_string(),
            severity: DiagnosticSeverity::Error,
            message: format!(
                "unsupported policy schema version: {}",
                request.schema_version
            ),
            path: Some("schema_version".to_string()),
            range: None,
        });
    }
    prepare_policy(&request.desired_yaml)
        .map_err(|error| diagnostic_from_manifest_error(&request.desired_yaml, error))
}

fn diagnostic_from_manifest_error(yaml: &str, error: ManifestError) -> PolicyDiagnostic {
    let precise_path = precise_manifest_error_path(yaml, &error);
    let (code, path, range) = match &error {
        ManifestError::YamlTooLarge { .. } => ("policy_too_large", None, None),
        ManifestError::Yaml(error) => ("invalid_yaml", None, yaml_error_range(yaml, error)),
        ManifestError::DuplicateRole(_) => ("duplicate_role", Some("roles"), None),
        ManifestError::DuplicateSchema(_) => ("duplicate_schema", Some("schemas"), None),
        ManifestError::UndefinedProfile(_, _) => ("undefined_profile", Some("schemas"), None),
        ManifestError::InvalidRolePattern(_) => {
            ("invalid_role_pattern", Some("role_pattern"), None)
        }
        ManifestError::MissingDefaultPrivilegeRole { .. } => (
            "missing_default_privilege_role",
            Some("default_privileges"),
            None,
        ),
        ManifestError::DuplicateRetirement(_) => {
            ("duplicate_retirement", Some("retirements"), None)
        }
        ManifestError::RetirementRoleStillDesired(_) => {
            ("retirement_role_still_desired", Some("retirements"), None)
        }
        ManifestError::RetirementSelfReassign { .. } => {
            ("retirement_self_reassign", Some("retirements"), None)
        }
        ManifestError::PasswordWithoutLogin { .. } => {
            ("password_without_login", Some("roles"), None)
        }
        ManifestError::InvalidValidUntil { .. } => {
            ("invalid_password_valid_until", Some("roles"), None)
        }
        ManifestError::InvalidConfigParameter { .. } => {
            ("invalid_config_parameter", Some("roles"), None)
        }
        ManifestError::SetRoleWithoutMembership { .. } => {
            ("set_role_without_membership", Some("roles"), None)
        }
        ManifestError::TooManyEntries { collection, .. } => {
            ("too_many_entries", Some(collection.as_str()), None)
        }
        ManifestError::ValueTooLong { .. } => ("value_too_long", None, None),
        ManifestError::ReservedPublicName { .. } => ("reserved_public_name", None, None),
        ManifestError::ConflictingGrantEnsure { .. } => {
            ("conflicting_grant_ensure", Some("grants"), None)
        }
        ManifestError::ConflictingWildcardEnsure { .. } => {
            ("conflicting_wildcard_ensure", Some("grants"), None)
        }
        ManifestError::ConflictingDefaultPrivilegeEnsure { .. } => (
            "conflicting_default_privilege_ensure",
            Some("default_privileges"),
            None,
        ),
        ManifestError::DefaultPrivilegeScopeConflict { .. } => (
            "default_privilege_scope_conflict",
            Some("default_privileges"),
            None,
        ),
        ManifestError::DefaultPrivilegeScopeMissing { .. } => (
            "default_privilege_scope_missing",
            Some("default_privileges"),
            None,
        ),
        ManifestError::DefaultPrivilegeScopeSchemaMissing => (
            "default_privilege_scope_schema_missing",
            Some("default_privileges"),
            None,
        ),
        ManifestError::DefaultPrivilegeScopeSchemaForbidden { .. } => (
            "default_privilege_scope_schema_forbidden",
            Some("default_privileges"),
            None,
        ),
        ManifestError::InvalidDefaultPrivilegeOnType { .. } => (
            "invalid_default_privilege_object_type",
            Some("default_privileges"),
            None,
        ),
        ManifestError::ProfileAbsentDefaultPrivilege { .. } => {
            ("profile_absent_default_privilege", Some("profiles"), None)
        }
        ManifestError::ProfileAbsentGrant { .. } => {
            ("profile_absent_grant", Some("profiles"), None)
        }
        ManifestError::DatabaseGrantMissingName => {
            ("database_grant_missing_name", Some("grants"), None)
        }
        ManifestError::PredefinedRoleNotExternal { .. } => {
            ("predefined_role_not_external", Some("roles"), None)
        }
        ManifestError::ExclusiveMembershipOnManagedRole { .. } => (
            "exclusive_membership_on_managed_role",
            Some("memberships"),
            None,
        ),
    };
    PolicyDiagnostic {
        code: code.to_string(),
        severity: DiagnosticSeverity::Error,
        message: error.to_string(),
        path: precise_path.or_else(|| path.map(|path| manifest_path(yaml, path))),
        range,
    }
}

fn precise_manifest_error_path(yaml: &str, error: &ManifestError) -> Option<String> {
    let ManifestError::ExclusiveMembershipOnManagedRole { role } = error else {
        return None;
    };
    let manifest = parse_manifest(yaml).ok()?;
    let indexes = manifest
        .memberships
        .iter()
        .enumerate()
        .filter_map(|(index, membership)| {
            (membership.role == *role && membership.exclusive).then_some(index)
        })
        .collect::<Vec<_>>();
    (indexes.len() == 1)
        .then(|| manifest_path(yaml, &format!("memberships[{}].exclusive", indexes[0])))
}

fn manifest_path(yaml: &str, path: &str) -> String {
    let wrapped = serde_yaml::from_str::<serde_yaml::Value>(yaml)
        .ok()
        .and_then(|value| value.as_mapping().cloned())
        .is_some_and(|mapping| {
            mapping.contains_key(serde_yaml::Value::String("apiVersion".to_string()))
                && mapping.contains_key(serde_yaml::Value::String("spec".to_string()))
        });
    if wrapped {
        format!("spec.{path}")
    } else {
        path.to_string()
    }
}

fn yaml_error_range(yaml: &str, error: &serde_yaml::Error) -> Option<SourceRange> {
    let location = error.location()?;
    let line_start = yaml
        .split_inclusive('\n')
        .take(location.line().saturating_sub(1))
        .map(str::len)
        .sum::<usize>();
    let line = yaml.get(line_start..)?.split_once('\n').map_or_else(
        || yaml.get(line_start..).unwrap_or_default(),
        |(line, _)| line,
    );
    let column = location.column().saturating_sub(1);
    let relative = line
        .char_indices()
        .nth(column)
        .map_or(line.len(), |(offset, _)| offset);
    let start_byte = line_start + relative;
    Some(SourceRange {
        start_byte,
        end_byte: start_byte,
    })
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CompiledPolicy {
    /// Parsed declarative context, including retirements and auth-provider metadata.
    /// Passwords remain unresolved `from_env` declarations.
    pub manifest: PolicyManifest,
    pub expanded: CompiledExpandedPolicy,
    pub desired: CompiledRoleGraph,
}

impl CompiledPolicy {
    fn from_prepared(prepared: &PreparedPolicy) -> Self {
        Self {
            manifest: prepared.manifest.clone(),
            expanded: CompiledExpandedPolicy::from_expanded(
                &prepared.expanded,
                prepared.manifest.default_owner.as_deref(),
            ),
            desired: CompiledRoleGraph::from(&prepared.desired),
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CompiledExpandedPolicy {
    pub schemas: Vec<CompiledSchema>,
    pub roles: Vec<CompiledRole>,
    pub grants: Vec<CompiledGrant>,
    pub default_privileges: Vec<CompiledDefaultPrivilege>,
    pub memberships: Vec<CompiledMembership>,
}

impl CompiledExpandedPolicy {
    fn from_expanded(value: &ExpandedManifest, default_owner: Option<&str>) -> Self {
        Self {
            schemas: value
                .schemas
                .iter()
                .map(|schema| CompiledSchema {
                    name: schema.name.clone(),
                    owner: schema.owner.clone(),
                })
                .collect(),
            roles: value.roles.iter().map(CompiledRole::from).collect(),
            grants: value.grants.iter().map(CompiledGrant::from).collect(),
            default_privileges: value
                .default_privileges
                .iter()
                .flat_map(|entry| {
                    let scope = entry
                        .resolved_scope()
                        .expect("expanded default privilege has valid scope");
                    entry
                        .grant
                        .iter()
                        .map(move |grant| CompiledDefaultPrivilege {
                            owner: entry
                                .owner
                                .as_deref()
                                .or(default_owner)
                                .unwrap_or("postgres")
                                .to_string(),
                            scope: CompiledDefaultPrivilegeScope::from(&scope),
                            on_type: grant.on_type,
                            grantee: grant
                                .role
                                .clone()
                                .expect("prepared default privilege has a grantee"),
                            privileges: grant.privileges.clone(),
                            ensure: grant.ensure,
                        })
                })
                .collect(),
            memberships: value
                .memberships
                .iter()
                .flat_map(|membership| {
                    membership
                        .members
                        .iter()
                        .map(move |member| CompiledMembership {
                            role: membership.role.clone(),
                            member: member.name.clone(),
                            inherit: member.inherit(),
                            admin: member.admin(),
                            exclusive: membership.exclusive,
                        })
                })
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CompiledSchema {
    pub name: String,
    pub owner: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CompiledRole {
    pub name: String,
    pub external: bool,
    pub preserve_undeclared_grants: bool,
    pub login: Option<bool>,
    pub superuser: Option<bool>,
    pub createdb: Option<bool>,
    pub createrole: Option<bool>,
    pub inherit: Option<bool>,
    pub replication: Option<bool>,
    pub bypassrls: Option<bool>,
    pub connection_limit: Option<i32>,
    pub comment: Option<String>,
    pub password: Option<PasswordSource>,
    pub password_valid_until: Option<String>,
    pub config: BTreeMap<String, String>,
}

impl From<&crate::manifest::RoleDefinition> for CompiledRole {
    fn from(value: &crate::manifest::RoleDefinition) -> Self {
        Self {
            name: value.name.clone(),
            external: value.external,
            preserve_undeclared_grants: value.preserve_undeclared_grants,
            login: value.login,
            superuser: value.superuser,
            createdb: value.createdb,
            createrole: value.createrole,
            inherit: value.inherit,
            replication: value.replication,
            bypassrls: value.bypassrls,
            connection_limit: value.connection_limit,
            comment: value.comment.clone(),
            password: value.password.clone(),
            password_valid_until: value.password_valid_until.clone(),
            config: value
                .config
                .iter()
                .map(|(k, v)| (k.clone(), v.0.clone()))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CompiledGrant {
    pub role: String,
    pub object_type: ObjectType,
    pub schema: Option<String>,
    pub name: Option<String>,
    pub privileges: Vec<Privilege>,
    pub ensure: Ensure,
}
impl From<&crate::manifest::Grant> for CompiledGrant {
    fn from(value: &crate::manifest::Grant) -> Self {
        Self {
            role: value.role.clone(),
            object_type: value.object.object_type,
            schema: value.object.schema.clone(),
            name: value.object.name.clone(),
            privileges: value.privileges.clone(),
            ensure: value.ensure,
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CompiledDefaultPrivilege {
    pub owner: String,
    pub scope: CompiledDefaultPrivilegeScope,
    pub on_type: ObjectType,
    pub grantee: String,
    pub privileges: Vec<Privilege>,
    pub ensure: Ensure,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CompiledDefaultPrivilegeScope {
    Global,
    Schema { schema: String },
}
impl From<&DefaultPrivilegeScope> for CompiledDefaultPrivilegeScope {
    fn from(value: &DefaultPrivilegeScope) -> Self {
        match value {
            DefaultPrivilegeScope::Global => Self::Global,
            DefaultPrivilegeScope::Schema { schema } => Self::Schema {
                schema: schema.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CompiledMembership {
    pub role: String,
    pub member: String,
    pub inherit: bool,
    pub admin: bool,
    pub exclusive: bool,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CompiledRoleGraph {
    pub roles: Vec<DesiredRole>,
    pub schemas: Vec<DesiredSchema>,
    pub grants: Vec<DesiredGrant>,
    pub grant_absences: Vec<DesiredGrant>,
    pub default_privileges: Vec<DesiredDefaultPrivilege>,
    pub default_privilege_absences: Vec<DesiredDefaultPrivilege>,
    pub memberships: Vec<CompiledMembership>,
    pub exclusive_membership_roles: Vec<String>,
}

impl From<&RoleGraph> for CompiledRoleGraph {
    fn from(value: &RoleGraph) -> Self {
        let grants = |source: &BTreeMap<crate::model::GrantKey, BTreeSet<Privilege>>| {
            source
                .iter()
                .map(|(key, privileges)| DesiredGrant {
                    role: key.role.to_string(),
                    object_type: key.object_type,
                    schema: key.schema.clone(),
                    name: key.name.clone(),
                    privileges: privileges.clone(),
                })
                .collect()
        };
        let present: BTreeMap<_, _> = value
            .grants
            .iter()
            .map(|(key, state)| (key.clone(), state.privileges.clone()))
            .collect();
        let defaults = |source: &BTreeMap<crate::model::DefaultPrivKey, BTreeSet<Privilege>>| {
            source
                .iter()
                .map(|(key, privileges)| DesiredDefaultPrivilege {
                    owner: key.owner.clone(),
                    scope: CompiledDefaultPrivilegeScope::from(&key.scope),
                    on_type: key.on_type,
                    grantee: key.grantee.to_string(),
                    privileges: privileges.clone(),
                })
                .collect()
        };
        let present_defaults: BTreeMap<_, _> = value
            .default_privileges
            .iter()
            .map(|(key, state)| (key.clone(), state.privileges.clone()))
            .collect();
        Self {
            roles: value
                .roles
                .iter()
                .map(|(name, state)| DesiredRole {
                    name: name.clone(),
                    login: state.login,
                    superuser: state.superuser,
                    createdb: state.createdb,
                    createrole: state.createrole,
                    inherit: state.inherit,
                    replication: state.replication,
                    bypassrls: state.bypassrls,
                    connection_limit: state.connection_limit,
                    comment: state.comment.clone(),
                    password_valid_until: state.password_valid_until.clone(),
                    config: state.config.clone(),
                })
                .collect(),
            schemas: value
                .schemas
                .iter()
                .map(|(name, state)| DesiredSchema {
                    name: name.clone(),
                    owner: state.owner.clone(),
                    owner_privileges: state.owner_privileges.clone(),
                })
                .collect(),
            grants: grants(&present),
            grant_absences: grants(&value.grant_absences),
            default_privileges: defaults(&present_defaults),
            default_privilege_absences: defaults(&value.default_privilege_absences),
            memberships: value
                .memberships
                .iter()
                .map(|edge| CompiledMembership {
                    role: edge.role.clone(),
                    member: edge.member.clone(),
                    inherit: edge.inherit,
                    admin: edge.admin,
                    exclusive: value.exclusive_membership_roles.contains(&edge.role),
                })
                .collect(),
            exclusive_membership_roles: value.exclusive_membership_roles.iter().cloned().collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DesiredRole {
    pub name: String,
    pub login: bool,
    pub superuser: bool,
    pub createdb: bool,
    pub createrole: bool,
    pub inherit: bool,
    pub replication: bool,
    pub bypassrls: bool,
    pub connection_limit: i32,
    pub comment: Option<String>,
    pub password_valid_until: Option<String>,
    pub config: BTreeMap<String, String>,
}
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DesiredSchema {
    pub name: String,
    pub owner: Option<String>,
    pub owner_privileges: BTreeSet<Privilege>,
}
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DesiredGrant {
    pub role: String,
    pub object_type: ObjectType,
    pub schema: Option<String>,
    pub name: Option<String>,
    pub privileges: BTreeSet<Privilege>,
}
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DesiredDefaultPrivilege {
    pub owner: String,
    pub scope: CompiledDefaultPrivilegeScope,
    pub on_type: ObjectType,
    pub grantee: String,
    pub privileges: BTreeSet<Privilege>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(yaml: &str) -> PolicyRequest {
        PolicyRequest {
            schema_version: POLICY_SCHEMA_VERSION.into(),
            desired_yaml: yaml.into(),
        }
    }

    #[test]
    fn compile_expands_profiles_and_normalizes_graph() {
        let response = compile_policy(request(
            "profiles:\n  reader:\n    grants:\n      - privileges: [SELECT]\n        object: {type: table, name: '*'}\nschemas:\n  - name: app\n    owner: app_owner\n    profiles: [reader]\n",
        ));
        let policy = response.policy.expect("valid policy");
        assert_eq!(policy.expanded.roles[0].name, "app-reader");
        assert_eq!(policy.desired.grants[0].role, "app-reader");
        assert!(
            policy.desired.schemas[0]
                .owner_privileges
                .contains(&Privilege::Usage)
        );
    }

    #[test]
    fn password_source_is_metadata_and_is_not_resolved() {
        let response = compile_policy(request(
            "roles:\n  - name: app\n    login: true\n    password:\n      from_env: A_SECRET_THAT_DOES_NOT_EXIST\n",
        ));
        let policy = response
            .policy
            .expect("password source is valid authoring metadata");
        assert_eq!(
            policy.expanded.roles[0].password.as_ref().unwrap().from_env,
            "A_SECRET_THAT_DOES_NOT_EXIST"
        );
        assert_eq!(
            policy.manifest.roles[0].password.as_ref().unwrap().from_env,
            "A_SECRET_THAT_DOES_NOT_EXIST"
        );
    }

    #[test]
    fn semantic_error_has_no_invented_source_range() {
        let response = validate_policy(request(
            "roles:\n  - name: app\n    password: {from_env: SECRET}\n",
        ));
        assert!(!response.valid);
        assert_eq!(response.diagnostics[0].code, "password_without_login");
        assert!(response.diagnostics[0].range.is_none());
    }

    #[test]
    fn semantic_diagnostics_name_only_the_known_collection() {
        let cases = [
            (
                "grants:\n  - role: app\n    privileges: [CONNECT]\n    object: {type: database}\n",
                "database_grant_missing_name",
                "grants",
            ),
            (
                "default_privileges:\n  - owner: app\n    schema: public\n    scope: {type: global}\n    grant: []\n",
                "default_privilege_scope_conflict",
                "default_privileges",
            ),
            (
                "roles:\n  - name: team\nmemberships:\n  - role: team\n    exclusive: true\n    members: []\n",
                "exclusive_membership_on_managed_role",
                "memberships[0].exclusive",
            ),
        ];

        for (yaml, code, path) in cases {
            let response = validate_policy(request(yaml));
            assert!(!response.valid);
            assert_eq!(response.diagnostics[0].code, code);
            assert_eq!(response.diagnostics[0].path.as_deref(), Some(path));
            assert!(response.diagnostics[0].range.is_none());
        }
    }

    #[test]
    fn yaml_error_range_is_a_utf8_boundary() {
        let yaml = "roles:\n  - name: café\n    login: [\n";
        let response = validate_policy(request(yaml));
        let range = response.diagnostics[0].range.expect("syntax location");
        assert!(yaml.is_char_boundary(range.start_byte));
        assert!(yaml.is_char_boundary(range.end_byte));
    }

    #[test]
    fn manifest_bounds_are_applied_by_shared_preparation() {
        let roles = (0..=crate::bounds::MAX_ROLES)
            .map(|index| format!("  - name: r{index}\n"))
            .collect::<String>();
        let response = validate_policy(request(&format!("roles:\n{roles}")));
        assert_eq!(response.diagnostics[0].code, "too_many_entries");
        assert_eq!(response.diagnostics[0].path.as_deref(), Some("roles"));
    }

    #[test]
    fn oversized_yaml_is_rejected_before_parsing() {
        let yaml = " ".repeat(MAX_POLICY_YAML_BYTES + 1);
        let response = validate_policy(request(&yaml));
        assert_eq!(response.diagnostics[0].code, "policy_too_large");
        assert!(response.diagnostics[0].path.is_none());
        assert!(response.diagnostics[0].range.is_none());
    }

    #[test]
    fn kubernetes_wrapper_diagnostic_paths_include_spec() {
        let response = validate_policy(request(
            "apiVersion: pgroles.io/v1alpha1\nkind: PostgresPolicy\nspec:\n  roles:\n    - name: app\n      password: {from_env: SECRET}\n",
        ));
        assert_eq!(response.diagnostics[0].path.as_deref(), Some("spec.roles"));
    }

    #[test]
    fn exclusive_membership_has_a_precise_path_and_survives_compilation() {
        let invalid = validate_policy(request(
            "memberships:\n  - role: team\n    exclusive: true\n    members: []\n",
        ));
        assert_eq!(
            invalid.diagnostics[0].path.as_deref(),
            Some("memberships[0].exclusive")
        );

        let compiled = compile_policy(request(
            "memberships:\n  - role: pg_monitor\n    exclusive: true\n    members: [{name: observer}]\n",
        ))
        .policy
        .expect("predefined role may have exclusive membership");
        assert!(compiled.expanded.memberships[0].exclusive);
        assert!(compiled.desired.memberships[0].exclusive);
    }

    #[test]
    fn compiled_policy_preserves_non_graph_manifest_context() {
        let compiled = compile_policy(request(
            "role_pattern: '{schema}_{profile}'\ndefault_owner: app_owner\nretirements:\n  - role: legacy_app\n    reassign_owned_to: app_owner\n",
        ))
        .policy
        .expect("manifest context is valid");
        assert_eq!(
            compiled.manifest.role_pattern.as_deref(),
            Some("{schema}_{profile}")
        );
        assert_eq!(
            compiled.manifest.default_owner.as_deref(),
            Some("app_owner")
        );
        assert_eq!(compiled.manifest.retirements[0].role, "legacy_app");
    }
}
