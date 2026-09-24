//! Testable CLI logic for pgroles.
//!
//! All pure functions that don't require a live database connection live here.
//! The binary (`main.rs`) delegates to these, making validation, plan formatting,
//! and output rendering fully unit-testable.

use std::path::Path;

use anyhow::{Context, Result};

pub mod candidate;

use pgroles_core::authoring::{PreparedPolicy, prepare_policy};
use pgroles_core::composition::{self, ComposedPolicy, PolicyBundle, PolicyDocument};
use pgroles_core::diff::{self, Change};
use pgroles_core::manifest::{self, ExpandedManifest, PolicyManifest, RoleRetirement};
use pgroles_core::model::{DefaultPrivilegeScope, RoleGraph};
use pgroles_core::ownership::ManagedScope;
use pgroles_core::report::{self, PlanOutputMode};
use pgroles_core::sql;

// ---------------------------------------------------------------------------
// File loading
// ---------------------------------------------------------------------------

/// Read a manifest file from disk and return the raw YAML string.
pub fn read_manifest_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path)
        .with_context(|| format!("failed to read manifest file: {}", path.display()))
}

// ---------------------------------------------------------------------------
// Validation pipeline (pure — no DB)
// ---------------------------------------------------------------------------

/// Parse and validate a YAML string into a `PolicyManifest`.
pub fn parse(yaml: &str) -> Result<PolicyManifest> {
    manifest::parse_manifest(yaml).map_err(|err| anyhow::anyhow!("{err}"))
}

/// Parse, validate, and expand a manifest YAML string into an `ExpandedManifest`.
pub fn parse_and_expand(yaml: &str) -> Result<ExpandedManifest> {
    let policy_manifest = parse(yaml)?;
    manifest::expand_manifest(&policy_manifest).map_err(|err| anyhow::anyhow!("{err}"))
}

/// Full validation: parse, expand, and build a RoleGraph from a manifest string.
/// Returns the expanded manifest and the desired RoleGraph.
pub fn validate_manifest(yaml: &str) -> Result<ValidatedManifest> {
    let prepared = prepare_policy(yaml).map_err(|err| anyhow::anyhow!("{err}"))?;

    if prepared.manifest.roles.is_empty()
        && prepared.manifest.schemas.is_empty()
        && prepared.manifest.grants.is_empty()
        && prepared.manifest.memberships.is_empty()
    {
        tracing::warn!(
            "manifest defines no roles, schemas, grants, or memberships — is the file correct?"
        );
    }

    Ok(prepared)
}

/// The result of successfully validating a manifest.
pub type ValidatedManifest = PreparedPolicy;

/// Load, validate, and compose a policy bundle from disk.
pub fn validate_bundle_file(path: &Path) -> Result<ValidatedBundle> {
    let yaml = read_manifest_file(path)?;
    let bundle = composition::parse_policy_bundle(&yaml).map_err(|err| anyhow::anyhow!("{err}"))?;
    let documents = load_policy_documents(path, &bundle)?;
    let composed =
        composition::compose_bundle(&bundle, &documents).map_err(|err| anyhow::anyhow!("{err}"))?;

    Ok(ValidatedBundle {
        bundle,
        documents,
        composed,
    })
}

fn load_policy_documents(path: &Path, bundle: &PolicyBundle) -> Result<Vec<PolicyDocument>> {
    let base_dir = path
        .parent()
        .with_context(|| format!("bundle path has no parent directory: {}", path.display()))?;

    bundle
        .sources
        .iter()
        .map(|source| {
            let source_path = base_dir.join(&source.file);
            let yaml = read_manifest_file(&source_path)?;
            let fragment = composition::parse_policy_fragment(&yaml)
                .map_err(|err| anyhow::anyhow!("{err}"))
                .with_context(|| {
                    format!("failed to parse policy document: {}", source_path.display())
                })?;
            Ok(PolicyDocument {
                source: source.file.clone(),
                fragment,
            })
        })
        .collect()
}

/// The result of successfully validating a composed policy bundle.
pub struct ValidatedBundle {
    pub bundle: PolicyBundle,
    pub documents: Vec<PolicyDocument>,
    pub composed: ComposedPolicy,
}

// ---------------------------------------------------------------------------
// Plan computation (pure — given both role graphs)
// ---------------------------------------------------------------------------

/// Compute the list of changes needed to bring `current` state to `desired` state.
pub fn compute_plan(current: &RoleGraph, desired: &RoleGraph) -> Vec<Change> {
    diff::diff(current, desired)
}

/// Collect the role names that the current plan intends to drop.
pub fn planned_role_drops(changes: &[Change]) -> Vec<String> {
    changes
        .iter()
        .filter_map(|change| match change {
            Change::DropRole { name } => Some(name.clone()),
            _ => None,
        })
        .collect()
}

/// Insert explicit retirement actions before any matching role drops.
pub fn apply_role_retirements(changes: Vec<Change>, retirements: &[RoleRetirement]) -> Vec<Change> {
    diff::apply_role_retirements(changes, retirements)
}

/// Resolve password sources from environment variables for roles that declare them.
pub fn resolve_passwords(
    expanded: &ExpandedManifest,
) -> Result<std::collections::BTreeMap<String, String>> {
    diff::resolve_passwords(&expanded.roles).map_err(|err| anyhow::anyhow!("{err}"))
}

/// Inject `SetPassword` changes into a plan for roles with resolved passwords.
pub fn inject_password_changes(
    changes: Vec<Change>,
    resolved_passwords: &std::collections::BTreeMap<String, String>,
) -> Vec<Change> {
    diff::inject_password_changes(changes, resolved_passwords)
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

/// Format a plan as SQL statements.
pub fn format_plan_sql(changes: &[Change]) -> String {
    sql::render_all(changes)
}

/// Format a plan as SQL statements using an explicit SQL context.
pub fn format_plan_sql_with_context(changes: &[Change], ctx: &sql::SqlContext) -> String {
    sql::render_all_with_context(&report::redact_password_changes(changes), ctx)
}

/// Format a plan as JSON for machine consumption.
pub fn format_plan_json(changes: &[Change]) -> Result<String> {
    report::render_plan_json(changes, PlanOutputMode::Redacted)
        .map_err(|err| anyhow::anyhow!("{err}"))
}

/// Format a bundle plan as JSON with ownership annotations for each change.
pub fn format_bundle_plan_json(changes: &[Change], composed: &ComposedPolicy) -> Result<String> {
    report::render_bundle_plan_json(
        changes,
        &composed.report_context(),
        PlanOutputMode::Redacted,
    )
    .map_err(|err| anyhow::anyhow!("{err}"))
}

/// Summary statistics for a plan.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PlanSummary {
    pub roles_created: usize,
    pub roles_altered: usize,
    pub schemas_created: usize,
    pub schema_owners_altered: usize,
    pub roles_dropped: usize,
    pub comments_changed: usize,
    pub sessions_terminated: usize,
    pub ownerships_reassigned: usize,
    pub owned_objects_dropped: usize,
    pub grants: usize,
    pub revokes: usize,
    pub default_privileges_set: usize,
    pub default_privileges_revoked: usize,
    /// Global (owner-wide) default privilege changes, counted separately from
    /// the schema-scoped totals above because they affect every schema in the
    /// database.
    pub global_default_privileges_set: usize,
    pub global_default_privileges_revoked: usize,
    pub members_added: usize,
    pub members_removed: usize,
    pub passwords_set: usize,
}

impl PlanSummary {
    /// Compute summary statistics from a list of changes.
    pub fn from_changes(changes: &[Change]) -> Self {
        let mut summary = Self::default();
        for change in changes {
            match change {
                Change::CreateRole { .. } => summary.roles_created += 1,
                Change::CreateSchema { .. } => summary.schemas_created += 1,
                Change::AlterSchemaOwner { .. } => summary.schema_owners_altered += 1,
                Change::AlterRole { .. } => summary.roles_altered += 1,
                Change::DropRole { .. } => summary.roles_dropped += 1,
                Change::SetComment { .. } => summary.comments_changed += 1,
                Change::TerminateSessions { .. } => summary.sessions_terminated += 1,
                Change::ReassignOwned { .. } => summary.ownerships_reassigned += 1,
                Change::DropOwned { .. } => summary.owned_objects_dropped += 1,
                Change::Grant { .. } | Change::EnsureSchemaOwnerPrivileges { .. } => {
                    summary.grants += 1
                }
                Change::Revoke { .. } => summary.revokes += 1,
                Change::SetDefaultPrivilege { scope, .. } => {
                    if matches!(scope, DefaultPrivilegeScope::Global) {
                        summary.global_default_privileges_set += 1;
                    } else {
                        summary.default_privileges_set += 1;
                    }
                }
                Change::RevokeDefaultPrivilege { scope, .. } => {
                    if matches!(scope, DefaultPrivilegeScope::Global) {
                        summary.global_default_privileges_revoked += 1;
                    } else {
                        summary.default_privileges_revoked += 1;
                    }
                }
                Change::AddMember { .. } => summary.members_added += 1,
                Change::RemoveMember { .. } => summary.members_removed += 1,
                Change::SetPassword { .. } => summary.passwords_set += 1,
            }
        }
        summary
    }

    /// Total number of changes in the plan.
    pub fn total(&self) -> usize {
        self.roles_created
            + self.roles_altered
            + self.schemas_created
            + self.schema_owners_altered
            + self.roles_dropped
            + self.comments_changed
            + self.sessions_terminated
            + self.ownerships_reassigned
            + self.owned_objects_dropped
            + self.grants
            + self.revokes
            + self.default_privileges_set
            + self.default_privileges_revoked
            + self.global_default_privileges_set
            + self.global_default_privileges_revoked
            + self.members_added
            + self.members_removed
            + self.passwords_set
    }

    /// True if the plan has no changes.
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }

    /// True if the plan has structural drift (excluding password-only changes).
    ///
    /// Password changes always appear in plans because passwords cannot be read
    /// back from PostgreSQL for comparison. This method allows CI gates
    /// (`--exit-code`) to distinguish real drift from password-only changes.
    pub fn has_structural_changes(&self) -> bool {
        self.total() - self.passwords_set > 0
    }

    pub fn format_plan(&self) -> String {
        self.format_with_header("Plan")
    }

    pub fn format_applied(&self) -> String {
        self.format_with_header("Applied")
    }

    fn format_with_header(&self, header: &str) -> String {
        if self.is_empty() {
            return "No changes needed. Database is in sync with manifest.".to_string();
        }

        let mut output = String::new();
        output.push_str(&format!("{header}: {} change(s)\n", self.total()));

        let items: Vec<(&str, usize)> = vec![
            ("role(s) to create", self.roles_created),
            ("role(s) to alter", self.roles_altered),
            ("schema(s) to create", self.schemas_created),
            ("schema owner change(s)", self.schema_owners_altered),
            ("role(s) to drop", self.roles_dropped),
            ("comment(s) to change", self.comments_changed),
            ("session termination step(s)", self.sessions_terminated),
            ("ownership reassignment(s)", self.ownerships_reassigned),
            ("DROP OWNED cleanup step(s)", self.owned_objects_dropped),
            ("grant(s) to add", self.grants),
            ("grant(s) to revoke", self.revokes),
            ("default privilege(s) to set", self.default_privileges_set),
            (
                "default privilege(s) to revoke",
                self.default_privileges_revoked,
            ),
            (
                "GLOBAL default privilege(s) to set (affects every schema)",
                self.global_default_privileges_set,
            ),
            (
                "GLOBAL default privilege(s) to revoke (affects every schema)",
                self.global_default_privileges_revoked,
            ),
            ("membership(s) to add", self.members_added),
            ("membership(s) to remove", self.members_removed),
            ("password(s) to set", self.passwords_set),
        ];

        for (label, count) in items {
            if count > 0 {
                output.push_str(&format!("  {count} {label}\n"));
            }
        }

        output
    }
}

impl std::fmt::Display for PlanSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.format_plan())
    }
}

/// Format validation results for human-readable output.
pub fn format_validation_result(validated: &ValidatedManifest) -> String {
    let mut output = String::new();
    output.push_str("Manifest is valid.\n");
    output.push_str(&format!(
        "  {} schema(s) defined\n",
        validated.expanded.schemas.len()
    ));
    output.push_str(&format!(
        "  {} role(s) defined\n",
        validated.expanded.roles.len()
    ));
    output.push_str(&format!(
        "  {} grant(s) defined\n",
        validated.expanded.grants.len()
    ));
    output.push_str(&format!(
        "  {} default privilege(s) defined\n",
        validated.expanded.default_privileges.len()
    ));
    output.push_str(&format!(
        "  {} membership(s) defined\n",
        validated.expanded.memberships.len()
    ));
    output
}

/// Render a validated bundle as a single composed manifest YAML.
///
/// When `include_header` is true, the output is prefixed with a YAML comment
/// block recording the source bundle label, the manifest schema version
/// against which the body was rendered, and the fragments it composed, for
/// traceability when the rendered file is committed to a GitOps repo.
///
/// `source_label` should be a stable, machine-independent label (e.g. the
/// bundle file's basename). Callers must NOT pass absolute or `pwd`-relative
/// paths: the rendered output is intended to be byte-identical across
/// developer machines and CI runners, and embedding a local filesystem path
/// in the header would break that contract.
///
/// The body is the composed `PolicyManifest` serialized via serde_yaml and
/// then post-processed to drop noise that would otherwise churn under
/// upgrades or render in irrelevant places: `null` scalars, empty sequences
/// (except for required-field keys like `members`/`privileges`/`grant`),
/// and known empty top-level maps. Explicit naming patterns remain intact.
/// The cleaned output still round-trips through
/// `pgroles validate -f` / `diff -f` / `apply -f` because the parser fills
/// the same defaults back in on read.
pub fn format_rendered_bundle(
    validated: &ValidatedBundle,
    source_label: &str,
    include_header: bool,
) -> Result<String> {
    let raw =
        serde_yaml::to_value(&validated.composed.manifest).map_err(|err| anyhow::anyhow!(err))?;
    let cleaned = strip_manifest_defaults(raw);
    let body = serde_yaml::to_string(&cleaned).map_err(|err| anyhow::anyhow!(err))?;

    if !include_header {
        return Ok(body);
    }

    let mut header = String::new();
    header.push_str("# Rendered by `pgroles render-bundle`.\n");
    header.push_str("# Do not edit by hand — regenerate from the source bundle.\n");
    header.push_str(&format!("# Source bundle: {source_label}\n"));
    header.push_str(&format!("# Manifest schema: {RENDERED_MANIFEST_SCHEMA}\n"));
    header.push_str("# Fragments:\n");
    for document in &validated.documents {
        let label = document.fragment.policy.name.as_deref();
        match label {
            Some(name) => header.push_str(&format!("#   - {} ({name})\n", document.source)),
            None => header.push_str(&format!("#   - {}\n", document.source)),
        }
    }
    header.push_str("#\n");
    Ok(format!("{header}{body}"))
}

/// Schema identifier for the YAML body emitted by `render-bundle`. Bumped
/// only on incompatible changes to the `PolicyManifest` serialization shape.
/// Recorded in the header so `--check` failures after a pgroles upgrade can
/// be diagnosed as "schema bump → re-render required" rather than mystery
/// drift, and so consumers parsing the rendered file can detect mismatches.
pub const RENDERED_MANIFEST_SCHEMA: &str = "pgroles.manifest.v1";

/// Recursively strip serde-emitted defaults from a serialized manifest so
/// the rendered YAML stays focused on author-meaningful content.
///
/// Strips:
/// - `null` scalars (e.g. `login: null` on profiles, `name: null` on grants),
/// - empty sequences (`memberships: []`, `retirements: []`, …),
/// - empty top-level maps (`profiles: {}` when no profiles are declared),
///
/// Explicit naming patterns are preserved because they can override inherited patterns.
///
/// All stripped fields round-trip on parse because each has a `#[serde(default)]`
/// on its struct definition, so a re-read produces an equivalent `PolicyManifest`.
fn strip_manifest_defaults(value: serde_yaml::Value) -> serde_yaml::Value {
    strip_manifest_defaults_at(value, &[])
}

fn strip_manifest_defaults_at(value: serde_yaml::Value, path: &[String]) -> serde_yaml::Value {
    use serde_yaml::Value;
    match value {
        Value::Mapping(map) => {
            let mut out = serde_yaml::Mapping::new();
            for (k, v) in map {
                let mut child_path = path.to_vec();
                if let Some(key) = k.as_str() {
                    child_path.push(key.to_string());
                }
                let cleaned = strip_manifest_defaults_at(v, &child_path);
                if is_strippable(&child_path, &cleaned) {
                    continue;
                }
                out.insert(k, cleaned);
            }
            Value::Mapping(out)
        }
        Value::Sequence(seq) => Value::Sequence(
            seq.into_iter()
                .map(|item| strip_manifest_defaults_at(item, path))
                .collect(),
        ),
        other => other,
    }
}

fn is_strippable(path: &[String], value: &serde_yaml::Value) -> bool {
    use serde_yaml::Value;
    let key = path.last().map(String::as_str);
    match value {
        Value::Null => true,
        Value::Sequence(s) if s.is_empty() => {
            // Some sequence-valued fields in `PolicyManifest` are required
            // (no `#[serde(default)]` on the struct field) and stripping an
            // empty value would produce YAML that no longer deserializes
            // back into the same type. Keep this list aligned with the
            // struct definitions in `pgroles_core::manifest`:
            //   - `Grant.privileges`, `ProfileGrant.privileges`,
            //     `DefaultPrivilegeGrant.privileges`
            //   - `DefaultPrivilege.grant`
            //   - `Membership.members`
            !matches!(key, Some("privileges") | Some("grant") | Some("members"))
        }
        Value::Mapping(m) if m.is_empty() => {
            // Only strip empty maps whose position is known to be a defaulted
            // manifest field. A named profile such as `profiles.noop: {}` is
            // semantically meaningful even though its serialized profile body
            // is empty after defaults are removed.
            matches!(path, [field] if field == "profiles")
        }
        _ => false,
    }
}

/// Format bundle validation results for human-readable output.
pub fn format_bundle_validation_result(validated: &ValidatedBundle) -> String {
    let mut output = String::new();
    output.push_str("Policy bundle is valid.\n");
    output.push_str(&format!(
        "  {} source document(s) loaded\n",
        validated.documents.len()
    ));
    output.push_str(&format!(
        "  {} shared profile(s) defined\n",
        validated.bundle.shared.profiles.len()
    ));
    output.push_str(&format!(
        "  {} schema(s) defined\n",
        validated.composed.expanded.schemas.len()
    ));
    output.push_str(&format!(
        "  {} role(s) defined\n",
        validated.composed.expanded.roles.len()
    ));
    output.push_str(&format!(
        "  {} grant(s) defined\n",
        validated.composed.expanded.grants.len()
    ));
    output.push_str(&format!(
        "  {} default privilege(s) defined\n",
        validated.composed.expanded.default_privileges.len()
    ));
    output.push_str(&format!(
        "  {} membership(s) defined\n",
        validated.composed.expanded.memberships.len()
    ));
    output
}

/// Format a composed managed scope for human-readable debug output.
pub fn format_managed_scope_summary(scope: &ManagedScope) -> String {
    let mut output = String::new();
    output.push_str("Managed scope:\n");
    output.push_str(&format!("  {} role(s)\n", scope.roles.len()));
    output.push_str(&format!("  {} schema(s)\n", scope.schemas.len()));

    let owner_schemas: Vec<&str> = scope
        .schemas
        .iter()
        .filter_map(|(schema, managed)| managed.owner.then_some(schema.as_str()))
        .collect();
    let binding_schemas: Vec<&str> = scope
        .schemas
        .iter()
        .filter_map(|(schema, managed)| managed.bindings.then_some(schema.as_str()))
        .collect();

    output.push_str(&format!(
        "  owner-managed schema(s): {}\n",
        owner_schemas.len()
    ));
    if !owner_schemas.is_empty() {
        output.push_str(&format!("  owner scope: {}\n", owner_schemas.join(", ")));
    }

    output.push_str(&format!(
        "  binding-managed schema(s): {}\n",
        binding_schemas.len()
    ));
    if !binding_schemas.is_empty() {
        output.push_str(&format!(
            "  binding scope: {}\n",
            binding_schemas.join(", ")
        ));
    }

    output
}

// ---------------------------------------------------------------------------
// Inspect output formatting
// ---------------------------------------------------------------------------

/// Format a RoleGraph as a human-readable summary.
pub fn format_role_graph_summary(graph: &RoleGraph) -> String {
    let mut output = String::new();
    output.push_str(&format!("Roles: {}\n", graph.roles.len()));
    for (name, state) in &graph.roles {
        let login_marker = if state.login { "LOGIN" } else { "NOLOGIN" };
        output.push_str(&format!("  {name} ({login_marker})\n"));
    }
    output.push_str(&format!("Schemas: {}\n", graph.schemas.len()));
    for (name, state) in &graph.schemas {
        match &state.owner {
            Some(owner) => output.push_str(&format!("  {name} (owner: {owner})\n")),
            None => output.push_str(&format!("  {name}\n")),
        }
    }
    output.push_str(&format!("Grants: {}\n", graph.grants.len()));
    output.push_str(&format!(
        "Default privileges: {}\n",
        graph.default_privileges.len()
    ));
    output.push_str(&format!("Memberships: {}\n", graph.memberships.len()));
    for edge in &graph.memberships {
        output.push_str(&format!("  {} -> {}\n", edge.member, edge.role));
    }
    output
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pgroles_core::ownership::ManagedSchemaScope;

    const MINIMAL_MANIFEST: &str = r#"
default_owner: app_owner

schemas:
  - name: analytics
    owner: app_owner
    profiles: []

roles:
  - name: analytics
    login: true
    comment: "Analytics read-only role"

grants:
  - role: analytics
    privileges: [CONNECT]
    object: { type: database, name: mydb }
"#;

    const PROFILE_MANIFEST: &str = r#"
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
  viewer:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT]
        object: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT]
        on_type: table

schemas:
  - name: inventory
    profiles: [editor, viewer]
  - name: catalog
    profiles: [viewer]

roles:
  - name: app-service
    login: true

grants:
  - role: app-service
    privileges: [CONNECT]
    object: { type: database, name: mydb }

memberships:
  - role: inventory-editor
    members:
      - name: app-service
"#;

    const INVALID_YAML: &str = r#"
this is: [not: valid yaml: [[
"#;

    const UNDEFINED_PROFILE: &str = r#"
profiles:
  editor:
    grants: []

schemas:
  - name: myschema
    profiles: [nonexistent]
"#;

    // -----------------------------------------------------------------------
    // parse
    // -----------------------------------------------------------------------

    #[test]
    fn parse_valid_manifest() {
        let result = parse(MINIMAL_MANIFEST);
        assert!(result.is_ok());
        let manifest = result.unwrap();
        assert_eq!(manifest.default_owner, Some("app_owner".to_string()));
        assert_eq!(manifest.roles.len(), 1);
        assert_eq!(manifest.roles[0].name, "analytics");
    }

    #[test]
    fn parse_invalid_yaml() {
        let result = parse(INVALID_YAML);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("YAML parse error"), "got: {err_msg}");
    }

    // -----------------------------------------------------------------------
    // parse_and_expand
    // -----------------------------------------------------------------------

    #[test]
    fn expand_profile_manifest() {
        let expanded = parse_and_expand(PROFILE_MANIFEST).unwrap();

        assert_eq!(expanded.schemas.len(), 2);
        // inventory-editor, inventory-viewer, catalog-viewer, app-service
        assert_eq!(expanded.roles.len(), 4);

        let role_names: Vec<&str> = expanded.roles.iter().map(|r| r.name.as_str()).collect();
        assert!(role_names.contains(&"inventory-editor"));
        assert!(role_names.contains(&"inventory-viewer"));
        assert!(role_names.contains(&"catalog-viewer"));
        assert!(role_names.contains(&"app-service"));
    }

    #[test]
    fn expand_undefined_profile_fails() {
        let result = parse_and_expand(UNDEFINED_PROFILE);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("nonexistent"),
            "expected error about 'nonexistent' profile, got: {err_msg}"
        );
    }

    // -----------------------------------------------------------------------
    // validate_manifest
    // -----------------------------------------------------------------------

    #[test]
    fn validate_builds_role_graph() {
        let validated = validate_manifest(PROFILE_MANIFEST).unwrap();

        // Check the desired graph has the expected roles
        assert_eq!(validated.desired.roles.len(), 4);
        assert!(validated.desired.roles.contains_key("inventory-editor"));
        assert!(validated.desired.roles.contains_key("app-service"));

        // Check grants were expanded
        assert!(!validated.desired.grants.is_empty());

        // Check memberships
        assert!(!validated.desired.memberships.is_empty());
    }

    #[test]
    fn validate_accepts_manifests_over_the_browser_byte_limit() {
        use std::fmt::Write as _;

        // At the role and grant entry bounds, and larger than the 1 MiB browser limit.
        let comment = "c".repeat(250);
        let mut yaml = String::from("roles:\n");
        for index in 0..1024 {
            writeln!(
                yaml,
                "  - name: app_role_{index:04}\n    login: true\n    comment: \"{comment}\""
            )
            .unwrap();
        }
        yaml.push_str("grants:\n");
        for index in 0..4096 {
            writeln!(
                yaml,
                "  - role: app_role_{:04}\n    privileges: [SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER]\n    object: {{ type: table, schema: app, name: table_with_a_descriptive_name_{index:05} }}",
                index % 1024
            )
            .unwrap();
        }
        assert!(yaml.len() > pgroles_core::authoring::MAX_POLICY_YAML_BYTES);

        let validated = validate_manifest(&yaml).expect("native validation has no byte limit");
        assert_eq!(validated.desired.roles.len(), 1024);
        assert_eq!(validated.desired.grants.len(), 4096);
    }

    // -----------------------------------------------------------------------
    // compute_plan + format
    // -----------------------------------------------------------------------

    #[test]
    fn plan_from_empty_creates_roles() {
        let validated = validate_manifest(PROFILE_MANIFEST).unwrap();
        let current = RoleGraph::default(); // empty database

        let changes = compute_plan(&current, &validated.desired);
        assert!(!changes.is_empty());

        let summary = PlanSummary::from_changes(&changes);
        assert_eq!(summary.roles_created, 4); // inventory-editor, inventory-viewer, catalog-viewer, app-service
        assert_eq!(summary.schemas_created, 2); // inventory, catalog
        assert!(summary.grants > 0);
        assert!(!summary.is_empty());
    }

    #[test]
    fn plan_no_changes_when_in_sync() {
        let validated = validate_manifest(MINIMAL_MANIFEST).unwrap();
        // Simulate a DB that already has the desired state
        let current = validated.desired.clone();

        let changes = compute_plan(&current, &validated.desired);
        let summary = PlanSummary::from_changes(&changes);
        assert!(summary.is_empty());
        assert_eq!(summary.total(), 0);
    }

    #[test]
    fn format_plan_sql_produces_sql() {
        let validated = validate_manifest(MINIMAL_MANIFEST).unwrap();
        let current = RoleGraph::default();
        let changes = compute_plan(&current, &validated.desired);

        let sql_output = format_plan_sql(&changes);
        assert!(
            sql_output.contains("CREATE SCHEMA"),
            "expected CREATE SCHEMA in: {sql_output}"
        );
        assert!(
            sql_output.contains("CREATE ROLE"),
            "expected CREATE ROLE in: {sql_output}"
        );
        assert!(
            sql_output.contains("\"analytics\""),
            "expected quoted role name in: {sql_output}"
        );
    }

    #[test]
    fn planned_role_drops_only_returns_drop_changes() {
        let changes = vec![
            Change::CreateRole {
                name: "new-role".to_string(),
                state: pgroles_core::model::RoleState::default(),
            },
            Change::DropRole {
                name: "old-role".to_string(),
            },
            Change::DropRole {
                name: "stale-role".to_string(),
            },
        ];

        assert_eq!(
            planned_role_drops(&changes),
            vec!["old-role".to_string(), "stale-role".to_string()]
        );
    }

    #[test]
    fn apply_role_retirements_updates_plan_summary() {
        let changes = apply_role_retirements(
            vec![Change::DropRole {
                name: "legacy-app".to_string(),
            }],
            &[pgroles_core::manifest::RoleRetirement {
                role: "legacy-app".to_string(),
                reassign_owned_to: Some("app-owner".to_string()),
                drop_owned: true,
                terminate_sessions: true,
            }],
        );

        let summary = PlanSummary::from_changes(&changes);
        assert_eq!(summary.roles_dropped, 1);
        assert_eq!(summary.sessions_terminated, 1);
        assert_eq!(summary.ownerships_reassigned, 1);
        assert_eq!(summary.owned_objects_dropped, 1);
        assert_eq!(summary.total(), 4);
    }

    // -----------------------------------------------------------------------
    // PlanSummary display
    // -----------------------------------------------------------------------

    #[test]
    fn plan_summary_display_empty() {
        let summary = PlanSummary::default();
        let display = summary.to_string();
        assert!(display.contains("No changes needed"));
    }

    #[test]
    fn plan_summary_display_with_changes() {
        let summary = PlanSummary {
            roles_created: 2,
            schemas_created: 1,
            grants: 5,
            members_added: 1,
            ..Default::default()
        };
        let display = summary.to_string();
        assert!(display.contains("9 change(s)"), "got: {display}");
        assert!(display.contains("2 role(s) to create"), "got: {display}");
        assert!(display.contains("1 schema(s) to create"), "got: {display}");
        assert!(display.contains("5 grant(s) to add"), "got: {display}");
        assert!(display.contains("1 membership(s) to add"), "got: {display}");
        // Should not mention zero-count items
        assert!(!display.contains("to drop"), "got: {display}");
        assert!(!display.contains("to revoke"), "got: {display}");
    }

    // -----------------------------------------------------------------------
    // format_validation_result
    // -----------------------------------------------------------------------

    #[test]
    fn validation_result_shows_counts() {
        let validated = validate_manifest(PROFILE_MANIFEST).unwrap();
        let output = format_validation_result(&validated);
        assert!(output.contains("Manifest is valid"), "got: {output}");
        assert!(output.contains("2 schema(s)"), "got: {output}");
        assert!(output.contains("4 role(s)"), "got: {output}");
    }

    #[test]
    fn managed_scope_summary_lists_owner_and_binding_facets() {
        let scope = ManagedScope {
            roles: ["app".to_string(), "app_owner".to_string()]
                .into_iter()
                .collect(),
            schemas: [
                (
                    "inventory".to_string(),
                    ManagedSchemaScope {
                        owner: true,
                        bindings: true,
                    },
                ),
                (
                    "audit".to_string(),
                    ManagedSchemaScope {
                        owner: true,
                        bindings: false,
                    },
                ),
            ]
            .into_iter()
            .collect(),
        };

        let output = format_managed_scope_summary(&scope);

        assert!(output.contains("Managed scope:"), "got: {output}");
        assert!(output.contains("2 role(s)"), "got: {output}");
        assert!(output.contains("2 schema(s)"), "got: {output}");
        assert!(
            output.contains("owner scope: audit, inventory"),
            "got: {output}"
        );
        assert!(output.contains("binding scope: inventory"), "got: {output}");
    }

    // -----------------------------------------------------------------------
    // read_manifest_file
    // -----------------------------------------------------------------------

    #[test]
    fn read_nonexistent_file_fails() {
        let result = read_manifest_file(Path::new("/tmp/nonexistent-pgroles-test.yaml"));
        assert!(result.is_err());
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(
            err_msg.contains("failed to read manifest file"),
            "got: {err_msg}"
        );
    }

    // -----------------------------------------------------------------------
    // format_role_graph_summary
    // -----------------------------------------------------------------------

    #[test]
    fn role_graph_summary_format() {
        let validated = validate_manifest(MINIMAL_MANIFEST).unwrap();
        let summary = format_role_graph_summary(&validated.desired);
        assert!(summary.contains("Roles: 1"), "got: {summary}");
        assert!(summary.contains("Schemas: 1"), "got: {summary}");
        assert!(summary.contains("analytics (LOGIN)"), "got: {summary}");
    }

    // -----------------------------------------------------------------------
    // has_structural_changes — password-only drift detection
    // -----------------------------------------------------------------------

    #[test]
    fn has_structural_changes_true_for_non_password_changes() {
        let summary = PlanSummary {
            roles_created: 1,
            schemas_created: 1,
            grants: 2,
            ..Default::default()
        };
        assert!(summary.has_structural_changes());
    }

    #[test]
    fn has_structural_changes_false_for_password_only() {
        let summary = PlanSummary {
            passwords_set: 3,
            ..Default::default()
        };
        assert!(
            !summary.has_structural_changes(),
            "password-only plan should NOT be considered structural drift"
        );
    }

    #[test]
    fn has_structural_changes_true_for_mixed() {
        let summary = PlanSummary {
            roles_created: 1,
            passwords_set: 2,
            ..Default::default()
        };
        assert!(
            summary.has_structural_changes(),
            "mixed plan with structural + password changes IS structural drift"
        );
    }

    #[test]
    fn has_structural_changes_false_for_empty() {
        let summary = PlanSummary::default();
        assert!(!summary.has_structural_changes());
    }

    #[test]
    fn plan_summary_displays_password_count() {
        let summary = PlanSummary {
            passwords_set: 2,
            roles_created: 1,
            ..Default::default()
        };
        let display = summary.to_string();
        assert!(display.contains("2 password(s) to set"), "got: {display}");
        assert!(display.contains("3 change(s)"), "got: {display}");
    }

    // -----------------------------------------------------------------------
    // ReconciliationMode integration through compute_plan + filter
    // -----------------------------------------------------------------------

    #[test]
    fn additive_mode_filters_revokes_from_plan() {
        use pgroles_core::diff::{ReconciliationMode, filter_changes};
        use pgroles_core::model::RoleState;

        let validated = validate_manifest(PROFILE_MANIFEST).unwrap();

        let mut current = validated.desired.clone();
        current
            .roles
            .insert("stale-role".to_string(), RoleState::default());

        let changes = compute_plan(&current, &validated.desired);
        assert!(changes.iter().any(|c| matches!(
            c,
            pgroles_core::diff::Change::DropRole { name } if name == "stale-role"
        )));

        let filtered = filter_changes(changes, ReconciliationMode::Additive);
        assert!(
            !filtered
                .iter()
                .any(|c| matches!(c, pgroles_core::diff::Change::DropRole { .. })),
            "additive mode should filter out DropRole"
        );
    }

    #[test]
    fn adopt_mode_filters_drops_but_keeps_revokes() {
        use pgroles_core::diff::{ReconciliationMode, filter_changes};
        use pgroles_core::manifest::{ObjectType, Privilege};
        use pgroles_core::model::{GrantKey, GrantState, RoleState};
        use std::collections::BTreeSet;

        let validated = validate_manifest(MINIMAL_MANIFEST).unwrap();

        let mut current = validated.desired.clone();
        current
            .roles
            .insert("stale-role".to_string(), RoleState::default());
        current.grants.insert(
            GrantKey {
                role: "analytics".into(),
                object_type: ObjectType::Table,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Select]),
            },
        );

        let changes = compute_plan(&current, &validated.desired);

        let filtered = filter_changes(changes, ReconciliationMode::Adopt);
        assert!(
            !filtered
                .iter()
                .any(|c| matches!(c, pgroles_core::diff::Change::DropRole { .. })),
            "adopt mode should filter out DropRole"
        );
        assert!(
            filtered
                .iter()
                .any(|c| matches!(c, pgroles_core::diff::Change::Revoke { .. })),
            "adopt mode should keep Revoke changes"
        );
    }
    // -----------------------------------------------------------------------
    // format_plan_json
    // -----------------------------------------------------------------------

    #[test]
    fn plan_json_produces_valid_json() {
        let validated = validate_manifest(MINIMAL_MANIFEST).unwrap();
        let current = RoleGraph::default();
        let changes = compute_plan(&current, &validated.desired);

        let json_output = format_plan_json(&changes).unwrap();
        // Should be parseable JSON
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert!(parsed.is_array());
        // Should contain CreateRole
        let text = json_output.to_string();
        assert!(text.contains("CreateRole"), "got: {text}");
        assert!(text.contains("analytics"), "got: {text}");
    }

    #[test]
    fn format_plan_json_redacts_passwords() {
        let changes = vec![Change::SetPassword {
            name: "app-svc".to_string(),
            password: "super-secret".to_string(),
        }];

        let json = format_plan_json(&changes).expect("json formatting should succeed");
        assert!(json.contains("[REDACTED]"), "got: {json}");
        assert!(!json.contains("super-secret"), "got: {json}");
    }

    #[test]
    fn bundle_plan_json_includes_scope_and_ownership_annotations() {
        let bundle = composition::parse_policy_bundle(
            r#"
sources:
  - file: app.yaml
"#,
        )
        .unwrap();
        let documents = vec![composition::PolicyDocument {
            source: "app.yaml".to_string(),
            fragment: composition::parse_policy_fragment(
                r#"
policy:
  name: app
scope:
  roles: [app]
roles:
  - name: app
    login: false
"#,
            )
            .unwrap(),
        }];
        let composed = composition::compose_bundle(&bundle, &documents).unwrap();
        let changes = compute_plan(&RoleGraph::default(), &composed.desired);

        let json_output = format_bundle_plan_json(&changes, &composed).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();

        assert!(parsed.is_object());
        assert_eq!(
            parsed["schema_version"],
            pgroles_core::report::BUNDLE_PLAN_SCHEMA_VERSION
        );
        assert_eq!(parsed["managed_scope"]["roles"][0], "app");
        assert_eq!(parsed["changes"][0]["owner"]["document"], "app");
        assert_eq!(parsed["changes"][0]["owner"]["managed_key"]["kind"], "role");
        assert_eq!(parsed["changes"][0]["owner"]["managed_key"]["name"], "app");
    }

    #[test]
    fn format_plan_sql_redacts_passwords() {
        let changes = vec![
            Change::AlterRole {
                name: "app-svc".to_string(),
                attributes: vec![pgroles_core::model::RoleAttribute::SetConfig(
                    "application_name".to_string(),
                    "planned-config".to_string(),
                )],
            },
            Change::SetComment {
                name: "app-svc".to_string(),
                comment: Some("planned-comment".to_string()),
            },
            Change::SetPassword {
                name: "app-svc".to_string(),
                password: "super-secret".to_string(),
            },
        ];

        let sql = format_plan_sql_with_context(&changes, &sql::SqlContext::default());
        assert!(sql.contains("[REDACTED]"), "got: {sql}");
        assert!(!sql.contains("super-secret"), "got: {sql}");
        assert!(sql.contains("planned-config"), "got: {sql}");
        assert!(sql.contains("planned-comment"), "got: {sql}");
    }

    #[test]
    fn format_applied_uses_applied_header() {
        let summary = PlanSummary {
            roles_created: 1,
            schemas_created: 1,
            grants: 2,
            ..Default::default()
        };

        let display = summary.format_applied();
        assert!(
            display.starts_with("Applied: 4 change(s)\n"),
            "got: {display}"
        );
        assert!(display.contains("1 role(s) to create"), "got: {display}");
        assert!(display.contains("1 schema(s) to create"), "got: {display}");
        assert!(display.contains("2 grant(s) to add"), "got: {display}");
        assert!(!display.contains("Plan:"), "got: {display}");
    }

    // -----------------------------------------------------------------------
    // format_rendered_bundle
    // -----------------------------------------------------------------------

    fn validated_bundle_for_render() -> ValidatedBundle {
        let bundle = composition::parse_policy_bundle(
            r#"
sources:
  - file: platform.yaml
  - file: app.yaml
"#,
        )
        .unwrap();
        let documents = vec![
            composition::PolicyDocument {
                source: "platform.yaml".to_string(),
                fragment: composition::parse_policy_fragment(
                    r#"
policy:
  name: platform
scope:
  roles: [app_owner]
  schemas:
    - name: inventory
      facets: [owner]
roles:
  - name: app_owner
    login: false
schemas:
  - name: inventory
    owner: app_owner
"#,
                )
                .unwrap(),
            },
            composition::PolicyDocument {
                source: "app.yaml".to_string(),
                fragment: composition::parse_policy_fragment(
                    r#"
policy:
  name: app
scope:
  roles: [app_service]
roles:
  - name: app_service
    login: true
"#,
                )
                .unwrap(),
            },
        ];
        let composed = composition::compose_bundle(&bundle, &documents).unwrap();
        ValidatedBundle {
            bundle,
            documents,
            composed,
        }
    }

    #[test]
    fn rendered_bundle_preserves_explicit_default_over_custom_shared_pattern() {
        let mut validated = validated_bundle_for_render();
        validated.bundle.shared.role_pattern = Some("shared_{schema}_{profile}".into());
        validated
            .bundle
            .shared
            .profiles
            .insert("reader".into(), serde_yaml::from_str("grants: []").unwrap());
        let bindings = composition::PolicyDocument {
            source: "bindings.yaml".into(),
            fragment: composition::parse_policy_fragment(
                r#"
scope:
  schemas:
    - name: app
      facets: [bindings]
schemas:
  - name: app
    profiles: [reader]
    role_pattern: "{schema}-{profile}"
"#,
            )
            .unwrap(),
        };
        validated.documents.push(bindings);
        validated.composed =
            composition::compose_bundle(&validated.bundle, &validated.documents).unwrap();
        let rendered = format_rendered_bundle(&validated, "bundle.yaml", false).unwrap();
        let reparsed = validate_manifest(&rendered).unwrap();
        assert!(
            reparsed
                .expanded
                .roles
                .iter()
                .any(|role| role.name == "app-reader")
        );
        assert!(
            !reparsed
                .expanded
                .roles
                .iter()
                .any(|role| role.name == "shared_app_reader")
        );
    }

    #[test]
    fn rendered_bundle_round_trips_to_equivalent_expansion() {
        let validated = validated_bundle_for_render();
        let rendered = format_rendered_bundle(&validated, "bundle.yaml", true).unwrap();

        let reparsed = validate_manifest(&rendered).expect("rendered output must validate");

        // Stronger than just role-count: every role, schema, grant, and
        // default-privilege key from the composed manifest must be present
        // after a render -> parse -> expand round trip.
        use std::collections::BTreeSet;
        let original_roles: BTreeSet<_> = validated
            .composed
            .expanded
            .roles
            .iter()
            .map(|r| r.name.clone())
            .collect();
        let rendered_roles: BTreeSet<_> = reparsed
            .expanded
            .roles
            .iter()
            .map(|r| r.name.clone())
            .collect();
        assert_eq!(rendered_roles, original_roles);

        let original_schemas: BTreeSet<_> = validated
            .composed
            .expanded
            .schemas
            .iter()
            .map(|s| s.name.clone())
            .collect();
        let rendered_schemas: BTreeSet<_> = reparsed
            .expanded
            .schemas
            .iter()
            .map(|s| s.name.clone())
            .collect();
        assert_eq!(rendered_schemas, original_schemas);

        assert_eq!(
            reparsed.expanded.grants.len(),
            validated.composed.expanded.grants.len()
        );
        assert_eq!(
            reparsed.expanded.default_privileges.len(),
            validated.composed.expanded.default_privileges.len()
        );
        assert_eq!(
            reparsed.expanded.memberships.len(),
            validated.composed.expanded.memberships.len()
        );

        // Role config maps must survive the render round trip verbatim —
        // guards against default-stripping ever reaching inside `config`.
        use std::collections::BTreeMap;
        let config_by_role = |expanded: &pgroles_core::manifest::ExpandedManifest| {
            expanded
                .roles
                .iter()
                .map(|r| (r.name.clone(), r.config.clone()))
                .collect::<BTreeMap<_, _>>()
        };
        assert_eq!(
            config_by_role(&reparsed.expanded),
            config_by_role(&validated.composed.expanded)
        );
    }

    #[test]
    fn render_preserves_config_parameter_named_role_pattern() {
        // A config parameter is an arbitrary user-chosen PostgreSQL setting
        // name. One literally named `role_pattern` whose value equals the
        // default role pattern string must NOT be stripped by the renderer's
        // default-removal pass. Explicit schema overrides must also survive.
        let yaml = r#"
schemas:
  - name: inventory
    profiles: []
    role_pattern: "{schema}-{profile}"

roles:
  - name: app
    config:
      role_pattern: "{schema}-{profile}"
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let stripped = strip_manifest_defaults(value);
        let out = serde_yaml::to_string(&stripped).unwrap();

        // Both the explicit schema override and arbitrary config entry survive.
        assert_eq!(
            out.matches("role_pattern").count(),
            2,
            "expected both explicit patterns to survive, got:\n{out}"
        );
        // The config value is preserved verbatim.
        let reparsed: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        let config_value = reparsed["roles"][0]["config"]["role_pattern"]
            .as_str()
            .expect("config.role_pattern must survive rendering");
        assert_eq!(config_value, "{schema}-{profile}");
    }

    #[test]
    fn rendered_bundle_header_records_source_and_fragments() {
        let validated = validated_bundle_for_render();
        let rendered = format_rendered_bundle(&validated, "prod.yaml", true).unwrap();

        assert!(rendered.starts_with("# Rendered by `pgroles render-bundle`."));
        assert!(rendered.contains("# Source bundle: prod.yaml"));
        assert!(rendered.contains("#   - platform.yaml (platform)"));
        assert!(rendered.contains("#   - app.yaml (app)"));
    }

    #[test]
    fn rendered_bundle_header_records_manifest_schema_version() {
        // The schema-version marker is the diagnostic anchor that lets
        // users tell "the rendered file is stale because someone edited
        // the bundle" apart from "the rendered file is stale because
        // pgroles upgraded to a new manifest schema". It must always appear
        // in the header.
        let validated = validated_bundle_for_render();
        let rendered = format_rendered_bundle(&validated, "bundle.yaml", true).unwrap();
        assert!(
            rendered.contains(&format!("# Manifest schema: {RENDERED_MANIFEST_SCHEMA}")),
            "header must record manifest schema, got: {rendered}"
        );
    }

    #[test]
    fn rendered_bundle_strips_empty_collections_and_nulls() {
        let validated = validated_bundle_for_render();
        let rendered = format_rendered_bundle(&validated, "bundle.yaml", false).unwrap();

        // Empty top-level collections defaulted by serde must not appear.
        assert!(
            !rendered.contains("auth_providers: []"),
            "rendered output must not include empty auth_providers, got: {rendered}"
        );
        assert!(
            !rendered.contains("grants: []"),
            "rendered output must not include empty grants, got: {rendered}"
        );
        assert!(
            !rendered.contains("default_privileges: []"),
            "rendered output must not include empty default_privileges, got: {rendered}"
        );
        assert!(
            !rendered.contains("memberships: []"),
            "rendered output must not include empty memberships, got: {rendered}"
        );
        assert!(
            !rendered.contains("profiles: {}"),
            "rendered output must not include empty top-level profiles, got: {rendered}"
        );
        assert!(
            !rendered.contains("retirements: []"),
            "rendered output must not include empty retirements, got: {rendered}"
        );
        // Profile Option fields default to None — they must not serialize as `null`.
        assert!(
            !rendered.contains("login: null"),
            "rendered output must not include null login, got: {rendered}"
        );
        assert!(
            !rendered.contains("inherit: null"),
            "rendered output must not include null inherit, got: {rendered}"
        );
        // An omitted pattern stays omitted.
        assert!(
            !rendered.contains("role_pattern:"),
            "rendered output must omit absent role_pattern, got: {rendered}"
        );
    }

    #[test]
    fn rendered_bundle_no_header_emits_only_yaml() {
        let validated = validated_bundle_for_render();
        let rendered = format_rendered_bundle(&validated, "bundle.yaml", false).unwrap();

        assert!(
            !rendered.starts_with('#'),
            "without header, output should start with YAML, got: {rendered}"
        );
        // Still a valid manifest.
        validate_manifest(&rendered).expect("rendered output must validate");
    }

    #[test]
    fn rendered_bundle_is_deterministic() {
        let validated = validated_bundle_for_render();
        let first = format_rendered_bundle(&validated, "bundle.yaml", true).unwrap();
        let second = format_rendered_bundle(&validated, "bundle.yaml", true).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn rendered_bundle_preserves_required_empty_sequences() {
        // Membership.members and Grant.privileges are required fields (no
        // `#[serde(default)]`). The renderer must NOT strip them even when
        // empty, or the rendered YAML fails to deserialize as a manifest.
        let bundle = composition::parse_policy_bundle(
            r#"
sources:
  - file: app.yaml
"#,
        )
        .unwrap();
        let documents = vec![composition::PolicyDocument {
            source: "app.yaml".to_string(),
            fragment: composition::parse_policy_fragment(
                r#"
policy:
  name: app
scope:
  roles: [empty_group]
roles:
  - name: empty_group
    login: false
memberships:
  - role: empty_group
    members: []
"#,
            )
            .unwrap(),
        }];
        let composed = composition::compose_bundle(&bundle, &documents).unwrap();
        let validated = ValidatedBundle {
            bundle,
            documents,
            composed,
        };

        let rendered = format_rendered_bundle(&validated, "bundle.yaml", false).unwrap();

        // The required `members:` key must remain even when its value is `[]`.
        assert!(
            rendered.contains("members:"),
            "required `members` field must not be stripped, got: {rendered}"
        );

        // And the round trip must succeed.
        validate_manifest(&rendered)
            .expect("rendered output with empty required sequence must still parse");
    }

    #[test]
    fn rendered_bundle_preserves_referenced_empty_profiles() {
        // An empty profile body is valid and still meaningful when a schema
        // references it: expansion creates the schema/profile role using the
        // default role pattern. The renderer may strip the profile's defaulted
        // fields, but must keep the named profile entry itself.
        let bundle = composition::parse_policy_bundle(
            r#"
shared:
  profiles:
    noop: {}
sources:
  - file: app.yaml
"#,
        )
        .unwrap();
        let documents = vec![composition::PolicyDocument {
            source: "app.yaml".to_string(),
            fragment: composition::parse_policy_fragment(
                r#"
policy:
  name: app
scope:
  schemas:
    - name: inventory
      facets: [bindings]
schemas:
  - name: inventory
    profiles: [noop]
"#,
            )
            .unwrap(),
        }];
        let composed = composition::compose_bundle(&bundle, &documents).unwrap();
        let validated = ValidatedBundle {
            bundle,
            documents,
            composed,
        };

        let rendered = format_rendered_bundle(&validated, "bundle.yaml", false).unwrap();

        assert!(
            rendered.contains("noop: {}"),
            "empty referenced profile must be preserved, got: {rendered}"
        );
        let reparsed = validate_manifest(&rendered)
            .expect("rendered output with an empty referenced profile must still parse");
        assert!(
            reparsed
                .expanded
                .roles
                .iter()
                .any(|role| role.name == "inventory-noop"),
            "empty profile must still expand to its schema/profile role"
        );
    }
}
