//! SQL generation from [`Change`] operations.
//!
//! Each [`Change`] variant is rendered into one or more PostgreSQL DDL
//! statements. All identifiers are double-quoted to handle names containing
//! hyphens, dots, `@` signs, etc.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use crate::diff::Change;
use crate::manifest::{ObjectType, Privilege};
use crate::model::{DefaultPrivilegeScope, Grantee, RoleAttribute, RoleState};

// ---------------------------------------------------------------------------
// Identifier quoting
// ---------------------------------------------------------------------------

/// Double-quote a PostgreSQL identifier, escaping any embedded double quotes.
///
/// ```
/// use pgroles_core::sql::quote_ident;
/// assert_eq!(quote_ident("simple"), r#""simple""#);
/// assert_eq!(quote_ident("has\"quote"), r#""has""quote""#);
/// assert_eq!(quote_ident("user@example.com"), r#""user@example.com""#);
/// ```
pub fn quote_ident(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

// ---------------------------------------------------------------------------
// SQL context for version-dependent rendering
// ---------------------------------------------------------------------------

/// Context controlling version-dependent SQL generation.
#[derive(Debug, Clone)]
pub struct SqlContext {
    /// PostgreSQL major version (e.g., 14, 15, 16, 17).
    /// Controls syntax differences like `WITH INHERIT` in membership grants.
    pub pg_major_version: i32,
    /// Optional schema-scoped catalog inventory used to safely expand wildcard
    /// object statements (relations, sequences, routines) without leaking
    /// across subtypes.
    pub object_inventory: BTreeMap<(ObjectType, String), Vec<String>>,
    /// Relations owned by each managed role, as
    /// `(role, object_type, schema, object_name)`. Wildcard REVOKEs skip
    /// objects the grantee owns: an owner's privileges are inherent (an ACL
    /// entry records them once any grant materializes it), and revoking them
    /// breaks owner DML and foreign-key key-share checks. This makes the
    /// never-revoke-owner-privileges invariant hold by construction even when
    /// inspection-side tagging cannot see per-object ownership — e.g. a
    /// mixed-ownership schema folded into a `name: "*"` key.
    pub owned_relations: BTreeSet<(String, ObjectType, String, String)>,
    /// The role the connection is expected to run as, when it differs from
    /// the login role — e.g. the operator's `connection.params.setRole`,
    /// applied via `SET ROLE` after connect, or a `role` GUC in the
    /// connection options. A grantor-targeted revoke temporarily becomes the
    /// grantor via `SET ROLE`; restoring with `RESET ROLE` would reset to the
    /// *login* role, silently dropping the configured execution role for the
    /// rest of the plan (and the pooled connection). When set, revokes
    /// restore this role explicitly instead of using `RESET ROLE`.
    pub execution_role: Option<String>,
}

impl SqlContext {
    /// Create a context for a specific PG version number (from `server_version_num`).
    pub fn from_version_num(version_num: i32) -> Self {
        Self {
            pg_major_version: version_num / 10000,
            object_inventory: BTreeMap::new(),
            owned_relations: BTreeSet::new(),
            execution_role: None,
        }
    }

    /// Attach the connection's configured execution role (see
    /// [`SqlContext::execution_role`]).
    pub fn with_execution_role(mut self, execution_role: Option<String>) -> Self {
        self.execution_role = execution_role;
        self
    }

    /// Attach live object inventory for safer wildcard rendering.
    pub fn with_object_inventory(
        mut self,
        object_inventory: BTreeMap<(ObjectType, String), Vec<String>>,
    ) -> Self {
        self.object_inventory = object_inventory;
        self
    }

    /// Attach relation ownership for the owner-guard on wildcard REVOKEs.
    pub fn with_owned_relations(
        mut self,
        owned_relations: BTreeSet<(String, ObjectType, String, String)>,
    ) -> Self {
        self.owned_relations = owned_relations;
        self
    }

    /// Whether the grantee owns this relation. `PUBLIC` owns nothing.
    pub fn grantee_owns_relation(
        &self,
        role: &Grantee,
        object_type: ObjectType,
        schema: &str,
        name: &str,
    ) -> bool {
        match role {
            Grantee::Role(role_name) => self.owned_relations.contains(&(
                role_name.clone(),
                object_type,
                schema.to_string(),
                name.to_string(),
            )),
            Grantee::Public => false,
        }
    }

    /// Whether PG supports `GRANT ... WITH INHERIT TRUE/FALSE` (PG 16+).
    pub fn supports_grant_with_options(&self) -> bool {
        self.pg_major_version >= 16
    }
}

impl Default for SqlContext {
    fn default() -> Self {
        Self {
            pg_major_version: 16, // Default to PG 16+ (current minimum)
            object_inventory: BTreeMap::new(),
            owned_relations: BTreeSet::new(),
            execution_role: None,
        }
    }
}

// ---------------------------------------------------------------------------
// SQL rendering
// ---------------------------------------------------------------------------

/// Render a single [`Change`] into a SQL statement (including trailing `;`).
/// Uses default context (PG 16+).
pub fn render(change: &Change) -> String {
    render_statements(change).join("\n")
}

/// Render a single [`Change`] into one or more SQL statements.
/// Uses default context (PG 16+).
pub fn render_statements(change: &Change) -> Vec<String> {
    render_statements_with_context(change, &SqlContext::default())
}

/// Render a single [`Change`] into one or more SQL statements,
/// using the given [`SqlContext`] for version-dependent syntax.
pub fn render_statements_with_context(change: &Change, ctx: &SqlContext) -> Vec<String> {
    render_batch_with_context(std::slice::from_ref(change), ctx)
        .into_iter()
        .map(|statement| statement.sql)
        .collect()
}

/// One executable statement and its safe display counterpart.
///
/// Keep statements separate when executing: PostgreSQL's prepared query
/// protocol does not accept a multi-statement script.
pub struct RenderedStatement {
    /// Executable SQL, potentially containing a password. Never log this field.
    pub sql: String,
    /// The same statement with password values replaced for display or logging.
    pub redacted_sql: String,
}

/// Render an ordered plan, sharing role switches across consecutive revokes
/// attributed to the same grantor. No changes are reordered. Every temporary
/// role block restores the configured execution role (or the login role).
/// Password redaction uses change metadata, never SQL text parsing.
pub fn render_batch_with_context(changes: &[Change], ctx: &SqlContext) -> Vec<RenderedStatement> {
    let mut result = Vec::new();
    let mut active_grantor: Option<&str> = None;
    let restore = || match &ctx.execution_role {
        Some(role) => format!("SET ROLE {};", quote_ident(role)),
        None => "RESET ROLE;".to_string(),
    };
    let plain = |sql: String| RenderedStatement {
        redacted_sql: sql.clone(),
        sql,
    };
    for change in changes {
        // Object REVOKE acts on the current grantor's ACL entry (a superuser
        // acts as owner); GRANTED BY cannot impersonate another object grantor.
        // Membership revokes instead express attribution with GRANTED BY and
        // must continue to execute under the configured connection role.
        let grantor = match change {
            Change::Revoke { grantor, .. } => grantor.as_deref(),
            _ => None,
        };
        let statements = render_unscoped_statements(change, ctx);
        if statements.is_empty() {
            continue;
        }
        if grantor != active_grantor {
            if active_grantor.is_some() {
                result.push(plain(restore()));
            }
            if let Some(role) = grantor {
                result.push(plain(format!("SET ROLE {};", quote_ident(role))));
            }
            active_grantor = grantor;
        }
        for sql in statements {
            let redacted_sql = match change {
                Change::SetPassword { name, .. } => {
                    format!("ALTER ROLE {} PASSWORD '[REDACTED]';", quote_ident(name))
                }
                _ => sql.clone(),
            };
            result.push(RenderedStatement { sql, redacted_sql });
        }
    }
    if active_grantor.is_some() {
        result.push(plain(restore()));
    }
    result
}

fn render_unscoped_statements(change: &Change, ctx: &SqlContext) -> Vec<String> {
    match change {
        Change::CreateRole { name, state } => render_create_role(name, state),
        Change::CreateSchema { name, owner } => render_create_schema(name, owner.as_deref()),
        Change::AlterSchemaOwner { name, owner } => render_alter_schema_owner(name, owner),
        Change::EnsureSchemaOwnerPrivileges {
            name,
            owner,
            privileges,
        } => render_grant(
            &Grantee::Role(owner.clone()),
            privileges,
            ObjectType::Schema,
            None,
            Some(name.as_str()),
            ctx,
        ),
        Change::AlterRole { name, attributes } => render_alter_role(name, attributes),
        Change::SetComment { name, comment } => render_set_comment(name, comment),
        Change::Grant {
            role,
            privileges,
            object_type,
            schema,
            name,
        } => render_grant(
            role,
            privileges,
            *object_type,
            schema.as_deref(),
            name.as_deref(),
            ctx,
        ),
        Change::Revoke {
            role,
            privileges,
            object_type,
            schema,
            name,
            grantor: _,
        } => render_revoke(
            role,
            privileges,
            *object_type,
            schema.as_deref(),
            name.as_deref(),
            ctx,
        ),
        Change::SetDefaultPrivilege {
            owner,
            scope,
            on_type,
            grantee,
            privileges,
        } => render_set_default_privilege(owner, scope, *on_type, grantee, privileges),
        Change::RevokeDefaultPrivilege {
            owner,
            scope,
            on_type,
            grantee,
            privileges,
        } => render_revoke_default_privilege(owner, scope, *on_type, grantee, privileges),
        Change::AddMember {
            role,
            member,
            inherit,
            admin,
        } => render_add_member(role, member, *inherit, *admin, ctx),
        Change::RemoveMember {
            role,
            member,
            grantor,
        } => render_remove_member(role, member, grantor.as_deref(), ctx),
        Change::ReassignOwned { from_role, to_role } => render_reassign_owned(from_role, to_role),
        Change::DropOwned { role } => render_drop_owned(role),
        Change::TerminateSessions { role } => render_terminate_sessions(role),
        Change::SetPassword { name, password } => render_set_password(name, password),
        Change::DropRole { name } => vec![format!("DROP ROLE IF EXISTS {};", quote_ident(name))],
    }
}

/// Render all changes into a single SQL script (default context, PG 16+).
pub fn render_all(changes: &[Change]) -> String {
    render_all_with_context(changes, &SqlContext::default())
}

/// Render all changes into a single SQL script with version context.
pub fn render_all_with_context(changes: &[Change], ctx: &SqlContext) -> String {
    render_batch_with_context(changes, ctx)
        .into_iter()
        .map(|statement| statement.sql)
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// CREATE / ALTER SCHEMA
// ---------------------------------------------------------------------------

fn render_create_schema(name: &str, owner: Option<&str>) -> Vec<String> {
    let sql = match owner {
        Some(owner) => format!(
            "CREATE SCHEMA {} AUTHORIZATION {};",
            quote_ident(name),
            quote_ident(owner)
        ),
        None => format!("CREATE SCHEMA {};", quote_ident(name)),
    };
    vec![sql]
}

fn render_alter_schema_owner(name: &str, owner: &str) -> Vec<String> {
    vec![format!(
        "ALTER SCHEMA {} OWNER TO {};",
        quote_ident(name),
        quote_ident(owner)
    )]
}

// ---------------------------------------------------------------------------
// CREATE ROLE
// ---------------------------------------------------------------------------

// NOTE: PostgreSQL does not support `CREATE ROLE IF NOT EXISTS` natively.
// The PL/pgSQL idiom `DO $$ BEGIN CREATE ROLE ...; EXCEPTION WHEN
// duplicate_object THEN NULL; END $$;` would work but changes the SQL
// profile significantly. Instead, we rely on the plan-phase lifecycle
// (Pending -> Approved -> Applying -> Applied) and transaction atomicity
// to guarantee that a CREATE ROLE is not re-executed after a successful
// commit. The only edge case is a committed transaction whose K8s status
// update failed, which is handled by the plan's sql_hash deduplication.
fn render_create_role(name: &str, state: &RoleState) -> Vec<String> {
    let mut sql = format!("CREATE ROLE {}", quote_ident(name));
    let mut options = vec![
        bool_option("LOGIN", "NOLOGIN", state.login),
        bool_option("SUPERUSER", "NOSUPERUSER", state.superuser),
        bool_option("CREATEDB", "NOCREATEDB", state.createdb),
        bool_option("CREATEROLE", "NOCREATEROLE", state.createrole),
        bool_option("INHERIT", "NOINHERIT", state.inherit),
        bool_option("REPLICATION", "NOREPLICATION", state.replication),
        bool_option("BYPASSRLS", "NOBYPASSRLS", state.bypassrls),
    ];

    if state.connection_limit != -1 {
        options.push(format!("CONNECTION LIMIT {}", state.connection_limit));
    }

    if let Some(valid_until) = &state.password_valid_until {
        options.push(format!("VALID UNTIL {}", quote_literal(valid_until)));
    }

    let _ = write!(sql, " {}", options.join(" "));
    sql.push(';');

    let mut statements = vec![sql];
    if let Some(comment) = &state.comment {
        statements.push(format!(
            "COMMENT ON ROLE {} IS {};",
            quote_ident(name),
            quote_literal(comment)
        ));
    }

    // NOTE: state.config is intentionally not rendered here. Config defaults
    // cannot be part of CREATE ROLE, and a `role` setting may reference a
    // role created later in the same plan — the diff engine emits a separate
    // AlterRole with SetConfig attributes that orders after all creates.

    statements
}

fn bool_option(positive: &str, negative: &str, value: bool) -> String {
    if value {
        positive.to_string()
    } else {
        negative.to_string()
    }
}

// ---------------------------------------------------------------------------
// ALTER ROLE
// ---------------------------------------------------------------------------

fn render_alter_role(name: &str, attributes: &[RoleAttribute]) -> Vec<String> {
    let mut options = Vec::new();
    for attr in attributes {
        match attr {
            RoleAttribute::Login(v) => options.push(bool_option("LOGIN", "NOLOGIN", *v)),
            RoleAttribute::Superuser(v) => {
                options.push(bool_option("SUPERUSER", "NOSUPERUSER", *v));
            }
            RoleAttribute::Createdb(v) => {
                options.push(bool_option("CREATEDB", "NOCREATEDB", *v));
            }
            RoleAttribute::Createrole(v) => {
                options.push(bool_option("CREATEROLE", "NOCREATEROLE", *v));
            }
            RoleAttribute::Inherit(v) => options.push(bool_option("INHERIT", "NOINHERIT", *v)),
            RoleAttribute::Replication(v) => {
                options.push(bool_option("REPLICATION", "NOREPLICATION", *v));
            }
            RoleAttribute::Bypassrls(v) => {
                options.push(bool_option("BYPASSRLS", "NOBYPASSRLS", *v));
            }
            RoleAttribute::ConnectionLimit(v) => {
                options.push(format!("CONNECTION LIMIT {v}"));
            }
            RoleAttribute::ValidUntil(v) => match v {
                Some(ts) => options.push(format!("VALID UNTIL {}", quote_literal(ts))),
                None => options.push("VALID UNTIL 'infinity'".to_string()),
            },
            // SET/RESET are separate ALTER ROLE forms that cannot be combined
            // with attribute options — rendered as standalone statements below.
            RoleAttribute::SetConfig(..) | RoleAttribute::ResetConfig(..) => {}
        }
    }
    let mut statements = Vec::new();
    if !options.is_empty() {
        statements.push(format!(
            "ALTER ROLE {} {};",
            quote_ident(name),
            options.join(" ")
        ));
    }
    for attr in attributes {
        match attr {
            RoleAttribute::SetConfig(parameter, value) => {
                statements.push(render_set_config(name, parameter, value));
            }
            RoleAttribute::ResetConfig(parameter) => {
                statements.push(format!(
                    "ALTER ROLE {} RESET {};",
                    quote_ident(name),
                    quote_ident(parameter)
                ));
            }
            _ => {}
        }
    }
    statements
}

/// Render `ALTER ROLE ... SET parameter = value`.
///
/// The parameter name is identifier-quoted (dotted custom GUC names like
/// `app.tenant` quote as a single unit, which PostgreSQL accepts). List-quoted
/// parameters (search_path, ...) are rendered as one string literal per list
/// element — `SET search_path = 'a', 'b'` — because a single literal
/// `'a, b'` would be stored as ONE element literally named `a, b`. All other
/// values render as a single string literal; PostgreSQL coerces it to the
/// parameter's type.
fn render_set_config(name: &str, parameter: &str, value: &str) -> String {
    let rendered_value = if crate::guc::is_list_quote_parameter(parameter) {
        let elements = crate::guc::split_guc_list(value).unwrap_or_default();
        if elements.is_empty() {
            quote_literal("")
        } else {
            elements
                .iter()
                .map(|element| quote_literal(element))
                .collect::<Vec<_>>()
                .join(", ")
        }
    } else {
        quote_literal(value)
    };
    format!(
        "ALTER ROLE {} SET {} = {};",
        quote_ident(name),
        quote_ident(parameter),
        rendered_value
    )
}

// ---------------------------------------------------------------------------
// COMMENT ON ROLE
// ---------------------------------------------------------------------------

fn render_set_comment(name: &str, comment: &Option<String>) -> Vec<String> {
    vec![match comment {
        Some(text) => format!(
            "COMMENT ON ROLE {} IS {};",
            quote_ident(name),
            quote_literal(text)
        ),
        None => format!("COMMENT ON ROLE {} IS NULL;", quote_ident(name)),
    }]
}

// ---------------------------------------------------------------------------
// GRANT / REVOKE
// ---------------------------------------------------------------------------

/// Render a grantee for a GRANT/REVOKE subject position.
///
/// The PUBLIC pseudo-role must stay unquoted: `"PUBLIC"` would name an
/// ordinary role called PUBLIC instead.
pub fn render_grantee(grantee: &Grantee) -> String {
    match grantee {
        Grantee::Public => "PUBLIC".to_string(),
        Grantee::Role(name) => quote_ident(name),
    }
}

fn render_grant(
    role: &Grantee,
    privileges: &BTreeSet<Privilege>,
    object_type: ObjectType,
    schema: Option<&str>,
    name: Option<&str>,
    ctx: &SqlContext,
) -> Vec<String> {
    let privilege_list = format_privileges(privileges);
    render_privilege_statements(
        "GRANT",
        role,
        &privilege_list,
        object_type,
        schema,
        name,
        ctx,
    )
}

fn render_revoke(
    role: &Grantee,
    privileges: &BTreeSet<Privilege>,
    object_type: ObjectType,
    schema: Option<&str>,
    name: Option<&str>,
    ctx: &SqlContext,
) -> Vec<String> {
    render_privilege_statements(
        "REVOKE",
        role,
        &format_privileges(privileges),
        object_type,
        schema,
        name,
        ctx,
    )
}

fn render_privilege_statements(
    action: &str,
    role: &Grantee,
    privilege_list: &str,
    object_type: ObjectType,
    schema: Option<&str>,
    name: Option<&str>,
    ctx: &SqlContext,
) -> Vec<String> {
    let subject_preposition = if action == "GRANT" { "TO" } else { "FROM" };
    if matches!(
        object_type,
        ObjectType::Table
            | ObjectType::View
            | ObjectType::MaterializedView
            | ObjectType::Sequence
            | ObjectType::Function
    ) && name == Some("*")
    {
        return render_wildcard_expanded(
            action,
            subject_preposition,
            role,
            privilege_list,
            object_type,
            schema,
            ctx,
        );
    }

    let target = format_object_target(object_type, schema, name);
    vec![format!(
        "{action} {privilege_list} ON {target} {subject_preposition} {};",
        render_grantee(role)
    )]
}

fn render_wildcard_expanded(
    action: &str,
    subject_preposition: &str,
    role: &Grantee,
    privilege_list: &str,
    object_type: ObjectType,
    schema: Option<&str>,
    ctx: &SqlContext,
) -> Vec<String> {
    let schema_name = schema.unwrap_or("public");
    // Owner guard: a REVOKE must never touch objects the grantee owns. The
    // owner's privileges are inherent — see `SqlContext::owned_relations`.
    let skip_owned = action == "REVOKE";

    // Only revokes need per-object expansion (to apply the owner guard).
    // Grants have no owner interaction, so sequences and routines keep the
    // compact `ALL ... IN SCHEMA` form regardless of schema size.
    if !skip_owned && matches!(object_type, ObjectType::Sequence | ObjectType::Function) {
        return vec![format!(
            "{action} {privilege_list} ON {} {subject_preposition} {};",
            format_object_target(object_type, schema, Some("*")),
            render_grantee(role)
        )];
    }

    if let Some(object_names) = ctx
        .object_inventory
        .get(&(object_type, schema_name.to_string()))
    {
        return object_names
            .iter()
            .filter(|object_name| {
                !skip_owned
                    || !ctx.grantee_owns_relation(role, object_type, schema_name, object_name)
            })
            .map(|object_name| {
                let target = match object_type {
                    // Routine targets carry the identity arguments in the
                    // inventory name (`f(bigint)`).
                    ObjectType::Function => format_function_target(Some(schema_name), object_name),
                    _ => format!(
                        "{} {}.{}",
                        sql_object_type_keyword(object_type),
                        quote_ident(schema_name),
                        quote_ident(object_name)
                    ),
                };
                format!(
                    "{action} {privilege_list} ON {target} {subject_preposition} {};",
                    render_grantee(role)
                )
            })
            .collect();
    }

    // Inside the DO-block the grantee is normally a `%I` format argument.
    // PUBLIC must instead be embedded literally: `%I` would render it as the
    // quoted identifier "PUBLIC", which names an ordinary role.
    let (grantee_placeholder, grantee_argument) = match role {
        Grantee::Public => ("PUBLIC".to_string(), String::new()),
        Grantee::Role(name) => ("%I".to_string(), format!(", {}", quote_literal(name))),
    };

    // The owner guard survives the relation fallback too: exclude relations
    // owned by the grantee from the loop when revoking. Routines have no
    // DO-block fallback (pg_proc needs identity arguments); without inventory
    // they render in `ALL ROUTINES` form — contexts built by the CLI and the
    // operator always populate routine inventory.
    if object_type == ObjectType::Function {
        return vec![format!(
            "{action} {privilege_list} ON {} {subject_preposition} {};",
            format_object_target(object_type, schema, Some("*")),
            render_grantee(role)
        )];
    }
    let owner_filter = match (skip_owned, role) {
        (true, Grantee::Role(role_name)) => format!(
            "AND pg_get_userbyid(c.relowner) <> {}",
            quote_literal(role_name)
        ),
        _ => String::new(),
    };

    let type_keyword = sql_object_type_keyword(object_type);
    vec![format!(
        "DO $pgroles$\nDECLARE obj record;\nBEGIN\n  FOR obj IN\n    SELECT n.nspname AS schema_name, c.relname AS object_name\n    FROM pg_class c\n    JOIN pg_namespace n ON n.oid = c.relnamespace\n    WHERE c.relkind IN ({})\n      AND n.nspname = {}\n      {}\n    ORDER BY c.relname\n  LOOP\n    EXECUTE format('{} {} ON {type_keyword} %I.%I {} {};', obj.schema_name, obj.object_name{});\n  END LOOP;\nEND\n$pgroles$;",
        relation_relkinds_sql(object_type),
        quote_literal(schema_name),
        owner_filter,
        action,
        privilege_list,
        subject_preposition,
        grantee_placeholder,
        grantee_argument,
    )]
}

fn relation_relkinds_sql(object_type: ObjectType) -> &'static str {
    match object_type {
        ObjectType::Table => "'r', 'p'",
        ObjectType::View => "'v'",
        ObjectType::MaterializedView => "'m'",
        ObjectType::Sequence => "'S'",
        _ => unreachable!("relation_relkinds_literal only supports pg_class object types"),
    }
}

/// Format the object target for GRANT/REVOKE statements.
///
/// - Schema-level: `SCHEMA "myschema"` — object_type=Schema, name=Some("myschema")
/// - Wildcard: `ALL TABLES IN SCHEMA "myschema"` — name=Some("*")
/// - Specific: `TABLE "myschema"."mytable"` — name=Some("mytable")
/// - Database: `DATABASE "mydb"` — object_type=Database, name=Some("mydb")
fn format_object_target(
    object_type: ObjectType,
    schema: Option<&str>,
    name: Option<&str>,
) -> String {
    let type_keyword = sql_object_type_keyword(object_type);

    match object_type {
        ObjectType::Schema => {
            // Schema grants: name is the schema name itself
            let schema_name = name.unwrap_or("public");
            format!("{type_keyword} {}", quote_ident(schema_name))
        }
        ObjectType::Database => {
            let db_name = name.unwrap_or("postgres");
            format!("{type_keyword} {}", quote_ident(db_name))
        }
        ObjectType::Function => match name {
            Some("*") => {
                let schema_name = schema.unwrap_or("public");
                format!("ALL ROUTINES IN SCHEMA {}", quote_ident(schema_name))
            }
            Some(function_name) => format_function_target(schema, function_name),
            None => {
                let schema_name = schema.unwrap_or("public");
                format!("{type_keyword} {}", quote_ident(schema_name))
            }
        },
        _ => {
            match name {
                Some("*") => {
                    // Wildcard: ALL TABLES IN SCHEMA "schema"
                    let plural = sql_object_type_plural(object_type);
                    let schema_name = schema.unwrap_or("public");
                    format!("ALL {plural} IN SCHEMA {}", quote_ident(schema_name))
                }
                Some(obj_name) => {
                    // Specific object: TABLE "schema"."table"
                    let schema_name = schema.unwrap_or("public");
                    format!(
                        "{type_keyword} {}.{}",
                        quote_ident(schema_name),
                        quote_ident(obj_name)
                    )
                }
                None => {
                    // Shouldn't happen for non-schema/database types, but handle gracefully
                    let schema_name = schema.unwrap_or("public");
                    format!("{type_keyword} {}", quote_ident(schema_name))
                }
            }
        }
    }
}

fn format_function_target(schema: Option<&str>, function_name: &str) -> String {
    let schema_name = schema.unwrap_or("public");

    match function_name.rfind('(') {
        Some(paren_idx) if function_name.ends_with(')') => {
            let base_name = &function_name[..paren_idx];
            let args = &function_name[paren_idx..];
            format!(
                "ROUTINE {}.{}{}",
                quote_ident(schema_name),
                quote_ident(base_name),
                args
            )
        }
        _ => format!(
            "ROUTINE {}.{}",
            quote_ident(schema_name),
            quote_ident(function_name)
        ),
    }
}

/// Map ObjectType to the SQL keyword used in GRANT/REVOKE.
fn sql_object_type_keyword(object_type: ObjectType) -> &'static str {
    match object_type {
        ObjectType::Table => "TABLE",
        ObjectType::View => "TABLE", // PostgreSQL treats views as tables for GRANT
        ObjectType::MaterializedView => "TABLE", // Same
        ObjectType::Sequence => "SEQUENCE",
        ObjectType::Function => "ROUTINE",
        ObjectType::Schema => "SCHEMA",
        ObjectType::Database => "DATABASE",
        ObjectType::Type => "TYPE",
    }
}

/// Map ObjectType to the SQL plural keyword used in ALL ... IN SCHEMA.
fn sql_object_type_plural(object_type: ObjectType) -> &'static str {
    match object_type {
        ObjectType::Table | ObjectType::View | ObjectType::MaterializedView => "TABLES",
        ObjectType::Sequence => "SEQUENCES",
        ObjectType::Function => "ROUTINES",
        // PostgreSQL has no ALL TYPES IN SCHEMA syntax. Type grants should use
        // specific object names, not wildcards. If we get here the manifest is
        // likely misconfigured, but produce the closest valid SQL anyway.
        ObjectType::Type => "TABLES",
        // Schema/Database don't use ALL ... IN SCHEMA syntax
        ObjectType::Schema | ObjectType::Database => "TABLES",
    }
}

/// Format a privilege set as a comma-separated string.
pub(crate) fn format_privileges(privileges: &BTreeSet<Privilege>) -> String {
    privileges
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// ALTER DEFAULT PRIVILEGES
// ---------------------------------------------------------------------------

/// Map ObjectType to the keyword used in `ALTER DEFAULT PRIVILEGES ... ON`.
///
/// This differs from [`sql_object_type_plural`]: default privileges support
/// TYPES and SCHEMAS, and there is no `ALL ... IN SCHEMA` restriction here.
/// Manifest validation guarantees SCHEMAS only appears in global scope and
/// DATABASE never appears.
fn default_privilege_object_keyword(on_type: ObjectType) -> &'static str {
    match on_type {
        ObjectType::Table | ObjectType::View | ObjectType::MaterializedView => "TABLES",
        ObjectType::Sequence => "SEQUENCES",
        ObjectType::Function => "ROUTINES",
        ObjectType::Type => "TYPES",
        ObjectType::Schema => "SCHEMAS",
        // Manifest validation rejects database default privileges, so this is
        // unreachable. Rendering `TABLES` here would silently target the wrong
        // objects if that ever changed.
        ObjectType::Database => {
            unreachable!("default privileges on a database are rejected during manifest validation")
        }
    }
}

fn render_default_privilege_scope_clause(scope: &DefaultPrivilegeScope) -> String {
    match scope {
        DefaultPrivilegeScope::Global => String::new(),
        DefaultPrivilegeScope::Schema { schema } => {
            format!(" IN SCHEMA {}", quote_ident(schema))
        }
    }
}

fn render_set_default_privilege(
    owner: &str,
    scope: &DefaultPrivilegeScope,
    on_type: ObjectType,
    grantee: &Grantee,
    privileges: &BTreeSet<Privilege>,
) -> Vec<String> {
    let privilege_list = format_privileges(privileges);
    let type_keyword = default_privilege_object_keyword(on_type);
    vec![format!(
        "ALTER DEFAULT PRIVILEGES FOR ROLE {}{} GRANT {} ON {} TO {};",
        quote_ident(owner),
        render_default_privilege_scope_clause(scope),
        privilege_list,
        type_keyword,
        render_grantee(grantee)
    )]
}

fn render_revoke_default_privilege(
    owner: &str,
    scope: &DefaultPrivilegeScope,
    on_type: ObjectType,
    grantee: &Grantee,
    privileges: &BTreeSet<Privilege>,
) -> Vec<String> {
    let privilege_list = format_privileges(privileges);
    let type_keyword = default_privilege_object_keyword(on_type);
    vec![format!(
        "ALTER DEFAULT PRIVILEGES FOR ROLE {}{} REVOKE {} ON {} FROM {};",
        quote_ident(owner),
        render_default_privilege_scope_clause(scope),
        privilege_list,
        type_keyword,
        render_grantee(grantee)
    )]
}

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

fn render_add_member(
    role: &str,
    member: &str,
    inherit: bool,
    admin: bool,
    ctx: &SqlContext,
) -> Vec<String> {
    let mut sql = format!("GRANT {} TO {}", quote_ident(role), quote_ident(member));

    if ctx.supports_grant_with_options() {
        // PostgreSQL 16+: use WITH INHERIT / ADMIN syntax.
        let mut options = Vec::new();
        if inherit {
            options.push("INHERIT TRUE");
        } else {
            options.push("INHERIT FALSE");
        }
        if admin {
            options.push("ADMIN TRUE");
        }
        if !options.is_empty() {
            let _ = write!(sql, " WITH {}", options.join(", "));
        }
    } else {
        // PostgreSQL < 16: use legacy WITH ADMIN OPTION syntax.
        // INHERIT is controlled by the member role's attribute, not the grant.
        if admin {
            sql.push_str(" WITH ADMIN OPTION");
        }
    }

    sql.push(';');
    vec![sql]
}

fn render_remove_member(
    role: &str,
    member: &str,
    grantor: Option<&str>,
    ctx: &SqlContext,
) -> Vec<String> {
    // Since PostgreSQL 16 each membership edge records its grantor and a
    // plain REVOKE removes only the edge attributed to the revoker — an edge
    // granted by someone else survives with just a WARNING. `GRANTED BY`
    // targets the inspected edge exactly; it requires the grantor's
    // privileges, which the preflight verifies. Grantor data only exists on
    // PG16+ inspections, and pre-16 revokes are not grantor-attributed, so
    // the clause is version-gated alongside the data that feeds it.
    match grantor {
        Some(grantor) if ctx.supports_grant_with_options() => vec![format!(
            "REVOKE {} FROM {} GRANTED BY {};",
            quote_ident(role),
            quote_ident(member),
            quote_ident(grantor)
        )],
        _ => vec![format!(
            "REVOKE {} FROM {};",
            quote_ident(role),
            quote_ident(member)
        )],
    }
}

fn render_reassign_owned(from_role: &str, to_role: &str) -> Vec<String> {
    vec![format!(
        "REASSIGN OWNED BY {} TO {};",
        quote_ident(from_role),
        quote_ident(to_role)
    )]
}

fn render_drop_owned(role: &str) -> Vec<String> {
    vec![format!("DROP OWNED BY {};", quote_ident(role))]
}

fn render_terminate_sessions(role: &str) -> Vec<String> {
    vec![format!(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = {} AND pid <> pg_backend_pid();",
        quote_literal(role)
    )]
}

/// Render `ALTER ROLE ... PASSWORD` using a pre-computed SCRAM-SHA-256 verifier.
///
/// The `password` parameter is expected to be a SCRAM-SHA-256 verifier string
/// (starting with `SCRAM-SHA-256$`). PostgreSQL detects this prefix and stores
/// the verifier directly, so the cleartext password never appears in the SQL.
fn render_set_password(name: &str, password: &str) -> Vec<String> {
    vec![format!(
        "ALTER ROLE {} PASSWORD {};",
        quote_ident(name),
        quote_literal(password)
    )]
}

// ---------------------------------------------------------------------------
// String quoting
// ---------------------------------------------------------------------------

/// Single-quote a SQL string literal, escaping single quotes.
fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_ident_simple() {
        assert_eq!(quote_ident("simple"), "\"simple\"");
    }

    #[test]
    fn quote_ident_with_hyphen() {
        assert_eq!(quote_ident("inventory-editor"), "\"inventory-editor\"");
    }

    #[test]
    fn quote_ident_with_email() {
        assert_eq!(quote_ident("user@example.com"), "\"user@example.com\"");
    }

    #[test]
    fn quote_ident_with_embedded_quotes() {
        assert_eq!(quote_ident("has\"quote"), "\"has\"\"quote\"");
    }

    #[test]
    fn quote_literal_simple() {
        assert_eq!(quote_literal("hello"), "'hello'");
    }

    #[test]
    fn quote_literal_with_embedded_quotes() {
        assert_eq!(quote_literal("it's"), "'it''s'");
    }

    #[test]
    fn render_create_role_does_not_inline_config() {
        // Config for new roles is emitted by the diff engine as a separate
        // AlterRole change that orders after all CREATE ROLE statements.
        let change = Change::CreateRole {
            name: "blue".to_string(),
            state: RoleState {
                login: true,
                config: [("role".to_string(), "combined".to_string())]
                    .into_iter()
                    .collect(),
                ..RoleState::default()
            },
        };
        let statements = render_statements(&change);
        assert_eq!(statements.len(), 1);
        assert!(statements[0].starts_with("CREATE ROLE \"blue\""));
    }

    #[test]
    fn render_alter_role_config_only_emits_set_and_reset() {
        let change = Change::AlterRole {
            name: "blue".to_string(),
            attributes: vec![
                RoleAttribute::SetConfig("role".to_string(), "combined".to_string()),
                RoleAttribute::ResetConfig("statement_timeout".to_string()),
            ],
        };
        let statements = render_statements(&change);
        assert_eq!(
            statements,
            vec![
                "ALTER ROLE \"blue\" SET \"role\" = 'combined';".to_string(),
                "ALTER ROLE \"blue\" RESET \"statement_timeout\";".to_string(),
            ]
        );
    }

    #[test]
    fn render_alter_role_mixes_attributes_and_config() {
        let change = Change::AlterRole {
            name: "blue".to_string(),
            attributes: vec![
                RoleAttribute::Login(true),
                RoleAttribute::SetConfig("search_path".to_string(), "app, public".to_string()),
            ],
        };
        let statements = render_statements(&change);
        assert_eq!(
            statements,
            vec![
                "ALTER ROLE \"blue\" LOGIN;".to_string(),
                // List-quoted GUCs render one literal per element — a single
                // 'app, public' literal would store ONE schema named "app, public".
                "ALTER ROLE \"blue\" SET \"search_path\" = 'app', 'public';".to_string(),
            ]
        );
    }

    #[test]
    fn render_set_config_splits_list_guc_elements() {
        let change = Change::AlterRole {
            name: "blue".to_string(),
            attributes: vec![RoleAttribute::SetConfig(
                "search_path".to_string(),
                "\"$user\", public".to_string(),
            )],
        };
        let statements = render_statements(&change);
        assert_eq!(
            statements,
            vec!["ALTER ROLE \"blue\" SET \"search_path\" = '$user', 'public';".to_string()]
        );
    }

    #[test]
    fn render_set_config_keeps_non_list_values_as_single_literal() {
        let change = Change::AlterRole {
            name: "blue".to_string(),
            attributes: vec![RoleAttribute::SetConfig(
                "app.motd".to_string(),
                "hello, world".to_string(),
            )],
        };
        let statements = render_statements(&change);
        assert_eq!(
            statements,
            vec!["ALTER ROLE \"blue\" SET \"app.motd\" = 'hello, world';".to_string()]
        );
    }

    #[test]
    fn render_set_config_quotes_literal_values() {
        let change = Change::AlterRole {
            name: "blue".to_string(),
            attributes: vec![RoleAttribute::SetConfig(
                "app.tenant".to_string(),
                "o'brien".to_string(),
            )],
        };
        let statements = render_statements(&change);
        assert_eq!(
            statements,
            vec!["ALTER ROLE \"blue\" SET \"app.tenant\" = 'o''brien';".to_string()]
        );
    }

    #[test]
    fn render_create_role_basic() {
        let change = Change::CreateRole {
            name: "inventory-editor".to_string(),
            state: RoleState::default(),
        };
        let sql = render(&change);
        assert!(sql.starts_with("CREATE ROLE \"inventory-editor\""));
        assert!(sql.contains("NOLOGIN"));
        assert!(sql.contains("NOSUPERUSER"));
        assert!(sql.contains("INHERIT")); // default is INHERIT
        assert!(sql.ends_with(';'));
    }

    #[test]
    fn render_create_schema_with_owner() {
        let change = Change::CreateSchema {
            name: "inventory".to_string(),
            owner: Some("inventory_owner".to_string()),
        };
        assert_eq!(
            render(&change),
            "CREATE SCHEMA \"inventory\" AUTHORIZATION \"inventory_owner\";"
        );
    }

    #[test]
    fn render_create_schema_without_owner() {
        let change = Change::CreateSchema {
            name: "inventory".to_string(),
            owner: None,
        };
        assert_eq!(render(&change), "CREATE SCHEMA \"inventory\";");
    }

    #[test]
    fn render_alter_schema_owner() {
        let change = Change::AlterSchemaOwner {
            name: "inventory".to_string(),
            owner: "inventory_owner".to_string(),
        };
        assert_eq!(
            render(&change),
            "ALTER SCHEMA \"inventory\" OWNER TO \"inventory_owner\";"
        );
    }

    #[test]
    fn render_ensure_schema_owner_privileges() {
        let change = Change::EnsureSchemaOwnerPrivileges {
            name: "inventory".to_string(),
            owner: "inventory_owner".to_string(),
            privileges: BTreeSet::from([Privilege::Create, Privilege::Usage]),
        };
        assert_eq!(
            render(&change),
            "GRANT CREATE, USAGE ON SCHEMA \"inventory\" TO \"inventory_owner\";"
        );
    }

    #[test]
    fn render_create_role_with_login_and_comment() {
        let change = Change::CreateRole {
            name: "analytics".to_string(),
            state: RoleState {
                login: true,
                comment: Some("Analytics readonly role".to_string()),
                ..RoleState::default()
            },
        };
        let sql = render(&change);
        assert!(sql.contains("LOGIN"));
        assert!(sql.contains("COMMENT ON ROLE \"analytics\" IS 'Analytics readonly role';"));
    }

    #[test]
    fn render_alter_role() {
        let change = Change::AlterRole {
            name: "r1".to_string(),
            attributes: vec![RoleAttribute::Login(true), RoleAttribute::Createdb(true)],
        };
        let sql = render(&change);
        assert_eq!(sql, "ALTER ROLE \"r1\" LOGIN CREATEDB;");
    }

    #[test]
    fn render_drop_role() {
        let change = Change::DropRole {
            name: "old-role".to_string(),
        };
        assert_eq!(render(&change), "DROP ROLE IF EXISTS \"old-role\";");
    }

    #[test]
    fn render_grant_schema_usage() {
        let change = Change::Grant {
            role: "inventory-editor".into(),
            privileges: BTreeSet::from([Privilege::Usage]),
            object_type: ObjectType::Schema,
            schema: None,
            name: Some("inventory".to_string()),
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "GRANT USAGE ON SCHEMA \"inventory\" TO \"inventory-editor\";"
        );
    }

    #[test]
    fn render_grant_all_tables() {
        let change = Change::Grant {
            role: "inventory-editor".into(),
            privileges: BTreeSet::from([Privilege::Select, Privilege::Insert]),
            object_type: ObjectType::Table,
            schema: Some("inventory".to_string()),
            name: Some("*".to_string()),
        };
        let sql = render_statements_with_context(
            &change,
            &SqlContext::default().with_object_inventory(BTreeMap::from([(
                (ObjectType::Table, "inventory".to_string()),
                vec!["orders".to_string(), "widgets".to_string()],
            )])),
        )
        .join("\n");
        assert_eq!(
            sql,
            "GRANT INSERT, SELECT ON TABLE \"inventory\".\"orders\" TO \"inventory-editor\";\nGRANT INSERT, SELECT ON TABLE \"inventory\".\"widgets\" TO \"inventory-editor\";"
        );
    }

    #[test]
    fn render_wildcard_revoke_skips_objects_the_grantee_owns() {
        let change = Change::Revoke {
            grantor: None,
            role: "app_owner".into(),
            privileges: BTreeSet::from([Privilege::Update]),
            object_type: ObjectType::Table,
            schema: Some("mix".to_string()),
            name: Some("*".to_string()),
        };
        let inventory = BTreeMap::from([(
            (ObjectType::Table, "mix".to_string()),
            vec!["t_own".to_string(), "t_other".to_string()],
        )]);
        let owned = BTreeSet::from([(
            "app_owner".to_string(),
            ObjectType::Table,
            "mix".to_string(),
            "t_own".to_string(),
        )]);
        let ctx = SqlContext::default()
            .with_object_inventory(inventory)
            .with_owned_relations(owned);

        // The owned table is skipped; the other table's explicit drift revokes.
        assert_eq!(
            render_statements_with_context(&change, &ctx).join("\n"),
            "REVOKE UPDATE ON TABLE \"mix\".\"t_other\" FROM \"app_owner\";"
        );

        // GRANTs are not filtered — granting to an owner is a harmless no-op.
        let grant = Change::Grant {
            role: "app_owner".into(),
            privileges: BTreeSet::from([Privilege::Select]),
            object_type: ObjectType::Table,
            schema: Some("mix".to_string()),
            name: Some("*".to_string()),
        };
        assert_eq!(render_statements_with_context(&grant, &ctx).len(), 2);
    }

    #[test]
    fn render_wildcard_sequence_revoke_skips_owned_sequence() {
        let change = Change::Revoke {
            grantor: None,
            role: "seq_owner".into(),
            privileges: BTreeSet::from([Privilege::Update]),
            object_type: ObjectType::Sequence,
            schema: Some("mix".to_string()),
            name: Some("*".to_string()),
        };
        let ctx = SqlContext::default()
            .with_object_inventory(BTreeMap::from([(
                (ObjectType::Sequence, "mix".to_string()),
                vec!["seq_own".to_string(), "seq_other".to_string()],
            )]))
            .with_owned_relations(BTreeSet::from([(
                "seq_owner".to_string(),
                ObjectType::Sequence,
                "mix".to_string(),
                "seq_own".to_string(),
            )]));

        assert_eq!(
            render_statements_with_context(&change, &ctx).join("\n"),
            "REVOKE UPDATE ON SEQUENCE \"mix\".\"seq_other\" FROM \"seq_owner\";"
        );
    }

    #[test]
    fn render_wildcard_function_revoke_skips_owned_routine() {
        let change = Change::Revoke {
            grantor: None,
            role: "fn_owner".into(),
            privileges: BTreeSet::from([Privilege::Execute]),
            object_type: ObjectType::Function,
            schema: Some("mix".to_string()),
            name: Some("*".to_string()),
        };
        let ctx = SqlContext::default()
            .with_object_inventory(BTreeMap::from([(
                (ObjectType::Function, "mix".to_string()),
                vec!["f_own(bigint)".to_string(), "f_other(text)".to_string()],
            )]))
            .with_owned_relations(BTreeSet::from([(
                "fn_owner".to_string(),
                ObjectType::Function,
                "mix".to_string(),
                "f_own(bigint)".to_string(),
            )]));

        assert_eq!(
            render_statements_with_context(&change, &ctx).join("\n"),
            "REVOKE EXECUTE ON ROUTINE \"mix\".\"f_other\"(text) FROM \"fn_owner\";"
        );
    }

    #[test]
    fn render_wildcard_grants_keep_all_form_for_sequences_and_routines() {
        let seq = Change::Grant {
            role: "r1".into(),
            privileges: BTreeSet::from([Privilege::Usage]),
            object_type: ObjectType::Sequence,
            schema: Some("s".to_string()),
            name: Some("*".to_string()),
        };
        let ctx = SqlContext::default().with_object_inventory(BTreeMap::from([(
            (ObjectType::Sequence, "s".to_string()),
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
        )]));
        assert_eq!(
            render_statements_with_context(&seq, &ctx).join("\n"),
            "GRANT USAGE ON ALL SEQUENCES IN SCHEMA \"s\" TO \"r1\";"
        );

        let routine = Change::Grant {
            role: "r1".into(),
            privileges: BTreeSet::from([Privilege::Execute]),
            object_type: ObjectType::Function,
            schema: Some("s".to_string()),
            name: Some("*".to_string()),
        };
        assert_eq!(
            render_statements_with_context(&routine, &ctx).join("\n"),
            "GRANT EXECUTE ON ALL ROUTINES IN SCHEMA \"s\" TO \"r1\";"
        );
    }

    #[test]
    fn render_wildcard_sequence_do_block_excludes_owner() {
        let change = Change::Revoke {
            grantor: None,
            role: "seq_owner".into(),
            privileges: BTreeSet::from([Privilege::Update]),
            object_type: ObjectType::Sequence,
            schema: Some("mix".to_string()),
            name: Some("*".to_string()),
        };
        let sql = render_statements_with_context(&change, &SqlContext::default()).join("\n");
        assert!(
            sql.contains("relkind IN ('S')")
                && sql.contains("pg_get_userbyid(c.relowner) <> 'seq_owner'"),
            "sequence fallback must expand and exclude owner: {sql}"
        );
    }

    #[test]
    fn render_wildcard_revoke_do_block_excludes_owner() {
        let change = Change::Revoke {
            grantor: None,
            role: "app_owner".into(),
            privileges: BTreeSet::from([Privilege::Update]),
            object_type: ObjectType::Table,
            schema: Some("mix".to_string()),
            name: Some("*".to_string()),
        };
        let sql = render_statements_with_context(&change, &SqlContext::default()).join("\n");
        assert!(
            sql.contains("pg_get_userbyid(c.relowner) <> 'app_owner'"),
            "DO-block fallback must exclude owner-owned relations: {sql}"
        );
    }

    #[test]
    fn render_grant_specific_table() {
        let change = Change::Grant {
            role: "r1".into(),
            privileges: BTreeSet::from([Privilege::Select]),
            object_type: ObjectType::Table,
            schema: Some("public".to_string()),
            name: Some("users".to_string()),
        };
        let sql = render(&change);
        assert_eq!(sql, "GRANT SELECT ON TABLE \"public\".\"users\" TO \"r1\";");
    }

    #[test]
    fn render_grant_specific_function() {
        let change = Change::Grant {
            role: "r1".into(),
            privileges: BTreeSet::from([Privilege::Execute]),
            object_type: ObjectType::Function,
            schema: Some("public".to_string()),
            name: Some("refresh_users(integer, text)".to_string()),
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "GRANT EXECUTE ON ROUTINE \"public\".\"refresh_users\"(integer, text) TO \"r1\";"
        );
    }

    #[test]
    fn render_revoke_specific_routine_for_function_object() {
        let change = Change::Revoke {
            grantor: None,
            role: "r1".into(),
            privileges: BTreeSet::from([Privilege::Execute]),
            object_type: ObjectType::Function,
            schema: Some("public".to_string()),
            name: Some("run_something()".to_string()),
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "REVOKE EXECUTE ON ROUTINE \"public\".\"run_something\"() FROM \"r1\";"
        );
    }

    #[test]
    fn render_grant_all_routines_for_function_wildcard() {
        let change = Change::Grant {
            role: "inventory-editor".into(),
            privileges: BTreeSet::from([Privilege::Execute]),
            object_type: ObjectType::Function,
            schema: Some("inventory".to_string()),
            name: Some("*".to_string()),
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "GRANT EXECUTE ON ALL ROUTINES IN SCHEMA \"inventory\" TO \"inventory-editor\";"
        );
    }

    #[test]
    fn render_revoke_all_sequences() {
        let change = Change::Revoke {
            grantor: None,
            role: "inventory-editor".into(),
            privileges: BTreeSet::from([Privilege::Usage, Privilege::Select]),
            object_type: ObjectType::Sequence,
            schema: Some("inventory".to_string()),
            name: Some("*".to_string()),
        };
        let sql = render(&change);
        // Without inventory the sequence wildcard renders as a guarded
        // DO-block: per-object expansion keeps the owner guard available.
        assert!(
            sql.contains("relkind IN ('S')")
                && sql.contains("ON SEQUENCE %I.%I")
                && sql.contains("pg_get_userbyid(c.relowner) <> 'inventory-editor'"),
            "sequence wildcard should expand with owner exclusion: {sql}"
        );
    }

    #[test]
    fn render_set_default_privilege() {
        let change = Change::SetDefaultPrivilege {
            owner: "app_owner".to_string(),
            scope: DefaultPrivilegeScope::Schema {
                schema: "inventory".to_string(),
            },
            on_type: ObjectType::Table,
            grantee: "inventory-editor".into(),
            privileges: BTreeSet::from([Privilege::Select, Privilege::Insert]),
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "ALTER DEFAULT PRIVILEGES FOR ROLE \"app_owner\" IN SCHEMA \"inventory\" GRANT INSERT, SELECT ON TABLES TO \"inventory-editor\";"
        );
    }

    #[test]
    fn render_revoke_default_privilege() {
        let change = Change::RevokeDefaultPrivilege {
            owner: "app_owner".to_string(),
            scope: DefaultPrivilegeScope::Schema {
                schema: "inventory".to_string(),
            },
            on_type: ObjectType::Function,
            grantee: "inventory-editor".into(),
            privileges: BTreeSet::from([Privilege::Execute]),
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "ALTER DEFAULT PRIVILEGES FOR ROLE \"app_owner\" IN SCHEMA \"inventory\" REVOKE EXECUTE ON ROUTINES FROM \"inventory-editor\";"
        );
    }

    #[test]
    fn render_add_member_basic() {
        let change = Change::AddMember {
            role: "inventory-editor".to_string(),
            member: "user@example.com".to_string(),
            inherit: true,
            admin: false,
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "GRANT \"inventory-editor\" TO \"user@example.com\" WITH INHERIT TRUE;"
        );
    }

    #[test]
    fn render_add_member_with_admin() {
        let change = Change::AddMember {
            role: "inventory-editor".to_string(),
            member: "admin@example.com".to_string(),
            inherit: true,
            admin: true,
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "GRANT \"inventory-editor\" TO \"admin@example.com\" WITH INHERIT TRUE, ADMIN TRUE;"
        );
    }

    #[test]
    fn render_add_member_no_inherit() {
        let change = Change::AddMember {
            role: "inventory-editor".to_string(),
            member: "noinherit@example.com".to_string(),
            inherit: false,
            admin: false,
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "GRANT \"inventory-editor\" TO \"noinherit@example.com\" WITH INHERIT FALSE;"
        );
    }

    #[test]
    fn batch_preserves_order_role_boundaries_and_redaction() {
        let revoke = |schema: &str, grantor: &str| Change::Revoke {
            role: Grantee::Role("reader".into()),
            privileges: BTreeSet::from([Privilege::Usage]),
            object_type: ObjectType::Schema,
            schema: None,
            name: Some(schema.into()),
            grantor: Some(grantor.into()),
        };
        let changes = vec![
            revoke("a", "owner"),
            revoke("b", "owner"),
            revoke("c", "other"),
            revoke("d", "owner"),
            Change::SetPassword {
                name: "reader".into(),
                password: "secret".into(),
            },
            revoke("e", "owner"),
        ];
        let ctx = SqlContext::default().with_execution_role(Some("executor".into()));
        let batch = render_batch_with_context(&changes, &ctx);
        let full = batch
            .iter()
            .map(|s| s.sql.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(full, render_all_with_context(&changes, &ctx));
        assert_eq!(
            full.lines().collect::<Vec<_>>(),
            vec![
                "SET ROLE \"owner\";",
                "REVOKE USAGE ON SCHEMA \"a\" FROM \"reader\";",
                "REVOKE USAGE ON SCHEMA \"b\" FROM \"reader\";",
                "SET ROLE \"executor\";",
                "SET ROLE \"other\";",
                "REVOKE USAGE ON SCHEMA \"c\" FROM \"reader\";",
                "SET ROLE \"executor\";",
                "SET ROLE \"owner\";",
                "REVOKE USAGE ON SCHEMA \"d\" FROM \"reader\";",
                "SET ROLE \"executor\";",
                "ALTER ROLE \"reader\" PASSWORD 'secret';",
                "SET ROLE \"owner\";",
                "REVOKE USAGE ON SCHEMA \"e\" FROM \"reader\";",
                "SET ROLE \"executor\";",
            ]
        );
        assert_eq!(full.matches("SET ROLE \"owner\";").count(), 3);
        assert_eq!(full.matches("SET ROLE \"executor\";").count(), 4);
        assert!(full.contains("FROM \"reader\";\nREVOKE USAGE ON SCHEMA \"b\""));
        assert!(full.contains("SET ROLE \"executor\";\nALTER ROLE"));
        let redacted = batch
            .iter()
            .map(|s| s.redacted_sql.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!redacted.contains("secret"));
        assert!(redacted.contains("PASSWORD '[REDACTED]'"));
        assert!(full.contains("secret"));
        assert!(render_batch_with_context(&[], &ctx).is_empty());
    }

    #[test]
    fn batch_keeps_wildcard_expansion_in_one_role_block() {
        let change = Change::Revoke {
            role: Grantee::Role("reader".into()),
            privileges: BTreeSet::from([Privilege::Select]),
            object_type: ObjectType::Table,
            schema: Some("app".into()),
            name: Some("*".into()),
            grantor: Some("owner".into()),
        };
        let ctx = SqlContext::default().with_object_inventory(BTreeMap::from([(
            (ObjectType::Table, "app".into()),
            vec!["a".into(), "b".into()],
        )]));
        let sql = render_all_with_context(&[change.clone(), change], &ctx);
        assert_eq!(
            sql.lines()
                .filter(|line| line.starts_with("SET ROLE"))
                .count(),
            1
        );
        assert_eq!(sql.matches("RESET ROLE").count(), 1);
        assert_eq!(sql.matches("REVOKE SELECT").count(), 4);
    }

    #[test]
    fn render_revoke_with_grantor_wraps_in_set_role() {
        let change = Change::Revoke {
            role: Grantee::Role("analyst".into()),
            privileges: BTreeSet::from([Privilege::Select]),
            object_type: ObjectType::Table,
            schema: Some("app".to_string()),
            name: Some("orders".to_string()),
            grantor: Some("report_owner".to_string()),
        };
        let statements = render_statements(&change);
        assert_eq!(
            statements,
            vec![
                "SET ROLE \"report_owner\";".to_string(),
                "REVOKE SELECT ON TABLE \"app\".\"orders\" FROM \"analyst\";".to_string(),
                "RESET ROLE;".to_string(),
            ]
        );
    }

    #[test]
    fn render_revoke_with_grantor_restores_execution_role() {
        // With a configured execution role (operator setRole / `-c role=...`),
        // RESET ROLE would fall back to the *login* role and drop that
        // boundary for the rest of the plan; the restore must be explicit.
        let ctx = SqlContext::default().with_execution_role(Some("pg_admin".to_string()));
        let change = Change::Revoke {
            role: Grantee::Role("analyst".into()),
            privileges: BTreeSet::from([Privilege::Select]),
            object_type: ObjectType::Table,
            schema: Some("app".to_string()),
            name: Some("orders".to_string()),
            grantor: Some("report_owner".to_string()),
        };
        let statements = render_statements_with_context(&change, &ctx);
        assert_eq!(
            statements,
            vec![
                "SET ROLE \"report_owner\";".to_string(),
                "REVOKE SELECT ON TABLE \"app\".\"orders\" FROM \"analyst\";".to_string(),
                "SET ROLE \"pg_admin\";".to_string(),
            ]
        );
    }

    #[test]
    fn render_remove_member_with_grantor_uses_granted_by() {
        let change = Change::RemoveMember {
            role: "editors".to_string(),
            member: "user@example.com".to_string(),
            grantor: Some("team_lead".to_string()),
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "REVOKE \"editors\" FROM \"user@example.com\" GRANTED BY \"team_lead\";"
        );
    }

    #[test]
    fn render_remove_member_grantor_is_dropped_pre_pg16() {
        // Pre-16 revokes are not grantor-attributed and GRANTED BY for role
        // revocation follows the per-edge grantor model, so the clause is
        // version-gated with the data that feeds it.
        let ctx = SqlContext {
            pg_major_version: 15,
            ..Default::default()
        };
        let change = Change::RemoveMember {
            role: "editors".to_string(),
            member: "user@example.com".to_string(),
            grantor: Some("team_lead".to_string()),
        };
        let sql = render_statements_with_context(&change, &ctx).join("\n");
        assert_eq!(sql, "REVOKE \"editors\" FROM \"user@example.com\";");
    }

    #[test]
    fn render_remove_member() {
        let change = Change::RemoveMember {
            grantor: None,
            role: "inventory-editor".to_string(),
            member: "user@example.com".to_string(),
        };
        let sql = render(&change);
        assert_eq!(
            sql,
            "REVOKE \"inventory-editor\" FROM \"user@example.com\";"
        );
    }

    #[test]
    fn render_reassign_owned() {
        let change = Change::ReassignOwned {
            from_role: "legacy-owner".to_string(),
            to_role: "app-owner".to_string(),
        };
        assert_eq!(
            render(&change),
            "REASSIGN OWNED BY \"legacy-owner\" TO \"app-owner\";"
        );
    }

    #[test]
    fn render_drop_owned() {
        let change = Change::DropOwned {
            role: "legacy-owner".to_string(),
        };
        assert_eq!(render(&change), "DROP OWNED BY \"legacy-owner\";");
    }

    #[test]
    fn render_terminate_sessions() {
        let change = Change::TerminateSessions {
            role: "legacy-owner".to_string(),
        };
        assert_eq!(
            render(&change),
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'legacy-owner' AND pid <> pg_backend_pid();"
        );
    }

    #[test]
    fn render_set_comment_some() {
        let change = Change::SetComment {
            name: "r1".to_string(),
            comment: Some("A test role".to_string()),
        };
        assert_eq!(render(&change), "COMMENT ON ROLE \"r1\" IS 'A test role';");
    }

    #[test]
    fn render_set_comment_none() {
        let change = Change::SetComment {
            name: "r1".to_string(),
            comment: None,
        };
        assert_eq!(render(&change), "COMMENT ON ROLE \"r1\" IS NULL;");
    }

    // -----------------------------------------------------------------------
    // PG version-dependent rendering
    // -----------------------------------------------------------------------

    #[test]
    fn render_add_member_pg15_legacy_syntax() {
        let ctx = SqlContext {
            pg_major_version: 15,
            ..Default::default()
        };
        let change = Change::AddMember {
            role: "editors".to_string(),
            member: "user@example.com".to_string(),
            inherit: true,
            admin: false,
        };
        let sql = render_statements_with_context(&change, &ctx).join("\n");
        assert_eq!(sql, "GRANT \"editors\" TO \"user@example.com\";");
    }

    #[test]
    fn render_add_member_pg15_with_admin() {
        let ctx = SqlContext {
            pg_major_version: 15,
            ..Default::default()
        };
        let change = Change::AddMember {
            role: "editors".to_string(),
            member: "admin@example.com".to_string(),
            inherit: true,
            admin: true,
        };
        let sql = render_statements_with_context(&change, &ctx).join("\n");
        assert_eq!(
            sql,
            "GRANT \"editors\" TO \"admin@example.com\" WITH ADMIN OPTION;"
        );
    }

    #[test]
    fn render_add_member_pg16_with_options() {
        let ctx = SqlContext {
            pg_major_version: 16,
            ..Default::default()
        };
        let change = Change::AddMember {
            role: "editors".to_string(),
            member: "user@example.com".to_string(),
            inherit: false,
            admin: true,
        };
        let sql = render_statements_with_context(&change, &ctx).join("\n");
        assert_eq!(
            sql,
            "GRANT \"editors\" TO \"user@example.com\" WITH INHERIT FALSE, ADMIN TRUE;"
        );
    }

    #[test]
    fn render_materialized_view_wildcard_with_inventory_expands_per_object() {
        let ctx = SqlContext::default().with_object_inventory(BTreeMap::from([(
            (ObjectType::MaterializedView, "reporting".to_string()),
            vec!["daily_sales".to_string(), "weekly_sales".to_string()],
        )]));
        let change = Change::Revoke {
            grantor: None,
            role: "analytics".into(),
            privileges: [Privilege::Select].into_iter().collect(),
            object_type: ObjectType::MaterializedView,
            schema: Some("reporting".to_string()),
            name: Some("*".to_string()),
        };

        let sql = render_statements_with_context(&change, &ctx);
        assert_eq!(
            sql,
            vec![
                "REVOKE SELECT ON TABLE \"reporting\".\"daily_sales\" FROM \"analytics\";"
                    .to_string(),
                "REVOKE SELECT ON TABLE \"reporting\".\"weekly_sales\" FROM \"analytics\";"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn render_materialized_view_wildcard_without_inventory_uses_catalog_loop() {
        let change = Change::Revoke {
            grantor: None,
            role: "analytics".into(),
            privileges: [Privilege::Select].into_iter().collect(),
            object_type: ObjectType::MaterializedView,
            schema: Some("reporting".to_string()),
            name: Some("*".to_string()),
        };

        let sql = render_statements_with_context(&change, &SqlContext::default());
        assert_eq!(sql.len(), 1);
        assert!(sql[0].contains("WHERE c.relkind IN ('m')"));
        assert!(sql[0].contains("REVOKE SELECT ON TABLE %I.%I FROM %I;"));
    }

    // -----------------------------------------------------------------------
    // JSON serialization of changes
    // -----------------------------------------------------------------------

    #[test]
    fn change_serializes_to_json() {
        let change = Change::CreateRole {
            name: "test".to_string(),
            state: RoleState::default(),
        };
        let json = serde_json::to_string(&change).unwrap();
        assert!(json.contains("CreateRole"));
        assert!(json.contains("test"));
    }

    /// Full integration: manifest → expand → model → diff → SQL
    #[test]
    fn full_pipeline_manifest_to_sql() {
        use crate::diff::diff;
        use crate::manifest::{expand_manifest, parse_manifest};
        use crate::model::RoleGraph;

        let yaml = r#"
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
    owner: inventory_owner
    profiles: [editor]

memberships:
  - role: inventory-editor
    members:
      - name: "user@example.com"
"#;
        let manifest = parse_manifest(yaml).unwrap();
        let expanded = expand_manifest(&manifest).unwrap();
        let desired =
            RoleGraph::from_expanded(&expanded, manifest.default_owner.as_deref()).unwrap();
        let current = RoleGraph::default();

        let changes = diff(&current, &desired);
        let sql = render_all(&changes);

        // Smoke test: the output should contain key SQL statements
        assert!(sql.contains("CREATE ROLE \"inventory-editor\""));
        assert!(sql.contains("CREATE SCHEMA \"inventory\" AUTHORIZATION \"inventory_owner\";"));
        assert!(sql.contains("GRANT USAGE ON SCHEMA \"inventory\" TO \"inventory-editor\""));
        assert!(sql.contains("GRANT DELETE, INSERT, SELECT, UPDATE ON TABLE"));
        assert!(sql.contains("ALTER DEFAULT PRIVILEGES"));
        assert!(sql.contains("GRANT \"inventory-editor\" TO \"user@example.com\""));

        // Print for manual inspection during development
        #[cfg(test)]
        {
            eprintln!("--- Generated SQL ---\n{sql}\n--- End ---");
        }
    }

    #[test]
    fn render_set_password() {
        let change = Change::SetPassword {
            name: "app-service".to_string(),
            password: "s3cret!".to_string(),
        };
        let sql = render(&change);
        assert_eq!(sql, "ALTER ROLE \"app-service\" PASSWORD 's3cret!';");
    }

    #[test]
    fn render_set_password_escapes_quotes() {
        let change = Change::SetPassword {
            name: "r1".to_string(),
            password: "pass'word".to_string(),
        };
        let sql = render(&change);
        assert_eq!(sql, "ALTER ROLE \"r1\" PASSWORD 'pass''word';");
    }

    #[test]
    fn render_set_password_with_backslash() {
        let change = Change::SetPassword {
            name: "r1".to_string(),
            password: r"pass\word".to_string(),
        };
        let sql = render(&change);
        assert_eq!(sql, r#"ALTER ROLE "r1" PASSWORD 'pass\word';"#);
    }

    #[test]
    fn render_set_password_with_dollar_signs() {
        let change = Change::SetPassword {
            name: "r1".to_string(),
            password: "pa$$word".to_string(),
        };
        let sql = render(&change);
        assert_eq!(sql, "ALTER ROLE \"r1\" PASSWORD 'pa$$word';");
    }

    #[test]
    fn render_set_password_with_unicode() {
        let change = Change::SetPassword {
            name: "r1".to_string(),
            password: "pässwörd_日本語".to_string(),
        };
        let sql = render(&change);
        assert_eq!(sql, "ALTER ROLE \"r1\" PASSWORD 'pässwörd_日本語';");
    }

    #[test]
    fn render_set_password_with_newline() {
        let change = Change::SetPassword {
            name: "r1".to_string(),
            password: "line1\nline2".to_string(),
        };
        let sql = render(&change);
        // Newlines are passed through in single-quoted strings — PostgreSQL handles them.
        assert_eq!(sql, "ALTER ROLE \"r1\" PASSWORD 'line1\nline2';");
    }

    #[test]
    fn quote_literal_with_backslash() {
        // PostgreSQL standard_conforming_strings=on (default since 9.1):
        // backslashes are literal in standard strings.
        assert_eq!(quote_literal(r"back\slash"), r"'back\slash'");
    }

    #[test]
    fn quote_literal_with_multiple_quotes() {
        assert_eq!(quote_literal("it's a 'test'"), "'it''s a ''test'''");
    }

    #[test]
    fn render_create_role_with_valid_until() {
        let change = Change::CreateRole {
            name: "expiring-role".to_string(),
            state: RoleState {
                login: true,
                password_valid_until: Some("2025-12-31T00:00:00Z".to_string()),
                ..RoleState::default()
            },
        };
        let sql = render(&change);
        assert!(sql.contains("LOGIN"));
        assert!(sql.contains("VALID UNTIL '2025-12-31T00:00:00Z'"));
    }

    #[test]
    fn render_alter_role_valid_until_set() {
        let change = Change::AlterRole {
            name: "r1".to_string(),
            attributes: vec![RoleAttribute::ValidUntil(Some(
                "2025-06-01T00:00:00Z".to_string(),
            ))],
        };
        let sql = render(&change);
        assert_eq!(sql, "ALTER ROLE \"r1\" VALID UNTIL '2025-06-01T00:00:00Z';");
    }

    #[test]
    fn render_alter_role_valid_until_remove() {
        let change = Change::AlterRole {
            name: "r1".to_string(),
            attributes: vec![RoleAttribute::ValidUntil(None)],
        };
        let sql = render(&change);
        assert_eq!(sql, "ALTER ROLE \"r1\" VALID UNTIL 'infinity';");
    }

    // -----------------------------------------------------------------------
    // PUBLIC grantee and global default privileges
    // -----------------------------------------------------------------------

    #[test]
    fn public_renders_unquoted_but_a_role_named_public_does_not() {
        let revoke_public = render(&Change::Revoke {
            grantor: None,
            role: Grantee::Public,
            privileges: [Privilege::Execute].into_iter().collect(),
            object_type: ObjectType::Function,
            schema: Some("api".to_string()),
            name: Some("f()".to_string()),
        });
        assert_eq!(
            revoke_public,
            r#"REVOKE EXECUTE ON ROUTINE "api"."f"() FROM PUBLIC;"#
        );

        let grant_public = render(&Change::Grant {
            role: Grantee::Public,
            privileges: [Privilege::Usage].into_iter().collect(),
            object_type: ObjectType::Schema,
            schema: None,
            name: Some("api".to_string()),
        });
        assert_eq!(grant_public, r#"GRANT USAGE ON SCHEMA "api" TO PUBLIC;"#);

        // A real role that merely looks like the keyword stays quoted.
        let lowercase = render(&Change::Grant {
            role: "public".into(),
            privileges: [Privilege::Usage].into_iter().collect(),
            object_type: ObjectType::Schema,
            schema: None,
            name: Some("api".to_string()),
        });
        assert_eq!(lowercase, r#"GRANT USAGE ON SCHEMA "api" TO "public";"#);
    }

    #[test]
    fn public_wildcard_revoke_uses_all_routines_in_schema() {
        assert_eq!(
            render(&Change::Revoke {
                grantor: None,
                role: Grantee::Public,
                privileges: [Privilege::Execute].into_iter().collect(),
                object_type: ObjectType::Function,
                schema: Some("api".to_string()),
                name: Some("*".to_string()),
            }),
            r#"REVOKE EXECUTE ON ALL ROUTINES IN SCHEMA "api" FROM PUBLIC;"#
        );
    }

    #[test]
    fn relation_wildcard_do_block_embeds_public_literally() {
        // `%I` would render the keyword as the quoted identifier "PUBLIC",
        // which names an ordinary role.
        let sql = render(&Change::Revoke {
            grantor: None,
            role: Grantee::Public,
            privileges: [Privilege::Select].into_iter().collect(),
            object_type: ObjectType::Table,
            schema: Some("app".to_string()),
            name: Some("*".to_string()),
        });
        assert!(sql.contains("FROM PUBLIC;'"), "{sql}");
        assert!(!sql.contains("FROM %I"), "{sql}");

        // Ordinary roles still go through the %I parameter.
        let role_sql = render(&Change::Revoke {
            grantor: None,
            role: "reader".into(),
            privileges: [Privilege::Select].into_iter().collect(),
            object_type: ObjectType::Table,
            schema: Some("app".to_string()),
            name: Some("*".to_string()),
        });
        assert!(role_sql.contains("FROM %I"), "{role_sql}");
        assert!(role_sql.contains("'reader'"), "{role_sql}");
    }

    #[test]
    fn global_default_privileges_render_without_in_schema() {
        assert_eq!(
            render(&Change::RevokeDefaultPrivilege {
                owner: "function_owner".to_string(),
                scope: DefaultPrivilegeScope::Global,
                on_type: ObjectType::Function,
                grantee: Grantee::Public,
                privileges: [Privilege::Execute].into_iter().collect(),
            }),
            r#"ALTER DEFAULT PRIVILEGES FOR ROLE "function_owner" REVOKE EXECUTE ON ROUTINES FROM PUBLIC;"#
        );

        assert_eq!(
            render(&Change::SetDefaultPrivilege {
                owner: "app_owner".to_string(),
                scope: DefaultPrivilegeScope::Schema {
                    schema: "app".to_string()
                },
                on_type: ObjectType::Function,
                grantee: "reader".into(),
                privileges: [Privilege::Execute].into_iter().collect(),
            }),
            r#"ALTER DEFAULT PRIVILEGES FOR ROLE "app_owner" IN SCHEMA "app" GRANT EXECUTE ON ROUTINES TO "reader";"#
        );
    }

    #[test]
    fn default_privilege_object_keywords_cover_types_and_schemas() {
        let keyword_for = |on_type| {
            render(&Change::SetDefaultPrivilege {
                owner: "o".to_string(),
                scope: DefaultPrivilegeScope::Global,
                on_type,
                grantee: "r".into(),
                privileges: [Privilege::Usage].into_iter().collect(),
            })
        };
        assert!(keyword_for(ObjectType::Type).contains("ON TYPES"));
        assert!(keyword_for(ObjectType::Schema).contains("ON SCHEMAS"));
        assert!(keyword_for(ObjectType::Table).contains("ON TABLES"));
        assert!(keyword_for(ObjectType::Sequence).contains("ON SEQUENCES"));
        assert!(keyword_for(ObjectType::Function).contains("ON ROUTINES"));
    }
}
