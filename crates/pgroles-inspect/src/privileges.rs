//! Query object privileges from PostgreSQL catalog tables.
//!
//! Uses `aclexplode()` to decompose explicit ACL arrays from `pg_class`,
//! `pg_namespace`, `pg_proc`, `pg_type`, and `pg_database`.
//!
//! Managed-role inspection intentionally does not synthesize owner/default ACLs
//! from `acldefault(...)`. Doing so would make implicit owner privileges appear
//! as explicit managed grants, causing drift where the manifest never declared
//! those self-grants.
//!
//! PUBLIC (ACL grantee OID 0) is different: when the manifest declares PUBLIC
//! rules, [`fetch_public_object_privileges`] reports PUBLIC's *effective*
//! privileges for exactly those scopes, using `acldefault` for NULL ACLs and
//! keeping only grantee-0 entries. Informational PUBLIC display for `inspect`
//! output still lives in the `public_grants` module.
//!
//! The privilege character mapping:
//!   r = SELECT, a = INSERT, w = UPDATE, d = DELETE, D = TRUNCATE,
//!   x = REFERENCES, t = TRIGGER, X = EXECUTE, U = USAGE, C = CREATE,
//!   c = CONNECT, T = TEMPORARY

use std::collections::{BTreeMap, BTreeSet};

use sqlx::PgPool;

use crate::{
    ColumnLevelGrantDiagnostic, UnsatisfiableWildcardGrant, UnsatisfiableWildcardObject,
    WildcardGrantPattern, WildcardInspectionStats,
};
use pgroles_core::manifest::{ObjectType, Privilege};
use pgroles_core::model::{GrantKey, GrantState, Grantee};

use crate::PublicObjectScope;

/// A raw ACL row returned by our `aclexplode()` queries.
///
/// Rows are kept verbatim by [`RawPrivilegeState`] so a single read over a
/// union of scopes can be narrowed in memory to any scope it covers — the
/// row-level predicates below are exactly the SQL `WHERE` clauses of the
/// per-scope queries.
#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct AclRow {
    /// The grantee role name. Privilege queries filter to managed roles in SQL;
    /// inventory queries synthesize NULL because they do not carry grantees.
    pub(crate) grantee: Option<String>,
    /// The privilege type as a single character (e.g. 'r' for SELECT).
    pub(crate) privilege_type: String,
    /// The schema name (NULL for database-level grants).
    pub(crate) schema_name: Option<String>,
    /// The object name (the schema name itself for schema-level grants).
    pub(crate) object_name: String,
    /// The object type discriminator we embed in the query.
    pub(crate) obj_type: String,
}

impl AclRow {
    /// The schema this row is scoped by, mirroring the `n.nspname = ANY($1)`
    /// predicate of every privilege query: schema-level rows carry the schema
    /// in `object_name` (their `schema_name` is NULL by construction).
    fn scoping_schema(&self) -> Option<&str> {
        match self.obj_type.as_str() {
            "schema" => Some(self.object_name.as_str()),
            _ => self.schema_name.as_deref(),
        }
    }

    /// Is this row inside `schemas` × `roles` — the scope a per-config query
    /// would have asked the server for?
    fn in_scope(&self, schemas: &BTreeSet<String>, roles: &BTreeSet<String>) -> bool {
        let schema_matches = self
            .scoping_schema()
            .is_some_and(|schema| schemas.contains(schema));
        let grantee_matches = self
            .grantee
            .as_deref()
            .is_some_and(|grantee| roles.contains(grantee));
        schema_matches && grantee_matches
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(crate) struct GrantabilityRow {
    schema_name: String,
    object_name: String,
    owner_name: String,
    obj_type: String,
    can_select: bool,
    can_insert: bool,
    can_update: bool,
    can_delete: bool,
    can_truncate: bool,
    can_references: bool,
    can_trigger: bool,
    can_execute: bool,
    can_usage: bool,
}

impl GrantabilityRow {
    /// Narrow this row to the privileges a scope actually asks about.
    ///
    /// The grantability query computes each `can_*` as
    /// `need AND (owner OR has_privilege(... WITH GRANT OPTION))`, so a row
    /// read with every `need` set to true masks down, by simple conjunction,
    /// to exactly the row a narrower `need` set would have produced. This is
    /// what lets one grantability read serve many scopes.
    fn masked(&self, needs: &BTreeSet<Privilege>) -> Self {
        Self {
            schema_name: self.schema_name.clone(),
            object_name: self.object_name.clone(),
            owner_name: self.owner_name.clone(),
            obj_type: self.obj_type.clone(),
            can_select: self.can_select && needs.contains(&Privilege::Select),
            can_insert: self.can_insert && needs.contains(&Privilege::Insert),
            can_update: self.can_update && needs.contains(&Privilege::Update),
            can_delete: self.can_delete && needs.contains(&Privilege::Delete),
            can_truncate: self.can_truncate && needs.contains(&Privilege::Truncate),
            can_references: self.can_references && needs.contains(&Privilege::References),
            can_trigger: self.can_trigger && needs.contains(&Privilege::Trigger),
            can_execute: self.can_execute && needs.contains(&Privilege::Execute),
            can_usage: self.can_usage && needs.contains(&Privilege::Usage),
        }
    }
}

pub(crate) struct PrivilegeInspectionResult {
    pub grants: BTreeMap<GrantKey, GrantState>,
    pub diagnostics: Vec<UnsatisfiableWildcardGrant>,
    pub wildcard_stats: WildcardInspectionStats,
}

/// The `(object_type, schema)` pairs a set of wildcard grants selects over,
/// each with the privileges wanted somewhere in that pair.
#[derive(Debug, Clone, Default)]
pub(crate) struct WildcardScopeFilter {
    scopes: BTreeMap<(ObjectType, String), BTreeSet<Privilege>>,
}

/// The array-per-column form the SQL `unnest(...)` scope CTE binds.
struct WildcardScopeArrays {
    schema_names: Vec<String>,
    object_types: Vec<String>,
    need_select: Vec<bool>,
    need_insert: Vec<bool>,
    need_update: Vec<bool>,
    need_delete: Vec<bool>,
    need_truncate: Vec<bool>,
    need_references: Vec<bool>,
    need_trigger: Vec<bool>,
    need_execute: Vec<bool>,
    need_usage: Vec<bool>,
}

impl WildcardScopeFilter {
    fn from_wildcards(wildcard_grants: &[WildcardGrantPattern]) -> Self {
        let mut scopes: BTreeMap<(ObjectType, String), BTreeSet<Privilege>> = BTreeMap::new();

        for wildcard in wildcard_grants {
            if matches!(
                wildcard.object_type,
                ObjectType::Schema | ObjectType::Database
            ) {
                continue;
            }

            scopes
                .entry((wildcard.object_type, wildcard.schema.clone()))
                .or_default()
                .extend(wildcard.privileges.iter().copied());
        }

        Self { scopes }
    }

    /// A filter over `scopes` that asks about every privilege.
    ///
    /// Used for the shared grantability read: the resulting rows carry the
    /// unmasked truth, which [`GrantabilityRow::masked`] narrows per scope.
    pub(crate) fn from_scopes(scopes: &BTreeSet<(ObjectType, String)>) -> Self {
        Self {
            scopes: scopes
                .iter()
                .filter(|(object_type, _)| {
                    !matches!(object_type, ObjectType::Schema | ObjectType::Database)
                })
                .map(|scope| (scope.clone(), all_privileges()))
                .collect(),
        }
    }

    fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }

    fn len(&self) -> usize {
        self.scopes.len()
    }

    fn unique_schemas(&self) -> Vec<String> {
        self.scopes
            .keys()
            .map(|(_, schema)| schema.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    fn contains(&self, object_type: ObjectType, schema_name: &str) -> bool {
        self.scopes
            .contains_key(&(object_type, schema_name.to_string()))
    }

    fn needs(&self, object_type: ObjectType, schema_name: &str) -> Option<&BTreeSet<Privilege>> {
        self.scopes.get(&(object_type, schema_name.to_string()))
    }

    fn arrays(&self) -> WildcardScopeArrays {
        let mut arrays = WildcardScopeArrays {
            schema_names: Vec::with_capacity(self.scopes.len()),
            object_types: Vec::with_capacity(self.scopes.len()),
            need_select: Vec::with_capacity(self.scopes.len()),
            need_insert: Vec::with_capacity(self.scopes.len()),
            need_update: Vec::with_capacity(self.scopes.len()),
            need_delete: Vec::with_capacity(self.scopes.len()),
            need_truncate: Vec::with_capacity(self.scopes.len()),
            need_references: Vec::with_capacity(self.scopes.len()),
            need_trigger: Vec::with_capacity(self.scopes.len()),
            need_execute: Vec::with_capacity(self.scopes.len()),
            need_usage: Vec::with_capacity(self.scopes.len()),
        };

        for ((object_type, schema), privileges) in &self.scopes {
            arrays.schema_names.push(schema.clone());
            arrays
                .object_types
                .push(object_type_label(*object_type).to_string());
            arrays
                .need_select
                .push(privileges.contains(&Privilege::Select));
            arrays
                .need_insert
                .push(privileges.contains(&Privilege::Insert));
            arrays
                .need_update
                .push(privileges.contains(&Privilege::Update));
            arrays
                .need_delete
                .push(privileges.contains(&Privilege::Delete));
            arrays
                .need_truncate
                .push(privileges.contains(&Privilege::Truncate));
            arrays
                .need_references
                .push(privileges.contains(&Privilege::References));
            arrays
                .need_trigger
                .push(privileges.contains(&Privilege::Trigger));
            arrays
                .need_execute
                .push(privileges.contains(&Privilege::Execute));
            arrays
                .need_usage
                .push(privileges.contains(&Privilege::Usage));
        }

        arrays
    }
}

/// Map a PostgreSQL ACL privilege character to our `Privilege` enum.
fn acl_char_to_privilege(character: &str) -> Option<Privilege> {
    match character {
        "r" | "SELECT" => Some(Privilege::Select),
        "a" | "INSERT" => Some(Privilege::Insert),
        "w" | "UPDATE" => Some(Privilege::Update),
        "d" | "DELETE" => Some(Privilege::Delete),
        "D" | "TRUNCATE" => Some(Privilege::Truncate),
        "x" | "REFERENCES" => Some(Privilege::References),
        "t" | "TRIGGER" => Some(Privilege::Trigger),
        "X" | "EXECUTE" => Some(Privilege::Execute),
        "U" | "USAGE" => Some(Privilege::Usage),
        "C" | "CREATE" => Some(Privilege::Create),
        "c" | "CONNECT" => Some(Privilege::Connect),
        "T" | "TEMPORARY" => Some(Privilege::Temporary),
        _ => None,
    }
}

/// Map our query's `obj_type` discriminator string to an `ObjectType`.
fn obj_type_str_to_object_type(obj_type: &str) -> Option<ObjectType> {
    match obj_type {
        "table" => Some(ObjectType::Table),
        "view" => Some(ObjectType::View),
        "materialized_view" => Some(ObjectType::MaterializedView),
        "sequence" => Some(ObjectType::Sequence),
        "function" => Some(ObjectType::Function),
        "schema" => Some(ObjectType::Schema),
        "database" => Some(ObjectType::Database),
        "type" => Some(ObjectType::Type),
        _ => None,
    }
}

fn object_type_label(object_type: ObjectType) -> &'static str {
    match object_type {
        ObjectType::Table => "table",
        ObjectType::View => "view",
        ObjectType::MaterializedView => "materialized_view",
        ObjectType::Sequence => "sequence",
        ObjectType::Function => "function",
        ObjectType::Schema => "schema",
        ObjectType::Database => "database",
        ObjectType::Type => "type",
    }
}

/// Fetch all object privileges from the database for the given schemas and roles.
///
/// Queries tables/views/sequences via `pg_class`, schemas via `pg_namespace`,
/// functions via `pg_proc`, types via `pg_type`, and (optionally) databases via
/// `pg_database`.
///
/// Returns a map of `GrantKey → GrantState` ready for insertion into a `RoleGraph`.
pub async fn fetch_privileges(
    pool: &PgPool,
    managed_schemas: &[&str],
    managed_roles: &[&str],
) -> Result<BTreeMap<GrantKey, GrantState>, sqlx::Error> {
    Ok(
        fetch_privileges_with_wildcards(pool, managed_schemas, managed_roles, &[], &[])
            .await?
            .grants,
    )
}

/// Fetch schema-scoped object names grouped by object type.
pub async fn fetch_object_inventory(
    pool: &PgPool,
    managed_schemas: &[&str],
) -> Result<BTreeMap<(ObjectType, String), Vec<String>>, sqlx::Error> {
    let rows = sqlx::query_as::<_, AclRow>(
        r#"
        SELECT
            NULL::text AS grantee,
            '' AS privilege_type,
            n.nspname AS schema_name,
            c.relname::text AS object_name,
            CASE c.relkind
                WHEN 'r' THEN 'table'
                WHEN 'p' THEN 'table'
                WHEN 'v' THEN 'view'
                WHEN 'm' THEN 'materialized_view'
            END AS obj_type
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = ANY($1)
          AND c.relkind IN ('r', 'p', 'v', 'm')

        UNION ALL

        SELECT
            NULL::text AS grantee,
            '' AS privilege_type,
            n.nspname AS schema_name,
            c.relname::text AS object_name,
            'sequence' AS obj_type
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = ANY($1)
          AND c.relkind = 'S'

        UNION ALL

        SELECT
            NULL::text AS grantee,
            '' AS privilege_type,
            n.nspname AS schema_name,
            p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' AS object_name,
            'function' AS obj_type
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = ANY($1)

        UNION ALL

        SELECT
            NULL::text AS grantee,
            '' AS privilege_type,
            n.nspname AS schema_name,
            t.typname::text AS object_name,
            'type' AS obj_type
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = ANY($1)
          AND t.typname NOT LIKE '\_%'
          AND t.typtype <> 'p'

        ORDER BY schema_name, obj_type, object_name
        "#,
    )
    .bind(managed_schemas)
    .fetch_all(pool)
    .await?;

    let mut inventory = BTreeMap::new();
    for row in rows {
        let Some(object_type) = obj_type_str_to_object_type(&row.obj_type) else {
            continue;
        };
        inventory
            .entry((
                object_type,
                row.schema_name
                    .expect("relation inventory rows always include schema"),
            ))
            .or_insert_with(Vec::new)
            .push(row.object_name);
    }
    Ok(inventory)
}

async fn fetch_object_inventory_for_wildcards(
    pool: &PgPool,
    filter: &WildcardScopeFilter,
) -> Result<BTreeMap<(ObjectType, String), Vec<String>>, sqlx::Error> {
    if filter.is_empty() {
        return Ok(BTreeMap::new());
    }
    let wildcard_schemas = filter.unique_schemas();
    let arrays = filter.arrays();

    let rows = sqlx::query_as::<_, AclRow>(
        r#"
        WITH wildcard_scope(
            schema_name,
            obj_type,
            need_select,
            need_insert,
            need_update,
            need_delete,
            need_truncate,
            need_references,
            need_trigger,
            need_execute,
            need_usage
        ) AS (
            SELECT *
            FROM unnest(
                $1::text[],
                $2::text[],
                $3::bool[],
                $4::bool[],
                $5::bool[],
                $6::bool[],
                $7::bool[],
                $8::bool[],
                $9::bool[],
                $10::bool[],
                $11::bool[]
            )
        )
        SELECT
            NULL::text AS grantee,
            '' AS privilege_type,
            n.nspname AS schema_name,
            c.relname::text AS object_name,
            CASE c.relkind
                WHEN 'r' THEN 'table'
                WHEN 'p' THEN 'table'
                WHEN 'v' THEN 'view'
                WHEN 'm' THEN 'materialized_view'
            END AS obj_type
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN wildcard_scope scope
          ON scope.schema_name = n.nspname
         AND scope.obj_type = CASE c.relkind
                WHEN 'r' THEN 'table'
                WHEN 'p' THEN 'table'
                WHEN 'v' THEN 'view'
                WHEN 'm' THEN 'materialized_view'
             END
        WHERE c.relkind IN ('r', 'p', 'v', 'm')
          AND n.nspname = ANY($12)

        UNION ALL

        SELECT
            NULL::text AS grantee,
            '' AS privilege_type,
            n.nspname AS schema_name,
            c.relname::text AS object_name,
            'sequence' AS obj_type
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN wildcard_scope scope
          ON scope.schema_name = n.nspname
         AND scope.obj_type = 'sequence'
        WHERE c.relkind = 'S'
          AND n.nspname = ANY($12)

        UNION ALL

        SELECT
            NULL::text AS grantee,
            '' AS privilege_type,
            n.nspname AS schema_name,
            p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' AS object_name,
            'function' AS obj_type
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        JOIN wildcard_scope scope
          ON scope.schema_name = n.nspname
         AND scope.obj_type = 'function'
        WHERE n.nspname = ANY($12)

        UNION ALL

        SELECT
            NULL::text AS grantee,
            '' AS privilege_type,
            n.nspname AS schema_name,
            t.typname::text AS object_name,
            'type' AS obj_type
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        JOIN wildcard_scope scope
          ON scope.schema_name = n.nspname
         AND scope.obj_type = 'type'
        WHERE t.typname NOT LIKE '\_%'
          AND t.typtype <> 'p'
          AND n.nspname = ANY($12)

        ORDER BY schema_name, obj_type, object_name
        "#,
    )
    .bind(&arrays.schema_names)
    .bind(&arrays.object_types)
    .bind(&arrays.need_select)
    .bind(&arrays.need_insert)
    .bind(&arrays.need_update)
    .bind(&arrays.need_delete)
    .bind(&arrays.need_truncate)
    .bind(&arrays.need_references)
    .bind(&arrays.need_trigger)
    .bind(&arrays.need_execute)
    .bind(&arrays.need_usage)
    .bind(&wildcard_schemas)
    .fetch_all(pool)
    .await?;

    let mut inventory = BTreeMap::new();
    for row in rows {
        let Some(object_type) = obj_type_str_to_object_type(&row.obj_type) else {
            continue;
        };
        inventory
            .entry((
                object_type,
                row.schema_name
                    .expect("relation inventory rows always include schema"),
            ))
            .or_insert_with(Vec::new)
            .push(row.object_name);
    }
    Ok(inventory)
}

/// Fetch only relation names (tables, views, materialized views) for callers
/// that specifically need relation inventory.
pub async fn fetch_relation_inventory(
    pool: &PgPool,
    managed_schemas: &[&str],
) -> Result<BTreeMap<(ObjectType, String), Vec<String>>, sqlx::Error> {
    Ok(fetch_object_inventory(pool, managed_schemas)
        .await?
        .into_iter()
        .filter(|((object_type, _), _)| {
            matches!(
                object_type,
                ObjectType::Table | ObjectType::View | ObjectType::MaterializedView
            )
        })
        .collect())
}

/// Every privilege row and wildcard-inventory entry inside one scope, exactly
/// as the server returned it.
///
/// Nothing here is interpreted: this is the shared half of inspection, read
/// once over the union of many scopes and narrowed in memory by
/// [`derive_privileges`].
pub(crate) struct RawPrivilegeState {
    pub(crate) acl_rows: Vec<AclRow>,
    /// Objects in each wildcard `(object_type, schema)` scope that was read.
    pub(crate) inventory: BTreeMap<(ObjectType, String), BTreeSet<String>>,
    /// Grantee-0 rows for the object families the read's PUBLIC scopes named.
    /// Kept apart from `acl_rows` because they are synthesized through
    /// `acldefault` and carry no grantee name to filter on.
    pub(crate) public_acl_rows: Vec<AclRow>,
}

/// The unmasked grantability of every object in a set of wildcard scopes,
/// together with the executor those answers are about.
pub(crate) struct RawGrantability {
    pub(crate) executor: String,
    pub(crate) rows: BTreeMap<(ObjectType, String, String), GrantabilityRow>,
}

/// Read privilege rows, wildcard inventory, and PUBLIC rows for a scope.
///
/// `managed_schemas` × `managed_roles` bound the ACL rows, `wildcard_scopes`
/// the inventory and `public_scopes` the PUBLIC rows, so the result covers
/// every narrower scope contained in those four.
pub(crate) async fn read_raw_privileges(
    pool: &PgPool,
    managed_schemas: &[&str],
    managed_roles: &[&str],
    wildcard_scopes: &BTreeSet<(ObjectType, String)>,
    public_scopes: &[PublicObjectScope],
) -> Result<RawPrivilegeState, sqlx::Error> {
    let mut inventory: BTreeMap<(ObjectType, String), BTreeSet<String>> = BTreeMap::new();
    if !wildcard_scopes.is_empty() {
        let filter = WildcardScopeFilter::from_scopes(wildcard_scopes);
        for ((object_type, schema_name), object_names) in
            fetch_object_inventory_for_wildcards(pool, &filter).await?
        {
            inventory.insert(
                (object_type, schema_name),
                object_names.into_iter().collect(),
            );
        }
    }

    // Run all the independent queries and collect results.
    // We use separate queries per object type rather than one giant UNION
    // because the NULL-ACL handling (acldefault) differs per type.
    let relation_rows = fetch_relation_privileges(pool, managed_schemas, managed_roles).await?;
    let schema_rows = fetch_schema_privileges(pool, managed_schemas, managed_roles).await?;
    let function_rows = fetch_function_privileges(pool, managed_schemas, managed_roles).await?;
    let type_rows = fetch_type_privileges(pool, managed_schemas, managed_roles).await?;

    let public_acl_rows = if public_scopes.is_empty() {
        Vec::new()
    } else {
        read_raw_public_privileges(pool, public_scopes).await?
    };

    Ok(RawPrivilegeState {
        acl_rows: relation_rows
            .into_iter()
            .chain(schema_rows)
            .chain(function_rows)
            .chain(type_rows)
            .collect(),
        inventory,
        public_acl_rows,
    })
}

/// Read the unmasked grantability of every object in `wildcard_scopes`.
pub(crate) async fn read_raw_grantability(
    pool: &PgPool,
    wildcard_scopes: &BTreeSet<(ObjectType, String)>,
) -> Result<RawGrantability, sqlx::Error> {
    let executor = fetch_current_user(pool).await?;
    let filter = WildcardScopeFilter::from_scopes(wildcard_scopes);
    let rows = fetch_wildcard_grantability(pool, &filter).await?;
    Ok(RawGrantability { executor, rows })
}

/// Read and derive privileges for a single scope.
///
/// The narrow path: read exactly this scope, then derive it. It is the same
/// read-then-derive seam the shared snapshot uses, so the two cannot drift.
pub(crate) async fn fetch_privileges_with_wildcards(
    pool: &PgPool,
    managed_schemas: &[&str],
    managed_roles: &[&str],
    wildcard_grants: &[WildcardGrantPattern],
    public_scopes: &[PublicObjectScope],
) -> Result<PrivilegeInspectionResult, sqlx::Error> {
    let wildcard_scopes = wildcard_scopes_of(wildcard_grants);
    let raw = read_raw_privileges(
        pool,
        managed_schemas,
        managed_roles,
        &wildcard_scopes,
        public_scopes,
    )
    .await?;
    let derived = derive_privileges(
        &raw,
        &managed_schemas.iter().map(|s| s.to_string()).collect(),
        &managed_roles.iter().map(|s| s.to_string()).collect(),
        wildcard_grants,
        public_scopes,
    );
    let grantability = if derived.unsatisfied.is_empty() {
        None
    } else {
        Some(read_raw_grantability(pool, &wildcard_scopes_of(&derived.unsatisfied)).await?)
    };
    // This path reads grantability for itself, so it always paid for the query.
    Ok(derived.finish(grantability.as_ref(), grantability.is_some()))
}

/// The `(object_type, schema)` pairs a set of wildcard grants selects over.
pub(crate) fn wildcard_scopes_of(
    wildcard_grants: &[WildcardGrantPattern],
) -> BTreeSet<(ObjectType, String)> {
    wildcard_grants
        .iter()
        .filter(|wildcard| {
            !matches!(
                wildcard.object_type,
                ObjectType::Schema | ObjectType::Database
            )
        })
        .map(|wildcard| (wildcard.object_type, wildcard.schema.clone()))
        .collect()
}

/// What a scope's privileges look like before wildcard normalization.
///
/// Split out of [`derive_privileges`] because the unsatisfiable-wildcard
/// diagnostics are computed against the *pre*-normalization grants and may
/// need a grantability read, which the caller performs between the two halves.
pub(crate) struct DerivedPrivileges {
    grants: BTreeMap<GrantKey, GrantState>,
    inventory: BTreeMap<(ObjectType, String), BTreeSet<String>>,
    wildcard_grants: Vec<WildcardGrantPattern>,
    /// Wildcards with at least one matching object missing a desired
    /// privilege. Empty means no grantability read is needed at all.
    pub(crate) unsatisfied: Vec<WildcardGrantPattern>,
    pub(crate) wildcard_stats: WildcardInspectionStats,
}

/// Narrow a raw read to one scope, reproducing the per-scope queries in memory.
pub(crate) fn derive_privileges(
    raw: &RawPrivilegeState,
    managed_schemas: &BTreeSet<String>,
    managed_roles: &BTreeSet<String>,
    wildcard_grants: &[WildcardGrantPattern],
    public_scopes: &[PublicObjectScope],
) -> DerivedPrivileges {
    let mut grants: BTreeMap<GrantKey, GrantState> = BTreeMap::new();
    let has_wildcards = !wildcard_grants.is_empty();
    let wildcard_scope_filter = WildcardScopeFilter::from_wildcards(wildcard_grants);
    let mut wildcard_stats = WildcardInspectionStats {
        configured_grants: wildcard_grants.len(),
        configured_scopes: wildcard_scope_filter.len(),
        ..WildcardInspectionStats::default()
    };

    let mut inventory: BTreeMap<(ObjectType, String), BTreeSet<String>> = raw
        .inventory
        .iter()
        .filter(|((object_type, schema), _)| wildcard_scope_filter.contains(*object_type, schema))
        .map(|(scope, names)| (scope.clone(), names.clone()))
        .collect();

    let rows: Vec<&AclRow> = raw
        .acl_rows
        .iter()
        .filter(|row| row.in_scope(managed_schemas, managed_roles))
        .collect();

    for row in &rows {
        if has_wildcards
            && let Some(object_type) = obj_type_str_to_object_type(&row.obj_type)
            && !matches!(object_type, ObjectType::Schema | ObjectType::Database)
            && let Some(schema_name) = &row.schema_name
            && wildcard_scope_filter.contains(object_type, schema_name)
        {
            inventory
                .entry((object_type, schema_name.clone()))
                .or_default()
                .insert(row.object_name.clone());
        }
    }
    wildcard_stats.inventory_objects = inventory.values().map(BTreeSet::len).sum();

    for row in rows {
        let Some(grantee) = row.grantee.as_ref() else {
            continue;
        };

        let privilege = match acl_char_to_privilege(&row.privilege_type) {
            Some(privilege) => privilege,
            None => continue,
        };

        let object_type = match obj_type_str_to_object_type(&row.obj_type) {
            Some(object_type) => object_type,
            None => continue,
        };

        // Build the GrantKey.
        // Schema-level grants: object_type=Schema, schema=None, name=Some(schema_name)
        // Database-level grants: object_type=Database, schema=None, name=Some(db_name)
        // Other: object_type, schema=Some(schema_name), name=Some(object_name)
        let (schema, name) = match object_type {
            ObjectType::Schema => (None, Some(row.object_name.clone())),
            ObjectType::Database => (None, Some(row.object_name.clone())),
            _ => (row.schema_name.clone(), Some(row.object_name.clone())),
        };

        let key = GrantKey {
            // Joined through pg_roles, so this is always a real role name —
            // even one spelled "PUBLIC" — never the pseudo-role.
            role: Grantee::Role(grantee.clone()),
            object_type,
            schema,
            name,
        };

        let entry = grants.entry(key).or_insert_with(|| GrantState {
            privileges: BTreeSet::new(),
        });
        entry.privileges.insert(privilege);
    }

    // PUBLIC state, kept only for declared scopes. Merged before wildcard
    // normalization so a present-ensure PUBLIC wildcard collapses its
    // per-object rows like any role wildcard; scopes declared only absent are
    // not wildcard patterns, so their rows stay per-object for the diff's
    // range-scan.
    if !public_scopes.is_empty() {
        for (key, state) in derive_public_privileges(&raw.public_acl_rows, public_scopes) {
            grants.insert(key, state);
        }
    }

    let unsatisfied = if has_wildcards {
        unsatisfied_wildcard_grants(&grants, &inventory, wildcard_grants)
    } else {
        Vec::new()
    };
    wildcard_stats.unsatisfied_grants = unsatisfied.len();

    DerivedPrivileges {
        grants,
        inventory,
        wildcard_grants: wildcard_grants.to_vec(),
        unsatisfied,
        wildcard_stats,
    }
}

impl DerivedPrivileges {
    /// Finish the derivation, given grantability for the unsatisfied wildcards
    /// (`None` when [`Self::unsatisfied`] is empty and none was read).
    ///
    /// `read_performed` says whether *this* derivation paid for the read.
    /// A shared snapshot reads grantability at most once and reuses it for
    /// every later derivation, so counting a query per derivation would report
    /// K queries for one query — in the metric that exists to show the read
    /// count no longer tracks the candidate count.
    pub(crate) fn finish(
        mut self,
        grantability: Option<&RawGrantability>,
        read_performed: bool,
    ) -> PrivilegeInspectionResult {
        let diagnostics = match (self.unsatisfied.is_empty(), grantability) {
            (false, Some(raw)) => {
                let filter = WildcardScopeFilter::from_wildcards(&self.unsatisfied);
                self.wildcard_stats.unsatisfied_scopes = filter.len();
                // Narrow the shared read to exactly the rows and privileges a
                // per-scope grantability query would have returned.
                let scoped: BTreeMap<(ObjectType, String, String), GrantabilityRow> = raw
                    .rows
                    .iter()
                    .filter_map(|((object_type, schema, object), row)| {
                        filter.needs(*object_type, schema).map(|needs| {
                            (
                                (*object_type, schema.clone(), object.clone()),
                                row.masked(needs),
                            )
                        })
                    })
                    .collect();
                self.wildcard_stats.grantability_queries = usize::from(read_performed);
                self.wildcard_stats.grantability_objects = scoped.len();
                detect_unsatisfiable_wildcards(
                    &self.grants,
                    &scoped,
                    &self.unsatisfied,
                    &raw.executor,
                )
            }
            _ => Vec::new(),
        };

        let grants = if self.wildcard_grants.is_empty() {
            self.grants
        } else {
            normalize_wildcard_grants(self.grants, &self.inventory, &self.wildcard_grants)
        };

        PrivilegeInspectionResult {
            grants,
            diagnostics,
            wildcard_stats: self.wildcard_stats,
        }
    }
}

async fn fetch_current_user(pool: &PgPool) -> Result<String, sqlx::Error> {
    let (user,) = sqlx::query_as::<_, (String,)>("SELECT current_user::text")
        .fetch_one(pool)
        .await?;
    Ok(user)
}

/// Read raw PUBLIC (ACL grantee OID 0) rows for the object families the
/// declared scopes name.
///
/// Unlike the managed-role reads above, NULL ACLs are exploded through
/// `acldefault(...)` so PostgreSQL's implicit built-ins — EXECUTE on
/// routines, USAGE on types, CONNECT/TEMPORARY on the database — are visible.
/// An `ensure: absent` rule must see them or no revoke would ever be planned
/// on a fresh object. Only grantee-0 entries are returned, so the synthesis
/// can never leak implicit owner privileges into managed-role state.
///
/// `acldefault` is applied to every object family for uniformity; it only
/// changes the result for functions, types, and the database, because the
/// other families' defaults contain no grantee-0 entries. Its contents are
/// identical on PG 16, 17, and 18.
///
/// The rows are unfiltered beyond the object families and schemas queried.
/// [`derive_public_privileges`] applies the per-scope privilege filter, so a
/// read over several configs' scopes can serve each of them.
pub(crate) async fn read_raw_public_privileges(
    pool: &PgPool,
    scopes: &[PublicObjectScope],
) -> Result<Vec<AclRow>, sqlx::Error> {
    let unique_schemas = |predicate: &dyn Fn(ObjectType) -> bool| -> Vec<String> {
        scopes
            .iter()
            .filter(|scope| predicate(scope.object_type))
            .filter_map(|scope| scope.schema.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };

    let mut rows: Vec<AclRow> = Vec::new();

    let relation_schemas = unique_schemas(&|object_type| {
        matches!(
            object_type,
            ObjectType::Table
                | ObjectType::View
                | ObjectType::MaterializedView
                | ObjectType::Sequence
        )
    });
    if !relation_schemas.is_empty() {
        rows.extend(
            sqlx::query_as::<_, AclRow>(
                r#"
                SELECT
                    NULL::text AS grantee,
                    acl.privilege_type,
                    n.nspname::text AS schema_name,
                    c.relname::text AS object_name,
                    CASE c.relkind
                        WHEN 'r' THEN 'table'
                        WHEN 'p' THEN 'table'
                        WHEN 'v' THEN 'view'
                        WHEN 'm' THEN 'materialized_view'
                        WHEN 'S' THEN 'sequence'
                    END AS obj_type
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                CROSS JOIN LATERAL aclexplode(
                    COALESCE(
                        c.relacl,
                        acldefault(
                            CASE WHEN c.relkind = 'S' THEN 'S' ELSE 'r' END::"char",
                            c.relowner
                        )
                    )
                ) AS acl
                WHERE n.nspname = ANY($1)
                  AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
                  AND acl.grantee = 0
                ORDER BY n.nspname, c.relname
                "#,
            )
            .bind(&relation_schemas)
            .fetch_all(pool)
            .await?,
        );
    }

    let function_schemas = unique_schemas(&|object_type| object_type == ObjectType::Function);
    if !function_schemas.is_empty() {
        rows.extend(
            sqlx::query_as::<_, AclRow>(
                r#"
                SELECT
                    NULL::text AS grantee,
                    acl.privilege_type,
                    n.nspname::text AS schema_name,
                    (p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')')::text AS object_name,
                    'function' AS obj_type
                FROM pg_proc p
                JOIN pg_namespace n ON n.oid = p.pronamespace
                CROSS JOIN LATERAL aclexplode(
                    COALESCE(p.proacl, acldefault('f'::"char", p.proowner))
                ) AS acl
                WHERE n.nspname = ANY($1)
                  AND acl.grantee = 0
                ORDER BY n.nspname, p.proname
                "#,
            )
            .bind(&function_schemas)
            .fetch_all(pool)
            .await?,
        );
    }

    let type_schemas = unique_schemas(&|object_type| object_type == ObjectType::Type);
    if !type_schemas.is_empty() {
        rows.extend(
            sqlx::query_as::<_, AclRow>(
                r#"
                SELECT
                    NULL::text AS grantee,
                    acl.privilege_type,
                    n.nspname::text AS schema_name,
                    t.typname::text AS object_name,
                    'type' AS obj_type
                FROM pg_type t
                JOIN pg_namespace n ON n.oid = t.typnamespace
                CROSS JOIN LATERAL aclexplode(
                    COALESCE(t.typacl, acldefault('T'::"char", t.typowner))
                ) AS acl
                WHERE n.nspname = ANY($1)
                  AND t.typname NOT LIKE '\_%'
                  AND t.typtype <> 'p'
                  AND acl.grantee = 0
                ORDER BY n.nspname, t.typname
                "#,
            )
            .bind(&type_schemas)
            .fetch_all(pool)
            .await?,
        );
    }

    let schema_names: Vec<String> = scopes
        .iter()
        .filter(|scope| scope.object_type == ObjectType::Schema)
        .filter_map(|scope| scope.name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if !schema_names.is_empty() {
        rows.extend(
            sqlx::query_as::<_, AclRow>(
                r#"
                SELECT
                    NULL::text AS grantee,
                    acl.privilege_type,
                    NULL::text AS schema_name,
                    n.nspname::text AS object_name,
                    'schema' AS obj_type
                FROM pg_namespace n
                CROSS JOIN LATERAL aclexplode(
                    COALESCE(n.nspacl, acldefault('n'::"char", n.nspowner))
                ) AS acl
                WHERE n.nspname = ANY($1)
                  AND acl.grantee = 0
                ORDER BY n.nspname
                "#,
            )
            .bind(&schema_names)
            .fetch_all(pool)
            .await?,
        );
    }

    if scopes
        .iter()
        .any(|scope| scope.object_type == ObjectType::Database)
    {
        rows.extend(
            sqlx::query_as::<_, AclRow>(
                r#"
                SELECT
                    NULL::text AS grantee,
                    acl.privilege_type,
                    NULL::text AS schema_name,
                    db.datname::text AS object_name,
                    'database' AS obj_type
                FROM pg_database db
                CROSS JOIN LATERAL aclexplode(
                    COALESCE(db.datacl, acldefault('d'::"char", db.datdba))
                ) AS acl
                WHERE db.datname = current_database()
                  AND acl.grantee = 0
                "#,
            )
            .fetch_all(pool)
            .await?,
        );
    }

    Ok(rows)
}

/// Narrow raw PUBLIC rows to the scopes one manifest declared.
///
/// Rows are filtered to the privileges the manifest's PUBLIC rules mention
/// for the matching scope. A PUBLIC edge the manifest never names stays out
/// of the graph entirely, which is what keeps convergence from revoking
/// unmanaged PUBLIC grants (see the #108 wildcard regression).
pub(crate) fn derive_public_privileges(
    rows: &[AclRow],
    scopes: &[PublicObjectScope],
) -> BTreeMap<GrantKey, GrantState> {
    let mut grants: BTreeMap<GrantKey, GrantState> = BTreeMap::new();
    for row in rows {
        let Some(privilege) = acl_char_to_privilege(&row.privilege_type) else {
            continue;
        };
        let Some(object_type) = obj_type_str_to_object_type(&row.obj_type) else {
            continue;
        };

        if !public_scopes_cover(
            scopes,
            object_type,
            row.schema_name.as_deref(),
            &row.object_name,
            privilege,
        ) {
            continue;
        }

        let (schema, name) = match object_type {
            ObjectType::Schema | ObjectType::Database => (None, Some(row.object_name.clone())),
            _ => (row.schema_name.clone(), Some(row.object_name.clone())),
        };
        grants
            .entry(GrantKey {
                role: Grantee::Public,
                object_type,
                schema,
                name,
            })
            .or_insert_with(|| GrantState {
                privileges: BTreeSet::new(),
            })
            .privileges
            .insert(privilege);
    }

    grants
}

/// Whether some declared PUBLIC scope covers this object and names this
/// privilege.
fn public_scopes_cover(
    scopes: &[PublicObjectScope],
    object_type: ObjectType,
    schema_name: Option<&str>,
    object_name: &str,
    privilege: Privilege,
) -> bool {
    scopes.iter().any(|scope| {
        if scope.object_type != object_type || !scope.privileges.contains(&privilege) {
            return false;
        }
        match object_type {
            ObjectType::Schema => scope.name.as_deref() == Some(object_name),
            ObjectType::Database => scope.name.as_deref().is_none_or(|name| name == object_name),
            _ => {
                scope.schema.as_deref() == schema_name
                    && scope
                        .name
                        .as_deref()
                        .is_some_and(|name| name == "*" || name == object_name)
            }
        }
    })
}

fn unsatisfied_wildcard_grants(
    grants: &BTreeMap<GrantKey, GrantState>,
    inventory: &BTreeMap<(ObjectType, String), BTreeSet<String>>,
    wildcard_grants: &[WildcardGrantPattern],
) -> Vec<WildcardGrantPattern> {
    let mut unsatisfied = Vec::new();

    for wildcard in wildcard_grants {
        let Some(object_names) = inventory.get(&(wildcard.object_type, wildcard.schema.clone()))
        else {
            continue;
        };

        if object_names.is_empty() {
            continue;
        }

        let mut missing_privileges = BTreeSet::new();
        for object_name in object_names {
            let key = GrantKey {
                role: Grantee::parse(&wildcard.role),
                object_type: wildcard.object_type,
                schema: Some(wildcard.schema.clone()),
                name: Some(object_name.clone()),
            };

            let existing = grants.get(&key);
            for privilege in &wildcard.privileges {
                if !existing.is_some_and(|state| state.privileges.contains(privilege)) {
                    missing_privileges.insert(*privilege);
                }
            }
        }

        if !missing_privileges.is_empty() {
            unsatisfied.push(WildcardGrantPattern {
                role: wildcard.role.clone(),
                object_type: wildcard.object_type,
                schema: wildcard.schema.clone(),
                privileges: missing_privileges,
            });
        }
    }

    unsatisfied
}

async fn fetch_wildcard_grantability(
    pool: &PgPool,
    filter: &WildcardScopeFilter,
) -> Result<BTreeMap<(ObjectType, String, String), GrantabilityRow>, sqlx::Error> {
    if filter.is_empty() {
        return Ok(BTreeMap::new());
    }
    let wildcard_schemas = filter.unique_schemas();
    let arrays = filter.arrays();

    let rows = sqlx::query_as::<_, GrantabilityRow>(
        r#"
        WITH wildcard_scope(
            schema_name,
            obj_type,
            need_select,
            need_insert,
            need_update,
            need_delete,
            need_truncate,
            need_references,
            need_trigger,
            need_execute,
            need_usage
        ) AS (
            SELECT *
            FROM unnest(
                $1::text[],
                $2::text[],
                $3::bool[],
                $4::bool[],
                $5::bool[],
                $6::bool[],
                $7::bool[],
                $8::bool[],
                $9::bool[],
                $10::bool[],
                $11::bool[]
            )
        )
        SELECT
            n.nspname AS schema_name,
            c.relname::text AS object_name,
            pg_get_userbyid(c.relowner) AS owner_name,
            CASE c.relkind
                WHEN 'r' THEN 'table'
                WHEN 'p' THEN 'table'
                WHEN 'v' THEN 'view'
                WHEN 'm' THEN 'materialized_view'
            END AS obj_type,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_select
                 WHEN scope.need_select THEN has_table_privilege(current_user, c.oid, 'SELECT WITH GRANT OPTION')
                 ELSE false END AS can_select,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_insert
                 WHEN scope.need_insert THEN has_table_privilege(current_user, c.oid, 'INSERT WITH GRANT OPTION')
                 ELSE false END AS can_insert,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_update
                 WHEN scope.need_update THEN has_table_privilege(current_user, c.oid, 'UPDATE WITH GRANT OPTION')
                 ELSE false END AS can_update,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_delete
                 WHEN scope.need_delete THEN has_table_privilege(current_user, c.oid, 'DELETE WITH GRANT OPTION')
                 ELSE false END AS can_delete,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_truncate
                 WHEN scope.need_truncate THEN has_table_privilege(current_user, c.oid, 'TRUNCATE WITH GRANT OPTION')
                 ELSE false END AS can_truncate,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_references
                 WHEN scope.need_references THEN has_table_privilege(current_user, c.oid, 'REFERENCES WITH GRANT OPTION')
                 ELSE false END AS can_references,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_trigger
                 WHEN scope.need_trigger THEN has_table_privilege(current_user, c.oid, 'TRIGGER WITH GRANT OPTION')
                 ELSE false END AS can_trigger,
            false AS can_execute,
            false AS can_usage
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN wildcard_scope scope
          ON scope.schema_name = n.nspname
         AND scope.obj_type = CASE c.relkind
                WHEN 'r' THEN 'table'
                WHEN 'p' THEN 'table'
                WHEN 'v' THEN 'view'
                WHEN 'm' THEN 'materialized_view'
             END
        CROSS JOIN LATERAL (
            SELECT pg_has_role(current_user, c.relowner, 'USAGE') AS can_grant_as_owner
        ) owner_grant
        WHERE c.relkind IN ('r', 'p', 'v', 'm')
          AND n.nspname = ANY($12)

        UNION ALL

        SELECT
            n.nspname AS schema_name,
            c.relname::text AS object_name,
            pg_get_userbyid(c.relowner) AS owner_name,
            'sequence' AS obj_type,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_select
                 WHEN scope.need_select THEN has_sequence_privilege(current_user, c.oid, 'SELECT WITH GRANT OPTION')
                 ELSE false END AS can_select,
            false AS can_insert,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_update
                 WHEN scope.need_update THEN has_sequence_privilege(current_user, c.oid, 'UPDATE WITH GRANT OPTION')
                 ELSE false END AS can_update,
            false AS can_delete,
            false AS can_truncate,
            false AS can_references,
            false AS can_trigger,
            false AS can_execute,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_usage
                 WHEN scope.need_usage THEN has_sequence_privilege(current_user, c.oid, 'USAGE WITH GRANT OPTION')
                 ELSE false END AS can_usage
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN wildcard_scope scope
          ON scope.schema_name = n.nspname
         AND scope.obj_type = 'sequence'
        CROSS JOIN LATERAL (
            SELECT pg_has_role(current_user, c.relowner, 'USAGE') AS can_grant_as_owner
        ) owner_grant
        WHERE c.relkind = 'S'
          AND n.nspname = ANY($12)

        UNION ALL

        SELECT
            n.nspname AS schema_name,
            p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' AS object_name,
            pg_get_userbyid(p.proowner) AS owner_name,
            'function' AS obj_type,
            false AS can_select,
            false AS can_insert,
            false AS can_update,
            false AS can_delete,
            false AS can_truncate,
            false AS can_references,
            false AS can_trigger,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_execute
                 WHEN scope.need_execute THEN has_function_privilege(current_user, p.oid, 'EXECUTE WITH GRANT OPTION')
                 ELSE false END AS can_execute,
            false AS can_usage
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        JOIN wildcard_scope scope
          ON scope.schema_name = n.nspname
         AND scope.obj_type = 'function'
        CROSS JOIN LATERAL (
            SELECT pg_has_role(current_user, p.proowner, 'USAGE') AS can_grant_as_owner
        ) owner_grant
        WHERE n.nspname = ANY($12)

        UNION ALL

        SELECT
            n.nspname AS schema_name,
            t.typname::text AS object_name,
            pg_get_userbyid(t.typowner) AS owner_name,
            'type' AS obj_type,
            false AS can_select,
            false AS can_insert,
            false AS can_update,
            false AS can_delete,
            false AS can_truncate,
            false AS can_references,
            false AS can_trigger,
            false AS can_execute,
            CASE WHEN owner_grant.can_grant_as_owner THEN scope.need_usage
                 WHEN scope.need_usage THEN has_type_privilege(current_user, t.oid, 'USAGE WITH GRANT OPTION')
                 ELSE false END AS can_usage
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        JOIN wildcard_scope scope
          ON scope.schema_name = n.nspname
         AND scope.obj_type = 'type'
        CROSS JOIN LATERAL (
            SELECT pg_has_role(current_user, t.typowner, 'USAGE') AS can_grant_as_owner
        ) owner_grant
        WHERE t.typname NOT LIKE '\_%'
          AND t.typtype <> 'p'
          AND n.nspname = ANY($12)

        ORDER BY schema_name, obj_type, object_name
        "#,
    )
    .bind(&arrays.schema_names)
    .bind(&arrays.object_types)
    .bind(&arrays.need_select)
    .bind(&arrays.need_insert)
    .bind(&arrays.need_update)
    .bind(&arrays.need_delete)
    .bind(&arrays.need_truncate)
    .bind(&arrays.need_references)
    .bind(&arrays.need_trigger)
    .bind(&arrays.need_execute)
    .bind(&arrays.need_usage)
    .bind(&wildcard_schemas)
    .fetch_all(pool)
    .await?;

    let mut grantability = BTreeMap::new();
    for row in rows {
        let Some(object_type) = obj_type_str_to_object_type(&row.obj_type) else {
            continue;
        };
        grantability.insert(
            (
                object_type,
                row.schema_name.clone(),
                row.object_name.clone(),
            ),
            row,
        );
    }
    Ok(grantability)
}

fn detect_unsatisfiable_wildcards(
    grants: &BTreeMap<GrantKey, GrantState>,
    grantability: &BTreeMap<(ObjectType, String, String), GrantabilityRow>,
    wildcard_grants: &[WildcardGrantPattern],
    executor: &str,
) -> Vec<UnsatisfiableWildcardGrant> {
    let mut diagnostics = Vec::new();

    for wildcard in wildcard_grants {
        let mut skipped_objects = Vec::new();
        let mut skipped_privileges = BTreeSet::new();

        for ((object_type, schema_name, object_name), row) in grantability {
            if *object_type != wildcard.object_type || schema_name != &wildcard.schema {
                continue;
            }

            let key = GrantKey {
                role: Grantee::parse(&wildcard.role),
                object_type: wildcard.object_type,
                schema: Some(wildcard.schema.clone()),
                name: Some(object_name.clone()),
            };
            let existing = grants.get(&key);
            let mut missing_non_grantable = BTreeSet::new();
            for privilege in &wildcard.privileges {
                if existing.is_some_and(|state| state.privileges.contains(privilege)) {
                    continue;
                }
                if can_grant(row, *privilege) {
                    continue;
                }
                missing_non_grantable.insert(*privilege);
                skipped_privileges.insert(*privilege);
            }

            if !missing_non_grantable.is_empty() {
                skipped_objects.push(UnsatisfiableWildcardObject {
                    name: object_name.clone(),
                    owner: row.owner_name.clone(),
                    privileges: missing_non_grantable,
                });
            }
        }

        if !skipped_objects.is_empty() {
            diagnostics.push(UnsatisfiableWildcardGrant {
                role: wildcard.role.clone(),
                object_type: wildcard.object_type,
                schema: wildcard.schema.clone(),
                privileges: skipped_privileges,
                executor: executor.to_string(),
                skipped_count: skipped_objects.len(),
                examples: skipped_objects.into_iter().take(5).collect(),
            });
        }
    }

    diagnostics
}

fn can_grant(row: &GrantabilityRow, privilege: Privilege) -> bool {
    match privilege {
        Privilege::Select => row.can_select,
        Privilege::Insert => row.can_insert,
        Privilege::Update => row.can_update,
        Privilege::Delete => row.can_delete,
        Privilege::Truncate => row.can_truncate,
        Privilege::References => row.can_references,
        Privilege::Trigger => row.can_trigger,
        Privilege::Execute => row.can_execute,
        Privilege::Usage => row.can_usage,
        // Database and schema privileges are not object-wildcard grant targets.
        Privilege::Create | Privilege::Connect | Privilege::Temporary => false,
    }
}

/// Insert a vacuously-satisfied wildcard into the grants map. Used when no
/// objects of the target type exist in the schema — the wildcard is satisfied
/// by definition, so we populate the current state with the desired privileges
/// to prevent the diff engine from re-issuing the grant on every reconcile.
fn insert_vacuous_wildcard(
    grants: &mut BTreeMap<GrantKey, GrantState>,
    wildcard: &WildcardGrantPattern,
) {
    let wildcard_key = GrantKey {
        role: Grantee::parse(&wildcard.role),
        object_type: wildcard.object_type,
        schema: Some(wildcard.schema.clone()),
        name: Some("*".to_string()),
    };
    grants.insert(
        wildcard_key,
        GrantState {
            privileges: wildcard.privileges.clone(),
        },
    );
}

fn normalize_wildcard_grants(
    mut grants: BTreeMap<GrantKey, GrantState>,
    inventory: &BTreeMap<(ObjectType, String), BTreeSet<String>>,
    wildcard_grants: &[WildcardGrantPattern],
) -> BTreeMap<GrantKey, GrantState> {
    for wildcard in wildcard_grants {
        let Some(object_names) = inventory.get(&(wildcard.object_type, wildcard.schema.clone()))
        else {
            // No inventory entry at all — insert vacuous wildcard.
            insert_vacuous_wildcard(&mut grants, wildcard);
            continue;
        };

        if object_names.is_empty() {
            // Inventory entry exists but is empty — same treatment.
            insert_vacuous_wildcard(&mut grants, wildcard);
            continue;
        }
        let mut shared_privileges = all_privileges();

        for object_name in object_names {
            let key = GrantKey {
                role: Grantee::parse(&wildcard.role),
                object_type: wildcard.object_type,
                schema: Some(wildcard.schema.clone()),
                name: Some(object_name.clone()),
            };

            if let Some(state) = grants.get(&key) {
                shared_privileges.retain(|privilege| state.privileges.contains(privilege));
            } else {
                shared_privileges.clear();
                break;
            }
        }

        if shared_privileges.is_empty() {
            continue;
        }

        let wildcard_key = GrantKey {
            role: Grantee::parse(&wildcard.role),
            object_type: wildcard.object_type,
            schema: Some(wildcard.schema.clone()),
            name: Some("*".to_string()),
        };

        grants.insert(
            wildcard_key,
            GrantState {
                privileges: shared_privileges.clone(),
            },
        );

        for object_name in object_names {
            let key = GrantKey {
                role: Grantee::parse(&wildcard.role),
                object_type: wildcard.object_type,
                schema: Some(wildcard.schema.clone()),
                name: Some(object_name.clone()),
            };

            let remove_key = match grants.get_mut(&key) {
                Some(state) => {
                    state
                        .privileges
                        .retain(|privilege| !shared_privileges.contains(privilege));
                    state.privileges.is_empty()
                }
                None => false,
            };

            if remove_key {
                grants.remove(&key);
            }
        }
    }

    grants
}

fn all_privileges() -> BTreeSet<Privilege> {
    [
        Privilege::Select,
        Privilege::Insert,
        Privilege::Update,
        Privilege::Delete,
        Privilege::Truncate,
        Privilege::References,
        Privilege::Trigger,
        Privilege::Execute,
        Privilege::Usage,
        Privilege::Create,
        Privilege::Connect,
        Privilege::Temporary,
    ]
    .into_iter()
    .collect()
}

/// Fetch privileges on tables, views, materialized views, and sequences.
///
/// Uses `pg_class` joined with `pg_namespace`. The `relkind` column determines
/// the object type:
///   'r' = table, 'v' = view, 'm' = materialized view, 'S' = sequence, 'p' = partitioned table
///
/// Only explicit ACLs are inspected. NULL ACLs produce no rows.
///
/// ACL entries whose grantee is the relation's owner are excluded: once any
/// grant materializes a relation's ACL, PostgreSQL records the owner's
/// inherent privileges in it, and treating that entry as granted state makes
/// the diff plan revokes of privileges nobody granted (breaking owner DML and
/// owner-executed FK key-share checks).
async fn fetch_relation_privileges(
    pool: &PgPool,
    managed_schemas: &[&str],
    managed_roles: &[&str],
) -> Result<Vec<AclRow>, sqlx::Error> {
    sqlx::query_as::<_, AclRow>(
        r#"
        SELECT
            grantee.rolname AS grantee,
            acl.privilege_type,
            n.nspname AS schema_name,
            c.relname::text AS object_name,
            CASE c.relkind
                WHEN 'r' THEN 'table'
                WHEN 'p' THEN 'table'
                WHEN 'v' THEN 'view'
                WHEN 'm' THEN 'materialized_view'
                WHEN 'S' THEN 'sequence'
            END AS obj_type
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL aclexplode(c.relacl) AS acl
        JOIN pg_roles grantee ON grantee.oid = acl.grantee
        WHERE n.nspname = ANY($1)
          AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
          AND grantee.rolname = ANY($2)
          AND grantee.rolname <> pg_get_userbyid(c.relowner)
        ORDER BY n.nspname, c.relname
        "#,
    )
    .bind(managed_schemas)
    .bind(managed_roles)
    .fetch_all(pool)
    .await
}

/// Fetch privileges on schemas.
///
/// Uses `pg_namespace`. For schema grants, the object_name is the schema name itself.
/// Only explicit ACLs are inspected. NULL ACLs produce no rows.
/// Owner-grantee entries are excluded (see `fetch_relation_privileges`).
async fn fetch_schema_privileges(
    pool: &PgPool,
    managed_schemas: &[&str],
    managed_roles: &[&str],
) -> Result<Vec<AclRow>, sqlx::Error> {
    sqlx::query_as::<_, AclRow>(
        r#"
        SELECT
            grantee.rolname AS grantee,
            acl.privilege_type,
            NULL::text AS schema_name,
            n.nspname::text AS object_name,
            'schema' AS obj_type
        FROM pg_namespace n
        CROSS JOIN LATERAL aclexplode(n.nspacl) AS acl
        JOIN pg_roles grantee ON grantee.oid = acl.grantee
        WHERE n.nspname = ANY($1)
          AND grantee.rolname = ANY($2)
          AND grantee.rolname <> pg_get_userbyid(n.nspowner)
        ORDER BY n.nspname
        "#,
    )
    .bind(managed_schemas)
    .bind(managed_roles)
    .fetch_all(pool)
    .await
}

/// Fetch privileges on functions/procedures.
///
/// Uses `pg_proc` joined with `pg_namespace`.
/// Function names can be overloaded, so we include the OID-derived
/// identity signature via `pg_catalog.pg_get_function_identity_arguments()`.
/// Only explicit ACLs are inspected. NULL ACLs produce no rows.
/// Owner-grantee entries are excluded (see `fetch_relation_privileges`).
async fn fetch_function_privileges(
    pool: &PgPool,
    managed_schemas: &[&str],
    managed_roles: &[&str],
) -> Result<Vec<AclRow>, sqlx::Error> {
    sqlx::query_as::<_, AclRow>(
        r#"
        SELECT
            grantee.rolname AS grantee,
            acl.privilege_type,
            n.nspname AS schema_name,
            p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')' AS object_name,
            'function' AS obj_type
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        CROSS JOIN LATERAL aclexplode(p.proacl) AS acl
        JOIN pg_roles grantee ON grantee.oid = acl.grantee
        WHERE n.nspname = ANY($1)
          AND grantee.rolname = ANY($2)
          AND grantee.rolname <> pg_get_userbyid(p.proowner)
        ORDER BY n.nspname, p.proname
        "#,
    )
    .bind(managed_schemas)
    .bind(managed_roles)
    .fetch_all(pool)
    .await
}

/// Fetch privileges on types/domains.
///
/// Uses `pg_type` joined with `pg_namespace`.
/// We filter out internal/array types (typname not starting with '_',
/// typtype not 'p' for pseudo-types).
/// Only explicit ACLs are inspected. NULL ACLs produce no rows.
/// Owner-grantee entries are excluded (see `fetch_relation_privileges`).
async fn fetch_type_privileges(
    pool: &PgPool,
    managed_schemas: &[&str],
    managed_roles: &[&str],
) -> Result<Vec<AclRow>, sqlx::Error> {
    sqlx::query_as::<_, AclRow>(
        r#"
        SELECT
            grantee.rolname AS grantee,
            acl.privilege_type,
            n.nspname AS schema_name,
            t.typname::text AS object_name,
            'type' AS obj_type
        FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        CROSS JOIN LATERAL aclexplode(t.typacl) AS acl
        JOIN pg_roles grantee ON grantee.oid = acl.grantee
        WHERE n.nspname = ANY($1)
          AND t.typname NOT LIKE '\_%'
          AND t.typtype <> 'p'
          AND grantee.rolname = ANY($2)
          AND grantee.rolname <> pg_get_userbyid(t.typowner)
        ORDER BY n.nspname, t.typname
        "#,
    )
    .bind(managed_schemas)
    .bind(managed_roles)
    .fetch_all(pool)
    .await
}

/// Fetch database-level privileges on the current database.
///
/// Uses `pg_database`. This is separate because it's not schema-scoped; we
/// always query the current database. Only explicit ACLs are inspected.
pub async fn fetch_database_privileges(
    pool: &PgPool,
    managed_roles: &[&str],
) -> Result<BTreeMap<GrantKey, GrantState>, sqlx::Error> {
    let rows = sqlx::query_as::<_, AclRow>(
        r#"
        SELECT
            grantee.rolname AS grantee,
            acl.privilege_type,
            NULL::text AS schema_name,
            db.datname::text AS object_name,
            'database' AS obj_type
        FROM pg_database db
        CROSS JOIN LATERAL aclexplode(db.datacl) AS acl
        JOIN pg_roles grantee ON grantee.oid = acl.grantee
        WHERE db.datname = current_database()
          AND grantee.rolname = ANY($1)
          AND grantee.rolname <> pg_get_userbyid(db.datdba)
        ORDER BY db.datname
        "#,
    )
    .bind(managed_roles)
    .fetch_all(pool)
    .await?;

    let mut grants: BTreeMap<GrantKey, GrantState> = BTreeMap::new();

    for row in rows {
        let Some(grantee) = row.grantee.as_ref() else {
            continue;
        };

        let privilege = match acl_char_to_privilege(&row.privilege_type) {
            Some(privilege) => privilege,
            None => continue,
        };

        let key = GrantKey {
            role: Grantee::Role(grantee.clone()),
            object_type: ObjectType::Database,
            schema: None,
            name: Some(row.object_name.clone()),
        };

        let entry = grants.entry(key).or_insert_with(|| GrantState {
            privileges: std::collections::BTreeSet::new(),
        });
        entry.privileges.insert(privilege);
    }

    Ok(grants)
}

/// Count the relations (tables, views, materialized views, sequences) each
/// of `role_names` owns inside `managed_schemas`.
///
/// Ownership is what makes an ACL entry invisible to inspection — see
/// `fetch_relation_privileges` — so callers use this to warn when a plan
/// grants or revokes privileges on a role's own objects.
pub async fn fetch_owned_relation_counts(
    pool: &PgPool,
    managed_schemas: &[&str],
    role_names: &[&str],
) -> Result<BTreeMap<String, i64>, sqlx::Error> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        r#"
        SELECT
            pg_get_userbyid(c.relowner) AS owner_name,
            count(*)::bigint AS owned
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = ANY($1)
          AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
          AND pg_get_userbyid(c.relowner) = ANY($2)
        GROUP BY 1
        ORDER BY 1
        "#,
    )
    .bind(managed_schemas)
    .bind(role_names)
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().collect())
}

/// A raw column-level ACL row returned by `fetch_column_level_grants`.
#[derive(Debug, Clone, sqlx::FromRow)]
struct ColumnAclRow {
    schema_name: String,
    relation_name: String,
    /// The grantee role name, or the literal `"PUBLIC"` for grants to the
    /// PUBLIC pseudo-role (ACL grantee OID 0) — rendered explicitly in SQL
    /// since `pg_get_userbyid(0)` returns `"unknown (OID=0)"`, not `PUBLIC`.
    grantee_name: String,
    privilege_type: String,
    column_name: String,
}

/// Detect column-level ACL entries (`GRANT ... (column) ON table TO role`) on
/// relations inside the given schemas.
///
/// pgroles never manages column-level privileges — it only inspects
/// `pg_class.relacl` (table/view/etc.-level grants), never
/// `pg_attribute.attacl`. This function exists purely for detection: it
/// aggregates any column-level ACL entries found so callers can surface an
/// advisory diagnostic. It does not filter by grantee role, since any
/// column-level grant in a managed schema is an audit signal regardless of
/// who holds it.
///
/// Scoped to relation kinds that can carry column ACLs: ordinary/partitioned
/// tables, views, materialized views, and foreign tables. Foreign tables are
/// included even though pgroles does not otherwise inspect them — a
/// column-level grant on an FDW-backed table is exactly the kind of sensitive
/// access this detector exists to surface.
pub async fn fetch_column_level_grants(
    pool: &PgPool,
    privilege_schemas: &[&str],
) -> Result<Vec<ColumnLevelGrantDiagnostic>, sqlx::Error> {
    if privilege_schemas.is_empty() {
        return Ok(Vec::new());
    }

    let rows = sqlx::query_as::<_, ColumnAclRow>(
        r#"
        SELECT
            n.nspname::text AS schema_name,
            c.relname::text AS relation_name,
            CASE WHEN acl.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(acl.grantee) END AS grantee_name,
            acl.privilege_type,
            a.attname::text AS column_name
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_attribute a ON a.attrelid = c.oid AND NOT a.attisdropped AND a.attnum > 0
        CROSS JOIN LATERAL aclexplode(a.attacl) AS acl
        WHERE a.attacl IS NOT NULL
          AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND n.nspname = ANY($1)
        ORDER BY n.nspname, c.relname, grantee_name, a.attname
        "#,
    )
    .bind(privilege_schemas)
    .fetch_all(pool)
    .await?;

    Ok(aggregate_column_acl_rows(rows))
}

/// Aggregate raw column-ACL rows into one [`ColumnLevelGrantDiagnostic`] per
/// `(schema, relation, grantee)`, collecting the affected columns and
/// privilege types. A `BTreeMap` key drives iteration order so the resulting
/// `Vec` is deterministic regardless of row order.
///
/// Column lists are capped at construction (mirroring the
/// `UnsatisfiableWildcardGrant` `examples`/`skipped_count` pattern): only the
/// first [`crate::COLUMN_LEVEL_GRANT_EXAMPLE_LIMIT`] column names (sorted) are
/// kept, with the overflow recorded in `skipped_columns`, so a wide table
/// with thousands of column grants doesn't hold every name in memory.
fn aggregate_column_acl_rows(rows: Vec<ColumnAclRow>) -> Vec<ColumnLevelGrantDiagnostic> {
    struct Accumulator {
        columns: BTreeSet<String>,
        privileges: BTreeSet<Privilege>,
    }

    let mut aggregated: BTreeMap<(String, String, String), Accumulator> = BTreeMap::new();

    for row in rows {
        let Some(privilege) = acl_char_to_privilege(&row.privilege_type) else {
            continue;
        };

        let entry = aggregated
            .entry((row.schema_name, row.relation_name, row.grantee_name))
            .or_insert_with(|| Accumulator {
                columns: BTreeSet::new(),
                privileges: BTreeSet::new(),
            });
        entry.columns.insert(row.column_name);
        entry.privileges.insert(privilege);
    }

    aggregated
        .into_iter()
        .map(|((schema, relation, grantee), acc)| {
            let total = acc.columns.len();
            let columns: Vec<String> = acc
                .columns
                .into_iter()
                .take(crate::COLUMN_LEVEL_GRANT_EXAMPLE_LIMIT)
                .collect();
            ColumnLevelGrantDiagnostic {
                schema,
                relation,
                grantee,
                skipped_columns: total - columns.len(),
                columns,
                privileges: acc.privileges,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WildcardGrantPattern;

    fn grantability_row(object_name: &str, owner_name: &str, can_execute: bool) -> GrantabilityRow {
        GrantabilityRow {
            schema_name: "app".to_string(),
            object_name: object_name.to_string(),
            owner_name: owner_name.to_string(),
            obj_type: "function".to_string(),
            can_select: false,
            can_insert: false,
            can_update: false,
            can_delete: false,
            can_truncate: false,
            can_references: false,
            can_trigger: false,
            can_execute,
            can_usage: false,
        }
    }

    fn execute_wildcard() -> WildcardGrantPattern {
        WildcardGrantPattern {
            role: "app-editor".to_string(),
            object_type: ObjectType::Function,
            schema: "app".to_string(),
            privileges: BTreeSet::from([Privilege::Execute]),
        }
    }

    #[test]
    fn acl_char_mapping_covers_all_privileges() {
        // Standard PostgreSQL ACL characters
        let cases = vec![
            ("r", Privilege::Select),
            ("a", Privilege::Insert),
            ("w", Privilege::Update),
            ("d", Privilege::Delete),
            ("D", Privilege::Truncate),
            ("x", Privilege::References),
            ("t", Privilege::Trigger),
            ("X", Privilege::Execute),
            ("U", Privilege::Usage),
            ("C", Privilege::Create),
            ("c", Privilege::Connect),
            ("T", Privilege::Temporary),
        ];
        for (char, expected) in cases {
            assert_eq!(
                acl_char_to_privilege(char),
                Some(expected),
                "failed for char '{char}'"
            );
        }
        assert_eq!(acl_char_to_privilege("Z"), None);
    }

    #[test]
    fn obj_type_str_mapping_covers_all_types() {
        let cases = vec![
            ("table", ObjectType::Table),
            ("view", ObjectType::View),
            ("materialized_view", ObjectType::MaterializedView),
            ("sequence", ObjectType::Sequence),
            ("function", ObjectType::Function),
            ("schema", ObjectType::Schema),
            ("database", ObjectType::Database),
            ("type", ObjectType::Type),
        ];
        for (type_str, expected) in cases {
            assert_eq!(
                obj_type_str_to_object_type(type_str),
                Some(expected),
                "failed for type_str '{type_str}'"
            );
        }
        assert_eq!(obj_type_str_to_object_type("unknown"), None);
    }

    #[test]
    fn diagnostics_report_missing_non_grantable_wildcard_object() {
        let grants = BTreeMap::new();
        let grantability = BTreeMap::from([
            (
                (ObjectType::Function, "app".to_string(), "f1()".to_string()),
                grantability_row("f1()", "app_owner", true),
            ),
            (
                (ObjectType::Function, "app".to_string(), "f2()".to_string()),
                grantability_row("f2()", "definer", false),
            ),
        ]);

        let diagnostics = detect_unsatisfiable_wildcards(
            &grants,
            &grantability,
            &[execute_wildcard()],
            "app_owner",
        );

        assert_eq!(diagnostics.len(), 1);
        let diagnostic = &diagnostics[0];
        assert_eq!(diagnostic.role, "app-editor");
        assert_eq!(diagnostic.object_type, ObjectType::Function);
        assert_eq!(diagnostic.schema, "app");
        assert_eq!(diagnostic.executor, "app_owner");
        assert_eq!(diagnostic.skipped_count, 1);
        assert_eq!(diagnostic.privileges, BTreeSet::from([Privilege::Execute]));
        assert_eq!(diagnostic.examples[0].name, "f2()");
        assert_eq!(diagnostic.examples[0].owner, "definer");
        let rendered = diagnostic.to_string();
        assert!(rendered.contains("UnsatisfiableWildcardGrant"));
        assert!(rendered.contains("app_owner"));
        assert!(rendered.contains("f2()"));
        assert!(rendered.contains("EXECUTE"));
    }

    #[test]
    fn diagnostics_ignore_missing_grantable_wildcard_object() {
        let grants = BTreeMap::new();
        let grantability = BTreeMap::from([(
            (ObjectType::Function, "app".to_string(), "f1()".to_string()),
            grantability_row("f1()", "app_owner", true),
        )]);

        let diagnostics = detect_unsatisfiable_wildcards(
            &grants,
            &grantability,
            &[execute_wildcard()],
            "app_owner",
        );

        assert!(diagnostics.is_empty());
    }

    #[test]
    fn diagnostics_ignore_non_grantable_object_that_already_has_privilege() {
        let grants = BTreeMap::from([(
            GrantKey {
                role: "app-editor".into(),
                object_type: ObjectType::Function,
                schema: Some("app".to_string()),
                name: Some("f2()".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Execute]),
            },
        )]);
        let grantability = BTreeMap::from([(
            (ObjectType::Function, "app".to_string(), "f2()".to_string()),
            grantability_row("f2()", "definer", false),
        )]);

        let diagnostics = detect_unsatisfiable_wildcards(
            &grants,
            &grantability,
            &[execute_wildcard()],
            "app_owner",
        );

        assert!(diagnostics.is_empty());
    }

    #[test]
    fn unsatisfied_wildcards_are_empty_when_every_object_has_requested_privileges() {
        let grants = BTreeMap::from([
            (
                GrantKey {
                    role: "app-editor".into(),
                    object_type: ObjectType::Function,
                    schema: Some("app".to_string()),
                    name: Some("f1()".to_string()),
                },
                GrantState {
                    privileges: BTreeSet::from([Privilege::Execute]),
                },
            ),
            (
                GrantKey {
                    role: "app-editor".into(),
                    object_type: ObjectType::Function,
                    schema: Some("app".to_string()),
                    name: Some("f2()".to_string()),
                },
                GrantState {
                    privileges: BTreeSet::from([Privilege::Execute]),
                },
            ),
        ]);
        let inventory = BTreeMap::from([(
            (ObjectType::Function, "app".to_string()),
            BTreeSet::from(["f1()".to_string(), "f2()".to_string()]),
        )]);

        let unsatisfied = unsatisfied_wildcard_grants(&grants, &inventory, &[execute_wildcard()]);

        assert!(unsatisfied.is_empty());
    }

    #[test]
    fn unsatisfied_wildcards_keep_only_missing_privileges() {
        let wildcard = WildcardGrantPattern {
            role: "app-editor".to_string(),
            object_type: ObjectType::Table,
            schema: "app".to_string(),
            privileges: BTreeSet::from([Privilege::Select, Privilege::Insert]),
        };
        let grants = BTreeMap::from([(
            GrantKey {
                role: "app-editor".into(),
                object_type: ObjectType::Table,
                schema: Some("app".to_string()),
                name: Some("widgets".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Select]),
            },
        )]);
        let inventory = BTreeMap::from([(
            (ObjectType::Table, "app".to_string()),
            BTreeSet::from(["widgets".to_string()]),
        )]);

        let unsatisfied = unsatisfied_wildcard_grants(&grants, &inventory, &[wildcard]);

        assert_eq!(unsatisfied.len(), 1);
        assert_eq!(
            unsatisfied[0].privileges,
            BTreeSet::from([Privilege::Insert])
        );
    }

    #[test]
    fn wildcard_scope_filter_deduplicates_scopes_and_unions_privileges() {
        let filter = WildcardScopeFilter::from_wildcards(&[
            WildcardGrantPattern {
                role: "reader".to_string(),
                object_type: ObjectType::Table,
                schema: "app".to_string(),
                privileges: BTreeSet::from([Privilege::Select]),
            },
            WildcardGrantPattern {
                role: "writer".to_string(),
                object_type: ObjectType::Table,
                schema: "app".to_string(),
                privileges: BTreeSet::from([Privilege::Insert]),
            },
        ]);

        let arrays = filter.arrays();
        assert_eq!(arrays.schema_names, vec!["app"]);
        assert_eq!(arrays.object_types, vec!["table"]);
        assert_eq!(arrays.need_select, vec![true]);
        assert_eq!(arrays.need_insert, vec![true]);
        assert_eq!(arrays.need_update, vec![false]);
    }

    #[test]
    fn wildcard_scope_filter_reports_unique_schemas() {
        let filter = WildcardScopeFilter::from_wildcards(&[
            WildcardGrantPattern {
                role: "reader".to_string(),
                object_type: ObjectType::Table,
                schema: "app".to_string(),
                privileges: BTreeSet::from([Privilege::Select]),
            },
            WildcardGrantPattern {
                role: "reader".to_string(),
                object_type: ObjectType::Function,
                schema: "app".to_string(),
                privileges: BTreeSet::from([Privilege::Execute]),
            },
            WildcardGrantPattern {
                role: "reader".to_string(),
                object_type: ObjectType::Table,
                schema: "audit".to_string(),
                privileges: BTreeSet::from([Privilege::Select]),
            },
        ]);

        assert_eq!(filter.unique_schemas(), vec!["app", "audit"]);
    }

    #[test]
    fn wildcard_normalization_promotes_shared_table_privileges() {
        let mut grants = BTreeMap::new();
        grants.insert(
            GrantKey {
                role: "inventory-editor".into(),
                object_type: ObjectType::Table,
                schema: Some("inventory".to_string()),
                name: Some("widgets".to_string()),
            },
            GrantState {
                privileges: [Privilege::Select, Privilege::Insert].into_iter().collect(),
            },
        );
        grants.insert(
            GrantKey {
                role: "inventory-editor".into(),
                object_type: ObjectType::Table,
                schema: Some("inventory".to_string()),
                name: Some("orders".to_string()),
            },
            GrantState {
                privileges: [Privilege::Select].into_iter().collect(),
            },
        );

        let inventory = BTreeMap::from([(
            (ObjectType::Table, "inventory".to_string()),
            BTreeSet::from(["orders".to_string(), "widgets".to_string()]),
        )]);
        let selectors = vec![WildcardGrantPattern {
            role: "inventory-editor".to_string(),
            object_type: ObjectType::Table,
            schema: "inventory".to_string(),
            privileges: BTreeSet::from([
                Privilege::Select,
                Privilege::Insert,
                Privilege::Update,
                Privilege::Delete,
            ]),
        }];

        let normalized = normalize_wildcard_grants(grants, &inventory, &selectors);

        let wildcard = normalized
            .get(&GrantKey {
                role: "inventory-editor".into(),
                object_type: ObjectType::Table,
                schema: Some("inventory".to_string()),
                name: Some("*".to_string()),
            })
            .expect("wildcard grant should be synthesized");
        assert_eq!(wildcard.privileges, BTreeSet::from([Privilege::Select]));

        let specific = normalized
            .get(&GrantKey {
                role: "inventory-editor".into(),
                object_type: ObjectType::Table,
                schema: Some("inventory".to_string()),
                name: Some("widgets".to_string()),
            })
            .expect("extra object-specific privileges should remain");
        assert_eq!(specific.privileges, BTreeSet::from([Privilege::Insert]));
    }

    #[test]
    fn normalize_wildcard_empty_inventory_inserts_vacuous_wildcard() {
        // When no objects of the wildcard type exist in the schema, the
        // normalizer should insert a wildcard key with all privileges so
        // the diff sees the desired wildcard as already satisfied.
        let grants = BTreeMap::new();
        let inventory = BTreeMap::new(); // empty — no sequences in "accounts"

        let desired_privs =
            BTreeSet::from([Privilege::Select, Privilege::Update, Privilege::Usage]);
        let wildcards = vec![WildcardGrantPattern {
            role: "accounts-editor".to_string(),
            object_type: ObjectType::Sequence,
            schema: "accounts".to_string(),
            privileges: desired_privs.clone(),
        }];

        let result = normalize_wildcard_grants(grants, &inventory, &wildcards);

        let wildcard_key = GrantKey {
            role: "accounts-editor".into(),
            object_type: ObjectType::Sequence,
            schema: Some("accounts".to_string()),
            name: Some("*".to_string()),
        };

        let entry = result
            .get(&wildcard_key)
            .expect("vacuous wildcard should be present");
        assert_eq!(
            entry.privileges, desired_privs,
            "vacuous wildcard should have the desired privileges"
        );
    }

    #[test]
    fn normalize_wildcard_empty_set_in_inventory_inserts_vacuous_wildcard() {
        // Same as above but the inventory has the key with an empty set.
        let grants = BTreeMap::new();
        let mut inventory: BTreeMap<(ObjectType, String), BTreeSet<String>> = BTreeMap::new();
        inventory.insert(
            (ObjectType::Function, "accounts".to_string()),
            BTreeSet::new(),
        );

        let wildcards = vec![WildcardGrantPattern {
            role: "accounts-editor".to_string(),
            object_type: ObjectType::Function,
            schema: "accounts".to_string(),
            privileges: BTreeSet::from([Privilege::Execute]),
        }];

        let result = normalize_wildcard_grants(grants, &inventory, &wildcards);

        let wildcard_key = GrantKey {
            role: "accounts-editor".into(),
            object_type: ObjectType::Function,
            schema: Some("accounts".to_string()),
            name: Some("*".to_string()),
        };

        let entry = result
            .get(&wildcard_key)
            .expect("vacuous wildcard should be present for empty object set");
        assert_eq!(
            entry.privileges,
            BTreeSet::from([Privilege::Execute]),
            "vacuous wildcard should carry the desired privileges"
        );
    }

    #[test]
    fn normalize_wildcard_nonempty_inventory_still_collapses() {
        // Ensure the existing behavior for non-empty inventories is preserved.
        let mut grants = BTreeMap::new();
        grants.insert(
            GrantKey {
                role: "app".into(),
                object_type: ObjectType::Sequence,
                schema: Some("public".to_string()),
                name: Some("seq1".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([Privilege::Select, Privilege::Usage]),
            },
        );
        grants.insert(
            GrantKey {
                role: "app".into(),
                object_type: ObjectType::Sequence,
                schema: Some("public".to_string()),
                name: Some("seq2".to_string()),
            },
            GrantState {
                privileges: BTreeSet::from([
                    Privilege::Select,
                    Privilege::Usage,
                    Privilege::Update,
                ]),
            },
        );

        let mut inventory: BTreeMap<(ObjectType, String), BTreeSet<String>> = BTreeMap::new();
        inventory.insert(
            (ObjectType::Sequence, "public".to_string()),
            BTreeSet::from(["seq1".to_string(), "seq2".to_string()]),
        );

        let wildcards = vec![WildcardGrantPattern {
            role: "app".to_string(),
            object_type: ObjectType::Sequence,
            schema: "public".to_string(),
            privileges: BTreeSet::from([Privilege::Select, Privilege::Update, Privilege::Usage]),
        }];

        let result = normalize_wildcard_grants(grants, &inventory, &wildcards);

        let wildcard_key = GrantKey {
            role: "app".into(),
            object_type: ObjectType::Sequence,
            schema: Some("public".to_string()),
            name: Some("*".to_string()),
        };

        let entry = result
            .get(&wildcard_key)
            .expect("wildcard should be present");
        // shared privileges are Select + Usage (the intersection)
        assert!(entry.privileges.contains(&Privilege::Select));
        assert!(entry.privileges.contains(&Privilege::Usage));
        assert!(
            !entry.privileges.contains(&Privilege::Update),
            "Update is not shared across all sequences"
        );
    }

    #[test]
    fn object_inventory_supports_non_relation_wildcards() {
        let mut inventory: BTreeMap<(ObjectType, String), BTreeSet<String>> = BTreeMap::new();
        inventory.insert(
            (ObjectType::Function, "public".to_string()),
            BTreeSet::from(["refresh_widgets()".to_string()]),
        );
        inventory.insert(
            (ObjectType::Type, "public".to_string()),
            BTreeSet::from(["widget_status".to_string()]),
        );
        inventory.insert(
            (ObjectType::Sequence, "public".to_string()),
            BTreeSet::from(["widgets_id_seq".to_string()]),
        );

        let wildcards = vec![
            WildcardGrantPattern {
                role: "app".to_string(),
                object_type: ObjectType::Function,
                schema: "public".to_string(),
                privileges: BTreeSet::from([Privilege::Execute]),
            },
            WildcardGrantPattern {
                role: "app".to_string(),
                object_type: ObjectType::Type,
                schema: "public".to_string(),
                privileges: BTreeSet::from([Privilege::Usage]),
            },
            WildcardGrantPattern {
                role: "app".to_string(),
                object_type: ObjectType::Sequence,
                schema: "public".to_string(),
                privileges: BTreeSet::from([Privilege::Usage]),
            },
        ];

        let result = normalize_wildcard_grants(BTreeMap::new(), &inventory, &wildcards);

        assert!(
            !result.contains_key(&GrantKey {
                role: "app".into(),
                object_type: ObjectType::Function,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            }),
            "existing function inventory should prevent vacuous wildcard synthesis"
        );
        assert!(
            !result.contains_key(&GrantKey {
                role: "app".into(),
                object_type: ObjectType::Type,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            }),
            "existing type inventory should prevent vacuous wildcard synthesis"
        );
        assert!(
            !result.contains_key(&GrantKey {
                role: "app".into(),
                object_type: ObjectType::Sequence,
                schema: Some("public".to_string()),
                name: Some("*".to_string()),
            }),
            "existing sequence inventory should prevent vacuous wildcard synthesis"
        );
    }

    fn column_acl_row(
        schema: &str,
        relation: &str,
        grantee: &str,
        privilege: &str,
        column: &str,
    ) -> ColumnAclRow {
        ColumnAclRow {
            schema_name: schema.to_string(),
            relation_name: relation.to_string(),
            grantee_name: grantee.to_string(),
            privilege_type: privilege.to_string(),
            column_name: column.to_string(),
        }
    }

    #[test]
    fn aggregate_column_acl_rows_caps_columns_and_counts_overflow() {
        let rows: Vec<ColumnAclRow> = (0..12)
            .map(|i| column_acl_row("app", "wide", "reader", "r", &format!("col_{i:02}")))
            .collect();

        let diagnostics = aggregate_column_acl_rows(rows);
        assert_eq!(diagnostics.len(), 1);
        let diagnostic = &diagnostics[0];
        assert_eq!(
            diagnostic.columns.len(),
            crate::COLUMN_LEVEL_GRANT_EXAMPLE_LIMIT
        );
        assert_eq!(diagnostic.skipped_columns, 4);
        // Examples are the lexicographically first columns (BTreeSet order).
        assert_eq!(diagnostic.columns[0], "col_00");
        assert_eq!(diagnostic.columns[7], "col_07");
    }

    #[test]
    fn aggregate_column_acl_rows_groups_by_schema_relation_grantee() {
        let rows = vec![
            column_acl_row("app", "widgets", "reader", "r", "name"),
            column_acl_row("app", "widgets", "reader", "r", "secret"),
            column_acl_row("app", "widgets", "reader", "w", "secret"),
            column_acl_row("app", "widgets", "PUBLIC", "r", "id"),
        ];

        let diagnostics = aggregate_column_acl_rows(rows);

        assert_eq!(diagnostics.len(), 2);

        let reader = diagnostics
            .iter()
            .find(|d| d.grantee == "reader")
            .expect("reader diagnostic present");
        assert_eq!(reader.schema, "app");
        assert_eq!(reader.relation, "widgets");
        assert_eq!(
            reader.columns,
            vec!["name".to_string(), "secret".to_string()]
        );
        assert_eq!(
            reader.privileges,
            BTreeSet::from([Privilege::Select, Privilege::Update])
        );

        let public = diagnostics
            .iter()
            .find(|d| d.grantee == "PUBLIC")
            .expect("PUBLIC diagnostic present");
        assert_eq!(public.columns, vec!["id".to_string()]);
        assert_eq!(public.privileges, BTreeSet::from([Privilege::Select]));
    }

    #[test]
    fn aggregate_column_acl_rows_separates_different_relations_and_schemas() {
        let rows = vec![
            column_acl_row("app", "widgets", "reader", "r", "name"),
            column_acl_row("app", "orders", "reader", "r", "name"),
            column_acl_row("audit", "widgets", "reader", "r", "name"),
        ];

        let diagnostics = aggregate_column_acl_rows(rows);

        assert_eq!(diagnostics.len(), 3);
    }

    #[test]
    fn aggregate_column_acl_rows_ignores_unknown_privilege_characters() {
        let rows = vec![column_acl_row("app", "widgets", "reader", "Z", "name")];

        let diagnostics = aggregate_column_acl_rows(rows);

        assert!(diagnostics.is_empty());
    }

    #[test]
    fn aggregate_column_acl_rows_is_deterministic_regardless_of_input_order() {
        let ordered = vec![
            column_acl_row("app", "widgets", "reader", "r", "name"),
            column_acl_row("app", "widgets", "writer", "a", "name"),
        ];
        let mut reversed = ordered.clone();
        reversed.reverse();

        let ordered_result = aggregate_column_acl_rows(ordered);
        let reversed_result = aggregate_column_acl_rows(reversed);

        let ordered_grantees: Vec<&str> =
            ordered_result.iter().map(|d| d.grantee.as_str()).collect();
        let reversed_grantees: Vec<&str> =
            reversed_result.iter().map(|d| d.grantee.as_str()).collect();
        assert_eq!(ordered_grantees, reversed_grantees);
        assert_eq!(ordered_grantees, vec!["reader", "writer"]);
    }

    // -----------------------------------------------------------------------
    // Live database tests (`cargo test -- --include-ignored`)
    // -----------------------------------------------------------------------

    fn with_runtime<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Runtime::new()
            .expect("failed to create tokio runtime")
            .block_on(future)
    }

    fn database_url() -> String {
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for live DB tests")
    }

    fn unique_name(prefix: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        format!("{prefix}_{nanos}")
    }

    fn execute_sql(sql: &str) {
        use sqlx::Executor;

        with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            pool.execute(sql)
                .await
                .expect("failed to execute setup SQL");
        });
    }

    struct TestDbCleanup {
        sql: String,
    }

    impl TestDbCleanup {
        fn new(sql: String) -> Self {
            Self { sql }
        }
    }

    impl Drop for TestDbCleanup {
        fn drop(&mut self) {
            execute_sql(&self.sql);
        }
    }

    fn live_config(schema: &str, role: &str) -> crate::InspectConfig {
        crate::InspectConfig {
            managed_roles: vec![role.to_string()],
            managed_schemas: vec![],
            privilege_schemas: vec![schema.to_string()],
            include_database_privileges: false,
            database_targets: Vec::new(),
            wildcard_grants: vec![],
            public_object_scopes: vec![],
            default_priv_scopes: vec![],
        }
    }

    #[test]
    #[ignore]
    fn inspect_with_diagnostics_detects_column_level_grant() {
        let schema = unique_name("colgrant_schema");
        let role = unique_name("colgrant_role");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            CREATE SCHEMA "{schema}";
            CREATE ROLE "{role}" NOLOGIN;
            CREATE TABLE "{schema}".widgets (id serial primary key, name text, secret text);
            GRANT SELECT (secret) ON "{schema}".widgets TO "{role}";
            "#
        ));

        let inspection = with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            crate::inspect_with_diagnostics(&pool, &live_config(&schema, &role))
                .await
                .expect("inspection should succeed")
        });

        assert_eq!(inspection.diagnostics.column_level_grants.len(), 1);
        let diagnostic = &inspection.diagnostics.column_level_grants[0];
        assert_eq!(diagnostic.schema, schema);
        assert_eq!(diagnostic.relation, "widgets");
        assert_eq!(diagnostic.grantee, role);
        assert_eq!(diagnostic.columns, vec!["secret".to_string()]);
        assert_eq!(diagnostic.privileges, BTreeSet::from([Privilege::Select]));
    }

    #[test]
    #[ignore]
    fn inspect_with_diagnostics_ignores_plain_table_level_grant() {
        let schema = unique_name("colgrant_schema");
        let role = unique_name("colgrant_role");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            CREATE SCHEMA "{schema}";
            CREATE ROLE "{role}" NOLOGIN;
            CREATE TABLE "{schema}".widgets (id serial primary key, name text, secret text);
            GRANT SELECT ON "{schema}".widgets TO "{role}";
            "#
        ));

        let inspection = with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            crate::inspect_with_diagnostics(&pool, &live_config(&schema, &role))
                .await
                .expect("inspection should succeed")
        });

        assert!(
            inspection.diagnostics.column_level_grants.is_empty(),
            "a plain table-level grant must not be reported as a column-level grant"
        );
    }

    #[test]
    #[ignore]
    fn inspect_with_diagnostics_renders_public_grantee_for_column_grant() {
        let schema = unique_name("colgrant_schema");
        let role = unique_name("colgrant_role");
        let _cleanup = TestDbCleanup::new(format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            "#
        ));

        execute_sql(&format!(
            r#"
            DROP SCHEMA IF EXISTS "{schema}" CASCADE;
            DROP ROLE IF EXISTS "{role}";
            CREATE SCHEMA "{schema}";
            CREATE ROLE "{role}" NOLOGIN;
            CREATE TABLE "{schema}".widgets (id serial primary key, name text, secret text);
            GRANT SELECT (secret) ON "{schema}".widgets TO PUBLIC;
            "#
        ));

        // The role isn't the grantee here (PUBLIC is), but InspectConfig
        // still needs at least one managed role to build valid query
        // parameters; column-level grant detection does not filter by
        // grantee role, so PUBLIC is detected regardless.
        let inspection = with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            crate::inspect_with_diagnostics(&pool, &live_config(&schema, &role))
                .await
                .expect("inspection should succeed")
        });

        assert_eq!(inspection.diagnostics.column_level_grants.len(), 1);
        let diagnostic = &inspection.diagnostics.column_level_grants[0];
        assert_eq!(diagnostic.grantee, "PUBLIC");
        assert_eq!(diagnostic.columns, vec!["secret".to_string()]);
    }

    #[test]
    #[ignore]
    fn fetch_column_level_grants_returns_empty_for_no_privilege_schemas() {
        let result = with_runtime(async {
            let pool = PgPool::connect(&database_url())
                .await
                .expect("failed to connect to live test database");
            fetch_column_level_grants(&pool, &[])
                .await
                .expect("fetch should succeed with no schemas")
        });

        assert!(result.is_empty());
    }
}
