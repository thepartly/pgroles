//! Query PostgreSQL role memberships from `pg_auth_members`.

use sqlx::PgPool;

use pgroles_core::model::MembershipEdge;

/// A row from our membership query.
#[derive(Debug, sqlx::FromRow)]
pub struct MembershipRow {
    /// The group role name.
    pub role_name: String,
    /// The member role name.
    pub member_name: String,
    /// Whether the member has admin option on this membership.
    pub admin_option: bool,
    /// Whether the member inherits the role's privileges.
    /// Available since PostgreSQL 16. For older versions we fall back to
    /// the member role's `rolinherit` attribute.
    pub inherit_option: bool,
    /// PG16+ SET permission; legacy memberships always permit SET ROLE.
    pub set_option: bool,
    /// The role that granted this edge. Recorded per edge since
    /// PostgreSQL 16, where a plain REVOKE removes only the edge attributed
    /// to the revoker — removing a membership means revoking every grantor's
    /// edge (`REVOKE ... GRANTED BY`). `None` on older servers, whose revokes
    /// are not grantor-attributed.
    pub grantor: Option<String>,
}

impl MembershipRow {
    /// Convert to the core model's `MembershipEdge`.
    pub fn to_membership_edge(&self) -> MembershipEdge {
        MembershipEdge {
            role: self.role_name.clone(),
            member: self.member_name.clone(),
            inherit: self.inherit_option,
            admin: self.admin_option,
        }
    }
}

/// Fetch all role memberships from the database.
///
/// If `managed_roles` is provided, only returns memberships where the group
/// role is in the managed set. If `None`, returns all non-system memberships.
///
/// Uses PostgreSQL 16+ `inherit_option` column if available, otherwise falls
/// back to the member role's `rolinherit` attribute.
pub async fn fetch_memberships(
    pool: &PgPool,
    managed_roles: Option<&[&str]>,
) -> Result<Vec<MembershipRow>, sqlx::Error> {
    // Check if we're on PG16+ by probing for the inherit_option column.
    let has_inherit_option = check_pg16_inherit_option(pool).await?;

    if has_inherit_option {
        fetch_memberships_pg16(pool, managed_roles).await
    } else {
        fetch_memberships_legacy(pool, managed_roles).await
    }
}

/// Fetch memberships granted from PostgreSQL's predefined (`pg_*`) roles to
/// ordinary roles.
///
/// These grants pass permission checks without appearing in any object ACL,
/// so they are reported informationally by `pgroles inspect` and exported by
/// `pgroles generate` even when no manifest declares them. Members that are
/// themselves system roles (other `pg_*` roles, `postgres`) are excluded to
/// match generate's non-system scope.
pub async fn fetch_predefined_memberships(
    pool: &PgPool,
) -> Result<Vec<MembershipRow>, sqlx::Error> {
    let has_inherit_option = check_pg16_inherit_option(pool).await?;
    if has_inherit_option {
        sqlx::query_as::<_, MembershipRow>(
            r#"
            SELECT
                gr.rolname AS role_name,
                mr.rolname AS member_name,
                m.admin_option,
                m.inherit_option,
                m.set_option,
                g.rolname AS grantor
            FROM pg_auth_members m
            JOIN pg_roles gr ON gr.oid = m.roleid
            JOIN pg_roles mr ON mr.oid = m.member
            JOIN pg_roles g ON g.oid = m.grantor
            WHERE gr.rolname LIKE 'pg\_%'
              AND mr.rolname NOT LIKE 'pg\_%'
              AND mr.rolname <> 'postgres'
            ORDER BY gr.rolname, mr.rolname
            "#,
        )
        .fetch_all(pool)
        .await
    } else {
        sqlx::query_as::<_, MembershipRow>(
            r#"
            SELECT
                gr.rolname AS role_name,
                mr.rolname AS member_name,
                m.admin_option,
                mr.rolinherit AS inherit_option,
                true AS set_option,
                NULL::text AS grantor
            FROM pg_auth_members m
            JOIN pg_roles gr ON gr.oid = m.roleid
            JOIN pg_roles mr ON mr.oid = m.member
            WHERE gr.rolname LIKE 'pg\_%'
              AND mr.rolname NOT LIKE 'pg\_%'
              AND mr.rolname <> 'postgres'
            ORDER BY gr.rolname, mr.rolname
            "#,
        )
        .fetch_all(pool)
        .await
    }
}

/// Render predefined-role memberships for `pgroles inspect` output.
///
/// Empty input renders nothing, matching [`crate::format_public_grants`].
pub fn format_predefined_memberships(rows: &[MembershipRow]) -> String {
    if rows.is_empty() {
        return String::new();
    }
    let mut output = String::new();
    output.push_str("\nPredefined-role memberships (master keys; managed only when declared):\n");
    for row in rows {
        output.push_str(&format!(
            "  \"{}\" member of \"{}\"{}\n",
            row.member_name,
            row.role_name,
            if row.admin_option {
                " (with admin)"
            } else {
                ""
            },
        ));
    }
    output
}

/// Check whether the `pg_auth_members.inherit_option` column exists (PG16+).
async fn check_pg16_inherit_option(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let row: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'pg_catalog'
              AND table_name = 'pg_auth_members'
              AND column_name = 'inherit_option'
        )
        "#,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

/// Fetch memberships on PostgreSQL 16+ (has `inherit_option` column).
async fn fetch_memberships_pg16(
    pool: &PgPool,
    managed_roles: Option<&[&str]>,
) -> Result<Vec<MembershipRow>, sqlx::Error> {
    match managed_roles {
        Some(names) => {
            sqlx::query_as::<_, MembershipRow>(
                r#"
                SELECT
                    gr.rolname AS role_name,
                    mr.rolname AS member_name,
                    m.admin_option,
                    m.inherit_option,
                    m.set_option,
                    g.rolname AS grantor
                FROM pg_auth_members m
                JOIN pg_roles gr ON gr.oid = m.roleid
                JOIN pg_roles mr ON mr.oid = m.member
                JOIN pg_roles g ON g.oid = m.grantor
                WHERE gr.rolname = ANY($1)
                ORDER BY gr.rolname, mr.rolname
                "#,
            )
            .bind(names)
            .fetch_all(pool)
            .await
        }
        None => {
            sqlx::query_as::<_, MembershipRow>(
                r#"
                SELECT
                    gr.rolname AS role_name,
                    mr.rolname AS member_name,
                    m.admin_option,
                    m.inherit_option,
                    m.set_option,
                    g.rolname AS grantor
                FROM pg_auth_members m
                JOIN pg_roles gr ON gr.oid = m.roleid
                JOIN pg_roles mr ON mr.oid = m.member
                JOIN pg_roles g ON g.oid = m.grantor
                WHERE gr.rolname NOT LIKE 'pg_%'
                ORDER BY gr.rolname, mr.rolname
                "#,
            )
            .fetch_all(pool)
            .await
        }
    }
}

/// Fetch memberships on PostgreSQL < 16 (no `inherit_option` column).
/// Falls back to the member role's `rolinherit` attribute.
async fn fetch_memberships_legacy(
    pool: &PgPool,
    managed_roles: Option<&[&str]>,
) -> Result<Vec<MembershipRow>, sqlx::Error> {
    match managed_roles {
        Some(names) => {
            sqlx::query_as::<_, MembershipRow>(
                r#"
                SELECT
                    gr.rolname AS role_name,
                    mr.rolname AS member_name,
                    m.admin_option,
                    mr.rolinherit AS inherit_option,
                    true AS set_option,
                    NULL::text AS grantor
                FROM pg_auth_members m
                JOIN pg_roles gr ON gr.oid = m.roleid
                JOIN pg_roles mr ON mr.oid = m.member
                WHERE gr.rolname = ANY($1)
                ORDER BY gr.rolname, mr.rolname
                "#,
            )
            .bind(names)
            .fetch_all(pool)
            .await
        }
        None => {
            sqlx::query_as::<_, MembershipRow>(
                r#"
                SELECT
                    gr.rolname AS role_name,
                    mr.rolname AS member_name,
                    m.admin_option,
                    mr.rolinherit AS inherit_option,
                    true AS set_option,
                    NULL::text AS grantor
                FROM pg_auth_members m
                JOIN pg_roles gr ON gr.oid = m.roleid
                JOIN pg_roles mr ON mr.oid = m.member
                WHERE gr.rolname NOT LIKE 'pg_%'
                ORDER BY gr.rolname, mr.rolname
                "#,
            )
            .fetch_all(pool)
            .await
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_row_maps_to_membership_edge() {
        let row = MembershipRow {
            grantor: None,
            set_option: true,
            role_name: "editors".to_string(),
            member_name: "alice@example.com".to_string(),
            admin_option: true,
            inherit_option: false,
        };

        let edge = row.to_membership_edge();
        assert_eq!(edge.role, "editors");
        assert_eq!(edge.member, "alice@example.com");
        assert!(!edge.inherit);
        assert!(edge.admin);
    }
}
