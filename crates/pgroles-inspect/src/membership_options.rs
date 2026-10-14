//! Read-only, concrete executor attribution for membership option intents.
use pgroles_core::{diff::Change, membership_options::MembershipAuthority, model::RoleGraph};
use sqlx::PgPool;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, thiserror::Error)]
pub enum MembershipPlanningError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Options(#[from] pgroles_core::membership_options::MembershipOptionsError),
}

impl MembershipPlanningError {
    /// Stable diagnostic code shared with [`crate::AuthorityIssue::code`].
    pub const NO_USABLE_GRANTOR: &'static str = "NoUsableGrantor";

    /// The blocker message when resolution failed only because the executor
    /// holds no usable ADMIN authority for an increase. That is an
    /// executor-authority failure like any preflight finding — nothing has
    /// run — so callers report it as one rather than as a planning fault.
    pub fn executor_authority_blocker(&self) -> Option<String> {
        match self {
            Self::Options(
                error @ pgroles_core::membership_options::MembershipOptionsError::NoUsableGrantor {
                    ..
                },
            ) => Some(error.to_string()),
            _ => None,
        }
    }
}

pub async fn resolve_membership_options(
    pool: &PgPool,
    changes: Vec<Change>,
    current: &RoleGraph,
) -> Result<Vec<Change>, MembershipPlanningError> {
    let targets: BTreeSet<String> = changes
        .iter()
        .filter_map(|c| match c {
            Change::UpdateMemberOptions { role, .. } => Some(role.clone()),
            _ => None,
        })
        .collect();
    if targets.is_empty() {
        return Ok(changes);
    }
    let executor: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(pool)
        .await?;
    let phase = membership_removal_phase(pool, &changes, &executor).await?;
    let superuser: bool =
        sqlx::query_scalar("SELECT rolsuper FROM pg_roles WHERE rolname=current_user")
            .fetch_one(pool)
            .await?;
    let bootstrap: String = sqlx::query_scalar("SELECT rolname::text FROM pg_roles WHERE oid=10")
        .fetch_one(pool)
        .await?;
    let dropped: BTreeSet<String> = changes
        .iter()
        .filter_map(|c| match c {
            Change::DropRole { name } => Some(name.clone()),
            _ => None,
        })
        .collect();
    // PostgreSQL evaluates inherited ADMIN, not SET-only or arbitrary MEMBER
    // paths. Superuser grants are attributed to bootstrap OID 10, which is
    // not necessarily a role named postgres and is not the non-bootstrap SU.
    let rows: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT DISTINCT target.rolname, grantor.rolname
        FROM pg_auth_members edge
        JOIN pg_roles target ON target.oid = edge.roleid
        JOIN pg_roles grantor ON grantor.oid = edge.member
        WHERE target.rolname = ANY($1) AND edge.admin_option
          AND pg_has_role(current_user, grantor.oid, 'USAGE')
          AND (NOT target.rolsuper OR (SELECT rolsuper FROM pg_roles WHERE rolname = current_user))
        UNION
        SELECT target.rolname, bootstrap.rolname
        FROM pg_roles target CROSS JOIN pg_roles bootstrap
        WHERE target.rolname = ANY($1) AND bootstrap.oid = 10
          AND (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)
        ORDER BY 1, 2
    "#,
    )
    .bind(targets.into_iter().collect::<Vec<_>>())
    .fetch_all(pool)
    .await?;
    let mut usable_grantors: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (role, grantor) in rows {
        if !dropped.contains(&grantor)
            && (superuser || phase.inherited_roles.contains(&grantor))
            && (superuser && grantor == bootstrap
                || !phase.admin_lost.contains(&(role.clone(), grantor.clone())))
        {
            usable_grantors.entry(role).or_default().insert(grantor);
        }
    }
    Ok(
        pgroles_core::membership_options::resolve_membership_options(
            changes,
            current,
            &MembershipAuthority {
                executor,
                usable_grantors,
            },
        )?,
    )
}

/// Project existing catalog rows through the removal phase per grantor.
/// Independent INHERIT/ADMIN suppliers remain effective until every supplier
/// is removed. Positive grants are not used as authority for earlier steps.
pub(crate) struct MembershipRemovalPhase {
    pub inherit_lost: Vec<(String, String)>,
    pub admin_lost: Vec<(String, String)>,
    pub inherited_roles: BTreeSet<String>,
}

pub(crate) async fn membership_removal_phase(
    pool: &PgPool,
    changes: &[Change],
    executor: &str,
) -> Result<MembershipRemovalPhase, sqlx::Error> {
    let rows: Vec<(String,String,String,bool,bool)> = sqlx::query_as(
        "SELECT r.rolname::text,m.rolname::text,g.rolname::text,a.inherit_option,a.admin_option FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member JOIN pg_roles g ON g.oid=a.grantor"
    ).fetch_all(pool).await?;
    let mut projected: BTreeMap<(String, String, String), (bool, bool)> = rows
        .into_iter()
        .map(|(role, member, grantor, inherit, admin)| ((role, member, grantor), (inherit, admin)))
        .collect();
    fn effective(
        rows: &BTreeMap<(String, String, String), (bool, bool)>,
    ) -> BTreeMap<(String, String), (bool, bool)> {
        let mut result: BTreeMap<(String, String), (bool, bool)> = BTreeMap::new();
        for ((role, member, _), (inherit, admin)) in rows {
            let flags = result.entry((role.clone(), member.clone())).or_default();
            flags.0 |= *inherit;
            flags.1 |= *admin;
        }
        result
    }
    let before = effective(&projected);
    for change in changes {
        match change {
            Change::RemoveMember {
                role,
                member,
                grantor,
            } => projected.retain(|(r, m, g), _| {
                r != role || m != member || grantor.as_ref().is_some_and(|v| v != g)
            }),
            Change::UpdateMemberOptions {
                role,
                member,
                grantor,
                inherit,
                admin,
                ..
            } => {
                if let Some(flags) =
                    projected.get_mut(&(role.clone(), member.clone(), grantor.clone()))
                {
                    if *inherit == Some(false) {
                        flags.0 = false;
                    }
                    if *admin == Some(false) {
                        flags.1 = false;
                    }
                }
            }
            _ => {}
        }
    }
    let after = effective(&projected);
    let inherit_lost = before
        .iter()
        .filter(|(key, flags)| flags.0 && !after.get(*key).is_some_and(|v| v.0))
        .map(|(key, _)| key.clone())
        .collect();
    let admin_lost = before
        .iter()
        .filter(|(key, flags)| flags.1 && !after.get(*key).is_some_and(|v| v.1))
        .map(|(key, _)| key.clone())
        .collect();
    let mut inherited_roles = BTreeSet::from([executor.to_string()]);
    loop {
        let mut changed = false;
        for ((role, member), flags) in &after {
            if flags.0 && inherited_roles.contains(member) {
                changed |= inherited_roles.insert(role.clone());
            }
        }
        if !changed {
            break;
        }
    }
    Ok(MembershipRemovalPhase {
        inherit_lost,
        admin_lost,
        inherited_roles,
    })
}
