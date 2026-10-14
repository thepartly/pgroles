//! Effect-pair extraction and intersection.
//!
//! ADR-001 Decision 6 defines when an ephemeral overlay forces fresh review of
//! a candidate's plan: **iff the set of `(role, object)` pairs touched by the
//! active overlay's effects intersects the set touched by the candidate plan's
//! effects.** The comparison is deliberately narrower than "the change digest
//! moved" — overlays legitimately move the digest, and blanket invalidation
//! would make candidates unusable on any policy with continuous ephemeral
//! traffic.
//!
//! This module is the pure half of that rule. It takes typed effects
//! ([`Change`]) and membership overlay edges and projects both into the same
//! pair space, so the operator only has to ask whether two sets intersect.
//!
//! # The pair space
//!
//! * *role* is the resolved PostgreSQL role name — these are post-expansion
//!   effects, so profile/pattern expansion has already happened.
//! * *object* is [`EffectObject`], the fully-qualified target. Wildcards have
//!   already been expanded against objects observed under the lock by the time
//!   a [`Change`] exists, so nothing here re-expands them.
//! * Membership edges normalise to `(member, EffectObject::Role(role))`: the
//!   granted role is the *object* of the effect, and the member is the role
//!   whose access changes.
//! * Role-attribute-only effects (`LOGIN`, `CONNECTION LIMIT`, passwords,
//!   comments, drops) touch [`EffectObject::RoleAttributes`] — the "(role, ∅)"
//!   of the ADR.
//!
//! # Intersection
//!
//! Two pairs intersect only if their roles match, and then:
//!
//! * a schema-level object intersects any object *within* that schema, because
//!   a grant on the schema and a grant on a table in it can be the same access;
//! * `(role, ∅)` intersects any object of the same role — an attribute change
//!   is not scoped to an object, so it cannot be shown not to overlap. This is
//!   the conservative direction: the cost of a false intersection is one extra
//!   review round, the cost of a false miss is an unreviewed effect.
//! * everything else intersects only itself.
//!
//! Roles match when they are equal, and `PUBLIC` matches every role, because a
//! privilege held by PUBLIC is held by every role.

use std::collections::BTreeSet;

use crate::diff::Change;
use crate::manifest::ObjectType;
use crate::model::{DefaultPrivilegeScope, MembershipEdge, PUBLIC_ROLE};

/// The object half of an effect pair.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum EffectObject {
    /// The role itself, with no object — the ADR's `(role, ∅)`. Attribute
    /// changes, passwords, comments, creates and drops.
    RoleAttributes,
    /// A role treated as the object of a membership edge.
    Role(String),
    /// Every object in a schema. Also the projection of a schema-scoped effect
    /// with no named target (default privileges, schema-wide grants).
    Schema(String),
    /// One named object inside a schema.
    Relation {
        schema: String,
        name: String,
        object_type: ObjectType,
    },
    /// The database itself (`GRANT CONNECT ON DATABASE ...`).
    Database(String),
}

/// One `(role, object)` pair touched by an effect.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EffectPair {
    pub role: String,
    pub object: EffectObject,
}

impl EffectPair {
    fn new(role: impl Into<String>, object: EffectObject) -> Self {
        Self {
            role: role.into(),
            object,
        }
    }

    /// Does this pair intersect `other` under the ADR-001 Decision 6 rule?
    pub fn intersects(&self, other: &EffectPair) -> bool {
        roles_intersect(&self.role, &other.role) && objects_intersect(&self.object, &other.object)
    }
}

/// A privilege held by PUBLIC is held by every role, so an effect on PUBLIC
/// reaches the same objects as an effect on any named role. `PUBLIC` is
/// reserved and can never name a real role, so the comparison is unambiguous.
fn roles_intersect(left: &str, right: &str) -> bool {
    left == right || left == PUBLIC_ROLE || right == PUBLIC_ROLE
}

fn objects_intersect(left: &EffectObject, right: &EffectObject) -> bool {
    use EffectObject::*;
    match (left, right) {
        // An attribute-only effect is not scoped to an object, so it cannot be
        // shown not to overlap anything else on the same role.
        (RoleAttributes, _) | (_, RoleAttributes) => true,
        (Role(a), Role(b)) => a == b,
        (Schema(a), Schema(b)) => a == b,
        (Schema(schema), Relation { schema: other, .. })
        | (Relation { schema: other, .. }, Schema(schema)) => schema == other,
        (
            Relation {
                schema: a_schema,
                name: a_name,
                object_type: a_type,
            },
            Relation {
                schema: b_schema,
                name: b_name,
                object_type: b_type,
            },
        ) => a_schema == b_schema && a_name == b_name && a_type == b_type,
        (Database(a), Database(b)) => a == b,
        _ => false,
    }
}

/// Project a default-privilege scope into the pair space.
fn default_privilege_object(scope: &DefaultPrivilegeScope) -> EffectObject {
    match scope {
        DefaultPrivilegeScope::Schema { schema } => EffectObject::Schema(schema.clone()),
        // A global rule applies in every schema the owner creates objects in,
        // including schemas no policy names, so nothing bounds it to a schema
        // and it must be treated as overlapping anything on the same role.
        DefaultPrivilegeScope::Global => EffectObject::RoleAttributes,
    }
}

/// Project a grant/revoke target into the pair space.
fn grant_object(object_type: ObjectType, schema: Option<&str>, name: Option<&str>) -> EffectObject {
    match object_type {
        // A schema-typed effect names the schema in either field depending on
        // how the manifest expressed it.
        ObjectType::Schema => match (name, schema) {
            (Some(name), _) => EffectObject::Schema(name.to_string()),
            (None, Some(schema)) => EffectObject::Schema(schema.to_string()),
            (None, None) => EffectObject::RoleAttributes,
        },
        ObjectType::Database => match name {
            Some(name) => EffectObject::Database(name.to_string()),
            // A database grant with no name is the connected database; no
            // better identity is available, so it can only match another
            // unnamed one.
            None => EffectObject::Database(String::new()),
        },
        object_type => match (schema, name) {
            (Some(schema), Some(name)) => EffectObject::Relation {
                schema: schema.to_string(),
                name: name.to_string(),
                object_type,
            },
            // No named target left after expansion means the whole schema.
            (Some(schema), None) => EffectObject::Schema(schema.to_string()),
            (None, Some(name)) => EffectObject::Relation {
                schema: String::new(),
                name: name.to_string(),
                object_type,
            },
            (None, None) => EffectObject::RoleAttributes,
        },
    }
}

/// Every `(role, object)` pair touched by one effect.
pub fn change_pairs(change: &Change) -> Vec<EffectPair> {
    match change {
        Change::CreateRole { name, .. }
        | Change::AlterRole { name, .. }
        | Change::SetComment { name, .. }
        | Change::SetPassword { name, .. }
        | Change::DropRole { name } => {
            vec![EffectPair::new(name, EffectObject::RoleAttributes)]
        }
        Change::DropOwned { role } | Change::TerminateSessions { role } => {
            vec![EffectPair::new(role, EffectObject::RoleAttributes)]
        }
        Change::ReassignOwned { from_role, to_role } => vec![
            EffectPair::new(from_role, EffectObject::RoleAttributes),
            EffectPair::new(to_role, EffectObject::RoleAttributes),
        ],
        Change::CreateSchema { name, owner } => owner
            .iter()
            .map(|owner| EffectPair::new(owner, EffectObject::Schema(name.clone())))
            .collect(),
        Change::AlterSchemaOwner { name, owner }
        | Change::EnsureSchemaOwnerPrivileges { name, owner, .. } => {
            vec![EffectPair::new(owner, EffectObject::Schema(name.clone()))]
        }
        Change::Grant {
            role,
            object_type,
            schema,
            name,
            ..
        }
        | Change::Revoke {
            role,
            object_type,
            schema,
            name,
            ..
        } => vec![EffectPair::new(
            role.as_str(),
            grant_object(*object_type, schema.as_deref(), name.as_deref()),
        )],
        // Default privileges change what the grantee will hold on objects the
        // owner creates. Both roles are touched: the grantee gains access, the
        // owner's future objects change.
        Change::SetDefaultPrivilege {
            owner,
            scope,
            grantee,
            ..
        }
        | Change::RevokeDefaultPrivilege {
            owner,
            scope,
            grantee,
            ..
        } => {
            let object = default_privilege_object(scope);
            vec![
                EffectPair::new(grantee.as_str(), object.clone()),
                EffectPair::new(owner, object),
            ]
        }
        Change::AddMember { role, member, .. }
        | Change::UpdateMemberOptions { role, member, .. }
        | Change::RemoveMember { role, member, .. } => {
            vec![EffectPair::new(member, EffectObject::Role(role.clone()))]
        }
    }
}

/// Every pair touched by a set of effects.
pub fn effect_pairs(changes: &[Change]) -> BTreeSet<EffectPair> {
    changes.iter().flat_map(change_pairs).collect()
}

/// Every pair touched by a set of membership overlay edges.
///
/// The overlay the operator composes today is memberships only; keeping this a
/// separate entry point means a future overlay of another shape gets its own
/// projection rather than being squeezed through [`effect_pairs`].
pub fn membership_overlay_pairs<'a>(
    edges: impl IntoIterator<Item = &'a MembershipEdge>,
) -> BTreeSet<EffectPair> {
    edges
        .into_iter()
        .map(|edge| EffectPair::new(&edge.member, EffectObject::Role(edge.role.clone())))
        .collect()
}

/// The pairs present in both sets, under the intersection rule above.
///
/// Returns the *left* set's members, because the caller reports which of the
/// candidate's own effects a reviewer must look at again.
pub fn intersecting_pairs(
    left: &BTreeSet<EffectPair>,
    right: &BTreeSet<EffectPair>,
) -> BTreeSet<EffectPair> {
    left.iter()
        .filter(|pair| right.iter().any(|other| pair.intersects(other)))
        .cloned()
        .collect()
}

/// Whether any pair in `left` intersects any pair in `right`.
pub fn pairs_intersect(left: &BTreeSet<EffectPair>, right: &BTreeSet<EffectPair>) -> bool {
    left.iter()
        .any(|pair| right.iter().any(|other| pair.intersects(other)))
}

/// A short human-readable rendering of a pair, for conditions and Events.
pub fn describe_pair(pair: &EffectPair) -> String {
    match &pair.object {
        EffectObject::RoleAttributes => format!("{} (role attributes)", pair.role),
        EffectObject::Role(role) => format!("{} -> {role} (membership)", pair.role),
        EffectObject::Schema(schema) => format!("{} on schema {schema}", pair.role),
        EffectObject::Relation {
            schema,
            name,
            object_type,
        } => format!("{} on {object_type} {schema}.{name}", pair.role),
        EffectObject::Database(name) => format!("{} on database {name}", pair.role),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Privilege;
    use crate::model::Grantee;

    fn grant(
        role: &str,
        object_type: ObjectType,
        schema: Option<&str>,
        name: Option<&str>,
    ) -> Change {
        Change::Grant {
            role: Grantee::parse(role),
            privileges: BTreeSet::from([Privilege::Select]),
            object_type,
            schema: schema.map(str::to_string),
            name: name.map(str::to_string),
        }
    }

    fn member_edge(role: &str, member: &str) -> MembershipEdge {
        MembershipEdge {
            role: role.to_string(),
            member: member.to_string(),
            inherit: true,
            admin: false,
        }
    }

    #[test]
    fn membership_edges_normalize_to_member_and_role_as_object() {
        let pairs = membership_overlay_pairs(&[member_edge("app_rw", "alice")]);
        assert_eq!(
            pairs,
            BTreeSet::from([EffectPair::new(
                "alice",
                EffectObject::Role("app_rw".to_string())
            )])
        );

        // The diff's own membership change must land on the same pair, or the
        // overlay and the candidate could never be compared.
        assert_eq!(
            effect_pairs(&[Change::AddMember {
                role: "app_rw".to_string(),
                member: "alice".to_string(),
                inherit: true,
                admin: false,
            }]),
            pairs
        );
    }

    #[test]
    fn a_schema_level_effect_intersects_any_object_in_that_schema() {
        let schema_level = effect_pairs(&[grant("app_rw", ObjectType::Schema, None, Some("app"))]);
        let table_level = effect_pairs(&[grant(
            "app_rw",
            ObjectType::Table,
            Some("app"),
            Some("orders"),
        )]);

        assert!(pairs_intersect(&schema_level, &table_level));
        assert!(pairs_intersect(&table_level, &schema_level));

        let other_schema = effect_pairs(&[grant(
            "app_rw",
            ObjectType::Table,
            Some("billing"),
            Some("invoices"),
        )]);
        assert!(!pairs_intersect(&schema_level, &other_schema));
    }

    #[test]
    fn attribute_only_effects_match_the_same_role_only() {
        let attributes = effect_pairs(&[Change::AlterRole {
            name: "alice".to_string(),
            attributes: Vec::new(),
        }]);

        let same_role = membership_overlay_pairs(&[member_edge("app_rw", "alice")]);
        let other_role = membership_overlay_pairs(&[member_edge("app_rw", "bob")]);

        assert!(pairs_intersect(&attributes, &same_role));
        assert!(!pairs_intersect(&attributes, &other_role));
    }

    #[test]
    fn distinct_objects_on_the_same_role_do_not_intersect() {
        let orders = effect_pairs(&[grant(
            "app_rw",
            ObjectType::Table,
            Some("app"),
            Some("orders"),
        )]);
        let invoices = effect_pairs(&[grant(
            "app_rw",
            ObjectType::Table,
            Some("app"),
            Some("invoices"),
        )]);
        assert!(!pairs_intersect(&orders, &invoices));
    }

    #[test]
    fn the_same_object_under_different_types_does_not_intersect() {
        let table = effect_pairs(&[grant(
            "app_rw",
            ObjectType::Table,
            Some("app"),
            Some("orders"),
        )]);
        let sequence = effect_pairs(&[grant(
            "app_rw",
            ObjectType::Sequence,
            Some("app"),
            Some("orders"),
        )]);
        assert!(!pairs_intersect(&table, &sequence));
    }

    #[test]
    fn different_roles_never_intersect() {
        let alice = effect_pairs(&[grant(
            "alice",
            ObjectType::Table,
            Some("app"),
            Some("orders"),
        )]);
        let bob = effect_pairs(&[grant("bob", ObjectType::Table, Some("app"), Some("orders"))]);
        assert!(!pairs_intersect(&alice, &bob));
    }

    #[test]
    fn revoke_and_grant_of_the_same_access_land_on_the_same_pair() {
        let granted = effect_pairs(&[grant(
            "app_rw",
            ObjectType::Table,
            Some("app"),
            Some("orders"),
        )]);
        let revoked = effect_pairs(&[Change::Revoke {
            grantor: None,
            role: Grantee::parse("app_rw"),
            privileges: BTreeSet::from([Privilege::Select]),
            object_type: ObjectType::Table,
            schema: Some("app".to_string()),
            name: Some("orders".to_string()),
        }]);
        assert_eq!(granted, revoked);
    }

    #[test]
    fn default_privileges_touch_both_grantee_and_owner_at_schema_level() {
        let pairs = effect_pairs(&[Change::SetDefaultPrivilege {
            owner: "app_owner".to_string(),
            scope: DefaultPrivilegeScope::Schema {
                schema: "app".to_string(),
            },
            on_type: ObjectType::Table,
            grantee: Grantee::parse("app_ro"),
            privileges: BTreeSet::from([Privilege::Select]),
        }]);
        assert_eq!(
            pairs,
            BTreeSet::from([
                EffectPair::new("app_owner", EffectObject::Schema("app".to_string())),
                EffectPair::new("app_ro", EffectObject::Schema("app".to_string())),
            ])
        );
    }

    #[test]
    fn a_public_effect_overlaps_every_named_role_on_the_same_object() {
        let object = EffectObject::Relation {
            schema: "app".to_string(),
            name: "orders".to_string(),
            object_type: ObjectType::Table,
        };
        let public = EffectPair::new(PUBLIC_ROLE, object.clone());
        let named = EffectPair::new("alice", object);
        assert!(public.intersects(&named));
        assert!(named.intersects(&public));
    }

    #[test]
    fn a_public_effect_still_respects_object_scope() {
        let public = EffectPair::new(PUBLIC_ROLE, EffectObject::Schema("app".to_string()));
        let elsewhere = EffectPair::new("alice", EffectObject::Schema("other".to_string()));
        assert!(!public.intersects(&elsewhere));
    }

    #[test]
    fn a_global_default_privilege_is_not_bounded_to_any_schema() {
        let pairs = effect_pairs(&[Change::SetDefaultPrivilege {
            owner: "app_owner".to_string(),
            scope: DefaultPrivilegeScope::Global,
            on_type: ObjectType::Table,
            grantee: Grantee::parse("app_ro"),
            privileges: BTreeSet::from([Privilege::Select]),
        }]);
        assert_eq!(
            pairs,
            BTreeSet::from([
                EffectPair::new("app_owner", EffectObject::RoleAttributes),
                EffectPair::new("app_ro", EffectObject::RoleAttributes),
            ])
        );
        // It must overlap a schema-scoped effect on the same role, since the
        // global rule reaches every schema.
        assert!(
            EffectPair::new("app_ro", EffectObject::RoleAttributes).intersects(&EffectPair::new(
                "app_ro",
                EffectObject::Schema("anything".to_string())
            ))
        );
    }

    #[test]
    fn a_non_overlapping_overlay_leaves_the_candidate_alone() {
        // The case the ADR exists to protect: continuous ephemeral traffic on
        // unrelated roles must not force a candidate back through review.
        let overlay = membership_overlay_pairs(&[member_edge("oncall_admin", "carol")]);
        let candidate = effect_pairs(&[
            grant(
                "reporting_reader",
                ObjectType::Table,
                Some("app"),
                Some("orders"),
            ),
            Change::CreateRole {
                name: "reporting_reader".to_string(),
                state: Default::default(),
            },
        ]);
        assert!(!pairs_intersect(&candidate, &overlay));
        assert!(intersecting_pairs(&candidate, &overlay).is_empty());
    }

    #[test]
    fn intersecting_pairs_reports_the_left_sides_own_effects() {
        let overlay = membership_overlay_pairs(&[member_edge("app_rw", "alice")]);
        let candidate = effect_pairs(&[
            Change::RemoveMember {
                grantor: None,
                role: "app_rw".to_string(),
                member: "alice".to_string(),
            },
            grant("bob", ObjectType::Table, Some("app"), Some("orders")),
        ]);
        let overlapping = intersecting_pairs(&candidate, &overlay);
        assert_eq!(
            overlapping,
            BTreeSet::from([EffectPair::new(
                "alice",
                EffectObject::Role("app_rw".to_string())
            )])
        );
        assert_eq!(
            describe_pair(overlapping.iter().next().unwrap()),
            "alice -> app_rw (membership)"
        );
    }

    #[test]
    fn database_scoped_effects_do_not_reach_into_schemas() {
        let database = effect_pairs(&[grant("app_rw", ObjectType::Database, None, Some("orders"))]);
        let schema = effect_pairs(&[grant("app_rw", ObjectType::Schema, None, Some("app"))]);
        assert!(!pairs_intersect(&database, &schema));
        assert!(pairs_intersect(&database, &database.clone()));
    }
}
