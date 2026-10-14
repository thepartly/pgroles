//! The checks an apply runs before it executes a plan.
//!
//! The operator's apply, its candidate previews, and the CLI's `apply` and
//! `diff` all evaluate a plan through [`evaluate_execution_guards`], so a
//! preview cannot pass a plan that the apply it predicts would refuse. Each
//! surface decides what to do with a finding — refuse, warn or record it — but
//! none decides on its own what the findings are.

use pgroles_core::diff::{Change, ReconciliationMode};
use pgroles_core::manifest::RoleRetirement;
use pgroles_core::model::RoleGraph;
use sqlx::PgPool;

use crate::preflight::{AuthorityIssue, preflight_authority_issues};
use crate::safety::{DropRoleSafetyAssessment, DropRoleSafetyReport, inspect_drop_role_safety};

/// How the apply being evaluated will run.
#[derive(Debug, Clone, Copy)]
pub struct ExecutionSettings {
    /// Whether the apply executes SQL. Nothing is refused on behalf of one
    /// that never does, such as an observe-mode policy, for an ownership
    /// transfer; the other guards describe the SQL and apply regardless.
    pub executes: bool,
    /// Whether adopt-mode schema ownership transfers were explicitly allowed.
    pub allow_schema_owner_transfers: bool,
    /// How that allowance is given on this surface, phrased to complete
    /// "to permit this, …": `set spec.allow_schema_owner_transfers` or
    /// `pass --allow-schema-owner-transfers`.
    pub transfer_allowance: &'static str,
}

/// The guard behind a blocker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionGuard {
    /// The executor lacks privileges a planned statement needs.
    ExecutorAuthority,
    /// Adopt mode would transfer schema ownership that was not allowed.
    SchemaOwnerTransfer,
    /// A planned role drop leaves owned objects, privileges or sessions that
    /// its retirement does not handle.
    RoleDropSafety,
}

/// One reason the apply would refuse to execute the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionBlocker {
    pub guard: ExecutionGuard,
    /// Stable kind within the guard.
    pub code: String,
    /// Readable explanation naming the affected roles or objects.
    pub message: String,
}

/// What the guards found for one plan, before any of it executes.
#[derive(Debug, Default)]
pub struct ExecutionGuardFindings {
    /// The adopt-mode transfers the apply refuses, as `(schema, new owner)`.
    pub refused_schema_owner_transfers: Vec<(String, String)>,
    /// Role-drop safety: blockers refuse the apply, warnings are hazards the
    /// planned retirement handles.
    pub drop_safety: DropRoleSafetyAssessment,
    pub authority: Vec<AuthorityIssue>,
    transfer_allowance: &'static str,
}

impl ExecutionGuardFindings {
    /// Every blocker, one per affected schema, role or statement, in the
    /// order an apply reports them.
    pub fn blockers(&self) -> Vec<ExecutionBlocker> {
        let transfers = self
            .refused_schema_owner_transfers
            .iter()
            .map(|(name, owner)| ExecutionBlocker {
                guard: ExecutionGuard::SchemaOwnerTransfer,
                code: "AdoptSchemaOwnerTransfer".to_string(),
                message: format!(
                    "adopt mode would transfer ownership of schema \"{name}\" to \"{owner}\"; \
                     to permit this, {}",
                    self.transfer_allowance
                ),
            });
        let drops = self
            .drop_safety
            .blockers
            .issues
            .iter()
            .map(|issue| ExecutionBlocker {
                guard: ExecutionGuard::RoleDropSafety,
                code: "UnsafeRoleDrop".to_string(),
                message: DropRoleSafetyReport {
                    issues: vec![issue.clone()],
                }
                .to_string(),
            });
        let authority = self.authority.iter().map(|issue| ExecutionBlocker {
            guard: ExecutionGuard::ExecutorAuthority,
            code: issue.code().to_string(),
            message: issue.to_string(),
        });
        transfers.chain(drops).chain(authority).collect()
    }

    /// The single refusal message for every refused ownership transfer.
    pub fn owner_transfer_refusal(&self) -> Option<String> {
        if self.refused_schema_owner_transfers.is_empty() {
            return None;
        }
        let transfers = self
            .refused_schema_owner_transfers
            .iter()
            .map(|(name, owner)| format!("\"{name}\" -> \"{owner}\""))
            .collect::<Vec<_>>();
        Some(format!(
            "adopt mode would transfer ownership of {} schema(s): {}. To permit this, {}; \
             use additive mode to skip transfers, or declare each schema's current owner.",
            transfers.len(),
            transfers.join(", "),
            self.transfer_allowance
        ))
    }
}

/// The adopt-mode schema ownership transfers an apply with `settings` refuses.
pub fn refused_schema_owner_transfers(
    settings: &ExecutionSettings,
    mode: ReconciliationMode,
    changes: &[Change],
) -> Vec<(String, String)> {
    if !settings.executes || settings.allow_schema_owner_transfers {
        return Vec::new();
    }
    pgroles_core::diff::adopt_schema_owner_transfers(mode, changes)
        .into_iter()
        .map(|(name, owner)| (name.to_string(), owner.to_string()))
        .collect()
}

/// Run every guard an apply runs before it executes `changes` against
/// `current` on `pool`. The guards only read the catalog.
pub async fn evaluate_execution_guards(
    pool: &PgPool,
    settings: &ExecutionSettings,
    mode: ReconciliationMode,
    changes: &[Change],
    current: &RoleGraph,
    retirements: &[RoleRetirement],
) -> Result<ExecutionGuardFindings, sqlx::Error> {
    let dropped_roles: Vec<String> = changes
        .iter()
        .filter_map(|change| match change {
            Change::DropRole { name } => Some(name.clone()),
            _ => None,
        })
        .collect();
    let drop_safety = inspect_drop_role_safety(pool, &dropped_roles)
        .await?
        .assess(retirements);
    let authority = preflight_authority_issues(pool, changes, current).await?;
    Ok(ExecutionGuardFindings {
        refused_schema_owner_transfers: refused_schema_owner_transfers(settings, mode, changes),
        drop_safety,
        authority,
        transfer_allowance: settings.transfer_allowance,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safety::DropRoleSafetyIssue;

    const OPERATOR: ExecutionSettings = ExecutionSettings {
        executes: true,
        allow_schema_owner_transfers: false,
        transfer_allowance: "set spec.allow_schema_owner_transfers",
    };

    fn transfer() -> Vec<Change> {
        vec![Change::AlterSchemaOwner {
            name: "warehouse".into(),
            owner: "warehouse_owner".into(),
        }]
    }

    #[test]
    fn only_an_apply_that_executes_without_the_allowance_refuses_adopt_transfers() {
        let refused =
            refused_schema_owner_transfers(&OPERATOR, ReconciliationMode::Adopt, &transfer());
        assert_eq!(
            refused,
            vec![("warehouse".to_string(), "warehouse_owner".to_string())]
        );
        let allowed = ExecutionSettings {
            allow_schema_owner_transfers: true,
            ..OPERATOR
        };
        let observing = ExecutionSettings {
            executes: false,
            ..OPERATOR
        };
        for (settings, mode) in [
            (allowed, ReconciliationMode::Adopt),
            (observing, ReconciliationMode::Adopt),
            (OPERATOR, ReconciliationMode::Authoritative),
            (OPERATOR, ReconciliationMode::Additive),
        ] {
            assert!(refused_schema_owner_transfers(&settings, mode, &transfer()).is_empty());
        }
    }

    #[test]
    fn findings_name_the_guard_behind_every_blocker_in_apply_order() {
        let findings = ExecutionGuardFindings {
            refused_schema_owner_transfers: vec![("warehouse".into(), "warehouse_owner".into())],
            drop_safety: DropRoleSafetyAssessment {
                warnings: Default::default(),
                blockers: DropRoleSafetyReport {
                    issues: vec![DropRoleSafetyIssue {
                        role: "retired".into(),
                        owned_object_count: 1,
                        owned_object_examples: vec!["table public.t".into()],
                        shared_owned_object_count: 0,
                        shared_owned_object_examples: vec![],
                        external_owned_object_count: 0,
                        external_owned_object_examples: vec![],
                        privilege_dependency_count: 0,
                        privilege_dependency_examples: vec![],
                        external_privilege_dependency_count: 0,
                        external_privilege_dependency_examples: vec![],
                        other_dependency_count: 0,
                        other_dependency_examples: vec![],
                        external_other_dependency_count: 0,
                        external_other_dependency_examples: vec![],
                        active_session_count: 0,
                    }],
                },
            },
            authority: vec![AuthorityIssue::MissingDefaultPrivilegeOwner {
                owner: "app_owner".into(),
            }],
            transfer_allowance: OPERATOR.transfer_allowance,
        };
        let blockers = findings.blockers();
        assert_eq!(
            blockers
                .iter()
                .map(|blocker| (blocker.guard, blocker.code.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (
                    ExecutionGuard::SchemaOwnerTransfer,
                    "AdoptSchemaOwnerTransfer"
                ),
                (ExecutionGuard::RoleDropSafety, "UnsafeRoleDrop"),
                (
                    ExecutionGuard::ExecutorAuthority,
                    "MissingDefaultPrivilegeOwner"
                ),
            ]
        );
        assert!(blockers[0].message.contains("\"warehouse\""));
        assert!(
            blockers[0]
                .message
                .contains("spec.allow_schema_owner_transfers")
        );
        assert!(blockers[1].message.contains("retired"));
        assert!(blockers[2].message.contains("app_owner"));
        let refusal = findings.owner_transfer_refusal().unwrap();
        assert!(refusal.contains("1 schema(s): \"warehouse\" -> \"warehouse_owner\""));
        assert!(refusal.contains("set spec.allow_schema_owner_transfers"));
        assert!(ExecutionGuardFindings::default().blockers().is_empty());
        assert!(
            ExecutionGuardFindings::default()
                .owner_transfer_refusal()
                .is_none()
        );
    }
}
