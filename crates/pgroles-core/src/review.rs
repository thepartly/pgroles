//! Redacted, deterministic review output; never an execution approval token.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::diff::{Change, ReconciliationMode};
use crate::ownership::describe_change;
use crate::report::{BundleReportContext, PlanOutputMode, build_bundle_plan, shape_plan_changes};

/// Conservative review priority based on change kind, not an environment-aware risk assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ReviewPriority {
    High,
    Review,
    Informational,
}

pub fn priority(change: &Change) -> ReviewPriority {
    match change {
        Change::CreateRole { state, .. }
            if state.superuser
                || state.createrole
                || state.createdb
                || state.replication
                || state.bypassrls =>
        {
            ReviewPriority::High
        }
        Change::Grant { role, .. } if role.is_public() => ReviewPriority::High,
        Change::SetDefaultPrivilege { grantee, .. } if grantee.is_public() => ReviewPriority::High,
        Change::AddMember { admin: true, .. } => ReviewPriority::High,
        Change::DropRole { .. }
        | Change::DropOwned { .. }
        | Change::TerminateSessions { .. }
        | Change::ReassignOwned { .. }
        | Change::AlterSchemaOwner { .. }
        | Change::AlterRole { .. }
        | Change::Revoke { .. }
        | Change::RevokeDefaultPrivilege { .. }
        | Change::RemoveMember { .. }
        | Change::SetPassword { .. } => ReviewPriority::High,
        Change::CreateRole { .. }
        | Change::CreateSchema { .. }
        | Change::Grant { .. }
        | Change::SetDefaultPrivilege { .. }
        | Change::AddMember { .. }
        | Change::EnsureSchemaOwnerPrivileges { .. } => ReviewPriority::Review,
        Change::SetComment { .. } => ReviewPriority::Informational,
    }
}

#[derive(Serialize)]
struct Row {
    priority: ReviewPriority,
    source: String,
    change: Change,
}

fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        let entity = match character {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '\\' => "&#92;",
            '|' => "&#124;",
            '`' => "&#96;",
            '[' => "&#91;",
            ']' => "&#93;",
            '*' => "&#42;",
            '_' => "&#95;",
            '~' => "&#126;",
            // Neutralize GFM bare URLs, mentions, and issue references as well.
            '@' => "&#64;",
            '#' => "&#35;",
            ':' => "&#58;",
            '.' => "&#46;",
            '\r' | '\n' => " ",
            _ => {
                escaped.push(character);
                continue;
            }
        };
        escaped.push_str(entity);
    }
    escaped
}

/// Render the final filtered plan. Bundle attribution is by owning document;
/// a single manifest is attributed to its supplied path. No line numbers are invented.
pub fn render_markdown(
    changes: &[Change],
    source: &str,
    mode: ReconciliationMode,
    bundle: Option<&BundleReportContext<'_>>,
) -> Result<String, crate::report::BundlePlanRenderError> {
    let rows: Vec<Row> = match bundle {
        Some(context) => build_bundle_plan(changes, context, PlanOutputMode::Redacted)?
            .changes
            .into_iter()
            .map(|entry| Row {
                priority: priority(&entry.change),
                source: entry.owner.document,
                change: entry.change,
            })
            .collect(),
        None => shape_plan_changes(changes, PlanOutputMode::Redacted)
            .into_iter()
            .map(|change| Row {
                priority: priority(&change),
                source: source.into(),
                change,
            })
            .collect(),
    };
    let encoded = serde_json::to_vec(&("pgroles.review.v1", source, mode, &rows))?;
    let digest = Sha256::digest(encoded);
    let fingerprint: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let high = rows
        .iter()
        .filter(|r| r.priority == ReviewPriority::High)
        .count();
    let review = rows
        .iter()
        .filter(|r| r.priority == ReviewPriority::Review)
        .count();
    let info = rows.len() - high - review;
    let mut output = format!(
        "## pgroles review\n\nSource: {}. Mode: {mode:?}.\n\n{} change(s): **{high} high priority**, {review} review, {info} informational.\n\nRedacted report fingerprint (pgroles.review.v1): `{fingerprint}`\n\nThis identifies the displayed changes, source attribution, and mode. It excludes password values, role configuration values, role comments, and database identity and is not an approval token or a database-state fingerprint. Record the target environment alongside this report. Declared passwords appear even when no structural drift exists. Priorities are conservative change-kind hints; inspect the details and database impact before applying.\n",
        escape(source),
        rows.len()
    );
    if rows.is_empty() {
        output.push_str("\nNo changes are planned in this reconciliation mode.\n");
        return Ok(output);
    }
    output.push_str("\n| Priority | Change | Details | Source |\n| --- | --- | --- | --- |\n");
    for row in rows {
        output.push_str(&format!(
            "| {:?} | {} | {} | {} |\n",
            row.priority,
            escape(&describe_change(&row.change)),
            escape(&serde_json::to_string(&row.change)?),
            escape(&row.source)
        ));
    }
    Ok(output)
}

/// Markdown footer that ties a report to the recorded review artifact written
/// by the same planning run.
///
/// `fingerprint` is the artifact's `recorded.review_fingerprint`. Reviewers
/// match a report to its file by comparing the two values; neither is an
/// approval token.
pub fn render_review_artifact_footer(fingerprint: &str) -> String {
    // Code spans do not decode entities, so keep only the digest alphabet
    // instead of escaping.
    let fingerprint: String = fingerprint
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == ':')
        .collect();
    format!(
        "\nRecorded review artifact fingerprint ({}): `{fingerprint}`\n\nThe recorded review file written by this run has the same `recorded.review_fingerprint`; the explorer displays it after import. It identifies the recorded content and is not an approval token.\n",
        crate::review_artifact::REVIEW_ARTIFACT_SCHEMA_VERSION,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn review_artifact_footer_names_the_fingerprint() {
        let footer = render_review_artifact_footer("sha256:0123abcd");
        assert!(footer.contains("pgroles.review-artifact.v2"));
        assert!(footer.contains("`sha256:0123abcd`"));
        let hostile = render_review_artifact_footer("sha256:`x`<b>\n| y");
        assert!(hostile.contains("`sha256:xby`"));
    }
    #[test]
    fn bundle_uses_real_document_ownership_and_rejects_missing_attribution() {
        let mut ownership = crate::ownership::OwnershipIndex::default();
        ownership
            .roles
            .insert("app".into(), "application-fragment".into());
        let managed_scope = crate::ownership::ManagedScope::default();
        let context = BundleReportContext {
            ownership: &ownership,
            managed_scope: &managed_scope,
        };
        let changes = [Change::DropRole { name: "app".into() }];
        let report = render_markdown(
            &changes,
            "bundle.yaml",
            ReconciliationMode::Authoritative,
            Some(&context),
        )
        .unwrap();
        assert!(report.contains("application-fragment"));
        assert!(report.contains("drop role"));
        assert!(
            render_markdown(
                &[Change::DropRole {
                    name: "unknown".into()
                }],
                "bundle.yaml",
                ReconciliationMode::Authoritative,
                Some(&context)
            )
            .is_err()
        );
    }
    #[test]
    fn elevated_attributes_and_delegation_are_high_priority() {
        let state = crate::model::RoleState {
            superuser: true,
            ..Default::default()
        };
        assert_eq!(
            priority(&Change::CreateRole {
                name: "admin".into(),
                state
            }),
            ReviewPriority::High
        );
        assert_eq!(
            priority(&Change::AddMember {
                role: "group".into(),
                member: "app".into(),
                inherit: true,
                admin: true
            }),
            ReviewPriority::High
        );
        assert_eq!(
            priority(&Change::SetComment {
                name: "app".into(),
                comment: None
            }),
            ReviewPriority::Informational
        );
    }
    #[test]
    fn redacts_credentials_and_escapes_untrusted_markdown() {
        let changes = vec![
            Change::SetPassword {
                name: "x|[link](javascript:bad)<b>\nnext ~~hidden~~ @team #123 https://example.com www.example.com".into(),
                password: "SCRAM-secret".into(),
            },
            Change::SetComment {
                name: "app".into(),
                comment: Some("COMMENT-secret".into()),
            },
            Change::AlterRole {
                name: "app".into(),
                attributes: vec![crate::model::RoleAttribute::SetConfig(
                    "app.token".into(),
                    "CONFIG-secret".into(),
                )],
            },
        ];
        let report =
            render_markdown(&changes, "[source]|<b>", ReconciliationMode::Additive, None).unwrap();
        assert!(!report.contains("SCRAM-secret"));
        assert!(!report.contains("COMMENT-secret"));
        assert!(!report.contains("CONFIG-secret"));
        assert!(!report.contains("<b>"));
        assert!(!report.contains("[link]"));
        assert!(report.contains("&#124;"));
        assert!(!report.contains("~~hidden~~"));
        assert!(!report.contains("@team"));
        assert!(!report.contains("#123"));
        assert!(!report.contains("https://"));
        assert!(!report.contains("www.example.com"));
        assert!(report.contains("REDACTED"));
        assert!(report.contains("2 high priority"));
    }
    #[test]
    fn fingerprint_tracks_report_context_but_not_password_verifiers() {
        fn fingerprint(report: &str) -> &str {
            report
                .lines()
                .find(|line| line.starts_with("Redacted report fingerprint"))
                .unwrap()
                .split('`')
                .nth(1)
                .unwrap()
        }
        let changes = vec![Change::SetPassword {
            name: "app".into(),
            password: "one".into(),
        }];
        let a = render_markdown(&changes, "a.yaml", ReconciliationMode::Additive, None).unwrap();
        let b = render_markdown(
            &[Change::SetPassword {
                name: "app".into(),
                password: "two".into(),
            }],
            "a.yaml",
            ReconciliationMode::Additive,
            None,
        )
        .unwrap();
        assert_eq!(a, b);
        assert_ne!(
            fingerprint(&a),
            fingerprint(
                &render_markdown(&changes, "b.yaml", ReconciliationMode::Additive, None).unwrap()
            )
        );
        assert_ne!(
            fingerprint(&a),
            fingerprint(
                &render_markdown(&changes, "a.yaml", ReconciliationMode::Authoritative, None)
                    .unwrap()
            )
        );
        assert!(
            render_markdown(&[], "a.yaml", ReconciliationMode::Adopt, None)
                .unwrap()
                .contains("No changes are planned")
        );
    }
}
