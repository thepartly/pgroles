//! ADR-002 prototype: teams attach policies to one `PostgresDatabase`, each
//! within what the database owner delegated, and the operator composes the
//! accepted ones into a single policy it reconciles with a non-superuser
//! executor.
//!
//! Covers composition under delegations, rejection by delegation, scope and
//! precedence, retention of a policy's last accepted content through a
//! rejected edit (one the composition rejects, and one the controller refuses
//! before composition), and a team leaving while another still grants to its
//! role.

use pgroles_operator::database::PostgresDatabase;
use serde_json::{Value, json};

use crate::harness::{Scenario, scenario};

const PLATFORM: &str = "pgd-platform";
const BILLING: &str = "pgd-billing";
const SHIPPING: &str = "pgd-shipping";
const ANALYTICS: &str = "pgd-analytics";
const DATABASE: &str = "pgd-appdb";
const COMPOSED: &str = "pgd-appdb-composed";

fn billing_policy() -> Value {
    json!({
        "databaseRef": {"name": DATABASE, "namespace": PLATFORM},
        "roles": [
            {"name": "pgd_billing_owner"},
            {"name": "pgd_billing_api", "login": true},
            // References: billing grants to these but does not create them.
            {"name": "pgd_team_payments", "external": true},
            {"name": "pgd_shipping_api", "external": true},
        ],
        "schemas": [{"name": "pgd_billing", "owner": "pgd_billing_owner"}],
        "grants": [
            {"role": "pgd_billing_api", "privileges": ["USAGE"],
             "object": {"type": "schema", "name": "pgd_billing"}},
            {"role": "pgd_team_payments", "privileges": ["USAGE"],
             "object": {"type": "schema", "name": "pgd_billing"}},
            {"role": "pgd_shipping_api", "privileges": ["USAGE"],
             "object": {"type": "schema", "name": "pgd_billing"}},
        ],
    })
}

fn attached(roles: Value) -> Value {
    json!({
        "databaseRef": {"name": DATABASE, "namespace": PLATFORM},
        "roles": roles,
    })
}

async fn accepted(s: &Scenario, namespace: &str, name: &str, status: &str, reason: &str) {
    s.wait_policy_condition_in(namespace, name, "Accepted", status, reason)
        .await;
}

/// Wait until the composed policy has reconciled its current generation, so
/// what PostgreSQL shows next is that composition's result.
async fn composed_converged(s: &Scenario) {
    s.reconcile_in(PLATFORM, COMPOSED).await;
    s.wait_policy_condition_in(PLATFORM, COMPOSED, "Ready", "True", "Reconciled")
        .await;
}

async fn still_retained(s: &Scenario, reason: &str) {
    let billing = s
        .wait_policy_condition_in(BILLING, "billing", "Accepted", "False", reason)
        .await;
    let message = billing
        .status
        .and_then(|status| {
            status
                .conditions
                .into_iter()
                .find(|c| c.condition_type == "Accepted")
        })
        .and_then(|condition| condition.message)
        .unwrap_or_default();
    assert!(
        message.contains("still applied"),
        "a rejected edit keeps the last accepted content: {message}"
    );
    // The younger policy that wants billing's role stays out.
    accepted(s, BILLING, "squatter", "False", "Conflicted").await;
}

#[tokio::test]
async fn teams_attach_to_a_postgres_database_within_their_delegations() {
    scenario(|s| async move {
        s.owns_roles(&[
            "pgd_team_payments",
            "pgd_billing_api",
            "pgd_billing_owner",
            "pgd_shipping_api",
            "pgd_analytics_reader",
            "pgd_executor",
        ]);
        s.owns_schemas(&["pgd_billing"]);
        // A non-superuser executor, as the ADR's trust model recommends.
        s.sql(
            "CREATE ROLE pgd_executor LOGIN CREATEROLE PASSWORD 'pgd-test-password';
             ALTER ROLE pgd_executor SET createrole_self_grant = 'set, inherit';",
        )
        .await;
        s.sql("GRANT CREATE ON DATABASE postgres TO pgd_executor").await;
        for namespace in [PLATFORM, BILLING, SHIPPING, ANALYTICS] {
            s.create_namespace(namespace).await;
        }
        s.database_secret_in(PLATFORM, "pgd-executor", "pgd_executor", "pgd-test-password")
            .await;
        s.create_database(
            PLATFORM,
            DATABASE,
            json!({
                "connection": {"secretRef": {"name": "pgd-executor"}},
                "interval": "1h",
                "mode": "apply",
                "approval": "auto",
                "reconciliationMode": "authoritative",
                "executorRole": "pgd_executor",
                "delegations": [
                    {"name": "platform", "namespaces": [PLATFORM], "roles": ["pgd_team_*"]},
                    {"name": "billing", "namespaces": [BILLING], "roles": ["pgd_billing_*"],
                     "schemas": [{"name": "pgd_billing", "facets": ["owner", "bindings"]}]},
                    {"name": "shipping", "namespaces": [SHIPPING], "roles": ["pgd_shipping_*"]},
                ],
            }),
        )
        .await;

        // 1. Three teams compose into one policy. Billing references roles
        //    the other teams create, declaring them external.
        s.create_policy_in(
            PLATFORM,
            "team-roles",
            attached(json!([{"name": "pgd_team_payments"}])),
        )
        .await;
        s.create_policy_in(
            SHIPPING,
            "shipping",
            attached(json!([{"name": "pgd_shipping_api", "login": true}])),
        )
        .await;
        s.create_policy_in(BILLING, "billing", billing_policy()).await;
        for (namespace, name) in [(PLATFORM, "team-roles"), (SHIPPING, "shipping"), (BILLING, "billing")] {
            accepted(&s, namespace, name, "True", "Accepted").await;
        }
        composed_converged(&s).await;
        s.wait_policy_condition_in(BILLING, "billing", "Ready", "True", "Reconciled")
            .await;
        assert_eq!(
            s.query_text("SELECT nspowner::regrole::text FROM pg_namespace WHERE nspname = 'pgd_billing'")
                .await,
            "pgd_billing_owner"
        );
        assert!(
            s.query_bool("SELECT has_schema_privilege('pgd_team_payments', 'pgd_billing', 'USAGE')")
                .await,
            "billing's grant to a role the platform team creates"
        );
        let database = s
            .databases_in(PLATFORM)
            .get(DATABASE)
            .await
            .unwrap();
        let billing_entry = database_entry(&database, BILLING, "billing");
        assert_eq!(billing_entry["delegations"], json!(["billing"]));

        // 2. Rejections, each confined to the policy that earned it.
        s.create_policy_in(
            ANALYTICS,
            "reporting",
            attached(json!([{"name": "pgd_analytics_reader"}])),
        )
        .await;
        let mut escalate = attached(json!([]));
        escalate["memberships"] =
            json!([{"role": "pgd_team_payments", "members": [{"name": "pgd_billing_api"}]}]);
        s.create_policy_in(BILLING, "escalate", escalate).await;
        s.create_policy_in(
            BILLING,
            "squatter",
            attached(json!([{"name": "pgd_billing_api", "superuser": true}])),
        )
        .await;
        accepted(&s, ANALYTICS, "reporting", "False", "NotDelegated").await;
        accepted(&s, BILLING, "escalate", "False", "OutOfScope").await;
        accepted(&s, BILLING, "squatter", "False", "Conflicted").await;
        accepted(&s, BILLING, "billing", "True", "Accepted").await;
        composed_converged(&s).await;
        assert!(
            !s.query_bool("SELECT rolsuper FROM pg_roles WHERE rolname = 'pgd_billing_api'")
                .await
        );
        assert!(!s.is_member("pgd_billing_api", "pgd_team_payments").await);
        assert!(
            !s.query_bool("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pgd_analytics_reader')")
                .await
        );

        // 3. Billing's edit reaches outside its delegation while the squatter
        //    waits for billing_api. The edit is rejected, the previous
        //    generation stays composed, and the squatter stays out.
        s.patch_policy_spec_in(
            BILLING,
            "billing",
            json!({"memberships": [{"role": "pgd_team_payments", "members": [{"name": "pgd_billing_api"}]}]}),
        )
        .await;
        still_retained(&s, "OutOfScope").await;
        composed_converged(&s).await;
        assert!(
            !s.query_bool("SELECT rolsuper FROM pg_roles WHERE rolname = 'pgd_billing_api'")
                .await
        );
        assert!(!s.is_member("pgd_billing_api", "pgd_team_payments").await);
        s.patch_policy_spec_in(BILLING, "billing", json!({"memberships": null}))
            .await;
        accepted(&s, BILLING, "billing", "True", "Accepted").await;

        // 4. An edit setting profiles, which only the database owner may set,
        //    is refused before composition — and still retained.
        s.patch_policy_spec_in(
            BILLING,
            "billing",
            json!({"profiles": {"mine": {"grants": []}}}),
        )
        .await;
        still_retained(&s, "Invalid").await;
        s.patch_policy_spec_in(BILLING, "billing", json!({"profiles": null}))
            .await;
        accepted(&s, BILLING, "billing", "True", "Accepted").await;

        // 5. Shipping leaves while billing still grants to its role. The role
        //    is composed as an external reference, so the plan converges.
        s.delete_policy_in(SHIPPING, "shipping").await;
        let composed = s
            .wait_for(
                &s.policies_in(PLATFORM),
                COMPOSED,
                "pgd_shipping_api declared external",
                |policy| {
                    policy
                        .spec
                        .roles
                        .iter()
                        .any(|role| role.name == "pgd_shipping_api" && role.external)
                },
            )
            .await;
        assert!(
            composed
                .spec
                .roles
                .iter()
                .all(|role| role.name != "pgd_billing_api" || role.superuser != Some(true))
        );
        composed_converged(&s).await;
        assert!(
            s.query_bool("SELECT has_schema_privilege('pgd_shipping_api', 'pgd_billing', 'USAGE')")
                .await,
            "leaving does not revoke what another team granted"
        );
    })
    .await;
}

fn database_entry(database: &PostgresDatabase, namespace: &str, name: &str) -> Value {
    let status = serde_json::to_value(database.status.as_ref().expect("database status")).unwrap();
    status["attached"]
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry["namespace"] == namespace && entry["name"] == name)
                .cloned()
        })
        .unwrap_or_else(|| panic!("no record for {namespace}/{name} in {status:#}"))
}
