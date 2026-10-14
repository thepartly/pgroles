//! What every scenario needs from the cluster: typed APIs, the database behind
//! a port-forward, waits that follow watches, and cleanup that runs when a
//! scenario fails.

use std::future::Future;
use std::io::Read;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::FutureExt;
use k8s_openapi::api::core::v1::{ConfigMap, Pod, Secret};
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::runtime::wait::{await_condition, conditions};
use kube::{Client, Resource, ResourceExt};
use pgroles_operator::crd::{
    PlanPhase, PolicyCondition, PostgresPolicy, PostgresPolicyCandidate, PostgresPolicyPlan,
    REQUESTED_RECONCILE_ANNOTATION, SqlCompression,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

pub const NAMESPACE: &str = "default";
/// Bounds a failure. A healthy operator reaches each state in seconds.
const WAIT_LIMIT: Duration = Duration::from_secs(180);
const POLICY_LABEL: &str = "pgroles.io/policy";

/// One scenario's view of the cluster, and everything it created.
pub struct Scenario {
    pub client: Client,
    pub db: PgPool,
    policies: Mutex<Vec<String>>,
    candidates: Mutex<Vec<String>>,
    secrets: Mutex<Vec<String>>,
    roles: Mutex<Vec<String>>,
    schemas: Mutex<Vec<String>>,
}

/// Run `body`, then remove what it created whether or not it passed.
pub async fn scenario<F, Fut>(body: F)
where
    F: FnOnce(Arc<Scenario>) -> Fut,
    Fut: Future<Output = ()>,
{
    let client = Client::try_default()
        .await
        .expect("a kubeconfig for the e2e cluster");
    let db = connect_postgres(client.clone()).await;
    let scenario = Arc::new(Scenario {
        client,
        db,
        policies: Mutex::default(),
        candidates: Mutex::default(),
        secrets: Mutex::default(),
        roles: Mutex::default(),
        schemas: Mutex::default(),
    });
    let outcome = AssertUnwindSafe(body(scenario.clone()))
        .catch_unwind()
        .await;
    if outcome.is_err() {
        scenario.dump().await;
    }
    scenario.cleanup().await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// The cluster's PostgreSQL, reached through a port-forward to `postgres-0`
/// that this process owns, so no `kubectl` subprocess is involved.
async fn connect_postgres(client: Client) -> PgPool {
    let pods: Api<Pod> = Api::namespaced(client, NAMESPACE);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a local port for the PostgreSQL forward");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut local, _)) = listener.accept().await {
            let pods = pods.clone();
            tokio::spawn(async move {
                let Ok(mut forwarder) = pods.portforward("postgres-0", &[5432]).await else {
                    return;
                };
                let Some(mut remote) = forwarder.take_stream(5432) else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
                drop(remote);
                let _ = forwarder.join().await;
            });
        }
    });
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&format!(
            "postgres://postgres:devpassword@127.0.0.1:{port}/postgres?sslmode=disable"
        ))
        .await
        .expect("PostgreSQL through the port-forward")
}

impl Scenario {
    pub fn policies(&self) -> Api<PostgresPolicy> {
        Api::namespaced(self.client.clone(), NAMESPACE)
    }

    pub fn plans(&self) -> Api<PostgresPolicyPlan> {
        Api::namespaced(self.client.clone(), NAMESPACE)
    }

    pub fn candidates(&self) -> Api<PostgresPolicyCandidate> {
        Api::namespaced(self.client.clone(), NAMESPACE)
    }

    // -- database --------------------------------------------------------

    /// Run SQL as the superuser. Every role and schema it creates must be
    /// named in `owns_roles`/`owns_schemas` so cleanup removes it.
    pub async fn sql(&self, statements: &str) {
        sqlx::raw_sql(statements)
            .execute(&self.db)
            .await
            .unwrap_or_else(|error| panic!("SQL failed: {error}\n{statements}"));
    }

    pub async fn query_bool(&self, query: &str) -> bool {
        sqlx::query_scalar(query)
            .fetch_one(&self.db)
            .await
            .unwrap_or_else(|error| panic!("query failed: {error}\n{query}"))
    }

    pub async fn is_member(&self, member: &str, role: &str) -> bool {
        self.query_bool(&format!(
            "SELECT pg_has_role('{member}', '{role}', 'MEMBER')"
        ))
        .await
    }

    pub fn owns_roles(&self, roles: &[&str]) {
        let mut owned = self.roles.lock().unwrap();
        owned.extend(roles.iter().map(|role| role.to_string()));
    }

    // -- Kubernetes objects ------------------------------------------------

    /// A Secret holding a DATABASE_URL for `user` on the cluster's database:
    /// the shared superuser URL with its credentials replaced.
    pub async fn database_secret(&self, name: &str, user: &str, password: &str) {
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), NAMESPACE);
        let shared = secrets.get("postgres-credentials").await.unwrap();
        let url = String::from_utf8(shared.data.unwrap()["DATABASE_URL"].0.clone()).unwrap();
        let (scheme, rest) = url.split_once("://").unwrap();
        let host = rest.rsplit_once('@').unwrap().1;
        let secret: Secret = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": name},
            "stringData": {"DATABASE_URL": format!("{scheme}://{user}:{password}@{host}")},
        }))
        .unwrap();
        self.secrets.lock().unwrap().push(name.to_string());
        secrets
            .create(&PostParams::default(), &secret)
            .await
            .unwrap();
    }

    pub async fn create_policy(&self, name: &str, spec: Value) -> PostgresPolicy {
        let policy = PostgresPolicy::new(
            name,
            serde_json::from_value(spec).expect("a well-formed PostgresPolicy spec"),
        );
        self.policies.lock().unwrap().push(name.to_string());
        self.policies()
            .create(&PostParams::default(), &policy)
            .await
            .unwrap()
    }

    pub async fn patch_policy_spec(&self, name: &str, spec: Value) {
        self.policies()
            .patch(
                name,
                &PatchParams::default(),
                &Patch::Merge(json!({"spec": spec})),
            )
            .await
            .unwrap();
    }

    // -- waits ---------------------------------------------------------------

    /// Follow `name` until `ready` holds, and return the object that met it.
    pub async fn wait_for<K>(
        &self,
        api: &Api<K>,
        name: &str,
        what: &str,
        ready: impl Fn(&K) -> bool + Send + 'static,
    ) -> K
    where
        K: Resource + Clone + DeserializeOwned + std::fmt::Debug + Send + 'static,
    {
        let watched = await_condition(api.clone(), name, move |object: Option<&K>| {
            object.is_some_and(&ready)
        });
        match tokio::time::timeout(WAIT_LIMIT, watched).await {
            Ok(Ok(Some(object))) => object,
            Ok(Ok(None)) => panic!("{name} was deleted while waiting for {what}"),
            Ok(Err(error)) => panic!("watching {name} for {what} failed: {error}"),
            Err(_) => {
                let last = api.get_opt(name).await.ok().flatten();
                panic!("{name} did not reach {what} within {WAIT_LIMIT:?}; last seen:\n{last:#?}")
            }
        }
    }

    pub async fn wait_policy_ready(
        &self,
        name: &str,
        status: &str,
        reason: &str,
    ) -> PostgresPolicy {
        let (status, reason) = (status.to_string(), reason.to_string());
        self.wait_for(
            &self.policies(),
            name,
            &format!("Ready={status}/{reason}"),
            move |policy| {
                ready(policy.status.as_ref().map(|s| s.conditions.as_slice()))
                    .is_some_and(|c| c.status == status && c.reason.as_deref() == Some(&reason))
            },
        )
        .await
    }

    pub async fn wait_plan_phase(&self, name: &str, phase: PlanPhase) -> PostgresPolicyPlan {
        self.wait_for(
            &self.plans(),
            name,
            &format!("phase {phase}"),
            move |plan| plan.status.as_ref().is_some_and(|s| s.phase == phase),
        )
        .await
    }

    /// The policy's current plan reference once it names a plan `accept`s.
    pub async fn wait_current_plan(
        &self,
        policy: &str,
        accept: impl Fn(&str) -> bool + Send + 'static,
    ) -> String {
        let policy = self
            .wait_for(&self.policies(), policy, "a current plan", move |policy| {
                current_plan(policy).is_some_and(|plan| accept(&plan))
            })
            .await;
        current_plan(&policy).unwrap()
    }

    /// Request a reconcile and wait until the operator has run it, whatever
    /// the outcome. What the returned policy shows is that run's result.
    pub async fn reconcile(&self, name: &str) -> PostgresPolicy {
        let requested = jiff::Timestamp::now().to_string();
        self.policies()
            .patch(
                name,
                &PatchParams::default(),
                &Patch::Merge(json!({
                    "metadata": {"annotations": {REQUESTED_RECONCILE_ANNOTATION: requested}}
                })),
            )
            .await
            .unwrap();
        self.wait_for(
            &self.policies(),
            name,
            &format!("an attempted reconcile for {requested}"),
            move |policy| {
                policy
                    .status
                    .as_ref()
                    .and_then(|s| s.last_attempted_reconcile_at.as_deref())
                    == Some(requested.as_str())
            },
        )
        .await
    }

    // -- plans -----------------------------------------------------------------

    pub async fn plans_of(&self, policy: &str) -> Vec<PostgresPolicyPlan> {
        self.plans()
            .list(&ListParams::default().labels(&format!("{POLICY_LABEL}={policy}")))
            .await
            .unwrap()
            .items
    }

    pub async fn plan(&self, name: &str) -> PostgresPolicyPlan {
        self.plans().get(name).await.unwrap()
    }

    /// The SQL a plan stores, inline or in its ConfigMap.
    pub async fn plan_sql(&self, name: &str) -> String {
        let status = self.plan(name).await.status.expect("a computed plan");
        if let Some(inline) = status.sql_inline.filter(|sql| !sql.is_empty()) {
            return inline;
        }
        let reference = status.sql_ref.expect("a plan with stored SQL");
        let maps: Api<ConfigMap> = Api::namespaced(self.client.clone(), NAMESPACE);
        let map = maps.get(&reference.name).await.unwrap();
        if matches!(reference.compression, Some(SqlCompression::Gzip)) {
            let bytes = &map.binary_data.unwrap()[&reference.key].0;
            let mut sql = String::new();
            flate2::read::GzDecoder::new(bytes.as_slice())
                .read_to_string(&mut sql)
                .unwrap();
            sql
        } else {
            map.data.unwrap()[&reference.key].clone()
        }
    }

    /// Record a reviewer decision the way a reviewer would: one status write
    /// carrying the decision condition and who made it.
    pub async fn decide(&self, plan: &str, decision: Decision) {
        let current = self.plan(plan).await;
        let mut conditions: Vec<Value> = current
            .status
            .map(|status| status.conditions)
            .unwrap_or_default()
            .into_iter()
            .filter(|c| c.condition_type != "Approved" && c.condition_type != "Denied")
            .map(|c| serde_json::to_value(c).unwrap())
            .collect();
        let (condition, reason) = match decision {
            Decision::Approve => ("Approved", "ApprovedByReviewer"),
            Decision::Deny => ("Denied", "DeniedByReviewer"),
        };
        conditions.push(json!({
            "type": condition, "status": "True", "reason": reason,
            "message": "recorded by the cluster e2e",
            "last_transition_time": jiff::Timestamp::now().to_string(),
        }));
        self.plans()
            .patch_status(
                plan,
                &PatchParams::default(),
                &Patch::Merge(json!({"status": {
                    "conditions": conditions,
                    "decidedBy": {"username": "e2e-reviewer"},
                }})),
            )
            .await
            .unwrap();
    }

    pub async fn set_plan_phase(&self, plan: &str, phase: PlanPhase) {
        self.plans()
            .patch_status(
                plan,
                &PatchParams::default(),
                &Patch::Merge(json!({"status": {"phase": phase}})),
            )
            .await
            .unwrap();
    }

    /// A second plan object identical to `original` — what an earlier
    /// controller left behind when it opened a plan per reconcile.
    pub async fn duplicate_plan(
        &self,
        original: &PostgresPolicyPlan,
        name: &str,
    ) -> PostgresPolicyPlan {
        let mut copy = original.clone();
        let meta = &mut copy.metadata;
        meta.name = Some(name.to_string());
        meta.resource_version = None;
        meta.uid = None;
        meta.creation_timestamp = None;
        meta.managed_fields = None;
        meta.generation = None;
        let status = copy.status.take();
        self.plans()
            .create(&PostParams::default(), &copy)
            .await
            .unwrap();
        self.plans()
            .patch_status(
                name,
                &PatchParams::default(),
                &Patch::Merge(json!({"status": status})),
            )
            .await
            .unwrap()
    }

    // -- teardown --------------------------------------------------------------

    async fn dump(&self) {
        let policies = self.policies.lock().unwrap().clone();
        for name in policies {
            if let Ok(policy) = self.policies().get(&name).await {
                eprintln!("--- policy {name}:\n{:#?}", policy.status);
                for plan in self.plans_of(&name).await {
                    eprintln!("--- plan {}:\n{:#?}", plan.name_any(), plan.status);
                }
            }
        }
        let candidates = self.candidates.lock().unwrap().clone();
        for name in candidates {
            if let Ok(candidate) = self.candidates().get(&name).await {
                eprintln!("--- candidate {name}:\n{:#?}", candidate.status);
            }
        }
    }

    async fn cleanup(&self) {
        let candidates = self.candidates.lock().unwrap().clone();
        for name in candidates {
            delete_and_wait(&self.candidates(), &name).await;
        }
        let policies = self.policies.lock().unwrap().clone();
        for name in policies {
            delete_and_wait(&self.policies(), &name).await;
        }
        let secrets: Api<Secret> = Api::namespaced(self.client.clone(), NAMESPACE);
        let names = self.secrets.lock().unwrap().clone();
        for name in names {
            let _ = secrets.delete(&name, &DeleteParams::default()).await;
        }
        let schemas = self.schemas.lock().unwrap().clone();
        for schema in schemas {
            let _ = sqlx::raw_sql(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
                .execute(&self.db)
                .await;
        }
        let roles = self.roles.lock().unwrap().clone();
        for role in roles {
            let _ = sqlx::raw_sql(&format!(
                "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN \
                 EXECUTE 'DROP OWNED BY \"{role}\"'; EXECUTE 'DROP ROLE \"{role}\"'; END IF; END $$"
            ))
            .execute(&self.db)
            .await;
        }
    }
}

pub enum Decision {
    Approve,
    Deny,
}

pub fn ready(conditions: Option<&[PolicyCondition]>) -> Option<&PolicyCondition> {
    conditions?.iter().find(|c| c.condition_type == "Ready")
}

pub fn current_plan(policy: &PostgresPolicy) -> Option<String> {
    policy
        .status
        .as_ref()?
        .current_plan_ref
        .as_ref()
        .map(|reference| reference.name.clone())
}

pub fn is_actionable(plan: &PostgresPolicyPlan) -> bool {
    plan.status
        .as_ref()
        .is_some_and(|s| matches!(s.phase, PlanPhase::Pending | PlanPhase::Approved))
}

async fn delete_and_wait<K>(api: &Api<K>, name: &str)
where
    K: Resource + Clone + DeserializeOwned + std::fmt::Debug + Send + 'static,
{
    let Ok(Some(object)) = api.get_opt(name).await else {
        return;
    };
    let uid = object.uid().unwrap_or_default();
    let _ = api.delete(name, &DeleteParams::default()).await;
    let _ = tokio::time::timeout(
        WAIT_LIMIT,
        await_condition(api.clone(), name, conditions::is_deleted(&uid)),
    )
    .await;
}
