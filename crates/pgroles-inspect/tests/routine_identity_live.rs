use pgroles_core::diff::{Change, diff};
use pgroles_core::manifest::{expand_manifest, parse_manifest};
use pgroles_core::model::RoleGraph;
use pgroles_core::sql::{qualified_function_name, render_statements};
use pgroles_inspect::{
    InspectConfig, InspectError, RawInspection, RoutineResolutionFailure, inspect,
};
use serde_json::json;
use sqlx::{Executor, PgPool};

fn policy(role: &str, schema: &str, names: &[String]) -> (RoleGraph, InspectConfig) {
    let manifest = json!({
        "roles": [{"name": role}],
        "grants": names.iter().map(|name| json!({
            "role": role, "privileges": ["EXECUTE"],
            "object": {"type": "function", "schema": schema, "name": name}
        })).collect::<Vec<_>>()
    });
    parse_policy(&manifest)
}

fn parse_policy(manifest: &serde_json::Value) -> (RoleGraph, InspectConfig) {
    let parsed = parse_manifest(&manifest.to_string()).unwrap();
    let expanded = expand_manifest(&parsed).unwrap();
    (
        RoleGraph::from_expanded(&expanded, None).unwrap(),
        InspectConfig::from_expanded(&expanded, false),
    )
}

async fn apply(pool: &PgPool, desired: &RoleGraph, config: &InspectConfig) {
    let current = inspect(pool, config).await.unwrap();
    let mut transaction = pool.begin().await.unwrap();
    for change in diff(&current, desired) {
        for statement in render_statements(&change) {
            transaction.execute(statement.as_str()).await.unwrap();
        }
    }
    transaction.commit().await.unwrap();
    let current = inspect(pool, config).await.unwrap();
    assert!(
        diff(&current, desired).is_empty(),
        "{:?}",
        diff(&current, desired)
    );
}

async fn fixture() -> (PgPool, String, String) {
    let pool = PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let schema = format!("routine_{suffix}");
    let role = format!("routine_role_{suffix}");
    pool.execute(
        format!(
            r#"
        CREATE SCHEMA "{schema}";
        CREATE ROLE "{role}";
        CREATE FUNCTION "{schema}".backoff_duration(attempt smallint, max_attempts smallint)
            RETURNS smallint LANGUAGE sql AS 'SELECT attempt';
        CREATE FUNCTION "{schema}".backoff_duration(attempt integer, max_attempts integer)
            RETURNS integer LANGUAGE sql AS 'SELECT attempt';
        CREATE FUNCTION "{schema}".returning(p_input integer, OUT result integer)
            LANGUAGE sql AS 'SELECT p_input';
        CREATE FUNCTION "{schema}".many(VARIADIC items integer[])
            RETURNS integer LANGUAGE sql AS 'SELECT cardinality(items)';
        CREATE PROCEDURE "{schema}".adjust(INOUT value integer)
            LANGUAGE plpgsql AS 'BEGIN value := value + 1; END';
        CREATE PROCEDURE "{schema}".calculate(IN amount integer, OUT result integer)
            LANGUAGE plpgsql AS 'BEGIN result := amount + 1; END';
        CREATE TYPE "{schema}"."state (v1)" AS ENUM ('ready');
        CREATE FUNCTION "{schema}"."strange(name)"(value "{schema}"."state (v1)", tags text[])
            RETURNS text LANGUAGE sql AS 'SELECT value::text';
        REVOKE EXECUTE ON ALL ROUTINES IN SCHEMA "{schema}" FROM PUBLIC;
    "#
        )
        .as_str(),
    )
    .await
    .unwrap();
    (pool, schema, role)
}

async fn cleanup(pool: PgPool, schema: &str, role: &str) {
    pool.execute(format!(r#"DROP SCHEMA "{schema}" CASCADE; DROP ROLE "{role}";"#).as_str())
        .await
        .unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL"]
async fn routine_signatures_converge_across_catalog_spellings() {
    let (pool, schema, role) = fixture().await;
    let canonical = vec![
        "backoff_duration(smallint, smallint)".to_string(),
        "returning(integer)".to_string(),
        "many(integer[])".to_string(),
        "adjust(integer)".to_string(),
        "calculate(integer)".to_string(),
        format!("strange(name)({schema}.\"state (v1)\", text[])"),
    ];
    let aliases = vec![
        "backoff_duration(INT2, pg_catalog.int2)".to_string(),
        "returning(int4)".to_string(),
        "many(INT[])".to_string(),
        "adjust(pg_catalog.int4)".to_string(),
        "calculate(INT4)".to_string(),
        format!("strange(name)({schema}.\"state (v1)\", pg_catalog.text[])"),
    ];
    let legacy: Vec<String> = sqlx::query_scalar(
        "SELECT proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1 AND NOT (proname='backoff_duration' AND proargtypes='23 23'::oidvector) ORDER BY proname"
    ).bind(&schema).fetch_all(&pool).await.unwrap();

    let canonical_policy = policy(&role, &schema, &canonical);
    let alias_policy = policy(&role, &schema, &aliases);
    let legacy_policy = policy(&role, &schema, &legacy);
    for (desired, config) in [&canonical_policy, &alias_policy, &legacy_policy] {
        apply(&pool, desired, config).await;
        apply(&pool, desired, config).await;
        for signature in &canonical {
            let allowed: bool =
                sqlx::query_scalar("SELECT has_function_privilege($1, $2, 'EXECUTE')")
                    .bind(&role)
                    .bind(qualified_function_name(&schema, signature))
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert!(allowed, "missing EXECUTE on {signature}");
        }
        let overload_allowed: bool =
            sqlx::query_scalar("SELECT has_function_privilege($1, $2, 'EXECUTE')")
                .bind(&role)
                .bind(qualified_function_name(
                    &schema,
                    "backoff_duration(integer, integer)",
                ))
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!overload_allowed, "an undeclared overload acquired EXECUTE");
    }

    let union = InspectConfig::union_of([&canonical_policy.1, &alias_policy.1, &legacy_policy.1]);
    let snapshot = RawInspection::read(&pool, &union).await.unwrap();
    for (desired, config) in [&canonical_policy, &alias_policy, &legacy_policy] {
        let derived = snapshot.derive(&pool, config).await.unwrap();
        assert!(diff(&derived.graph, desired).is_empty());
    }
    let narrow = RawInspection::read(&pool, &canonical_policy.1)
        .await
        .unwrap();
    assert!(!narrow.covers(&alias_policy.1));

    let (_, bare_config) = policy(&role, &schema, &["returning".to_string()]);
    let bare_current = inspect(&pool, &bare_config).await.unwrap();
    assert_eq!(
        bare_current.routine_aliases[&(schema.clone(), "returning".to_string())],
        "returning(integer)"
    );

    let empty = policy(&role, &schema, &[]);
    // Retain the routine inspection scope while removing all desired grants.
    apply(&pool, &empty.0, &canonical_policy.1).await;
    let allowed: bool = sqlx::query_scalar("SELECT has_function_privilege($1, $2, 'EXECUTE')")
        .bind(&role)
        .bind(qualified_function_name(&schema, &canonical[0]))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!allowed);
    cleanup(pool, &schema, &role).await;
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL"]
async fn routine_aliases_resolve_public_absences_and_reject_conflicts() {
    let (pool, schema, role) = fixture().await;
    pool.execute(
        format!(r#"GRANT EXECUTE ON ALL ROUTINES IN SCHEMA "{schema}" TO PUBLIC;"#).as_str(),
    )
    .await
    .unwrap();
    let absent = json!({
        "grants": [{"role": "PUBLIC", "ensure": "absent", "privileges": ["EXECUTE"],
            "object": {"type": "function", "schema": schema, "name": "backoff_duration(INT2, INT2)"}}]
    });
    let (desired, config) = parse_policy(&absent);
    let current = inspect(&pool, &config).await.unwrap();
    let changes = diff(&current, &desired);
    assert!(
        matches!(changes.as_slice(), [Change::Revoke { name: Some(name), .. }] if name == "backoff_duration(smallint, smallint)")
    );
    apply(&pool, &desired, &config).await;
    let mut conflict = absent.clone();
    conflict["grants"].as_array_mut().unwrap().push(json!({
        "role": "PUBLIC", "privileges": ["EXECUTE"],
        "object": {"type": "function", "schema": schema, "name": "backoff_duration(smallint, smallint)"}
    }));
    let (_, conflicting_config) = parse_policy(&conflict);
    assert!(matches!(
        inspect(&pool, &conflicting_config).await,
        Err(InspectError::ConflictingRoutineRules { .. })
    ));
    cleanup(pool, &schema, &role).await;
}

#[tokio::test]
#[ignore = "requires a live PostgreSQL"]
async fn unresolved_routine_targets_fail_only_their_own_policy() {
    let (pool, schema, role) = fixture().await;
    let single = |name: &str, ensure: &str| {
        parse_policy(&json!({
            "grants": [{"role": "PUBLIC", "ensure": ensure, "privileges": ["EXECUTE"],
                "object": {"type": "function", "schema": schema, "name": name}}]
        }))
    };
    let overloads = vec![
        "backoff_duration(integer, integer)".to_string(),
        "backoff_duration(smallint, smallint)".to_string(),
    ];
    let near_miss = "backoff_duration(attempt smallint,max_attempts smallint)";
    for (name, ensure, expected, candidates) in [
        (
            near_miss,
            "present",
            RoutineResolutionFailure::Unparseable,
            &overloads[..],
        ),
        (
            near_miss,
            "absent",
            RoutineResolutionFailure::Unparseable,
            &overloads[..],
        ),
        (
            "backoff_duration",
            "present",
            RoutineResolutionFailure::Ambiguous,
            &overloads[..],
        ),
        (
            "backoff_duration",
            "absent",
            RoutineResolutionFailure::Ambiguous,
            &overloads[..],
        ),
        (
            "backoff_duration(text, text)",
            "present",
            RoutineResolutionFailure::Missing,
            &overloads[..],
        ),
        (
            "does_not_exist(integer)",
            "present",
            RoutineResolutionFailure::Missing,
            &[][..],
        ),
    ] {
        let (_, config) = single(name, ensure);
        match inspect(&pool, &config).await {
            Err(InspectError::UnresolvedRoutine {
                name: reported,
                failure,
                candidates: found,
                ..
            }) => {
                assert_eq!(reported, name);
                assert_eq!(failure, expected, "{name} ({ensure})");
                assert_eq!(found, candidates, "{name} ({ensure})");
            }
            other => panic!("{name} ({ensure}): expected an unresolved routine, got {other:?}"),
        }
    }

    let (_, config) = single(near_miss, "present");
    let message = inspect(&pool, &config).await.unwrap_err().to_string();
    assert!(
        message.contains(
            "name the routine by its input types: \
             backoff_duration(integer, integer), backoff_duration(smallint, smallint)"
        ),
        "{message}"
    );

    let (desired, config) = single("does_not_exist(integer)", "absent");
    let current = inspect(&pool, &config).await.unwrap();
    assert!(diff(&current, &desired).is_empty());

    let valid = policy(&role, &schema, &overloads);
    let (_, broken) = single(near_miss, "present");
    let union = InspectConfig::union_of([&valid.1, &broken]);
    let snapshot = RawInspection::read(&pool, &union).await.unwrap();
    snapshot.derive(&pool, &valid.1).await.unwrap();
    assert!(matches!(
        snapshot.derive(&pool, &broken).await,
        Err(InspectError::UnresolvedRoutine { .. })
    ));
    cleanup(pool, &schema, &role).await;
}
