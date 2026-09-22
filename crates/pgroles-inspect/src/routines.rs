use std::collections::{BTreeMap, BTreeSet};

use pgroles_core::manifest::ObjectType;
use pgroles_core::sql::qualified_function_name;
use sqlx::PgPool;

use crate::{InspectConfig, InspectError};

#[derive(Default)]
pub(crate) struct RoutineCatalog {
    pub aliases: BTreeMap<(String, String), String>,
    targets: BTreeSet<(String, String)>,
}

impl RoutineCatalog {
    pub async fn read(pool: &PgPool, config: &InspectConfig) -> Result<Self, InspectError> {
        let targets = Self::targets(config);
        if targets.is_empty() {
            return Ok(Self::default());
        }
        let schemas: BTreeSet<&str> = targets.iter().map(|(schema, _)| schema.as_str()).collect();
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            r#"
            SELECT n.nspname::text,
                   p.proname || '(' || pg_catalog.pg_get_function_identity_arguments(p.oid) || ')',
                   p.proname || '(' || pg_catalog.oidvectortypes(p.proargtypes) || ')'
            FROM pg_catalog.pg_proc p
            JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = ANY($1)
            "#,
        )
        .bind(schemas.into_iter().collect::<Vec<_>>())
        .fetch_all(pool)
        .await?;

        let mut aliases = BTreeMap::new();
        for (schema, legacy, canonical) in rows {
            // Older generated policies contain argument names and modes.
            aliases.insert((schema.clone(), legacy), canonical.clone());
            aliases.insert((schema, canonical.clone()), canonical);
        }
        for (schema, name) in &targets {
            if aliases.contains_key(&(schema.clone(), name.clone())) {
                continue;
            }
            let canonical: Option<String> = sqlx::query_scalar(
                r#"
                SELECT p.proname || '(' || pg_catalog.oidvectortypes(p.proargtypes) || ')'
                FROM pg_catalog.pg_proc p
                WHERE p.oid = CASE WHEN $2 THEN pg_catalog.to_regprocedure($1)::oid
                                   ELSE pg_catalog.to_regproc($1)::oid END
                "#,
            )
            .bind(qualified_function_name(schema, name))
            .bind(name.ends_with(')'))
            .fetch_optional(pool)
            .await
            .map_err(|source| InspectError::RoutineTarget {
                schema: schema.clone(),
                name: name.clone(),
                source,
            })?;
            if let Some(canonical) = canonical {
                aliases.insert((schema.clone(), name.clone()), canonical);
            }
        }
        Ok(Self { aliases, targets })
    }

    pub fn missing_target(&self, config: &InspectConfig) -> Option<(String, String)> {
        Self::targets(config)
            .difference(&self.targets)
            .next()
            .cloned()
    }

    fn targets(config: &InspectConfig) -> BTreeSet<(String, String)> {
        config
            .routine_grants
            .iter()
            .filter_map(|grant| {
                let schema = grant.object.schema.as_ref()?;
                let name = grant.object.name.as_ref()?;
                (name != "*").then(|| (schema.clone(), name.clone()))
            })
            .collect()
    }

    pub fn canonical_name(&self, schema: &str, name: &str) -> String {
        self.aliases
            .get(&(schema.to_string(), name.to_string()))
            .cloned()
            .unwrap_or_else(|| name.to_string())
    }

    pub fn resolve_public_scopes(&self, config: &InspectConfig) -> InspectConfig {
        let mut resolved = config.clone();
        for scope in &mut resolved.public_object_scopes {
            if scope.object_type == ObjectType::Function
                && let (Some(schema), Some(name)) = (&scope.schema, &scope.name)
            {
                scope.name = Some(self.canonical_name(schema, name));
            }
        }
        resolved
    }

    pub fn validate(&self, config: &InspectConfig) -> Result<(), InspectError> {
        let mut assertions = BTreeMap::new();
        for grant in &config.routine_grants {
            let (Some(schema), Some(name)) = (&grant.object.schema, &grant.object.name) else {
                continue;
            };
            let name = self.canonical_name(schema, name);
            for privilege in &grant.privileges {
                let key = (grant.role.clone(), schema.clone(), name.clone(), *privilege);
                if let Some(previous) = assertions.insert(key, grant.ensure)
                    && previous != grant.ensure
                {
                    return Err(InspectError::ConflictingRoutineRules {
                        role: grant.role.clone(),
                        schema: schema.clone(),
                        name,
                    });
                }
            }
        }
        Ok(())
    }
}
