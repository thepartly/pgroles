//! Server-observed identity of the target: physical lineage and session endpoint.
//!
//! `pg_control_system().system_identifier` is the 64-bit value `initdb` writes
//! into `pg_control`. It answers a question no Kubernetes reference can: *is
//! this the same storage lineage the plan was computed against?* It survives
//! failover to a streaming replica, and it catches a restore taken from a
//! different cluster behind an unchanged endpoint.
//!
//! It is a *lineage* identifier rather than an instance one — replicas, PITR
//! and snapshot restores, Aurora clones and Neon branches all inherit the
//! parent's value, which is why the operator binds the logical connection
//! fingerprint alongside it.
//!
//! Availability: `pg_control_system()` has been executable by `PUBLIC` since
//! PostgreSQL 9.6, and no mainstream managed PostgreSQL (RDS, Aurora, Cloud
//! SQL, AlloyDB, Azure Flexible Server, Neon, Supabase) restricts it. Engines
//! that merely speak the PostgreSQL protocol — CockroachDB, Spanner's
//! PostgreSQL interface, Redshift, Aurora DSQL — do not implement it at all,
//! and on YugabyteDB the value is not meaningful. Those are the cases behind
//! the `Ok(None)` arm, together with a deployment that has deliberately
//! revoked `EXECUTE`.

use sqlx::PgPool;

/// SQLSTATE `undefined_function` — the engine has no `pg_control_system()`.
const SQLSTATE_UNDEFINED_FUNCTION: &str = "42883";
/// SQLSTATE `insufficient_privilege` — `EXECUTE` was revoked.
const SQLSTATE_INSUFFICIENT_PRIVILEGE: &str = "42501";

/// Read `system_identifier`, or `Ok(None)` when the target cannot answer.
///
/// Only the two SQLSTATEs that mean "this target does not offer the physical
/// identity" are folded into `None`. Everything else — a dropped connection, a
/// read-only recovery conflict, a timeout — is returned as an error, because
/// treating a transient failure as "unavailable" would let an approval quietly
/// lose the strongest half of its target binding.
pub async fn detect_system_identifier(pool: &PgPool) -> Result<Option<String>, sqlx::Error> {
    let result: Result<(i64,), sqlx::Error> =
        sqlx::query_as("SELECT system_identifier FROM pg_control_system()")
            .fetch_one(pool)
            .await;

    match result {
        // Rendered as an unsigned decimal string, which is how PostgreSQL's
        // own tooling (`pg_controldata`, `pg_basebackup`) prints it; the
        // catalog column is a signed `int8`.
        Ok((identifier,)) => Ok(Some((identifier as u64).to_string())),
        Err(err) if is_identity_unavailable(&err) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Where the server says this session is connected, as the server itself sees it.
///
/// Every field is evaluated server-side, so two sessions that reach one
/// database through different client-side names — two Secrets, a CNAME and
/// the raw host, a pooler in front of the server — read the same values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEndpoint {
    /// `current_database()`.
    pub database: String,
    /// `inet_server_addr()` without a netmask; `None` over a Unix socket.
    pub address: Option<String>,
    /// `inet_server_port()`; `None` over a Unix socket.
    pub port: Option<i32>,
}

/// Read the server-side endpoint of the current session.
pub async fn detect_server_endpoint(pool: &PgPool) -> Result<ServerEndpoint, sqlx::Error> {
    let (database, address, port): (String, Option<String>, Option<i32>) = sqlx::query_as(
        "SELECT current_database()::text, host(inet_server_addr()), inet_server_port()",
    )
    .fetch_one(pool)
    .await?;
    Ok(ServerEndpoint {
        database,
        address,
        port,
    })
}

fn is_identity_unavailable(err: &sqlx::Error) -> bool {
    let sqlx::Error::Database(db_err) = err else {
        return false;
    };
    matches!(
        db_err.code().as_deref(),
        Some(SQLSTATE_UNDEFINED_FUNCTION) | Some(SQLSTATE_INSUFFICIENT_PRIVILEGE)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_database_error_is_not_treated_as_unavailable() {
        assert!(!is_identity_unavailable(&sqlx::Error::PoolTimedOut));
        assert!(!is_identity_unavailable(&sqlx::Error::RowNotFound));
    }

    #[tokio::test]
    #[ignore = "requires a live PostgreSQL"]
    async fn reads_the_server_endpoint_from_a_live_server() {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
        let pool = PgPool::connect(&url).await.expect("connect");

        let endpoint = detect_server_endpoint(&pool).await.expect("query succeeds");
        let expected: (String,) = sqlx::query_as("SELECT current_database()::text")
            .fetch_one(&pool)
            .await
            .expect("query succeeds");
        assert_eq!(endpoint.database, expected.0);
        // The integration suites connect over TCP.
        assert!(endpoint.address.is_some(), "TCP sessions report an address");
        assert!(endpoint.port.is_some(), "TCP sessions report a port");
        assert_eq!(
            endpoint,
            detect_server_endpoint(&pool).await.expect("query succeeds"),
            "the endpoint must be stable across reads"
        );
    }

    #[tokio::test]
    #[ignore = "requires a live PostgreSQL"]
    async fn reads_the_system_identifier_from_a_live_server() {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL");
        let pool = PgPool::connect(&url).await.expect("connect");

        let identifier = detect_system_identifier(&pool)
            .await
            .expect("query succeeds")
            .expect("PostgreSQL always exposes pg_control_system()");

        assert!(identifier.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(
            identifier,
            detect_system_identifier(&pool)
                .await
                .expect("query succeeds")
                .expect("identifier"),
            "the identifier must be stable across reads"
        );
    }
}
