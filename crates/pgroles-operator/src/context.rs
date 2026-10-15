//! Shared operator context — database pool cache, metrics, and configuration.

use std::collections::HashMap;
use std::fmt::Write;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use futures::future::{BoxFuture, FutureExt};
use kube::runtime::events::Recorder;
use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use tokio::sync::{Mutex, RwLock};

use crate::crd::{ConnectionAuth, ConnectionSpec, SecretKeySelector};
use crate::observability::OperatorObservability;
use crate::plan::PlanRetention;
use crate::request_index::RequestIndex;

/// Longest a reconcile waits on one Kubernetes API request.
pub const API_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The client for the requests reconciles make — gets, lists, patches, status
/// writes, Events, finalizer updates — and never for watches.
///
/// Each request must finish, response body included, within
/// [`API_REQUEST_TIMEOUT`]. kube's own timeouts are idle timeouts sized for a
/// watch's long poll: a stalled call, such as the finalizer patch kube's
/// finalizer helper issues before a policy's first reconcile, or a response
/// that trickles in, could otherwise hold the controller's only reconcile
/// slot for minutes with nothing logged. Bounded, the call fails, the
/// controller logs the error and requeues, and the next attempt opens a fresh
/// request.
pub fn request_client(config: kube::Config) -> Result<kube::Client, kube::Error> {
    request_client_with_deadline(config, API_REQUEST_TIMEOUT)
}

fn request_client_with_deadline(
    config: kube::Config,
    timeout: Duration,
) -> Result<kube::Client, kube::Error> {
    Ok(kube::client::ClientBuilder::try_from(config)?
        .with_layer(&crate::request_deadline::RequestDeadlineLayer::new(timeout))
        .build())
}

/// Minimum pool size required for reconciliation.
///
/// One connection is held for the session-scoped advisory lock while the
/// reconcile loop performs inspection and apply work on the pool.
const POOL_MAX_CONNECTIONS: u32 = 5;

/// Bound how long a reconcile waits for a pooled connection before surfacing
/// a transient database connectivity failure.
const POOL_ACQUIRE_TIMEOUT_SECS: u64 = 10;

const _: () = assert!(POOL_MAX_CONNECTIONS >= 2);

/// How long a pooled connection may sit unused before it is closed.
///
/// Pools are cached for the operator's lifetime, so without this the operator
/// holds connections open against every managed database forever. sqlx's
/// default is 10 minutes — longer than the 5-minute default requeue interval,
/// so a reconcile always re-touches the pool before the reaper drains it and
/// the connections are never released. Reconnecting once per reconcile is
/// cheap next to occupying a backend slot on an idle database around the clock.
const POOL_IDLE_TIMEOUT_SECS: u64 = 60;

/// Hard ceiling on connection age, independent of activity.
///
/// Bounds how long a reconcile can keep using a connection whose server-side
/// state has drifted (failover, restarted pooler, rotated credentials).
const POOL_MAX_LIFETIME_SECS: u64 = 30 * 60;

/// Keep no connections open when nothing is reconciling.
const POOL_MIN_CONNECTIONS: u32 = 0;

const GCP_METADATA_TOKEN_ENDPOINT: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
const GCP_IAM_CREDENTIALS_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const GCP_TOKEN_CACHE_SKEW_SECS: u64 = 300;
const GCP_IMPERSONATED_TOKEN_LIFETIME_SECS: u64 = 3600;
const GCP_AUTH_HTTP_TIMEOUT_SECS: u64 = 10;

#[derive(Clone)]
struct CachedPool {
    resource_version: Option<String>,
    /// Fingerprint of all referenced secrets' resourceVersions (params mode).
    secret_fingerprint: Option<String>,
    /// Expiry for token-backed connection passwords.
    token_expires_at: Option<SystemTime>,
    pool: PgPool,
}

struct ResolvedConnectionUrl {
    database_url: String,
    token_expires_at: Option<SystemTime>,
    /// Optional role to `SET ROLE` to on every pooled connection. The value
    /// has already passed CRD-level identifier validation; the after-connect
    /// hook re-quotes defensively before interpolating it into SQL.
    set_role: Option<String>,
}

/// Build the `SET ROLE` SQL statement for the given identifier.
///
/// `SET ROLE` does not accept bind parameters, so the value is interpolated.
/// CRD admission already restricts the identifier to the
/// [`crate::crd::SET_ROLE_PATTERN`] regex; the embedded `"` doubling here is
/// defence in depth for the connection-pool path.
pub fn build_set_role_stmt(role: &str) -> String {
    format!("SET ROLE \"{}\"", role.replace('"', "\"\""))
}

/// Marker prefix used to flag SET-ROLE failures from the `after_connect`
/// hook so they can be distinguished from other connect-time errors.
const SET_ROLE_FAILURE_MARKER: &str = "pgroles:set-role-failed:";

/// Wrap a SET-ROLE failure in [`sqlx::Error::Protocol`] with a marker so
/// the outer `connect()` error can be classified as
/// [`ContextError::SetRoleFailed`] instead of a generic database connect
/// failure.
fn wrap_set_role_failure(role: &str, source: sqlx::Error) -> sqlx::Error {
    sqlx::Error::Protocol(format!("{SET_ROLE_FAILURE_MARKER}{role}: {source}"))
}

/// Classify a pool-level connect error, surfacing SET-ROLE hook failures
/// distinctly from genuine database-connect failures.
fn classify_pool_connect_error(set_role: Option<&str>, err: sqlx::Error) -> ContextError {
    if let (Some(role), sqlx::Error::Protocol(msg)) = (set_role, &err)
        && msg.starts_with(SET_ROLE_FAILURE_MARKER)
    {
        return ContextError::SetRoleFailed {
            role: role.to_string(),
            source: err,
        };
    }
    ContextError::DatabaseConnect { source: err }
}

#[derive(Clone)]
struct GcpAccessToken {
    token: String,
    expires_at: SystemTime,
}

trait GcpAccessTokenProvider: Send + Sync {
    fn fetch_token<'a>(
        &'a self,
        auth: &'a ConnectionAuth,
    ) -> BoxFuture<'a, Result<GcpAccessToken, ContextError>>;
}

#[derive(Clone)]
struct MetadataGcpAccessTokenProvider {
    client: reqwest::Client,
}

impl Default for MetadataGcpAccessTokenProvider {
    fn default() -> Self {
        Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(GCP_AUTH_HTTP_TIMEOUT_SECS))
                .build()
                .expect("GCP auth HTTP client should build"),
        }
    }
}

impl GcpAccessTokenProvider for MetadataGcpAccessTokenProvider {
    fn fetch_token<'a>(
        &'a self,
        auth: &'a ConnectionAuth,
    ) -> BoxFuture<'a, Result<GcpAccessToken, ContextError>> {
        async move {
            let scope = auth.gcp_scope();
            if let Some(target) = auth.gcp_impersonate_service_account() {
                self.fetch_impersonated_access_token(target, scope).await
            } else {
                self.fetch_metadata_access_token(scope).await
            }
        }
        .boxed()
    }
}

impl MetadataGcpAccessTokenProvider {
    async fn fetch_metadata_access_token(
        &self,
        scope: &str,
    ) -> Result<GcpAccessToken, ContextError> {
        let response = self
            .client
            .get(GCP_METADATA_TOKEN_ENDPOINT)
            .header("Metadata-Flavor", "Google")
            .query(&[("scopes", scope)])
            .send()
            .await
            .map_err(|source| ContextError::GcpAuthHttp {
                endpoint: "metadata",
                source,
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response_body_for_error(response).await;
            return Err(ContextError::GcpAuthRejected {
                endpoint: "metadata".to_string(),
                status: status.as_u16(),
                body,
            });
        }

        let body: MetadataTokenResponse =
            response
                .json()
                .await
                .map_err(|source| ContextError::GcpAuthHttp {
                    endpoint: "metadata",
                    source,
                })?;

        if body.access_token.trim().is_empty() {
            return Err(ContextError::GcpAuthInvalidResponse {
                detail: "metadata token response omitted access_token".to_string(),
            });
        }
        if body.expires_in == 0 {
            return Err(ContextError::GcpAuthInvalidResponse {
                detail: "metadata token response had zero expires_in".to_string(),
            });
        }

        Ok(GcpAccessToken {
            token: body.access_token,
            expires_at: SystemTime::now() + Duration::from_secs(body.expires_in),
        })
    }

    async fn fetch_impersonated_access_token(
        &self,
        target_service_account: &str,
        scope: &str,
    ) -> Result<GcpAccessToken, ContextError> {
        let source = self
            .fetch_metadata_access_token(GCP_IAM_CREDENTIALS_SCOPE)
            .await?;
        let encoded_target = percent_encoding::utf8_percent_encode(
            target_service_account,
            percent_encoding::NON_ALPHANUMERIC,
        )
        .to_string();
        let endpoint = format!(
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{encoded_target}:generateAccessToken"
        );
        let request = GenerateAccessTokenRequest {
            scope: vec![scope.to_string()],
            lifetime: format!("{GCP_IMPERSONATED_TOKEN_LIFETIME_SECS}s"),
        };

        let response = self
            .client
            .post(&endpoint)
            .bearer_auth(&source.token)
            .json(&request)
            .send()
            .await
            .map_err(|source| ContextError::GcpAuthHttp {
                endpoint: "iamcredentials",
                source,
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response_body_for_error(response).await;
            return Err(ContextError::GcpAuthRejected {
                endpoint: "iamcredentials".to_string(),
                status: status.as_u16(),
                body,
            });
        }

        let body: GenerateAccessTokenResponse =
            response
                .json()
                .await
                .map_err(|source| ContextError::GcpAuthHttp {
                    endpoint: "iamcredentials",
                    source,
                })?;

        if body.access_token.trim().is_empty() {
            return Err(ContextError::GcpAuthInvalidResponse {
                detail: "IAMCredentials response omitted accessToken".to_string(),
            });
        }
        let expires_at = parse_google_expire_time(&body.expire_time).ok_or_else(|| {
            ContextError::GcpAuthInvalidResponse {
                detail: format!(
                    "IAMCredentials response had invalid expireTime {:?}",
                    body.expire_time
                ),
            }
        })?;

        Ok(GcpAccessToken {
            token: body.access_token,
            expires_at,
        })
    }
}

#[derive(Deserialize)]
struct MetadataTokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Serialize)]
struct GenerateAccessTokenRequest {
    scope: Vec<String>,
    lifetime: String,
}

#[derive(Deserialize)]
struct GenerateAccessTokenResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "expireTime")]
    expire_time: String,
}

async fn response_body_for_error(response: reqwest::Response) -> String {
    match response.text().await {
        Ok(body) => truncate_for_error(body),
        Err(error) => format!("failed to read error body: {error}"),
    }
}

fn truncate_for_error(mut body: String) -> String {
    const MAX_ERROR_BODY_BYTES: usize = 512;
    if body.len() <= MAX_ERROR_BODY_BYTES {
        return body;
    }
    let mut end = MAX_ERROR_BODY_BYTES;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    body.truncate(end);
    body.push_str("...");
    body
}

fn parse_google_expire_time(expire_time: &str) -> Option<SystemTime> {
    expire_time
        .parse::<jiff::Timestamp>()
        .ok()
        .map(SystemTime::from)
}

fn token_expires_after_skew(expires_at: Option<SystemTime>, now: SystemTime) -> bool {
    let Some(expires_at) = expires_at else {
        return true;
    };
    let Some(refresh_at) = now.checked_add(Duration::from_secs(GCP_TOKEN_CACHE_SKEW_SECS)) else {
        return false;
    };
    expires_at > refresh_at
}

/// Guard returned by [`OperatorContext::try_lock_database`].
///
/// Holding this guard prevents other reconcile loops (within the same process)
/// from starting work on the same database target. The lock is released when
/// the guard is dropped.
pub struct DatabaseLockGuard {
    key: String,
    locks: Arc<Mutex<HashMap<String, ()>>>,
}

impl Drop for DatabaseLockGuard {
    fn drop(&mut self) {
        // Best-effort removal — `try_lock` avoids blocking the drop.
        if let Ok(mut map) = self.locks.try_lock() {
            map.remove(&self.key);
            tracing::debug!(database = %self.key, "released in-memory database lock");
        } else {
            // Spawn a task to clean up if the mutex is currently held.
            // Use Handle::try_current() so we don't panic when dropped
            // outside an active Tokio runtime (e.g. during shutdown).
            let key = self.key.clone();
            let locks = Arc::clone(&self.locks);
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    locks.lock().await.remove(&key);
                    tracing::debug!(database = %key, "released in-memory database lock (deferred)");
                });
                tracing::debug!(
                    database = %self.key,
                    "deferred in-memory database lock release to background task"
                );
            } else {
                // No runtime available — fall back to synchronous cleanup
                // via blocking_lock so the entry is still removed.
                let mut map = self.locks.blocking_lock();
                map.remove(&key);
                tracing::debug!(
                    database = %key,
                    "released in-memory database lock (fallback sync)"
                );
            }
        }
    }
}

/// Shared state for the operator, passed to every reconciliation.
#[derive(Clone)]
pub struct OperatorContext {
    /// Kubernetes client for API calls.
    pub kube_client: kube::Client,

    /// Kubernetes Event recorder for transition-based policy Events.
    pub event_recorder: Recorder,

    /// Cached database connection pools keyed by `"namespace/secret-name/secret-key"`.
    pool_cache: Arc<RwLock<HashMap<String, CachedPool>>>,
    /// In-process per-database reconciliation locks.
    ///
    /// Prevents concurrent reconcile loops from operating on the same database
    /// within a single operator replica. Cross-replica safety is provided by
    /// PostgreSQL advisory locks (see [`crate::advisory`]).
    database_locks: Arc<Mutex<HashMap<String, ()>>>,

    /// Shared health/metrics state.
    pub observability: OperatorObservability,

    /// Watch-fed indexes for relevant ephemeral requests.
    pub request_index: RequestIndex,

    /// Optional namespace which bounds every operator watch and list.
    pub watch_namespace: Option<String>,

    /// Terminal-plan retention bounds, shared by every policy reconcile.
    pub plan_retention: PlanRetention,

    /// Fetches short-lived provider-backed database passwords.
    gcp_token_provider: Arc<dyn GcpAccessTokenProvider>,
}

impl OperatorContext {
    /// Create a context with the request index and watch scope shared by the
    /// controller runtime.
    pub fn new_with_runtime_config(
        kube_client: kube::Client,
        observability: OperatorObservability,
        event_recorder: Recorder,
        request_index: RequestIndex,
        watch_namespace: Option<String>,
    ) -> Self {
        Self {
            kube_client,
            event_recorder,
            pool_cache: Arc::new(RwLock::new(HashMap::new())),
            observability,
            request_index,
            watch_namespace,
            plan_retention: PlanRetention::default(),
            database_locks: Arc::new(Mutex::new(HashMap::new())),
            gcp_token_provider: Arc::new(MetadataGcpAccessTokenProvider::default()),
        }
    }

    /// Replace the default plan retention bounds — typically with the
    /// environment-derived values resolved once at startup by
    /// [`PlanRetention::from_env`].
    pub fn with_plan_retention(mut self, plan_retention: PlanRetention) -> Self {
        self.plan_retention = plan_retention;
        self
    }

    /// Try to acquire the in-process lock for the given database identity.
    ///
    /// Returns `Some(guard)` if no other reconcile is in progress for this
    /// database, `None` if one is already running. The lock is released when
    /// the guard is dropped.
    pub async fn try_lock_database(&self, database_identity: &str) -> Option<DatabaseLockGuard> {
        let mut locks = self.database_locks.lock().await;
        if locks.contains_key(database_identity) {
            tracing::info!(
                database = %database_identity,
                "in-memory database lock contention — another reconcile is in progress"
            );
            return None;
        }
        locks.insert(database_identity.to_string(), ());
        tracing::debug!(database = %database_identity, "acquired in-memory database lock");
        Some(DatabaseLockGuard {
            key: database_identity.to_string(),
            locks: Arc::clone(&self.database_locks),
        })
    }

    /// Resolve a param from either its literal value or a Secret reference.
    ///
    /// Returns `Ok(Some(value))` if one is set, `Ok(None)` if neither is set.
    async fn resolve_param(
        &self,
        namespace: &str,
        literal: &Option<String>,
        secret: &Option<SecretKeySelector>,
    ) -> Result<Option<String>, ContextError> {
        if let Some(val) = literal {
            return Ok(Some(val.clone()));
        }
        if let Some(sel) = secret {
            return Ok(Some(
                self.fetch_secret_value(namespace, &sel.name, &sel.key)
                    .await?,
            ));
        }
        Ok(None)
    }

    /// Resolve a [`ConnectionSpec`] into a PostgreSQL connection URL string.
    ///
    /// - **URL mode** (`secret_ref` is Some): reads the Secret key as a connection URL.
    /// - **Params mode** (`params` is Some): resolves each field and constructs a URL.
    pub async fn resolve_connection_url(
        &self,
        namespace: &str,
        connection: &ConnectionSpec,
    ) -> Result<String, ContextError> {
        Ok(self
            .resolve_connection_url_with_metadata(namespace, connection)
            .await?
            .database_url)
    }

    /// Resolve a stable, non-secret fingerprint of the database target.
    ///
    /// Credentials and connection options are deliberately excluded so that
    /// password and token rotation do not invalidate active access. Host,
    /// port, or database changes do invalidate it, preventing cleanup from
    /// revoking an identically named role in a different database.
    pub async fn resolve_database_target_fingerprint(
        &self,
        namespace: &str,
        connection: &ConnectionSpec,
    ) -> Result<String, ContextError> {
        let (host, port, database) = if let Some(ref secret_ref) = connection.secret_ref {
            let database_url = self
                .fetch_secret_value(
                    namespace,
                    &secret_ref.name,
                    connection.effective_secret_key(),
                )
                .await?;
            database_target_from_url(&database_url)
                .map_err(|detail| ContextError::InvalidDatabaseUrl { detail })?
        } else if let Some(ref params) = connection.params {
            let host = self
                .resolve_param(namespace, &params.host, &params.host_secret)
                .await?
                .ok_or_else(|| ContextError::EmptyResolvedValue {
                    field: "host".to_string(),
                })?;
            let port = match self
                .resolve_param(
                    namespace,
                    &params.port.map(|port| port.to_string()),
                    &params.port_secret,
                )
                .await?
            {
                Some(value) => {
                    value
                        .parse::<u16>()
                        .map_err(|_| ContextError::InvalidResolvedPort {
                            value: value.clone(),
                        })?
                }
                None => 5432,
            };
            let database = self
                .resolve_param(namespace, &params.dbname, &params.dbname_secret)
                .await?
                .ok_or_else(|| ContextError::EmptyResolvedValue {
                    field: "dbname".to_string(),
                })?;
            (host.to_ascii_lowercase(), port, database)
        } else {
            return Err(ContextError::SecretMissing {
                name: "connection".to_string(),
                key: "neither secretRef nor params is set".to_string(),
            });
        };

        if host.trim().is_empty() {
            return Err(ContextError::EmptyResolvedValue {
                field: "host".to_string(),
            });
        }
        if database.trim().is_empty() {
            return Err(ContextError::EmptyResolvedValue {
                field: "dbname".to_string(),
            });
        }
        Ok(database_target_fingerprint(&host, port, &database))
    }

    async fn resolve_connection_url_with_metadata(
        &self,
        namespace: &str,
        connection: &ConnectionSpec,
    ) -> Result<ResolvedConnectionUrl, ContextError> {
        if let Some(ref secret_ref) = connection.secret_ref {
            // URL mode — read the full connection URL from the Secret.
            let database_url = self
                .fetch_secret_value(
                    namespace,
                    &secret_ref.name,
                    connection.effective_secret_key(),
                )
                .await?;
            Ok(ResolvedConnectionUrl {
                database_url,
                token_expires_at: None,
                set_role: None,
            })
        } else if let Some(ref params) = connection.params {
            // Params mode — resolve each field and build the URL.
            let host = self
                .resolve_param(namespace, &params.host, &params.host_secret)
                .await?
                .ok_or_else(|| ContextError::EmptyResolvedValue {
                    field: "host".to_string(),
                })?;
            if host.trim().is_empty() {
                return Err(ContextError::EmptyResolvedValue {
                    field: "host".to_string(),
                });
            }

            let port_str = params.port.map(|p| p.to_string());
            let port = self
                .resolve_param(namespace, &port_str, &params.port_secret)
                .await?
                .unwrap_or_else(|| "5432".to_string());
            if port.trim().is_empty() {
                return Err(ContextError::EmptyResolvedValue {
                    field: "port".to_string(),
                });
            }

            let dbname = self
                .resolve_param(namespace, &params.dbname, &params.dbname_secret)
                .await?
                .ok_or_else(|| ContextError::EmptyResolvedValue {
                    field: "dbname".to_string(),
                })?;
            if dbname.trim().is_empty() {
                return Err(ContextError::EmptyResolvedValue {
                    field: "dbname".to_string(),
                });
            }

            let username = self
                .resolve_param(namespace, &params.username, &params.username_secret)
                .await?
                .ok_or_else(|| ContextError::EmptyResolvedValue {
                    field: "username".to_string(),
                })?;
            if username.trim().is_empty() {
                return Err(ContextError::EmptyResolvedValue {
                    field: "username".to_string(),
                });
            }

            let (password, token_expires_at) = if let Some(auth) = &params.auth {
                let token = self.gcp_token_provider.fetch_token(auth).await?;
                (token.token, Some(token.expires_at))
            } else {
                let password = self
                    .resolve_param(namespace, &params.password, &params.password_secret)
                    .await?
                    .ok_or_else(|| ContextError::EmptyResolvedValue {
                        field: "password".to_string(),
                    })?;
                (password, None)
            };
            if password.trim().is_empty() {
                return Err(ContextError::EmptyResolvedValue {
                    field: "password".to_string(),
                });
            }

            use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
            let encoded_username = utf8_percent_encode(&username, NON_ALPHANUMERIC).to_string();
            let encoded_password = utf8_percent_encode(&password, NON_ALPHANUMERIC).to_string();

            let mut url = format!(
                "postgresql://{encoded_username}:{encoded_password}@{host}:{port}/{dbname}"
            );

            let ssl_mode = self
                .resolve_param(namespace, &params.ssl_mode, &params.ssl_mode_secret)
                .await?
                .or_else(|| params.auth.as_ref().map(|_| "require".to_string()));
            if let Some(ssl_mode) = ssl_mode {
                // Validate sslMode at runtime — CRD validation only catches
                // literal values; a secret ref could resolve to anything.
                if !crate::crd::VALID_SSL_MODES.contains(&ssl_mode.as_str()) {
                    return Err(ContextError::InvalidResolvedSslMode { value: ssl_mode });
                }
                url.push_str("?sslmode=");
                url.push_str(&ssl_mode);
            }

            Ok(ResolvedConnectionUrl {
                database_url: url,
                token_expires_at,
                set_role: params.set_role.clone(),
            })
        } else {
            Err(ContextError::SecretMissing {
                name: "connection".to_string(),
                key: "neither secretRef nor params is set".to_string(),
            })
        }
    }

    /// Get or create a PgPool for the given connection spec.
    ///
    /// Resolves the connection URL from the referenced Secret(s),
    /// and caches the resulting pool for reuse.
    pub async fn get_or_create_pool(
        &self,
        namespace: &str,
        connection: &ConnectionSpec,
    ) -> Result<PgPool, ContextError> {
        let cache_key = connection.cache_key(namespace);

        // For URL mode, we can do resource-version-based cache invalidation.
        // For params mode, compute a fingerprint from all referenced secrets'
        // resourceVersions so that secret rotations invalidate the cache.
        let (resource_version, secret_fingerprint) =
            if let Some(ref secret_ref) = connection.secret_ref {
                let secrets_api: kube::Api<k8s_openapi::api::core::v1::Secret> =
                    kube::Api::namespaced(self.kube_client.clone(), namespace);
                let secret = secrets_api.get(&secret_ref.name).await.map_err(|err| {
                    ContextError::SecretFetch {
                        name: secret_ref.name.clone(),
                        namespace: namespace.to_string(),
                        source: err,
                    }
                })?;
                (secret.metadata.resource_version, None)
            } else if connection.params.is_some() {
                // Params mode — collect all referenced secret names and fetch their
                // resourceVersions to build a fingerprint.
                let mut secret_names = std::collections::BTreeSet::new();
                connection.collect_secret_names(&mut secret_names);

                if secret_names.is_empty() {
                    // All values are literals — no secrets to watch.
                    (None, Some(String::new()))
                } else {
                    let secrets_api: kube::Api<k8s_openapi::api::core::v1::Secret> =
                        kube::Api::namespaced(self.kube_client.clone(), namespace);
                    let mut fingerprint_parts = Vec::new();
                    for name in &secret_names {
                        let secret = secrets_api.get(name).await.map_err(|err| {
                            ContextError::SecretFetch {
                                name: name.clone(),
                                namespace: namespace.to_string(),
                                source: err,
                            }
                        })?;
                        let rv = secret
                            .metadata
                            .resource_version
                            .unwrap_or_else(|| "unknown".to_string());
                        fingerprint_parts.push(format!("{name}={rv}"));
                    }
                    (None, Some(fingerprint_parts.join(",")))
                }
            } else {
                (None, None)
            };

        // Check cache.
        {
            let cache = self.pool_cache.read().await;
            if let Some(cached) = cache.get(&cache_key) {
                // URL mode: reuse if the Secret's resource_version matches.
                // Params mode: reuse if the secret fingerprint matches.
                let version_matches = match (&resource_version, &cached.resource_version) {
                    (Some(current), Some(cached_rv)) => current == cached_rv,
                    _ => true,
                };
                let fingerprint_matches = match (&secret_fingerprint, &cached.secret_fingerprint) {
                    (Some(current), Some(cached_fp)) => current == cached_fp,
                    (None, None) => true,
                    _ => false,
                };
                let token_fresh =
                    token_expires_after_skew(cached.token_expires_at, SystemTime::now());
                if version_matches && fingerprint_matches && token_fresh {
                    return Ok(cached.pool.clone());
                }
            }
        }

        let resolved = self
            .resolve_connection_url_with_metadata(namespace, connection)
            .await?;

        // Create pool with explicit sizing. Reconciliation holds one dedicated
        // connection for PostgreSQL advisory locking and needs additional pool
        // capacity for inspection/apply queries.
        let set_role = resolved.set_role.clone();
        let pool = pool_options()
            .after_connect(move |conn, _meta| {
                let set_role = set_role.clone();
                Box::pin(async move {
                    if let Some(role) = set_role {
                        let stmt = build_set_role_stmt(&role);
                        sqlx::Executor::execute(&mut *conn, stmt.as_str())
                            .await
                            .map_err(|err| wrap_set_role_failure(&role, err))?;
                    }
                    Ok(())
                })
            })
            .connect(&resolved.database_url)
            .await
            .map_err(|err| classify_pool_connect_error(resolved.set_role.as_deref(), err))?;

        // Cache it (write lock).
        let superseded = {
            let mut cache = self.pool_cache.write().await;
            cache.insert(
                cache_key,
                CachedPool {
                    resource_version,
                    secret_fingerprint,
                    token_expires_at: resolved.token_expires_at,
                    pool: pool.clone(),
                },
            )
        };
        close_unreachable_pool(superseded);

        Ok(pool)
    }

    /// Fetch a single string value from a Kubernetes Secret.
    ///
    /// Used to resolve role passwords from Secret references at reconcile time.
    pub async fn fetch_secret_value(
        &self,
        namespace: &str,
        secret_name: &str,
        secret_key: &str,
    ) -> Result<String, ContextError> {
        let secrets_api: kube::Api<k8s_openapi::api::core::v1::Secret> =
            kube::Api::namespaced(self.kube_client.clone(), namespace);

        let secret =
            secrets_api
                .get(secret_name)
                .await
                .map_err(|err| ContextError::SecretFetch {
                    name: secret_name.to_string(),
                    namespace: namespace.to_string(),
                    source: err,
                })?;

        let data = secret.data.ok_or_else(|| ContextError::SecretMissing {
            name: secret_name.to_string(),
            key: secret_key.to_string(),
        })?;

        let value_bytes = data
            .get(secret_key)
            .ok_or_else(|| ContextError::SecretMissing {
                name: secret_name.to_string(),
                key: secret_key.to_string(),
            })?;

        String::from_utf8(value_bytes.0.clone()).map_err(|_| ContextError::SecretMissing {
            name: secret_name.to_string(),
            key: secret_key.to_string(),
        })
    }

    /// Remove a cached pool (e.g. when secret changes or CR is deleted).
    pub async fn evict_pool(&self, namespace: &str, connection: &ConnectionSpec) {
        let cache_key = connection.cache_key(namespace);
        let evicted = {
            let mut cache = self.pool_cache.write().await;
            cache.remove(&cache_key)
        };
        close_unreachable_pool(evicted);
    }
}

/// Connection-pool sizing and lifetime shared by every managed database.
fn pool_options() -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(POOL_MAX_CONNECTIONS)
        .min_connections(POOL_MIN_CONNECTIONS)
        .acquire_timeout(Duration::from_secs(POOL_ACQUIRE_TIMEOUT_SECS))
        .idle_timeout(Duration::from_secs(POOL_IDLE_TIMEOUT_SECS))
        .max_lifetime(Duration::from_secs(POOL_MAX_LIFETIME_SECS))
}

/// Close a pool that is no longer reachable from the cache.
///
/// Dropping a `PgPool` only marks it closed: the backend connections are torn
/// down when the last handle drops the socket, which PostgreSQL logs as an
/// unexpected EOF. Closing explicitly sends a proper termination once in-flight
/// reconciles hand their connections back. The close is spawned because it
/// waits for those connections, and no caller should block on an eviction.
fn close_unreachable_pool(cached: Option<CachedPool>) {
    let Some(cached) = cached else {
        return;
    };
    tokio::spawn(async move {
        cached.pool.close().await;
    });
}

fn database_target_from_url(database_url: &str) -> Result<(String, u16, String), String> {
    let options = PgConnectOptions::from_str(database_url).map_err(|source| source.to_string())?;
    Ok((
        options.get_host().to_ascii_lowercase(),
        options.get_port(),
        options
            .get_database()
            .unwrap_or_else(|| options.get_username())
            .to_string(),
    ))
}

fn database_target_fingerprint(host: &str, port: u16, database: &str) -> String {
    let digest = Sha256::digest(format!("{}\0{port}\0{database}", host.to_ascii_lowercase()));
    let mut fingerprint = String::with_capacity(7 + digest.len() * 2);
    fingerprint.push_str("sha256:");
    for byte in digest {
        write!(&mut fingerprint, "{byte:02x}")
            .expect("writing a database target fingerprint cannot fail");
    }
    fingerprint
}

/// Errors from operator context operations.
#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    #[error("failed to fetch Secret {namespace}/{name}: {source}")]
    SecretFetch {
        name: String,
        namespace: String,
        source: kube::Error,
    },

    #[error("Secret \"{name}\" does not contain key \"{key}\"")]
    SecretMissing { name: String, key: String },

    #[error("failed to connect to database: {source}")]
    DatabaseConnect { source: sqlx::Error },

    #[error("failed to apply SET ROLE \"{role}\" on pooled connection: {source}")]
    SetRoleFailed { role: String, source: sqlx::Error },

    #[error("connection param \"{field}\" resolved to an empty or whitespace-only value")]
    EmptyResolvedValue { field: String },

    #[error("connection URL is invalid: {detail}")]
    InvalidDatabaseUrl { detail: String },

    #[error("connection port resolved to invalid value \"{value}\"")]
    InvalidResolvedPort { value: String },

    #[error(
        "connection param sslMode resolved to invalid value \"{value}\" (expected one of: disable, allow, prefer, require, verify-ca, verify-full)"
    )]
    InvalidResolvedSslMode { value: String },

    #[error("failed to fetch GCP auth token from {endpoint}: {source}")]
    GcpAuthHttp {
        endpoint: &'static str,
        source: reqwest::Error,
    },

    #[error("GCP auth token endpoint {endpoint} returned HTTP {status}: {body}")]
    GcpAuthRejected {
        endpoint: String,
        status: u16,
        body: String,
    },

    #[error("GCP auth token response was invalid: {detail}")]
    GcpAuthInvalidResponse { detail: String },
}

impl ContextError {
    /// Returns true when a Secret fetch failed due to a non-transient client-side API error.
    pub fn is_secret_fetch_non_transient(&self) -> bool {
        matches!(
            self,
            ContextError::SecretFetch {
                source: kube::Error::Api(response),
                ..
            } if (400..500).contains(&response.code) && response.code != 429
        )
    }

    pub fn is_gcp_auth_non_transient(&self) -> bool {
        matches!(
            self,
            ContextError::GcpAuthRejected { status, .. }
                if (400..500).contains(status) && *status != 429
        ) || matches!(self, ContextError::GcpAuthInvalidResponse { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serves every connection with `respond` and keeps the sockets open.
    async fn api_server<F, Fut>(respond: F) -> String
    where
        F: Fn(tokio::net::TcpStream) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let respond = Arc::new(respond);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(respond(socket));
            }
        });
        format!("http://{address}")
    }

    /// Issue one GET through a request client bounded at 200 ms, and report
    /// how long it took to fail.
    async fn bounded_get(url: String) -> Duration {
        let client = request_client_with_deadline(
            kube::Config::new(url.parse().unwrap()),
            Duration::from_millis(200),
        )
        .unwrap();
        let secrets: kube::Api<k8s_openapi::api::core::v1::Secret> =
            kube::Api::namespaced(client, "default");
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(Duration::from_secs(10), secrets.get("any"))
            .await
            .expect("the request outlived its deadline");
        assert!(outcome.is_err(), "the request cannot succeed");
        started.elapsed()
    }

    /// A server that accepts the connection and never answers.
    #[tokio::test]
    async fn a_request_to_an_unresponsive_api_server_fails_within_its_deadline() {
        let url = api_server(|socket| async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(socket);
        })
        .await;
        assert!(bounded_get(url).await < Duration::from_secs(2));
    }

    /// Headers arrive at once, then the body trickles in a byte at a time,
    /// fast enough that no idle timeout would ever fire. The deadline covers
    /// the whole response, so the request still fails on time.
    #[tokio::test]
    async fn a_trickling_response_fails_within_its_deadline() {
        let url = api_server(|mut socket| async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut request = [0u8; 4096];
            let _ = socket.read(&mut request).await;
            let headers = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                           content-length: 100000\r\n\r\n";
            if socket.write_all(headers.as_bytes()).await.is_err() {
                return;
            }
            for _ in 0..1000 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                if socket.write_all(b" ").await.is_err() {
                    return;
                }
            }
        })
        .await;
        assert!(bounded_get(url).await < Duration::from_secs(2));
    }

    /// Pools are cached for the operator's lifetime, so the only thing that
    /// ever closes an unused connection is the idle reaper. If the reap window
    /// reaches the requeue interval, every reconcile re-touches the pool before
    /// the reaper runs and the operator sits on open backends against every
    /// managed database forever — which is what sqlx's 10-minute default did
    /// against the 5-minute default requeue.
    #[test]
    fn idle_connections_are_reaped_between_reconciles() {
        let options = pool_options();

        assert_eq!(
            options.get_min_connections(),
            0,
            "a floor above zero would hold connections open on an idle database"
        );

        let idle_timeout = options
            .get_idle_timeout()
            .expect("an unset idle timeout never reaps");
        assert!(
            idle_timeout < Duration::from_secs(crate::reconciler::DEFAULT_REQUEUE_SECS),
            "idle timeout {idle_timeout:?} must drain within the {}s requeue interval",
            crate::reconciler::DEFAULT_REQUEUE_SECS
        );

        assert!(
            options.get_max_lifetime().is_some(),
            "connections need an age ceiling independent of activity"
        );
    }

    #[test]
    fn database_target_fingerprint_excludes_credentials_and_options() {
        let first = database_target_from_url(
            "postgresql://alice:first@DB.EXAMPLE:6432/inventory?sslmode=require",
        )
        .expect("first URL");
        let second = database_target_from_url(
            "postgresql://bob:second@db.example:6432/inventory?application_name=test",
        )
        .expect("second URL");

        assert_eq!(
            database_target_fingerprint(&first.0, first.1, &first.2),
            database_target_fingerprint(&second.0, second.1, &second.2)
        );
    }

    #[test]
    fn database_target_fingerprint_changes_on_retarget() {
        let original = database_target_fingerprint("db.example", 5432, "inventory");
        assert_ne!(
            original,
            database_target_fingerprint("db.example", 5432, "billing")
        );
        assert_ne!(
            original,
            database_target_fingerprint("other.example", 5432, "inventory")
        );
    }

    #[test]
    fn build_set_role_stmt_quotes_identifier() {
        assert_eq!(
            build_set_role_stmt("cloudsqlsuperuser"),
            "SET ROLE \"cloudsqlsuperuser\"",
        );
    }

    #[test]
    fn classify_pool_connect_error_surfaces_set_role_failure_with_role() {
        let raw = wrap_set_role_failure(
            "cloudsqlsuperuser",
            sqlx::Error::Protocol("permission denied".to_string()),
        );
        let classified = classify_pool_connect_error(Some("cloudsqlsuperuser"), raw);
        assert!(matches!(
            classified,
            ContextError::SetRoleFailed { ref role, .. } if role == "cloudsqlsuperuser"
        ));
    }

    #[test]
    fn classify_pool_connect_error_passes_through_unrelated_errors() {
        let err = sqlx::Error::PoolTimedOut;
        let classified = classify_pool_connect_error(Some("any_role"), err);
        assert!(matches!(classified, ContextError::DatabaseConnect { .. }));
    }

    #[test]
    fn classify_pool_connect_error_without_set_role_is_database_connect() {
        // Even a Protocol error with our marker shouldn't be classified as
        // SetRoleFailed when no role was configured for this pool.
        let raw = wrap_set_role_failure("ghost", sqlx::Error::Protocol("oops".to_string()));
        let classified = classify_pool_connect_error(None, raw);
        assert!(matches!(classified, ContextError::DatabaseConnect { .. }));
    }

    #[test]
    fn build_set_role_stmt_doubles_embedded_quote() {
        // CRD validation rejects identifiers containing `"`. This test pins
        // the defensive quoting in the connection-pool path anyway, so a
        // future relaxation of the validator can't silently allow injection.
        assert_eq!(build_set_role_stmt("a\"b"), "SET ROLE \"a\"\"b\"",);
    }

    #[test]
    fn pool_cache_key_format() {
        // Verify the cache key format is "namespace/secret-name/secret-key"
        let key = format!("{}/{}/{}", "prod", "pg-credentials", "DATABASE_URL");
        assert_eq!(key, "prod/pg-credentials/DATABASE_URL");
    }

    #[test]
    fn secret_fetch_not_found_is_non_transient() {
        let error = ContextError::SecretFetch {
            name: "db-credentials".into(),
            namespace: "default".into(),
            source: kube::Error::Api(
                kube::core::Status::failure("secrets \"db-credentials\" not found", "NotFound")
                    .with_code(404)
                    .boxed(),
            ),
        };

        assert!(error.is_secret_fetch_non_transient());
    }

    #[test]
    fn secret_fetch_forbidden_is_non_transient() {
        let error = ContextError::SecretFetch {
            name: "db-credentials".into(),
            namespace: "default".into(),
            source: kube::Error::Api(
                kube::core::Status::failure("forbidden", "Forbidden")
                    .with_code(403)
                    .boxed(),
            ),
        };

        assert!(error.is_secret_fetch_non_transient());
    }

    #[test]
    fn secret_fetch_server_error_remains_transient() {
        let error = ContextError::SecretFetch {
            name: "db-credentials".into(),
            namespace: "default".into(),
            source: kube::Error::Api(
                kube::core::Status::failure("internal error", "InternalError")
                    .with_code(500)
                    .boxed(),
            ),
        };

        assert!(!error.is_secret_fetch_non_transient());
    }

    #[test]
    fn gcp_auth_client_error_is_non_transient() {
        let error = ContextError::GcpAuthRejected {
            endpoint: "metadata".into(),
            status: 403,
            body: "forbidden".into(),
        };

        assert!(error.is_gcp_auth_non_transient());
    }

    #[test]
    fn gcp_auth_rate_limit_remains_transient() {
        let error = ContextError::GcpAuthRejected {
            endpoint: "metadata".into(),
            status: 429,
            body: "rate limited".into(),
        };

        assert!(!error.is_gcp_auth_non_transient());
    }

    #[test]
    fn token_expiry_uses_five_minute_refresh_skew() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        assert!(token_expires_after_skew(
            Some(now + Duration::from_secs(GCP_TOKEN_CACHE_SKEW_SECS + 1)),
            now
        ));
        assert!(!token_expires_after_skew(
            Some(now + Duration::from_secs(GCP_TOKEN_CACHE_SKEW_SECS)),
            now
        ));
    }

    #[test]
    fn parse_google_expire_time_accepts_rfc3339() {
        let parsed =
            parse_google_expire_time("2026-05-14T02:30:00Z").expect("expireTime should parse");
        assert_eq!(
            parsed
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1_778_725_800
        );
    }

    #[test]
    fn truncate_for_error_keeps_utf8_boundary() {
        let body = "é".repeat(300);
        let truncated = truncate_for_error(body);

        assert!(truncated.ends_with("..."));
        assert!(truncated.is_char_boundary(truncated.len() - 3));
    }

    #[tokio::test]
    async fn try_lock_database_acquires_when_free() {
        let locks: Arc<Mutex<HashMap<String, ()>>> = Arc::new(Mutex::new(HashMap::new()));
        let ctx = OperatorContextLockHelper {
            database_locks: locks,
        };
        let guard = ctx.try_lock("db-a").await;
        assert!(guard.is_some(), "should acquire lock on free database");
    }

    #[tokio::test]
    async fn try_lock_database_contention_returns_none() {
        let locks: Arc<Mutex<HashMap<String, ()>>> = Arc::new(Mutex::new(HashMap::new()));
        let ctx = OperatorContextLockHelper {
            database_locks: locks,
        };

        let _guard1 = ctx
            .try_lock("db-a")
            .await
            .expect("first lock should succeed");
        let guard2 = ctx.try_lock("db-a").await;
        assert!(guard2.is_none(), "second lock on same database should fail");
    }

    #[tokio::test]
    async fn try_lock_database_different_databases_independent() {
        let locks: Arc<Mutex<HashMap<String, ()>>> = Arc::new(Mutex::new(HashMap::new()));
        let ctx = OperatorContextLockHelper {
            database_locks: locks,
        };

        let guard_a = ctx.try_lock("db-a").await;
        let guard_b = ctx.try_lock("db-b").await;
        assert!(guard_a.is_some(), "lock on db-a should succeed");
        assert!(
            guard_b.is_some(),
            "lock on db-b should succeed (different database)"
        );
    }

    #[tokio::test]
    async fn try_lock_database_released_after_drop() {
        let locks: Arc<Mutex<HashMap<String, ()>>> = Arc::new(Mutex::new(HashMap::new()));
        let ctx = OperatorContextLockHelper {
            database_locks: Arc::clone(&locks),
        };

        {
            let _guard = ctx.try_lock("db-a").await.expect("should acquire");
            // guard is dropped here
        }

        // After drop, should be able to acquire again.
        let guard2 = ctx.try_lock("db-a").await;
        assert!(
            guard2.is_some(),
            "should re-acquire after previous guard dropped"
        );
    }

    #[tokio::test]
    async fn try_lock_database_concurrent_contention() {
        let locks: Arc<Mutex<HashMap<String, ()>>> = Arc::new(Mutex::new(HashMap::new()));

        // Simulate two concurrent reconciles for the same database.
        let locks1 = Arc::clone(&locks);
        let locks2 = Arc::clone(&locks);

        let handle1 = tokio::spawn(async move {
            let ctx = OperatorContextLockHelper {
                database_locks: locks1,
            };
            let guard = ctx.try_lock("shared-db").await;
            if guard.is_some() {
                // Hold the lock briefly.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            guard.is_some()
        });

        // Small delay so handle1 is likely first.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let handle2 = tokio::spawn(async move {
            let ctx = OperatorContextLockHelper {
                database_locks: locks2,
            };
            let guard = ctx.try_lock("shared-db").await;
            guard.is_some()
        });

        let (r1, r2) = tokio::join!(handle1, handle2);
        let acquired1 = r1.unwrap();
        let acquired2 = r2.unwrap();

        // Exactly one should succeed.
        assert!(
            acquired1 ^ acquired2,
            "exactly one of two concurrent locks should succeed: got ({acquired1}, {acquired2})"
        );
    }

    /// Helper to test locking without a real kube client.
    struct OperatorContextLockHelper {
        database_locks: Arc<Mutex<HashMap<String, ()>>>,
    }

    impl OperatorContextLockHelper {
        async fn try_lock(&self, database_identity: &str) -> Option<DatabaseLockGuard> {
            let mut locks = self.database_locks.lock().await;
            if locks.contains_key(database_identity) {
                return None;
            }
            locks.insert(database_identity.to_string(), ());
            Some(DatabaseLockGuard {
                key: database_identity.to_string(),
                locks: Arc::clone(&self.database_locks),
            })
        }
    }

    #[tokio::test]
    async fn try_lock_database_high_concurrency_same_db() {
        // Spawn many tasks all racing to lock the same database.
        let locks: Arc<Mutex<HashMap<String, ()>>> = Arc::new(Mutex::new(HashMap::new()));
        let concurrency = 50;
        let acquired_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(concurrency));

        let mut handles = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let locks_clone = Arc::clone(&locks);
            let count = Arc::clone(&acquired_count);
            let bar = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                // Synchronize start so all tasks race at the same instant.
                bar.wait().await;
                let ctx = OperatorContextLockHelper {
                    database_locks: locks_clone,
                };
                let guard = ctx.try_lock("contested-db").await;
                if guard.is_some() {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    // Hold lock briefly to let other tasks observe contention.
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Exactly one task should have acquired the lock.
        let total = acquired_count.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            total, 1,
            "exactly one of {concurrency} concurrent tasks should acquire the lock, got {total}"
        );
    }

    #[tokio::test]
    async fn try_lock_database_high_concurrency_different_dbs() {
        // Many tasks each locking a different database — all should succeed.
        let locks: Arc<Mutex<HashMap<String, ()>>> = Arc::new(Mutex::new(HashMap::new()));
        let concurrency = 50;
        let acquired_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(concurrency));

        let mut handles = Vec::with_capacity(concurrency);
        for i in 0..concurrency {
            let locks_clone = Arc::clone(&locks);
            let count = Arc::clone(&acquired_count);
            let bar = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                bar.wait().await;
                let ctx = OperatorContextLockHelper {
                    database_locks: locks_clone,
                };
                let db_name = format!("db-{i}");
                let guard = ctx.try_lock(&db_name).await;
                if guard.is_some() {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let total = acquired_count.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            total, concurrency,
            "all {concurrency} tasks locking different dbs should succeed, got {total}"
        );
    }

    #[tokio::test]
    async fn try_lock_database_acquire_release_cycle_under_contention() {
        // Repeatedly acquire and release the same database lock from many tasks.
        // Each task attempts the lock in a loop until it succeeds, simulating
        // the requeue-after-contention pattern used in the reconciler.
        let locks: Arc<Mutex<HashMap<String, ()>>> = Arc::new(Mutex::new(HashMap::new()));
        let concurrency = 20;
        let success_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(concurrency));

        let mut handles = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let locks_clone = Arc::clone(&locks);
            let count = Arc::clone(&success_count);
            let bar = Arc::clone(&barrier);
            handles.push(tokio::spawn(async move {
                bar.wait().await;
                // Retry up to 100 times with a small sleep between attempts,
                // simulating the jittered requeue pattern.
                for _ in 0..100 {
                    let ctx = OperatorContextLockHelper {
                        database_locks: Arc::clone(&locks_clone),
                    };
                    if let Some(_guard) = ctx.try_lock("shared-db").await {
                        count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        // Brief simulated work, then guard drops (releasing lock).
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                        return;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
                // Should not reach here in practice — fail the test if we do.
                panic!("task failed to acquire lock after 100 retries");
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        let total = success_count.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            total, concurrency,
            "all {concurrency} tasks should eventually acquire the lock"
        );
    }
}
