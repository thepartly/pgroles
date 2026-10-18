//! Microsoft Entra tokens for Azure Database for PostgreSQL Flexible Server.
//! The projected AKS service account token is exchanged for a database token;
//! neither token is persisted in a Kubernetes Secret or PostgreSQL URL config.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::auth::{AccessToken, truncate_for_error};
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use thiserror::Error;

pub const POSTGRES_SCOPE: &str = "https://ossrdbms-aad.database.windows.net/.default";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

#[derive(Debug, Error)]
pub enum AzureAuthError {
    #[error("missing Azure Workload Identity environment variable {0}")]
    MissingEnvironment(&'static str),
    #[error("invalid Azure authority host (expected an HTTPS origin)")]
    InvalidAuthority,
    #[error("Azure Workload Identity requires a PostgreSQL URL without a password")]
    InvalidConnection,
    #[error("projected Azure federated token is empty")]
    EmptyAssertion,
    #[error("invalid PostgreSQL connection URL: {0}")]
    Connection(#[from] sqlx::Error),
    #[error("invalid Azure tenant ID")]
    InvalidTenant,
    #[error("failed to read projected Azure federated token: {0}")]
    ReadAssertion(#[from] std::io::Error),
    #[error("Azure token request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Azure token endpoint returned HTTP {status}: {body}")]
    Rejected { status: u16, body: String },
    #[error("Azure token response has no usable access token or expiry")]
    InvalidResponse,
}

impl AzureAuthError {
    /// Configuration errors need a policy change or a repaired token mount.
    pub fn is_non_transient(&self) -> bool {
        match self {
            Self::MissingEnvironment(_)
            | Self::InvalidTenant
            | Self::InvalidResponse
            | Self::InvalidAuthority
            | Self::InvalidConnection
            | Self::EmptyAssertion
            | Self::Connection(_) => true,
            Self::ReadAssertion(error) => error.kind() == std::io::ErrorKind::NotFound,
            Self::Rejected { status, .. } => (400..500).contains(status) && *status != 429,
            Self::Request(_) => false,
        }
    }
}

fn truncate_error_body(body: String, assertion: &str) -> String {
    truncate_for_error(body.replace(assertion, "[redacted]"))
}

/// Process-scoped configuration. The projected assertion itself is read on each fetch.
#[derive(Clone, Debug)]
pub struct WorkloadIdentityConfig {
    tenant_id: String,
    client_id: String,
    token_file: PathBuf,
    authority: reqwest::Url,
}

impl WorkloadIdentityConfig {
    pub fn from_env() -> Result<Self, AzureAuthError> {
        Self::from_values(
            &required_env("AZURE_TENANT_ID")?,
            &required_env("AZURE_CLIENT_ID")?,
            required_env("AZURE_FEDERATED_TOKEN_FILE")?.into(),
            &std::env::var("AZURE_AUTHORITY_HOST")
                .unwrap_or_else(|_| "https://login.microsoftonline.com".into()),
        )
    }

    fn from_values(
        tenant: &str,
        client: &str,
        token_file: PathBuf,
        authority: &str,
    ) -> Result<Self, AzureAuthError> {
        if tenant.is_empty()
            || !tenant
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        {
            return Err(AzureAuthError::InvalidTenant);
        }
        if client.trim().is_empty() {
            return Err(AzureAuthError::MissingEnvironment("AZURE_CLIENT_ID"));
        }
        let authority =
            reqwest::Url::parse(authority).map_err(|_| AzureAuthError::InvalidAuthority)?;
        if authority.scheme() != "https"
            || authority.host_str().is_none()
            || !authority.username().is_empty()
            || authority.password().is_some()
            || authority.path() != "/"
            || authority.query().is_some()
            || authority.fragment().is_some()
        {
            return Err(AzureAuthError::InvalidAuthority);
        }
        Ok(Self {
            tenant_id: tenant.into(),
            client_id: client.into(),
            token_file,
            authority,
        })
    }
}

fn required_env(name: &'static str) -> Result<String, AzureAuthError> {
    std::env::var(name)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or(AzureAuthError::MissingEnvironment(name))
}

/// Reuses the HTTP client and configuration across exchanges, while re-reading the assertion.
#[derive(Clone)]
pub struct AzureTokenSource {
    config: WorkloadIdentityConfig,
    endpoint: reqwest::Url,
    client: reqwest::Client,
}

impl AzureTokenSource {
    pub fn new(config: WorkloadIdentityConfig) -> Self {
        let mut endpoint = config.authority.clone();
        endpoint.set_path(&format!("/{}/oauth2/v2.0/token", config.tenant_id));
        Self {
            config,
            endpoint,
            client: reqwest::Client::new(),
        }
    }

    pub async fn fetch(&self) -> Result<AccessToken, AzureAuthError> {
        fetch_token(
            &self.client,
            self.endpoint.as_str(),
            &self.config.client_id,
            &self.config.token_file,
        )
        .await
    }
}

/// Validate the passwordless connection and default to certificate/hostname verification.
/// Token acquisition is separate so invalid connection settings fail before an exchange.
pub fn connection_options(url: &str) -> Result<PgConnectOptions, AzureAuthError> {
    let parsed = reqwest::Url::parse(url).map_err(|_| AzureAuthError::InvalidConnection)?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.password().is_some()
        || parsed.query_pairs().any(|(key, _)| key == "password")
    {
        return Err(AzureAuthError::InvalidConnection);
    }
    let mut options = PgConnectOptions::from_str(url)?;
    if !parsed.query_pairs().any(|(key, _)| key == "sslmode") {
        options = options.ssl_mode(PgSslMode::VerifyFull);
    }
    Ok(options)
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

async fn fetch_token(
    client: &reqwest::Client,
    endpoint: &str,
    client_id: &str,
    token_file: &Path,
) -> Result<AccessToken, AzureAuthError> {
    let assertion = tokio::fs::read_to_string(token_file).await?;
    if client_id.trim().is_empty() {
        return Err(AzureAuthError::MissingEnvironment("AZURE_CLIENT_ID"));
    }
    if assertion.trim().is_empty() {
        return Err(AzureAuthError::EmptyAssertion);
    }
    let response = client
        .post(endpoint)
        .timeout(Duration::from_secs(10))
        .form(&[
            ("client_id", client_id),
            ("scope", POSTGRES_SCOPE),
            ("grant_type", "client_credentials"),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", assertion.trim()),
        ])
        .send()
        .await?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "failed to read error body".into());
        return Err(AzureAuthError::Rejected {
            status,
            body: truncate_error_body(body, assertion.trim()),
        });
    }
    let body: TokenResponse = response
        .json()
        .await
        .map_err(|_| AzureAuthError::InvalidResponse)?;
    if body.access_token.trim().is_empty() || body.expires_in == 0 {
        return Err(AzureAuthError::InvalidResponse);
    }
    let expires_at = SystemTime::now()
        .checked_add(Duration::from_secs(body.expires_in))
        .ok_or(AzureAuthError::InvalidResponse)?;
    Ok(AccessToken {
        value: body.access_token,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn missing_projected_token_is_non_transient() {
        let token_file = std::env::temp_dir().join(format!(
            "pgroles-azure-missing-{}/token",
            std::process::id()
        ));
        let error = fetch_token(
            &reqwest::Client::new(),
            "http://unused",
            "client-id",
            &token_file,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&error, AzureAuthError::ReadAssertion(source) if source.kind() == std::io::ErrorKind::NotFound)
        );
        assert!(error.is_non_transient());
        assert!(
            !AzureAuthError::ReadAssertion(std::io::ErrorKind::Interrupted.into())
                .is_non_transient()
        );
    }

    #[test]
    fn error_body_retains_diagnostics_and_redacts_assertion_before_utf8_truncation() {
        let body = format!("AADSTS70021: assertion-secret {}", "é".repeat(512));
        let body = truncate_error_body(body, "assertion-secret");
        assert!(body.starts_with("AADSTS70021: [redacted]"));
        assert!(!body.contains("assertion-secret"));
        assert!(body.len() <= 515);
        assert!(body.ends_with("..."));
        let error = AzureAuthError::Rejected { status: 400, body };
        assert!(error.to_string().contains("AADSTS70021"));
        assert!(error.is_non_transient());
        for status in [429, 500, 503] {
            assert!(
                !AzureAuthError::Rejected {
                    status,
                    body: String::new()
                }
                .is_non_transient()
            );
        }
    }

    fn serve_once(
        listener: std::sync::Arc<tokio::net::TcpListener>,
        expect: &str,
        status: &str,
        body: &str,
    ) -> tokio::task::JoinHandle<String> {
        let (expect, status, body) = (expect.to_owned(), status.to_owned(), body.to_owned());
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0; 1024];
                let size = socket.read(&mut chunk).await.unwrap();
                assert!(size > 0 && request.len() < 16384);
                request.extend_from_slice(&chunk[..size]);
                if let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + 4 + length {
                        break;
                    }
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.contains(&expect), "missing expected request field");
            socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            request
        })
    }

    async fn fixture(
        name: &str,
    ) -> (
        AzureTokenSource,
        std::sync::Arc<tokio::net::TcpListener>,
        PathBuf,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let file =
            std::env::temp_dir().join(format!("pgroles-azure-{name}-{}", std::process::id()));
        tokio::fs::write(&file, "projected-assertion")
            .await
            .unwrap();
        let config = WorkloadIdentityConfig::from_values(
            "tenant-id",
            "client-id",
            file.clone(),
            "https://login.microsoftonline.com/",
        )
        .unwrap();
        let mut source = AzureTokenSource::new(config);
        source.endpoint = format!("http://{}/token", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        (source, std::sync::Arc::new(listener), file)
    }

    #[tokio::test]
    async fn rejected_exchange_keeps_entra_error_body() {
        let (source, listener, file) = fixture("rejected").await;
        let server = serve_once(
            listener,
            "client_assertion=projected-assertion",
            "400 Bad Request",
            r#"{"error":"invalid_client","error_description":"AADSTS70021: No matching federated identity record found"}"#,
        );
        let error = source.fetch().await.unwrap_err();
        assert!(
            matches!(&error, AzureAuthError::Rejected { status: 400, body } if body.contains("AADSTS70021"))
        );
        assert!(error.is_non_transient());
        server.await.unwrap();
        tokio::fs::remove_file(file).await.unwrap();
    }

    #[tokio::test]
    async fn exchanges_projected_assertion() {
        let (source, listener, file) = fixture("exchange").await;
        let server = serve_once(
            listener,
            "client_assertion=projected-assertion",
            "200 OK",
            r#"{"access_token":"database-token","expires_in":3600}"#,
        );
        let result = source.fetch().await.unwrap();
        assert_eq!(result.value, "database-token");
        assert!(result.expires_at > SystemTime::now() + Duration::from_secs(3500));
        let request = server.await.unwrap();
        assert!(request.contains("client_id=client-id"));
        assert!(request.contains("grant_type=client_credentials"));
        assert!(
            request.contains("scope=https%3A%2F%2Fossrdbms-aad.database.windows.net%2F.default")
        );
        tokio::fs::remove_file(file).await.unwrap();
    }

    #[tokio::test]
    async fn reuses_source_and_reads_rotated_assertion() {
        let (source, listener, file) = fixture("rotation").await;
        let server = serve_once(
            listener.clone(),
            "client_assertion=projected-assertion",
            "200 OK",
            r#"{"access_token":"first-token","expires_in":3600}"#,
        );
        assert_eq!(source.fetch().await.unwrap().value, "first-token");
        server.await.unwrap();
        // Same source/client/config; only the projected file changes.
        tokio::fs::write(&file, "rotated-assertion").await.unwrap();
        let server = serve_once(
            listener,
            "client_assertion=rotated-assertion",
            "200 OK",
            r#"{"access_token":"second-token","expires_in":3600}"#,
        );
        assert_eq!(source.fetch().await.unwrap().value, "second-token");
        server.await.unwrap();
        tokio::fs::remove_file(file).await.unwrap();
    }

    #[tokio::test]
    async fn malformed_success_response_is_non_transient() {
        for (i, body) in [
            "not-json",
            "{}",
            r#"{"access_token":"","expires_in":3600}"#,
            r#"{"access_token":"token","expires_in":0}"#,
            r#"{"access_token":"token","expires_in":18446744073709551615}"#,
        ]
        .into_iter()
        .enumerate()
        {
            let (source, listener, file) = fixture(&format!("invalid-{i}")).await;
            let server = serve_once(listener, "client_id=client-id", "200 OK", body);
            let error = source.fetch().await.unwrap_err();
            assert!(matches!(error, AzureAuthError::InvalidResponse));
            assert!(error.is_non_transient());
            server.await.unwrap();
            tokio::fs::remove_file(file).await.unwrap();
        }
    }

    #[tokio::test]
    async fn empty_assertion_is_a_setup_error() {
        let (source, _, file) = fixture("empty").await;
        tokio::fs::write(&file, " \n").await.unwrap();
        let error = source.fetch().await.unwrap_err();
        assert!(matches!(error, AzureAuthError::EmptyAssertion));
        assert!(error.is_non_transient());
        tokio::fs::remove_file(file).await.unwrap();
    }

    #[test]
    fn validates_configuration_and_builds_authority_endpoint() {
        for authority in [
            "https://login.microsoftonline.com",
            "https://login.microsoftonline.us/",
            "https://login.chinacloudapi.cn/",
        ] {
            let config = WorkloadIdentityConfig::from_values(
                "tenant-id",
                "client",
                "token".into(),
                authority,
            )
            .unwrap();
            let source = AzureTokenSource::new(config);
            assert_eq!(source.endpoint.path(), "/tenant-id/oauth2/v2.0/token");
            assert_eq!(
                source.endpoint.origin().ascii_serialization(),
                authority.trim_end_matches('/')
            );
        }
        for authority in [
            "http://login.microsoftonline.com",
            "https://user:pass@example.com",
            "https://example.com/path",
            "https://example.com?query=1",
            "https://example.com#fragment",
            "invalid",
        ] {
            assert!(matches!(
                WorkloadIdentityConfig::from_values("tenant", "client", "token".into(), authority),
                Err(AzureAuthError::InvalidAuthority)
            ));
        }
        assert!(matches!(
            WorkloadIdentityConfig::from_values(
                "tenant",
                " ",
                "token".into(),
                "https://login.microsoftonline.com"
            ),
            Err(AzureAuthError::MissingEnvironment("AZURE_CLIENT_ID"))
        ));
        assert!(matches!(
            WorkloadIdentityConfig::from_values(
                "../tenant",
                "client",
                "token".into(),
                "https://login.microsoftonline.com"
            ),
            Err(AzureAuthError::InvalidTenant)
        ));
    }

    #[test]
    fn connection_policy_rejects_password_and_preserves_explicit_tls() {
        for url in [
            "postgres://user:password@localhost/db",
            "postgres://user@localhost/db?password=secret",
            "https://localhost/db",
        ] {
            assert!(matches!(
                connection_options(url),
                Err(AzureAuthError::InvalidConnection)
            ));
        }
        let options = connection_options("postgres://user@localhost/db").unwrap();
        assert!(matches!(options.get_ssl_mode(), PgSslMode::VerifyFull));
        let options = connection_options("postgres://user@localhost/db?sslmode=require").unwrap();
        assert!(matches!(options.get_ssl_mode(), PgSslMode::Require));
    }
}
