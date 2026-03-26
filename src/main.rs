//! NexusVault - Standalone Secrets Management Server
//!
//! A standalone HTTP server that exposes the Aegis Vault secrets engine
//! over a REST API. Provides secret storage, transit encryption, seal/unseal
//! lifecycle management, and audit logging.
//!
//! Usage:
//!   nexusvault --port 8200 --data-dir /var/lib/nexusvault --passphrase "my-secret" --api-key "my-api-key"
//!
//! Environment variables:
//!   NEXUSVAULT_PASSPHRASE  - Vault passphrase (alternative to --passphrase)
//!   NEXUSVAULT_API_KEY     - API key for authentication (alternative to --api-key)
//!   RUST_LOG               - Log level filter (default: info)

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use aegis_vault::{AegisVault, VaultConfig, VaultError};

// ---------------------------------------------------------------------------
// CLI Arguments
// ---------------------------------------------------------------------------

/// NexusVault - Zero-dependency secrets management server
#[derive(Parser, Debug)]
#[command(name = "nexusvault", version = "0.2.4", about = "Standalone secrets management server")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "8200")]
    port: u16,

    /// Host to bind to
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Data directory for vault persistence. If not set, vault runs in-memory only.
    #[arg(short, long)]
    data_dir: Option<PathBuf>,

    /// Passphrase for seal/unseal operations. Can also be set via NEXUSVAULT_PASSPHRASE env var.
    #[arg(long)]
    passphrase: Option<String>,

    /// Maximum secret versions to retain per key
    #[arg(long, default_value = "10")]
    max_versions: u32,

    /// Maximum audit log entries to keep in memory
    #[arg(long, default_value = "10000")]
    audit_log_max: usize,

    /// Disable auto-unseal on startup (vault starts sealed)
    #[arg(long)]
    start_sealed: bool,

    /// API key for bearer token authentication. Can also be set via NEXUSVAULT_API_KEY env var.
    /// If not set, the server will refuse to start (use --no-auth to disable).
    #[arg(long)]
    api_key: Option<String>,

    /// Disable API key authentication (NOT recommended for production)
    #[arg(long)]
    no_auth: bool,

    /// Component name bound to this API key (used for access control). Defaults to "api".
    #[arg(long, default_value = "api")]
    component_name: String,

    /// Path to TLS certificate file (PEM format). Enables HTTPS when set with --tls-key.
    #[arg(long)]
    tls_cert: Option<PathBuf>,

    /// Path to TLS private key file (PEM format). Enables HTTPS when set with --tls-cert.
    #[arg(long)]
    tls_key: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Application State
// ---------------------------------------------------------------------------

/// Simple rate limiter: tracks attempt timestamps within a rolling window.
struct RateLimiter {
    attempts: parking_lot::Mutex<std::collections::VecDeque<std::time::Instant>>,
    max_attempts: usize,
    window: std::time::Duration,
}

impl RateLimiter {
    fn new(max_attempts: usize, window: std::time::Duration) -> Self {
        Self {
            attempts: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            max_attempts,
            window,
        }
    }

    /// Returns true if the request is allowed, false if rate-limited.
    fn check(&self) -> bool {
        let mut attempts = self.attempts.lock();
        let now = std::time::Instant::now();
        // Evict expired entries
        while attempts.front().map_or(false, |t| now.duration_since(*t) > self.window) {
            attempts.pop_front();
        }
        if attempts.len() >= self.max_attempts {
            return false;
        }
        attempts.push_back(now);
        true
    }
}

struct AppState {
    vault: AegisVault,
    api_key: Option<String>,
    /// When auth is enabled, this is the verified component name for the API key.
    /// Overrides self-reported component query parameters.
    authenticated_component: Option<String>,
    /// Rate limiter for /v1/unseal endpoint (brute-force protection).
    unseal_limiter: RateLimiter,
}

// ---------------------------------------------------------------------------
// Request / Response Types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    sealed: bool,
}

#[derive(Serialize)]
struct StatusResponse {
    sealed: bool,
    secret_count: usize,
    transit_key_count: usize,
    uptime_secs: Option<u64>,
}

#[derive(Deserialize)]
struct SecretSetRequest {
    value: String,
    #[serde(default = "default_component")]
    component: String,
}

fn default_component() -> String {
    "api".to_string()
}

#[derive(Serialize)]
struct SecretGetResponse {
    key: String,
    value: String,
}

#[derive(Deserialize)]
struct SecretListQuery {
    #[serde(default)]
    prefix: String,
    #[serde(default = "default_component")]
    component: String,
}

#[derive(Serialize)]
struct SecretListResponse {
    keys: Vec<String>,
}

#[derive(Deserialize)]
struct ComponentQuery {
    #[serde(default = "default_component")]
    component: String,
}

#[derive(Deserialize)]
struct UnsealRequest {
    passphrase: String,
}

#[derive(Serialize)]
struct SealResponse {
    sealed: bool,
    message: String,
}

#[derive(Deserialize)]
struct TransitCreateKeyRequest {
    name: String,
}

#[derive(Deserialize)]
struct TransitEncryptRequest {
    key_name: String,
    plaintext: String,
}

#[derive(Serialize)]
struct TransitEncryptResponse {
    ciphertext: String,
}

#[derive(Deserialize)]
struct TransitDecryptRequest {
    key_name: String,
    ciphertext: String,
}

#[derive(Serialize)]
struct TransitDecryptResponse {
    plaintext: String,
}

#[derive(Serialize)]
struct TransitKeysResponse {
    keys: Vec<String>,
}

#[derive(Deserialize)]
struct AuditQuery {
    #[serde(default = "default_audit_limit")]
    limit: usize,
}

fn default_audit_limit() -> usize {
    50
}

#[derive(Serialize)]
struct AuditResponse {
    entries: Vec<AuditEntryResponse>,
}

#[derive(Serialize)]
struct AuditEntryResponse {
    timestamp: u64,
    operation: String,
    key: Option<String>,
    component: Option<String>,
    success: bool,
    detail: Option<String>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Error Handling
// ---------------------------------------------------------------------------

fn vault_error_to_status(err: &VaultError) -> StatusCode {
    match err {
        VaultError::Sealed => StatusCode::SERVICE_UNAVAILABLE,
        VaultError::SecretNotFound(_) => StatusCode::NOT_FOUND,
        VaultError::AccessDenied(_) => StatusCode::FORBIDDEN,
        VaultError::InvalidPassphrase => StatusCode::UNAUTHORIZED,
        VaultError::AlreadyExists(_) => StatusCode::CONFLICT,
        VaultError::Encryption(_) => StatusCode::INTERNAL_SERVER_ERROR,
        VaultError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        VaultError::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn error_response(err: VaultError) -> impl IntoResponse {
    let status = vault_error_to_status(&err);

    // Sanitize error messages: don't leak internal details to clients
    let client_message = match &err {
        VaultError::Sealed => "vault is sealed".to_string(),
        VaultError::SecretNotFound(key) => format!("secret not found: {key}"),
        VaultError::AccessDenied(_) => "access denied".to_string(),
        VaultError::InvalidPassphrase => "invalid passphrase".to_string(),
        VaultError::AlreadyExists(key) => format!("already exists: {key}"),
        // Never expose internal crypto, IO, or implementation details
        VaultError::Encryption(_) | VaultError::Io(_) | VaultError::Other(_) => {
            error!("Internal error: {}", err);
            "internal server error".to_string()
        }
    };

    (
        status,
        Json(ErrorResponse {
            error: client_message,
        }),
    )
}

// ---------------------------------------------------------------------------
// Authentication Middleware
// ---------------------------------------------------------------------------

/// Authenticated component name, injected by the auth middleware.
#[derive(Clone)]
struct AuthenticatedComponent(String);

async fn require_api_key(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, impl IntoResponse> {
    if let Some(ref expected_key) = state.api_key {
        let auth_header = request
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok());

        let authenticated = match auth_header {
            Some(header) if header.starts_with("Bearer ") => {
                let token = &header[7..];
                token == expected_key.as_str()
            }
            _ => false,
        };

        if !authenticated {
            warn!("Rejected unauthenticated request to {}", request.uri().path());
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid or missing API key — use 'Authorization: Bearer <key>'".into(),
                }),
            ));
        }

        // Inject the verified component identity, overriding self-reported values
        if let Some(ref component) = state.authenticated_component {
            request
                .extensions_mut()
                .insert(AuthenticatedComponent(component.clone()));
        }
    }

    Ok(next.run(request).await)
}

/// Resolve the component name: use authenticated identity if available, else fallback to query param.
fn resolve_component(
    auth: Option<&AuthenticatedComponent>,
    self_reported: &str,
) -> String {
    match auth {
        Some(AuthenticatedComponent(name)) => name.clone(),
        None => self_reported.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Route Handlers
// ---------------------------------------------------------------------------

/// GET /health
async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        version: "0.2.3",
        sealed: state.vault.is_sealed(),
    })
}

/// GET /v1/status
async fn status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let s = state.vault.status();
    Json(StatusResponse {
        sealed: s.sealed,
        secret_count: s.secret_count,
        transit_key_count: s.transit_key_count,
        uptime_secs: s.uptime_secs,
    })
}

/// GET /v1/secrets/:key
async fn secret_get(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthenticatedComponent>>,
    Path(key): Path<String>,
    Query(query): Query<ComponentQuery>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let component = resolve_component(auth.as_ref().map(|e| &e.0), &query.component);
    state
        .vault
        .get(&key, &component)
        .map(|value| Json(SecretGetResponse { key, value }))
        .map_err(error_response)
}

/// PUT /v1/secrets/:key
async fn secret_set(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthenticatedComponent>>,
    Path(key): Path<String>,
    Json(body): Json<SecretSetRequest>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let component = resolve_component(auth.as_ref().map(|e| &e.0), &body.component);
    state
        .vault
        .set(&key, &body.value, &component)
        .map(|_| (StatusCode::CREATED, Json(serde_json::json!({"message": "secret stored", "key": key}))))
        .map_err(error_response)
}

/// DELETE /v1/secrets/:key
async fn secret_delete(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthenticatedComponent>>,
    Path(key): Path<String>,
    Query(query): Query<ComponentQuery>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let component = resolve_component(auth.as_ref().map(|e| &e.0), &query.component);
    state
        .vault
        .delete(&key, &component)
        .map(|_| Json(serde_json::json!({"message": "secret deleted", "key": key})))
        .map_err(error_response)
}

/// GET /v1/secrets
async fn secret_list(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthenticatedComponent>>,
    Query(query): Query<SecretListQuery>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    let component = resolve_component(auth.as_ref().map(|e| &e.0), &query.component);
    state
        .vault
        .list(&query.prefix, &component)
        .map(|keys| Json(SecretListResponse { keys }))
        .map_err(error_response)
}

/// POST /v1/seal
async fn seal(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, impl IntoResponse> {
    state
        .vault
        .seal()
        .map(|_| {
            Json(SealResponse {
                sealed: true,
                message: "vault sealed".to_string(),
            })
        })
        .map_err(error_response)
}

/// POST /v1/unseal
async fn unseal(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UnsealRequest>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    if !state.unseal_limiter.check() {
        warn!("Unseal rate limit exceeded");
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "too many unseal attempts — try again later".into(),
            }),
        ));
    }

    state
        .vault
        .unseal(&body.passphrase)
        .map(|_| {
            Json(SealResponse {
                sealed: false,
                message: "vault unsealed".to_string(),
            })
        })
        .map_err(|err| {
            let status = vault_error_to_status(&err);
            (
                status,
                Json(ErrorResponse {
                    error: err.to_string(),
                }),
            )
        })
}

/// POST /v1/transit/keys
async fn transit_create_key(
    State(state): State<Arc<AppState>>,
    Json(body): Json<TransitCreateKeyRequest>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    state
        .vault
        .transit_create_key(&body.name)
        .map(|_| (StatusCode::CREATED, Json(serde_json::json!({"message": "transit key created", "name": body.name}))))
        .map_err(error_response)
}

/// GET /v1/transit/keys
async fn transit_list_keys(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let keys = state.vault.transit_list_keys();
    Json(TransitKeysResponse { keys })
}

/// POST /v1/transit/encrypt
async fn transit_encrypt(
    State(state): State<Arc<AppState>>,
    Json(body): Json<TransitEncryptRequest>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    use base64::Engine;
    let plaintext_bytes = body.plaintext.as_bytes();
    state
        .vault
        .transit_encrypt(&body.key_name, plaintext_bytes)
        .map(|ciphertext| {
            let encoded = base64::engine::general_purpose::STANDARD.encode(&ciphertext);
            Json(TransitEncryptResponse {
                ciphertext: format!("vault:v1:{}", encoded),
            })
        })
        .map_err(error_response)
}

/// POST /v1/transit/decrypt
async fn transit_decrypt(
    State(state): State<Arc<AppState>>,
    Json(body): Json<TransitDecryptRequest>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    use base64::Engine;
    let raw = body
        .ciphertext
        .strip_prefix("vault:v1:")
        .unwrap_or(&body.ciphertext);
    let ciphertext_bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|e| {
            error_response(VaultError::Encryption(format!(
                "invalid base64 ciphertext: {}",
                e
            )))
        })?;
    state
        .vault
        .transit_decrypt(&body.key_name, &ciphertext_bytes)
        .map(|plaintext| {
            Json(TransitDecryptResponse {
                plaintext: String::from_utf8_lossy(&plaintext).to_string(),
            })
        })
        .map_err(error_response)
}

/// GET /v1/audit
async fn audit(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuditQuery>,
) -> impl IntoResponse {
    let entries = state
        .vault
        .audit_entries(query.limit)
        .into_iter()
        .map(|e| AuditEntryResponse {
            timestamp: e.timestamp,
            operation: format!("{:?}", e.operation),
            key: e.key,
            component: e.component,
            success: e.success,
            detail: e.detail,
        })
        .collect();
    Json(AuditResponse { entries })
}

// ---------------------------------------------------------------------------
// Security Hardening
// ---------------------------------------------------------------------------

/// Disable core dumps on Linux to prevent master key exposure via memory dumps.
fn disable_core_dumps() {
    #[cfg(target_os = "linux")]
    {
        // PR_SET_DUMPABLE = 4, arg = 0 (not dumpable)
        let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if ret == 0 {
            tracing::info!("Core dumps disabled (PR_SET_DUMPABLE=0)");
        } else {
            tracing::warn!("Failed to disable core dumps via prctl");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        tracing::debug!("Core dump protection not available on this platform");
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Security hardening: prevent core dumps from leaking key material
    disable_core_dumps();

    let args = Args::parse();

    // Resolve API key from CLI arg or environment variable
    let api_key = args
        .api_key
        .or_else(|| std::env::var("NEXUSVAULT_API_KEY").ok());

    if api_key.is_none() && !args.no_auth {
        error!("No API key configured. Set --api-key or NEXUSVAULT_API_KEY, or use --no-auth to disable (not recommended).");
        std::process::exit(1);
    }

    if args.no_auth {
        warn!("Running WITHOUT API key authentication — do NOT use in production");
    }

    // Resolve passphrase from CLI arg or environment variable
    let passphrase = args
        .passphrase
        .or_else(|| std::env::var("NEXUSVAULT_PASSPHRASE").ok());

    // Build vault configuration
    let config = VaultConfig {
        data_dir: args.data_dir.clone(),
        auto_unseal: !args.start_sealed,
        passphrase,
        max_versions: args.max_versions,
        rotation_check_interval_secs: 3600,
        audit_log_max_entries: args.audit_log_max,
    };

    // Initialize the vault
    let vault = match AegisVault::init(config).await {
        Ok(v) => {
            info!(
                "Vault initialized (sealed={}, data_dir={:?})",
                v.is_sealed(),
                args.data_dir
            );
            v
        }
        Err(e) => {
            error!("Failed to initialize vault: {}. Starting with sealed vault.", e);
            AegisVault::new_auto(None)
        }
    };

    let authenticated_component = if api_key.is_some() {
        Some(args.component_name.clone())
    } else {
        None
    };

    let state = Arc::new(AppState {
        vault,
        api_key,
        authenticated_component,
        unseal_limiter: RateLimiter::new(5, std::time::Duration::from_secs(60)),
    });

    // Build router — /health is unauthenticated, all /v1/* routes require auth
    let authenticated_routes = Router::new()
        .route("/v1/status", get(status))
        .route("/v1/secrets/", get(secret_list))
        .route(
            "/v1/secrets/{key}",
            get(secret_get).put(secret_set).delete(secret_delete),
        )
        .route("/v1/seal", post(seal))
        .route("/v1/unseal", post(unseal))
        .route("/v1/transit/keys", get(transit_list_keys).post(transit_create_key))
        .route("/v1/transit/encrypt", post(transit_encrypt))
        .route("/v1/transit/decrypt", post(transit_decrypt))
        .route("/v1/audit", get(audit))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_api_key,
        ));

    let app = Router::new()
        .route("/health", get(health))
        .merge(authenticated_routes)
        .with_state(state);

    let addr = SocketAddr::from((
        args.host.parse::<std::net::IpAddr>().unwrap_or_else(|_| {
            error!("Invalid host '{}', falling back to 127.0.0.1", args.host);
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        }),
        args.port,
    ));

    info!(
        "Endpoints: GET /health, GET /v1/status, GET|PUT|DELETE /v1/secrets/{{key}}, POST /v1/seal, POST /v1/unseal"
    );

    // Start with TLS if cert and key are provided
    match (args.tls_cert, args.tls_key) {
        (Some(cert_path), Some(key_path)) => {
            info!("NexusVault server starting on https://{} (TLS enabled)", addr);
            let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
                .await
                .unwrap_or_else(|e| {
                    error!("Failed to load TLS certificate/key: {}", e);
                    std::process::exit(1);
                });
            axum_server::bind_rustls(addr, tls_config)
                .serve(app.into_make_service())
                .await
                .expect("TLS server failed");
        }
        (None, None) => {
            info!("NexusVault server starting on http://{} (no TLS — use a reverse proxy for production)", addr);
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .expect("Failed to bind to address");
            axum::serve(listener, app)
                .await
                .expect("Server failed");
        }
        _ => {
            error!("Both --tls-cert and --tls-key must be provided together");
            std::process::exit(1);
        }
    }
}
