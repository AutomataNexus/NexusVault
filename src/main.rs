//! NexusVault - Standalone Secrets Management Server
//!
//! A standalone HTTP server that exposes the Aegis Vault secrets engine
//! over a REST API. Provides secret storage, transit encryption, seal/unseal
//! lifecycle management, and audit logging.
//!
//! Usage:
//!   nexusvault --port 8200 --data-dir /var/lib/nexusvault --passphrase "my-secret"
//!
//! Environment variables:
//!   NEXUSVAULT_PASSPHRASE  - Vault passphrase (alternative to --passphrase)
//!   RUST_LOG               - Log level filter (default: info)

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use aegis_vault::{AegisVault, VaultConfig, VaultError};

// ---------------------------------------------------------------------------
// CLI Arguments
// ---------------------------------------------------------------------------

/// NexusVault - Zero-dependency secrets management server
#[derive(Parser, Debug)]
#[command(name = "nexusvault", version = "0.2.2", about = "Standalone secrets management server")]
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
}

// ---------------------------------------------------------------------------
// Application State
// ---------------------------------------------------------------------------

struct AppState {
    vault: AegisVault,
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
    (
        status,
        Json(ErrorResponse {
            error: err.to_string(),
        }),
    )
}

// ---------------------------------------------------------------------------
// Route Handlers
// ---------------------------------------------------------------------------

/// GET /health
async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok",
        version: "0.2.2",
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
    Path(key): Path<String>,
    Query(query): Query<ComponentQuery>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    state
        .vault
        .get(&key, &query.component)
        .map(|value| Json(SecretGetResponse { key, value }))
        .map_err(error_response)
}

/// PUT /v1/secrets/:key
async fn secret_set(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Json(body): Json<SecretSetRequest>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    state
        .vault
        .set(&key, &body.value, &body.component)
        .map(|_| (StatusCode::CREATED, Json(serde_json::json!({"message": "secret stored", "key": key}))))
        .map_err(error_response)
}

/// DELETE /v1/secrets/:key
async fn secret_delete(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    Query(query): Query<ComponentQuery>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    state
        .vault
        .delete(&key, &query.component)
        .map(|_| Json(serde_json::json!({"message": "secret deleted", "key": key})))
        .map_err(error_response)
}

/// GET /v1/secrets
async fn secret_list(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SecretListQuery>,
) -> Result<impl IntoResponse, impl IntoResponse> {
    state
        .vault
        .list(&query.prefix, &query.component)
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
    state
        .vault
        .unseal(&body.passphrase)
        .map(|_| {
            Json(SealResponse {
                sealed: false,
                message: "vault unsealed".to_string(),
            })
        })
        .map_err(error_response)
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

    let args = Args::parse();

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

    let state = Arc::new(AppState { vault });

    // Build router
    let app = Router::new()
        // Health check
        .route("/health", get(health))
        // Vault status
        .route("/v1/status", get(status))
        // Secret CRUD
        .route("/v1/secrets", get(secret_list))
        .route("/v1/secrets/{key}", get(secret_get))
        .route("/v1/secrets/{key}", put(secret_set))
        .route("/v1/secrets/{key}", delete(secret_delete))
        // Seal / Unseal
        .route("/v1/seal", post(seal))
        .route("/v1/unseal", post(unseal))
        // Transit encryption
        .route("/v1/transit/keys", get(transit_list_keys))
        .route("/v1/transit/keys", post(transit_create_key))
        .route("/v1/transit/encrypt", post(transit_encrypt))
        .route("/v1/transit/decrypt", post(transit_decrypt))
        // Audit log
        .route("/v1/audit", get(audit))
        .with_state(state);

    let addr = SocketAddr::from((
        args.host.parse::<std::net::IpAddr>().unwrap_or_else(|_| {
            error!("Invalid host '{}', falling back to 127.0.0.1", args.host);
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        }),
        args.port,
    ));

    info!("NexusVault server starting on http://{}", addr);
    info!(
        "Endpoints: GET /health, GET /v1/status, GET|PUT|DELETE /v1/secrets/{{key}}, POST /v1/seal, POST /v1/unseal"
    );

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app)
        .await
        .expect("Server failed");
}
