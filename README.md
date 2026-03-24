<p align="center">
  <img src="assets/NexusVault_logo.png" alt="NexusVault Logo" width="200"/>
</p>

<h1 align="center">NexusVault</h1>

<p align="center">
  <strong>Zero-dependency secrets management for Rust applications</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0"/></a>
  <img src="https://img.shields.io/badge/rust-1.75%2B-orange.svg" alt="Rust 1.75+"/>
  <img src="https://img.shields.io/badge/version-0.2.2-green.svg" alt="Version 0.2.2"/>
  <img src="https://img.shields.io/badge/tests-63-brightgreen.svg" alt="Tests: 63"/>
  <img src="https://img.shields.io/badge/LOC-2475-informational.svg" alt="LOC: 2475"/>
</p>

---

## Overview

NexusVault is a lightweight, Rust-native encrypted secrets manager designed to be embedded directly into application infrastructure or deployed as a standalone service. Unlike HashiCorp Vault, which operates as a heavyweight external dependency requiring its own cluster management, operator workflows, and enterprise licensing, NexusVault compiles into a single binary with zero runtime dependencies beyond the operating system.

NexusVault provides the core primitives that production applications actually need: encrypted key-value secret storage with versioning, a transit encryption engine for encryption-as-a-service, passphrase-based seal/unseal lifecycle, component-scoped access control, and a bounded in-memory audit log. All cryptographic operations use AES-256-GCM with PBKDF2-HMAC-SHA256 key derivation, implemented via the `aes-gcm` and `ring` crates -- both widely audited Rust cryptography libraries.

The project originated as the integrated vault module (`aegis-vault`) within the Aegis-DB multi-paradigm database platform. NexusVault extracts that module into a standalone server with an HTTP REST API, making it usable by any application regardless of whether it uses Aegis-DB. The vault can run in-memory for development or persist encrypted data to disk for production. Auto-unseal is supported for development convenience, while production deployments can start sealed and require an explicit unseal operation with the correct passphrase.

---

## Architecture

```
                        +-----------------------+
                        |     REST API Layer    |
                        |   (Axum HTTP Server)  |
                        +----------+------------+
                                   |
                    +--------------+--------------+
                    |                             |
          +---------+---------+       +-----------+-----------+
          |    AegisVault     |       |    Transit Engine     |
          |  (Main Facade)    |       | (Encryption-as-a-Svc)|
          +---------+---------+       +-----------+-----------+
                    |                             |
          +---------+---------+       +-----------+-----------+
          |    VaultStore     |       |   Named AES-256-GCM   |
          | (Encrypted K/V)   |       |   Keys (in-memory)    |
          +---------+---------+       +-----------------------+
                    |
       +------------+------------+
       |            |            |
+------+------+ +---+----+ +----+-------+
| SealManager | | Access | | Audit Log  |
| (Master Key | |Control | | (Bounded   |
|  Lifecycle) | |        | |  VecDeque) |
+------+------+ +--------+ +------------+
       |
+------+------+
|    Disk     |
| Persistence |
| (vault.dat  |
|  vault.key) |
+-------------+
```

**Data flow for a `SET` operation:**

1. HTTP request arrives at the REST API layer.
2. `AegisVault::set()` is called, which delegates to `VaultStore::set()`.
3. `VaultStore` checks that the vault is not sealed via `SealManager::is_sealed()`.
4. `AccessController::check_access()` validates the requesting component has write permission for the key prefix.
5. `SealManager::encrypt()` encrypts the plaintext value using AES-256-GCM with the master key.
6. The encrypted blob is stored as a new `SecretVersion` in the in-memory `HashMap`.
7. If `data_dir` is configured, `VaultStore::save_to_disk()` serializes the entire secrets map, encrypts it as a single blob, and writes it atomically (temp file + rename) to `vault.dat`.
8. `VaultAuditLog::record_success()` logs the operation.

---

## Features

### Encrypted Secret Storage

All secret values are encrypted at rest using AES-256-GCM with the vault's master key. Secrets are organized as key-value pairs with hierarchical path-style keys (e.g., `db/password`, `api/stripe/key`). Each secret maintains a version history, allowing rollback and audit of changes over time. Old versions are automatically pruned when the configurable `max_versions` limit is exceeded.

### Versioned Secrets

Every write to a secret key creates a new version rather than overwriting the previous value. Versions are numbered sequentially starting at 1. The `get` operation returns the current (latest) version by default, while `get_version` can retrieve any specific historical version. Each version records the creation timestamp and the component that created it.

### Seal/Unseal Lifecycle

The vault implements a seal/unseal lifecycle inspired by HashiCorp Vault. When sealed, the master encryption key is zeroized from memory and all operations that require decryption fail with a `VaultError::Sealed` error. Unsealing requires the correct passphrase, which is used to derive the master key via PBKDF2-HMAC-SHA256 (100,000 iterations) and then decrypt the stored master key blob. This ensures that even if the vault process is memory-dumped while sealed, the master key cannot be recovered.

### Transit Encryption Engine

The transit engine provides encryption-as-a-service: applications can create named encryption keys and use them to encrypt/decrypt arbitrary data without ever having access to the raw key material. Each transit key is an independent AES-256-GCM key generated from a cryptographically secure random source. This pattern is useful for encrypting data at the application layer (e.g., encrypting user PII before storing it in a database) without requiring the application to manage encryption keys directly.

### Component-Based Access Control

Access to secrets is governed by policies that restrict which components can perform which operations on which key prefixes. The `AccessController` supports both default-allow (for backwards compatibility and development) and default-deny modes. Policies specify allowed components, allowed key prefixes, and permitted operations (read, write, delete, list).

### Bounded Audit Log

Every vault operation -- reads, writes, deletes, seal/unseal events, transit operations -- is recorded in an in-memory audit log implemented as a bounded `VecDeque`. When the log reaches its configured maximum capacity, the oldest entries are evicted. Each entry records the timestamp, operation type, key (if applicable), requesting component, success/failure status, and optional detail message.

### Disk Persistence

When a `data_dir` is configured, the vault persists its encrypted data to disk after every mutation. The secrets map is serialized to JSON, encrypted as a single AES-256-GCM blob using the master key, and written atomically via a temp-file-and-rename pattern. The master key itself is stored separately in `vault.key`, encrypted with the passphrase-derived key. On startup, the vault loads both files and auto-unseals if configured.

### Auto-Unseal

For development and testing, the vault supports auto-unseal on startup. When `auto_unseal` is enabled and a passphrase is provided, the vault derives the master key from the passphrase and unseals automatically. If no passphrase is provided, a random one is generated and logged as a warning. Production deployments should disable auto-unseal and manage the unseal process explicitly.

### Atomic Writes

Disk persistence uses an atomic write strategy: data is first written to a `.tmp` file, then renamed to the final path. This prevents corruption if the process crashes mid-write. The `rename` operation is atomic on all major filesystems (ext4, XFS, APFS, NTFS).

### Key Zeroization

The master key type (`MasterKey`) implements the `Zeroize` trait via the `zeroize` crate. When the vault is sealed or the `MasterKey` is dropped, the key material is overwritten with zeros in memory. This mitigates the risk of key recovery from process memory dumps or core files.

### REST API

NexusVault exposes all vault operations over a JSON REST API built on Axum. The API supports secret CRUD, seal/unseal, transit encryption/decryption, and audit log retrieval. Responses use standard HTTP status codes (503 for sealed, 404 for not found, 403 for access denied, 409 for conflicts).

---

## Quick Start

### Running the Server

```bash
# Build from source
cargo build --release

# Run with in-memory storage (development)
./target/release/nexusvault --port 8200

# Run with disk persistence (production)
./target/release/nexusvault \
  --port 8200 \
  --data-dir /var/lib/nexusvault \
  --passphrase "your-secure-passphrase"

# Start sealed (requires explicit unseal)
./target/release/nexusvault \
  --port 8200 \
  --data-dir /var/lib/nexusvault \
  --start-sealed
```

### Basic Usage with curl

```bash
# Check health
curl http://localhost:8200/health

# Store a secret
curl -X PUT http://localhost:8200/v1/secrets/db/password \
  -H "Content-Type: application/json" \
  -d '{"value": "s3cret!", "component": "myapp"}'

# Retrieve a secret
curl http://localhost:8200/v1/secrets/db/password?component=myapp

# List secrets by prefix
curl "http://localhost:8200/v1/secrets?prefix=db/&component=myapp"

# Delete a secret
curl -X DELETE "http://localhost:8200/v1/secrets/db/password?component=myapp"

# Seal the vault
curl -X POST http://localhost:8200/v1/seal

# Unseal the vault
curl -X POST http://localhost:8200/v1/unseal \
  -H "Content-Type: application/json" \
  -d '{"passphrase": "your-secure-passphrase"}'
```

### Using as a Library

```rust
use aegis_vault::{AegisVault, VaultConfig};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = VaultConfig {
        data_dir: Some(PathBuf::from("/var/lib/myapp/vault")),
        auto_unseal: true,
        passphrase: Some("my-passphrase".to_string()),
        max_versions: 10,
        rotation_check_interval_secs: 3600,
        audit_log_max_entries: 10_000,
    };

    let vault = AegisVault::init(config).await?;

    // Store secrets
    vault.set("db/password", "hunter2", "myapp")?;
    vault.set("api/stripe_key", "sk_live_...", "myapp")?;

    // Retrieve secrets
    let password = vault.get("db/password", "myapp")?;
    println!("DB password: {}", password);

    // Transit encryption
    vault.transit_create_key("user-data")?;
    let ciphertext = vault.transit_encrypt("user-data", b"sensitive PII")?;
    let plaintext = vault.transit_decrypt("user-data", &ciphertext)?;
    assert_eq!(plaintext, b"sensitive PII");

    // Audit trail
    let entries = vault.audit_entries(10);
    for entry in &entries {
        println!("{}: {:?} on {:?}", entry.timestamp, entry.operation, entry.key);
    }

    Ok(())
}
```

---

## API Reference

### `AegisVault`

The main vault facade. Combines secret storage, transit encryption, seal management, access control, and audit logging into a single interface.

#### `AegisVault::init(config: VaultConfig) -> Result<Self, VaultError>`

Initialize the vault with the given configuration. Performs the full startup sequence:
1. Creates the `SealManager`.
2. If `data_dir` exists and contains a `vault.key` file, loads the encrypted master key blob.
3. If `auto_unseal` is true, derives the master key from the passphrase (or generates a new key on first run).
4. Creates `VaultStore`, `TransitEngine`, `AccessController`, and `VaultAuditLog`.
5. Loads persisted secrets from `vault.dat` if the vault is unsealed and the file exists.

**Errors:** `VaultError::Encryption` if the passphrase is wrong on an existing vault. `VaultError::Io` if disk operations fail.

---

#### `AegisVault::new_auto(data_dir: Option<PathBuf>) -> Self`

Synchronous constructor that creates a vault with auto-unseal enabled and no passphrase requirement. Generates a random master key. Intended for use in contexts where async initialization is not available (e.g., building `AppState` in a synchronous constructor).

**Parameters:**
- `data_dir` -- Optional path for disk persistence. If `None`, vault operates in-memory only.

**Returns:** An unsealed `AegisVault` instance. If auto-unseal fails, returns a sealed vault.

---

#### `AegisVault::get(key: &str, component: &str) -> Result<String, VaultError>`

Retrieve the current (latest) version of a secret by key.

**Parameters:**
- `key` -- The secret key path (e.g., `"db/password"`).
- `component` -- The requesting component name for access control and audit logging.

**Returns:** The decrypted secret value as a `String`.

**Errors:**
- `VaultError::Sealed` -- Vault is sealed.
- `VaultError::SecretNotFound` -- No secret exists with the given key.
- `VaultError::AccessDenied` -- Component does not have read access to this key.
- `VaultError::Encryption` -- Decryption failed (corrupted data).

---

#### `AegisVault::set(key: &str, value: &str, component: &str) -> Result<(), VaultError>`

Store a secret value. If the key already exists, a new version is created. The value is encrypted with AES-256-GCM before storage. If `data_dir` is configured, the vault data is persisted to disk after the write.

**Parameters:**
- `key` -- The secret key path.
- `value` -- The plaintext secret value to encrypt and store.
- `component` -- The requesting component name.

**Errors:**
- `VaultError::Sealed` -- Vault is sealed.
- `VaultError::AccessDenied` -- Component does not have write access.
- `VaultError::Encryption` -- Encryption failed.
- `VaultError::Io` -- Disk persistence failed.

---

#### `AegisVault::delete(key: &str, component: &str) -> Result<(), VaultError>`

Delete a secret and all its versions. If `data_dir` is configured, the vault data is persisted to disk after deletion.

**Parameters:**
- `key` -- The secret key path to delete.
- `component` -- The requesting component name.

**Errors:**
- `VaultError::Sealed` -- Vault is sealed.
- `VaultError::SecretNotFound` -- No secret exists with the given key.
- `VaultError::AccessDenied` -- Component does not have delete access.

---

#### `AegisVault::list(prefix: &str, component: &str) -> Result<Vec<String>, VaultError>`

List all secret keys matching a prefix. Pass an empty string to list all keys.

**Parameters:**
- `prefix` -- Key prefix to filter by (e.g., `"db/"` to list all database secrets).
- `component` -- The requesting component name.

**Returns:** A `Vec<String>` of matching key names.

**Errors:**
- `VaultError::Sealed` -- Vault is sealed.
- `VaultError::AccessDenied` -- Component does not have list access.

---

#### `AegisVault::seal() -> Result<(), VaultError>`

Seal the vault. The master key is zeroized from memory. All subsequent operations requiring encryption or decryption will fail with `VaultError::Sealed` until `unseal()` is called.

---

#### `AegisVault::unseal(passphrase: &str) -> Result<(), VaultError>`

Unseal the vault with a passphrase. Derives the master key via PBKDF2-HMAC-SHA256 and decrypts the stored master key blob. Reloads persisted secrets from disk if available.

**Parameters:**
- `passphrase` -- The passphrase used to derive the master key.

**Errors:**
- `VaultError::InvalidPassphrase` -- The passphrase is incorrect.
- `VaultError::Other` -- No encrypted key blob is available (vault was never initialized with a passphrase).

---

#### `AegisVault::is_sealed() -> bool`

Check if the vault is currently sealed. Returns `true` if sealed, `false` if unsealed.

---

#### `AegisVault::status() -> VaultStatus`

Get vault status information including sealed state, secret count, transit key count, and uptime since last unseal.

**Returns:** A `VaultStatus` struct:
```rust
pub struct VaultStatus {
    pub sealed: bool,
    pub secret_count: usize,
    pub transit_key_count: usize,
    pub uptime_secs: Option<u64>,
}
```

---

#### `AegisVault::transit_encrypt(key_name: &str, plaintext: &[u8]) -> Result<Vec<u8>, VaultError>`

Encrypt data using a named transit key. The raw key material is never exposed to the caller.

**Parameters:**
- `key_name` -- Name of the transit key to use.
- `plaintext` -- Data to encrypt.

**Returns:** Encrypted bytes (12-byte nonce + AES-256-GCM ciphertext).

**Errors:**
- `VaultError::SecretNotFound` -- Transit key does not exist.
- `VaultError::Encryption` -- Encryption failed.

---

#### `AegisVault::transit_decrypt(key_name: &str, ciphertext: &[u8]) -> Result<Vec<u8>, VaultError>`

Decrypt data using a named transit key.

**Parameters:**
- `key_name` -- Name of the transit key to use.
- `ciphertext` -- Data to decrypt (nonce + ciphertext as produced by `transit_encrypt`).

**Returns:** Decrypted plaintext bytes.

**Errors:**
- `VaultError::SecretNotFound` -- Transit key does not exist.
- `VaultError::Encryption` -- Decryption failed (wrong key or corrupted data).

---

#### `AegisVault::transit_create_key(name: &str) -> Result<(), VaultError>`

Create a new named transit encryption key. The key is a randomly generated 256-bit AES key.

**Parameters:**
- `name` -- Name for the new transit key.

**Errors:**
- `VaultError::AlreadyExists` -- A transit key with this name already exists.

---

#### `AegisVault::transit_list_keys() -> Vec<String>`

List all transit key names. Returns an empty vector if no transit keys have been created.

---

#### `AegisVault::audit_entries(limit: usize) -> Vec<VaultAuditEntry>`

Get the most recent audit log entries, ordered from newest to oldest.

**Parameters:**
- `limit` -- Maximum number of entries to return.

**Returns:** A `Vec<VaultAuditEntry>` where each entry contains:
```rust
pub struct VaultAuditEntry {
    pub timestamp: u64,
    pub operation: VaultOperation,  // Get, Set, Delete, List, Seal, Unseal, Rotate, TransitEncrypt, TransitDecrypt
    pub key: Option<String>,
    pub component: Option<String>,
    pub success: bool,
    pub detail: Option<String>,
}
```

---

## REST API Endpoints

All endpoints accept and return JSON. The base URL is `http://<host>:<port>`.

| Method | Path | Description | Request Body | Response |
|--------|------|-------------|--------------|----------|
| `GET` | `/health` | Health check | -- | `{"status":"ok","version":"0.2.2","sealed":false}` |
| `GET` | `/v1/status` | Vault status | -- | `{"sealed":false,"secret_count":5,"transit_key_count":2,"uptime_secs":3600}` |
| `GET` | `/v1/secrets/{key}` | Get a secret | Query: `?component=myapp` | `{"key":"db/password","value":"s3cret!"}` |
| `PUT` | `/v1/secrets/{key}` | Store a secret | `{"value":"s3cret!","component":"myapp"}` | `{"message":"secret stored","key":"db/password"}` |
| `DELETE` | `/v1/secrets/{key}` | Delete a secret | Query: `?component=myapp` | `{"message":"secret deleted","key":"db/password"}` |
| `GET` | `/v1/secrets` | List secrets | Query: `?prefix=db/&component=myapp` | `{"keys":["db/password","db/username"]}` |
| `POST` | `/v1/seal` | Seal the vault | -- | `{"sealed":true,"message":"vault sealed"}` |
| `POST` | `/v1/unseal` | Unseal the vault | `{"passphrase":"my-secret"}` | `{"sealed":false,"message":"vault unsealed"}` |
| `POST` | `/v1/transit/keys` | Create transit key | `{"name":"my-key"}` | `{"message":"transit key created","name":"my-key"}` |
| `GET` | `/v1/transit/keys` | List transit keys | -- | `{"keys":["my-key","other-key"]}` |
| `POST` | `/v1/transit/encrypt` | Encrypt data | `{"key_name":"my-key","plaintext":"hello"}` | `{"ciphertext":"vault:v1:base64..."}` |
| `POST` | `/v1/transit/decrypt` | Decrypt data | `{"key_name":"my-key","ciphertext":"vault:v1:base64..."}` | `{"plaintext":"hello"}` |
| `GET` | `/v1/audit` | Get audit log | Query: `?limit=50` | `{"entries":[...]}` |

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| `200` | Success |
| `201` | Created (secret stored, transit key created) |
| `401` | Unauthorized (invalid passphrase on unseal) |
| `403` | Forbidden (access control denied) |
| `404` | Not found (secret or transit key does not exist) |
| `409` | Conflict (transit key already exists) |
| `503` | Service unavailable (vault is sealed) |

### Error Response Format

All errors return a JSON body with an `error` field:

```json
{
  "error": "vault is sealed"
}
```

---

## Configuration Reference

### VaultConfig Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `data_dir` | `Option<PathBuf>` | `None` | Directory for vault persistence. If `None`, vault operates in-memory only. Files created: `vault.dat` (encrypted secrets), `vault.key` (encrypted master key). |
| `auto_unseal` | `bool` | `true` | Whether to automatically unseal on startup. If `true` and a passphrase is available, the vault unseals during initialization. |
| `passphrase` | `Option<String>` | `$AEGIS_VAULT_PASSPHRASE` | Passphrase for seal/unseal operations. Falls back to the `AEGIS_VAULT_PASSPHRASE` environment variable. If neither is set and auto-unseal is enabled, a random passphrase is generated (logged as a warning). |
| `max_versions` | `u32` | `10` | Maximum number of versions to retain per secret key. Older versions are pruned when this limit is exceeded. |
| `rotation_check_interval_secs` | `u64` | `3600` | Interval in seconds between automatic rotation TTL checks. Secrets with a `rotation_ttl_secs` metadata field that have exceeded their TTL will generate log warnings. |
| `audit_log_max_entries` | `usize` | `10000` | Maximum number of audit log entries to keep in memory. Oldest entries are evicted when this limit is reached. |

### CLI Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--port` | `-p` | `8200` | Port for the HTTP server |
| `--host` | | `127.0.0.1` | Host to bind to |
| `--data-dir` | `-d` | None | Data directory for persistence |
| `--passphrase` | | None | Vault passphrase (or set `NEXUSVAULT_PASSPHRASE` env var) |
| `--max-versions` | | `10` | Maximum secret versions per key |
| `--audit-log-max` | | `10000` | Maximum audit log entries |
| `--start-sealed` | | `false` | Start the vault in sealed state |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `NEXUSVAULT_PASSPHRASE` | Vault passphrase (alternative to `--passphrase` flag) |
| `AEGIS_VAULT_PASSPHRASE` | Vault passphrase (used by the `aegis-vault` library directly) |
| `RUST_LOG` | Log level filter (default: `info`). Examples: `debug`, `nexusvault=debug,aegis_vault=trace` |

---

## Security Model

### Key Derivation

The master encryption key is derived from the user-supplied passphrase using PBKDF2-HMAC-SHA256 with 100,000 iterations and a 16-byte cryptographically random salt. The derived key is 256 bits (32 bytes). The salt is stored alongside the encrypted master key blob, ensuring that the same passphrase produces different derived keys for different vault instances.

The derivation chain is:

```
passphrase (user input)
    |
    v
PBKDF2-HMAC-SHA256 (100,000 iterations, 16-byte random salt)
    |
    v
Derived Key (256-bit)
    |
    v
AES-256-GCM encrypt(Master Key)  -->  Encrypted Master Key Blob
    |                                   (stored in vault.key)
    v
Master Key (256-bit, random)
    |
    v
AES-256-GCM encrypt(secret values)  -->  Encrypted Secrets
                                          (stored in vault.dat)
```

### Encryption

All encryption uses AES-256-GCM (Galois/Counter Mode), which provides both confidentiality and authenticity. Each encryption operation generates a fresh 12-byte (96-bit) nonce from the OS cryptographic random number generator (`OsRng`). The ciphertext format is:

- **Master key blob:** `salt (16 bytes) || nonce (12 bytes) || ciphertext + tag`
- **Secret values:** `nonce (12 bytes) || ciphertext + tag`
- **Transit encryption:** `nonce (12 bytes) || ciphertext + tag`

AES-256-GCM provides a 128-bit authentication tag, ensuring that any tampering with the ciphertext is detected during decryption.

### Disk Persistence

When persistence is enabled, two files are written to the `data_dir`:

- **`vault.key`** -- The master key encrypted with the passphrase-derived key. Format: `salt (16) + nonce (12) + AES-256-GCM(master_key)`.
- **`vault.dat`** -- The entire secrets map serialized to JSON, then encrypted with the master key. Format: `nonce (12) + AES-256-GCM(json_blob)`.

Both files are written atomically using a temp-file-and-rename strategy to prevent corruption on crash.

### Access Control

The `AccessController` supports two modes:

- **Default-allow** (default): All operations are permitted unless explicitly denied by a policy. This is the default for backwards compatibility and development use.
- **Default-deny**: All operations are blocked unless a matching policy grants access. Recommended for production.

Policies specify:
- **Allowed components**: Which component names can use this policy (empty = all).
- **Allowed prefixes**: Which key prefixes this policy covers (empty = all).
- **Operations**: Read, write, delete permissions as booleans.

### Seal Lifecycle

The seal/unseal mechanism provides defense-in-depth:

1. **Sealed state**: The master key is `None` in memory. All encrypt/decrypt operations return `VaultError::Sealed`. The `MasterKey` struct's memory was zeroized when it was dropped.
2. **Unseal operation**: The passphrase is used to derive a key via PBKDF2, which decrypts the master key blob. The master key is loaded into memory and the vault transitions to unsealed state.
3. **Seal operation**: The master key is set to `None` and zeroized on drop. No passphrase is needed to seal.

The seal state does not affect the encrypted data on disk -- it only controls whether the master key is available in process memory.

### Memory Safety

- **Zeroization**: The `MasterKey` type implements `Drop` to zeroize the key bytes when the key is released. The `zeroize` crate is used, which prevents the compiler from optimizing away the zeroing write.
- **No unsafe code**: The vault implementation uses no `unsafe` blocks.
- **Concurrency**: All shared state is protected by `parking_lot::RwLock`, which provides reader-writer locking with no poisoning.

---

## Module Reference

| Module | File | Lines | Description |
|--------|------|-------|-------------|
| `lib` | `lib.rs` | 485 | Main `AegisVault` facade, `VaultStatus`, initialization logic |
| `master_key` | `master_key.rs` | 388 | `SealManager`, `MasterKey`, PBKDF2 key derivation, AES-256-GCM encrypt/decrypt |
| `store` | `store.rs` | 444 | `VaultStore` encrypted key-value storage, disk persistence, versioned get/set |
| `transit` | `transit.rs` | 201 | `TransitEngine` encryption-as-a-service with named keys |
| `access` | `access.rs` | 240 | `AccessController`, `AccessPolicy`, component-based access control |
| `config` | `config.rs` | 102 | `VaultConfig` with defaults, file path helpers, test config |
| `secret` | `secret.rs` | 151 | `Secret`, `SecretVersion`, `SecretMetadata`, version pruning |
| `audit` | `audit.rs` | 195 | `VaultAuditLog`, `VaultAuditEntry`, `VaultOperation`, bounded log |
| `error` | `error.rs` | 69 | `VaultError` enum with `thiserror` derives |
| `provider` | `provider.rs` | 102 | `AegisVaultProvider` simplified component-scoped wrapper |
| `rotation` | `rotation.rs` | 109 | Rotation TTL checking, async rotation loop |

---

## Comparison: NexusVault vs HashiCorp Vault

| Feature | NexusVault | HashiCorp Vault |
|---------|-----------|-----------------|
| **Language** | Rust | Go |
| **Deployment** | Single binary, embeddable | Separate server process, requires cluster |
| **Dependencies** | Zero runtime dependencies | Requires Consul or integrated storage |
| **Secret Storage** | AES-256-GCM encrypted KV | Multiple backends (KV, Consul, etc.) |
| **Transit Encryption** | Named AES-256-GCM keys | Named keys with multiple algorithms |
| **Seal/Unseal** | Single passphrase | Shamir's Secret Sharing (multiple keys) |
| **Key Derivation** | PBKDF2-HMAC-SHA256 (100K iterations) | Shamir + AES-256-GCM |
| **Access Control** | Component + prefix policies | Full ACL with paths, capabilities, tokens |
| **Audit Log** | In-memory bounded VecDeque | File, syslog, socket backends |
| **Secret Versioning** | Built-in, configurable retention | KV v2 engine |
| **Dynamic Secrets** | Not supported | Database, AWS, PKI, SSH, etc. |
| **Authentication** | Component identity | Tokens, AppRole, LDAP, OIDC, Kubernetes |
| **Replication** | Not built-in (use with Aegis-DB) | Integrated HA with Raft |
| **License** | Apache-2.0 | BSL 1.1 (source-available, not open-source) |
| **Resource Usage** | ~5 MB memory, instant startup | ~100 MB+ memory, slower startup |
| **Configuration** | Rust struct or CLI args | HCL files |
| **API** | REST/JSON | REST/JSON + CLI |
| **Namespaces** | Key prefixes | Enterprise-only feature |
| **Rotation** | TTL warnings + manual | Automated with lease management |
| **PKI/SSH** | Not supported | Full PKI and SSH certificate authority |

**When to use NexusVault:**
- You need a lightweight secrets manager embedded in your Rust application.
- You want a single binary with no external dependencies.
- Your use case is key-value secrets and transit encryption.
- You are already using Aegis-DB and want integrated secrets management.
- You need Apache-2.0 licensed software.

**When to use HashiCorp Vault:**
- You need dynamic secrets (database credentials, cloud IAM, PKI).
- You need multi-party unseal (Shamir's Secret Sharing).
- You need enterprise features (namespaces, sentinel policies, replication).
- You operate a large-scale multi-service infrastructure.
- You need integrated identity and authentication providers.

---

## Building from Source

### Prerequisites

- Rust 1.75 or later
- Cargo (included with Rust)

### Build

```bash
# Clone the repository
git clone https://github.com/automatanexus/NexusVault.git
cd NexusVault

# Build in debug mode
cargo build

# Build in release mode (optimized)
cargo build --release

# Run tests
cargo test

# Run the server
cargo run -- --port 8200 --data-dir ./data
```

### Build the aegis-vault library separately

If you want to use NexusVault as a library in your own Rust project, add the `aegis-vault` crate as a dependency:

```toml
[dependencies]
aegis-vault = { git = "https://github.com/automatanexus/Aegis-DB.git", version = "0.2.2" }
```

### Cross-compilation

```bash
# Linux x86_64 (musl for static linking)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# macOS ARM
rustup target add aarch64-apple-darwin
cargo build --release --target aarch64-apple-darwin
```

---

## Examples

### Storing Database Credentials

```bash
# Store credentials
curl -X PUT http://localhost:8200/v1/secrets/db/postgres/host \
  -H "Content-Type: application/json" \
  -d '{"value": "db.example.com", "component": "webapp"}'

curl -X PUT http://localhost:8200/v1/secrets/db/postgres/port \
  -H "Content-Type: application/json" \
  -d '{"value": "5432", "component": "webapp"}'

curl -X PUT http://localhost:8200/v1/secrets/db/postgres/password \
  -H "Content-Type: application/json" \
  -d '{"value": "super-secret-password", "component": "webapp"}'

# Retrieve all database secrets
curl "http://localhost:8200/v1/secrets?prefix=db/postgres/&component=webapp"
# {"keys":["db/postgres/host","db/postgres/port","db/postgres/password"]}
```

### Transit Encryption for User Data

```bash
# Create an encryption key for user PII
curl -X POST http://localhost:8200/v1/transit/keys \
  -H "Content-Type: application/json" \
  -d '{"name": "user-pii"}'

# Encrypt a social security number
curl -X POST http://localhost:8200/v1/transit/encrypt \
  -H "Content-Type: application/json" \
  -d '{"key_name": "user-pii", "plaintext": "123-45-6789"}'
# {"ciphertext":"vault:v1:BASE64_ENCODED_CIPHERTEXT"}

# Decrypt it back
curl -X POST http://localhost:8200/v1/transit/decrypt \
  -H "Content-Type: application/json" \
  -d '{"key_name": "user-pii", "ciphertext": "vault:v1:BASE64_ENCODED_CIPHERTEXT"}'
# {"plaintext":"123-45-6789"}
```

### Monitoring with the Audit Log

```bash
# Get the last 20 audit entries
curl "http://localhost:8200/v1/audit?limit=20"
# {
#   "entries": [
#     {
#       "timestamp": 1711234567,
#       "operation": "Set",
#       "key": "db/password",
#       "component": "webapp",
#       "success": true,
#       "detail": null
#     },
#     ...
#   ]
# }
```

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.

```
Copyright 2024-2026 AutomataNexus Development Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
