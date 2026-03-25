# NexusVault REST API Reference

Base URL: `http://<host>:<port>` (default: `http://127.0.0.1:8200`), or `https://` when TLS is enabled.

All `/v1/*` endpoints require authentication via the `Authorization: Bearer <api-key>` header (unless `--no-auth` is used). The `/health` endpoint is always unauthenticated.

All request and response bodies use JSON (`Content-Type: application/json`).

---

## Health & Status

### GET /health

Returns the server health status, version, and seal state. This endpoint always succeeds, even when the vault is sealed.

**Request:**
```bash
curl http://localhost:8200/health
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "version": "0.2.3",
  "sealed": false
}
```

---

### GET /v1/status

Returns detailed vault status information including secret count, transit key count, and uptime since last unseal.

**Request:**
```bash
curl http://localhost:8200/v1/status
```

**Response (200 OK):**
```json
{
  "sealed": false,
  "secret_count": 12,
  "transit_key_count": 3,
  "uptime_secs": 86412
}
```

When sealed, `uptime_secs` is `null` and `secret_count` reflects the count from before sealing.

---

## Secrets

### GET /v1/secrets/{key}

Retrieve the current (latest version) value of a secret.

**Path parameters:**
- `key` -- The secret key path. Use URL encoding for keys with special characters.

**Query parameters:**
- `component` (optional, default: `"api"`) -- The requesting component name for access control.

**Request:**
```bash
# Simple key
curl "http://localhost:8200/v1/secrets/db_password?component=webapp"

# Hierarchical key (URL-encoded slashes)
curl "http://localhost:8200/v1/secrets/db%2Fpostgres%2Fpassword?component=webapp"
```

**Response (200 OK):**
```json
{
  "key": "db/postgres/password",
  "value": "super-secret-password"
}
```

**Error responses:**

- **404 Not Found** -- Secret does not exist:
  ```json
  {"error": "secret not found: db/postgres/password"}
  ```

- **503 Service Unavailable** -- Vault is sealed:
  ```json
  {"error": "vault is sealed"}
  ```

- **403 Forbidden** -- Access denied:
  ```json
  {"error": "access denied: component 'webapp' is not allowed to Read key 'admin/master_key'"}
  ```

---

### PUT /v1/secrets/{key}

Store a secret value. If the key already exists, a new version is created. If `data_dir` is configured, the vault data is persisted to disk.

**Path parameters:**
- `key` -- The secret key path.

**Request body:**
- `value` (required) -- The plaintext secret value.
- `component` (optional, default: `"api"`) -- The requesting component name.

**Request:**
```bash
curl -X PUT http://localhost:8200/v1/secrets/db%2Fpassword \
  -H "Content-Type: application/json" \
  -d '{"value": "new-password-v2", "component": "webapp"}'
```

**Response (201 Created):**
```json
{
  "message": "secret stored",
  "key": "db/password"
}
```

**Error responses:**

- **503 Service Unavailable** -- Vault is sealed:
  ```json
  {"error": "vault is sealed"}
  ```

- **403 Forbidden** -- Access denied for write operation.

---

### DELETE /v1/secrets/{key}

Delete a secret and all its versions. This operation is irreversible.

**Path parameters:**
- `key` -- The secret key path.

**Query parameters:**
- `component` (optional, default: `"api"`) -- The requesting component name.

**Request:**
```bash
curl -X DELETE "http://localhost:8200/v1/secrets/db%2Fpassword?component=webapp"
```

**Response (200 OK):**
```json
{
  "message": "secret deleted",
  "key": "db/password"
}
```

**Error responses:**

- **404 Not Found** -- Secret does not exist.
- **503 Service Unavailable** -- Vault is sealed.
- **403 Forbidden** -- Access denied for delete operation.

---

### GET /v1/secrets

List secret keys matching a prefix.

**Query parameters:**
- `prefix` (optional, default: `""`) -- Key prefix to filter by. Empty string lists all keys.
- `component` (optional, default: `"api"`) -- The requesting component name.

**Request:**
```bash
# List all secrets
curl "http://localhost:8200/v1/secrets?component=webapp"

# List secrets under db/ prefix
curl "http://localhost:8200/v1/secrets?prefix=db/&component=webapp"

# List secrets under a specific application
curl "http://localhost:8200/v1/secrets?prefix=myapp/prod/&component=deployer"
```

**Response (200 OK):**
```json
{
  "keys": [
    "db/postgres/host",
    "db/postgres/port",
    "db/postgres/password",
    "db/postgres/username"
  ]
}
```

**Error responses:**

- **503 Service Unavailable** -- Vault is sealed.
- **403 Forbidden** -- Access denied for list operation.

---

## Seal Management

### POST /v1/seal

Seal the vault. The master encryption key is zeroized from memory. All subsequent operations that require encryption or decryption will return 503 until the vault is unsealed.

No request body is required.

**Request:**
```bash
curl -X POST http://localhost:8200/v1/seal
```

**Response (200 OK):**
```json
{
  "sealed": true,
  "message": "vault sealed"
}
```

---

### POST /v1/unseal

Unseal the vault with a passphrase. The passphrase is used to derive the master key via PBKDF2-HMAC-SHA256, which then decrypts the stored master key blob. Persisted secrets are reloaded from disk.

**Request body:**
- `passphrase` (required) -- The vault passphrase.

**Request:**
```bash
curl -X POST http://localhost:8200/v1/unseal \
  -H "Content-Type: application/json" \
  -d '{"passphrase": "my-secure-passphrase"}'
```

**Response (200 OK):**
```json
{
  "sealed": false,
  "message": "vault unsealed"
}
```

**Error responses:**

- **401 Unauthorized** -- Invalid passphrase:
  ```json
  {"error": "invalid passphrase"}
  ```

- **500 Internal Server Error** -- No encrypted key blob available (vault was never initialized with a passphrase):
  ```json
  {"error": "vault error: no encrypted key blob available"}
  ```

---

## Transit Encryption

The transit engine provides encryption-as-a-service. Applications can create named encryption keys and use them to encrypt/decrypt data without ever accessing the raw key material.

### POST /v1/transit/keys

Create a new named transit encryption key. The key is a randomly generated 256-bit AES key.

**Request body:**
- `name` (required) -- Name for the transit key.

**Request:**
```bash
curl -X POST http://localhost:8200/v1/transit/keys \
  -H "Content-Type: application/json" \
  -d '{"name": "user-data-key"}'
```

**Response (201 Created):**
```json
{
  "message": "transit key created",
  "name": "user-data-key"
}
```

**Error responses:**

- **409 Conflict** -- A transit key with this name already exists:
  ```json
  {"error": "secret already exists: transit key 'user-data-key'"}
  ```

---

### GET /v1/transit/keys

List all transit key names.

**Request:**
```bash
curl http://localhost:8200/v1/transit/keys
```

**Response (200 OK):**
```json
{
  "keys": [
    "user-data-key",
    "payment-key",
    "session-key"
  ]
}
```

---

### POST /v1/transit/encrypt

Encrypt plaintext data using a named transit key. The response contains the ciphertext in a prefixed base64 format: `vault:v1:<base64>`.

**Request body:**
- `key_name` (required) -- Name of the transit key to use.
- `plaintext` (required) -- The plaintext string to encrypt.

**Request:**
```bash
curl -X POST http://localhost:8200/v1/transit/encrypt \
  -H "Content-Type: application/json" \
  -d '{"key_name": "user-data-key", "plaintext": "123-45-6789"}'
```

**Response (200 OK):**
```json
{
  "ciphertext": "vault:v1:dGhpcyBpcyBiYXNlNjQgZW5jb2RlZCBjaXBoZXJ0ZXh0..."
}
```

**Error responses:**

- **404 Not Found** -- Transit key does not exist:
  ```json
  {"error": "secret not found: transit key 'nonexistent-key'"}
  ```

---

### POST /v1/transit/decrypt

Decrypt ciphertext using a named transit key. Accepts the `vault:v1:<base64>` format produced by the encrypt endpoint, or raw base64.

**Request body:**
- `key_name` (required) -- Name of the transit key to use.
- `ciphertext` (required) -- The ciphertext to decrypt (with or without `vault:v1:` prefix).

**Request:**
```bash
curl -X POST http://localhost:8200/v1/transit/decrypt \
  -H "Content-Type: application/json" \
  -d '{"key_name": "user-data-key", "ciphertext": "vault:v1:dGhpcyBpcyBiYXNlNjQgZW5jb2RlZCBjaXBoZXJ0ZXh0..."}'
```

**Response (200 OK):**
```json
{
  "plaintext": "123-45-6789"
}
```

**Error responses:**

- **404 Not Found** -- Transit key does not exist.
- **500 Internal Server Error** -- Decryption failed (wrong key, corrupted ciphertext, or invalid base64):
  ```json
  {"error": "encryption error: aead::Error"}
  ```

---

## Audit Log

### GET /v1/audit

Retrieve recent audit log entries, ordered from newest to oldest.

**Query parameters:**
- `limit` (optional, default: `50`) -- Maximum number of entries to return.

**Request:**
```bash
# Get last 10 entries
curl "http://localhost:8200/v1/audit?limit=10"

# Get default (50 entries)
curl http://localhost:8200/v1/audit
```

**Response (200 OK):**
```json
{
  "entries": [
    {
      "timestamp": 1711234590,
      "operation": "Get",
      "key": "db/password",
      "component": "webapp",
      "success": true,
      "detail": null
    },
    {
      "timestamp": 1711234580,
      "operation": "Set",
      "key": "db/password",
      "component": "webapp",
      "success": true,
      "detail": null
    },
    {
      "timestamp": 1711234570,
      "operation": "Get",
      "key": "admin/secret",
      "component": "unauthorized",
      "success": false,
      "detail": "vault is sealed"
    },
    {
      "timestamp": 1711234560,
      "operation": "Unseal",
      "key": null,
      "component": "system",
      "success": true,
      "detail": null
    }
  ]
}
```

**Operation types:**
| Operation | Description |
|-----------|-------------|
| `Get` | Secret read |
| `Set` | Secret write (create or update version) |
| `Delete` | Secret deletion |
| `List` | Secret key listing |
| `Seal` | Vault was sealed |
| `Unseal` | Vault was unsealed |
| `Rotate` | Secret rotation check |
| `TransitEncrypt` | Transit encryption operation |
| `TransitDecrypt` | Transit decryption operation |

---

## Complete Workflow Example

This example demonstrates a complete session: checking health, storing secrets, using transit encryption, reviewing the audit log, and sealing/unsealing the vault.

```bash
#!/bin/bash
BASE="http://localhost:8200"

# 1. Check vault health
echo "=== Health Check ==="
curl -s "$BASE/health" | jq .

# 2. Check status
echo "=== Vault Status ==="
curl -s "$BASE/v1/status" | jq .

# 3. Store database credentials
echo "=== Storing Secrets ==="
curl -s -X PUT "$BASE/v1/secrets/myapp%2Fdb%2Fhost" \
  -H "Content-Type: application/json" \
  -d '{"value": "db.prod.internal", "component": "deployer"}' | jq .

curl -s -X PUT "$BASE/v1/secrets/myapp%2Fdb%2Fpassword" \
  -H "Content-Type: application/json" \
  -d '{"value": "pr0d-p@ssw0rd!", "component": "deployer"}' | jq .

# 4. Retrieve a secret
echo "=== Get Secret ==="
curl -s "$BASE/v1/secrets/myapp%2Fdb%2Fpassword?component=deployer" | jq .

# 5. List secrets
echo "=== List Secrets ==="
curl -s "$BASE/v1/secrets?prefix=myapp/&component=deployer" | jq .

# 6. Create a transit key and encrypt data
echo "=== Transit Encryption ==="
curl -s -X POST "$BASE/v1/transit/keys" \
  -H "Content-Type: application/json" \
  -d '{"name": "pii-key"}' | jq .

ENCRYPTED=$(curl -s -X POST "$BASE/v1/transit/encrypt" \
  -H "Content-Type: application/json" \
  -d '{"key_name": "pii-key", "plaintext": "SSN: 123-45-6789"}' | jq -r .ciphertext)

echo "Encrypted: $ENCRYPTED"

# 7. Decrypt it back
echo "=== Transit Decryption ==="
curl -s -X POST "$BASE/v1/transit/decrypt" \
  -H "Content-Type: application/json" \
  -d "{\"key_name\": \"pii-key\", \"ciphertext\": \"$ENCRYPTED\"}" | jq .

# 8. Review audit log
echo "=== Audit Log ==="
curl -s "$BASE/v1/audit?limit=5" | jq .

# 9. Seal the vault
echo "=== Seal Vault ==="
curl -s -X POST "$BASE/v1/seal" | jq .

# 10. Verify operations fail while sealed
echo "=== Attempt Read While Sealed ==="
curl -s "$BASE/v1/secrets/myapp%2Fdb%2Fpassword?component=deployer" | jq .
# Expected: {"error": "vault is sealed"}

# 11. Unseal the vault
echo "=== Unseal Vault ==="
curl -s -X POST "$BASE/v1/unseal" \
  -H "Content-Type: application/json" \
  -d '{"passphrase": "your-passphrase-here"}' | jq .

# 12. Verify access is restored
echo "=== Read After Unseal ==="
curl -s "$BASE/v1/secrets/myapp%2Fdb%2Fpassword?component=deployer" | jq .

# 13. Delete a secret
echo "=== Delete Secret ==="
curl -s -X DELETE "$BASE/v1/secrets/myapp%2Fdb%2Fhost?component=deployer" | jq .

# 14. Final status
echo "=== Final Status ==="
curl -s "$BASE/v1/status" | jq .
```
