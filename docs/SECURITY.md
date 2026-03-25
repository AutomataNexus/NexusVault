# NexusVault Security Model

This document describes the cryptographic primitives, key management lifecycle, threat model, and security boundaries of NexusVault.

---

## Cryptographic Primitives

### AES-256-GCM

NexusVault uses AES-256-GCM (Galois/Counter Mode) as its sole symmetric encryption algorithm. AES-256-GCM is an authenticated encryption with associated data (AEAD) cipher that provides both confidentiality and integrity in a single operation.

**Properties:**
- **Key size:** 256 bits (32 bytes)
- **Nonce size:** 96 bits (12 bytes)
- **Authentication tag size:** 128 bits (16 bytes)
- **Mode:** Counter mode for encryption, GHASH for authentication

AES-256-GCM is implemented by the `aes-gcm` crate (version specified in Cargo.toml), which uses AES-NI hardware acceleration when available on x86/x86_64 processors. On platforms without AES-NI, a constant-time software implementation is used.

**Nonce generation:** Every encryption operation generates a fresh 12-byte nonce from the operating system's cryptographic random number generator (`OsRng` from the `rand` crate, backed by `getrandom`). Nonce reuse with the same key would be catastrophic for AES-GCM security, so NexusVault never reuses or derives nonces deterministically. With random 96-bit nonces, the probability of a nonce collision after 2^32 encryptions under the same key is approximately 2^-32, which is within the accepted safety margin defined by NIST SP 800-38D.

### PBKDF2-HMAC-SHA256

Key derivation from passphrases uses PBKDF2 (Password-Based Key Derivation Function 2) with HMAC-SHA256 as the pseudorandom function, implemented by the `ring` crate.

**Parameters:**
- **Algorithm:** PBKDF2-HMAC-SHA256
- **Iterations:** 100,000
- **Salt length:** 16 bytes (128 bits), cryptographically random
- **Output length:** 32 bytes (256 bits)

The iteration count of 100,000 is chosen to provide meaningful resistance against offline brute-force attacks while keeping unseal latency under 1 second on modern hardware. The salt is generated per-vault-instance using `OsRng` and stored in the encrypted key blob, ensuring that identical passphrases produce different derived keys for different vault instances.

**Key stretching chain:**
```
passphrase (UTF-8 bytes)
    + salt (16 random bytes)
    + iterations (100,000)
    |
    v
PBKDF2_HMAC_SHA256 --> derived_key (32 bytes)
```

The derived key is used exclusively to encrypt/decrypt the master key. It is never used directly to encrypt secret values.

### Random Number Generation

All random values (keys, nonces, salts, auto-generated passphrases) are sourced from `OsRng`, which delegates to the operating system's CSPRNG:
- **Linux:** `getrandom(2)` system call, falling back to `/dev/urandom`
- **macOS:** `SecRandomCopyBytes`
- **Windows:** `BCryptGenRandom`

---

## Key Hierarchy

NexusVault uses a two-tier key hierarchy:

```
Tier 0: Passphrase (user-provided or auto-generated)
    |
    | PBKDF2-HMAC-SHA256 (100K iterations, random salt)
    v
Tier 1: Derived Key (256-bit, ephemeral -- only in memory during unseal)
    |
    | AES-256-GCM decrypt
    v
Tier 2: Master Key (256-bit, random -- in memory while unsealed)
    |
    | AES-256-GCM encrypt/decrypt
    v
Secret Values (encrypted at rest and in the VaultStore HashMap)
```

**Transit keys** are independent of the master key hierarchy. Each transit key is a standalone 256-bit AES key generated from `OsRng`. Transit keys are currently held only in memory and are not persisted to disk. They are lost when the server process exits.

---

## Encrypted Key Blob Format

The master key is stored on disk in an encrypted blob with the following byte layout:

```
Offset  Length  Field
------  ------  -----
0       16      Salt (for PBKDF2 key derivation)
16      12      Nonce (for AES-256-GCM)
28      48      Ciphertext (32 bytes master key + 16 bytes GCM auth tag)
------  ------
Total:  76 bytes
```

The blob is stored in the file `<data_dir>/vault.key`.

---

## Encrypted Secrets Format

The secrets store is persisted as a single encrypted blob:

```
Offset  Length    Field
------  --------  -----
0       12        Nonce (for AES-256-GCM)
12      variable  Ciphertext (JSON-serialized secrets map + 16 bytes GCM auth tag)
```

The plaintext before encryption is a JSON object with the structure:
```json
{
  "secrets": {
    "key/path": {
      "key": "key/path",
      "versions": [
        {
          "version": 1,
          "encrypted_value": [/* bytes: nonce + AES-GCM ciphertext of the individual value */],
          "created_at": 1711234567,
          "created_by": "component-name",
          "expires_at": null
        }
      ],
      "metadata": {
        "key": "key/path",
        "current_version": 1,
        "created_at": 1711234567,
        "updated_at": 1711234567,
        "access_policy": null,
        "rotation_ttl_secs": null,
        "max_versions": 10
      }
    }
  }
}
```

Note the double encryption: individual secret values are encrypted with the master key when stored in the `VaultStore` (the `encrypted_value` field contains `nonce + ciphertext`), and then the entire JSON blob is encrypted again when persisted to disk. This means that even if the outer encryption were somehow broken, each individual secret value remains independently encrypted.

---

## Threat Model

### What NexusVault Protects Against

1. **Data at rest exposure:** If an attacker gains read access to the `vault.dat` and `vault.key` files, they cannot recover secret values without the passphrase. The master key is encrypted with a PBKDF2-derived key, and the secrets are encrypted with the master key.

2. **Memory exposure while sealed:** When the vault is sealed, the master key is zeroized from memory using the `zeroize` crate. An attacker who can read process memory (e.g., via `/proc/<pid>/mem` or a core dump) while the vault is sealed will not find the master key.

3. **Unauthorized component access:** The access control system can restrict which components can read, write, or delete specific secret prefixes, preventing lateral movement between application components.

4. **Disk corruption:** Atomic writes (temp file + rename) prevent partial writes from corrupting the vault data file. If the process crashes during a write, the previous intact file remains.

5. **Ciphertext tampering:** AES-256-GCM's authentication tag detects any modification to the ciphertext, nonce, or associated data. Tampered data will fail decryption with an error rather than producing incorrect plaintext.

### What NexusVault Does NOT Protect Against

1. **Memory exposure while unsealed:** While the vault is unsealed, the master key is held in plaintext in process memory. An attacker with the ability to read process memory (root access, ptrace, `/proc/<pid>/mem`, debugger attachment, or a memory-disclosure vulnerability in the application) can recover the master key. **Mitigation:** Run NexusVault as a dedicated process with restricted permissions. Use `prctl(PR_SET_DUMPABLE, 0)` on Linux to disable core dumps. Consider using memory locking (`mlock`) for production deployments.

2. **Passphrase brute-force with physical access:** An attacker who obtains the `vault.key` file can attempt offline brute-force of the passphrase. With 100,000 PBKDF2 iterations, a modern GPU can test approximately 100,000-500,000 passphrases per second. A 20-character random passphrase provides sufficient entropy to resist this attack; a short or dictionary-based passphrase does not. **Mitigation:** Use a strong, random passphrase of at least 20 characters.

3. **Side-channel attacks:** NexusVault does not implement countermeasures against timing attacks, power analysis, or electromagnetic emanation analysis beyond what the underlying `aes-gcm` and `ring` crates provide. The `aes-gcm` crate uses constant-time operations for the AES core, but the surrounding Rust code (HashMap lookups, string comparisons) may leak timing information. **Mitigation:** Deploy on hardware with AES-NI support and in environments where side-channel attacks are not a realistic threat.

4. **Compromised host operating system:** If the OS is compromised (kernel rootkit, malicious kernel module), all bets are off. The attacker can read process memory, intercept system calls, and modify the random number generator. **Mitigation:** Harden the host OS, keep it patched, use SELinux/AppArmor.

5. **Supply chain attacks:** NexusVault depends on third-party Rust crates (`aes-gcm`, `ring`, `parking_lot`, `serde`, etc.). A compromised dependency could exfiltrate secrets. **Mitigation:** Pin dependency versions, audit `Cargo.lock`, use `cargo-audit` to check for known vulnerabilities.

6. **Network-level attacks:** The REST API supports native TLS via rustls (`--tls-cert` and `--tls-key` flags). Without TLS, an attacker on the network path can intercept secret values in transit. **Mitigation:** Enable TLS with `--tls-cert` and `--tls-key`, or deploy behind a TLS-terminating reverse proxy (e.g., nginx, Caddy).

7. **Denial of service:** The `/v1/unseal` endpoint is rate-limited (5 attempts per 60-second window) to prevent brute-force attacks. Other endpoints do not have built-in rate limiting. **Mitigation:** Deploy behind a rate-limiting reverse proxy for comprehensive protection.

8. **Authentication:** The REST API requires bearer token authentication (`Authorization: Bearer <api-key>`) for all `/v1/*` endpoints. The API key is configured via `--api-key` or `NEXUSVAULT_API_KEY`. When authenticated, component identity is bound to the API key via `--component-name`, preventing self-reported identity spoofing. **Mitigation:** Always use `--api-key` in production (the server refuses to start without it unless `--no-auth` is explicitly set).

9. **Error information disclosure:** API error responses for encryption, IO, and internal errors return generic messages ("internal server error") rather than raw error details. Detailed error information is logged server-side only.

---

## Seal/Unseal Security Properties

| State | Master Key in Memory | Operations Available | Disk Files |
|-------|---------------------|---------------------|------------|
| **Sealed** | No (zeroized) | `unseal`, `is_sealed`, `status` only | `vault.key` and `vault.dat` remain encrypted on disk |
| **Unsealed** | Yes (plaintext) | All operations | Same files, updated on mutations |

The seal operation:
1. Sets the master key `Option` to `None`.
2. The previous `MasterKey` value is dropped, triggering `Zeroize::zeroize()` which overwrites the 32-byte key array with zeros.
3. The `SealStatus` is set to `Sealed`.

The unseal operation:
1. Reads the encrypted key blob from memory (loaded from `vault.key` on startup).
2. Derives the decryption key from the passphrase using PBKDF2 (100K iterations).
3. Decrypts the master key using AES-256-GCM.
4. Stores the master key in memory and sets `SealStatus` to `Unsealed`.
5. Loads and decrypts the secrets from `vault.dat`.

---

## Recommendations for Production Deployment

1. **Use a strong passphrase:** At least 20 characters, randomly generated. Store it in a secure location (e.g., a hardware security module, a separate secrets manager, or an encrypted file accessible only during deployment).

2. **Always use API key authentication:** Set `--api-key` (or `NEXUSVAULT_API_KEY`). The server refuses to start without it unless `--no-auth` is explicitly passed. Never use `--no-auth` in production.

3. **Enable TLS:** Use `--tls-cert` and `--tls-key` for native HTTPS support, or deploy behind a TLS-terminating reverse proxy. Without TLS, secrets and the passphrase are transmitted in cleartext.

4. **Start sealed in production:** Use `--start-sealed` and implement an operational procedure for unsealing (e.g., a human operator or an automated unsealing service).

5. **Restrict network access:** Bind to `127.0.0.1` and access only via localhost or a secure tunnel. Do not expose the API to the public internet without TLS and authentication.

6. **Core dumps are disabled automatically:** NexusVault calls `prctl(PR_SET_DUMPABLE, 0)` on Linux at startup. For additional protection, configure `/proc/sys/kernel/core_pattern` to discard cores.

7. **File permissions are set automatically:** All vault files (`vault.key`, `vault.dat`, `transit.dat`, `audit.log`) are created with `0600` permissions (owner-only read/write) on Unix systems.

8. **Monitor the audit log:** The audit log is persisted to `audit.log` as JSON lines when `data_dir` is configured. Monitor for failed operations, especially failed unseal attempts (rate-limited to 5 per 60 seconds).

9. **Rotate the passphrase periodically:** To rotate the passphrase, unseal with the current passphrase, re-initialize with a new passphrase (this re-encrypts the master key), and seal.

10. **Keep dependencies updated:** Run `cargo audit` regularly and update dependencies when security patches are released.

11. **Backup strategy:** Back up `vault.key`, `vault.dat`, and `transit.dat` together. All files are required to restore the vault. The passphrase is also required -- without it, the backup is useless.
