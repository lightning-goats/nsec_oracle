# Nsec Oracle

A server-side Nostr **signing oracle** for [LNbits](https://github.com/lnbits/lnbits). Nsec Oracle keeps Nostr private keys on your instance and lets other LNbits extensions — and admin-key API clients — sign events and encrypt/decrypt messages through per-key, per-kind permissions with rate limits and an audit log, without ever exposing the key.

> **Scope:** Nsec Oracle is for **in-instance signing** — extensions and API clients that run on your LNbits. It is *not* a relay-facing remote signer for external Nostr apps. To serve external clients over `bunker://` / `nostrconnect://`, use the dedicated [`nostr_bunker`](https://github.com/lnbits/nostr_bunker) extension; the two are complementary.

## Use Cases

- **Centralized key management** -- Keep one (or several) Nostr identities on your LNbits instance instead of pasting nsecs into every extension that needs to publish events.
- **Extension signing oracle** -- Extensions like CyberHerd, Split Payments, or LNURLp request signing through the oracle's internal Python API. They never see the private key.
- **External API consumer** -- Any HTTP client with a valid admin wallet key can call the REST endpoints to sign events or encrypt/decrypt messages; invoice wallet keys can retrieve public keys.
- **NIP-04 / NIP-44 encrypted messaging** -- Encrypt and decrypt direct messages without exposing keys to the calling application.
- **Key backup and migration** -- Export a key as hex or nsec via the admin-only export endpoint, then import it on another instance.
- **Multi-wallet isolation** -- Each LNbits wallet has its own independent set of keys and permissions, so different projects or users on the same instance stay separated.

## Quick Start

1. Enable the **Nsec Oracle** extension in your LNbits instance.
2. Open the extension UI and select a wallet.
3. **Generate** a new keypair or **Import** an existing nsec / hex private key.
4. Optionally add a **label** to the key for easier identification.
5. Use **Quick Setup** to grant permissions to other installed extensions that declare Nostr signing requirements, or add permissions manually.

Keys are encrypted at rest using the LNbits server secret. The plaintext private key only exists in memory for the brief moment required to sign or encrypt.

## API Reference

All endpoints are prefixed with `/nsec_oracle`. Authentication uses LNbits wallet keys passed in the `X-Api-Key` header.

### Keys (admin key required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/keys` | Import a key (`private_key`, optional `label`) |
| `POST` | `/api/v1/keys/generate` | Generate a new random keypair |
| `GET` | `/api/v1/keys` | List all keys (secrets stripped) |
| `PUT` | `/api/v1/keys/{key_id}` | Update key label |
| `DELETE` | `/api/v1/keys/{key_id}` | Delete key and its permissions |
| `GET` | `/api/v1/keys/{key_id}/export` | Export private key as hex and nsec |

### Public Key (invoice key)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/pubkey?key_id=` | Get public key hex (defaults to wallet's first key) |

### Signing (admin key)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/sign` | Sign a Nostr event (requires matching permission) |

Request body:
```json
{
  "extension_id": "cyberherd",
  "key_id": "abc123",
  "event": {
    "kind": 1,
    "content": "Hello Nostr!",
    "tags": []
  }
}
```

### NIP-04 Encrypt / Decrypt (admin key)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/nip04/encrypt` | NIP-04 encrypt a plaintext message |
| `POST` | `/api/v1/nip04/decrypt` | NIP-04 decrypt a ciphertext message |

Request body (encrypt):
```json
{
  "key_id": "abc123",
  "pubkey": "<recipient hex or npub>",
  "plaintext": "secret message"
}
```

Request body (decrypt):
```json
{
  "key_id": "abc123",
  "pubkey": "<sender hex or npub>",
  "ciphertext": "<NIP-04 ciphertext>"
}
```

### NIP-44 Encrypt / Decrypt (admin key)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/nip44/encrypt` | NIP-44 v2 encrypt a plaintext message |
| `POST` | `/api/v1/nip44/decrypt` | NIP-44 decrypt a payload |

Request body (encrypt):
```json
{
  "key_id": "abc123",
  "pubkey": "<recipient hex or npub>",
  "plaintext": "secret message"
}
```

Request body (decrypt):
```json
{
  "key_id": "abc123",
  "pubkey": "<sender hex or npub>",
  "payload": "<NIP-44 payload>"
}
```

NIP-44 endpoints require the `nostr_sdk` Python package to be installed.

### Permissions (admin key)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/permissions` | Grant a signing permission |
| `GET` | `/api/v1/permissions` | List all permissions |
| `PUT` | `/api/v1/permissions/{id}` | Update or clear a positive count/seconds rate-limit pair |
| `DELETE` | `/api/v1/permissions/{id}` | Revoke a permission |

### Discovery & Quick Setup (admin key)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/discover` | List extensions that declare `nostr_signing` in their `config.json` |
| `POST` | `/api/v1/quick-setup` | Grant all required permissions for an extension in one call |

### Signing Log (admin key)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/log?offset=0&limit=50` | Paginated signing audit log |

Returns `{"data": [...], "total": N}`.

## Internal Python API

Other LNbits extensions can call the oracle directly without going through HTTP:

```python
from lnbits.extensions.nsec_oracle.services import sign_event

signed = await sign_event(
    wallet_id="...",
    extension_id="myextension",
    unsigned_event={"kind": 1, "content": "Hello", "tags": []},
    key_id="abc123",
)
```

The `key_id` field is optional and defaults to the wallet's newest permitted key. Supplying it is recommended for wallets with multiple keys.

The same pattern works for `nip04_encrypt`, `nip04_decrypt`, `nip44_encrypt`, `nip44_decrypt`, and `get_wallet_pubkey`.

## Extension Discovery

Extensions can declare their signing needs in `config.json` so that Nsec Oracle's Quick Setup can detect them automatically:

```json
{
  "name": "My Extension",
  "nostr_signing": [
    {
      "kind": 1,
      "kind_label": "Short Text Note",
      "description": "Publish notes on behalf of the user.",
      "required": true,
      "recommended_rate_limit": {"count": 100, "seconds": 86400}
    }
  ]
}
```

## Background Tasks

A log cleanup task runs hourly and removes signing log entries older than 30 days.

## Security Model

- Private keys are encrypted at rest using `encrypt_internal_message()` (LNbits server secret + AES).
- The plaintext key is only held in memory during a sign/encrypt/decrypt operation.
- **Admin key** is required to manage keys, permissions, and view logs.
- **Admin key** is required for signing and encrypt/decrypt REST operations. Invoice keys can retrieve public keys only.
- Each wallet's keys and permissions are fully isolated from other wallets.
- The export endpoint is admin-key-only and is intended for backup purposes.
- Signing is gated by per-extension, per-kind permissions with optional rate limits.
