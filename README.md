# botnet

An open protocol and registry for verifiable AI bot identities.

Botnet gives every AI agent a cryptographically-bound identity — a deterministic ID derived from its public key, a signed record in a public registry, and a policy engine that governs who can act on its behalf. No bearer tokens, no shared secrets. Every mutation is authorized by Ed25519 proof.

**Live registry:** [botnet.pub](https://botnet.pub)

## Why

AI agents are proliferating. They send emails, write code, manage infrastructure, and talk to each other. But there's no standard way to answer basic questions about them:

- **Who operates this bot?** No verifiable link between a bot and its owner.
- **Is this bot still active?** No lifecycle management or revocation.
- **Can this bot do what it claims?** No capability declarations or attestations.
- **Who authorized this action?** No cryptographic proof chain.

Botnet is a minimal, opinionated answer: a public registry where bot identities are created, updated, and revoked using signed payloads — never bearer tokens.

## Core concepts

**Bot ID** — A deterministic identifier derived from a public key: `urn:bot:sha256:{hex(SHA-256(pk))}`. The same key always produces the same ID. No central authority assigns them.

**Bot Record** — The identity document for a bot. Contains its public keys, owner info, capabilities, endpoints, controller relationships, and lifecycle status (`active`, `deprecated`, `revoked`).

**Proof** — Every mutation (register, update, revoke, key rotation) must include a JWS signature over the JCS-canonicalized request payload. The registry verifies the signature against the bot's registered keys before accepting any change.

**Policy** — Optional m-of-n threshold rules per operation. A bot can require, for example, 2-of-3 signers to rotate a key or 3-of-5 to revoke the identity entirely. Signers can be the bot's own keys or keys belonging to controller bots.

**Attestation** — A signed statement one bot makes about another. Attestations are first-class objects in the registry with issuer verification, expiration, and structured claims.

**Controller** — A bot-to-bot delegation relationship. A controller bot can be granted specific permissions (key management, updates) over another bot, enabling hierarchical trust models.

## Install

```sh
curl -fsSL https://botnet.pub/install.sh | sh
```

Or pin a version:

```sh
BOTNET_VERSION=botnet-v0.1.0 curl -fsSL https://botnet.pub/install.sh | sh
```

## Quick start

Register a bot identity interactively (generates keys, prompts for name/description):

```sh
botnet --base-url https://botnet.pub/v1 register
```

Or register from a JSON file with explicit credentials:

```sh
# Generate an Ed25519 keypair (64-char hex seed)
SEED=$(openssl rand -hex 32)

# Register from a JSON record
botnet --base-url https://botnet.pub/v1 \
  --key-id my-key \
  --secret-seed-hex "$SEED" \
  register bot.json
```

Query the registry:

```sh
# Search for bots
botnet --base-url https://botnet.pub/v1 search --q "my-bot" --limit 10

# Fetch a specific bot
botnet --base-url https://botnet.pub/v1 get urn:bot:sha256:abc123...
```

Manage keys:

```sh
# Rotate a key
botnet rotate-key <bot_id> new-key.json

# Revoke a key
botnet remove-key <bot_id> <key_id> --reason "compromised"

# Revoke the entire identity
botnet revoke-bot <bot_id> --reason "decommissioned"
```

## API

All endpoints are available at `https://botnet.pub/v1`. Full interactive docs at [botnet.pub/swagger](https://botnet.pub/swagger).

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/v1/bots` | proof | Register a new bot |
| `GET` | `/v1/bots/{bot_id}` | — | Fetch a bot record |
| `PATCH` | `/v1/bots/{bot_id}` | proof | Update a bot record |
| `POST` | `/v1/bots/{bot_id}/keys` | proof | Add a public key |
| `DELETE` | `/v1/bots/{bot_id}/keys/{key_id}` | proof | Revoke a key |
| `POST` | `/v1/bots/{bot_id}/keys/rotate` | proof | Rotate a key |
| `POST` | `/v1/bots/{bot_id}/revoke` | proof | Revoke a bot |
| `POST` | `/v1/attestations` | signature | Publish an attestation |
| `GET` | `/v1/search` | — | Search bots |
| `GET` | `/v1/nonce` | — | Get anti-replay nonce |
| `GET` | `/v1/stats` | — | Registry statistics |

Auth model: mutation endpoints require a `proof` (single JWS) or `proof_set` (m-of-n threshold JWS) field in the request body. The server verifies signatures against the bot's registered keys and evaluates policy thresholds. No bearer tokens, no API keys.

## Auth model

```
Client                                  Registry
  |                                        |
  |  1. GET /v1/nonce                      |
  |--------------------------------------->|
  |<--- { nonce: "abc123" }                |
  |                                        |
  |  2. Build payload (JSON)               |
  |  3. JCS-canonicalize payload           |
  |  4. Sign canonical bytes (Ed25519)     |
  |  5. Attach JWS as `proof` field        |
  |                                        |
  |  POST /v1/bots  { ...payload, proof }  |
  |--------------------------------------->|
  |     6. Strip proof, re-canonicalize    |
  |     7. Verify JWS against bot's keys   |
  |     8. Check nonce (anti-replay)       |
  |     9. Evaluate policy thresholds      |
  |<--- 201 Created                        |
```

For multi-signature operations, include a `proof_set` array instead of `proof`. Each entry references a `key_ref` with `key_id` and optional `controller_bot_id`.

## Architecture

```
crates/
  identity-core/       Core types, bot ID derivation, validation
  identity-crypto/     Ed25519 JWS signing and verification
  identity-policy/     m-of-n threshold policy evaluation
  identity-storage/    Storage trait + SQLite, PostgreSQL, in-memory backends
  identity-server/     Axum HTTP API server
  identity-cli/        CLI client (botnet)
  identity-sdk/        Native Rust SDK
  identity-web/        WebAssembly SDK for browsers
```

## Development

```sh
# Run the server (defaults to SQLite)
cargo run -p identity-server

# Run with in-memory storage
STORAGE_BACKEND=memory cargo run -p identity-server

# Run tests
cargo test --workspace

# Lint
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
```

## License

MIT
