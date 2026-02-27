# AI Bot Identity Registry (Rust Workspace)

Bootstrap workspace for an AI Bot Identity Registry with:
- Axum server (`identity-server`)
- CLI (`identity-cli`)
- Native Rust SDK (`identity-sdk`)
- WebAssembly SDK (`identity-web`)
- Shared core/crypto/policy/storage crates

Hosted UI/API entrypoints (when deployed to `botnet.pub`):
- `/` live homepage with registry stats + quickstart
- `/v1` API root
- `/v1/stats` registry counts
- `/docs` docs index with `/docs/api` and `/docs/cli`
- `/openapi.json`, `/swagger` machine-readable + interactive API docs
- `/install.sh` install helper for `botnet`

## Quick start

```bash
cargo run -p identity-server
```

The server defaults to SQLite persistence:
- `STORAGE_BACKEND=sqlite`
- `DATABASE_URL=sqlite:///opt/botid/identity-registry.sqlite3`

For local ephemeral runs, set `STORAGE_BACKEND=memory`.

In another terminal:

```bash
cargo run -p identity-cli -- --help
```

Install CLI from GitHub Releases (after first `botnet-v*` release is published):

```bash
curl -fsSL https://raw.githubusercontent.com/botnetdotpub/botnet.pub/main/install.sh | sh
```

Pin a version:

```bash
BOTNET_VERSION=botnet-v0.1.0 curl -fsSL https://raw.githubusercontent.com/botnetdotpub/botnet.pub/main/install.sh | sh
```

## Common commands

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Releasing `botnet`

Create and push a tag to publish CLI binaries to GitHub Releases:

```bash
git tag botnet-v0.1.0
git push origin botnet-v0.1.0
```

Release workflow: `.github/workflows/botnet-release.yml`

CI/deploy note:
- GitHub Actions uses `rust-cache` so dependency/build artifacts can be reused across runs.
- A dedicated tag workflow (`.github/workflows/botnet-release.yml`) publishes `botnet` release archives.

## Storage backends

`identity-storage` now has three options:
- `SqliteStore` (default feature): no external database required.
- `PostgresStore` (optional feature): enable with `--features postgres`.
- `MemoryStore`: in-memory mock/test backend (idiomatic for fast unit tests).

Examples:

```bash
# default (sqlite + memory)
cargo test -p identity-storage

# postgres backend enabled
cargo test -p identity-storage --no-default-features --features postgres
```

## Deploy on a VPS (recommended: GitHub Actions + SCP + systemd rolling)

This is the recommended path for your setup.
- CI builds and tests the Rust binary on pushes to `main`.
- Deploy runs only after CI succeeds and reuses the CI artifact.
- VPS receives only the built binary over SCP.
- VPS runs rolling restarts via `systemd` (`identity-registry@a` then `@b`).

For this path, the VPS does **not** need Rust installed.

### 1. VPS prerequisites (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y curl
```

### 2. One-time setup for rolling services

```bash
sudo mkdir -p /etc/identity-registry
# First deploy from GitHub Actions will install:
# - /etc/systemd/system/identity-registry@.service
# - /etc/identity-registry/a.env and b.env
```

### 3. Configure GitHub repository secrets

```bash
VPS_HOST
VPS_USER
VPS_SSH_KEY
VPS_PORT   # optional, defaults to 22
```

### 4. Trigger deploy

```bash
# Push to main:
# - CI runs first (.github/workflows/ci.yml)
# - Deploy runs after CI succeeds (.github/workflows/vps-rolling-deploy.yml)
# You can also run deploy manually via workflow_dispatch.
```

### 5. Verify

```bash
curl -sSf http://127.0.0.1:8081/health
curl -sSf http://127.0.0.1:8082/health
curl -sSf http://<your-vps-ip-or-domain>/health
```

The deploy env files (`/etc/identity-registry/a.env` and `/etc/identity-registry/b.env`) are configured to use the same SQLite DB file:
- `DATABASE_URL=sqlite:///opt/botid/identity-registry.sqlite3`

### 6. What the deploy workflow does

Workflow file: `.github/workflows/vps-rolling-deploy.yml`

The workflow will:
1. Download `identity-server` release artifact from CI
2. SCP the binary + systemd/env config to the VPS
3. Update systemd units and env files
4. Run rolling restart (`identity-registry@a` then `identity-registry@b`) with `/health` checks

Prerequisite on VPS:
- `VPS_USER` must have passwordless `sudo` for `systemctl`, `install`, and writing `/etc/systemd`, `/etc/identity-registry`, `/usr/local/bin`, and `/opt/botid`.

### Optional: Caddy (manual only)

```bash
# Install the template from deploy/caddy/Caddyfile.identity-registry manually:
sudo mkdir -p /etc/caddy/sites-enabled
sudo install -Dm644 deploy/caddy/Caddyfile.identity-registry /etc/caddy/sites-enabled/botnet.pub.caddy
echo 'import /etc/caddy/sites-enabled/*.caddy' | sudo tee -a /etc/caddy/Caddyfile >/dev/null
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

## Layout

- `/crates/identity-core`: shared types, canonicalization, bot ID derivation
- `/crates/identity-crypto`: proof/JWS helpers (starter)
- `/crates/identity-policy`: threshold policy evaluation
- `/crates/identity-storage`: storage trait + SQLite(default)/Postgres(optional)/Memory(mock) backends
- `/crates/identity-server`: Axum HTTP API skeleton
- `/crates/identity-cli`: CLI skeleton using SDK
- `/crates/identity-sdk`: native SDK starter
- `/crates/identity-web`: WASM SDK starter
- `/crates/test-support`: testing helpers
- `/migrations`: SQL migrations
- `/deploy`: deployment templates for caddy + rolling systemd services
- `/scripts/remote_rolling_deploy.sh`: rolling binary deploy with health checks (used by GitHub Actions)
