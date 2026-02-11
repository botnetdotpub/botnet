# AI Agent Identity Registry (Rust Workspace)

Bootstrap workspace for an AI Agent Identity Registry with:
- Axum server (`identity-server`)
- CLI (`identity-cli`)
- Native Rust SDK (`identity-sdk`)
- WebAssembly SDK (`identity-web`)
- Shared core/crypto/policy/storage crates

## Quick start

```bash
cargo run -p identity-server
```

In another terminal:

```bash
cargo run -p identity-cli -- --help
```

## Common commands

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Deploy on a VPS (recommended: GitHub Actions + SCP + systemd rolling)

This is the recommended path for your setup.
- CI builds the Rust binary.
- VPS receives only the built binary over SCP.
- VPS runs rolling restarts via `systemd` (`identity-registry@a` then `@b`).

For this path, the VPS does **not** need Rust installed.

### 1. VPS prerequisites (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y caddy curl
```

### 2. One-time setup for rolling services

```bash
sudo mkdir -p /etc/identity-registry
sudo mkdir -p /etc/caddy/sites-enabled
# First deploy from GitHub Actions will install:
# - /etc/systemd/system/identity-registry@.service
# - /etc/identity-registry/a.env and b.env
# - /etc/caddy/sites-enabled/botnet.pub.caddy
```

### 3. Configure GitHub repository secrets

```bash
VPS_HOST
VPS_USER
VPS_SSH_KEY
VPS_PORT   # optional, defaults to 22
MANAGE_CADDY_CONFIG  # optional: set to "true" only if you want CI to manage Caddy files
```

### 4. Trigger deploy

```bash
# Push to main (or run workflow_dispatch):
# .github/workflows/vps-rolling-deploy.yml
```

### 5. Verify

```bash
curl -sSf http://127.0.0.1:8081/health
curl -sSf http://127.0.0.1:8082/health
curl -sSf http://<your-vps-ip-or-domain>/health
```

### 6. What the deploy workflow does

Workflow file: `.github/workflows/vps-rolling-deploy.yml`

The workflow will:
1. Build `identity-server` in release mode
2. SCP the binary + systemd/caddy config to the VPS
3. Update systemd units and install `/etc/caddy/sites-enabled/botnet.pub.caddy`
4. Run rolling restart (`identity-registry@a` then `identity-registry@b`) with `/health` checks

Prerequisite on VPS:
- `VPS_USER` must have passwordless `sudo` for `systemctl`, `install`, and writing `/etc/systemd` and `/etc/caddy`.
- Main `/etc/caddy/Caddyfile` must include: `import /etc/caddy/sites-enabled/*.caddy`
- By default, workflow does **not** modify main `/etc/caddy/Caddyfile` unless `MANAGE_CADDY_CONFIG=true`.

### Optional: Caddy automatic HTTPS

```bash
# Keep each site in its own file under /etc/caddy/sites-enabled/*.caddy.
# This repo defaults to botnet.pub in deploy/caddy/Caddyfile.identity-registry.
# Override with IDENTITY_REGISTRY_SITE if needed.
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

## Layout

- `/crates/identity-core`: shared types, canonicalization, agent ID derivation
- `/crates/identity-crypto`: proof/JWS helpers (starter)
- `/crates/identity-policy`: threshold policy evaluation
- `/crates/identity-storage`: storage trait + Postgres-backed skeleton
- `/crates/identity-server`: Axum HTTP API skeleton
- `/crates/identity-cli`: CLI skeleton using SDK
- `/crates/identity-sdk`: native SDK starter
- `/crates/identity-web`: WASM SDK starter
- `/crates/test-support`: testing helpers
- `/migrations`: SQL migrations
- `/deploy`: deployment templates for caddy + rolling systemd services
- `/scripts/remote_rolling_deploy.sh`: rolling binary deploy with health checks (used by GitHub Actions)
