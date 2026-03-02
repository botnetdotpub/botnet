use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{SecondsFormat, Utc};
use identity_cli::{generate_cli_docs, CliCommandDoc};
use identity_core::{
    bot_id::derive_bot_id, canonical::canonicalize, validation::validate_bot_record, Attestation,
    BotRecord, BotStatus, Controller, Delegation, Endpoint, Evidence, KeyRef, Owner, Policy,
    PolicyRule, Proof, ProofItem, PublicKey, SignatureRef, SignerRef, SignerSet,
};
use identity_crypto::{keys::verifying_key_from_jwk, verify_compact_jws};
use identity_policy::eval::{evaluate_threshold, Operation};
use identity_storage::{MemoryStore, SqliteStore, Storage};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashSet, net::SocketAddr, sync::Arc};

/// GitHub repository slug used in homepage and install links.
/// Change this if the repo moves to a different org or name.
const GITHUB_REPO: &str = "botnetdotpub/botnet";
use tower_http::trace::TraceLayer;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    store: Arc<dyn Storage>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            store: Arc::new(MemoryStore::default()),
        }
    }
}

impl AppState {
    fn new<S>(store: S) -> Self
    where
        S: Storage + 'static,
    {
        Self {
            store: Arc::new(store),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct AddKeyRequest {
    public_key: PublicKey,
    /// Single-signature authorization proof for this mutation.
    proof: Option<Proof>,
    /// Multi-signature authorization proofs for threshold policy checks.
    proof_set: Option<Vec<ProofItem>>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct RemoveKeyRequest {
    reason: Option<String>,
    /// Single-signature authorization proof for this mutation.
    proof: Option<Proof>,
    /// Multi-signature authorization proofs for threshold policy checks.
    proof_set: Option<Vec<ProofItem>>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct RotateKeyRequest {
    old_key_id: String,
    new_key: PublicKey,
    /// Single-signature authorization proof for this mutation.
    proof: Option<Proof>,
    /// Multi-signature authorization proofs for threshold policy checks.
    proof_set: Option<Vec<ProofItem>>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct RevokeBotRequest {
    reason: Option<String>,
    /// Single-signature authorization proof for this mutation.
    proof: Option<Proof>,
    /// Multi-signature authorization proofs for threshold policy checks.
    proof_set: Option<Vec<ProofItem>>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
struct PublishAttestationRequest {
    subject_bot_id: String,
    attestation: Attestation,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct SearchQuery {
    #[param(example = "alpha")]
    q: Option<String>,
    status: Option<BotStatus>,
    #[param(example = "calendar.read")]
    capability: Option<String>,
    #[param(minimum = 1, maximum = 200, example = 50)]
    limit: Option<usize>,
}

#[derive(Debug, Serialize, ToSchema)]
struct SearchResponse {
    count: usize,
    results: Vec<BotRecord>,
}

#[derive(Debug, Serialize, ToSchema)]
struct RootResponse {
    service: String,
    status: String,
    docs: String,
    openapi: String,
    swagger: String,
    health: String,
    stats: String,
    install: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct HealthResponse {
    status: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct NonceResponse {
    nonce: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct ErrorResponse {
    error: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct RegistryStatsResponse {
    total_bots: usize,
    active_bots: usize,
    deprecated_bots: usize,
    revoked_bots: usize,
    total_keys: usize,
    active_keys: usize,
    revoked_keys: usize,
    total_attestations: usize,
    total_controllers: usize,
    server_time: String,
    last_bot_update: Option<String>,
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "AI Bot Identity Registry API",
        description = "Authentication model: this API uses signed request payloads (not bearer tokens).\n\n\
        For mutation endpoints, clients must include exactly one authorization mode:\n\
        - `proof`: single signer JWS\n\
        - `proof_set`: multi-signer JWS set for m-of-n policy\n\n\
        The server verifies signatures over the JCS-canonicalized request payload with proof fields removed, \
        resolves signer keys (including delegated controllers), and enforces policy thresholds.\n\n\
        Auth-required mutation endpoints:\n\
        - POST /v1/bots\n\
        - PATCH /v1/bots/{bot_id}\n\
        - POST /v1/bots/{bot_id}/keys\n\
        - DELETE /v1/bots/{bot_id}/keys/{key_id}\n\
        - POST /v1/bots/{bot_id}/rotate\n\
        - POST /v1/bots/{bot_id}/revoke\n\
        - POST /v1/attestations (attestation.signature must verify against issuer key)"
    ),
    paths(
        api_root,
        health,
        registry_stats,
        create_bot,
        get_bot,
        update_bot,
        add_key,
        remove_key,
        rotate_key,
        revoke_bot,
        publish_attestation,
        search,
        get_nonce
    ),
    components(schemas(
        BotRecord,
        BotStatus,
        Owner,
        PublicKey,
        Endpoint,
        Controller,
        Delegation,
        Policy,
        PolicyRule,
        SignerSet,
        SignerRef,
        KeyRef,
        Proof,
        ProofItem,
        Attestation,
        SignatureRef,
        Evidence,
        AddKeyRequest,
        RemoveKeyRequest,
        RotateKeyRequest,
        RevokeBotRequest,
        PublishAttestationRequest,
        SearchResponse,
        RootResponse,
        HealthResponse,
        NonceResponse,
        RegistryStatsResponse,
        ErrorResponse
    )),
    tags(
        (name = "bot-registry", description = "AI Bot Identity Registry endpoints. Mutation routes require proof-based signature auth.")
    )
)]
struct ApiDoc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "identity_server=debug,tower_http=info".to_string()),
        )
        .init();

    let app = app_router(app_state_from_env().await?);

    let addr = bind_addr_from_env()?;
    tracing::info!("listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn app_state_from_env() -> anyhow::Result<AppState> {
    let backend = std::env::var("STORAGE_BACKEND").unwrap_or_else(|_| "sqlite".to_string());
    match backend.as_str() {
        "memory" => Ok(AppState::default()),
        "sqlite" => {
            let database_url = std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:///opt/botid/identity-registry.sqlite3".to_string());
            let store = SqliteStore::connect(&database_url).await?;
            store.run_migrations().await?;
            Ok(AppState::new(store))
        }
        other => anyhow::bail!("unsupported STORAGE_BACKEND '{other}' (expected sqlite|memory)"),
    }
}

fn bind_addr_from_env() -> anyhow::Result<SocketAddr> {
    parse_bind_addr(
        std::env::var("BIND_ADDR").ok().as_deref(),
        std::env::var("PORT").ok().as_deref(),
    )
}

fn parse_bind_addr(bind_addr: Option<&str>, port: Option<&str>) -> anyhow::Result<SocketAddr> {
    if let Some(bind_addr) = bind_addr {
        return bind_addr
            .parse::<SocketAddr>()
            .map_err(|e| anyhow::anyhow!("invalid BIND_ADDR '{bind_addr}': {e}"));
    }

    let port = port
        .map(|p| p.parse::<u16>())
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid PORT value: {e}"))?
        .unwrap_or(8080);

    Ok(SocketAddr::from(([0, 0, 0, 0], port)))
}

fn app_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(homepage))
        .route("/install.sh", get(install_script))
        .route("/docs", get(docs_index))
        .route("/docs/api", get(docs_api))
        .route("/docs/cli", get(docs_cli))
        .route("/openapi.json", get(openapi_json))
        .route("/swagger", get(swagger))
        .route("/health", get(health))
        .route("/v1", get(api_root))
        .route("/v1/stats", get(registry_stats))
        .route("/v1/bots", post(create_bot))
        .route("/v1/bots/{bot_id}", get(get_bot).patch(update_bot))
        .route("/v1/bots/{bot_id}/keys", post(add_key))
        .route("/v1/bots/{bot_id}/keys/{key_id}", delete(remove_key))
        .route("/v1/bots/{bot_id}/rotate", post(rotate_key))
        .route("/v1/bots/{bot_id}/revoke", post(revoke_bot))
        .route("/v1/attestations", post(publish_attestation))
        .route("/v1/search", get(search))
        .route("/v1/nonce", get(get_nonce))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[utoipa::path(
    get,
    path = "/v1",
    summary = "Service metadata (public)",
    responses(
        (status = 200, description = "Service metadata and docs links.", body = RootResponse)
    ),
    tag = "bot-registry"
)]
async fn api_root() -> impl IntoResponse {
    Json(RootResponse {
        service: "ai-bot-identity-registry".to_string(),
        status: "ok".to_string(),
        docs: "/docs".to_string(),
        openapi: "/openapi.json".to_string(),
        swagger: "/swagger".to_string(),
        health: "/health".to_string(),
        stats: "/v1/stats".to_string(),
        install: "/install.sh".to_string(),
    })
}

async fn homepage() -> impl IntoResponse {
    Html(
        r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>botnet.pub | Bot Identity Registry</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
      :root {
        --bg: #06080d;
        --bg-soft: #0a0d14;
        --card: #0e131d;
        --line: #1b2231;
        --line-2: #2a3347;
        --text: #e5e7ef;
        --muted: #99a4b7;
        --mono: #7a859c;
        --cyan: #22d3ee;
        --green: #22c55e;
        --red: #fb7185;
      }
      * { box-sizing: border-box; margin: 0; padding: 0; }
      body {
        min-height: 100vh;
        color: var(--text);
        font-family: "Space Grotesk", "Avenir Next", "Segoe UI", sans-serif;
        background:
          radial-gradient(900px 400px at 8% 0%, rgba(34,211,238,0.08), transparent 58%),
          radial-gradient(700px 320px at 92% 18%, rgba(99,102,241,0.08), transparent 60%),
          linear-gradient(180deg, #05070b 0%, #06080d 100%);
      }
      main {
        max-width: 1180px;
        margin: 0 auto;
        padding: 1.25rem 1rem 2.5rem;
      }

      .nav {
        display: flex;
        align-items: center;
        justify-content: space-between;
        border: 1px solid var(--line);
        border-radius: 14px;
        padding: 0.85rem 1rem;
        background: rgba(8, 11, 18, 0.62);
        backdrop-filter: blur(8px);
      }
      .brand {
        color: #f8fafc;
        font-size: 1.05rem;
        font-weight: 600;
        letter-spacing: 0.06em;
      }
      .brand span {
        color: var(--mono);
        font-family: "IBM Plex Mono", monospace;
        font-size: 0.9rem;
        margin-right: 0.45rem;
      }
      .nav-links {
        display: flex;
        align-items: center;
        gap: 1.1rem;
      }
      .nav-links a {
        text-decoration: none;
        font-family: "IBM Plex Mono", monospace;
        text-transform: uppercase;
        letter-spacing: 0.09em;
        font-size: 0.77rem;
        color: var(--muted);
      }
      .nav-links a:hover { color: #f8fafc; }
      .github-btn {
        padding: 0.55rem 0.88rem;
        border: 1px solid var(--line-2);
        border-radius: 10px;
      }

      .hero {
        margin-top: 1rem;
        border: 1px solid var(--line);
        border-radius: 18px;
        background: linear-gradient(180deg, rgba(10, 14, 22, 0.95), rgba(7, 10, 17, 0.95));
        overflow: hidden;
      }
      .hero-inner {
        display: grid;
        grid-template-columns: 1.1fr 0.9fr;
        gap: 1.2rem;
        padding: 1.5rem;
      }
      .eyebrow {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        font-size: 0.72rem;
        font-family: "IBM Plex Mono", monospace;
        letter-spacing: 0.18em;
        text-transform: uppercase;
        color: var(--mono);
      }
      .eyebrow::before {
        content: "";
        width: 7px;
        height: 7px;
        border-radius: 50%;
        background: var(--green);
        box-shadow: 0 0 12px rgba(34, 197, 94, 0.65);
      }
      h1 {
        margin-top: 0.85rem;
        font-size: clamp(2.15rem, 5vw, 4rem);
        line-height: 1.03;
        letter-spacing: -0.03em;
        max-width: 13ch;
      }
      .lede {
        margin-top: 1rem;
        color: #b7c0d1;
        max-width: 52ch;
        font-size: 1.06rem;
        line-height: 1.5;
      }
      .status {
        display: inline-flex;
        align-items: center;
        gap: 0.45rem;
        margin-top: 1.1rem;
        padding: 0.42rem 0.72rem;
        border-radius: 999px;
        border: 1px solid #1e3346;
        background: rgba(34, 211, 238, 0.08);
        color: #8be9fa;
        font-size: 0.83rem;
        font-family: "IBM Plex Mono", monospace;
      }
      .hero-actions {
        margin-top: 1.2rem;
        display: flex;
        gap: 0.7rem;
        flex-wrap: wrap;
      }
      .btn {
        text-decoration: none;
        border-radius: 11px;
        border: 1px solid var(--line-2);
        padding: 0.7rem 0.92rem;
        font-size: 0.85rem;
        color: #d6def0;
      }
      .btn.primary {
        border-color: #10485a;
        background: linear-gradient(180deg, #0a3e50, #0c283a);
      }

      .terminal {
        border: 1px solid var(--line);
        border-radius: 14px;
        background: #0a0f18;
        overflow: hidden;
        box-shadow: inset 0 1px 0 rgba(255,255,255,0.04);
        animation: float 8s ease-in-out infinite;
      }
      .terminal-head {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0.62rem 0.72rem;
        border-bottom: 1px solid var(--line);
        background: rgba(255,255,255,0.02);
      }
      .dots {
        display: flex;
        gap: 0.38rem;
      }
      .dots span {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        display: block;
      }
      .dots span:nth-child(1) { background: #fb7185; }
      .dots span:nth-child(2) { background: #f59e0b; }
      .dots span:nth-child(3) { background: #34d399; }
      .title {
        color: var(--mono);
        font-size: 0.7rem;
        font-family: "IBM Plex Mono", monospace;
        letter-spacing: 0.13em;
      }
      .terminal-body {
        padding: 0.9rem;
      }
      .row {
        display: grid;
        grid-template-columns: 1fr auto;
        gap: 0.55rem;
        padding: 0.47rem 0;
        border-bottom: 1px dashed #1a2331;
        font-family: "IBM Plex Mono", monospace;
        color: #aab4c9;
        font-size: 0.82rem;
      }
      .row:last-child { border-bottom: 0; }
      .row strong { color: #dbe4f6; font-weight: 500; }
      .good { color: #33d17a; }
      .warn { color: #f97316; }

      .quick {
        margin-top: 1rem;
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 1rem;
      }
      .panel {
        border: 1px solid var(--line);
        border-radius: 14px;
        background: var(--card);
        padding: 1rem;
      }
      .panel h2 {
        font-family: "IBM Plex Mono", monospace;
        text-transform: uppercase;
        letter-spacing: 0.16em;
        font-size: 0.73rem;
        color: var(--mono);
      }
      .panel p {
        margin-top: 0.65rem;
        color: var(--muted);
        line-height: 1.45;
      }
      pre {
        margin-top: 0.75rem;
        padding: 0.82rem 0.9rem;
        border-radius: 11px;
        border: 1px solid #243247;
        background: #090d15;
        color: #f8fafc;
        font-family: "IBM Plex Mono", monospace;
        font-size: 0.84rem;
        overflow-x: auto;
      }
      .prompt { color: #22c55e; margin-right: 0.42rem; }

      .stats {
        margin-top: 1rem;
        border: 1px solid var(--line);
        border-radius: 14px;
        overflow: hidden;
        display: grid;
        grid-template-columns: repeat(6, minmax(0, 1fr));
      }
      .metric {
        padding: 0.9rem;
        border-right: 1px solid var(--line);
        background: linear-gradient(180deg, #0b1018, #090d15);
      }
      .metric:last-child { border-right: 0; }
      .metric .k {
        color: var(--mono);
        font-family: "IBM Plex Mono", monospace;
        text-transform: uppercase;
        font-size: 0.63rem;
        letter-spacing: 0.15em;
      }
      .metric .v {
        margin-top: 0.46rem;
        font-size: clamp(1.1rem, 2vw, 1.55rem);
        font-weight: 700;
        letter-spacing: -0.02em;
      }
      .metric:nth-child(1) .v { color: #60a5fa; }
      .metric:nth-child(2) .v { color: #4ade80; }
      .metric:nth-child(3) .v { color: #fb7185; }
      .metric:nth-child(4) .v { color: #22d3ee; }
      .metric:nth-child(5) .v { color: #fda4af; }
      .metric:nth-child(6) .v { color: #a78bfa; }

      .meta {
        margin-top: 0.75rem;
        padding: 0.7rem 0.9rem;
        border: 1px solid var(--line);
        border-radius: 11px;
        color: var(--muted);
        font-family: "IBM Plex Mono", monospace;
        font-size: 0.75rem;
        display: flex;
        justify-content: space-between;
        gap: 1rem;
        flex-wrap: wrap;
      }
      .api-links {
        margin-top: 0.8rem;
        display: flex;
        flex-wrap: wrap;
        gap: 0.62rem;
      }
      .api-links a {
        text-decoration: none;
        color: #c7d2fe;
        border: 1px solid var(--line-2);
        border-radius: 999px;
        padding: 0.44rem 0.7rem;
        font-size: 0.77rem;
        font-family: "IBM Plex Mono", monospace;
      }
      .api-links a:hover { border-color: #475569; }
      .note {
        margin-top: 0.55rem;
        min-height: 1.1rem;
        color: #fb7185;
        font-size: 0.82rem;
      }

      @keyframes float {
        0% { transform: translateY(0px); }
        50% { transform: translateY(-6px); }
        100% { transform: translateY(0px); }
      }

      @media (max-width: 960px) {
        .hero-inner { grid-template-columns: 1fr; }
        .quick { grid-template-columns: 1fr; }
        .stats { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      }
      @media (max-width: 680px) {
        .nav-links a:not(.github-btn) { display: none; }
        .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        h1 { font-size: 2.35rem; }
      }
    </style>
  </head>
  <body>
    <main>
      <header class="nav">
        <div class="brand"><span>$</span>botnet.pub registry</div>
        <nav class="nav-links">
          <a href="#quickstart">quickstart</a>
          <a href="/docs">docs</a>
          <a href="/swagger">swagger</a>
          <a class="github-btn" href="https://github.com/GITHUB_REPO_PLACEHOLDER" target="_blank" rel="noreferrer">github</a>
        </nav>
      </header>

      <section class="hero">
        <div class="hero-inner">
          <div>
            <p class="eyebrow">live registry control plane</p>
            <h1>Verifiable bot identities for autonomous systems.</h1>
            <p class="lede">Track bots, keys, and attestations with signature-enforced updates and policy thresholds. Minimal API, public docs, production-ready workflow.</p>
            <div id="health" class="status">Loading service health...</div>
            <div class="hero-actions">
              <a class="btn primary" href="#quickstart">Start in 1 command</a>
              <a class="btn" href="/openapi.json">OpenAPI</a>
            </div>
          </div>
          <aside class="terminal">
            <div class="terminal-head">
              <div class="dots"><span></span><span></span><span></span></div>
              <div class="title">botnet.pub runtime</div>
            </div>
            <div class="terminal-body">
              <div class="row"><span><strong>status</strong></span><span id="term_health" class="good">loading</span></div>
              <div class="row"><span><strong>bots.active</strong></span><span id="term_active_bots">-</span></div>
              <div class="row"><span><strong>bots.revoked</strong></span><span id="term_revoked_bots">-</span></div>
              <div class="row"><span><strong>keys.active</strong></span><span id="term_active_keys">-</span></div>
              <div class="row"><span><strong>attestations</strong></span><span id="term_attestations">-</span></div>
              <div class="row"><span><strong>last.update</strong></span><span id="term_last_update" class="warn">-</span></div>
            </div>
          </aside>
        </div>
      </section>

      <section class="stats">
        <article class="metric"><div class="k">Bots</div><div id="total_bots" class="v">-</div></article>
        <article class="metric"><div class="k">Active</div><div id="active_bots" class="v">-</div></article>
        <article class="metric"><div class="k">Revoked</div><div id="revoked_bots" class="v">-</div></article>
        <article class="metric"><div class="k">Keys Active</div><div id="active_keys" class="v">-</div></article>
        <article class="metric"><div class="k">Keys Revoked</div><div id="revoked_keys" class="v">-</div></article>
        <article class="metric"><div class="k">Attestations</div><div id="total_attestations" class="v">-</div></article>
      </section>

      <section class="meta">
        <div>last bot update: <span id="last_update">-</span></div>
        <div>server time: <span id="server_time">-</span></div>
      </section>

      <section id="quickstart" class="quick">
        <article class="panel">
          <h2>Install CLI</h2>
          <p>One command install for <code>botnet</code>.</p>
          <pre><span class="prompt">$</span>curl -fsSL https://botnet.pub/install.sh | sh</pre>
        </article>
        <article class="panel">
          <h2>Query Registry</h2>
          <p>Hit search immediately after install.</p>
          <pre><span class="prompt">$</span>botnet --base-url https://botnet.pub/v1 search --limit 5</pre>
          <div class="api-links">
            <a href="/v1">/v1</a>
            <a href="/v1/stats">/v1/stats</a>
            <a href="/docs">/docs</a>
            <a href="/swagger">/swagger</a>
            <a href="/openapi.json">/openapi.json</a>
          </div>
          <div class="note" id="load_error"></div>
        </article>
      </section>

      <section class="quick">
        <article class="panel">
          <h2>Health</h2>
          <pre><span class="prompt">$</span>curl -sSf https://botnet.pub/health</pre>
        </article>
        <article class="panel">
          <h2>Auth Model</h2>
          <p>Mutations require signed payloads via <code>proof</code> or <code>proof_set</code> and policy threshold checks.</p>
        </article>
      </section>
    </main>
    <script>
      function set(id, value) { document.getElementById(id).textContent = value; }
      async function refresh() {
        try {
          const [healthRes, statsRes] = await Promise.all([fetch("/health"), fetch("/v1/stats")]);
          const health = await healthRes.json();
          const stats = await statsRes.json();

          set("total_bots", stats.total_bots);
          set("active_bots", stats.active_bots);
          set("revoked_bots", stats.revoked_bots);
          set("active_keys", stats.active_keys);
          set("revoked_keys", stats.revoked_keys);
          set("total_attestations", stats.total_attestations);
          set("server_time", stats.server_time || "-");
          set("last_update", stats.last_bot_update || "none yet");
          set("term_active_bots", stats.active_bots);
          set("term_revoked_bots", stats.revoked_bots);
          set("term_active_keys", stats.active_keys);
          set("term_attestations", stats.total_attestations);
          set("term_last_update", stats.last_bot_update || "none yet");

          const healthEl = document.getElementById("health");
          const termHealth = document.getElementById("term_health");
          if (health.status === "ok") {
            healthEl.textContent = "Service healthy";
            healthEl.style.background = "rgba(34, 211, 238, 0.08)";
            healthEl.style.borderColor = "#1e3346";
            healthEl.style.color = "#8be9fa";
            termHealth.textContent = "healthy";
            termHealth.className = "good";
          } else {
            healthEl.textContent = "Service degraded";
            healthEl.style.background = "rgba(251, 113, 133, 0.11)";
            healthEl.style.borderColor = "#4c1d2e";
            healthEl.style.color = "#fecdd3";
            termHealth.textContent = "degraded";
            termHealth.className = "warn";
          }
          document.getElementById("load_error").textContent = "";
        } catch (err) {
          document.getElementById("load_error").textContent =
            "Could not load live stats right now. API endpoints are still available.";
          document.getElementById("term_health").textContent = "offline";
          document.getElementById("term_health").className = "warn";
        }
      }
      refresh();
      setInterval(refresh, 15000);
    </script>
  </body>
</html>
"##
        .replace("GITHUB_REPO_PLACEHOLDER", GITHUB_REPO),
    )
}

async fn install_script() -> impl IntoResponse {
    (
        [("content-type", "text/x-shellscript; charset=utf-8")],
        include_str!("../../../install.sh"),
    )
}

#[derive(Debug)]
struct ApiDocsModel {
    endpoints: Vec<ApiEndpointDoc>,
    schemas: Vec<ApiSchemaDoc>,
}

#[derive(Debug)]
struct ApiEndpointDoc {
    method: String,
    path: String,
    summary: String,
    description: Option<String>,
    operation_id: Option<String>,
    auth: String,
    parameters: Vec<ApiParameterDoc>,
    request_body: Option<String>,
    responses: Vec<ApiResponseDoc>,
}

#[derive(Debug)]
struct ApiParameterDoc {
    name: String,
    location: String,
    required: bool,
    schema: String,
    description: Option<String>,
}

#[derive(Debug)]
struct ApiResponseDoc {
    status: String,
    description: Option<String>,
}

#[derive(Debug)]
struct ApiSchemaDoc {
    name: String,
    kind: String,
    required_fields: usize,
    property_count: usize,
}

async fn docs_index() -> impl IntoResponse {
    let api_docs = build_api_docs_model();
    let cli_docs = generate_cli_docs();
    let command_count = count_cli_commands(&cli_docs.commands);

    let sidebar_html = r##"
        <div class="side-group">
          <div class="side-title">Getting Started</div>
          <a href="/docs" class="side-link active">Overview</a>
          <a href="/docs/api" class="side-link">API Reference</a>
          <a href="/docs/cli" class="side-link">CLI Reference</a>
        </div>
        <div class="side-group">
          <div class="side-title">Resources</div>
          <a href="/openapi.json" class="side-link">OpenAPI Spec</a>
          <a href="/swagger" class="side-link">Swagger UI</a>
          <a href="/install.sh" class="side-link">Install Script</a>
        </div>
    "##;

    let content_html = format!(
        r##"
        <section id="welcome" class="doc-section">
          <h1>Documentation Home</h1>
          <p>Docs are generated from Rust source-of-truth metadata: HTTP endpoints and schemas from <code>utoipa</code> OpenAPI generation, and CLI commands from Clap command definitions.</p>
        </section>
        <section id="coverage" class="doc-section">
          <h2>Generated Coverage</h2>
          <table>
            <thead><tr><th>Surface</th><th>Source</th><th>Coverage</th></tr></thead>
            <tbody>
              <tr><td>API</td><td><code>ApiDoc::openapi()</code></td><td>{} endpoints / {} schemas</td></tr>
              <tr><td>CLI</td><td><code>Cli::command()</code></td><td>{} commands</td></tr>
            </tbody>
          </table>
        </section>
        <section id="quickstart" class="doc-section">
          <h2>Quickstart</h2>
          <p>Install the CLI and query the registry in under a minute.</p>
          <pre><code>curl -fsSL https://botnet.pub/install.sh | sh
botnet --base-url https://botnet.pub/v1 search --limit 5</code></pre>
        </section>
        <section id="choose-path" class="doc-section">
          <h2>Choose Your Path</h2>
          <div class="doc-grid">
            <article class="mini-card">
              <h3>API Track</h3>
              <p>Endpoint contracts, auth requirements, request/response schemas, and route-level details.</p>
              <a href="/docs/api">Open API Reference</a>
            </article>
            <article class="mini-card">
              <h3>CLI Track</h3>
              <p>Global flags, command catalog, and generated help output for every CLI command.</p>
              <a href="/docs/cli">Open CLI Reference</a>
            </article>
          </div>
        </section>
        "##,
        api_docs.endpoints.len(),
        api_docs.schemas.len(),
        command_count
    );

    let toc_html = r##"
        <a href="#welcome">Welcome</a>
        <a href="#coverage">Coverage</a>
        <a href="#quickstart">Quickstart</a>
        <a href="#choose-path">Choose Path</a>
    "##;

    docs_shell(DocsShellArgs {
        page_title: "Documentation Home",
        page_subtitle: "Generated from Rust handlers, schemas, and command definitions.",
        sidebar_html,
        content_html: &content_html,
        toc_html,
        home_active: true,
        api_active: false,
        cli_active: false,
    })
}

async fn docs_api() -> impl IntoResponse {
    let api_docs = build_api_docs_model();

    let sidebar_html = r##"
        <div class="side-group">
          <div class="side-title">Developers</div>
          <a href="/docs" class="side-link">Overview</a>
          <a href="/docs/api" class="side-link active">API Reference</a>
          <a href="/docs/cli" class="side-link">CLI Reference</a>
        </div>
        <div class="side-group">
          <div class="side-title">API Guide</div>
          <a href="#overview" class="side-link">Overview</a>
          <a href="#auth-flow" class="side-link">Auth Flow</a>
          <a href="#quickstart-reads" class="side-link">Read Quickstart</a>
          <a href="#quickstart-mutations" class="side-link">Mutation Quickstart</a>
          <a href="#matrix" class="side-link">Endpoint Matrix</a>
          <a href="#details" class="side-link">Endpoint Details</a>
          <a href="#schemas" class="side-link">Schema Catalog</a>
        </div>
        <div class="side-group">
          <div class="side-title">Tools</div>
          <a href="/swagger" class="side-link">Swagger UI</a>
          <a href="/openapi.json" class="side-link">OpenAPI JSON</a>
        </div>
        "##;

    let mut matrix_rows = String::new();
    let mut detail_sections = String::new();
    for endpoint in &api_docs.endpoints {
        matrix_rows.push_str(&format!(
            r#"<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>"#,
            escape_html(&endpoint.method),
            escape_html(&endpoint.path),
            escape_html(&endpoint.summary),
            escape_html(&endpoint.auth)
        ));

        let mut parameter_rows = String::new();
        for parameter in &endpoint.parameters {
            let required = if parameter.required { "yes" } else { "no" };
            parameter_rows.push_str(&format!(
                r#"<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td></tr>"#,
                escape_html(&parameter.name),
                escape_html(&parameter.location),
                required,
                escape_html(&parameter.schema),
                escape_html(parameter.description.as_deref().unwrap_or("-"))
            ));
        }
        if parameter_rows.is_empty() {
            parameter_rows.push_str(r#"<tr><td colspan="5">No parameters.</td></tr>"#);
        }

        let mut response_rows = String::new();
        for response in &endpoint.responses {
            response_rows.push_str(&format!(
                r#"<tr><td><code>{}</code></td><td>{}</td></tr>"#,
                escape_html(&response.status),
                escape_html(response.description.as_deref().unwrap_or("-"))
            ));
        }

        detail_sections.push_str(&format!(
            r##"
            <section id="{}" class="doc-section">
              <h2><code>{}</code> <code>{}</code></h2>
              <p>{}</p>
              <p><strong>Auth:</strong> {}</p>
              <p><strong>Operation ID:</strong> <code>{}</code></p>
              <p><strong>Request Body:</strong> {}</p>
              <table>
                <thead><tr><th>Parameter</th><th>In</th><th>Required</th><th>Type</th><th>Description</th></tr></thead>
                <tbody>{}</tbody>
              </table>
              <table>
                <thead><tr><th>Status</th><th>Description</th></tr></thead>
                <tbody>{}</tbody>
              </table>
              {}
            </section>
            "##,
            endpoint_anchor(endpoint),
            escape_html(&endpoint.method),
            escape_html(&endpoint.path),
            escape_html(&endpoint.summary),
            escape_html(&endpoint.auth),
            escape_html(endpoint.operation_id.as_deref().unwrap_or("unknown")),
            endpoint
                .request_body
                .as_ref()
                .map(|rb| format!("<code>{}</code>", escape_html(rb)))
                .unwrap_or_else(|| "none".to_string()),
            parameter_rows,
            response_rows,
            endpoint
                .description
                .as_ref()
                .map(|desc| format!("<p>{}</p>", escape_html(desc)))
                .unwrap_or_default(),
        ));
    }

    let mut schema_rows = String::new();
    for schema in &api_docs.schemas {
        schema_rows.push_str(&format!(
            r#"<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>"#,
            escape_html(&schema.name),
            escape_html(&schema.kind),
            schema.property_count,
            schema.required_fields
        ));
    }

    let content_html = format!(
        r##"
        <section id="overview" class="doc-section">
          <h1>API Reference</h1>
          <p>This page combines human guidance with generated data. Endpoint contracts and schemas are extracted from the server's OpenAPI model, so docs stay aligned with Rust handlers and types.</p>
          <p>Base URL: <code>https://botnet.pub/v1</code>.</p>
        </section>
        <section id="auth-flow" class="doc-section">
          <h2>Auth Flow (Mutations)</h2>
          <p>Reads are public. Mutations are proof-authenticated. For mutation routes, include exactly one of <code>proof</code> or <code>proof_set</code> in the JSON body.</p>
          <p>Server verification steps:</p>
          <ol>
            <li>Remove <code>proof</code>/<code>proof_set</code> from payload.</li>
            <li>Canonicalize payload with JCS.</li>
            <li>Verify Ed25519 detached JWS signatures.</li>
            <li>Resolve signer keys (self + controller keys when present).</li>
            <li>Enforce policy threshold for the operation.</li>
          </ol>
          <pre><code>{{
  "proof": {{
    "algorithm": "Ed25519",
    "key_id": "k1",
    "created": "2026-02-15T00:00:00Z",
    "jws": "&lt;detached-jws&gt;"
  }}
}}</code></pre>
        </section>
        <section id="quickstart-reads" class="doc-section">
          <h2>Read Quickstart</h2>
          <pre><code># service metadata
curl -sSf https://botnet.pub/v1

# health
curl -sSf https://botnet.pub/health

# stats
curl -sSf https://botnet.pub/v1/stats

# search
curl -sSf "https://botnet.pub/v1/search?q=assistant&limit=5"

# fetch by id
curl -sSf https://botnet.pub/v1/bots/&lt;BOT_ID&gt;</code></pre>
        </section>
        <section id="quickstart-mutations" class="doc-section">
          <h2>Mutation Quickstart</h2>
          <p>1) Build the operation payload file without proof fields.</p>
          <p>2) Canonicalize and sign that payload using your Ed25519 key.</p>
          <p>3) Attach <code>proof</code> (or <code>proof_set</code>) and submit.</p>
          <pre><code># create bot (signed payload)
curl -sSf -X POST https://botnet.pub/v1/bots \
  -H "content-type: application/json" \
  --data @signed-bot-record.json

# add key (signed payload)
curl -sSf -X POST https://botnet.pub/v1/bots/&lt;BOT_ID&gt;/keys \
  -H "content-type: application/json" \
  --data @signed-add-key.json

# revoke bot (signed payload)
curl -sSf -X POST https://botnet.pub/v1/bots/&lt;BOT_ID&gt;/revoke \
  -H "content-type: application/json" \
  --data @signed-revoke.json</code></pre>
        </section>
        <section id="matrix" class="doc-section">
          <h2>Endpoint Matrix</h2>
          <table>
            <thead><tr><th>Method</th><th>Path</th><th>Summary</th><th>Auth</th></tr></thead>
            <tbody>{}</tbody>
          </table>
        </section>
        <section id="details" class="doc-section">
          <h2>Endpoint Details</h2>
          <p>Each endpoint below includes operation ID, auth semantics, parameters, request body shape, and response codes directly extracted from OpenAPI.</p>
        </section>
        {}
        <section id="schemas" class="doc-section">
          <h2>Schema Catalog</h2>
          <table>
            <thead><tr><th>Schema</th><th>Kind</th><th>Properties</th><th>Required</th></tr></thead>
            <tbody>{}</tbody>
          </table>
        </section>
        "##,
        matrix_rows, detail_sections, schema_rows
    );

    let toc_html = String::from(
        r##"
        <a href="#overview">Overview</a>
        <a href="#auth-flow">Auth Flow</a>
        <a href="#quickstart-reads">Read Quickstart</a>
        <a href="#quickstart-mutations">Mutation Quickstart</a>
        <a href="#matrix">Endpoint Matrix</a>
        <a href="#details">Endpoint Details</a>
        <a href="#schemas">Schema Catalog</a>
    "##,
    );

    docs_shell(DocsShellArgs {
        page_title: "API Reference",
        page_subtitle: "Human guide plus generated OpenAPI route and schema reference.",
        sidebar_html,
        content_html: &content_html,
        toc_html: &toc_html,
        home_active: false,
        api_active: true,
        cli_active: false,
    })
}

async fn docs_cli() -> impl IntoResponse {
    let cli_docs = generate_cli_docs();
    let mut command_docs = Vec::new();
    flatten_cli_commands(&cli_docs.commands, &mut command_docs);

    let mut command_nav = String::new();
    for command in &cli_docs.commands {
        command_nav.push_str(&format!(
            r##"<a href="#{}" class="side-link"><code>{}</code></a>"##,
            cli_command_anchor(command),
            escape_html(&command.invocation)
        ));
    }

    let sidebar_html = format!(
        r##"
        <div class="side-group">
          <div class="side-title">Developers</div>
          <a href="/docs" class="side-link">Overview</a>
          <a href="/docs/api" class="side-link">API Reference</a>
          <a href="/docs/cli" class="side-link active">CLI Reference</a>
        </div>
        <div class="side-group">
          <div class="side-title">CLI Guide</div>
          <a href="#install" class="side-link">Install</a>
          <a href="#quickstart" class="side-link">Quickstart</a>
          <a href="#signing" class="side-link">Signing Model</a>
          <a href="#inputs" class="side-link">JSON Inputs</a>
          <a href="#playbooks" class="side-link">Command Playbooks</a>
          <a href="#catalog" class="side-link">Generated Catalog</a>
          <a href="#details" class="side-link">Command Details</a>
        </div>
        <div class="side-group">
          <div class="side-title">Top Commands</div>
          {}
        </div>
        "##,
        command_nav
    );

    let mut catalog_rows = String::new();
    let mut detail_sections = String::new();
    for command in &command_docs {
        let explanation = cli_command_explainer(command);
        catalog_rows.push_str(&format!(
            r#"<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>"#,
            escape_html(&command.invocation),
            escape_html(explanation.purpose),
            escape_html(command.about.as_deref().unwrap_or("-")),
            escape_html(&command.usage)
        ));

        detail_sections.push_str(&format!(
            r##"
            <section id="{}" class="doc-section">
              <h2><code>{}</code></h2>
              <p>{}</p>
              <p><strong>When to use:</strong> {}</p>
              <p><strong>Input file:</strong> {}</p>
              <p><strong>Usage:</strong> <code>{}</code></p>
              <p><strong>Example:</strong></p>
              <pre><code>{}</code></pre>
              <pre><code>{}</code></pre>
            </section>
            "##,
            cli_command_anchor(command),
            escape_html(&command.invocation),
            escape_html(command.about.as_deref().unwrap_or("No summary available.")),
            escape_html(explanation.purpose),
            escape_html(explanation.input_file),
            escape_html(&command.usage),
            escape_html(explanation.example),
            escape_html(&command.help)
        ));
    }

    let content_html = format!(
        r##"
        <section id="install" class="doc-section">
          <h1>CLI Reference</h1>
          <p>This page combines human task guides with generated command metadata from Clap. You get practical workflows plus up-to-date usage output from code.</p>
          <pre><code>curl -fsSL https://botnet.pub/install.sh | sh
botnet --help</code></pre>
        </section>
        <section id="quickstart" class="doc-section">
          <h2>Quickstart</h2>
          <p>Run a read-only check first, then run a signed mutation.</p>
          <pre><code># read-only search
botnet --base-url https://botnet.pub/v1 search --q assistant --limit 5

# signed register
botnet --base-url https://botnet.pub/v1 \
  --key-id k1 \
  --secret-seed-hex 0000000000000000000000000000000000000000000000000000000000000000 \
  register bot.json</code></pre>
        </section>
        <section id="signing" class="doc-section">
          <h2>Signing Model</h2>
          <p>These commands require signing flags: <code>register</code>, <code>update</code>, <code>add-key</code>, <code>remove-key</code>, <code>rotate-key</code>, <code>revoke-bot</code>, <code>publish-attestation</code>.</p>
          <p>Read-only commands do not require keys: <code>get</code>, <code>search</code>, <code>nonce</code>.</p>
          <p>Use the same key ID and seed consistently for workflows that mutate the same bot identity.</p>
        </section>
        <section id="inputs" class="doc-section">
          <h2>JSON Inputs</h2>
          <p>Most mutation commands read JSON files. Start with these templates.</p>
          <p><strong><code>register</code> / <code>update</code> file (<code>BotRecord</code>):</strong></p>
          <pre><code>{{
  "status": "active",
  "display_name": "Example Bot",
  "description": "Automates routine tasks.",
  "public_keys": [
    {{
      "key_id": "k1",
      "algorithm": "Ed25519",
      "public_key_multibase": "z6Mke...",
      "purpose": ["signing"],
      "primary": true
    }}
  ],
  "capabilities": ["calendar.read", "email.send"]
}}</code></pre>
          <p><strong><code>add-key</code> file (<code>PublicKey</code>):</strong></p>
          <pre><code>{{
  "key_id": "k2",
  "algorithm": "Ed25519",
  "public_key_multibase": "z6Mkh...",
  "purpose": ["signing"],
  "primary": false
}}</code></pre>
          <p><strong><code>rotate-key</code> file:</strong></p>
          <pre><code>{{
  "old_key_id": "k1",
  "new_key": {{
    "key_id": "k2",
    "algorithm": "Ed25519",
    "public_key_multibase": "z6Mkh...",
    "purpose": ["signing"],
    "primary": true
  }}
}}</code></pre>
          <p><strong><code>publish-attestation</code> file (<code>Attestation</code>):</strong></p>
          <pre><code>{{
  "issuer_bot_id": "urn:bot:sha256:...",
  "type": "compliance",
  "statement": {{ "level": "gold" }},
  "signature": {{
    "algorithm": "Ed25519",
    "key_id": "issuer-key",
    "jws": "&lt;detached-jws&gt;"
  }}
}}</code></pre>
        </section>
        <section id="playbooks" class="doc-section">
          <h2>Command Playbooks</h2>
          <p>Use these common paths depending on your goal.</p>
          <table>
            <thead><tr><th>Goal</th><th>Command Sequence</th></tr></thead>
            <tbody>
              <tr><td>Create and verify a bot</td><td><code>register</code> → <code>get</code> → <code>search</code></td></tr>
              <tr><td>Key lifecycle</td><td><code>add-key</code> → <code>rotate-key</code> → <code>remove-key</code></td></tr>
              <tr><td>Shutdown identity</td><td><code>revoke-bot</code> (and verify via <code>get</code>)</td></tr>
              <tr><td>Trust signals</td><td><code>publish-attestation</code> to subject bot record</td></tr>
            </tbody>
          </table>
        </section>
        <section id="catalog" class="doc-section">
          <h2>Generated Catalog</h2>
          <table>
            <thead><tr><th>Command</th><th>Purpose</th><th>Help Summary</th><th>Usage</th></tr></thead>
            <tbody>{}</tbody>
          </table>
        </section>
        <section id="details" class="doc-section">
          <h2>Command Details</h2>
          <p>Human notes plus full generated help output for each command.</p>
        </section>
        {}
        "##,
        catalog_rows, detail_sections
    );

    let toc_html = String::from(
        r##"
        <a href="#install">Install</a>
        <a href="#quickstart">Quickstart</a>
        <a href="#signing">Signing Model</a>
        <a href="#inputs">JSON Inputs</a>
        <a href="#playbooks">Command Playbooks</a>
        <a href="#catalog">Generated Catalog</a>
        <a href="#details">Command Details</a>
    "##,
    );

    docs_shell(DocsShellArgs {
        page_title: "CLI Reference",
        page_subtitle: "Human workflows plus generated command metadata from Clap.",
        sidebar_html: &sidebar_html,
        content_html: &content_html,
        toc_html: &toc_html,
        home_active: false,
        api_active: false,
        cli_active: true,
    })
}

#[derive(Clone, Copy)]
struct CliCommandGuide {
    purpose: &'static str,
    input_file: &'static str,
    example: &'static str,
}

fn cli_command_explainer(command: &CliCommandDoc) -> CliCommandGuide {
    match command.invocation.as_str() {
        "botnet register" => CliCommandGuide {
            purpose: "Create a new bot identity from a BotRecord JSON file.",
            input_file: "BotRecord JSON file required.",
            example: "botnet --base-url https://botnet.pub/v1 --key-id k1 --secret-seed-hex <SEED_HEX> register bot.json",
        },
        "botnet get" => CliCommandGuide {
            purpose: "Fetch one bot record by bot ID.",
            input_file: "No file input.",
            example: "botnet --base-url https://botnet.pub/v1 get urn:bot:sha256:<id>",
        },
        "botnet update" => CliCommandGuide {
            purpose: "Update mutable bot fields using a BotRecord JSON file.",
            input_file: "BotRecord JSON file required.",
            example: "botnet --base-url https://botnet.pub/v1 --key-id k1 --secret-seed-hex <SEED_HEX> update urn:bot:sha256:<id> bot-update.json",
        },
        "botnet add-key" => CliCommandGuide {
            purpose: "Attach a new signing key to an existing bot.",
            input_file: "PublicKey JSON file required.",
            example: "botnet --base-url https://botnet.pub/v1 --key-id k1 --secret-seed-hex <SEED_HEX> add-key urn:bot:sha256:<id> new-key.json",
        },
        "botnet remove-key" => CliCommandGuide {
            purpose: "Revoke an existing key on a bot.",
            input_file: "No file input.",
            example: "botnet --base-url https://botnet.pub/v1 --key-id k1 --secret-seed-hex <SEED_HEX> remove-key urn:bot:sha256:<id> k2 --reason compromised",
        },
        "botnet rotate-key" => CliCommandGuide {
            purpose: "Rotate a key in one operation: revoke old key and add new key.",
            input_file: "Rotate JSON file required (old_key_id + new_key).",
            example: "botnet --base-url https://botnet.pub/v1 --key-id k1 --secret-seed-hex <SEED_HEX> rotate-key urn:bot:sha256:<id> rotate.json",
        },
        "botnet revoke-bot" => CliCommandGuide {
            purpose: "Revoke the entire bot identity (status becomes revoked).",
            input_file: "No file input.",
            example: "botnet --base-url https://botnet.pub/v1 --key-id k1 --secret-seed-hex <SEED_HEX> revoke-bot urn:bot:sha256:<id> --reason retired",
        },
        "botnet publish-attestation" => CliCommandGuide {
            purpose: "Publish an issuer-signed attestation to a subject bot.",
            input_file: "Attestation JSON file required.",
            example: "botnet --base-url https://botnet.pub/v1 --key-id issuer-key --secret-seed-hex <SEED_HEX> publish-attestation urn:bot:sha256:<subject> attestation.json",
        },
        "botnet search" => CliCommandGuide {
            purpose: "Find bots by query, status, capability, and limit filters.",
            input_file: "No file input.",
            example: "botnet --base-url https://botnet.pub/v1 search --q assistant --status active --limit 20",
        },
        "botnet nonce" => CliCommandGuide {
            purpose: "Fetch a server nonce for anti-replay signing flows.",
            input_file: "No file input.",
            example: "botnet --base-url https://botnet.pub/v1 nonce",
        },
        _ => CliCommandGuide {
            purpose: "Run this command for specialized workflow actions.",
            input_file: "See generated help output below.",
            example: "botnet --help",
        },
    }
}

fn build_api_docs_model() -> ApiDocsModel {
    let openapi = serde_json::to_value(ApiDoc::openapi()).unwrap_or(Value::Null);

    let mut endpoints = Vec::new();
    if let Some(paths) = openapi.get("paths").and_then(Value::as_object) {
        for (path, path_item) in paths {
            let Some(path_obj) = path_item.as_object() else {
                continue;
            };
            for method in ["get", "post", "patch", "put", "delete", "options", "head"] {
                let Some(operation) = path_obj.get(method).and_then(Value::as_object) else {
                    continue;
                };

                let summary = operation
                    .get("summary")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| {
                        operation
                            .get("operationId")
                            .and_then(Value::as_str)
                            .map(prettify_identifier)
                            .unwrap_or_else(|| "Untitled operation".to_string())
                    });
                let description = operation
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let operation_id = operation
                    .get("operationId")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let auth = auth_requirement(method, path).to_string();

                let mut parameters = Vec::new();
                if let Some(params) = operation.get("parameters").and_then(Value::as_array) {
                    for parameter in params {
                        let Some(param) = parameter.as_object() else {
                            continue;
                        };
                        parameters.push(ApiParameterDoc {
                            name: param
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or("unknown")
                                .to_string(),
                            location: param
                                .get("in")
                                .and_then(Value::as_str)
                                .unwrap_or("query")
                                .to_string(),
                            required: param
                                .get("required")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                            schema: param
                                .get("schema")
                                .map(describe_schema)
                                .unwrap_or_else(|| "unknown".to_string()),
                            description: param
                                .get("description")
                                .and_then(Value::as_str)
                                .map(str::to_string),
                        });
                    }
                }

                let request_body = operation
                    .get("requestBody")
                    .and_then(|body| body.get("content"))
                    .and_then(Value::as_object)
                    .and_then(|content| {
                        content
                            .get("application/json")
                            .or_else(|| content.values().next())
                            .and_then(|entry| entry.get("schema"))
                    })
                    .map(describe_schema);

                let mut responses = Vec::new();
                if let Some(response_map) = operation.get("responses").and_then(Value::as_object) {
                    for (status, response) in response_map {
                        responses.push(ApiResponseDoc {
                            status: status.to_string(),
                            description: response
                                .get("description")
                                .and_then(Value::as_str)
                                .map(str::to_string),
                        });
                    }
                }
                responses.sort_by(|a, b| a.status.cmp(&b.status));

                endpoints.push(ApiEndpointDoc {
                    method: method.to_ascii_uppercase(),
                    path: path.to_string(),
                    summary,
                    description,
                    operation_id,
                    auth,
                    parameters,
                    request_body,
                    responses,
                });
            }
        }
    }
    endpoints.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then_with(|| method_rank(&a.method).cmp(&method_rank(&b.method)))
    });

    let mut schemas = Vec::new();
    if let Some(schema_map) = openapi
        .get("components")
        .and_then(|components| components.get("schemas"))
        .and_then(Value::as_object)
    {
        for (name, schema) in schema_map {
            let required_fields = schema
                .get("required")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            let property_count = schema
                .get("properties")
                .and_then(Value::as_object)
                .map_or(0, serde_json::Map::len);
            let kind = describe_schema_kind(schema);
            schemas.push(ApiSchemaDoc {
                name: name.clone(),
                kind,
                required_fields,
                property_count,
            });
        }
    }
    schemas.sort_by(|a, b| a.name.cmp(&b.name));

    ApiDocsModel { endpoints, schemas }
}

fn flatten_cli_commands<'a>(commands: &'a [CliCommandDoc], out: &mut Vec<&'a CliCommandDoc>) {
    for command in commands {
        out.push(command);
        flatten_cli_commands(&command.subcommands, out);
    }
}

fn count_cli_commands(commands: &[CliCommandDoc]) -> usize {
    let mut total = 0;
    for command in commands {
        total += 1 + count_cli_commands(&command.subcommands);
    }
    total
}

fn endpoint_anchor(endpoint: &ApiEndpointDoc) -> String {
    slugify(&format!(
        "{} {}",
        endpoint.method.to_lowercase(),
        endpoint.path
    ))
}

fn cli_command_anchor(command: &CliCommandDoc) -> String {
    slugify(&command.invocation)
}

fn method_rank(method: &str) -> u8 {
    match method {
        "GET" => 0,
        "POST" => 1,
        "PATCH" => 2,
        "PUT" => 3,
        "DELETE" => 4,
        "OPTIONS" => 5,
        "HEAD" => 6,
        _ => 7,
    }
}

fn auth_requirement(method: &str, path: &str) -> &'static str {
    match (method, path) {
        ("post", "/v1/bots")
        | ("patch", "/v1/bots/{bot_id}")
        | ("post", "/v1/bots/{bot_id}/keys")
        | ("delete", "/v1/bots/{bot_id}/keys/{key_id}")
        | ("post", "/v1/bots/{bot_id}/rotate")
        | ("post", "/v1/bots/{bot_id}/revoke") => "proof or proof_set required",
        ("post", "/v1/attestations") => "issuer attestation signature required",
        _ => "public",
    }
}

fn prettify_identifier(identifier: &str) -> String {
    identifier
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    format!(
                        "{}{}",
                        first.to_ascii_uppercase(),
                        chars.as_str().to_ascii_lowercase()
                    )
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn describe_schema(schema: &Value) -> String {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .rsplit('/')
            .next()
            .unwrap_or(reference)
            .to_string();
    }

    if let Some(schema_type) = schema.get("type").and_then(Value::as_str) {
        if schema_type == "array" {
            if let Some(item_schema) = schema.get("items") {
                return format!("array<{}>", describe_schema(item_schema));
            }
            return "array".to_string();
        }
        return schema_type.to_string();
    }

    if schema.get("oneOf").is_some() {
        return "oneOf".to_string();
    }
    if schema.get("anyOf").is_some() {
        return "anyOf".to_string();
    }
    if schema.get("allOf").is_some() {
        return "allOf".to_string();
    }
    "object".to_string()
}

fn describe_schema_kind(schema: &Value) -> String {
    let kind = describe_schema(schema);
    if kind == "object" {
        if let Some(enum_values) = schema.get("enum").and_then(Value::as_array) {
            return format!("enum({})", enum_values.len());
        }
    }
    kind
}

fn slugify(input: &str) -> String {
    let mut output = String::new();
    let mut last_was_dash = false;

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            output.push('-');
            last_was_dash = true;
        }
    }

    let trimmed = output.trim_matches('-');
    if trimmed.is_empty() {
        "section".to_string()
    } else {
        trimmed.to_string()
    }
}

fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

struct DocsShellArgs<'a> {
    page_title: &'a str,
    page_subtitle: &'a str,
    sidebar_html: &'a str,
    content_html: &'a str,
    toc_html: &'a str,
    home_active: bool,
    api_active: bool,
    cli_active: bool,
}

fn docs_shell(args: DocsShellArgs<'_>) -> Html<String> {
    let home_tab = if args.home_active { "active" } else { "" };
    let api_tab = if args.api_active { "active" } else { "" };
    let cli_tab = if args.cli_active { "active" } else { "" };

    let html = format!(
        r##"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>botnet.pub docs | {}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;600;700;800&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet" />
    <style>
      :root {{
        --bg: #070a11;
        --panel: #0f1522;
        --line: #1f2b3f;
        --line-soft: #172133;
        --text: #e6eaf4;
        --muted: #9aa5b9;
        --accent: #60a5fa;
      }}
      * {{ box-sizing: border-box; }}
      html, body {{ margin: 0; height: 100%; }}
      body {{
        font-family: "Manrope", "Avenir Next", "Segoe UI", sans-serif;
        color: var(--text);
        background:
          radial-gradient(900px 360px at 8% -10%, rgba(56, 189, 248, 0.12), transparent 56%),
          radial-gradient(700px 280px at 100% 8%, rgba(99, 102, 241, 0.10), transparent 60%),
          var(--bg);
      }}
      .topbar {{
        height: 64px;
        border-bottom: 1px solid var(--line);
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0 1rem;
        position: sticky;
        top: 0;
        background: rgba(8, 12, 20, 0.86);
        backdrop-filter: blur(8px);
        z-index: 10;
      }}
      .brand {{
        font-weight: 700;
        letter-spacing: 0.03em;
      }}
      .tabs {{
        display: flex;
        gap: 0.45rem;
      }}
      .tabs a {{
        color: var(--muted);
        text-decoration: none;
        border: 1px solid var(--line-soft);
        border-radius: 999px;
        padding: 0.35rem 0.62rem;
        font-size: 0.78rem;
        font-family: ui-monospace, Menlo, Consolas, monospace;
      }}
      .tabs a.active {{
        color: #dbeafe;
        border-color: #2f4367;
        background: #111a2b;
      }}
      .search {{
        border: 1px solid var(--line-soft);
        border-radius: 999px;
        padding: 0.35rem 0.7rem;
        color: var(--muted);
        font-family: ui-monospace, Menlo, Consolas, monospace;
        font-size: 0.78rem;
      }}
      .layout {{
        display: grid;
        grid-template-columns: 280px minmax(0, 1fr) 220px;
        min-height: calc(100vh - 64px);
      }}
      .sidebar {{
        border-right: 1px solid var(--line);
        padding: 1rem;
        background: rgba(10, 15, 24, 0.75);
      }}
      .side-group {{ margin-bottom: 1.2rem; }}
      .side-title {{
        color: var(--muted);
        font-size: 0.73rem;
        text-transform: uppercase;
        letter-spacing: 0.12em;
        margin-bottom: 0.45rem;
        font-family: ui-monospace, Menlo, Consolas, monospace;
      }}
      .side-link {{
        display: block;
        color: #c6cfdf;
        text-decoration: none;
        padding: 0.38rem 0.42rem;
        border-radius: 8px;
        font-size: 0.9rem;
      }}
      .side-link:hover {{ background: #121b2d; }}
      .side-link.active {{
        background: #16233a;
        border: 1px solid #2a4065;
      }}
      .content {{
        padding: 1.2rem 1.4rem 2rem;
      }}
      .headline {{
        border: 1px solid var(--line);
        border-radius: 12px;
        background: var(--panel);
        padding: 0.95rem 1rem;
      }}
      .headline h1 {{
        margin: 0;
        font-size: clamp(1.6rem, 3.4vw, 2.25rem);
        letter-spacing: -0.02em;
      }}
      .headline p {{
        margin: 0.45rem 0 0;
        color: var(--muted);
      }}
      .doc-section {{
        margin-top: 1rem;
        border: 1px solid var(--line);
        border-radius: 12px;
        background: var(--panel);
        padding: 1rem;
      }}
      .doc-section h1,
      .doc-section h2 {{
        margin: 0 0 0.55rem;
      }}
      .doc-section p {{
        margin: 0;
        color: var(--muted);
        line-height: 1.55;
      }}
      .doc-section ol,
      .doc-section ul {{
        margin: 0.55rem 0 0;
        padding-left: 1.2rem;
        color: var(--muted);
        line-height: 1.5;
      }}
      .doc-section li + li {{
        margin-top: 0.25rem;
      }}
      .doc-grid {{
        margin-top: 0.7rem;
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 0.75rem;
      }}
      .mini-card {{
        border: 1px solid #24324a;
        border-radius: 10px;
        padding: 0.8rem;
        background: #0b111c;
      }}
      .mini-card h3 {{ margin: 0; }}
      .mini-card p {{ margin-top: 0.35rem; font-size: 0.9rem; }}
      .mini-card a {{
        display: inline-block;
        margin-top: 0.55rem;
        color: #93c5fd;
        text-decoration: none;
        font-size: 0.9rem;
      }}
      table {{
        width: 100%;
        border-collapse: collapse;
        margin-top: 0.6rem;
      }}
      th, td {{
        border: 1px solid #26344c;
        padding: 0.5rem;
        text-align: left;
        vertical-align: top;
        font-size: 0.9rem;
      }}
      th {{ background: #111b2d; }}
      code, pre {{
        font-family: "IBM Plex Mono", "SFMono-Regular", "Menlo", monospace;
      }}
      pre {{
        margin: 0.75rem 0 0;
        border: 1px solid #2a3b5a;
        border-radius: 10px;
        background: #090e18;
        color: #eef2ff;
        padding: 0.85rem;
        overflow: auto;
      }}
      .toc {{
        border-left: 1px solid var(--line);
        padding: 1rem 0.9rem;
        background: rgba(10, 15, 24, 0.65);
      }}
      .toc h3 {{
        margin: 0;
        color: var(--muted);
        font-size: 0.73rem;
        text-transform: uppercase;
        letter-spacing: 0.12em;
        font-family: ui-monospace, Menlo, Consolas, monospace;
      }}
      .toc nav {{
        margin-top: 0.55rem;
        display: grid;
        gap: 0.35rem;
      }}
      .toc a {{
        color: #c4cede;
        text-decoration: none;
        font-size: 0.87rem;
      }}
      .toc a:hover {{ color: #ffffff; }}
      @media (max-width: 1100px) {{
        .layout {{ grid-template-columns: 240px minmax(0, 1fr); }}
        .toc {{ display: none; }}
      }}
      @media (max-width: 760px) {{
        .layout {{ grid-template-columns: 1fr; }}
        .sidebar {{ border-right: 0; border-bottom: 1px solid var(--line); }}
        .tabs {{ display: none; }}
      }}
    </style>
  </head>
  <body>
    <header class="topbar">
      <div class="brand">botnet.pub docs</div>
      <nav class="tabs">
        <a href="/docs" class="{}">home</a>
        <a href="/docs/api" class="{}">api</a>
        <a href="/docs/cli" class="{}">cli</a>
      </nav>
      <div class="search">search (soon)</div>
    </header>
    <main class="layout">
      <aside class="sidebar">{}</aside>
      <section class="content">
        <div class="headline">
          <h1>{}</h1>
          <p>{}</p>
        </div>
        {}
      </section>
      <aside class="toc">
        <h3>On This Page</h3>
        <nav>{}</nav>
      </aside>
    </main>
  </body>
</html>"##,
        args.page_title,
        home_tab,
        api_tab,
        cli_tab,
        args.sidebar_html,
        args.page_title,
        args.page_subtitle,
        args.content_html,
        args.toc_html
    );
    Html(html)
}

async fn openapi_json() -> impl IntoResponse {
    Json(ApiDoc::openapi())
}

async fn swagger() -> impl IntoResponse {
    Html(
        r#"<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>AI Bot Registry Swagger</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.ui = SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui'
      });
    </script>
  </body>
</html>
"#,
    )
}

#[utoipa::path(
    get,
    path = "/health",
    summary = "Health check (public)",
    responses(
        (status = 200, description = "Liveness endpoint.", body = HealthResponse)
    ),
    tag = "bot-registry"
)]
async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

#[utoipa::path(
    get,
    path = "/v1/stats",
    summary = "Registry stats (public)",
    responses(
        (status = 200, description = "Current registry counts and health-adjacent metrics.", body = RegistryStatsResponse),
        (status = 500, description = "Server error.", body = ErrorResponse)
    ),
    tag = "bot-registry"
)]
async fn registry_stats(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let bots = state.store.list_bots().await.map_err(internal)?;

    let total_bots = bots.len();
    let active_bots = bots
        .iter()
        .filter(|b| matches!(b.status, BotStatus::Active))
        .count();
    let deprecated_bots = bots
        .iter()
        .filter(|b| matches!(b.status, BotStatus::Deprecated))
        .count();
    let revoked_bots = bots
        .iter()
        .filter(|b| matches!(b.status, BotStatus::Revoked))
        .count();

    let total_keys = bots.iter().map(|b| b.public_keys.len()).sum();
    let active_keys = bots
        .iter()
        .flat_map(|b| b.public_keys.iter())
        .filter(|k| k.revoked_at.is_none())
        .count();
    let revoked_keys = total_keys - active_keys;
    let total_attestations = bots
        .iter()
        .map(|b| b.attestations.as_ref().map(|v| v.len()).unwrap_or(0))
        .sum();
    let total_controllers = bots
        .iter()
        .map(|b| b.controllers.as_ref().map(|v| v.len()).unwrap_or(0))
        .sum();
    let last_bot_update = bots.iter().filter_map(|b| b.updated_at.clone()).max();

    Ok(Json(RegistryStatsResponse {
        total_bots,
        active_bots,
        deprecated_bots,
        revoked_bots,
        total_keys,
        active_keys,
        revoked_keys,
        total_attestations,
        total_controllers,
        server_time: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        last_bot_update,
    }))
}

#[utoipa::path(
    post,
    path = "/v1/bots",
    summary = "Create bot (auth required)",
    request_body = BotRecord,
    responses(
        (status = 201, description = "Bot created.", body = BotRecord),
        (status = 400, description = "Invalid payload, signature, or policy inputs.", body = ErrorResponse),
        (status = 409, description = "Bot already exists.", body = ErrorResponse),
        (status = 500, description = "Server error.", body = ErrorResponse)
    ),
    tag = "bot-registry",
    description = "Create a new bot identity record. Auth is proof-based: provide either `proof` (single signature) \
                   or `proof_set` (multi-signature), but not both. Signatures are verified over the JCS-canonicalized payload \
                   with proof fields removed."
)]
async fn create_bot(
    State(state): State<AppState>,
    Json(mut incoming): Json<BotRecord>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    validate_bot_record(&incoming).map_err(invalid)?;

    verify_record_signatures(&incoming, &incoming, state.store.as_ref())
        .await
        .map_err(invalid)?;

    let primary = incoming
        .public_keys
        .iter()
        .find(|k| k.primary.unwrap_or(false))
        .ok_or_else(|| invalid(anyhow::anyhow!("missing primary key")))?;

    let (_, pk_bytes) = multibase::decode(&primary.public_key_multibase)
        .map_err(|e| invalid(anyhow::anyhow!("invalid multibase key: {e}")))?;

    let bot_id = derive_bot_id(&pk_bytes);
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    incoming.bot_id = Some(bot_id.clone());
    incoming.version = Some(1);
    incoming.created_at = Some(now.clone());
    incoming.updated_at = Some(now);

    if state
        .store
        .get_bot(&bot_id)
        .await
        .map_err(internal)?
        .is_some()
    {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "bot already exists".to_string(),
            }),
        ));
    }
    state.store.create_bot(&incoming).await.map_err(internal)?;

    Ok((StatusCode::CREATED, Json(incoming)))
}

#[utoipa::path(
    get,
    path = "/v1/bots/{bot_id}",
    summary = "Get bot (public)",
    params(
        ("bot_id" = String, Path, description = "Bot identifier")
    ),
    responses(
        (status = 200, description = "Bot record.", body = BotRecord),
        (status = 404, description = "Bot not found.", body = ErrorResponse),
        (status = 500, description = "Server error.", body = ErrorResponse)
    ),
    tag = "bot-registry"
)]
async fn get_bot(
    State(state): State<AppState>,
    Path(bot_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let Some(bot) = state.store.get_bot(&bot_id).await.map_err(internal)? else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not found".to_string(),
            }),
        ));
    };
    Ok((StatusCode::OK, Json(bot)))
}

#[utoipa::path(
    patch,
    path = "/v1/bots/{bot_id}",
    summary = "Update bot (auth required)",
    params(
        ("bot_id" = String, Path, description = "Bot identifier")
    ),
    request_body = BotRecord,
    responses(
        (status = 200, description = "Updated bot record.", body = BotRecord),
        (status = 400, description = "Invalid payload/signature or policy threshold not met.", body = ErrorResponse),
        (status = 404, description = "Bot not found.", body = ErrorResponse),
        (status = 500, description = "Server error.", body = ErrorResponse)
    ),
    tag = "bot-registry",
    description = "Update mutable fields on a bot record. Requires either `proof` or `proof_set`. \
                   The server verifies signatures from `proof` or `proof_set`, \
                   resolves controller keys when used, and enforces the bot's operation policy (including m-of-n threshold rules)."
)]
async fn update_bot(
    State(state): State<AppState>,
    Path(bot_id): Path<String>,
    Json(mut incoming): Json<BotRecord>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let current = state
        .store
        .get_bot(&bot_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not found".to_string(),
                }),
            )
        })?;

    // keep identity and immutable metadata server-managed
    incoming.bot_id = Some(bot_id.clone());
    incoming.created_at = current.created_at.clone();

    validate_bot_record(&incoming).map_err(invalid)?;
    let valid_signers = verify_record_signatures(&incoming, &current, state.store.as_ref())
        .await
        .map_err(invalid)?;

    evaluate_threshold(current.policy.as_ref(), Operation::Update, &valid_signers)
        .map_err(invalid)?;

    let version = current.version.unwrap_or(1) + 1;
    incoming.version = Some(version);
    incoming.updated_at = Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));

    state.store.update_bot(&incoming).await.map_err(internal)?;
    Ok((StatusCode::OK, Json(incoming)))
}

#[utoipa::path(
    post,
    path = "/v1/bots/{bot_id}/keys",
    summary = "Add key (auth required)",
    params(
        ("bot_id" = String, Path, description = "Bot identifier")
    ),
    request_body = AddKeyRequest,
    responses(
        (status = 200, description = "Updated bot record with new key.", body = BotRecord),
        (status = 400, description = "Invalid request/signature/policy.", body = ErrorResponse),
        (status = 404, description = "Bot not found.", body = ErrorResponse),
        (status = 409, description = "Key ID or key material already exists.", body = ErrorResponse),
        (status = 500, description = "Server error.", body = ErrorResponse)
    ),
    tag = "bot-registry",
    description = "Add a new key to a bot. Requires either `proof` or `proof_set`; signatures are verified against the updated canonical payload and policy."
)]
async fn add_key(
    State(state): State<AppState>,
    Path(bot_id): Path<String>,
    Json(request): Json<AddKeyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let current = state
        .store
        .get_bot(&bot_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not found".to_string(),
                }),
            )
        })?;

    if current.status == BotStatus::Revoked {
        return Err(invalid(anyhow::anyhow!("cannot add key to a revoked bot")));
    }

    if current
        .public_keys
        .iter()
        .any(|k| k.key_id == request.public_key.key_id)
    {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "key_id already exists".to_string(),
            }),
        ));
    }
    if current
        .public_keys
        .iter()
        .any(|k| k.public_key_multibase == request.public_key.public_key_multibase)
    {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "public key already exists".to_string(),
            }),
        ));
    }

    let mut updated = current.clone();
    let mut new_key = request.public_key;
    if new_key.primary.unwrap_or(false) {
        for key in &mut updated.public_keys {
            key.primary = Some(false);
        }
    } else if new_key.primary.is_none() {
        new_key.primary = Some(false);
    }
    updated.public_keys.push(new_key);
    updated.proof = request.proof;
    updated.proof_set = request.proof_set;

    validate_bot_record(&updated).map_err(invalid)?;
    let valid_signers = verify_record_signatures(&updated, &current, state.store.as_ref())
        .await
        .map_err(invalid)?;
    evaluate_threshold(current.policy.as_ref(), Operation::AddKey, &valid_signers)
        .map_err(invalid)?;

    updated.bot_id = Some(bot_id.clone());
    updated.created_at = current.created_at.clone();
    updated.version = Some(current.version.unwrap_or(1) + 1);
    updated.updated_at = Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));

    state.store.update_bot(&updated).await.map_err(internal)?;
    Ok((StatusCode::OK, Json(updated)))
}

#[utoipa::path(
    delete,
    path = "/v1/bots/{bot_id}/keys/{key_id}",
    summary = "Revoke key (auth required)",
    params(
        ("bot_id" = String, Path, description = "Bot identifier"),
        ("key_id" = String, Path, description = "Signing key identifier")
    ),
    request_body = RemoveKeyRequest,
    responses(
        (status = 200, description = "Updated bot record with key revoked.", body = BotRecord),
        (status = 400, description = "Invalid request/signature/policy.", body = ErrorResponse),
        (status = 404, description = "Bot or key not found.", body = ErrorResponse),
        (status = 500, description = "Server error.", body = ErrorResponse)
    ),
    tag = "bot-registry",
    description = "Revoke a key for a bot. Requires either `proof` or `proof_set`; the signer set must satisfy the policy for `revoke_key`."
)]
async fn remove_key(
    State(state): State<AppState>,
    Path((bot_id, key_id)): Path<(String, String)>,
    Json(request): Json<RemoveKeyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let current = state
        .store
        .get_bot(&bot_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not found".to_string(),
                }),
            )
        })?;

    if current.status == BotStatus::Revoked {
        return Err(invalid(anyhow::anyhow!("bot is already revoked")));
    }

    let mut updated = current.clone();
    updated.proof = request.proof;
    updated.proof_set = request.proof_set;
    let effective_time = first_proof_created_at(&updated).map_err(invalid)?;
    let idx = updated
        .public_keys
        .iter()
        .position(|k| k.key_id == key_id)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "key not found".to_string(),
                }),
            )
        })?;
    if updated.public_keys[idx].revoked_at.is_some() {
        return Err(invalid(anyhow::anyhow!("key is already revoked")));
    }
    let was_primary = updated.public_keys[idx].primary.unwrap_or(false);
    updated.public_keys[idx].revoked_at = Some(effective_time.clone());
    updated.public_keys[idx].revocation_reason = request
        .reason
        .clone()
        .or_else(|| Some("revoked".to_string()));
    updated.public_keys[idx].primary = Some(false);

    if was_primary {
        let replacement = updated
            .public_keys
            .iter_mut()
            .find(|k| k.key_id != key_id && k.revoked_at.is_none())
            .ok_or_else(|| invalid(anyhow::anyhow!("cannot revoke the only active key")))?;
        replacement.primary = Some(true);
    }

    validate_bot_record(&updated).map_err(invalid)?;
    let valid_signers = verify_record_signatures(&updated, &current, state.store.as_ref())
        .await
        .map_err(invalid)?;
    evaluate_threshold(
        current.policy.as_ref(),
        Operation::RevokeKey,
        &valid_signers,
    )
    .map_err(invalid)?;

    updated.bot_id = Some(bot_id.clone());
    updated.created_at = current.created_at.clone();
    updated.version = Some(current.version.unwrap_or(1) + 1);
    updated.updated_at = Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
    state.store.update_bot(&updated).await.map_err(internal)?;
    Ok((StatusCode::OK, Json(updated)))
}

#[utoipa::path(
    post,
    path = "/v1/bots/{bot_id}/rotate",
    summary = "Rotate key (auth required)",
    params(
        ("bot_id" = String, Path, description = "Bot identifier")
    ),
    request_body = RotateKeyRequest,
    responses(
        (status = 200, description = "Updated bot record with rotated key.", body = BotRecord),
        (status = 400, description = "Invalid request/signature/policy.", body = ErrorResponse),
        (status = 404, description = "Bot or old key not found.", body = ErrorResponse),
        (status = 409, description = "New key conflicts with an existing key.", body = ErrorResponse),
        (status = 500, description = "Server error.", body = ErrorResponse)
    ),
    tag = "bot-registry",
    description = "Rotate a bot signing key in one operation (revoke old + add new). Requires either `proof` or `proof_set` and policy approval."
)]
async fn rotate_key(
    State(state): State<AppState>,
    Path(bot_id): Path<String>,
    Json(request): Json<RotateKeyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let current = state
        .store
        .get_bot(&bot_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not found".to_string(),
                }),
            )
        })?;

    if current.status == BotStatus::Revoked {
        return Err(invalid(anyhow::anyhow!(
            "cannot rotate key on a revoked bot"
        )));
    }

    if current
        .public_keys
        .iter()
        .any(|k| k.key_id == request.new_key.key_id)
    {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "new key_id already exists".to_string(),
            }),
        ));
    }
    if current
        .public_keys
        .iter()
        .any(|k| k.public_key_multibase == request.new_key.public_key_multibase)
    {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "new public key already exists".to_string(),
            }),
        ));
    }

    let mut updated = current.clone();
    updated.proof = request.proof;
    updated.proof_set = request.proof_set;
    let effective_time = first_proof_created_at(&updated).map_err(invalid)?;
    let old_idx = updated
        .public_keys
        .iter()
        .position(|k| k.key_id == request.old_key_id)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "old key not found".to_string(),
                }),
            )
        })?;
    if updated.public_keys[old_idx].revoked_at.is_some() {
        return Err(invalid(anyhow::anyhow!("old key is already revoked")));
    }

    let old_was_primary = updated.public_keys[old_idx].primary.unwrap_or(false);
    updated.public_keys[old_idx].revoked_at = Some(effective_time.clone());
    updated.public_keys[old_idx].revocation_reason = Some("rotated".to_string());
    updated.public_keys[old_idx].primary = Some(false);

    let mut new_key = request.new_key;
    if old_was_primary {
        for key in &mut updated.public_keys {
            key.primary = Some(false);
        }
        new_key.primary = Some(true);
    } else if new_key.primary.unwrap_or(false) {
        for key in &mut updated.public_keys {
            if key.revoked_at.is_none() {
                key.primary = Some(false);
            }
        }
    } else if new_key.primary.is_none() {
        new_key.primary = Some(false);
    }

    updated.public_keys.push(new_key);
    validate_bot_record(&updated).map_err(invalid)?;
    let valid_signers = verify_record_signatures(&updated, &current, state.store.as_ref())
        .await
        .map_err(invalid)?;
    evaluate_threshold(
        current.policy.as_ref(),
        Operation::RotateKey,
        &valid_signers,
    )
    .map_err(invalid)?;

    updated.bot_id = Some(bot_id.clone());
    updated.created_at = current.created_at.clone();
    updated.version = Some(current.version.unwrap_or(1) + 1);
    updated.updated_at = Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));

    state.store.update_bot(&updated).await.map_err(internal)?;
    Ok((StatusCode::OK, Json(updated)))
}

#[utoipa::path(
    post,
    path = "/v1/bots/{bot_id}/revoke",
    summary = "Revoke bot (auth required)",
    params(
        ("bot_id" = String, Path, description = "Bot identifier")
    ),
    request_body = RevokeBotRequest,
    responses(
        (status = 200, description = "Bot revoked.", body = BotRecord),
        (status = 400, description = "Invalid request/signature/policy.", body = ErrorResponse),
        (status = 404, description = "Bot not found.", body = ErrorResponse),
        (status = 500, description = "Server error.", body = ErrorResponse)
    ),
    tag = "bot-registry",
    description = "Revoke an entire bot identity. Requires either `proof` or `proof_set`; signatures must satisfy `revoke_bot` policy."
)]
async fn revoke_bot(
    State(state): State<AppState>,
    Path(bot_id): Path<String>,
    Json(request): Json<RevokeBotRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let current = state
        .store
        .get_bot(&bot_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "not found".to_string(),
                }),
            )
        })?;

    let mut updated = current.clone();
    updated.proof = request.proof;
    updated.proof_set = request.proof_set;
    let effective_time = first_proof_created_at(&updated).map_err(invalid)?;
    updated.status = BotStatus::Revoked;
    for key in &mut updated.public_keys {
        if key.revoked_at.is_none() {
            key.revoked_at = Some(effective_time.clone());
        }
        if key.revocation_reason.is_none() {
            key.revocation_reason = request
                .reason
                .clone()
                .or_else(|| Some("bot revoked".to_string()));
        }
    }
    validate_bot_record(&updated).map_err(invalid)?;
    let valid_signers = verify_record_signatures(&updated, &current, state.store.as_ref())
        .await
        .map_err(invalid)?;
    evaluate_threshold(
        current.policy.as_ref(),
        Operation::RevokeBot,
        &valid_signers,
    )
    .map_err(invalid)?;

    updated.bot_id = Some(bot_id.clone());
    updated.created_at = current.created_at.clone();
    updated.version = Some(current.version.unwrap_or(1) + 1);
    updated.updated_at = Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
    state.store.update_bot(&updated).await.map_err(internal)?;

    Ok((StatusCode::OK, Json(updated)))
}

#[utoipa::path(
    post,
    path = "/v1/attestations",
    summary = "Publish attestation (signature required)",
    request_body = PublishAttestationRequest,
    responses(
        (status = 201, description = "Attestation published.", body = Attestation),
        (status = 400, description = "Invalid attestation signature or payload.", body = ErrorResponse),
        (status = 404, description = "Subject or issuer bot not found.", body = ErrorResponse),
        (status = 500, description = "Server error.", body = ErrorResponse)
    ),
    tag = "bot-registry",
    description = "Attach an attestation to a subject bot. The attestation itself must include a valid issuer signature in `attestation.signature`."
)]
async fn publish_attestation(
    State(state): State<AppState>,
    Json(request): Json<PublishAttestationRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let subject = state
        .store
        .get_bot(&request.subject_bot_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "subject bot not found".to_string(),
                }),
            )
        })?;
    let issuer = state
        .store
        .get_bot(&request.attestation.issuer_bot_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "issuer bot not found".to_string(),
                }),
            )
        })?;

    let signer_key = issuer
        .public_keys
        .iter()
        .find(|k| k.key_id == request.attestation.signature.key_id)
        .ok_or_else(|| invalid(anyhow::anyhow!("issuer key_id not found")))?;

    let payload = AttestationPayload {
        subject_bot_id: &request.subject_bot_id,
        issuer_bot_id: &request.attestation.issuer_bot_id,
        attestation_type: &request.attestation.r#type,
        statement: &request.attestation.statement,
        issued_at: &request.attestation.issued_at,
        expires_at: &request.attestation.expires_at,
    };
    let canon = canonicalize(&payload).map_err(|e| invalid(e.into()))?;
    verify_signature_with_key(&request.attestation.signature.jws, &canon, signer_key)
        .map_err(invalid)?;

    let mut attestation = request.attestation;
    if attestation.attestation_id.is_none() {
        attestation.attestation_id = Some(Uuid::new_v4().to_string());
    }

    let mut updated_subject = subject.clone();
    let mut attestations = updated_subject.attestations.take().unwrap_or_default();
    attestations.push(attestation.clone());
    updated_subject.attestations = Some(attestations);
    updated_subject.version = Some(subject.version.unwrap_or(1) + 1);
    updated_subject.updated_at = Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
    state
        .store
        .update_bot(&updated_subject)
        .await
        .map_err(internal)?;

    Ok((StatusCode::CREATED, Json(attestation)))
}

#[utoipa::path(
    get,
    path = "/v1/search",
    summary = "Search bots (public)",
    params(SearchQuery),
    responses(
        (status = 200, description = "Search results.", body = SearchResponse),
        (status = 500, description = "Server error.", body = ErrorResponse)
    ),
    tag = "bot-registry"
)]
async fn search(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let mut results = state.store.list_bots().await.map_err(internal)?;

    if let Some(status) = query.status {
        results.retain(|r| r.status == status);
    }

    if let Some(capability) = query.capability {
        let capability = capability.to_ascii_lowercase();
        results.retain(|r| {
            r.capabilities
                .as_ref()
                .map(|caps| caps.iter().any(|c| c.to_ascii_lowercase() == capability))
                .unwrap_or(false)
        });
    }

    if let Some(q) = query.q {
        let q = q.to_ascii_lowercase();
        results.retain(|r| {
            r.bot_id
                .as_deref()
                .map(|id| id.to_ascii_lowercase().contains(&q))
                .unwrap_or(false)
                || r.display_name
                    .as_deref()
                    .map(|name| name.to_ascii_lowercase().contains(&q))
                    .unwrap_or(false)
                || r.description
                    .as_deref()
                    .map(|desc| desc.to_ascii_lowercase().contains(&q))
                    .unwrap_or(false)
        });
    }

    results.sort_by_key(|r| r.bot_id.clone().unwrap_or_default());
    let limit = query.limit.unwrap_or(50).min(200);
    results.truncate(limit);

    Ok(Json(SearchResponse {
        count: results.len(),
        results,
    }))
}

#[utoipa::path(
    get,
    path = "/v1/nonce",
    summary = "Issue nonce (public)",
    responses(
        (status = 200, description = "Fresh nonce for anti-replay usage.", body = NonceResponse),
        (status = 500, description = "Server error.", body = ErrorResponse)
    ),
    tag = "bot-registry"
)]
async fn get_nonce(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let nonce = state.store.issue_nonce().await.map_err(internal)?;
    Ok((StatusCode::OK, Json(NonceResponse { nonce })))
}

#[derive(Serialize)]
struct AttestationPayload<'a> {
    subject_bot_id: &'a str,
    issuer_bot_id: &'a str,
    #[serde(rename = "type")]
    attestation_type: &'a str,
    statement: &'a serde_json::Value,
    issued_at: &'a Option<String>,
    expires_at: &'a Option<String>,
}

async fn verify_record_signatures(
    incoming: &BotRecord,
    signer_source: &BotRecord,
    store: &dyn Storage,
) -> anyhow::Result<Vec<(Option<String>, String)>> {
    // Auth model: verify detached JWS signatures against the JCS-canonicalized payload
    // with proof fields removed, then return unique signer identities for policy checks.
    let proofs = unified_proofs(incoming)?;
    let canon = canonicalize(&incoming.payload_for_signing())?;

    let mut seen = HashSet::new();
    let mut valid_signers = Vec::with_capacity(proofs.len());
    for proof in proofs {
        if proof.algorithm != "Ed25519" {
            anyhow::bail!("unsupported proof algorithm: {}", proof.algorithm);
        }
        if !seen.insert(proof.key_ref.clone()) {
            anyhow::bail!("duplicate signer in proof_set");
        }

        let key = resolve_signing_key(signer_source, store, &proof.key_ref).await?;
        verify_signature_with_key(&proof.jws, &canon, &key)?;
        valid_signers.push((
            proof.key_ref.controller_bot_id.clone(),
            proof.key_ref.key_id.clone(),
        ));
    }

    Ok(valid_signers)
}

fn verify_signature_with_key(jws: &str, payload: &[u8], key: &PublicKey) -> anyhow::Result<()> {
    let (_, pk_bytes) = multibase::decode(&key.public_key_multibase)
        .map_err(|e| anyhow::anyhow!("invalid public key multibase: {e}"))?;
    let jwk = identity_crypto::keys::jwk_from_ed25519_pub(&pk_bytes)?;
    let verifying_key = verifying_key_from_jwk(&jwk)?;
    verify_compact_jws(jws, payload, &verifying_key)
}

async fn resolve_signing_key(
    signer_source: &BotRecord,
    store: &dyn Storage,
    key_ref: &KeyRef,
) -> anyhow::Result<PublicKey> {
    if let Some(controller_bot_id) = &key_ref.controller_bot_id {
        // Controller signatures are only valid when the controller is explicitly delegated
        // on the target bot and the referenced controller key is currently active.
        let allowed = signer_source
            .controllers
            .as_ref()
            .map(|controllers| {
                controllers
                    .iter()
                    .any(|c| c.controller_bot_id == *controller_bot_id)
            })
            .unwrap_or(false);
        if !allowed {
            anyhow::bail!(
                "controller {} is not registered for this bot",
                controller_bot_id
            );
        }

        let controller = store
            .get_bot(controller_bot_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("controller bot not found: {}", controller_bot_id))?;
        if controller.status == BotStatus::Revoked {
            anyhow::bail!("controller {} is revoked", controller_bot_id);
        }

        return controller
            .public_keys
            .iter()
            .find(|k| k.key_id == key_ref.key_id && k.revoked_at.is_none())
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("controller key_id not found or revoked"));
    }

    signer_source
        .public_keys
        .iter()
        .find(|k| k.key_id == key_ref.key_id && k.revoked_at.is_none())
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("signing key_id not found or revoked"))
}

fn unified_proofs(record: &BotRecord) -> anyhow::Result<Vec<ProofItem>> {
    match (&record.proof, &record.proof_set) {
        (Some(_), Some(_)) => anyhow::bail!("provide either proof or proof_set, not both"),
        (None, None) => anyhow::bail!("missing proof/proof_set"),
        (Some(p), None) => Ok(vec![ProofItem {
            algorithm: p.algorithm.clone(),
            key_ref: KeyRef {
                key_id: p.key_id.clone(),
                controller_bot_id: None,
            },
            created: p.created.clone(),
            nonce: p.nonce.clone(),
            jws: p.jws.clone(),
        }]),
        (None, Some(set)) => {
            if set.is_empty() {
                anyhow::bail!("proof_set must contain at least one signature");
            }
            Ok(set.clone())
        }
    }
}

fn first_proof_created_at(record: &BotRecord) -> anyhow::Result<String> {
    let proofs = unified_proofs(record)?;
    proofs
        .first()
        .map(|p| p.created.clone())
        .ok_or_else(|| anyhow::anyhow!("proof_set must contain at least one signature"))
}

#[allow(dead_code)]
fn unify_proofs(record: &BotRecord) -> Option<Vec<ProofItem>> {
    record.proof_set.clone().or_else(|| {
        record.proof.clone().map(|p| {
            vec![ProofItem {
                algorithm: p.algorithm,
                key_ref: KeyRef {
                    key_id: p.key_id,
                    controller_bot_id: None,
                },
                created: p.created,
                nonce: p.nonce,
                jws: p.jws,
            }]
        })
    })
}

fn invalid(err: anyhow::Error) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: err.to_string(),
        }),
    )
}

fn internal(err: anyhow::Error) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: err.to_string(),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use ed25519_dalek::SigningKey;
    use http::{Request, StatusCode};
    use identity_core::{Attestation, BotStatus, Proof, PublicKey, SignatureRef};
    use identity_crypto::sign_compact_jws;
    use rand::rngs::OsRng;
    use serde_json::json;
    use tower::util::ServiceExt;

    fn unsigned_record(signing_key: &SigningKey, key_id: &str) -> BotRecord {
        BotRecord {
            bot_id: None,
            version: None,
            status: BotStatus::Active,
            display_name: Some("Example Bot".to_string()),
            description: Some("For tests".to_string()),
            owner: None,
            public_keys: vec![PublicKey {
                key_id: key_id.to_string(),
                algorithm: "Ed25519".to_string(),
                public_key_multibase: multibase::encode(
                    multibase::Base::Base58Btc,
                    signing_key.verifying_key().to_bytes(),
                ),
                purpose: vec!["signing".to_string()],
                valid_from: None,
                valid_to: None,
                revoked_at: None,
                revocation_reason: None,
                primary: Some(true),
                origin: None,
            }],
            endpoints: None,
            capabilities: None,
            controllers: None,
            parent_bot_id: None,
            policy: None,
            attestations: None,
            evidence: None,
            created_at: None,
            updated_at: None,
            proof: None,
            proof_set: None,
        }
    }

    fn sign_record(record: &mut BotRecord, signing_key: &SigningKey, key_id: &str) {
        sign_record_with_created(record, signing_key, key_id, "2026-02-15T00:00:00Z");
    }

    fn sign_record_with_created(
        record: &mut BotRecord,
        signing_key: &SigningKey,
        key_id: &str,
        created: &str,
    ) {
        let payload = record.payload_for_signing();
        let canon = canonicalize(&payload).expect("canon");
        let jws = sign_compact_jws(&canon, signing_key, key_id, true).expect("sign");
        record.proof = Some(Proof {
            algorithm: "Ed25519".to_string(),
            key_id: key_id.to_string(),
            created: created.to_string(),
            nonce: None,
            jws,
        });
    }

    async fn create_bot_for_test(
        app: &Router,
        signing_key: &SigningKey,
        key_id: &str,
        name: &str,
    ) -> (String, BotRecord) {
        let mut create = unsigned_record(signing_key, key_id);
        create.display_name = Some(name.to_string());
        sign_record(&mut create, signing_key, key_id);

        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/bots")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&create).expect("encode create"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("create request");
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let created_json = body_json(create_response).await;
        let bot_id = created_json["bot_id"].as_str().expect("bot id").to_string();
        let created = serde_json::from_value(created_json).expect("created record");
        (bot_id, created)
    }

    async fn body_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        serde_json::from_slice(&bytes).expect("json body")
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let app = app_router(AppState::default());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn homepage_returns_html() {
        let app = app_router(AppState::default());
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = String::from_utf8(bytes.to_vec()).expect("utf8");
        assert!(body.contains("botnet.pub registry"));
        assert!(body.contains("/v1/stats"));
    }

    #[tokio::test]
    async fn api_root_returns_docs_pointer() {
        let app = app_router(AppState::default());
        let response = app
            .oneshot(Request::builder().uri("/v1").body(Body::empty()).unwrap())
            .await
            .expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["docs"], "/docs");
        assert_eq!(json["stats"], "/v1/stats");
    }

    #[tokio::test]
    async fn docs_index_returns_html() {
        let app = app_router(AppState::default());
        let response = app
            .oneshot(Request::builder().uri("/docs").body(Body::empty()).unwrap())
            .await
            .expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = String::from_utf8(bytes.to_vec()).expect("utf8");
        assert!(body.contains("Documentation Home"));
        assert!(body.contains("Generated Coverage"));
        assert!(body.contains("/docs/api"));
    }

    #[tokio::test]
    async fn docs_api_returns_html() {
        let app = app_router(AppState::default());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/docs/api")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = String::from_utf8(bytes.to_vec()).expect("utf8");
        assert!(body.contains("API Reference"));
        assert!(body.contains("/v1/bots"));
        assert!(body.contains("Schema Catalog"));
        assert!(body.contains("Operation ID"));
    }

    #[tokio::test]
    async fn docs_cli_returns_html() {
        let app = app_router(AppState::default());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/docs/cli")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = String::from_utf8(bytes.to_vec()).expect("utf8");
        assert!(body.contains("CLI Reference"));
        assert!(body.contains("botnet --help"));
        assert!(body.contains("botnet publish-attestation"));
        assert!(body.contains("metadata from Clap"));
    }

    #[tokio::test]
    async fn openapi_json_exposes_paths() {
        let app = app_router(AppState::default());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/openapi.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["openapi"], "3.1.0");
        assert!(json["paths"]["/v1/bots"].is_object());
        assert!(json["paths"]["/v1/stats"].is_object());
    }

    #[tokio::test]
    async fn swagger_page_loads() {
        let app = app_router(AppState::default());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/swagger")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = String::from_utf8(bytes.to_vec()).expect("utf8");
        assert!(body.contains("swagger-ui"));
        assert!(body.contains("/openapi.json"));
    }

    #[tokio::test]
    async fn install_script_endpoint_serves_shell_script() {
        let app = app_router(AppState::default());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/install.sh")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let body = String::from_utf8(bytes.to_vec()).expect("utf8");
        assert!(body.contains("BOTNET_VERSION"));
        assert!(body.contains("botnet"));
    }

    #[tokio::test]
    async fn create_get_and_update_bot_success() {
        let app = app_router(AppState::default());
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let key_id = "k1";

        let mut create = unsigned_record(&signing_key, key_id);
        sign_record(&mut create, &signing_key, key_id);

        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/bots")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&create).unwrap()))
                    .unwrap(),
            )
            .await
            .expect("create request");

        assert_eq!(create_response.status(), StatusCode::CREATED);
        let created = body_json(create_response).await;
        let bot_id = created["bot_id"].as_str().expect("bot id").to_string();
        assert_eq!(created["version"], 1);

        let get_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/bots/{bot_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("get request");
        assert_eq!(get_response.status(), StatusCode::OK);

        let mut update = serde_json::from_value::<BotRecord>(created).expect("record");
        update.display_name = Some("Updated Name".to_string());
        sign_record(&mut update, &signing_key, key_id);

        let update_response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/v1/bots/{bot_id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&update).unwrap()))
                    .unwrap(),
            )
            .await
            .expect("update request");

        assert_eq!(update_response.status(), StatusCode::OK);
        let updated = body_json(update_response).await;
        assert_eq!(updated["display_name"], "Updated Name");
        assert_eq!(updated["version"], 2);
    }

    #[tokio::test]
    async fn create_rejects_missing_proof() {
        let app = app_router(AppState::default());
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let create = unsigned_record(&signing_key, "k1");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/bots")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&create).unwrap()))
                    .unwrap(),
            )
            .await
            .expect("request");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = body_json(response).await;
        assert!(json["error"].as_str().unwrap().contains("missing proof"));
    }

    #[tokio::test]
    async fn create_rejects_tampered_payload_signature() {
        let app = app_router(AppState::default());
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let key_id = "k1";
        let mut create = unsigned_record(&signing_key, key_id);
        sign_record(&mut create, &signing_key, key_id);
        create.display_name = Some("tampered-after-signing".to_string());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/bots")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&create).unwrap()))
                    .unwrap(),
            )
            .await
            .expect("request");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn update_rejects_unknown_bot() {
        let app = app_router(AppState::default());
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let key_id = "k1";

        let mut update = unsigned_record(&signing_key, key_id);
        update.bot_id = Some("urn:bot:sha256:missing".to_string());
        sign_record(&mut update, &signing_key, key_id);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/v1/bots/urn%3Abot%3Asha256%3Amissing")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&update).unwrap()))
                    .unwrap(),
            )
            .await
            .expect("request");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn nonce_endpoint_returns_nonce() {
        let app = app_router(AppState::default());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/nonce")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert!(json["nonce"].as_str().is_some());
    }

    #[tokio::test]
    async fn stats_endpoint_returns_counts() {
        let app = app_router(AppState::default());
        let mut rng = OsRng;
        let signer = SigningKey::generate(&mut rng);

        let _ = create_bot_for_test(&app, &signer, "k1", "stats-bot").await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("stats request");
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["total_bots"], 1);
        assert_eq!(json["active_bots"], 1);
        assert_eq!(json["total_keys"], 1);
        assert_eq!(json["active_keys"], 1);
    }

    #[tokio::test]
    async fn add_key_endpoint_adds_secondary_key() {
        let app = app_router(AppState::default());
        let mut rng = OsRng;
        let signer = SigningKey::generate(&mut rng);

        let (bot_id, created) = create_bot_for_test(&app, &signer, "k1", "add-key").await;

        let added_key = SigningKey::generate(&mut rng);
        let new_key = PublicKey {
            key_id: "k2".to_string(),
            algorithm: "Ed25519".to_string(),
            public_key_multibase: multibase::encode(
                multibase::Base::Base58Btc,
                added_key.verifying_key().to_bytes(),
            ),
            purpose: vec!["signing".to_string()],
            valid_from: None,
            valid_to: None,
            revoked_at: None,
            revocation_reason: None,
            primary: Some(false),
            origin: None,
        };

        let mut to_sign = created.clone();
        to_sign.public_keys.push(new_key.clone());
        sign_record(&mut to_sign, &signer, "k1");

        let request = json!({
            "public_key": new_key,
            "proof": to_sign.proof,
            "proof_set": serde_json::Value::Null
        });

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/bots/{bot_id}/keys"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&request).expect("encode add-key"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("add key");

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["public_keys"].as_array().expect("keys").len(), 2);
    }

    #[tokio::test]
    async fn remove_key_endpoint_revokes_non_primary_key() {
        let app = app_router(AppState::default());
        let mut rng = OsRng;
        let signer = SigningKey::generate(&mut rng);

        let (bot_id, created) = create_bot_for_test(&app, &signer, "k1", "remove-key").await;

        let second_key = SigningKey::generate(&mut rng);
        let new_key = PublicKey {
            key_id: "k2".to_string(),
            algorithm: "Ed25519".to_string(),
            public_key_multibase: multibase::encode(
                multibase::Base::Base58Btc,
                second_key.verifying_key().to_bytes(),
            ),
            purpose: vec!["signing".to_string()],
            valid_from: None,
            valid_to: None,
            revoked_at: None,
            revocation_reason: None,
            primary: Some(false),
            origin: None,
        };
        let mut add_sign = created.clone();
        add_sign.public_keys.push(new_key.clone());
        sign_record(&mut add_sign, &signer, "k1");
        let add_request = json!({
            "public_key": new_key,
            "proof": add_sign.proof,
        });
        let add_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/bots/{bot_id}/keys"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&add_request).expect("encode add request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("add key");
        assert_eq!(add_response.status(), StatusCode::OK);
        let added_record: BotRecord =
            serde_json::from_value(body_json(add_response).await).expect("added");

        let created_at = "2026-02-15T01:02:03Z";
        let mut revoke_candidate = added_record.clone();
        let key = revoke_candidate
            .public_keys
            .iter_mut()
            .find(|k| k.key_id == "k2")
            .expect("k2");
        key.revoked_at = Some(created_at.to_string());
        key.revocation_reason = Some("retired".to_string());
        key.primary = Some(false);
        sign_record_with_created(&mut revoke_candidate, &signer, "k1", created_at);

        let remove_request = json!({
            "reason": "retired",
            "proof": revoke_candidate.proof,
        });
        let remove_response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/bots/{bot_id}/keys/k2"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&remove_request).expect("encode remove"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("remove key");
        assert_eq!(remove_response.status(), StatusCode::OK);
        let removed = body_json(remove_response).await;
        let removed_key = removed["public_keys"]
            .as_array()
            .expect("keys")
            .iter()
            .find(|k| k["key_id"] == "k2")
            .expect("k2");
        assert_eq!(removed_key["revocation_reason"], "retired");
    }

    #[tokio::test]
    async fn rotate_key_endpoint_revokes_old_and_sets_new_primary() {
        let app = app_router(AppState::default());
        let mut rng = OsRng;
        let signer = SigningKey::generate(&mut rng);
        let (bot_id, created) = create_bot_for_test(&app, &signer, "k1", "rotate").await;

        let new_signing = SigningKey::generate(&mut rng);
        let new_key = PublicKey {
            key_id: "k2".to_string(),
            algorithm: "Ed25519".to_string(),
            public_key_multibase: multibase::encode(
                multibase::Base::Base58Btc,
                new_signing.verifying_key().to_bytes(),
            ),
            purpose: vec!["signing".to_string()],
            valid_from: None,
            valid_to: None,
            revoked_at: None,
            revocation_reason: None,
            primary: Some(true),
            origin: None,
        };

        let created_at = "2026-02-15T01:10:00Z";
        let mut rotate_candidate = created.clone();
        let old = rotate_candidate
            .public_keys
            .iter_mut()
            .find(|k| k.key_id == "k1")
            .expect("k1");
        old.revoked_at = Some(created_at.to_string());
        old.revocation_reason = Some("rotated".to_string());
        old.primary = Some(false);
        rotate_candidate.public_keys.push(new_key.clone());
        sign_record_with_created(&mut rotate_candidate, &signer, "k1", created_at);

        let request = json!({
            "old_key_id": "k1",
            "new_key": new_key,
            "proof": rotate_candidate.proof,
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/bots/{bot_id}/rotate"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&request).expect("encode rotate"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("rotate");

        assert_eq!(response.status(), StatusCode::OK);
        let rotated = body_json(response).await;
        let keys = rotated["public_keys"].as_array().expect("keys");
        assert_eq!(keys.len(), 2);
        assert!(keys
            .iter()
            .any(|k| k["key_id"] == "k2" && k["primary"] == true));
    }

    #[tokio::test]
    async fn revoke_bot_endpoint_marks_status_revoked() {
        let app = app_router(AppState::default());
        let mut rng = OsRng;
        let signer = SigningKey::generate(&mut rng);
        let (bot_id, created) = create_bot_for_test(&app, &signer, "k1", "revoke").await;

        let created_at = "2026-02-15T02:00:00Z";
        let mut revoke_candidate = created.clone();
        revoke_candidate.status = BotStatus::Revoked;
        revoke_candidate.public_keys.iter_mut().for_each(|k| {
            k.revoked_at = Some(created_at.to_string());
            k.revocation_reason = Some("sunset".to_string());
        });
        sign_record_with_created(&mut revoke_candidate, &signer, "k1", created_at);

        let request = json!({
            "reason": "sunset",
            "proof": revoke_candidate.proof,
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/bots/{bot_id}/revoke"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&request).expect("encode revoke"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("revoke");

        assert_eq!(response.status(), StatusCode::OK);
        let revoked = body_json(response).await;
        assert_eq!(revoked["status"], "revoked");
    }

    #[tokio::test]
    async fn publish_attestation_endpoint_appends_to_subject() {
        let app = app_router(AppState::default());
        let mut rng = OsRng;
        let subject_signer = SigningKey::generate(&mut rng);
        let issuer_signer = SigningKey::generate(&mut rng);

        let (subject_id, _) =
            create_bot_for_test(&app, &subject_signer, "subject-k1", "subject").await;
        let (issuer_id, _) = create_bot_for_test(&app, &issuer_signer, "issuer-k1", "issuer").await;

        let mut attestation = Attestation {
            attestation_id: None,
            issuer_bot_id: issuer_id.clone(),
            r#type: "capability".to_string(),
            statement: json!({"allows": ["calendar.read"]}),
            signature: SignatureRef {
                algorithm: "Ed25519".to_string(),
                key_id: "issuer-k1".to_string(),
                jws: String::new(),
            },
            issued_at: Some("2026-02-15T03:00:00Z".to_string()),
            expires_at: None,
        };

        let payload = AttestationPayload {
            subject_bot_id: &subject_id,
            issuer_bot_id: &attestation.issuer_bot_id,
            attestation_type: &attestation.r#type,
            statement: &attestation.statement,
            issued_at: &attestation.issued_at,
            expires_at: &attestation.expires_at,
        };
        let canon = canonicalize(&payload).expect("canon attestation");
        attestation.signature.jws =
            sign_compact_jws(&canon, &issuer_signer, "issuer-k1", true).expect("sign attestation");

        let request = json!({
            "subject_bot_id": subject_id,
            "attestation": attestation,
        });
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/attestations")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&request).expect("encode attestation"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("attestation");
        assert_eq!(response.status(), StatusCode::CREATED);

        let get_subject = app
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/bots/{subject_id}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("get subject");
        let subject_json = body_json(get_subject).await;
        assert_eq!(
            subject_json["attestations"]
                .as_array()
                .expect("attestations")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn search_endpoint_filters_by_query_and_limit() {
        let app = app_router(AppState::default());
        let mut rng = OsRng;
        let signer_a = SigningKey::generate(&mut rng);
        let signer_b = SigningKey::generate(&mut rng);

        let _ = create_bot_for_test(&app, &signer_a, "k1", "Alpha Bot").await;
        let _ = create_bot_for_test(&app, &signer_b, "k1", "Beta Bot").await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/search?q=alpha&limit=1")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("search");
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["count"], 1);
        assert_eq!(
            body["results"][0]["display_name"]
                .as_str()
                .expect("display_name"),
            "Alpha Bot"
        );
    }

    #[test]
    fn bind_addr_from_env_defaults_to_8080() {
        let addr = parse_bind_addr(None, None).expect("default addr");
        assert_eq!(addr.to_string(), "0.0.0.0:8080");
    }

    #[test]
    fn bind_addr_from_env_prefers_bind_addr() {
        let addr = parse_bind_addr(Some("127.0.0.1:7000"), Some("9999")).expect("bind addr");
        assert_eq!(addr.to_string(), "127.0.0.1:7000");
    }

    #[test]
    fn bind_addr_from_env_uses_port_when_bind_addr_missing() {
        let addr = parse_bind_addr(None, Some("7777")).expect("port addr");
        assert_eq!(addr.to_string(), "0.0.0.0:7777");
    }

    #[test]
    fn bind_addr_from_env_rejects_invalid_values() {
        assert!(parse_bind_addr(Some("not-an-addr"), None).is_err());
        assert!(parse_bind_addr(None, Some("not-a-port")).is_err());
    }
}
