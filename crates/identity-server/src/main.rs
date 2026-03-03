mod site;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{SecondsFormat, Utc};
use identity_core::{
    bot_id::derive_bot_id, canonical::canonicalize, validation::validate_bot_record, Attestation,
    BotRecord, BotStatus, Controller, Delegation, Endpoint, Evidence, KeyRef, Owner, Policy,
    PolicyRule, Proof, ProofItem, PublicKey, SignatureRef, SignerRef, SignerSet,
};
use identity_crypto::{keys::verifying_key_from_jwk, verify_compact_jws};
use identity_policy::eval::{evaluate_threshold, Operation};
use identity_storage::{MemoryStore, SqliteStore, Storage};
use serde::{Deserialize, Serialize};
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
        .route("/", get(site::homepage))
        .route("/install.sh", get(site::install_script))
        .route("/docs", get(site::docs_index))
        .route("/docs/protocol", get(site::docs_protocol))
        .route("/docs/api", get(site::docs_api))
        .route("/docs/cli", get(site::docs_cli))
        .route("/openapi.json", get(site::openapi_json))
        .route("/swagger", get(site::swagger))
        .route("/bots/{bot_id}", get(site::bot_profile))
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
        assert!(body.contains("botnet.pub"));
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
        assert!(body.contains("Documentation"));
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
    async fn docs_protocol_returns_html() {
        let app = app_router(AppState::default());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/docs/protocol")
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
        assert!(body.contains("Protocol Specification"));
        assert!(body.contains("Bot ID"));
        assert!(body.contains("Proof Model"));
        assert!(body.contains("Policy Engine"));
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
