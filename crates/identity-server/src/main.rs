use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{SecondsFormat, Utc};
use identity_core::{
    agent_id::derive_agent_id, canonical::canonicalize, validation::validate_agent_record,
    AgentRecord, AgentStatus, Attestation, KeyRef, Proof, ProofItem, PublicKey,
};
use identity_crypto::{keys::verifying_key_from_jwk, verify_compact_jws};
use identity_policy::eval::{evaluate_threshold, Operation};
use identity_storage::{MemoryStore, SqliteStore, Storage};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashSet, net::SocketAddr, sync::Arc};
use tower_http::trace::TraceLayer;
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

#[derive(Debug, Deserialize)]
struct AddKeyRequest {
    public_key: PublicKey,
    proof: Option<Proof>,
    proof_set: Option<Vec<ProofItem>>,
}

#[derive(Debug, Deserialize)]
struct RemoveKeyRequest {
    reason: Option<String>,
    proof: Option<Proof>,
    proof_set: Option<Vec<ProofItem>>,
}

#[derive(Debug, Deserialize)]
struct RotateKeyRequest {
    old_key_id: String,
    new_key: PublicKey,
    proof: Option<Proof>,
    proof_set: Option<Vec<ProofItem>>,
}

#[derive(Debug, Deserialize)]
struct RevokeAgentRequest {
    reason: Option<String>,
    proof: Option<Proof>,
    proof_set: Option<Vec<ProofItem>>,
}

#[derive(Debug, Deserialize)]
struct PublishAttestationRequest {
    subject_agent_id: String,
    attestation: Attestation,
}

#[derive(Debug, Deserialize)]
struct SearchQuery {
    q: Option<String>,
    status: Option<AgentStatus>,
    capability: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct SearchResponse {
    count: usize,
    results: Vec<AgentRecord>,
}

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
        .route("/", get(root))
        .route("/docs", get(docs))
        .route("/health", get(health))
        .route("/v1/agents", post(create_agent))
        .route("/v1/agents/{agent_id}", get(get_agent).patch(update_agent))
        .route("/v1/agents/{agent_id}/keys", post(add_key))
        .route("/v1/agents/{agent_id}/keys/{key_id}", delete(remove_key))
        .route("/v1/agents/{agent_id}/rotate", post(rotate_key))
        .route("/v1/agents/{agent_id}/revoke", post(revoke_agent))
        .route("/v1/attestations", post(publish_attestation))
        .route("/v1/search", get(search))
        .route("/v1/nonce", get(get_nonce))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn root() -> impl IntoResponse {
    Json(json!({
        "service": "ai-agent-identity-registry",
        "status": "ok",
        "docs": "/docs",
        "health": "/health"
    }))
}

async fn docs() -> impl IntoResponse {
    Html(
        r#"<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>AI Agent Registry API Docs</title>
    <style>
      body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem auto; max-width: 920px; padding: 0 1rem; line-height: 1.45; }
      h1 { margin-bottom: 0.2rem; }
      code { background: #f3f4f6; padding: 0.1rem 0.35rem; border-radius: 4px; }
      table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
      th, td { border: 1px solid #e5e7eb; text-align: left; padding: 0.55rem 0.65rem; vertical-align: top; }
      th { background: #f9fafb; }
      .muted { color: #6b7280; }
    </style>
  </head>
  <body>
    <h1>AI Agent Registry API</h1>
    <p class="muted">Starter API surface for agent identity records, keys, and policy-managed operations.</p>
    <p>Health check: <code>/health</code></p>
    <table>
      <thead><tr><th>Method</th><th>Path</th><th>Operation</th><th>Status</th></tr></thead>
      <tbody>
        <tr><td>GET</td><td><code>/health</code></td><td>Service health</td><td>Implemented</td></tr>
        <tr><td>GET</td><td><code>/v1/nonce</code></td><td>Issue nonce</td><td>Implemented</td></tr>
        <tr><td>POST</td><td><code>/v1/agents</code></td><td>Create agent</td><td>Implemented</td></tr>
        <tr><td>GET</td><td><code>/v1/agents/{agent_id}</code></td><td>Get agent</td><td>Implemented</td></tr>
        <tr><td>PATCH</td><td><code>/v1/agents/{agent_id}</code></td><td>Update agent</td><td>Implemented</td></tr>
        <tr><td>POST</td><td><code>/v1/agents/{agent_id}/keys</code></td><td>Add key</td><td>Implemented</td></tr>
        <tr><td>DELETE</td><td><code>/v1/agents/{agent_id}/keys/{key_id}</code></td><td>Remove key</td><td>Implemented</td></tr>
        <tr><td>POST</td><td><code>/v1/agents/{agent_id}/rotate</code></td><td>Rotate key</td><td>Implemented</td></tr>
        <tr><td>POST</td><td><code>/v1/agents/{agent_id}/revoke</code></td><td>Revoke agent</td><td>Implemented</td></tr>
        <tr><td>POST</td><td><code>/v1/attestations</code></td><td>Publish attestation</td><td>Implemented</td></tr>
        <tr><td>GET</td><td><code>/v1/search</code></td><td>Search agents</td><td>Implemented</td></tr>
      </tbody>
    </table>
  </body>
</html>
"#,
    )
}

async fn health() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

async fn create_agent(
    State(state): State<AppState>,
    Json(mut incoming): Json<AgentRecord>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    validate_agent_record(&incoming).map_err(invalid)?;

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

    let agent_id = derive_agent_id(&pk_bytes);
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    incoming.agent_id = Some(agent_id.clone());
    incoming.version = Some(1);
    incoming.created_at = Some(now.clone());
    incoming.updated_at = Some(now);

    if state
        .store
        .get_agent(&agent_id)
        .await
        .map_err(internal)?
        .is_some()
    {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({"error": "agent already exists"})),
        ));
    }
    state
        .store
        .create_agent(&incoming)
        .await
        .map_err(internal)?;

    Ok((StatusCode::CREATED, Json(incoming)))
}

async fn get_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let Some(agent) = state.store.get_agent(&agent_id).await.map_err(internal)? else {
        return Err((StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))));
    };
    Ok((StatusCode::OK, Json(agent)))
}

async fn update_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(mut incoming): Json<AgentRecord>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let current = state
        .store
        .get_agent(&agent_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))))?;

    // keep identity and immutable metadata server-managed
    incoming.agent_id = Some(agent_id.clone());
    incoming.created_at = current.created_at.clone();

    validate_agent_record(&incoming).map_err(invalid)?;
    let valid_signers = verify_record_signatures(&incoming, &current, state.store.as_ref())
        .await
        .map_err(invalid)?;

    evaluate_threshold(current.policy.as_ref(), Operation::Update, &valid_signers)
        .map_err(invalid)?;

    let version = current.version.unwrap_or(1) + 1;
    incoming.version = Some(version);
    incoming.updated_at = Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));

    state
        .store
        .update_agent(&incoming)
        .await
        .map_err(internal)?;
    Ok((StatusCode::OK, Json(incoming)))
}

async fn add_key(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(request): Json<AddKeyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let current = state
        .store
        .get_agent(&agent_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))))?;

    if current.status == AgentStatus::Revoked {
        return Err(invalid(anyhow::anyhow!(
            "cannot add key to a revoked agent"
        )));
    }

    if current
        .public_keys
        .iter()
        .any(|k| k.key_id == request.public_key.key_id)
    {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({"error": "key_id already exists"})),
        ));
    }
    if current
        .public_keys
        .iter()
        .any(|k| k.public_key_multibase == request.public_key.public_key_multibase)
    {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({"error": "public key already exists"})),
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

    validate_agent_record(&updated).map_err(invalid)?;
    let valid_signers = verify_record_signatures(&updated, &current, state.store.as_ref())
        .await
        .map_err(invalid)?;
    evaluate_threshold(current.policy.as_ref(), Operation::AddKey, &valid_signers)
        .map_err(invalid)?;

    updated.agent_id = Some(agent_id.clone());
    updated.created_at = current.created_at.clone();
    updated.version = Some(current.version.unwrap_or(1) + 1);
    updated.updated_at = Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));

    state.store.update_agent(&updated).await.map_err(internal)?;
    Ok((StatusCode::OK, Json(updated)))
}

async fn remove_key(
    State(state): State<AppState>,
    Path((agent_id, key_id)): Path<(String, String)>,
    Json(request): Json<RemoveKeyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let current = state
        .store
        .get_agent(&agent_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))))?;

    if current.status == AgentStatus::Revoked {
        return Err(invalid(anyhow::anyhow!("agent is already revoked")));
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
                Json(json!({"error": "key not found"})),
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

    validate_agent_record(&updated).map_err(invalid)?;
    let valid_signers = verify_record_signatures(&updated, &current, state.store.as_ref())
        .await
        .map_err(invalid)?;
    evaluate_threshold(
        current.policy.as_ref(),
        Operation::RevokeKey,
        &valid_signers,
    )
    .map_err(invalid)?;

    updated.agent_id = Some(agent_id.clone());
    updated.created_at = current.created_at.clone();
    updated.version = Some(current.version.unwrap_or(1) + 1);
    updated.updated_at = Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
    state.store.update_agent(&updated).await.map_err(internal)?;
    Ok((StatusCode::OK, Json(updated)))
}

async fn rotate_key(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(request): Json<RotateKeyRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let current = state
        .store
        .get_agent(&agent_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))))?;

    if current.status == AgentStatus::Revoked {
        return Err(invalid(anyhow::anyhow!(
            "cannot rotate key on a revoked agent"
        )));
    }

    if current
        .public_keys
        .iter()
        .any(|k| k.key_id == request.new_key.key_id)
    {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({"error": "new key_id already exists"})),
        ));
    }
    if current
        .public_keys
        .iter()
        .any(|k| k.public_key_multibase == request.new_key.public_key_multibase)
    {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({"error": "new public key already exists"})),
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
                Json(json!({"error": "old key not found"})),
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
    validate_agent_record(&updated).map_err(invalid)?;
    let valid_signers = verify_record_signatures(&updated, &current, state.store.as_ref())
        .await
        .map_err(invalid)?;
    evaluate_threshold(
        current.policy.as_ref(),
        Operation::RotateKey,
        &valid_signers,
    )
    .map_err(invalid)?;

    updated.agent_id = Some(agent_id.clone());
    updated.created_at = current.created_at.clone();
    updated.version = Some(current.version.unwrap_or(1) + 1);
    updated.updated_at = Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));

    state.store.update_agent(&updated).await.map_err(internal)?;
    Ok((StatusCode::OK, Json(updated)))
}

async fn revoke_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(request): Json<RevokeAgentRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let current = state
        .store
        .get_agent(&agent_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))))?;

    let mut updated = current.clone();
    updated.proof = request.proof;
    updated.proof_set = request.proof_set;
    let effective_time = first_proof_created_at(&updated).map_err(invalid)?;
    updated.status = AgentStatus::Revoked;
    for key in &mut updated.public_keys {
        if key.revoked_at.is_none() {
            key.revoked_at = Some(effective_time.clone());
        }
        if key.revocation_reason.is_none() {
            key.revocation_reason = request
                .reason
                .clone()
                .or_else(|| Some("agent revoked".to_string()));
        }
    }
    validate_agent_record(&updated).map_err(invalid)?;
    let valid_signers = verify_record_signatures(&updated, &current, state.store.as_ref())
        .await
        .map_err(invalid)?;
    evaluate_threshold(
        current.policy.as_ref(),
        Operation::RevokeAgent,
        &valid_signers,
    )
    .map_err(invalid)?;

    updated.agent_id = Some(agent_id.clone());
    updated.created_at = current.created_at.clone();
    updated.version = Some(current.version.unwrap_or(1) + 1);
    updated.updated_at = Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));
    state.store.update_agent(&updated).await.map_err(internal)?;

    Ok((StatusCode::OK, Json(updated)))
}

async fn publish_attestation(
    State(state): State<AppState>,
    Json(request): Json<PublishAttestationRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let subject = state
        .store
        .get_agent(&request.subject_agent_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "subject agent not found"})),
            )
        })?;
    let issuer = state
        .store
        .get_agent(&request.attestation.issuer_agent_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "issuer agent not found"})),
            )
        })?;

    let signer_key = issuer
        .public_keys
        .iter()
        .find(|k| k.key_id == request.attestation.signature.key_id)
        .ok_or_else(|| invalid(anyhow::anyhow!("issuer key_id not found")))?;

    let payload = AttestationPayload {
        subject_agent_id: &request.subject_agent_id,
        issuer_agent_id: &request.attestation.issuer_agent_id,
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
        .update_agent(&updated_subject)
        .await
        .map_err(internal)?;

    Ok((StatusCode::CREATED, Json(attestation)))
}

async fn search(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let mut results = state.store.list_agents().await.map_err(internal)?;

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
            r.agent_id
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

    results.sort_by_key(|r| r.agent_id.clone().unwrap_or_default());
    let limit = query.limit.unwrap_or(50).min(200);
    results.truncate(limit);

    Ok(Json(SearchResponse {
        count: results.len(),
        results,
    }))
}

async fn get_nonce(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let nonce = state.store.issue_nonce().await.map_err(internal)?;
    Ok((StatusCode::OK, Json(json!({ "nonce": nonce }))))
}

#[derive(Serialize)]
struct AttestationPayload<'a> {
    subject_agent_id: &'a str,
    issuer_agent_id: &'a str,
    #[serde(rename = "type")]
    attestation_type: &'a str,
    statement: &'a serde_json::Value,
    issued_at: &'a Option<String>,
    expires_at: &'a Option<String>,
}

async fn verify_record_signatures(
    incoming: &AgentRecord,
    signer_source: &AgentRecord,
    store: &dyn Storage,
) -> anyhow::Result<Vec<(Option<String>, String)>> {
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
            proof.key_ref.controller_agent_id.clone(),
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
    signer_source: &AgentRecord,
    store: &dyn Storage,
    key_ref: &KeyRef,
) -> anyhow::Result<PublicKey> {
    if let Some(controller_agent_id) = &key_ref.controller_agent_id {
        let allowed = signer_source
            .controllers
            .as_ref()
            .map(|controllers| {
                controllers
                    .iter()
                    .any(|c| c.controller_agent_id == *controller_agent_id)
            })
            .unwrap_or(false);
        if !allowed {
            anyhow::bail!(
                "controller {} is not registered for this agent",
                controller_agent_id
            );
        }

        let controller = store.get_agent(controller_agent_id).await?.ok_or_else(|| {
            anyhow::anyhow!("controller agent not found: {}", controller_agent_id)
        })?;
        if controller.status == AgentStatus::Revoked {
            anyhow::bail!("controller {} is revoked", controller_agent_id);
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

fn unified_proofs(record: &AgentRecord) -> anyhow::Result<Vec<ProofItem>> {
    match (&record.proof, &record.proof_set) {
        (Some(_), Some(_)) => anyhow::bail!("provide either proof or proof_set, not both"),
        (None, None) => anyhow::bail!("missing proof/proof_set"),
        (Some(p), None) => Ok(vec![ProofItem {
            algorithm: p.algorithm.clone(),
            key_ref: KeyRef {
                key_id: p.key_id.clone(),
                controller_agent_id: None,
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

fn first_proof_created_at(record: &AgentRecord) -> anyhow::Result<String> {
    let proofs = unified_proofs(record)?;
    proofs
        .first()
        .map(|p| p.created.clone())
        .ok_or_else(|| anyhow::anyhow!("proof_set must contain at least one signature"))
}

#[allow(dead_code)]
fn unify_proofs(record: &AgentRecord) -> Option<Vec<ProofItem>> {
    record.proof_set.clone().or_else(|| {
        record.proof.clone().map(|p| {
            vec![ProofItem {
                algorithm: p.algorithm,
                key_ref: KeyRef {
                    key_id: p.key_id,
                    controller_agent_id: None,
                },
                created: p.created,
                nonce: p.nonce,
                jws: p.jws,
            }]
        })
    })
}

fn invalid(err: anyhow::Error) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": err.to_string()})),
    )
}

fn internal(err: anyhow::Error) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": err.to_string()})),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use ed25519_dalek::SigningKey;
    use http::{Request, StatusCode};
    use identity_core::{AgentStatus, Attestation, Proof, PublicKey, SignatureRef};
    use identity_crypto::sign_compact_jws;
    use rand::rngs::OsRng;
    use serde_json::json;
    use tower::util::ServiceExt;

    fn unsigned_record(signing_key: &SigningKey, key_id: &str) -> AgentRecord {
        AgentRecord {
            agent_id: None,
            version: None,
            status: AgentStatus::Active,
            display_name: Some("Example Agent".to_string()),
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
            parent_agent_id: None,
            policy: None,
            attestations: None,
            evidence: None,
            created_at: None,
            updated_at: None,
            proof: None,
            proof_set: None,
        }
    }

    fn sign_record(record: &mut AgentRecord, signing_key: &SigningKey, key_id: &str) {
        sign_record_with_created(record, signing_key, key_id, "2026-02-15T00:00:00Z");
    }

    fn sign_record_with_created(
        record: &mut AgentRecord,
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

    async fn create_agent_for_test(
        app: &Router,
        signing_key: &SigningKey,
        key_id: &str,
        name: &str,
    ) -> (String, AgentRecord) {
        let mut create = unsigned_record(signing_key, key_id);
        create.display_name = Some(name.to_string());
        sign_record(&mut create, signing_key, key_id);

        let create_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/agents")
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
        let agent_id = created_json["agent_id"]
            .as_str()
            .expect("agent id")
            .to_string();
        let created = serde_json::from_value(created_json).expect("created record");
        (agent_id, created)
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
    async fn root_returns_docs_pointer() {
        let app = app_router(AppState::default());
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .expect("request");
        assert_eq!(response.status(), StatusCode::OK);
        let json = body_json(response).await;
        assert_eq!(json["docs"], "/docs");
    }

    #[tokio::test]
    async fn docs_returns_html() {
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
        assert!(body.contains("AI Agent Registry API"));
        assert!(body.contains("/v1/agents"));
    }

    #[tokio::test]
    async fn create_get_and_update_agent_success() {
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
                    .uri("/v1/agents")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&create).unwrap()))
                    .unwrap(),
            )
            .await
            .expect("create request");

        assert_eq!(create_response.status(), StatusCode::CREATED);
        let created = body_json(create_response).await;
        let agent_id = created["agent_id"].as_str().expect("agent id").to_string();
        assert_eq!(created["version"], 1);

        let get_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/agents/{agent_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("get request");
        assert_eq!(get_response.status(), StatusCode::OK);

        let mut update = serde_json::from_value::<AgentRecord>(created).expect("record");
        update.display_name = Some("Updated Name".to_string());
        sign_record(&mut update, &signing_key, key_id);

        let update_response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/v1/agents/{agent_id}"))
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
                    .uri("/v1/agents")
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
                    .uri("/v1/agents")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&create).unwrap()))
                    .unwrap(),
            )
            .await
            .expect("request");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn update_rejects_unknown_agent() {
        let app = app_router(AppState::default());
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let key_id = "k1";

        let mut update = unsigned_record(&signing_key, key_id);
        update.agent_id = Some("urn:agent:sha256:missing".to_string());
        sign_record(&mut update, &signing_key, key_id);

        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/v1/agents/urn%3Aagent%3Asha256%3Amissing")
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
    async fn add_key_endpoint_adds_secondary_key() {
        let app = app_router(AppState::default());
        let mut rng = OsRng;
        let signer = SigningKey::generate(&mut rng);

        let (agent_id, created) = create_agent_for_test(&app, &signer, "k1", "add-key").await;

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
                    .uri(format!("/v1/agents/{agent_id}/keys"))
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

        let (agent_id, created) = create_agent_for_test(&app, &signer, "k1", "remove-key").await;

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
                    .uri(format!("/v1/agents/{agent_id}/keys"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&add_request).expect("encode add request"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("add key");
        assert_eq!(add_response.status(), StatusCode::OK);
        let added_record: AgentRecord =
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
                    .uri(format!("/v1/agents/{agent_id}/keys/k2"))
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
        let (agent_id, created) = create_agent_for_test(&app, &signer, "k1", "rotate").await;

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
                    .uri(format!("/v1/agents/{agent_id}/rotate"))
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
    async fn revoke_agent_endpoint_marks_status_revoked() {
        let app = app_router(AppState::default());
        let mut rng = OsRng;
        let signer = SigningKey::generate(&mut rng);
        let (agent_id, created) = create_agent_for_test(&app, &signer, "k1", "revoke").await;

        let created_at = "2026-02-15T02:00:00Z";
        let mut revoke_candidate = created.clone();
        revoke_candidate.status = AgentStatus::Revoked;
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
                    .uri(format!("/v1/agents/{agent_id}/revoke"))
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
            create_agent_for_test(&app, &subject_signer, "subject-k1", "subject").await;
        let (issuer_id, _) =
            create_agent_for_test(&app, &issuer_signer, "issuer-k1", "issuer").await;

        let mut attestation = Attestation {
            attestation_id: None,
            issuer_agent_id: issuer_id.clone(),
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
            subject_agent_id: &subject_id,
            issuer_agent_id: &attestation.issuer_agent_id,
            attestation_type: &attestation.r#type,
            statement: &attestation.statement,
            issued_at: &attestation.issued_at,
            expires_at: &attestation.expires_at,
        };
        let canon = canonicalize(&payload).expect("canon attestation");
        attestation.signature.jws =
            sign_compact_jws(&canon, &issuer_signer, "issuer-k1", true).expect("sign attestation");

        let request = json!({
            "subject_agent_id": subject_id,
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
                    .uri(format!("/v1/agents/{subject_id}"))
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

        let _ = create_agent_for_test(&app, &signer_a, "k1", "Alpha Agent").await;
        let _ = create_agent_for_test(&app, &signer_b, "k1", "Beta Agent").await;

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
            "Alpha Agent"
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
