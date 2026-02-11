use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{SecondsFormat, Utc};
use identity_core::{
    agent_id::derive_agent_id, canonical::canonicalize, validation::validate_agent_record,
    AgentRecord, KeyRef, ProofItem,
};
use identity_crypto::{keys::verifying_key_from_jwk, verify_compact_jws};
use identity_policy::eval::{evaluate_threshold, Operation};
use serde_json::json;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

#[derive(Clone, Default)]
struct AppState {
    agents: Arc<RwLock<HashMap<String, AgentRecord>>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "identity_server=debug,tower_http=info".to_string()),
        )
        .init();

    let app = app_router(AppState::default());

    let addr = bind_addr_from_env()?;
    tracing::info!("listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
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
        <tr><td>POST</td><td><code>/v1/agents/{agent_id}/keys</code></td><td>Add key</td><td>Scaffolded (501)</td></tr>
        <tr><td>DELETE</td><td><code>/v1/agents/{agent_id}/keys/{key_id}</code></td><td>Remove key</td><td>Scaffolded (501)</td></tr>
        <tr><td>POST</td><td><code>/v1/agents/{agent_id}/rotate</code></td><td>Rotate key</td><td>Scaffolded (501)</td></tr>
        <tr><td>POST</td><td><code>/v1/agents/{agent_id}/revoke</code></td><td>Revoke agent</td><td>Scaffolded (501)</td></tr>
        <tr><td>POST</td><td><code>/v1/attestations</code></td><td>Publish attestation</td><td>Scaffolded (501)</td></tr>
        <tr><td>GET</td><td><code>/v1/search</code></td><td>Search agents</td><td>Scaffolded (501)</td></tr>
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

    verify_single_proof_against_record(&incoming).map_err(invalid)?;

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

    let mut agents = state.agents.write().await;
    if agents.contains_key(&agent_id) {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({"error": "agent already exists"})),
        ));
    }
    agents.insert(agent_id, incoming.clone());

    Ok((StatusCode::CREATED, Json(incoming)))
}

async fn get_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let agents = state.agents.read().await;
    let Some(agent) = agents.get(&agent_id) else {
        return Err((StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))));
    };
    Ok((StatusCode::OK, Json(agent.clone())))
}

async fn update_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Json(mut incoming): Json<AgentRecord>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let mut agents = state.agents.write().await;
    let current = agents
        .get(&agent_id)
        .cloned()
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))))?;

    // keep identity and immutable metadata server-managed
    incoming.agent_id = Some(agent_id.clone());
    incoming.created_at = current.created_at.clone();

    verify_single_proof_against_record(&incoming).map_err(invalid)?;

    let valid_signers = collect_signers(&incoming).map_err(invalid)?;
    evaluate_threshold(current.policy.as_ref(), Operation::Update, &valid_signers)
        .map_err(invalid)?;

    let version = current.version.unwrap_or(1) + 1;
    incoming.version = Some(version);
    incoming.updated_at = Some(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true));

    agents.insert(agent_id, incoming.clone());
    Ok((StatusCode::OK, Json(incoming)))
}

async fn add_key() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"error": "not implemented"})),
    )
}

async fn remove_key() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"error": "not implemented"})),
    )
}

async fn rotate_key() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"error": "not implemented"})),
    )
}

async fn revoke_agent() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"error": "not implemented"})),
    )
}

async fn publish_attestation() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"error": "not implemented"})),
    )
}

async fn search() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"error": "not implemented"})),
    )
}

async fn get_nonce() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({"nonce": Uuid::new_v4().to_string()})),
    )
}

fn verify_single_proof_against_record(record: &AgentRecord) -> anyhow::Result<()> {
    let proof = record
        .proof
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing proof"))?;

    let key = record
        .public_keys
        .iter()
        .find(|k| k.key_id == proof.key_id)
        .ok_or_else(|| anyhow::anyhow!("proof key_id not found in public_keys"))?;

    let (_, pk_bytes) = multibase::decode(&key.public_key_multibase)
        .map_err(|e| anyhow::anyhow!("invalid public key multibase: {e}"))?;
    let jwk = identity_crypto::keys::jwk_from_ed25519_pub(&pk_bytes)?;
    let verifying_key = verifying_key_from_jwk(&jwk)?;

    let payload = record.payload_for_signing();
    let canon = canonicalize(&payload)?;
    verify_compact_jws(&proof.jws, &canon, &verifying_key)
}

fn collect_signers(record: &AgentRecord) -> anyhow::Result<Vec<(Option<String>, String)>> {
    if let Some(set) = &record.proof_set {
        let mut out = Vec::with_capacity(set.len());
        for p in set {
            out.push((
                p.key_ref.controller_agent_id.clone(),
                p.key_ref.key_id.clone(),
            ));
        }
        return Ok(out);
    }

    if let Some(p) = &record.proof {
        return Ok(vec![(None, p.key_id.clone())]);
    }

    Err(anyhow::anyhow!("missing proof/proof_set"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use ed25519_dalek::SigningKey;
    use http::{Request, StatusCode};
    use identity_core::{AgentStatus, Proof, PublicKey};
    use identity_crypto::sign_compact_jws;
    use rand::rngs::OsRng;
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
        let payload = record.payload_for_signing();
        let canon = canonicalize(&payload).expect("canon");
        let jws = sign_compact_jws(&canon, signing_key, key_id, true).expect("sign");
        record.proof = Some(Proof {
            algorithm: "Ed25519".to_string(),
            key_id: key_id.to_string(),
            created: "2026-02-15T00:00:00Z".to_string(),
            nonce: None,
            jws,
        });
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
    async fn scaffolded_mutation_endpoints_return_not_implemented() {
        let app = app_router(AppState::default());
        let cases = [
            ("POST", "/v1/agents/a/keys"),
            ("DELETE", "/v1/agents/a/keys/k1"),
            ("POST", "/v1/agents/a/rotate"),
            ("POST", "/v1/agents/a/revoke"),
            ("POST", "/v1/attestations"),
            ("GET", "/v1/search"),
        ];

        for (method, uri) in cases {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(Body::empty())
                        .expect("request builder"),
                )
                .await
                .expect("request");

            assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        }
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
