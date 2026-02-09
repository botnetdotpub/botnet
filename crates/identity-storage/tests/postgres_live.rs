use identity_core::{AgentRecord, AgentStatus, PublicKey};
use identity_storage::{PostgresStore, Storage};

fn sample_agent(agent_id: &str) -> AgentRecord {
    AgentRecord {
        agent_id: Some(agent_id.to_string()),
        version: Some(1),
        status: AgentStatus::Active,
        display_name: Some("postgres-live".to_string()),
        description: None,
        owner: None,
        public_keys: vec![PublicKey {
            key_id: "k1".to_string(),
            algorithm: "Ed25519".to_string(),
            public_key_multibase: "zLiveKey".to_string(),
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

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL to run"]
async fn postgres_round_trip_when_database_is_available() {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to run this integration test");

    let store = PostgresStore::connect(&database_url)
        .await
        .expect("connect postgres");
    store.run_migrations().await.expect("run migrations");

    let agent = sample_agent("urn:agent:sha256:postgres-live");
    store.create_agent(&agent).await.expect("create agent");

    let fetched = store
        .get_agent("urn:agent:sha256:postgres-live")
        .await
        .expect("get agent")
        .expect("agent exists");
    assert_eq!(fetched.display_name.as_deref(), Some("postgres-live"));

    let nonce = store.issue_nonce().await.expect("issue nonce");
    assert!(store.consume_nonce(&nonce).await.expect("consume nonce"));
}
