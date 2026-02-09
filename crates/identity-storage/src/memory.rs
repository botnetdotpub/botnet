use crate::storage::Storage;
use async_trait::async_trait;
use identity_core::{AgentRecord, Policy, PublicKey};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct MemoryStore {
    agents: Arc<RwLock<HashMap<String, AgentRecord>>>,
    nonces: Arc<RwLock<HashMap<String, bool>>>,
}

#[async_trait]
impl Storage for MemoryStore {
    async fn create_agent(&self, record: &AgentRecord) -> anyhow::Result<AgentRecord> {
        let agent_id = record
            .agent_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("agent_id required before create"))?;

        let mut agents = self.agents.write().await;
        if agents.contains_key(&agent_id) {
            anyhow::bail!("agent already exists");
        }
        agents.insert(agent_id, record.clone());
        Ok(record.clone())
    }

    async fn get_agent(&self, agent_id: &str) -> anyhow::Result<Option<AgentRecord>> {
        let agents = self.agents.read().await;
        Ok(agents.get(agent_id).cloned())
    }

    async fn update_agent(&self, record: &AgentRecord) -> anyhow::Result<AgentRecord> {
        let agent_id = record
            .agent_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("agent_id required before update"))?;

        let mut agents = self.agents.write().await;
        if !agents.contains_key(&agent_id) {
            anyhow::bail!("agent not found");
        }
        agents.insert(agent_id, record.clone());
        Ok(record.clone())
    }

    async fn get_policy(&self, agent_id: &str) -> anyhow::Result<Option<Policy>> {
        Ok(self
            .get_agent(agent_id)
            .await?
            .and_then(|record| record.policy.clone()))
    }

    async fn get_agent_pubkey(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> anyhow::Result<Option<PublicKey>> {
        let key = self
            .get_agent(agent_id)
            .await?
            .and_then(|record| record.public_keys.into_iter().find(|k| k.key_id == key_id));
        Ok(key)
    }

    async fn get_controller_pubkey(
        &self,
        target_agent_id: &str,
        controller_agent_id: &str,
        key_id: &str,
    ) -> anyhow::Result<Option<PublicKey>> {
        let Some(target) = self.get_agent(target_agent_id).await? else {
            return Ok(None);
        };

        let controllers: HashSet<String> = target
            .controllers
            .unwrap_or_default()
            .into_iter()
            .map(|c| c.controller_agent_id)
            .collect();

        if !controllers.contains(controller_agent_id) {
            return Ok(None);
        }

        self.get_agent_pubkey(controller_agent_id, key_id).await
    }

    async fn issue_nonce(&self) -> anyhow::Result<String> {
        let nonce = Uuid::new_v4().to_string();
        self.nonces.write().await.insert(nonce.clone(), false);
        Ok(nonce)
    }

    async fn consume_nonce(&self, nonce: &str) -> anyhow::Result<bool> {
        let mut nonces = self.nonces.write().await;
        let Some(used) = nonces.get_mut(nonce) else {
            return Ok(false);
        };

        if *used {
            return Ok(false);
        }

        *used = true;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Storage;
    use identity_core::{AgentStatus, Controller, PolicyRule, PublicKey, SignerSet};

    fn sample_agent(agent_id: &str, key_id: &str) -> AgentRecord {
        AgentRecord {
            agent_id: Some(agent_id.to_string()),
            version: Some(1),
            status: AgentStatus::Active,
            display_name: Some("sample".to_string()),
            description: None,
            owner: None,
            public_keys: vec![PublicKey {
                key_id: key_id.to_string(),
                algorithm: "Ed25519".to_string(),
                public_key_multibase: "zSample".to_string(),
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
    async fn create_get_update_round_trip() {
        let store = MemoryStore::default();
        let mut agent = sample_agent("urn:agent:sha256:a", "k1");
        store.create_agent(&agent).await.expect("create");

        let fetched = store
            .get_agent("urn:agent:sha256:a")
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(fetched.public_keys[0].key_id, "k1");

        agent.display_name = Some("updated".to_string());
        store.update_agent(&agent).await.expect("update");
        let fetched = store
            .get_agent("urn:agent:sha256:a")
            .await
            .expect("get after update")
            .expect("exists");
        assert_eq!(fetched.display_name.as_deref(), Some("updated"));
    }

    #[tokio::test]
    async fn get_policy_and_key_lookup_work() {
        let store = MemoryStore::default();
        let mut agent = sample_agent("urn:agent:sha256:a", "k1");
        agent.policy = Some(identity_core::Policy {
            version: 1,
            updated_at: "2026-02-15T00:00:00Z".to_string(),
            rules: vec![PolicyRule {
                operation: "update".to_string(),
                r#type: "threshold".to_string(),
                m: 1,
                set_id: "owners".to_string(),
            }],
            signer_sets: vec![SignerSet {
                set_id: "owners".to_string(),
                members: vec![],
            }],
        });
        store.create_agent(&agent).await.expect("create");

        let policy = store
            .get_policy("urn:agent:sha256:a")
            .await
            .expect("policy")
            .expect("exists");
        assert_eq!(policy.version, 1);

        let key = store
            .get_agent_pubkey("urn:agent:sha256:a", "k1")
            .await
            .expect("key")
            .expect("exists");
        assert_eq!(key.algorithm, "Ed25519");
    }

    #[tokio::test]
    async fn controller_lookup_requires_relationship() {
        let store = MemoryStore::default();

        let mut target = sample_agent("urn:agent:sha256:target", "target-key");
        target.controllers = Some(vec![Controller {
            controller_agent_id: "urn:agent:sha256:controller".to_string(),
            role: Some("owner".to_string()),
            delegation: None,
        }]);

        let controller = sample_agent("urn:agent:sha256:controller", "controller-key");

        store.create_agent(&target).await.expect("target create");
        store
            .create_agent(&controller)
            .await
            .expect("controller create");

        let found = store
            .get_controller_pubkey(
                "urn:agent:sha256:target",
                "urn:agent:sha256:controller",
                "controller-key",
            )
            .await
            .expect("lookup");
        assert!(found.is_some());

        let missing = store
            .get_controller_pubkey(
                "urn:agent:sha256:target",
                "urn:agent:sha256:other",
                "controller-key",
            )
            .await
            .expect("lookup missing");
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn nonce_is_single_use() {
        let store = MemoryStore::default();
        let nonce = store.issue_nonce().await.expect("issue nonce");

        assert!(store.consume_nonce(&nonce).await.expect("first consume"));
        assert!(!store.consume_nonce(&nonce).await.expect("second consume"));
        assert!(!store
            .consume_nonce("missing")
            .await
            .expect("missing consume"));
    }
}
