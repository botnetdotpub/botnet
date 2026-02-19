use crate::storage::Storage;
use async_trait::async_trait;
use identity_core::{BotRecord, Policy, PublicKey};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct MemoryStore {
    bots: Arc<RwLock<HashMap<String, BotRecord>>>,
    nonces: Arc<RwLock<HashMap<String, bool>>>,
}

#[async_trait]
impl Storage for MemoryStore {
    async fn create_bot(&self, record: &BotRecord) -> anyhow::Result<BotRecord> {
        let bot_id = record
            .bot_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("bot_id required before create"))?;

        let mut bots = self.bots.write().await;
        if bots.contains_key(&bot_id) {
            anyhow::bail!("bot already exists");
        }
        bots.insert(bot_id, record.clone());
        Ok(record.clone())
    }

    async fn get_bot(&self, bot_id: &str) -> anyhow::Result<Option<BotRecord>> {
        let bots = self.bots.read().await;
        Ok(bots.get(bot_id).cloned())
    }

    async fn list_bots(&self) -> anyhow::Result<Vec<BotRecord>> {
        let bots = self.bots.read().await;
        Ok(bots.values().cloned().collect())
    }

    async fn update_bot(&self, record: &BotRecord) -> anyhow::Result<BotRecord> {
        let bot_id = record
            .bot_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("bot_id required before update"))?;

        let mut bots = self.bots.write().await;
        if !bots.contains_key(&bot_id) {
            anyhow::bail!("bot not found");
        }
        bots.insert(bot_id, record.clone());
        Ok(record.clone())
    }

    async fn get_policy(&self, bot_id: &str) -> anyhow::Result<Option<Policy>> {
        Ok(self
            .get_bot(bot_id)
            .await?
            .and_then(|record| record.policy.clone()))
    }

    async fn get_bot_pubkey(
        &self,
        bot_id: &str,
        key_id: &str,
    ) -> anyhow::Result<Option<PublicKey>> {
        let key = self
            .get_bot(bot_id)
            .await?
            .and_then(|record| record.public_keys.into_iter().find(|k| k.key_id == key_id));
        Ok(key)
    }

    async fn get_controller_pubkey(
        &self,
        target_bot_id: &str,
        controller_bot_id: &str,
        key_id: &str,
    ) -> anyhow::Result<Option<PublicKey>> {
        let Some(target) = self.get_bot(target_bot_id).await? else {
            return Ok(None);
        };

        let controllers: HashSet<String> = target
            .controllers
            .unwrap_or_default()
            .into_iter()
            .map(|c| c.controller_bot_id)
            .collect();

        if !controllers.contains(controller_bot_id) {
            return Ok(None);
        }

        self.get_bot_pubkey(controller_bot_id, key_id).await
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
    use identity_core::{BotStatus, Controller, PolicyRule, PublicKey, SignerSet};

    fn sample_bot(bot_id: &str, key_id: &str) -> BotRecord {
        BotRecord {
            bot_id: Some(bot_id.to_string()),
            version: Some(1),
            status: BotStatus::Active,
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

    #[tokio::test]
    async fn create_get_update_round_trip() {
        let store = MemoryStore::default();
        let mut bot = sample_bot("urn:bot:sha256:a", "k1");
        store.create_bot(&bot).await.expect("create");

        let fetched = store
            .get_bot("urn:bot:sha256:a")
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(fetched.public_keys[0].key_id, "k1");

        bot.display_name = Some("updated".to_string());
        store.update_bot(&bot).await.expect("update");
        let fetched = store
            .get_bot("urn:bot:sha256:a")
            .await
            .expect("get after update")
            .expect("exists");
        assert_eq!(fetched.display_name.as_deref(), Some("updated"));
    }

    #[tokio::test]
    async fn get_policy_and_key_lookup_work() {
        let store = MemoryStore::default();
        let mut bot = sample_bot("urn:bot:sha256:a", "k1");
        bot.policy = Some(identity_core::Policy {
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
        store.create_bot(&bot).await.expect("create");

        let policy = store
            .get_policy("urn:bot:sha256:a")
            .await
            .expect("policy")
            .expect("exists");
        assert_eq!(policy.version, 1);

        let key = store
            .get_bot_pubkey("urn:bot:sha256:a", "k1")
            .await
            .expect("key")
            .expect("exists");
        assert_eq!(key.algorithm, "Ed25519");
    }

    #[tokio::test]
    async fn controller_lookup_requires_relationship() {
        let store = MemoryStore::default();

        let mut target = sample_bot("urn:bot:sha256:target", "target-key");
        target.controllers = Some(vec![Controller {
            controller_bot_id: "urn:bot:sha256:controller".to_string(),
            role: Some("owner".to_string()),
            delegation: None,
        }]);

        let controller = sample_bot("urn:bot:sha256:controller", "controller-key");

        store.create_bot(&target).await.expect("target create");
        store
            .create_bot(&controller)
            .await
            .expect("controller create");

        let found = store
            .get_controller_pubkey(
                "urn:bot:sha256:target",
                "urn:bot:sha256:controller",
                "controller-key",
            )
            .await
            .expect("lookup");
        assert!(found.is_some());

        let missing = store
            .get_controller_pubkey(
                "urn:bot:sha256:target",
                "urn:bot:sha256:other",
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
