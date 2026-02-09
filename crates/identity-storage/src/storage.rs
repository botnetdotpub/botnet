use async_trait::async_trait;
use identity_core::{AgentRecord, Policy, PublicKey};

#[async_trait]
pub trait Storage: Send + Sync {
    async fn create_agent(&self, record: &AgentRecord) -> anyhow::Result<AgentRecord>;
    async fn get_agent(&self, agent_id: &str) -> anyhow::Result<Option<AgentRecord>>;
    async fn update_agent(&self, record: &AgentRecord) -> anyhow::Result<AgentRecord>;

    async fn get_policy(&self, agent_id: &str) -> anyhow::Result<Option<Policy>>;

    async fn get_agent_pubkey(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> anyhow::Result<Option<PublicKey>>;
    async fn get_controller_pubkey(
        &self,
        target_agent_id: &str,
        controller_agent_id: &str,
        key_id: &str,
    ) -> anyhow::Result<Option<PublicKey>>;

    async fn issue_nonce(&self) -> anyhow::Result<String>;
    async fn consume_nonce(&self, nonce: &str) -> anyhow::Result<bool>;
}
