use async_trait::async_trait;
use identity_core::{BotRecord, Policy, PublicKey};

#[async_trait]
pub trait Storage: Send + Sync {
    async fn create_bot(&self, record: &BotRecord) -> anyhow::Result<BotRecord>;
    async fn get_bot(&self, bot_id: &str) -> anyhow::Result<Option<BotRecord>>;
    async fn list_bots(&self) -> anyhow::Result<Vec<BotRecord>>;
    async fn update_bot(&self, record: &BotRecord) -> anyhow::Result<BotRecord>;

    async fn get_policy(&self, bot_id: &str) -> anyhow::Result<Option<Policy>>;

    async fn get_bot_pubkey(&self, bot_id: &str, key_id: &str)
        -> anyhow::Result<Option<PublicKey>>;
    async fn get_controller_pubkey(
        &self,
        target_bot_id: &str,
        controller_bot_id: &str,
        key_id: &str,
    ) -> anyhow::Result<Option<PublicKey>>;

    async fn issue_nonce(&self) -> anyhow::Result<String>;
    async fn consume_nonce(&self, nonce: &str) -> anyhow::Result<bool>;
}
