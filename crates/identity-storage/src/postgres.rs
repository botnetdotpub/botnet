use crate::storage::Storage;
use anyhow::Context;
use async_trait::async_trait;
use chrono::Utc;
use identity_core::{BotRecord, Policy, PublicKey};
#[cfg(test)]
use sqlx::postgres::PgPoolOptions;
use sqlx::{migrate::Migrator, PgPool, Row};
use uuid::Uuid;

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");

#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let pool = PgPool::connect(database_url)
            .await
            .context("failed to connect to postgres")?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn run_migrations(&self) -> anyhow::Result<()> {
        MIGRATOR
            .run(&self.pool)
            .await
            .context("failed to run migrations")?;
        Ok(())
    }
}

#[async_trait]
impl Storage for PostgresStore {
    async fn create_bot(&self, record: &BotRecord) -> anyhow::Result<BotRecord> {
        let bot_id = record
            .bot_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("bot_id required before create"))?;

        let data = serde_json::to_value(record).context("serialize bot record")?;
        let status = serde_json::to_string(&record.status)
            .context("serialize status")?
            .trim_matches('"')
            .to_string();

        sqlx::query("INSERT INTO bots (bot_id, status, version, data) VALUES ($1, $2, $3, $4)")
            .bind(&bot_id)
            .bind(status)
            .bind(1_i64)
            .bind(data)
            .execute(&self.pool)
            .await
            .context("insert bot")?;

        Ok(record.clone())
    }

    async fn get_bot(&self, bot_id: &str) -> anyhow::Result<Option<BotRecord>> {
        let row = sqlx::query("SELECT data FROM bots WHERE bot_id = $1")
            .bind(bot_id)
            .fetch_optional(&self.pool)
            .await
            .context("select bot")?;

        let Some(row) = row else {
            return Ok(None);
        };

        let data: serde_json::Value = row.try_get("data").context("read data column")?;
        let record: BotRecord = serde_json::from_value(data).context("deserialize bot")?;
        Ok(Some(record))
    }

    async fn list_bots(&self) -> anyhow::Result<Vec<BotRecord>> {
        let rows = sqlx::query("SELECT data FROM bots")
            .fetch_all(&self.pool)
            .await
            .context("list bots")?;

        rows.into_iter()
            .map(|row| {
                let data: serde_json::Value = row.try_get("data").context("read data column")?;
                serde_json::from_value(data).context("deserialize bot")
            })
            .collect()
    }

    async fn update_bot(&self, record: &BotRecord) -> anyhow::Result<BotRecord> {
        let bot_id = record
            .bot_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("bot_id required before update"))?;
        let data = serde_json::to_value(record).context("serialize update record")?;

        sqlx::query(
            "UPDATE bots SET data = $2, updated_at = $3, version = version + 1 WHERE bot_id = $1",
        )
        .bind(bot_id)
        .bind(data)
        .bind(Utc::now())
        .execute(&self.pool)
        .await
        .context("update bot")?;

        Ok(record.clone())
    }

    async fn get_policy(&self, bot_id: &str) -> anyhow::Result<Option<Policy>> {
        let row = sqlx::query("SELECT data FROM bots WHERE bot_id = $1")
            .bind(bot_id)
            .fetch_optional(&self.pool)
            .await
            .context("select bot for policy")?;

        let Some(row) = row else {
            return Ok(None);
        };

        let data: serde_json::Value = row.try_get("data").context("read data")?;
        let policy = data
            .get("policy")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .context("deserialize policy")?;
        Ok(policy)
    }

    async fn get_bot_pubkey(
        &self,
        bot_id: &str,
        key_id: &str,
    ) -> anyhow::Result<Option<PublicKey>> {
        Ok(self
            .get_bot(bot_id)
            .await?
            .and_then(|record| record.public_keys.into_iter().find(|k| k.key_id == key_id)))
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

        let allowed = target
            .controllers
            .unwrap_or_default()
            .into_iter()
            .any(|c| c.controller_bot_id == controller_bot_id);
        if !allowed {
            return Ok(None);
        }

        self.get_bot_pubkey(controller_bot_id, key_id).await
    }

    async fn issue_nonce(&self) -> anyhow::Result<String> {
        let nonce = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO nonces (nonce) VALUES ($1)")
            .bind(&nonce)
            .execute(&self.pool)
            .await
            .context("insert nonce")?;
        Ok(nonce)
    }

    async fn consume_nonce(&self, nonce: &str) -> anyhow::Result<bool> {
        let result =
            sqlx::query("UPDATE nonces SET used_at = NOW() WHERE nonce = $1 AND used_at IS NULL")
                .bind(nonce)
                .execute(&self.pool)
                .await
                .context("consume nonce")?;

        Ok(result.rows_affected() == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity_core::{BotRecord, BotStatus, PublicKey};

    fn lazy_store() -> PostgresStore {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://postgres:postgres@localhost:1/identity_registry")
            .expect("connect_lazy");
        PostgresStore::from_pool(pool)
    }

    #[tokio::test]
    async fn create_bot_requires_bot_id_before_db_access() {
        let store = lazy_store();
        let record = BotRecord {
            bot_id: None,
            version: None,
            status: BotStatus::Active,
            display_name: None,
            description: None,
            owner: None,
            public_keys: vec![PublicKey {
                key_id: "k1".to_string(),
                algorithm: "Ed25519".to_string(),
                public_key_multibase: "zKey".to_string(),
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
        };

        let err = store.create_bot(&record).await.expect_err("must fail");
        assert!(err.to_string().contains("bot_id required before create"));
    }

    #[tokio::test]
    async fn update_bot_requires_bot_id_before_db_access() {
        let store = lazy_store();
        let record = BotRecord {
            bot_id: None,
            version: None,
            status: BotStatus::Active,
            display_name: None,
            description: None,
            owner: None,
            public_keys: vec![PublicKey {
                key_id: "k1".to_string(),
                algorithm: "Ed25519".to_string(),
                public_key_multibase: "zKey".to_string(),
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
        };

        let err = store.update_bot(&record).await.expect_err("must fail");
        assert!(err.to_string().contains("bot_id required before update"));
    }
}
