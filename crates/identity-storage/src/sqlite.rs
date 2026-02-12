use crate::storage::Storage;
use anyhow::Context;
use async_trait::async_trait;
use chrono::{SecondsFormat, Utc};
use identity_core::{AgentRecord, Policy, PublicKey};
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use uuid::Uuid;

#[derive(Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(database_url)
            .await
            .context("failed to connect to sqlite")?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn run_migrations(&self) -> anyhow::Result<()> {
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&self.pool)
            .await
            .context("enable sqlite foreign keys")?;
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&self.pool)
            .await
            .context("enable sqlite WAL mode")?;
        sqlx::query("PRAGMA synchronous = NORMAL")
            .execute(&self.pool)
            .await
            .context("set sqlite synchronous mode")?;
        sqlx::query("PRAGMA busy_timeout = 5000")
            .execute(&self.pool)
            .await
            .context("set sqlite busy timeout")?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS agents (
                agent_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                version INTEGER NOT NULL DEFAULT 1,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .context("create agents table")?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS nonces (
                nonce TEXT PRIMARY KEY,
                issued_at TEXT NOT NULL,
                used_at TEXT
            )",
        )
        .execute(&self.pool)
        .await
        .context("create nonces table")?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status)")
            .execute(&self.pool)
            .await
            .context("create status index")?;

        Ok(())
    }
}

#[async_trait]
impl Storage for SqliteStore {
    async fn create_agent(&self, record: &AgentRecord) -> anyhow::Result<AgentRecord> {
        let agent_id = record
            .agent_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("agent_id required before create"))?;
        let status = serde_json::to_string(&record.status)
            .context("serialize status")?
            .trim_matches('"')
            .to_string();
        let data = serde_json::to_string(record).context("serialize agent record")?;
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);

        sqlx::query(
            "INSERT INTO agents (agent_id, status, version, data, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&agent_id)
        .bind(status)
        .bind(1_i64)
        .bind(data)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await
        .context("insert agent")?;

        Ok(record.clone())
    }

    async fn get_agent(&self, agent_id: &str) -> anyhow::Result<Option<AgentRecord>> {
        let row = sqlx::query("SELECT data FROM agents WHERE agent_id = ?")
            .bind(agent_id)
            .fetch_optional(&self.pool)
            .await
            .context("select agent")?;

        let Some(row) = row else {
            return Ok(None);
        };

        let data: String = row.try_get("data").context("read data column")?;
        let record: AgentRecord = serde_json::from_str(&data).context("deserialize agent")?;
        Ok(Some(record))
    }

    async fn list_agents(&self) -> anyhow::Result<Vec<AgentRecord>> {
        let rows = sqlx::query("SELECT data FROM agents")
            .fetch_all(&self.pool)
            .await
            .context("list agents")?;

        rows.into_iter()
            .map(|row| {
                let data: String = row.try_get("data").context("read data column")?;
                serde_json::from_str(&data).context("deserialize agent")
            })
            .collect()
    }

    async fn update_agent(&self, record: &AgentRecord) -> anyhow::Result<AgentRecord> {
        let agent_id = record
            .agent_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("agent_id required before update"))?;
        let status = serde_json::to_string(&record.status)
            .context("serialize status")?
            .trim_matches('"')
            .to_string();
        let data = serde_json::to_string(record).context("serialize update record")?;
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);

        sqlx::query(
            "UPDATE agents
             SET data = ?, status = ?, updated_at = ?, version = version + 1
             WHERE agent_id = ?",
        )
        .bind(data)
        .bind(status)
        .bind(now)
        .bind(agent_id)
        .execute(&self.pool)
        .await
        .context("update agent")?;

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
        Ok(self
            .get_agent(agent_id)
            .await?
            .and_then(|record| record.public_keys.into_iter().find(|k| k.key_id == key_id)))
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

        let allowed = target
            .controllers
            .unwrap_or_default()
            .into_iter()
            .any(|c| c.controller_agent_id == controller_agent_id);
        if !allowed {
            return Ok(None);
        }

        self.get_agent_pubkey(controller_agent_id, key_id).await
    }

    async fn issue_nonce(&self) -> anyhow::Result<String> {
        let nonce = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        sqlx::query("INSERT INTO nonces (nonce, issued_at) VALUES (?, ?)")
            .bind(&nonce)
            .bind(now)
            .execute(&self.pool)
            .await
            .context("insert nonce")?;
        Ok(nonce)
    }

    async fn consume_nonce(&self, nonce: &str) -> anyhow::Result<bool> {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        let result =
            sqlx::query("UPDATE nonces SET used_at = ? WHERE nonce = ? AND used_at IS NULL")
                .bind(now)
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
    use identity_core::{AgentStatus, Controller, PublicKey};

    fn sample_agent(agent_id: &str, key_id: &str) -> AgentRecord {
        AgentRecord {
            agent_id: Some(agent_id.to_string()),
            version: Some(1),
            status: AgentStatus::Active,
            display_name: Some("sqlite".to_string()),
            description: None,
            owner: None,
            public_keys: vec![PublicKey {
                key_id: key_id.to_string(),
                algorithm: "Ed25519".to_string(),
                public_key_multibase: "zSqliteKey".to_string(),
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
    async fn sqlite_round_trip_and_nonce() {
        let store = SqliteStore::connect("sqlite::memory:")
            .await
            .expect("connect");
        store.run_migrations().await.expect("migrate");

        let agent = sample_agent("urn:agent:sha256:sqlite-a", "k1");
        store.create_agent(&agent).await.expect("create");

        let fetched = store
            .get_agent("urn:agent:sha256:sqlite-a")
            .await
            .expect("get")
            .expect("exists");
        assert_eq!(fetched.display_name.as_deref(), Some("sqlite"));

        let nonce = store.issue_nonce().await.expect("nonce");
        assert!(store.consume_nonce(&nonce).await.expect("consume first"));
        assert!(!store.consume_nonce(&nonce).await.expect("consume second"));
    }

    #[tokio::test]
    async fn sqlite_controller_key_lookup() {
        let store = SqliteStore::connect("sqlite::memory:")
            .await
            .expect("connect");
        store.run_migrations().await.expect("migrate");

        let mut target = sample_agent("urn:agent:sha256:target", "target-k1");
        target.controllers = Some(vec![Controller {
            controller_agent_id: "urn:agent:sha256:controller".to_string(),
            role: Some("owner".to_string()),
            delegation: None,
        }]);
        let controller = sample_agent("urn:agent:sha256:controller", "controller-k1");

        store.create_agent(&target).await.expect("target");
        store.create_agent(&controller).await.expect("controller");

        let found = store
            .get_controller_pubkey(
                "urn:agent:sha256:target",
                "urn:agent:sha256:controller",
                "controller-k1",
            )
            .await
            .expect("lookup");
        assert!(found.is_some());
    }
}
