use anyhow::Context;
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::SigningKey;
use identity_core::{canonical::canonicalize, AgentRecord, KeyRef, Proof, ProofItem};
use identity_crypto::sign_compact_jws;

pub trait Signer {
    fn key_id(&self) -> &str;
    fn controller_agent_id(&self) -> Option<&str> {
        None
    }
    fn sign(&self, canonical_payload: &[u8]) -> anyhow::Result<String>;
}

pub struct LocalEd25519Signer {
    key_id: String,
    signing_key: SigningKey,
    detached_jws: bool,
    controller_agent_id: Option<String>,
}

impl LocalEd25519Signer {
    pub fn from_seed_bytes(key_id: impl Into<String>, seed: &[u8]) -> anyhow::Result<Self> {
        let seed_arr: [u8; 32] = seed
            .try_into()
            .map_err(|_| anyhow::anyhow!("Ed25519 seed must be exactly 32 bytes"))?;
        Ok(Self {
            key_id: key_id.into(),
            signing_key: SigningKey::from_bytes(&seed_arr),
            detached_jws: true,
            controller_agent_id: None,
        })
    }

    pub fn with_controller(mut self, controller_agent_id: impl Into<String>) -> Self {
        self.controller_agent_id = Some(controller_agent_id.into());
        self
    }

    pub fn with_detached_jws(mut self, detached_jws: bool) -> Self {
        self.detached_jws = detached_jws;
        self
    }
}

impl Signer for LocalEd25519Signer {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn controller_agent_id(&self) -> Option<&str> {
        self.controller_agent_id.as_deref()
    }

    fn sign(&self, canonical_payload: &[u8]) -> anyhow::Result<String> {
        sign_compact_jws(
            canonical_payload,
            &self.signing_key,
            &self.key_id,
            self.detached_jws,
        )
    }
}

pub struct Client {
    base_url: String,
    http: reqwest::Client,
}

impl Client {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            http: reqwest::Client::new(),
        }
    }

    pub async fn create_agent(
        &self,
        mut record: AgentRecord,
        signer: &dyn Signer,
    ) -> anyhow::Result<AgentRecord> {
        attach_single_proof(&mut record, signer)?;

        let response = self
            .http
            .post(format!("{}/agents", self.base_url.trim_end_matches('/')))
            .json(&record)
            .send()
            .await
            .context("POST /agents failed")?
            .error_for_status()
            .context("POST /agents returned error status")?;

        response
            .json::<AgentRecord>()
            .await
            .context("decode create response")
    }

    pub async fn get_agent(&self, agent_id: &str) -> anyhow::Result<AgentRecord> {
        let response = self
            .http
            .get(format!(
                "{}/agents/{}",
                self.base_url.trim_end_matches('/'),
                urlencoding::encode(agent_id)
            ))
            .send()
            .await
            .context("GET /agents/:id failed")?
            .error_for_status()
            .context("GET /agents/:id returned error status")?;

        response
            .json::<AgentRecord>()
            .await
            .context("decode get response")
    }

    pub async fn update_agent(
        &self,
        agent_id: &str,
        mut record: AgentRecord,
        signer: &dyn Signer,
    ) -> anyhow::Result<AgentRecord> {
        attach_single_proof(&mut record, signer)?;

        let response = self
            .http
            .patch(format!(
                "{}/agents/{}",
                self.base_url.trim_end_matches('/'),
                urlencoding::encode(agent_id)
            ))
            .json(&record)
            .send()
            .await
            .context("PATCH /agents/:id failed")?
            .error_for_status()
            .context("PATCH /agents/:id returned error status")?;

        response
            .json::<AgentRecord>()
            .await
            .context("decode update response")
    }
}

pub fn attach_single_proof(record: &mut AgentRecord, signer: &dyn Signer) -> anyhow::Result<()> {
    record.proof = None;
    record.proof_set = None;

    let payload = record.payload_for_signing();
    let canon = canonicalize(&payload).context("canonicalize payload")?;
    let jws = signer.sign(&canon)?;

    record.proof = Some(Proof {
        algorithm: "Ed25519".into(),
        key_id: signer.key_id().to_string(),
        created: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        nonce: None,
        jws,
    });

    Ok(())
}

pub fn attach_proof_set(record: &mut AgentRecord, signers: &[&dyn Signer]) -> anyhow::Result<()> {
    if signers.is_empty() {
        anyhow::bail!("proof_set requires at least one signer");
    }

    record.proof = None;
    record.proof_set = None;

    let payload = record.payload_for_signing();
    let canon = canonicalize(&payload).context("canonicalize payload")?;

    let mut set = Vec::with_capacity(signers.len());
    for signer in signers {
        let jws = signer.sign(&canon)?;
        set.push(ProofItem {
            algorithm: "Ed25519".into(),
            key_ref: KeyRef {
                key_id: signer.key_id().to_string(),
                controller_agent_id: signer.controller_agent_id().map(str::to_string),
            },
            created: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            nonce: None,
            jws,
        });
    }

    record.proof_set = Some(set);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use identity_core::{AgentStatus, PublicKey};
    use identity_crypto::verify_compact_jws;
    use rand::rngs::OsRng;

    fn sample_record() -> (AgentRecord, SigningKey) {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let public_key_multibase = multibase::encode(
            multibase::Base::Base58Btc,
            signing_key.verifying_key().to_bytes(),
        );

        (
            AgentRecord {
                agent_id: Some("urn:agent:sha256:placeholder".to_string()),
                version: Some(7),
                status: AgentStatus::Active,
                display_name: Some("sdk-test".to_string()),
                description: None,
                owner: None,
                public_keys: vec![PublicKey {
                    key_id: "k1".to_string(),
                    algorithm: "Ed25519".to_string(),
                    public_key_multibase,
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
                created_at: Some("2026-02-15T00:00:00Z".to_string()),
                updated_at: Some("2026-02-15T00:00:00Z".to_string()),
                proof: None,
                proof_set: None,
            },
            signing_key,
        )
    }

    #[test]
    fn local_signer_rejects_invalid_seed_len() {
        assert!(LocalEd25519Signer::from_seed_bytes("k1", &[1, 2, 3]).is_err());
    }

    #[test]
    fn attach_single_proof_sets_proof_and_clears_proof_set() {
        let (mut record, signing_key) = sample_record();
        record.proof_set = Some(vec![]);
        let signer = LocalEd25519Signer::from_seed_bytes("k1", &signing_key.to_bytes()).unwrap();

        attach_single_proof(&mut record, &signer).expect("attach proof");

        assert!(record.proof.is_some());
        assert!(record.proof_set.is_none());
        assert_eq!(record.proof.as_ref().unwrap().key_id, "k1");
    }

    #[test]
    fn attach_single_proof_produces_verifiable_jws() {
        let (mut record, signing_key) = sample_record();
        let signer = LocalEd25519Signer::from_seed_bytes("k1", &signing_key.to_bytes()).unwrap();

        attach_single_proof(&mut record, &signer).expect("attach proof");

        let proof = record.proof.as_ref().expect("proof");
        let payload = record.payload_for_signing();
        let canon = canonicalize(&payload).expect("canon");
        verify_compact_jws(&proof.jws, &canon, &signing_key.verifying_key())
            .expect("proof should verify");
    }

    #[test]
    fn attach_proof_set_requires_signers() {
        let (mut record, _) = sample_record();
        let err = attach_proof_set(&mut record, &[]).expect_err("must fail");
        assert!(err.to_string().contains("at least one signer"));
    }

    #[test]
    fn attach_proof_set_sets_controller_refs() {
        let (mut record, signing_key) = sample_record();
        let signer = LocalEd25519Signer::from_seed_bytes("k1", &signing_key.to_bytes())
            .unwrap()
            .with_controller("urn:agent:sha256:controller");
        let signers: Vec<&dyn Signer> = vec![&signer];

        attach_proof_set(&mut record, &signers).expect("attach set");

        assert!(record.proof.is_none());
        let proof_set = record.proof_set.as_ref().expect("proof_set");
        assert_eq!(proof_set.len(), 1);
        assert_eq!(
            proof_set[0].key_ref.controller_agent_id.as_deref(),
            Some("urn:agent:sha256:controller")
        );
    }
}
