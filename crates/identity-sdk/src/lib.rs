use anyhow::Context;
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::SigningKey;
use identity_core::{
    canonical::canonicalize, Attestation, BotRecord, BotStatus, KeyRef, Proof, ProofItem, PublicKey,
};
use identity_crypto::sign_compact_jws;
use serde::{Deserialize, Serialize};

pub trait Signer {
    fn key_id(&self) -> &str;
    fn controller_bot_id(&self) -> Option<&str> {
        None
    }
    fn sign(&self, canonical_payload: &[u8]) -> anyhow::Result<String>;
}

pub struct LocalEd25519Signer {
    key_id: String,
    signing_key: SigningKey,
    detached_jws: bool,
    controller_bot_id: Option<String>,
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
            controller_bot_id: None,
        })
    }

    pub fn with_controller(mut self, controller_bot_id: impl Into<String>) -> Self {
        self.controller_bot_id = Some(controller_bot_id.into());
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

    fn controller_bot_id(&self) -> Option<&str> {
        self.controller_bot_id.as_deref()
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResponse {
    pub count: usize,
    pub results: Vec<BotRecord>,
}

#[derive(Debug, Clone, Deserialize)]
struct NonceResponse {
    nonce: String,
}

#[derive(Debug, Clone, Serialize)]
struct AddKeyRequest {
    public_key: PublicKey,
    proof: Option<Proof>,
    proof_set: Option<Vec<ProofItem>>,
}

#[derive(Debug, Clone, Serialize)]
struct RemoveKeyRequest {
    reason: Option<String>,
    proof: Option<Proof>,
    proof_set: Option<Vec<ProofItem>>,
}

#[derive(Debug, Clone, Serialize)]
struct RotateKeyRequest {
    old_key_id: String,
    new_key: PublicKey,
    proof: Option<Proof>,
    proof_set: Option<Vec<ProofItem>>,
}

#[derive(Debug, Clone, Serialize)]
struct RevokeBotRequest {
    reason: Option<String>,
    proof: Option<Proof>,
    proof_set: Option<Vec<ProofItem>>,
}

#[derive(Debug, Clone, Serialize)]
struct PublishAttestationRequest {
    subject_bot_id: String,
    attestation: Attestation,
}

#[derive(Serialize)]
struct AttestationPayload<'a> {
    subject_bot_id: &'a str,
    issuer_bot_id: &'a str,
    #[serde(rename = "type")]
    attestation_type: &'a str,
    statement: &'a serde_json::Value,
    issued_at: &'a Option<String>,
    expires_at: &'a Option<String>,
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

    pub async fn create_bot(
        &self,
        mut record: BotRecord,
        signer: &dyn Signer,
    ) -> anyhow::Result<BotRecord> {
        attach_single_proof(&mut record, signer)?;

        let response = self
            .http
            .post(self.endpoint("bots"))
            .json(&record)
            .send()
            .await
            .context("POST /bots failed")?
            .error_for_status()
            .context("POST /bots returned error status")?;

        response
            .json::<BotRecord>()
            .await
            .context("decode create response")
    }

    pub async fn get_bot(&self, bot_id: &str) -> anyhow::Result<BotRecord> {
        let response = self
            .http
            .get(self.endpoint(&format!("bots/{}", urlencoding::encode(bot_id))))
            .send()
            .await
            .context("GET /bots/:id failed")?
            .error_for_status()
            .context("GET /bots/:id returned error status")?;

        response
            .json::<BotRecord>()
            .await
            .context("decode get response")
    }

    pub async fn update_bot(
        &self,
        bot_id: &str,
        mut record: BotRecord,
        signer: &dyn Signer,
    ) -> anyhow::Result<BotRecord> {
        attach_single_proof(&mut record, signer)?;

        let response = self
            .http
            .patch(self.endpoint(&format!("bots/{}", urlencoding::encode(bot_id))))
            .json(&record)
            .send()
            .await
            .context("PATCH /bots/:id failed")?
            .error_for_status()
            .context("PATCH /bots/:id returned error status")?;

        response
            .json::<BotRecord>()
            .await
            .context("decode update response")
    }

    pub async fn add_key(
        &self,
        bot_id: &str,
        mut public_key: PublicKey,
        signer: &dyn Signer,
    ) -> anyhow::Result<BotRecord> {
        let current = self.get_bot(bot_id).await?;
        let mut candidate = current.clone();

        if public_key.primary.unwrap_or(false) {
            for key in &mut candidate.public_keys {
                key.primary = Some(false);
            }
        } else if public_key.primary.is_none() {
            public_key.primary = Some(false);
        }
        candidate.public_keys.push(public_key.clone());

        let proof = sign_record_with_created(&candidate, signer, now_timestamp())?;
        let request = AddKeyRequest {
            public_key,
            proof: Some(proof),
            proof_set: None,
        };

        let response = self
            .http
            .post(self.endpoint(&format!("bots/{}/keys", urlencoding::encode(bot_id))))
            .json(&request)
            .send()
            .await
            .context("POST /bots/:id/keys failed")?
            .error_for_status()
            .context("POST /bots/:id/keys returned error status")?;

        response
            .json::<BotRecord>()
            .await
            .context("decode add key response")
    }

    pub async fn remove_key(
        &self,
        bot_id: &str,
        key_id: &str,
        reason: Option<String>,
        signer: &dyn Signer,
    ) -> anyhow::Result<BotRecord> {
        let current = self.get_bot(bot_id).await?;
        let mut candidate = current.clone();
        let created = now_timestamp();

        let idx = candidate
            .public_keys
            .iter()
            .position(|k| k.key_id == key_id)
            .ok_or_else(|| anyhow::anyhow!("key not found: {}", key_id))?;

        if candidate.public_keys[idx].revoked_at.is_some() {
            anyhow::bail!("key already revoked: {}", key_id);
        }

        let was_primary = candidate.public_keys[idx].primary.unwrap_or(false);
        candidate.public_keys[idx].revoked_at = Some(created.clone());
        candidate.public_keys[idx].revocation_reason = reason.clone().or(Some("revoked".into()));
        candidate.public_keys[idx].primary = Some(false);

        if was_primary {
            let replacement = candidate
                .public_keys
                .iter_mut()
                .find(|k| k.key_id != key_id && k.revoked_at.is_none())
                .ok_or_else(|| anyhow::anyhow!("cannot revoke the only active key"))?;
            replacement.primary = Some(true);
        }

        let proof = sign_record_with_created(&candidate, signer, created)?;
        let request = RemoveKeyRequest {
            reason,
            proof: Some(proof),
            proof_set: None,
        };

        let response = self
            .http
            .delete(self.endpoint(&format!(
                "bots/{}/keys/{}",
                urlencoding::encode(bot_id),
                urlencoding::encode(key_id)
            )))
            .json(&request)
            .send()
            .await
            .context("DELETE /bots/:id/keys/:key_id failed")?
            .error_for_status()
            .context("DELETE /bots/:id/keys/:key_id returned error status")?;

        response
            .json::<BotRecord>()
            .await
            .context("decode remove key response")
    }

    pub async fn rotate_key(
        &self,
        bot_id: &str,
        old_key_id: &str,
        mut new_key: PublicKey,
        signer: &dyn Signer,
    ) -> anyhow::Result<BotRecord> {
        let current = self.get_bot(bot_id).await?;
        let mut candidate = current.clone();
        let created = now_timestamp();

        let old_idx = candidate
            .public_keys
            .iter()
            .position(|k| k.key_id == old_key_id)
            .ok_or_else(|| anyhow::anyhow!("old key not found: {}", old_key_id))?;

        if candidate.public_keys[old_idx].revoked_at.is_some() {
            anyhow::bail!("old key already revoked: {}", old_key_id);
        }

        let old_was_primary = candidate.public_keys[old_idx].primary.unwrap_or(false);
        candidate.public_keys[old_idx].revoked_at = Some(created.clone());
        candidate.public_keys[old_idx].revocation_reason = Some("rotated".to_string());
        candidate.public_keys[old_idx].primary = Some(false);

        if old_was_primary {
            for key in &mut candidate.public_keys {
                key.primary = Some(false);
            }
            new_key.primary = Some(true);
        } else if new_key.primary.unwrap_or(false) {
            for key in &mut candidate.public_keys {
                if key.revoked_at.is_none() {
                    key.primary = Some(false);
                }
            }
        } else if new_key.primary.is_none() {
            new_key.primary = Some(false);
        }

        candidate.public_keys.push(new_key.clone());

        let proof = sign_record_with_created(&candidate, signer, created)?;
        let request = RotateKeyRequest {
            old_key_id: old_key_id.to_string(),
            new_key,
            proof: Some(proof),
            proof_set: None,
        };

        let response = self
            .http
            .post(self.endpoint(&format!("bots/{}/rotate", urlencoding::encode(bot_id))))
            .json(&request)
            .send()
            .await
            .context("POST /bots/:id/rotate failed")?
            .error_for_status()
            .context("POST /bots/:id/rotate returned error status")?;

        response
            .json::<BotRecord>()
            .await
            .context("decode rotate key response")
    }

    pub async fn revoke_bot(
        &self,
        bot_id: &str,
        reason: Option<String>,
        signer: &dyn Signer,
    ) -> anyhow::Result<BotRecord> {
        let current = self.get_bot(bot_id).await?;
        let mut candidate = current;
        let created = now_timestamp();

        candidate.status = BotStatus::Revoked;
        for key in &mut candidate.public_keys {
            if key.revoked_at.is_none() {
                key.revoked_at = Some(created.clone());
            }
            if key.revocation_reason.is_none() {
                key.revocation_reason = reason.clone().or(Some("bot revoked".into()));
            }
        }

        let proof = sign_record_with_created(&candidate, signer, created)?;
        let request = RevokeBotRequest {
            reason,
            proof: Some(proof),
            proof_set: None,
        };

        let response = self
            .http
            .post(self.endpoint(&format!("bots/{}/revoke", urlencoding::encode(bot_id))))
            .json(&request)
            .send()
            .await
            .context("POST /bots/:id/revoke failed")?
            .error_for_status()
            .context("POST /bots/:id/revoke returned error status")?;

        response
            .json::<BotRecord>()
            .await
            .context("decode revoke response")
    }

    pub async fn publish_attestation(
        &self,
        subject_bot_id: &str,
        mut attestation: Attestation,
        signer: &dyn Signer,
    ) -> anyhow::Result<Attestation> {
        let payload = AttestationPayload {
            subject_bot_id,
            issuer_bot_id: &attestation.issuer_bot_id,
            attestation_type: &attestation.r#type,
            statement: &attestation.statement,
            issued_at: &attestation.issued_at,
            expires_at: &attestation.expires_at,
        };
        let canon = canonicalize(&payload).context("canonicalize attestation payload")?;

        attestation.signature.algorithm = "Ed25519".to_string();
        attestation.signature.key_id = signer.key_id().to_string();
        attestation.signature.jws = signer.sign(&canon)?;

        let request = PublishAttestationRequest {
            subject_bot_id: subject_bot_id.to_string(),
            attestation,
        };

        let response = self
            .http
            .post(self.endpoint("attestations"))
            .json(&request)
            .send()
            .await
            .context("POST /attestations failed")?
            .error_for_status()
            .context("POST /attestations returned error status")?;

        response
            .json::<Attestation>()
            .await
            .context("decode attestation response")
    }

    pub async fn search_bots(
        &self,
        q: Option<&str>,
        status: Option<BotStatus>,
        capability: Option<&str>,
        limit: Option<usize>,
    ) -> anyhow::Result<SearchResponse> {
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(query) = q {
            params.push(("q", query.to_string()));
        }
        if let Some(status) = status {
            params.push(("status", status_as_str(status).to_string()));
        }
        if let Some(capability) = capability {
            params.push(("capability", capability.to_string()));
        }
        if let Some(limit) = limit {
            params.push(("limit", limit.to_string()));
        }

        let response = self
            .http
            .get(self.endpoint("search"))
            .query(&params)
            .send()
            .await
            .context("GET /search failed")?
            .error_for_status()
            .context("GET /search returned error status")?;

        response
            .json::<SearchResponse>()
            .await
            .context("decode search response")
    }

    pub async fn get_nonce(&self) -> anyhow::Result<String> {
        let response = self
            .http
            .get(self.endpoint("nonce"))
            .send()
            .await
            .context("GET /nonce failed")?
            .error_for_status()
            .context("GET /nonce returned error status")?;

        let nonce = response
            .json::<NonceResponse>()
            .await
            .context("decode nonce response")?;
        Ok(nonce.nonce)
    }

    fn endpoint(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}

pub fn attach_single_proof(record: &mut BotRecord, signer: &dyn Signer) -> anyhow::Result<()> {
    let created = now_timestamp();
    let proof = sign_record_with_created(record, signer, created)?;
    record.proof_set = None;
    record.proof = Some(proof);
    Ok(())
}

pub fn attach_proof_set(record: &mut BotRecord, signers: &[&dyn Signer]) -> anyhow::Result<()> {
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
                controller_bot_id: signer.controller_bot_id().map(str::to_string),
            },
            created: now_timestamp(),
            nonce: None,
            jws,
        });
    }

    record.proof_set = Some(set);
    Ok(())
}

fn sign_record_with_created(
    record: &BotRecord,
    signer: &dyn Signer,
    created: String,
) -> anyhow::Result<Proof> {
    // Canonical signing payload excludes server-managed fields and any proof/proof_set fields.
    let payload = record.payload_for_signing();
    let canon = canonicalize(&payload).context("canonicalize payload")?;
    let jws = signer.sign(&canon)?;

    Ok(Proof {
        algorithm: "Ed25519".into(),
        key_id: signer.key_id().to_string(),
        created,
        nonce: None,
        jws,
    })
}

fn now_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn status_as_str(status: BotStatus) -> &'static str {
    match status {
        BotStatus::Active => "active",
        BotStatus::Deprecated => "deprecated",
        BotStatus::Revoked => "revoked",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use identity_core::{BotStatus, PublicKey};
    use identity_crypto::verify_compact_jws;
    use rand::rngs::OsRng;

    fn sample_record() -> (BotRecord, SigningKey) {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let public_key_multibase = multibase::encode(
            multibase::Base::Base58Btc,
            signing_key.verifying_key().to_bytes(),
        );

        (
            BotRecord {
                bot_id: Some("urn:bot:sha256:placeholder".to_string()),
                version: Some(7),
                status: BotStatus::Active,
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
                parent_bot_id: None,
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
            .with_controller("urn:bot:sha256:controller");
        let signers: Vec<&dyn Signer> = vec![&signer];

        attach_proof_set(&mut record, &signers).expect("attach set");

        assert!(record.proof.is_none());
        let proof_set = record.proof_set.as_ref().expect("proof_set");
        assert_eq!(proof_set.len(), 1);
        assert_eq!(
            proof_set[0].key_ref.controller_bot_id.as_deref(),
            Some("urn:bot:sha256:controller")
        );
    }

    #[test]
    fn status_as_str_matches_api_values() {
        assert_eq!(status_as_str(BotStatus::Active), "active");
        assert_eq!(status_as_str(BotStatus::Deprecated), "deprecated");
        assert_eq!(status_as_str(BotStatus::Revoked), "revoked");
    }
}
