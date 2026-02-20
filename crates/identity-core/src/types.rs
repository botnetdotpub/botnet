use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BotStatus {
    Active,
    Deprecated,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct BotRecord {
    pub bot_id: Option<String>,
    pub version: Option<u64>,
    pub status: BotStatus,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub owner: Option<Owner>,
    pub public_keys: Vec<PublicKey>,
    pub endpoints: Option<Vec<Endpoint>>,
    pub capabilities: Option<Vec<String>>,
    pub controllers: Option<Vec<Controller>>,
    pub parent_bot_id: Option<String>,
    pub policy: Option<Policy>,
    pub attestations: Option<Vec<Attestation>>,
    pub evidence: Option<Vec<Evidence>>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    /// Single-signature authorization proof for bot mutations.
    /// The JWS signs the JCS-canonicalized payload with proof fields removed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
    /// Multi-signature authorization proofs for m-of-n policy operations.
    /// Each signer must be unique by `(controller_bot_id, key_id)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_set: Option<Vec<ProofItem>>,
}

impl BotRecord {
    pub fn payload_for_signing(&self) -> Self {
        let mut clone = self.clone();
        clone.bot_id = None;
        clone.version = None;
        clone.created_at = None;
        clone.updated_at = None;
        clone.proof = None;
        clone.proof_set = None;
        clone
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Owner {
    pub r#type: String,
    pub id: Option<String>,
    pub contact_uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct PublicKey {
    pub key_id: String,
    pub algorithm: String,
    pub public_key_multibase: String,
    pub purpose: Vec<String>,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub revoked_at: Option<String>,
    pub revocation_reason: Option<String>,
    pub primary: Option<bool>,
    pub origin: Option<KeyOrigin>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct KeyOrigin {
    pub r#type: String,
    pub scheme: Option<String>,
    pub master_fingerprint: Option<String>,
    pub derivation_path: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Endpoint {
    pub r#type: String,
    pub url: String,
    pub auth: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Controller {
    pub controller_bot_id: String,
    pub role: Option<String>,
    pub delegation: Option<Delegation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Delegation {
    pub allows: Vec<String>,
    pub constraints: Option<BTreeMap<String, Vec<String>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Policy {
    pub version: u64,
    pub updated_at: String,
    pub rules: Vec<PolicyRule>,
    pub signer_sets: Vec<SignerSet>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct PolicyRule {
    pub operation: String,
    pub r#type: String,
    pub m: u32,
    pub set_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct SignerSet {
    pub set_id: String,
    pub members: Vec<SignerRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct SignerRef {
    pub r#ref: KeyRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema, PartialEq, Eq, Hash)]
pub struct KeyRef {
    pub key_id: String,
    pub controller_bot_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Proof {
    pub algorithm: String,
    pub key_id: String,
    pub created: String,
    pub nonce: Option<String>,
    pub jws: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct ProofItem {
    pub algorithm: String,
    pub key_ref: KeyRef,
    pub created: String,
    pub nonce: Option<String>,
    pub jws: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Attestation {
    pub attestation_id: Option<String>,
    pub issuer_bot_id: String,
    pub r#type: String,
    pub statement: serde_json::Value,
    pub signature: SignatureRef,
    pub issued_at: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct SignatureRef {
    pub algorithm: String,
    pub key_id: String,
    pub jws: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, ToSchema)]
pub struct Evidence {
    pub r#type: String,
    pub uri: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> BotRecord {
        BotRecord {
            bot_id: Some("urn:bot:sha256:test".to_string()),
            version: Some(42),
            status: BotStatus::Active,
            display_name: Some("test".to_string()),
            description: Some("desc".to_string()),
            owner: None,
            public_keys: vec![PublicKey {
                key_id: "k1".to_string(),
                algorithm: "Ed25519".to_string(),
                public_key_multibase: "zTestPublicKey".to_string(),
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
            proof: Some(Proof {
                algorithm: "Ed25519".to_string(),
                key_id: "k1".to_string(),
                created: "2026-02-15T00:00:00Z".to_string(),
                nonce: Some("n".to_string()),
                jws: "header..sig".to_string(),
            }),
            proof_set: Some(vec![ProofItem {
                algorithm: "Ed25519".to_string(),
                key_ref: KeyRef {
                    key_id: "k2".to_string(),
                    controller_bot_id: Some("urn:bot:sha256:controller".to_string()),
                },
                created: "2026-02-15T00:00:01Z".to_string(),
                nonce: None,
                jws: "header..sig2".to_string(),
            }]),
        }
    }

    #[test]
    fn payload_for_signing_strips_server_and_proof_fields() {
        let record = sample_record();
        let payload = record.payload_for_signing();

        assert!(payload.bot_id.is_none());
        assert!(payload.version.is_none());
        assert!(payload.created_at.is_none());
        assert!(payload.updated_at.is_none());
        assert!(payload.proof.is_none());
        assert!(payload.proof_set.is_none());

        assert_eq!(payload.status, BotStatus::Active);
        assert_eq!(payload.display_name.as_deref(), Some("test"));
        assert_eq!(payload.public_keys[0].key_id, "k1");
    }
}
