use crate::{AgentRecord, Policy};
use anyhow::{bail, Context};

pub fn validate_agent_record(record: &AgentRecord) -> anyhow::Result<()> {
    if record.public_keys.is_empty() {
        bail!("agent must include at least one public key");
    }

    let primary_count = record
        .public_keys
        .iter()
        .filter(|k| k.primary.unwrap_or(false))
        .count();
    if primary_count != 1 {
        bail!("exactly one key must be primary=true");
    }

    if let Some(policy) = record.policy.as_ref() {
        validate_policy(policy).context("invalid policy")?;
    }

    if record.proof.is_some() && record.proof_set.is_some() {
        bail!("provide either proof or proof_set, not both");
    }

    Ok(())
}

pub fn validate_policy(policy: &Policy) -> anyhow::Result<()> {
    for rule in &policy.rules {
        if rule.r#type != "threshold" {
            bail!("unsupported policy rule type: {}", rule.r#type);
        }

        let signer_set = policy
            .signer_sets
            .iter()
            .find(|s| s.set_id == rule.set_id)
            .ok_or_else(|| anyhow::anyhow!("missing signer set {}", rule.set_id))?;

        let n = signer_set.members.len() as u32;
        if n == 0 {
            bail!("signer set {} must not be empty", signer_set.set_id);
        }
        if rule.m == 0 || rule.m > n {
            bail!("invalid threshold m={} for n={}", rule.m, n);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        canonical::canonicalize, AgentRecord, AgentStatus, KeyRef, Policy, PolicyRule, Proof,
        PublicKey, SignerRef, SignerSet,
    };

    fn sample_record() -> AgentRecord {
        AgentRecord {
            agent_id: None,
            version: None,
            status: AgentStatus::Active,
            display_name: Some("test".to_string()),
            description: None,
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

    fn sample_policy(m: u32, members: &[&str]) -> Policy {
        Policy {
            version: 1,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            rules: vec![PolicyRule {
                operation: "update".to_string(),
                r#type: "threshold".to_string(),
                m,
                set_id: "owners".to_string(),
            }],
            signer_sets: vec![SignerSet {
                set_id: "owners".to_string(),
                members: members
                    .iter()
                    .map(|k| SignerRef {
                        r#ref: KeyRef {
                            key_id: (*k).to_string(),
                            controller_agent_id: None,
                        },
                    })
                    .collect(),
            }],
        }
    }

    #[test]
    fn canonicalization_is_deterministic() {
        let record = sample_record();
        let a = canonicalize(&record).expect("canon a");
        let b = canonicalize(&record).expect("canon b");
        assert_eq!(a, b);
    }

    #[test]
    fn record_validation_requires_primary() {
        let mut record = sample_record();
        record.public_keys[0].primary = Some(false);
        assert!(validate_agent_record(&record).is_err());
    }

    #[test]
    fn record_validation_rejects_empty_public_keys() {
        let mut record = sample_record();
        record.public_keys.clear();
        assert!(validate_agent_record(&record).is_err());
    }

    #[test]
    fn record_validation_rejects_multiple_primaries() {
        let mut record = sample_record();
        record.public_keys.push(PublicKey {
            key_id: "k2".to_string(),
            algorithm: "Ed25519".to_string(),
            public_key_multibase: "zTestPublicKey2".to_string(),
            purpose: vec!["signing".to_string()],
            valid_from: None,
            valid_to: None,
            revoked_at: None,
            revocation_reason: None,
            primary: Some(true),
            origin: None,
        });
        assert!(validate_agent_record(&record).is_err());
    }

    #[test]
    fn record_validation_rejects_proof_and_proof_set_together() {
        let mut record = sample_record();
        record.proof = Some(Proof {
            algorithm: "Ed25519".to_string(),
            key_id: "k1".to_string(),
            created: "2026-02-15T00:00:00Z".to_string(),
            nonce: None,
            jws: "header..sig".to_string(),
        });
        record.proof_set = Some(vec![]);
        assert!(validate_agent_record(&record).is_err());
    }

    #[test]
    fn policy_validation_accepts_valid_threshold() {
        let policy = sample_policy(1, &["k1", "k2"]);
        validate_policy(&policy).expect("policy should be valid");
    }

    #[test]
    fn policy_validation_rejects_missing_signer_set() {
        let policy = Policy {
            version: 1,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            rules: vec![PolicyRule {
                operation: "update".to_string(),
                r#type: "threshold".to_string(),
                m: 1,
                set_id: "missing".to_string(),
            }],
            signer_sets: vec![],
        };
        assert!(validate_policy(&policy).is_err());
    }

    #[test]
    fn policy_validation_rejects_invalid_threshold_bounds() {
        let policy_zero = sample_policy(0, &["k1"]);
        assert!(validate_policy(&policy_zero).is_err());

        let policy_too_high = sample_policy(3, &["k1", "k2"]);
        assert!(validate_policy(&policy_too_high).is_err());
    }

    #[test]
    fn policy_validation_rejects_unsupported_rule_type() {
        let mut policy = sample_policy(1, &["k1"]);
        policy.rules[0].r#type = "unknown".to_string();
        assert!(validate_policy(&policy).is_err());
    }
}
