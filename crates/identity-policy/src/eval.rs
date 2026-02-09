use identity_core::Policy;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy)]
pub enum Operation {
    Update,
    AddKey,
    RotateKey,
    RevokeKey,
    RevokeAgent,
    ManagePolicy,
}

impl Operation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::AddKey => "add_key",
            Self::RotateKey => "rotate_key",
            Self::RevokeKey => "revoke_key",
            Self::RevokeAgent => "revoke_agent",
            Self::ManagePolicy => "manage_policy",
        }
    }
}

pub fn evaluate_threshold(
    policy: Option<&Policy>,
    op: Operation,
    valid_signers: &[(Option<String>, String)],
) -> anyhow::Result<()> {
    let Some(policy) = policy else {
        if valid_signers.is_empty() {
            anyhow::bail!("no valid signatures")
        }
        return Ok(());
    };

    let rule = policy
        .rules
        .iter()
        .find(|r| r.operation == op.as_str())
        .ok_or_else(|| anyhow::anyhow!("no policy rule for {}", op.as_str()))?;

    if rule.r#type != "threshold" {
        anyhow::bail!("unsupported policy type {}", rule.r#type);
    }

    let signer_set = policy
        .signer_sets
        .iter()
        .find(|s| s.set_id == rule.set_id)
        .ok_or_else(|| anyhow::anyhow!("signer set not found: {}", rule.set_id))?;

    let allowed: HashSet<(Option<String>, String)> = signer_set
        .members
        .iter()
        .map(|m| (m.r#ref.controller_agent_id.clone(), m.r#ref.key_id.clone()))
        .collect();

    let mut seen = HashSet::new();
    for signer in valid_signers {
        if allowed.contains(signer) {
            seen.insert(signer.clone());
        }
    }

    if seen.len() < rule.m as usize {
        anyhow::bail!("threshold not met: have={}, need={}", seen.len(), rule.m)
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity_core::{KeyRef, Policy, PolicyRule, SignerRef, SignerSet};

    fn sample_policy(m: u32) -> Policy {
        Policy {
            version: 1,
            updated_at: "2026-01-01T00:00:00Z".into(),
            rules: vec![PolicyRule {
                operation: "update".into(),
                r#type: "threshold".into(),
                m,
                set_id: "owners".into(),
            }],
            signer_sets: vec![SignerSet {
                set_id: "owners".into(),
                members: vec![
                    SignerRef {
                        r#ref: KeyRef {
                            key_id: "k1".into(),
                            controller_agent_id: None,
                        },
                    },
                    SignerRef {
                        r#ref: KeyRef {
                            key_id: "k2".into(),
                            controller_agent_id: Some("urn:agent:sha256:controller".into()),
                        },
                    },
                ],
            }],
        }
    }

    #[test]
    fn threshold_success() {
        let mut policy = sample_policy(2);
        policy.signer_sets[0].members[1].r#ref.controller_agent_id = None;

        let valid = vec![(None, "k1".to_string()), (None, "k2".to_string())];
        evaluate_threshold(Some(&policy), Operation::Update, &valid).expect("must pass");
    }

    #[test]
    fn threshold_ignores_duplicate_signatures() {
        let policy = sample_policy(2);
        let valid = vec![
            (None, "k1".to_string()),
            (None, "k1".to_string()),
            (
                Some("urn:agent:sha256:controller".to_string()),
                "k2".to_string(),
            ),
        ];
        evaluate_threshold(Some(&policy), Operation::Update, &valid).expect("must pass");
    }

    #[test]
    fn threshold_fails_when_below_required_signers() {
        let policy = sample_policy(2);
        let valid = vec![(None, "k1".to_string())];
        let err = evaluate_threshold(Some(&policy), Operation::Update, &valid).expect_err("fail");
        assert!(err.to_string().contains("threshold not met"));
    }

    #[test]
    fn fails_without_matching_operation_rule() {
        let policy = sample_policy(1);
        let valid = vec![(None, "k1".to_string())];
        let err =
            evaluate_threshold(Some(&policy), Operation::RotateKey, &valid).expect_err("fail");
        assert!(err.to_string().contains("no policy rule"));
    }

    #[test]
    fn default_policy_requires_at_least_one_signature() {
        let empty: Vec<(Option<String>, String)> = vec![];
        assert!(evaluate_threshold(None, Operation::Update, &empty).is_err());

        let one = vec![(None, "k1".to_string())];
        evaluate_threshold(None, Operation::Update, &one).expect("must pass");
    }
}
