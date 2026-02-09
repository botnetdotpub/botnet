use sha2::{Digest, Sha256};

pub fn derive_agent_id(pk_bytes: &[u8]) -> String {
    let hash = Sha256::digest(pk_bytes);
    format!("urn:agent:sha256:{}", hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::derive_agent_id;

    #[test]
    fn derive_agent_id_is_stable() {
        let pk = [7_u8; 32];
        let id = derive_agent_id(&pk);
        assert_eq!(
            id,
            "urn:agent:sha256:4bb06f8e4e3a7715d201d573d0aa423762e55dabd61a2c02278fa56cc6d294e0"
        );
    }
}
