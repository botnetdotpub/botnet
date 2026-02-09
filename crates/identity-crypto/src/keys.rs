use anyhow::Context;
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde_json::json;

pub fn generate_ed25519() -> SigningKey {
    let mut rng = OsRng;
    SigningKey::generate(&mut rng)
}

pub fn jwk_from_ed25519_pub(pk_raw: &[u8]) -> anyhow::Result<serde_json::Value> {
    if pk_raw.len() != 32 {
        anyhow::bail!("Ed25519 public key must be 32 bytes")
    }

    Ok(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": Base64UrlUnpadded::encode_string(pk_raw),
    }))
}

pub fn verifying_key_from_jwk(jwk: &serde_json::Value) -> anyhow::Result<VerifyingKey> {
    let kty = jwk.get("kty").and_then(|v| v.as_str()).unwrap_or_default();
    let crv = jwk.get("crv").and_then(|v| v.as_str()).unwrap_or_default();
    if kty != "OKP" || crv != "Ed25519" {
        anyhow::bail!("unsupported JWK kty/crv")
    }

    let x = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing JWK x"))?;
    let bytes = Base64UrlUnpadded::decode_vec(x).context("invalid JWK x encoding")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("JWK x must decode to 32 bytes"))?;

    VerifyingKey::from_bytes(&arr).context("invalid Ed25519 verifying key bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwk_roundtrip_for_generated_key() {
        let sk = generate_ed25519();
        let vk = sk.verifying_key();
        let jwk = jwk_from_ed25519_pub(&vk.to_bytes()).expect("jwk");
        let parsed = verifying_key_from_jwk(&jwk).expect("parse jwk");
        assert_eq!(parsed.to_bytes(), vk.to_bytes());
    }

    #[test]
    fn jwk_from_pub_rejects_non_32_byte_keys() {
        let err = jwk_from_ed25519_pub(&[1, 2, 3]).expect_err("must fail");
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn verifying_key_from_jwk_rejects_wrong_curve() {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        });
        let err = verifying_key_from_jwk(&jwk).expect_err("must fail");
        assert!(err.to_string().contains("unsupported JWK"));
    }
}
