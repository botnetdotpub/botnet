use anyhow::Context;
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Value};

pub fn sign_compact_jws(
    payload: &[u8],
    signing_key: &SigningKey,
    key_id: &str,
    detached: bool,
) -> anyhow::Result<String> {
    let header = if detached {
        json!({"alg": "EdDSA", "kid": key_id, "b64": false, "crit": ["b64"]})
    } else {
        json!({"alg": "EdDSA", "kid": key_id})
    };

    let header_raw = serde_json::to_vec(&header).context("serialize jws header")?;
    let header_b64 = Base64UrlUnpadded::encode_string(&header_raw);

    let (payload_segment, signing_input) = if detached {
        (
            String::new(),
            [header_b64.as_bytes(), b".", payload].concat(),
        )
    } else {
        let payload_b64 = Base64UrlUnpadded::encode_string(payload);
        (
            payload_b64.clone(),
            [header_b64.as_bytes(), b".", payload_b64.as_bytes()].concat(),
        )
    };

    let sig = signing_key.sign(&signing_input);
    let sig_b64 = Base64UrlUnpadded::encode_string(&sig.to_bytes());

    Ok(format!("{}.{}.{}", header_b64, payload_segment, sig_b64))
}

pub fn verify_compact_jws(
    jws_compact: &str,
    payload: &[u8],
    verifying_key: &VerifyingKey,
) -> anyhow::Result<()> {
    let parts: Vec<&str> = jws_compact.split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!("invalid compact JWS format");
    }

    let header_b64 = parts[0];
    let payload_segment = parts[1];
    let sig_b64 = parts[2];

    let header_bytes =
        Base64UrlUnpadded::decode_vec(header_b64).context("invalid JWS header b64")?;
    let header: Value = serde_json::from_slice(&header_bytes).context("invalid JWS header json")?;

    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if alg != "EdDSA" {
        anyhow::bail!("unsupported JWS algorithm: {}", alg);
    }

    let b64_disabled = header
        .get("b64")
        .and_then(|v| v.as_bool())
        .map(|v| !v)
        .unwrap_or(false);

    let signing_input = if b64_disabled {
        if !payload_segment.is_empty() {
            anyhow::bail!("detached JWS must have an empty payload segment");
        }
        [header_b64.as_bytes(), b".", payload].concat()
    } else {
        let embedded_payload = Base64UrlUnpadded::decode_vec(payload_segment)
            .context("invalid embedded payload b64")?;
        if embedded_payload != payload {
            anyhow::bail!("embedded payload does not match provided payload")
        }
        [header_b64.as_bytes(), b".", payload_segment.as_bytes()].concat()
    };

    let sig_bytes = Base64UrlUnpadded::decode_vec(sig_b64).context("invalid JWS signature b64")?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid Ed25519 signature length"))?;
    let sig = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(&signing_input, &sig)
        .context("Ed25519 signature verification failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_ed25519;
    use base64ct::Encoding;

    #[test]
    fn sign_and_verify_roundtrip_embedded() {
        let sk = generate_ed25519();
        let vk = sk.verifying_key();
        let payload = b"hello canonical payload";
        let jws = sign_compact_jws(payload, &sk, "k1", false).expect("sign");
        verify_compact_jws(&jws, payload, &vk).expect("verify");
    }

    #[test]
    fn sign_and_verify_roundtrip_detached() {
        let sk = generate_ed25519();
        let vk = sk.verifying_key();
        let payload = b"hello canonical payload";
        let jws = sign_compact_jws(payload, &sk, "k1", true).expect("sign");
        verify_compact_jws(&jws, payload, &vk).expect("verify");
    }

    #[test]
    fn verify_fails_for_wrong_payload() {
        let sk = generate_ed25519();
        let vk = sk.verifying_key();
        let jws = sign_compact_jws(b"payload-a", &sk, "k1", true).expect("sign");
        let err = verify_compact_jws(&jws, b"payload-b", &vk).expect_err("must fail");
        assert!(err.to_string().contains("verification failed"));
    }

    #[test]
    fn verify_fails_for_wrong_verifying_key() {
        let signer = generate_ed25519();
        let other = generate_ed25519();
        let jws = sign_compact_jws(b"payload", &signer, "k1", false).expect("sign");
        let err = verify_compact_jws(&jws, b"payload", &other.verifying_key()).expect_err("fail");
        assert!(err.to_string().contains("verification failed"));
    }

    #[test]
    fn verify_rejects_non_compact_format() {
        let vk = generate_ed25519().verifying_key();
        let err = verify_compact_jws("abc.def", b"payload", &vk).expect_err("must fail");
        assert!(err.to_string().contains("invalid compact JWS format"));
    }

    #[test]
    fn verify_rejects_modified_algorithm() {
        let sk = generate_ed25519();
        let vk = sk.verifying_key();
        let jws = sign_compact_jws(b"payload", &sk, "k1", false).expect("sign");
        let parts: Vec<&str> = jws.split('.').collect();

        let mut header: Value =
            serde_json::from_slice(&Base64UrlUnpadded::decode_vec(parts[0]).expect("decode"))
                .expect("header json");
        header["alg"] = Value::String("HS256".to_string());
        let new_header = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header).unwrap());
        let tampered = format!("{}.{}.{}", new_header, parts[1], parts[2]);

        let err = verify_compact_jws(&tampered, b"payload", &vk).expect_err("must fail");
        assert!(err.to_string().contains("unsupported JWS algorithm"));
    }
}
