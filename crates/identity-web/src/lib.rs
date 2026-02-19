use identity_core::{canonical::canonicalize, BotRecord};
use wasm_bindgen::prelude::*;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct WasmClient {
    base_url: String,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl WasmClient {
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(constructor))]
    pub fn new(base_url: String) -> WasmClient {
        WasmClient { base_url }
    }

    pub fn base_url(&self) -> String {
        self.base_url.clone()
    }

    pub async fn create_bot(&self, record_json: String) -> Result<String, JsValue> {
        // Starter behavior: validates + canonicalizes payload shape.
        // Networking and browser key management are added in follow-up steps.
        let mut record: BotRecord = serde_json::from_str(&record_json)
            .map_err(|e| JsValue::from_str(&format!("invalid record JSON: {e}")))?;

        record.proof = None;
        record.proof_set = None;
        let payload = record.payload_for_signing();

        let canon = canonicalize(&payload)
            .map_err(|e| JsValue::from_str(&format!("canonicalization failed: {e}")))?;

        Ok(serde_json::json!({
            "base_url": self.base_url,
            "canonical_payload_hex": hex::encode(canon),
            "note": "create_bot network/signing flow is scaffolded"
        })
        .to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::executor::block_on;

    #[test]
    fn constructor_stores_base_url() {
        let client = WasmClient::new("https://registry.example/v1".to_string());
        assert_eq!(client.base_url(), "https://registry.example/v1");
    }

    #[test]
    fn create_bot_returns_scaffold_payload_for_valid_input() {
        let client = WasmClient::new("https://registry.example/v1".to_string());
        let input = serde_json::json!({
            "bot_id": null,
            "version": null,
            "status": "active",
            "display_name": "web-test",
            "description": null,
            "owner": null,
            "public_keys": [{
                "key_id": "k1",
                "algorithm": "Ed25519",
                "public_key_multibase": "zKey",
                "purpose": ["signing"],
                "valid_from": null,
                "valid_to": null,
                "revoked_at": null,
                "revocation_reason": null,
                "primary": true,
                "origin": null
            }],
            "endpoints": null,
            "capabilities": null,
            "controllers": null,
            "parent_bot_id": null,
            "policy": null,
            "attestations": null,
            "evidence": null,
            "created_at": null,
            "updated_at": null
        });

        let result = block_on(client.create_bot(input.to_string())).expect("create_bot");
        let out: serde_json::Value = serde_json::from_str(&result).expect("json output");
        assert_eq!(out["base_url"], "https://registry.example/v1");
        assert!(out["canonical_payload_hex"].as_str().is_some());
    }
}
