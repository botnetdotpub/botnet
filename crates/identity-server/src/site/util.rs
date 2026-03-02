use serde_json::Value;

pub fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

pub fn slugify(input: &str) -> String {
    let mut output = String::new();
    let mut last_was_dash = false;

    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            output.push('-');
            last_was_dash = true;
        }
    }

    let trimmed = output.trim_matches('-');
    if trimmed.is_empty() {
        "section".to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn endpoint_anchor(method: &str, path: &str) -> String {
    slugify(&format!("{} {}", method.to_lowercase(), path))
}

pub fn method_rank(method: &str) -> u8 {
    match method {
        "GET" => 0,
        "POST" => 1,
        "PATCH" => 2,
        "PUT" => 3,
        "DELETE" => 4,
        "OPTIONS" => 5,
        "HEAD" => 6,
        _ => 7,
    }
}

pub fn auth_requirement(method: &str, path: &str) -> &'static str {
    match (method, path) {
        ("post", "/v1/bots")
        | ("patch", "/v1/bots/{bot_id}")
        | ("post", "/v1/bots/{bot_id}/keys")
        | ("delete", "/v1/bots/{bot_id}/keys/{key_id}")
        | ("post", "/v1/bots/{bot_id}/rotate")
        | ("post", "/v1/bots/{bot_id}/revoke") => "proof or proof_set required",
        ("post", "/v1/attestations") => "issuer attestation signature required",
        _ => "public",
    }
}

pub fn prettify_identifier(identifier: &str) -> String {
    identifier
        .split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    format!(
                        "{}{}",
                        first.to_ascii_uppercase(),
                        chars.as_str().to_ascii_lowercase()
                    )
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn describe_schema(schema: &Value) -> String {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
        return reference
            .rsplit('/')
            .next()
            .unwrap_or(reference)
            .to_string();
    }

    if let Some(schema_type) = schema.get("type").and_then(Value::as_str) {
        if schema_type == "array" {
            if let Some(item_schema) = schema.get("items") {
                return format!("array<{}>", describe_schema(item_schema));
            }
            return "array".to_string();
        }
        return schema_type.to_string();
    }

    if schema.get("oneOf").is_some() {
        return "oneOf".to_string();
    }
    if schema.get("anyOf").is_some() {
        return "anyOf".to_string();
    }
    if schema.get("allOf").is_some() {
        return "allOf".to_string();
    }
    "object".to_string()
}

pub fn describe_schema_kind(schema: &Value) -> String {
    let kind = describe_schema(schema);
    if kind == "object" {
        if let Some(enum_values) = schema.get("enum").and_then(Value::as_array) {
            return format!("enum({})", enum_values.len());
        }
    }
    kind
}
