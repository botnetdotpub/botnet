use anyhow::Context;

pub async fn load_json_fixture(path: &str) -> anyhow::Result<serde_json::Value> {
    let raw = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read fixture {path}"))?;
    serde_json::from_str(&raw).context("parse fixture as json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn load_json_fixture_reads_valid_json() {
        let path =
            std::env::temp_dir().join(format!("test-support-fixture-{}.json", std::process::id()));
        tokio::fs::write(&path, "{\"ok\":true}")
            .await
            .expect("write fixture");

        let value = load_json_fixture(path.to_str().expect("utf8 path"))
            .await
            .expect("load fixture");
        assert_eq!(value["ok"], true);

        tokio::fs::remove_file(path).await.expect("cleanup");
    }
}
