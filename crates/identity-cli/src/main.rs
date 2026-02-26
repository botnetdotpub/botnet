use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use identity_core::{Attestation, BotRecord, BotStatus, PublicKey};
use identity_sdk::{Client, LocalEd25519Signer};
use serde::de::DeserializeOwned;
use serde::Deserialize;

#[derive(Parser, Debug)]
#[command(name = "botnet")]
#[command(about = "AI Bot Registry CLI")]
struct Cli {
    #[arg(long, default_value = "http://localhost:8080/v1")]
    base_url: String,

    #[arg(long, help = "Signer key ID")]
    key_id: Option<String>,

    #[arg(long, help = "Ed25519 secret seed as 64-char hex")]
    secret_seed_hex: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Register {
        file: String,
    },
    Get {
        bot_id: String,
    },
    Update {
        bot_id: String,
        file: String,
    },
    AddKey {
        bot_id: String,
        file: String,
    },
    RemoveKey {
        bot_id: String,
        key_id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    RotateKey {
        bot_id: String,
        file: String,
    },
    RevokeBot {
        bot_id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    PublishAttestation {
        subject_bot_id: String,
        file: String,
    },
    Search {
        #[arg(long)]
        q: Option<String>,
        #[arg(long)]
        status: Option<StatusArg>,
        #[arg(long)]
        capability: Option<String>,
        #[arg(long)]
        limit: Option<usize>,
    },
    Nonce,
}

#[derive(Debug, Clone, ValueEnum)]
enum StatusArg {
    Active,
    Deprecated,
    Revoked,
}

impl From<StatusArg> for BotStatus {
    fn from(value: StatusArg) -> Self {
        match value {
            StatusArg::Active => BotStatus::Active,
            StatusArg::Deprecated => BotStatus::Deprecated,
            StatusArg::Revoked => BotStatus::Revoked,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RotateKeyInput {
    old_key_id: String,
    new_key: PublicKey,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let Cli {
        base_url,
        key_id,
        secret_seed_hex,
        command,
    } = cli;

    let client = Client::new(base_url);

    match command {
        Commands::Register { file } => {
            let signer = required_signer(key_id.as_deref(), secret_seed_hex.as_deref())?;
            let record: BotRecord = read_json(&file)?;
            let created = client.create_bot(record, &signer).await?;
            println!("{}", serde_json::to_string_pretty(&created)?);
        }
        Commands::Get { bot_id } => {
            let bot = client.get_bot(&bot_id).await?;
            println!("{}", serde_json::to_string_pretty(&bot)?);
        }
        Commands::Update { bot_id, file } => {
            let signer = required_signer(key_id.as_deref(), secret_seed_hex.as_deref())?;
            let record: BotRecord = read_json(&file)?;
            let updated = client.update_bot(&bot_id, record, &signer).await?;
            println!("{}", serde_json::to_string_pretty(&updated)?);
        }
        Commands::AddKey { bot_id, file } => {
            let signer = required_signer(key_id.as_deref(), secret_seed_hex.as_deref())?;
            let key: PublicKey = read_json(&file)?;
            let updated = client.add_key(&bot_id, key, &signer).await?;
            println!("{}", serde_json::to_string_pretty(&updated)?);
        }
        Commands::RemoveKey {
            bot_id,
            key_id: remove_key_id,
            reason,
        } => {
            let signer = required_signer(key_id.as_deref(), secret_seed_hex.as_deref())?;
            let updated = client
                .remove_key(&bot_id, &remove_key_id, reason, &signer)
                .await?;
            println!("{}", serde_json::to_string_pretty(&updated)?);
        }
        Commands::RotateKey { bot_id, file } => {
            let signer = required_signer(key_id.as_deref(), secret_seed_hex.as_deref())?;
            let payload: RotateKeyInput = read_json(&file)?;
            let updated = client
                .rotate_key(&bot_id, &payload.old_key_id, payload.new_key, &signer)
                .await?;
            println!("{}", serde_json::to_string_pretty(&updated)?);
        }
        Commands::RevokeBot { bot_id, reason } => {
            let signer = required_signer(key_id.as_deref(), secret_seed_hex.as_deref())?;
            let updated = client.revoke_bot(&bot_id, reason, &signer).await?;
            println!("{}", serde_json::to_string_pretty(&updated)?);
        }
        Commands::PublishAttestation {
            subject_bot_id,
            file,
        } => {
            let signer = required_signer(key_id.as_deref(), secret_seed_hex.as_deref())?;
            let attestation: Attestation = read_json(&file)?;
            let created = client
                .publish_attestation(&subject_bot_id, attestation, &signer)
                .await?;
            println!("{}", serde_json::to_string_pretty(&created)?);
        }
        Commands::Search {
            q,
            status,
            capability,
            limit,
        } => {
            let response = client
                .search_bots(
                    q.as_deref(),
                    status.map(Into::into),
                    capability.as_deref(),
                    limit,
                )
                .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Commands::Nonce => {
            let nonce = client.get_nonce().await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"nonce": nonce}))?
            );
        }
    }

    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &str) -> anyhow::Result<T> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path))?;
    serde_json::from_str(&text).with_context(|| format!("parse {} as JSON", path))
}

fn required_signer(
    key_id: Option<&str>,
    secret_seed_hex: Option<&str>,
) -> anyhow::Result<LocalEd25519Signer> {
    let key_id =
        key_id.ok_or_else(|| anyhow::anyhow!("--key-id is required for signed operations"))?;

    let seed_hex = secret_seed_hex
        .ok_or_else(|| anyhow::anyhow!("--secret-seed-hex is required for signed operations"))?;

    let seed = hex::decode(seed_hex).context("decode --secret-seed-hex")?;
    LocalEd25519Signer::from_seed_bytes(key_id, &seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_register_command_with_signing_args() {
        let cli = Cli::parse_from([
            "botnet",
            "--base-url",
            "http://localhost:8080/v1",
            "--key-id",
            "k1",
            "--secret-seed-hex",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "register",
            "bot.json",
        ]);

        assert_eq!(cli.base_url, "http://localhost:8080/v1");
        assert_eq!(cli.key_id.as_deref(), Some("k1"));
        match cli.command {
            Commands::Register { file } => assert_eq!(file, "bot.json"),
            _ => panic!("expected register command"),
        }
    }

    #[test]
    fn parses_rotate_key_command() {
        let cli = Cli::parse_from([
            "botnet",
            "--key-id",
            "k1",
            "--secret-seed-hex",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "rotate-key",
            "urn:bot:sha256:abc",
            "rotate.json",
        ]);

        match cli.command {
            Commands::RotateKey { bot_id, file } => {
                assert_eq!(bot_id, "urn:bot:sha256:abc");
                assert_eq!(file, "rotate.json");
            }
            _ => panic!("expected rotate-key command"),
        }
    }

    #[test]
    fn parses_search_command_with_status() {
        let cli = Cli::parse_from([
            "botnet", "search", "--q", "alpha", "--status", "active", "--limit", "10",
        ]);

        match cli.command {
            Commands::Search {
                q,
                status,
                capability,
                limit,
            } => {
                assert_eq!(q.as_deref(), Some("alpha"));
                assert!(matches!(status, Some(StatusArg::Active)));
                assert!(capability.is_none());
                assert_eq!(limit, Some(10));
            }
            _ => panic!("expected search command"),
        }
    }

    #[test]
    fn required_signer_fails_without_args() {
        assert!(required_signer(None, None).is_err());
        assert!(required_signer(Some("k1"), None).is_err());
    }
}
