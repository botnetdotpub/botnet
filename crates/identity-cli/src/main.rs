use anyhow::Context;
use clap::{Parser, Subcommand};
use identity_core::AgentRecord;
use identity_sdk::{Client, LocalEd25519Signer};

#[derive(Parser, Debug)]
#[command(name = "agentctl")]
#[command(about = "AI Agent Registry CLI")]
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
        agent_id: String,
    },
    Update {
        agent_id: String,
        file: String,
    },
    RotateKey {
        agent_id: String,
        file: String,
    },
    RevokeAgent {
        agent_id: String,
        reason: Option<String>,
    },
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
            let record = read_record(&file)?;
            let created = client.create_agent(record, &signer).await?;
            println!("{}", serde_json::to_string_pretty(&created)?);
        }
        Commands::Get { agent_id } => {
            let agent = client.get_agent(&agent_id).await?;
            println!("{}", serde_json::to_string_pretty(&agent)?);
        }
        Commands::Update { agent_id, file } => {
            let signer = required_signer(key_id.as_deref(), secret_seed_hex.as_deref())?;
            let record = read_record(&file)?;
            let updated = client.update_agent(&agent_id, record, &signer).await?;
            println!("{}", serde_json::to_string_pretty(&updated)?);
        }
        Commands::RotateKey { agent_id, file } => {
            println!(
                "rotate_key is scaffolded but not implemented yet (agent_id={}, file={})",
                agent_id, file
            );
        }
        Commands::RevokeAgent { agent_id, reason } => {
            println!(
                "revoke_agent is scaffolded but not implemented yet (agent_id={}, reason={})",
                agent_id,
                reason.unwrap_or_else(|| "<none>".to_string())
            );
        }
    }

    Ok(())
}

fn read_record(path: &str) -> anyhow::Result<AgentRecord> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path))?;
    serde_json::from_str(&text).with_context(|| format!("parse {} as AgentRecord JSON", path))
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
            "agentctl",
            "--base-url",
            "http://localhost:8080/v1",
            "--key-id",
            "k1",
            "--secret-seed-hex",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "register",
            "agent.json",
        ]);

        assert_eq!(cli.base_url, "http://localhost:8080/v1");
        assert_eq!(cli.key_id.as_deref(), Some("k1"));
        match cli.command {
            Commands::Register { file } => assert_eq!(file, "agent.json"),
            _ => panic!("expected register command"),
        }
    }

    #[test]
    fn required_signer_fails_without_args() {
        assert!(required_signer(None, None).is_err());
        assert!(required_signer(Some("k1"), None).is_err());
    }
}
