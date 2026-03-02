use anyhow::Context;
use clap::{builder::StyledStr, Command, CommandFactory, Parser, Subcommand, ValueEnum};
use identity_core::{Attestation, BotRecord, BotStatus, PublicKey};
use identity_sdk::{Client, LocalEd25519Signer};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
#[command(name = "botnet")]
#[command(about = "AI Bot Registry CLI")]
pub struct Cli {
    #[arg(
        long,
        default_value = "http://localhost:8080/v1",
        help = "API base URL"
    )]
    pub base_url: String,

    #[arg(long, help = "Signer key ID for signed operations")]
    pub key_id: Option<String>,

    #[arg(long, help = "Ed25519 secret seed as 64-char hex for local signing")]
    pub secret_seed_hex: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Register a bot interactively or from a JSON file (signed)")]
    Register {
        #[arg(help = "Path to a bot JSON file (omit for interactive mode)")]
        file: Option<String>,
    },
    #[command(about = "Fetch a bot by ID")]
    Get { bot_id: String },
    #[command(about = "Update a bot from a JSON file (signed)")]
    Update { bot_id: String, file: String },
    #[command(about = "Add a public key to a bot (signed)")]
    AddKey { bot_id: String, file: String },
    #[command(about = "Revoke a key on a bot (signed)")]
    RemoveKey {
        bot_id: String,
        key_id: String,
        #[arg(long, help = "Optional revocation reason")]
        reason: Option<String>,
    },
    #[command(about = "Rotate a key in one operation (signed)")]
    RotateKey { bot_id: String, file: String },
    #[command(about = "Revoke a bot identity (signed)")]
    RevokeBot {
        bot_id: String,
        #[arg(long, help = "Optional revocation reason")]
        reason: Option<String>,
    },
    #[command(about = "Publish an attestation for a subject bot (signed by issuer key)")]
    PublishAttestation {
        subject_bot_id: String,
        file: String,
    },
    #[command(about = "Search bots by filters")]
    Search {
        #[arg(long, help = "Text query against ID/name/description")]
        q: Option<String>,
        #[arg(long, help = "Filter by bot status")]
        status: Option<StatusArg>,
        #[arg(long, help = "Filter by capability")]
        capability: Option<String>,
        #[arg(long, help = "Maximum rows (default server limit if omitted)")]
        limit: Option<usize>,
    },
    #[command(about = "Fetch a nonce for anti-replay workflows")]
    Nonce,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum StatusArg {
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

#[derive(Debug, Clone, Serialize)]
pub struct CliDocs {
    pub binary_name: String,
    pub about: Option<String>,
    pub long_about: Option<String>,
    pub usage: String,
    pub help: String,
    pub commands: Vec<CliCommandDoc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CliCommandDoc {
    pub invocation: String,
    pub about: Option<String>,
    pub long_about: Option<String>,
    pub usage: String,
    pub help: String,
    pub subcommands: Vec<CliCommandDoc>,
}

pub fn cli_command() -> Command {
    Cli::command()
}

pub fn generate_cli_docs() -> CliDocs {
    let command = cli_command();
    let binary_name = command.get_name().to_string();
    let commands = command
        .get_subcommands()
        .cloned()
        .map(|sub| build_command_doc(sub, &binary_name))
        .collect();

    CliDocs {
        binary_name,
        about: styled_to_string(command.get_about()),
        long_about: styled_to_string(command.get_long_about()),
        usage: render_usage(&command),
        help: render_long_help(&command),
        commands,
    }
}

pub async fn run(cli: Cli) -> anyhow::Result<()> {
    let Cli {
        base_url,
        key_id,
        secret_seed_hex,
        command,
    } = cli;

    let client = Client::new(base_url);

    match command {
        Commands::Register { file } => match file {
            Some(path) => {
                let signer = required_signer(key_id.as_deref(), secret_seed_hex.as_deref())?;
                let record: BotRecord = read_json(&path)?;
                let created = client.create_bot(record, &signer).await?;
                println!("{}", serde_json::to_string_pretty(&created)?);
            }
            None => {
                interactive_register(&client).await?;
            }
        },
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

fn prompt(label: &str, default: &str) -> anyhow::Result<String> {
    if default.is_empty() {
        eprint!("{}: ", label);
    } else {
        eprint!("{} [{}]: ", label, default);
    }
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf).context("read stdin")?;
    let trimmed = buf.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

async fn interactive_register(client: &Client) -> anyhow::Result<()> {
    let signing_key = identity_crypto::keys::generate_ed25519();
    let pub_bytes = signing_key.verifying_key().to_bytes();
    let public_key_multibase = multibase::encode(multibase::Base::Base58Btc, pub_bytes);
    let key_id = format!("key-{}", &hex::encode(pub_bytes)[..8]);
    let seed_hex = hex::encode(signing_key.to_bytes());

    let display_name = prompt("Display name", "My Bot")?;
    let description = prompt("Description", "")?;

    let public_key = PublicKey {
        key_id: key_id.clone(),
        algorithm: "Ed25519".to_string(),
        public_key_multibase,
        purpose: vec!["signing".to_string()],
        valid_from: None,
        valid_to: None,
        revoked_at: None,
        revocation_reason: None,
        primary: Some(true),
        origin: None,
    };

    let record = BotRecord {
        bot_id: None,
        version: None,
        status: BotStatus::Active,
        display_name: Some(display_name),
        description: if description.is_empty() {
            None
        } else {
            Some(description)
        },
        owner: None,
        public_keys: vec![public_key],
        endpoints: None,
        capabilities: None,
        controllers: None,
        parent_bot_id: None,
        policy: None,
        attestations: None,
        evidence: None,
        created_at: None,
        updated_at: None,
        proof: None,
        proof_set: None,
    };

    let seed_bytes = signing_key.to_bytes();
    let signer = LocalEd25519Signer::from_seed_bytes(&key_id, seed_bytes.as_slice())?;
    let created = client.create_bot(record, &signer).await?;

    eprintln!();
    eprintln!("--- credentials (save these, the secret cannot be recovered) ---");
    eprintln!("key-id:          {}", key_id);
    eprintln!("secret-seed-hex: {}", seed_hex);
    eprintln!("----------------------------------------------------------------");
    eprintln!();

    println!("{}", serde_json::to_string_pretty(&created)?);

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

fn styled_to_string(value: Option<&StyledStr>) -> Option<String> {
    value.and_then(|styled| {
        let rendered = styled.to_string();
        let trimmed = rendered.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn render_usage(command: &Command) -> String {
    let mut cmd = command.clone();
    cmd.render_usage().to_string().trim().to_string()
}

fn render_long_help(command: &Command) -> String {
    let mut cmd = command.clone();
    cmd.render_long_help().to_string().trim().to_string()
}

fn build_command_doc(command: Command, parent_invocation: &str) -> CliCommandDoc {
    let command_name = command.get_name().to_string();
    let invocation = format!("{parent_invocation} {command_name}");
    let subcommands = command
        .get_subcommands()
        .cloned()
        .map(|sub| build_command_doc(sub, &invocation))
        .collect();

    CliCommandDoc {
        invocation,
        about: styled_to_string(command.get_about()),
        long_about: styled_to_string(command.get_long_about()),
        usage: render_usage(&command),
        help: render_long_help(&command),
        subcommands,
    }
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
            Commands::Register { file } => assert_eq!(file.as_deref(), Some("bot.json")),
            _ => panic!("expected register command"),
        }
    }

    #[test]
    fn parses_register_command_without_file() {
        let cli = Cli::parse_from(["botnet", "register"]);

        match cli.command {
            Commands::Register { file } => assert!(file.is_none()),
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

    #[test]
    fn cli_docs_include_core_commands() {
        let docs = generate_cli_docs();
        assert_eq!(docs.binary_name, "botnet");
        assert!(docs
            .commands
            .iter()
            .any(|c| c.invocation == "botnet register"));
        assert!(docs
            .commands
            .iter()
            .any(|c| c.invocation == "botnet publish-attestation"));
    }
}
