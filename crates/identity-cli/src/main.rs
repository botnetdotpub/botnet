use clap::Parser;
use identity_cli::{run, Cli};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(Cli::parse()).await
}
