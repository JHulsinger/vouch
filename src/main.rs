use anyhow::Result;
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use std::path::PathBuf;
use vouch::acme_client::AcmeClient;
#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "vouch: A fast, statically-linked, pure-Rust ACME client",
    long_about = None
)]
struct Cli {
    /// Configuration directory
    #[arg(long, global = true)]
    config_dir: Option<PathBuf>,
    /// Working directory for state
    #[arg(long, global = true)]
    work_dir: Option<PathBuf>,
    /// Logs directory
    #[arg(long, global = true)]
    logs_dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand, Debug)]
enum Commands {
    /// Obtain or renew a certificate
    Certonly {
        /// Domain to obtain the certificate for
        #[arg(short, long)]
        domain: String,
        /// Email for Let's Encrypt registration
        #[arg(short, long)]
        email: String,
        /// Output directory for certs
        #[arg(short, long, default_value = ".")]
        out_dir: PathBuf,
    },
}
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let default_config_dir = ProjectDirs::from("io", "vouch", "vouch")
        .map(|project_dirs| project_dirs.config_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".").join(".vouch"));
    let config_dir = cli.config_dir.unwrap_or(default_config_dir);
    match &cli.command {
        Commands::Certonly {
            domain,
            email,
            out_dir: _out_dir,
        } => {
            println!("🚀 Starting vouch for domain: {}", domain);
            println!("📦 Registering account with Let's Encrypt (Staging)...");
            let client = AcmeClient::new(email, config_dir).await?;
            println!("✅ Account created!");
            println!("📝 Creating order for {}...", domain);
            let mut order = client.new_order(domain).await?;
            println!("✅ Order pending. State: {:?}", order.state().status);
            if let Err(e) = client.verify_and_finalize(&mut order).await {
                println!("❌ ACME Verification Failed: {}", e);
            }
            println!("🏁 vouch run complete");
        }
    }
    Ok(())
}
