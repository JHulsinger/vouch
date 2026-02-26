use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use directories::ProjectDirs;
use std::path::PathBuf;
use tracing::{error, info};
use vouch::acme_client::AcmeClient;
use vouch::plugins::webroot::WebrootAuthenticator;
use x509_parser::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};

/// Helper to check if a certificate is expiring within a given number of days
fn check_expiration_days(cert_bytes: &[u8], threshold_days: u32) -> anyhow::Result<(bool, i64)> {
    let (_, cert) = X509Certificate::from_der(cert_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {:?}", e))?;
    
    let not_after = cert.validity().not_after.timestamp();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let days_left = (not_after - now) / 86400;

    Ok((days_left <= threshold_days as i64, days_left))
}

#[derive(Clone, Debug, ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

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

    /// Use the Let's Encrypt production server (WARNING: Subject to strict rate limits)
    #[arg(long, global = true, default_value_t = false)]
    production: bool,

    /// Custom ACME directory URL (overrides --production if set)
    #[arg(long, global = true)]
    server: Option<String>,

    /// Path to a custom root certificate PEM file (useful for testing against Pebble)
    #[arg(long, global = true)]
    root_cert: Option<PathBuf>,

    /// Log format
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,

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
        /// Webroot path for HTTP-01 challenge fulfillment
        #[arg(short, long)]
        webroot: Option<PathBuf>,
        /// Output directory for certs
        #[arg(short, long, default_value = ".")]
        out_dir: PathBuf,
        /// DNS plugin path (for DNS-01 challenges)
        #[arg(long)]
        dns_plugin: Option<PathBuf>,

        /// Wait time (seconds) for DNS propagation
        #[arg(long, default_value_t = 60)]
        dns_propagation_seconds: u64,
        
        /// Preferred challenge type (http-01 or dns-01)
        #[arg(long, default_value = "http-01")]
        preferred_challenge: String,
    },
    
    /// Renew all certificates that are approaching expiration
    Renew {
        /// Number of days before expiration to consider a certificate due for renewal
        #[arg(long, default_value_t = 30)]
        days: u32,
        
        /// Authenticator plugin path (for IPC)
        #[arg(long)]
        authenticator: Option<PathBuf>,
        
        /// DNS plugin path (for DNS-01 challenges)
        #[arg(long)]
        dns_plugin: Option<PathBuf>,

        /// Wait time (seconds) for DNS propagation
        #[arg(long, default_value_t = 60)]
        dns_propagation_seconds: u64,

        /// Installer plugin path (for IPC)
        #[arg(long)]
        installer: Option<PathBuf>,
        
        /// Webroot path for HTTP-01 challenges (creates .well-known/acme-challenge/)
        #[arg(long)]
        webroot: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let log_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .from_env_lossy();

    match cli.log_format {
        LogFormat::Text => {
            tracing_subscriber::fmt()
                .with_env_filter(log_filter)
                .init();
        }
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(log_filter)
                .init();
        }
    }

    if let Err(e) = run(cli).await {
        error!("Error: {:#}", e);
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    let default_config_dir = ProjectDirs::from("io", "vouch", "vouch")
        .map(|project_dirs| project_dirs.config_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".").join(".vouch"));
    let config_dir = cli.config_dir.unwrap_or(default_config_dir);
    match &cli.command {
        Commands::Certonly {
            domain,
            email,
            webroot,
            out_dir: _out_dir,
            dns_plugin: _dns_plugin,
            dns_propagation_seconds,
            preferred_challenge,
        } => {
            info!("🚀 Starting vouch for domain: {}", domain);
            
            let env_name = if cli.server.is_some() { "CUSTOM" } else if cli.production { "PRODUCTION" } else { "STAGING" };
            info!("📦 Registering account with Let's Encrypt ({env_name})...");
            let client = AcmeClient::new(email, config_dir, cli.production, cli.server, cli.root_cert).await?;
            info!("✅ Account created/loaded!");
            
            info!("📝 Creating order for {}...", domain);
            let mut order = client.new_order(domain).await?;
            info!("✅ Order pending. State: {:?}", order.state().status);
            
            let mut webroot_auth = webroot.as_ref().map(|path| WebrootAuthenticator::new(path.clone()));
            let authenticator_ref = webroot_auth.as_mut().map(|w| w as &mut dyn vouch::interfaces::Authenticator);

            if let Err(e) = client.verify_and_finalize(&mut order, domain, authenticator_ref, None, preferred_challenge, *dns_propagation_seconds).await {
                error!("❌ Finalization failed: {:?}", e);
                std::process::exit(2);
            }
            info!("🏁 vouch run complete");
        },
        Commands::Renew {
            days,
            authenticator,
            dns_plugin,
            dns_propagation_seconds,
            installer,
            webroot,
        } => {
            info!("🔄 Starting renewal check...");
            let mut renewed_count = 0;
            let mut checked_count = 0;

            if config_dir.exists() {
                for entry in std::fs::read_dir(&config_dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_dir() {
                        let cert_path = path.join("domain.crt");
                        if cert_path.exists() {
                            let domain_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                            checked_count += 1;
                            
                            let cert_bytes = std::fs::read(&cert_path)?;
                            match check_expiration_days(&cert_bytes, *days) {
                                Ok((needs_renewal, days_left)) => {
                                    if needs_renewal {
                                        info!("⚠️ Certificate for {} expires in {} days (threshold: {}). Triggering renewal...", domain_name, days_left, days);
                                    
                                    let env_name = if cli.server.is_some() { "CUSTOM" } else if cli.production { "PRODUCTION" } else { "STAGING" };
                                    info!("📦 Registering account with Let's Encrypt ({env_name})...");
                                    
                                    // Instantiate the client with an empty email (uses existing account)
                                    let client = AcmeClient::new("", config_dir.clone(), cli.production, cli.server.clone(), cli.root_cert.clone()).await?;
                                    info!("📝 Creating order for {}...", domain_name);
                                    let mut order = client.new_order(&domain_name).await?;

                                    // Resolve Plugins using concrete types to avoid lifetime issues with Box<dyn>
                                    let mut webroot_auth = webroot.as_ref().map(|w| vouch::plugins::webroot::WebrootAuthenticator::new(w.clone()));
                                    let mut ipc_auth = if let Some(p) = authenticator {
                                        let p_str: &std::path::Path = p;
                                        Some(vouch::interfaces::IpcPlugin::new(p_str.to_str().expect("invalid authenticator path")))
                                    } else if let Some(p) = dns_plugin {
                                        let p_str: &std::path::Path = p;
                                        Some(vouch::interfaces::IpcPlugin::new(p_str.to_str().expect("invalid dns plugin path")))
                                    } else {
                                        None
                                    };
                                    let mut ipc_inst = installer.as_ref().map(|p| {
                                        let p_str: &std::path::Path = p;
                                        vouch::interfaces::IpcPlugin::new(p_str.to_str().expect("invalid installer path"))
                                    });

                                    let mut auth_ref: Option<&mut dyn vouch::interfaces::Authenticator> = None;
                                    let preferred_challenge_str = if dns_plugin.is_some() { "dns-01" } else { "http-01" };

                                    if let Some(ref mut w) = webroot_auth {
                                        auth_ref = Some(w);
                                    } else if let Some(ref mut i) = ipc_auth {
                                        auth_ref = Some(i);
                                    }

                                    let inst_ref: Option<&mut dyn vouch::interfaces::Installer> = ipc_inst.as_mut().map(|i| i as &mut dyn vouch::interfaces::Installer);
                                    
                                    if let Err(e) = client.verify_and_finalize(&mut order, &domain_name, auth_ref, inst_ref, preferred_challenge_str, *dns_propagation_seconds).await {
                                        error!("❌ Failed to renew certificate for {}: {:?}", domain_name, e);
                                    } else {
                                        info!("✅ Successfully renewed certificate for {}", domain_name);
                                        renewed_count += 1;
                                    }
                                    } else {
                                        info!("⏭️ Certificate for {} is valid for {} more days. Skipping.", domain_name, days_left);
                                    }
                                },
                                Err(e) => {
                                    error!("❌ Failed to parse certificate at {:?}: {}", cert_path, e);
                                }
                            }
                        }
                    }
                }
            }
            
            info!("🏁 Renewal check complete. Checked: {}, Renewed: {}", checked_count, renewed_count);
            let exit_code = if checked_count > 0 && renewed_count == 0 { 0 } else { 0 }; 
            std::process::exit(exit_code);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ::rcgen::{CertificateParams, KeyPair};
    use ::time::{OffsetDateTime, Duration};

    #[test]
    fn test_check_expiration_days() {
        let now = OffsetDateTime::now_utc();
        
        // 1. Certificate expiring tomorrow (needs renewal under 30 days)
        let mut params1 = CertificateParams::new(vec!["test.example.com".to_string()]);
        params1.not_before = now - Duration::days(1);
        params1.not_after = now + Duration::days(1);
        let cert_tomorrow = rcgen::Certificate::from_params(params1).unwrap();
        let der_tomorrow = cert_tomorrow.serialize_der().unwrap();
        
        let (needs_renewal, days_left) = check_expiration_days(&der_tomorrow, 30).unwrap();
        assert!(needs_renewal, "Cert expiring tomorrow should need renewal under 30 day threshold");
        assert_eq!(days_left, 1);

        // 2. Certificate expiring in 60 days (does NOT need renewal under 30 days)
        let mut params2 = CertificateParams::new(vec!["test.example.com".to_string()]);
        params2.not_after = now + Duration::days(60);
        let cert_future = rcgen::Certificate::from_params(params2).unwrap();
        let der_future = cert_future.serialize_der().unwrap();
        
        let (needs_renewal, days_left) = check_expiration_days(&der_future, 30).unwrap();
        assert!(!needs_renewal, "Cert expiring in 60 days should NOT need renewal under 30 day threshold (got {})", days_left);
        // It could be 59 or 60 depending on the exact second
        assert!(days_left == 60 || days_left == 59); 
    }
}
