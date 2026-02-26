use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use directories::ProjectDirs;
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::fmt::writer::MakeWriterExt;


use vouch::acme_client::{AcmeClient, ExternalAccountBindingConfig, KeyType, RsaKeySize, EllipticCurve};
use vouch::plugins::webroot::WebrootAuthenticator;
use vouch::hooks::{run_hooks, HookContext, HookKind};
use vouch::renewal::{check_expiration, parse_renew_before_expiry, pick_deterministic_ari_renewal_time, leaf_cert_der_from_pem_or_der};

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

    /// External Account Binding key identifier (KID) for ACME providers that require EAB
    #[arg(long, global = true, env = "VOUCH_EAB_KID")]
    eab_kid: Option<String>,

    /// External Account Binding HMAC key (supports `hex:`, `base64:`, `base64url:` prefixes; otherwise auto-detects)
    #[arg(long, global = true, env = "VOUCH_EAB_HMAC_KEY")]
    eab_hmac_key: Option<String>,

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
        /// DNS plugin path (for DNS-01 challenges)
        #[arg(long)]
        dns_plugin: Option<PathBuf>,
        /// Wait time (seconds) for DNS propagation
        #[arg(long, default_value_t = 60)]
        dns_propagation_seconds: u64,
        /// Preferred challenge type (http-01 or dns-01)
        #[arg(long, default_value = "http-01")]
        preferred_challenge: String,

        /// Command(s) to run before attempting issuance (repeatable)
        #[arg(long)]
        pre_hook: Vec<String>,
        /// Command(s) to run after attempting issuance (repeatable)
        #[arg(long)]
        post_hook: Vec<String>,
        /// Command(s) to run after successful issuance (repeatable)
        #[arg(long)]
        deploy_hook: Vec<String>,

        /// Key type (rsa or ecdsa)
        #[arg(long, value_enum, default_value_t = KeyType::Ecdsa)]
        key_type: KeyType,
        /// RSA key size (2048, 3072, 4096)
        #[arg(long, value_enum, default_value_t = RsaKeySize::R2048)]
        rsa_key_size: RsaKeySize,
        /// Elliptic curve (p256, p384)
        #[arg(long, value_enum, default_value_t = EllipticCurve::P256)]
        elliptic_curve: EllipticCurve,
    },
    
    /// Renew all certificates that are approaching expiration
    Renew {
        /// Number of days before expiration (or Certbot-style duration like '30d', '12h') to consider a certificate due for renewal
        #[arg(long, default_value = "30d")]
        renew_before_expiry: String,
        
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
        /// Webroot path for HTTP-01 challenges
        #[arg(long)]
        webroot: Option<PathBuf>,

        /// Command(s) to run before attempting renewal (repeatable)
        #[arg(long)]
        pre_hook: Vec<String>,
        /// Command(s) to run after attempting renewal (repeatable)
        #[arg(long)]
        post_hook: Vec<String>,
        /// Command(s) to run after each successful renewal (repeatable)
        #[arg(long)]
        deploy_hook: Vec<String>,
        /// Alias for deploy_hook (Certbot compatibility)
        #[arg(long)]
        renew_hook: Option<String>,

        /// Key type (rsa or ecdsa)
        #[arg(long, value_enum, default_value_t = KeyType::Ecdsa)]
        key_type: KeyType,
        /// RSA key size (2048, 3072, 4096)
        #[arg(long, value_enum, default_value_t = RsaKeySize::R2048)]
        rsa_key_size: RsaKeySize,
        /// Elliptic curve (p256, p384)
        #[arg(long, value_enum, default_value_t = EllipticCurve::P256)]
        elliptic_curve: EllipticCurve,
    },

    /// List managed certificates and their statuses
    Certificates,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let default_config_dir = ProjectDirs::from("io", "vouch", "vouch")
        .map(|project_dirs| project_dirs.config_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".").join(".vouch"));
    
    let config_dir = cli.config_dir.clone().unwrap_or(default_config_dir.clone());
    let work_dir = cli.work_dir.clone().unwrap_or_else(|| config_dir.join("work"));
    let logs_dir = cli.logs_dir.clone().unwrap_or_else(|| config_dir.join("logs"));

    std::fs::create_dir_all(&config_dir).ok();
    std::fs::create_dir_all(&work_dir).ok();
    std::fs::create_dir_all(&logs_dir).ok();

    let file_appender = tracing_appender::rolling::daily(&logs_dir, "vouch.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let log_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .from_env_lossy();

    match cli.log_format {
        LogFormat::Text => {
            tracing_subscriber::fmt()
                .with_env_filter(log_filter)
                .with_writer(std::io::stdout.and(non_blocking))
                .init();
        }
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(log_filter)
                .with_writer(std::io::stdout.and(non_blocking))
                .init();
        }
    }

    if let Err(e) = run(cli, config_dir, work_dir).await {
        error!("Fatal Error: {:#}", e);
        std::process::exit(1);
    }
}

async fn run(cli: Cli, config_dir: PathBuf, _work_dir: PathBuf) -> Result<()> {
    let eab_config = match (cli.eab_kid.clone(), cli.eab_hmac_key.clone()) {
        (None, None) => None,
        (Some(kid), Some(key)) => Some(ExternalAccountBindingConfig::new(kid, &key)?),
        _ => anyhow::bail!("Both --eab-kid and --eab-hmac-key are required if either is provided"),
    };

    match &cli.command {
        Commands::Certonly {
            domain,
            email,
            webroot,
            dns_plugin,
            dns_propagation_seconds,
            preferred_challenge,
            pre_hook,
            post_hook,
            deploy_hook,
            key_type,
            rsa_key_size,
            elliptic_curve,
        } => {
            let hook_ctx = HookContext::new().with_var("VOUCH_DOMAIN", domain);
            run_hooks(HookKind::Pre, pre_hook, &hook_ctx)?;

            let result = async {
                if domain.starts_with("*.") && preferred_challenge != "dns-01" {
                    anyhow::bail!("Wildcard domains require DNS-01 challenge. Use --preferred-challenge dns-01");
                }

                info!("🚀 Requesting certificate for: {}", domain);
                let client = AcmeClient::new(
                    email,
                    config_dir.clone(),
                    cli.production,
                    cli.server.clone(),
                    cli.root_cert.clone(),
                    eab_config.clone(),
                ).await?;

                let mut order = client.new_order(domain).await?;

                let mut webroot_auth = webroot.as_ref().map(|path| WebrootAuthenticator::new(path.clone()));
                let mut dns_auth = dns_plugin.as_ref().map(|p| vouch::interfaces::IpcPlugin::new(p.to_str().expect("invalid dns plugin path")));

                let auth_ref: Option<&mut dyn vouch::interfaces::Authenticator> = if let Some(ref mut w) = webroot_auth {
                    Some(w)
                } else if let Some(ref mut d) = dns_auth {
                    Some(d)
                } else {
                    None
                };

                client.verify_and_finalize(
                    &mut order,
                    domain,
                    auth_ref,
                    None,
                    preferred_challenge,
                    *dns_propagation_seconds,
                    key_type.clone(),
                    *rsa_key_size,
                    elliptic_curve.clone(),
                ).await?;

                run_hooks(HookKind::Deploy, deploy_hook, &hook_ctx)?;
                Ok(())
            }.await;

            run_hooks(HookKind::Post, post_hook, &hook_ctx)?;
            result
        }

        Commands::Renew {
            renew_before_expiry,
            authenticator,
            dns_plugin,
            dns_propagation_seconds,
            installer,
            webroot,
            pre_hook,
            post_hook,
            deploy_hook,
            renew_hook,
            key_type,
            rsa_key_size,
            elliptic_curve,
        } => {
            let threshold = parse_renew_before_expiry(renew_before_expiry)?;
            let mut deploy_hooks = deploy_hook.clone();
            if let Some(rh) = renew_hook {
                deploy_hooks.push(rh.clone());
            }

            info!("🔄 Starting renewal scan (threshold: {:#?})...", threshold);
            
            run_hooks(HookKind::Pre, pre_hook, &HookContext::new())?;

            let mut checked = 0;
            let mut renewed = 0;

            if config_dir.exists() {
                for entry in std::fs::read_dir(&config_dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_dir() {
                        let cert_path = path.join("domain.crt");
                        let key_path = path.join("domain.key");
                        if cert_path.exists() && key_path.exists() {
                            let domain_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                            checked += 1;
                            
                            let cert_bytes = std::fs::read(&cert_path)?;
                            let (mut should_renew, days_left) = check_expiration(&cert_bytes, threshold)?;
                            
                            let mut replaces = None;
                            if let Ok(der) = leaf_cert_der_from_pem_or_der(&cert_bytes) {
                                let der = rustls_pki_types::CertificateDer::from(der);
                                if let Ok(cert_id) = instant_acme::CertificateIdentifier::try_from(&der) {
                                    let cert_id = cert_id.into_owned();
                                    replaces = Some(cert_id.clone());
                                    
                                    // ARI Check (Optional/Best Effort)
                                    let account_client = AcmeClient::new("", config_dir.clone(), cli.production, cli.server.clone(), cli.root_cert.clone(), eab_config.clone()).await?;
                                    match account_client.account.renewal_info(&cert_id).await {
                                        Ok((info, _)) => {
                                            let now = time::OffsetDateTime::now_utc();
                                            let selected = pick_deterministic_ari_renewal_time(&info.suggested_window, &domain_name);
                                            if now >= selected {
                                                info!("📅 ARI suggests renewal for {} (now={}, selected={})", domain_name, now, selected);
                                                should_renew = true;
                                            }
                                        }
                                        Err(_) => {} // Fall back to threshold check
                                    }
                                }
                            }

                            if should_renew {
                                info!("⚠️ Renewing {} (exps in {} days)...", domain_name, days_left);
                                let client = AcmeClient::new("", config_dir.clone(), cli.production, cli.server.clone(), cli.root_cert.clone(), eab_config.clone()).await?;
                                
                                let mut order = if let Some(rep) = replaces {
                                    client.account.new_order(&instant_acme::NewOrder::new(&[instant_acme::Identifier::Dns(domain_name.clone())]).replaces(rep)).await?
                                } else {
                                    client.new_order(&domain_name).await?
                                };

                                let mut webroot_auth = webroot.as_ref().map(|w| WebrootAuthenticator::new(w.clone()));
                                let mut dns_auth = dns_plugin.as_ref().map(|p| vouch::interfaces::IpcPlugin::new(p.to_str().expect("invalid dns plugin path")));
                                let mut ipc_auth = authenticator.as_ref().map(|p| vouch::interfaces::IpcPlugin::new(p.to_str().expect("invalid authenticator path")));
                                
                                let auth_ref: Option<&mut dyn vouch::interfaces::Authenticator> = if let Some(ref mut w) = webroot_auth {
                                    Some(w)
                                } else if let Some(ref mut d) = dns_auth {
                                    Some(d)
                                } else if let Some(ref mut i) = ipc_auth {
                                    Some(i)
                                } else {
                                    None
                                };

                                let mut installer_plugin = installer.as_ref().map(|p| vouch::interfaces::IpcPlugin::new(p.to_str().expect("invalid installer path")));
                                let inst_ref: Option<&mut dyn vouch::interfaces::Installer> = installer_plugin.as_mut().map(|i| i as &mut dyn vouch::interfaces::Installer);

                                let pref_chal = if dns_plugin.is_some() { "dns-01" } else { "http-01" };
                                
                                if let Err(e) = client.verify_and_finalize(
                                    &mut order,
                                    &domain_name,
                                    auth_ref,
                                    inst_ref,
                                    pref_chal,
                                    *dns_propagation_seconds,
                                    key_type.clone(),
                                    *rsa_key_size,
                                    elliptic_curve.clone()
                                ).await {
                                    error!("❌ Failed to renew {}: {}", domain_name, e);
                                } else {
                                    renewed += 1;
                                    let hctx = HookContext::new()
                                        .with_var("VOUCH_DOMAIN", &domain_name)
                                        .with_var("VOUCH_CERT_PATH", cert_path.to_str().unwrap_or(""))
                                        .with_var("VOUCH_KEY_PATH", key_path.to_str().unwrap_or(""))
                                        // Certbot compatibility
                                        .with_var("RENEWED_DOMAINS", &domain_name)
                                        .with_var("RENEWED_LINEAGE", path.to_str().unwrap_or(""))
                                        .with_var("RENEWED_CERT", cert_path.to_str().unwrap_or(""))
                                        .with_var("RENEWED_PRIVKEY", key_path.to_str().unwrap_or(""));
                                    run_hooks(HookKind::Deploy, &deploy_hooks, &hctx)?;
                                }
                            } else {
                                info!("⏭️ Skipping {} ({} days remaining)", domain_name, days_left);
                            }
                        }
                    }
                }
            }

            run_hooks(HookKind::Post, post_hook, &HookContext::new())?;
            info!("🏁 Renewal check complete. Checked: {}, Renewed: {}", checked, renewed);
            Ok(())
        }

        Commands::Certificates => {
            if config_dir.exists() {
                for entry in std::fs::read_dir(&config_dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.is_dir() {
                        let cert_path = path.join("domain.crt");
                        if cert_path.exists() {
                            let domain = path.file_name().unwrap_or_default().to_string_lossy();
                            let cert_bytes = std::fs::read(&cert_path)?;
                            let (_, days_left) = check_expiration(&cert_bytes, std::time::Duration::from_secs(0))?;
                            println!("- {} ({} days remaining) at {:?}", domain, days_left, path);
                        }
                    }
                }
            }
            Ok(())
        }
    }
}
