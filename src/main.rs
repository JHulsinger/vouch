use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::fmt::writer::MakeWriterExt;

use vouch::acme_client::{AcmeClient, ExternalAccountBindingConfig, KeyType, RsaKeySize, EllipticCurve};
use vouch::plugins::dns_hook::DnsHookAuthenticator;
use vouch::plugins::webroot::WebrootAuthenticator;
use vouch::hooks::{run_hooks, HookContext, HookKind};
use vouch::renewal::{
    check_expiration,
    parse_renew_before_expiry,
    pick_deterministic_ari_renewal_time,
    leaf_cert_der_from_pem_or_der,
    load_renewal_configs,
};
use vouch::storage::{default_dirs_linux, write_renewal_config, RenewalParams};

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
    /// Use the ACME staging server (Certbot-compatible dry run)
    #[arg(long, global = true, default_value_t = false)]
    dry_run: bool,

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
        /// Domain(s) to obtain the certificate for (repeatable)
        #[arg(short = 'd', long = "domain", required = true, num_args = 1..)]
        domains: Vec<String>,
        /// Certbot-compatible lineage name
        #[arg(long)]
        cert_name: Option<String>,
        /// Email for Let's Encrypt registration
        #[arg(short, long)]
        email: String,
        /// Webroot path for HTTP-01 challenge fulfillment
        #[arg(short, long)]
        webroot: Option<PathBuf>,
        /// DNS plugin path (for DNS-01 challenges)
        #[arg(long)]
        dns_plugin: Option<PathBuf>,
        /// Script to run for DNS-01 auth (Certbot manual-auth-hook compatible)
        #[arg(long)]
        manual_auth_hook: Option<String>,
        /// Script to run for DNS-01 cleanup (Certbot manual-cleanup-hook compatible)
        #[arg(long)]
        manual_cleanup_hook: Option<String>,
        /// Wait time (seconds) for DNS propagation
        #[arg(long, default_value_t = 60)]
        dns_propagation_seconds: u64,
        /// Preferred challenge type (http-01 or dns-01)
        #[arg(long = "preferred-challenges", default_value = "http-01")]
        preferred_challenges: String,

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

        /// Renew only a specific lineage name (Certbot-compatible)
        #[arg(long)]
        cert_name: Option<String>,
        
        /// Authenticator plugin path (for IPC)
        #[arg(long)]
        authenticator: Option<PathBuf>,
        /// DNS plugin path (for DNS-01 challenges)
        #[arg(long)]
        dns_plugin: Option<PathBuf>,
        /// Script to run for DNS-01 auth (Certbot manual-auth-hook compatible)
        #[arg(long)]
        manual_auth_hook: Option<String>,
        /// Script to run for DNS-01 cleanup (Certbot manual-cleanup-hook compatible)
        #[arg(long)]
        manual_cleanup_hook: Option<String>,
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

    let (default_config_dir, default_work_dir, default_logs_dir) = default_dirs_linux();
    let config_dir = cli.config_dir.clone().unwrap_or(default_config_dir);
    let work_dir = cli.work_dir.clone().unwrap_or(default_work_dir);
    let logs_dir = cli.logs_dir.clone().unwrap_or(default_logs_dir);

    if let Err(e) = std::fs::create_dir_all(&config_dir) {
        eprintln!("Failed to create config dir {}: {}", config_dir.display(), e);
        std::process::exit(1);
    }
    if let Err(e) = std::fs::create_dir_all(&work_dir) {
        eprintln!("Failed to create work dir {}: {}", work_dir.display(), e);
        std::process::exit(1);
    }
    if let Err(e) = std::fs::create_dir_all(&logs_dir) {
        eprintln!("Failed to create logs dir {}: {}", logs_dir.display(), e);
        std::process::exit(1);
    }

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

fn key_type_label(key_type: &KeyType) -> &'static str {
    match key_type {
        KeyType::Ecdsa => "ecdsa",
        KeyType::Rsa => "rsa",
    }
}

fn rsa_key_size_label(size: &RsaKeySize) -> &'static str {
    match size {
        RsaKeySize::R2048 => "2048",
        RsaKeySize::R3072 => "3072",
        RsaKeySize::R4096 => "4096",
    }
}

fn elliptic_curve_label(curve: &EllipticCurve) -> &'static str {
    match curve {
        EllipticCurve::P256 => "p256",
        EllipticCurve::P384 => "p384",
    }
}

fn build_renew_hook_context(
    domains: &[String],
    lineage: &vouch::storage::LineagePaths,
) -> HookContext {
    HookContext::new()
        .with_var("RENEWED_DOMAINS", domains.join(" "))
        .with_var("RENEWED_LINEAGE", lineage.live_dir.to_string_lossy().to_string())
        .with_var("RENEWED_CERT", lineage.cert.to_string_lossy().to_string())
        .with_var("RENEWED_PRIVKEY", lineage.privkey.to_string_lossy().to_string())
        .with_var("RENEWED_CHAIN", lineage.chain.to_string_lossy().to_string())
        .with_var("RENEWED_FULLCHAIN", lineage.fullchain.to_string_lossy().to_string())
}

fn normalize_preferred_challenge(preferred: &str) -> String {
    let p = preferred.trim().to_ascii_lowercase();
    if p == "dns-01" || p == "http-01" {
        p
    } else {
        "http-01".to_string()
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
            domains,
            cert_name,
            email,
            webroot,
            dns_plugin,
            manual_auth_hook,
            manual_cleanup_hook,
            dns_propagation_seconds,
            preferred_challenges,
            pre_hook,
            post_hook,
            deploy_hook,
            key_type,
            rsa_key_size,
            elliptic_curve,
        } => {
            let mut unique_domains = Vec::new();
            for d in domains.iter() {
                if !unique_domains.contains(d) {
                    unique_domains.push(d.clone());
                }
            }
            let domains = unique_domains;
            let primary_domain = domains
                .first()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("At least one domain is required"))?;
            let lineage_name = cert_name.clone().unwrap_or_else(|| primary_domain.clone());

            let hook_ctx = HookContext::new().with_var("VOUCH_DOMAIN", &primary_domain);
            run_hooks(HookKind::Pre, pre_hook, &hook_ctx)?;

            let result = async {
                let mut preferred = normalize_preferred_challenge(preferred_challenges);
                if manual_auth_hook.is_some() || dns_plugin.is_some() {
                    if preferred == "http-01" {
                        preferred = "dns-01".to_string();
                    }
                }
                if domains.iter().any(|d| d.starts_with("*.")) && preferred != "dns-01" {
                    anyhow::bail!("Wildcard domains require DNS-01 challenge. Use --preferred-challenges dns-01");
                }

                info!("Requesting certificate for: {}", domains.join(", "));

                let production = if cli.dry_run { false } else { cli.production };
                let server_override = if cli.dry_run {
                    cli.server
                        .clone()
                        .or(Some(instant_acme::LetsEncrypt::Staging.url().to_string()))
                } else {
                    cli.server.clone()
                };
                let client = AcmeClient::new(
                    email,
                    config_dir.clone(),
                    production,
                    server_override.clone(),
                    cli.root_cert.clone(),
                    eab_config.clone(),
                )
                .await?;

                let mut order = client.new_order_for_domains(&domains).await?;

                let mut webroot_auth = webroot.as_ref().map(|path| WebrootAuthenticator::new(path.clone()));
                let mut dns_hook_auth = manual_auth_hook
                    .as_ref()
                    .map(|cmd| DnsHookAuthenticator::new(cmd.clone(), manual_cleanup_hook.clone()));
                let mut dns_auth = dns_plugin
                    .as_ref()
                    .map(|p| vouch::interfaces::IpcPlugin::new(p.to_str().expect("invalid dns plugin path")));
                let has_webroot = webroot_auth.is_some();
                let has_dns_hook = dns_hook_auth.is_some();
                let has_dns_plugin = dns_auth.is_some();

                let auth_ref: Option<&mut dyn vouch::interfaces::Authenticator> = if let Some(ref mut w) = webroot_auth {
                    Some(w)
                } else if let Some(ref mut d) = dns_hook_auth {
                    Some(d)
                } else if let Some(ref mut d) = dns_auth {
                    Some(d)
                } else {
                    None
                };

                if preferred == "dns-01" && !(has_dns_hook || has_dns_plugin) {
                    anyhow::bail!("DNS-01 requires a DNS hook or DNS plugin");
                }
                if preferred == "http-01" && !has_webroot {
                    anyhow::bail!("HTTP-01 requires --webroot");
                }

                let lineage = client
                    .verify_and_finalize(
                        &mut order,
                        &lineage_name,
                        auth_ref,
                        None,
                        &preferred,
                        *dns_propagation_seconds,
                        key_type.clone(),
                        *rsa_key_size,
                        elliptic_curve.clone(),
                    )
                    .await?;

                let deploy_ctx = build_renew_hook_context(&domains, &lineage)
                    .with_var("VOUCH_DOMAIN", &primary_domain);
                run_hooks(HookKind::Deploy, deploy_hook, &deploy_ctx)?;

                let mut params = RenewalParams::default();
                params.domains = domains.clone();
                params.preferred_challenges = Some(preferred.clone());
                if webroot.is_some() {
                    params.authenticator = Some("webroot".to_string());
                    params.webroot_path = webroot.clone();
                    if let Some(path) = webroot.clone() {
                        params.webroot_map = Some(
                            domains
                                .iter()
                                .map(|d| (d.clone(), path.clone()))
                                .collect(),
                        );
                    }
                } else if manual_auth_hook.is_some() {
                    params.authenticator = Some("manual".to_string());
                    params.manual_auth_hook = manual_auth_hook.clone();
                    params.manual_cleanup_hook = manual_cleanup_hook.clone();
                } else if dns_plugin.is_some() {
                    params.authenticator = Some("dns".to_string());
                }

                if let Some(s) = server_override.clone() {
                    params.server = Some(s);
                } else if !production {
                    params.server = Some(instant_acme::LetsEncrypt::Staging.url().to_string());
                }

                params.key_type = Some(key_type_label(key_type).to_string());
                params.rsa_key_size = Some(rsa_key_size_label(rsa_key_size).to_string());
                params.elliptic_curve = Some(elliptic_curve_label(elliptic_curve).to_string());

                write_renewal_config(&config_dir, &lineage_name, &params)?;

                Ok(())
            }
            .await;

            run_hooks(HookKind::Post, post_hook, &hook_ctx)?;
            result
        }

        Commands::Renew {
            renew_before_expiry,
            cert_name,
            authenticator,
            dns_plugin,
            manual_auth_hook,
            manual_cleanup_hook,
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

            info!("Starting renewal scan (threshold: {:#?})...", threshold);
            run_hooks(HookKind::Pre, pre_hook, &HookContext::new())?;

            let mut checked = 0;
            let mut renewed = 0;

            let configs = load_renewal_configs(&config_dir)?;
            for cfg in configs {
                if let Some(target) = cert_name {
                    if cfg.name != target.as_str() {
                        continue;
                    }
                }

                let domains = if !cfg.domains.is_empty() {
                    cfg.domains.clone()
                } else {
                    error!("No domains found for lineage {}", cfg.name);
                    continue;
                };

                let primary_domain = domains[0].clone();
                let cert_path = cfg
                    .fullchain
                    .clone()
                    .or_else(|| cfg.cert.clone())
                    .unwrap_or_else(|| config_dir.join("live").join(&cfg.name).join("fullchain.pem"));

                if !cert_path.exists() {
                    error!("Missing cert for lineage {} at {}", cfg.name, cert_path.display());
                    continue;
                }

                checked += 1;
                let cert_bytes = std::fs::read(&cert_path)?;
                let (mut should_renew, days_left) = check_expiration(&cert_bytes, threshold)?;

                let mut replaces = None;
                if let Ok(der) = leaf_cert_der_from_pem_or_der(&cert_bytes) {
                    let der = rustls_pki_types::CertificateDer::from(der);
                    if let Ok(cert_id) = instant_acme::CertificateIdentifier::try_from(&der) {
                        let cert_id = cert_id.into_owned();
                        replaces = Some(cert_id.clone());

                        let production = if cli.dry_run { false } else { cli.production };
                        let server_override = if cli.dry_run {
                            cli.server
                                .clone()
                                .or(Some(instant_acme::LetsEncrypt::Staging.url().to_string()))
                        } else {
                            cli.server.clone().or_else(|| cfg.server.clone())
                        };
                        let account_client = AcmeClient::new(
                            "",
                            config_dir.clone(),
                            production,
                            server_override,
                            cli.root_cert.clone(),
                            eab_config.clone(),
                        )
                        .await?;
                        if let Ok((info, _)) = account_client.account.renewal_info(&cert_id).await {
                            let now = time::OffsetDateTime::now_utc();
                            let selected =
                                pick_deterministic_ari_renewal_time(&info.suggested_window, &cfg.name);
                            if now >= selected {
                                info!(
                                    "ARI suggests renewal for {} (now={}, selected={})",
                                    cfg.name, now, selected
                                );
                                should_renew = true;
                            }
                        }
                    }
                }

                if !should_renew {
                    info!("Skipping {} ({} days remaining)", cfg.name, days_left);
                    continue;
                }

                info!("Renewing {} ({} days remaining)", cfg.name, days_left);

                let production = if cli.dry_run { false } else { cli.production };
                let server_override = if cli.dry_run {
                    cli.server
                        .clone()
                        .or(Some(instant_acme::LetsEncrypt::Staging.url().to_string()))
                } else {
                    cli.server.clone().or_else(|| cfg.server.clone())
                };
                let client = AcmeClient::new(
                    "",
                    config_dir.clone(),
                    production,
                    server_override,
                    cli.root_cert.clone(),
                    eab_config.clone(),
                )
                .await?;

                let mut order = if let Some(rep) = replaces {
                    let identifiers: Vec<instant_acme::Identifier> =
                        domains.iter().map(|d| instant_acme::Identifier::Dns(d.clone())).collect();
                    client
                        .account
                        .new_order(&instant_acme::NewOrder::new(&identifiers).replaces(rep))
                        .await?
                } else {
                    client.new_order_for_domains(&domains).await?
                };

                let webroot_path = if let Some(path) = webroot.clone() {
                    Some(path)
                } else if let Some(path) = cfg.webroot_path.clone() {
                    Some(path)
                } else if !cfg.webroot_map.is_empty() {
                    cfg.webroot_map
                        .iter()
                        .find(|(d, _)| d == &primary_domain)
                        .map(|(_, p)| p.clone())
                        .or_else(|| cfg.webroot_map.first().map(|(_, p)| p.clone()))
                } else {
                    None
                };

                let manual_auth = manual_auth_hook.clone().or_else(|| cfg.manual_auth_hook.clone());
                let manual_cleanup =
                    manual_cleanup_hook.clone().or_else(|| cfg.manual_cleanup_hook.clone());

                let mut webroot_auth = webroot_path
                    .as_ref()
                    .map(|w| WebrootAuthenticator::new(w.clone()));
                let mut dns_hook_auth = manual_auth
                    .as_ref()
                    .map(|cmd| DnsHookAuthenticator::new(cmd.clone(), manual_cleanup.clone()));
                let mut dns_auth = dns_plugin
                    .as_ref()
                    .map(|p| vouch::interfaces::IpcPlugin::new(p.to_str().expect("invalid dns plugin path")));
                let mut ipc_auth = authenticator
                    .as_ref()
                    .map(|p| vouch::interfaces::IpcPlugin::new(p.to_str().expect("invalid authenticator path")));
                let has_webroot = webroot_auth.is_some();
                let has_dns_hook = dns_hook_auth.is_some();
                let has_dns_plugin = dns_auth.is_some();

                let auth_ref: Option<&mut dyn vouch::interfaces::Authenticator> = if let Some(ref mut w) = webroot_auth {
                    Some(w)
                } else if let Some(ref mut d) = dns_hook_auth {
                    Some(d)
                } else if let Some(ref mut d) = dns_auth {
                    Some(d)
                } else if let Some(ref mut i) = ipc_auth {
                    Some(i)
                } else {
                    None
                };

                let mut installer_plugin = installer
                    .as_ref()
                    .map(|p| vouch::interfaces::IpcPlugin::new(p.to_str().expect("invalid installer path")));
                let inst_ref: Option<&mut dyn vouch::interfaces::Installer> =
                    installer_plugin.as_mut().map(|i| i as &mut dyn vouch::interfaces::Installer);

                let mut pref_chal = cfg
                    .preferred_challenges
                    .clone()
                    .unwrap_or_else(|| "http-01".to_string());
                if manual_auth.is_some() || dns_plugin.is_some() {
                    pref_chal = "dns-01".to_string();
                }
                if domains.iter().any(|d| d.starts_with("*.")) {
                    pref_chal = "dns-01".to_string();
                }

                if pref_chal == "dns-01" && !(has_dns_hook || has_dns_plugin) {
                    error!("DNS-01 requires a DNS hook or DNS plugin for {}", cfg.name);
                    continue;
                }
                if pref_chal == "http-01" && !has_webroot {
                    error!("HTTP-01 requires webroot for {}", cfg.name);
                    continue;
                }

                match client
                    .verify_and_finalize(
                        &mut order,
                        &cfg.name,
                        auth_ref,
                        inst_ref,
                        &pref_chal,
                        *dns_propagation_seconds,
                        key_type.clone(),
                        *rsa_key_size,
                        elliptic_curve.clone(),
                    )
                    .await
                {
                    Ok(lineage) => {
                        renewed += 1;
                        let deploy_ctx =
                            build_renew_hook_context(&domains, &lineage).with_var("VOUCH_DOMAIN", &primary_domain);
                        run_hooks(HookKind::Deploy, &deploy_hooks, &deploy_ctx)?;
                    }
                    Err(e) => {
                        error!("Failed to renew {}: {}", cfg.name, e);
                    }
                }
            }

            run_hooks(HookKind::Post, post_hook, &HookContext::new())?;
            info!("Renewal check complete. Checked: {}, Renewed: {}", checked, renewed);
            Ok(())
        }

        Commands::Certificates => {
            let configs = load_renewal_configs(&config_dir)?;
            for cfg in configs {
                let cert_path = cfg
                    .fullchain
                    .clone()
                    .or_else(|| cfg.cert.clone())
                    .unwrap_or_else(|| config_dir.join("live").join(&cfg.name).join("fullchain.pem"));
                if cert_path.exists() {
                    let cert_bytes = std::fs::read(&cert_path)?;
                    let (_, days_left) =
                        check_expiration(&cert_bytes, std::time::Duration::from_secs(0))?;
                    println!(
                        "- {} ({} days remaining) at {}",
                        cfg.name,
                        days_left,
                        cert_path.display()
                    );
                }
            }
            Ok(())
        }
    }
}
