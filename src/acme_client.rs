use anyhow::{Context, Result};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use instant_acme::{
    Account, AccountCredentials, Identifier, LetsEncrypt, NewAccount, NewOrder, Order,
    ExternalAccountKey,
};
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use clap::ValueEnum;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Clone, Debug, Default, ValueEnum)]
pub enum KeyType {
    #[default]
    Ecdsa,
    Rsa,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum RsaKeySize {
    #[default]
    #[value(name = "2048")]
    R2048 = 2048,
    #[value(name = "3072")]
    R3072 = 3072,
    #[value(name = "4096")]
    R4096 = 4096,
}

#[derive(Clone, Debug, Default, ValueEnum)]
pub enum EllipticCurve {
    #[default]
    P256,
    P384,
}

const RETRY_ATTEMPTS: usize = 4;
const RETRY_FAILURE_PENALTY_MS: f64 = 12_000.0;
const RETRY_DELAY_CHOICES_MS: [u64; 5] = [500, 1_000, 1_500, 2_000, 4_000];
const RETRY_SUCCESS_PROB: [f64; 5] = [0.22, 0.38, 0.52, 0.64, 0.82];

pub struct AcmeClient {
    pub account: Account,
    pub config_dir: PathBuf,
}

impl AcmeClient {
    fn dynamic_retry_plan(attempts: usize) -> Vec<Duration> {
        if attempts == 0 {
            return Vec::new();
        }

        let mut dp = vec![0.0_f64; attempts + 1];
        let mut choice = vec![0usize; attempts];
        dp[attempts] = RETRY_FAILURE_PENALTY_MS;

        for attempt in (0..attempts).rev() {
            let mut best_cost = f64::INFINITY;
            let mut best_index = 0usize;

            for (index, delay_ms) in RETRY_DELAY_CHOICES_MS.iter().enumerate() {
                let p_success = RETRY_SUCCESS_PROB[index];
                let expected_cost = (*delay_ms as f64) + (1.0_f64 - p_success) * dp[attempt + 1];

                if expected_cost < best_cost {
                    best_cost = expected_cost;
                    best_index = index;
                }
            }

            dp[attempt] = best_cost;
            choice[attempt] = best_index;
        }

        choice
            .into_iter()
            .map(|index| Duration::from_millis(RETRY_DELAY_CHOICES_MS[index]))
            .collect()
    }

    /// Initialize a new ACME client and register an account with the staging API.
    pub async fn new(
        email: &str,
        config_dir: PathBuf,
        production: bool,
        custom_server: Option<String>,
        root_cert: Option<PathBuf>,
        eab_kid: Option<String>,
        eab_hmac_key: Option<String>,
    ) -> Result<Self> {
        fs::create_dir_all(&config_dir).context("Failed to create config dir")?;
        let creds_path = config_dir.join("account_creds.json");
        let lock_path = config_dir.join("account_creds.json.lock");
        use fs3::FileExt;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let lock_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .context("Failed to open lock file")?;
        lock_file
            .lock_exclusive()
            .context("Failed to lock account creds")?;
        let account = if creds_path.exists() {
            info!("🔄 Loading existing ACME account credentials...");
            let creds_json = fs::read_to_string(&creds_path)?;
            let creds: AccountCredentials = serde_json::from_str(&creds_json)?;
            let builder = match root_cert {
                Some(path) => instant_acme::Account::builder_with_root(path)
                    .context("Failed to init HTTP client with custom root")?,
                None => instant_acme::Account::builder().context("Failed to init HTTP client")?,
            };
            builder
                .from_credentials(creds)
                .await?
        } else {
            info!("🆕 Generating new ACME account instance...");
            let contact = if email.is_empty() {
                vec![]
            } else {
                vec![format!("mailto:{}", email)]
            };
            let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();
            let url = if let Some(s) = custom_server {
                s
            } else if production {
                LetsEncrypt::Production.url().to_string()
            } else {
                LetsEncrypt::Staging.url().to_string()
            };
            let builder = match root_cert {
                Some(path) => instant_acme::Account::builder_with_root(path)
                    .context("Failed to init HTTP client with custom root")?,
                None => instant_acme::Account::builder().context("Failed to init HTTP client")?,
            };
            let eab = match (eab_kid, eab_hmac_key) {
                (Some(kid), Some(hmac)) => {
                    let key_bytes = BASE64_URL_SAFE_NO_PAD.decode(hmac.trim_end_matches('='))
                        .context("Failed to decode EAB HMAC key (expected base64url)")?;
                    Some(ExternalAccountKey::new(kid, &key_bytes))
                }
                _ => None,
            };

            let (account, creds) = builder
                .create(
                    &NewAccount {
                        contact: &contact_refs,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    url,
                    eab.as_ref(),
                )
                .await
                .context("Failed to create ACME account")?;
            let creds_json = serde_json::to_string(&creds)?;
            let mut temp_file = tempfile::Builder::new()
                .prefix("acme_creds_tmp_")
                .tempfile_in(&config_dir)
                .context("Failed to create temp file")?;
            let mut perms = fs::metadata(temp_file.path())?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(temp_file.path(), perms)?;
            use std::io::Write;
            temp_file.write_all(creds_json.as_bytes())?;
            temp_file.flush()?;
            temp_file.persist(&creds_path)?;
            account
        };
        lock_file.unlock()?;
        Ok(Self {
            account,
            config_dir,
        })
    }
    /// Execute an async operation with exponential backoff.
    async fn with_backoff<T, F, Fut>(mut operation: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, anyhow::Error>>,
    {
        for delay in Self::dynamic_retry_plan(RETRY_ATTEMPTS) {
            match operation().await {
                Ok(val) => return Ok(val),
                Err(e) => {
                    warn!("Network/API error: {}. Retrying in {:?}...", e, delay);
                    tokio::time::sleep(delay).await;
                }
            }
        }
        operation()
            .await
            .context("Action failed after maximum retries")
    }
    /// Create a new order for a specific domain with exponential backoff.
    pub async fn new_order(&self, domain: &str) -> Result<Order> {
        let identifiers = [Identifier::Dns(domain.to_string())];
        Self::with_backoff(|| async {
            let order = self
                .account
                .new_order(&NewOrder::new(&identifiers))
                .await
                .map_err(|e| anyhow::anyhow!(e))?;
            Ok(order)
        })
        .await
    }
    /// Wait for the order to be ready, simulating challenge fulfillment, and finalize it.
    pub async fn verify_and_finalize(
        &self,
        order: &mut Order,
        domain: &str,
        mut installer: Option<&mut dyn crate::interfaces::Installer>,
        preferred_challenge: &str,
        dns_propagation_seconds: u64,
        key_type: KeyType,
        rsa_key_size: RsaKeySize,
        elliptic_curve: EllipticCurve,
    ) -> Result<()> {
        use instant_acme::{AuthorizationStatus, ChallengeType, OrderStatus, RetryPolicy};
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.context("Failed to get authorization")?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                _ => anyhow::bail!("Invalid authorization status: {:?}", authz.status),
            }
            let domain_ident = authz.identifier().to_string();

            let challenge_type = if preferred_challenge == "dns-01" {
                ChallengeType::Dns01
            } else {
                ChallengeType::Http01
            };

            let mut challenge = authz
                .challenge(challenge_type.clone())
                .ok_or_else(|| anyhow::anyhow!("no {:?} challenge found", challenge_type))?;

            let token = challenge.token.clone();
            let key_authorization = challenge
                .key_authorization()
                .as_str()
                .to_string();

            if let Some(ref mut auth) = authenticator {
                info!("🔌 Delegating challenge to Authenticator plugin...");
                auth.perform(&domain_ident, &token, &key_authorization)?;
                
                if challenge_type == ChallengeType::Dns01 {
                    info!("⏳ Waiting {} seconds for DNS propagation...", dns_propagation_seconds);
                    tokio::time::sleep(std::time::Duration::from_secs(dns_propagation_seconds)).await;
                }
            } else {
                info!(
                    "Stub: Authenticator would deploy challenge ({:?}) here for {}...",
                    challenge_type,
                    domain_ident
                );
            }

            info!("Setting challenge ready with backoff...");
            let mut ready = false;
            for delay in Self::dynamic_retry_plan(RETRY_ATTEMPTS) {
                match challenge.set_ready().await {
                    Ok(_) => {
                        ready = true;
                        break;
                    }
                    Err(e) => {
                        warn!(
                            "API error communicating challenge readiness: {}. Retrying in {:?}...",
                            e, delay
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
            if !ready {
                if let Some(ref mut auth) = authenticator {
                    let _ = auth.cleanup(&domain_ident, &token);
                }
                challenge
                    .set_ready()
                    .await
                    .context("Failed to set challenge ready after maximum retries")?;
            }

            if let Some(ref mut auth) = authenticator {
                let _ = auth.cleanup(&domain_ident, &token);
            }
        }
        info!("⏳ Polling Let's Encrypt for order status...");
        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .context("Failed to poll order")?;
        if status != OrderStatus::Ready {
            anyhow::bail!("Unexpected order status: {:?}", status);
        }
        info!("📜 Requesting certificate issuance (finalizing)...");
        
        let mut names = Vec::new();
        let mut identifiers = order.identifiers();
        while let Some(result) = identifiers.next().await {
            names.push(result.map_err(|e| anyhow::anyhow!("Failed to get identifier: {:?}", e))?.to_string());
        }

        let mut params = CertificateParams::new(names).context("Failed to create certificate params")?;
        params.distinguished_name = DistinguishedName::new();
        
        let key_pair = match key_type {
            KeyType::Ecdsa => {
                let curve = match elliptic_curve {
                    EllipticCurve::P256 => &rcgen::PKCS_ECDSA_P256_SHA256,
                    EllipticCurve::P384 => &rcgen::PKCS_ECDSA_P384_SHA384,
                };
                KeyPair::generate_for_alg(curve).context("Failed to generate ECDSA key")?
            }
            KeyType::Rsa => {
                KeyPair::generate_rsa(rsa_key_size as usize).context("Failed to generate RSA key")?
            }
        };

        let csr = params.serialize_request(&key_pair).context("Failed to serialize CSR")?;
        order.finalize_csr(csr.der()).await.context("Failed to finalize order with custom CSR")?;

        let private_key_pem = key_pair.serialize_pem();
        let cert_chain_pem = order
            .poll_certificate(&RetryPolicy::new())
            .await
            .context("Failed to poll certificate")?;

        let domain_dir = self.config_dir.join(domain);
        fs::create_dir_all(&domain_dir).context("Failed to create domain config dir")?;

        let key_path = domain_dir.join("domain.key");
        let crt_path = domain_dir.join("domain.crt");
        let key_old_path = domain_dir.join("domain.key.old");
        let crt_old_path = domain_dir.join("domain.crt.old");
        
        let has_old = key_path.exists() && crt_path.exists();
        if has_old {
            std::fs::copy(&key_path, &key_old_path).ok();
            std::fs::copy(&crt_path, &crt_old_path).ok();
        }

        let mut temp_key = tempfile::Builder::new()
            .prefix("key_tmp_")
            .tempfile_in(&domain_dir)
            .context("Failed to create temp key file")?;
        let mut perms = fs::metadata(temp_key.path())?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(temp_key.path(), perms)?;
        temp_key.write_all(private_key_pem.as_bytes())?;
        temp_key.flush()?;
        temp_key.persist(&key_path)?;
        let mut temp_crt = tempfile::Builder::new()
            .prefix("crt_tmp_")
            .tempfile_in(&domain_dir)
            .context("Failed to create temp crt file")?;
        let mut perms = fs::metadata(temp_crt.path())?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(temp_crt.path(), perms)?;
        temp_crt.write_all(cert_chain_pem.as_bytes())?;
        temp_crt.flush()?;
        temp_crt.persist(&crt_path)?;
        info!(
            "✅ Certificates successfully saved to {:?}",
            self.config_dir
        );

        if let Some(ref mut inst) = installer {
            info!("🔌 Delegating deployment to Installer plugin...");
            if let Err(e) = (|| -> Result<()> {
                inst.deploy_cert(
                    domain,
                    crt_path.to_str().ok_or_else(|| anyhow::anyhow!("Invalid cert path"))?,
                    key_path.to_str().ok_or_else(|| anyhow::anyhow!("Invalid key path"))?,
                )?;
                inst.save("vouch-renewal")?;
                inst.restart()?;
                Ok(())
            })() {
                error!("❌ Installer failed: {}. Rolling back to previous certificate...", e);
                if has_old {
                    std::fs::copy(&key_old_path, &key_path).ok();
                    std::fs::copy(&crt_old_path, &crt_path).ok();
                }
                return Err(e);
            }
        }

        Ok(())
    }
}
