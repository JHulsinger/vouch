use anyhow::{Context, Result};
use base64::engine::general_purpose::{STANDARD as B64_STANDARD, URL_SAFE_NO_PAD as B64_URL_SAFE};
use base64::Engine as _;
use instant_acme::{
    Account, AccountCredentials, ExternalAccountKey, Identifier, LetsEncrypt, NewAccount, NewOrder,
    Order,
};
use clap::ValueEnum;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::keygen::generate_csr_der_and_private_key_pem;
use crate::storage::{write_lineage, LineagePaths, read_live_symlinks, restore_live_symlinks};

#[derive(Clone, Debug, Default, ValueEnum, PartialEq, Eq)]
pub enum KeyType {
    #[default]
    Ecdsa,
    Rsa,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum, PartialEq, Eq)]
pub enum RsaKeySize {
    #[default]
    #[value(name = "2048")]
    R2048 = 2048,
    #[value(name = "3072")]
    R3072 = 3072,
    #[value(name = "4096")]
    R4096 = 4096,
}

#[derive(Clone, Debug, Default, ValueEnum, PartialEq, Eq)]
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

#[derive(Clone, Debug)]
pub struct ExternalAccountBindingConfig {
    pub kid: String,
    pub hmac_key: Vec<u8>,
}

impl ExternalAccountBindingConfig {
    pub fn new(kid: String, hmac_key: &str) -> Result<Self> {
        let hmac_key = decode_eab_hmac_key(hmac_key)?;
        Ok(Self { kid, hmac_key })
    }
}

fn decode_eab_hmac_key(input: &str) -> Result<Vec<u8>> {
    let input = input.trim();
    if input.is_empty() {
        anyhow::bail!("EAB HMAC key is empty");
    }

    let (prefix, value) = input
        .split_once(':')
        .map(|(p, v)| (Some(p.trim().to_ascii_lowercase()), v.trim()))
        .unwrap_or((None, input));

    let decode_hex = |s: &str| -> Result<Vec<u8>> {
        Ok(hex::decode(s.trim()).context("Failed to decode EAB key as hex")?)
    };
    let decode_b64_std = |s: &str| -> Result<Vec<u8>> {
        Ok(B64_STANDARD
            .decode(s.trim())
            .context("Failed to decode EAB key as base64")?)
    };
    let decode_b64_url = |s: &str| -> Result<Vec<u8>> {
        Ok(B64_URL_SAFE
            .decode(s.trim())
            .context("Failed to decode EAB key as base64url")?)
    };

    let key = match prefix.as_deref() {
        Some("hex") => decode_hex(value)?,
        Some("base64") | Some("b64") => decode_b64_std(value)?,
        Some("base64url") | Some("b64url") => decode_b64_url(value)?,
        Some(other) => anyhow::bail!(
            "Unknown EAB key encoding prefix '{other}'. Use 'hex:', 'base64:' or 'base64url:'"
        ),
        None => decode_b64_url(value)
            .or_else(|_| decode_b64_std(value))
            .or_else(|_| decode_hex(value))
            .context("Failed to decode EAB key (tried base64url, base64, hex)")?,
    };

    if key.is_empty() {
        anyhow::bail!("Decoded EAB HMAC key is empty");
    }
    Ok(key)
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

    pub async fn new(
        email: &str,
        config_dir: PathBuf,
        production: bool,
        custom_server: Option<String>,
        root_cert: Option<PathBuf>,
        external_account_binding: Option<ExternalAccountBindingConfig>,
    ) -> Result<Self> {
        fs::create_dir_all(&config_dir).context("Failed to create config dir")?;
        let accounts_dir = config_dir.join("accounts").join("vouch");
        fs::create_dir_all(&accounts_dir).context("Failed to create accounts dir")?;

        let legacy_creds = config_dir.join("account_creds.json");
        let legacy_lock = config_dir.join("account_creds.json.lock");
        let new_creds = accounts_dir.join("account_creds.json");
        let new_lock = accounts_dir.join("account_creds.json.lock");

        let (creds_path, lock_path) = if legacy_creds.exists() && !new_creds.exists() {
            (legacy_creds, legacy_lock)
        } else {
            (new_creds, new_lock)
        };
        use fs3::FileExt;
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
                Some(path) => Account::builder_with_root(path)
                    .context("Failed to init HTTP client with custom root")?,
                None => Account::builder().context("Failed to init HTTP client")?,
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
                Some(path) => Account::builder_with_root(path)
                    .context("Failed to init HTTP client with custom root")?,
                None => Account::builder().context("Failed to init HTTP client")?,
            };

            let eak = external_account_binding.as_ref().map(|cfg| {
                ExternalAccountKey::new(cfg.kid.clone(), cfg.hmac_key.as_slice())
            });
            if let Some(cfg) = external_account_binding.as_ref() {
                info!(
                    "🔗 Using External Account Binding (kid={}, hmac_key_len={})",
                    cfg.kid,
                    cfg.hmac_key.len()
                );
            }

            let (account, creds) = builder
                .create(
                    &NewAccount {
                        contact: &contact_refs,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    url,
                    eak.as_ref(),
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
    /// Create a new order for one or more domains with exponential backoff.
    pub async fn new_order_for_domains(&self, domains: &[String]) -> Result<Order> {
        let identifiers: Vec<Identifier> = domains
            .iter()
            .map(|d| Identifier::Dns(d.to_string()))
            .collect();
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
    /// Create a new order for a specific domain with exponential backoff.
    pub async fn new_order(&self, domain: &str) -> Result<Order> {
        self.new_order_for_domains(&[domain.to_string()]).await
    }
    /// Wait for the order to be ready, simulating challenge fulfillment, and finalize it.
    pub async fn verify_and_finalize(
        &self,
        order: &mut Order,
        lineage_name: &str,
        mut authenticator: Option<&mut dyn crate::interfaces::Authenticator>,
        mut installer: Option<&mut dyn crate::interfaces::Installer>,
        preferred_challenge: &str,
        dns_propagation_seconds: u64,
        key_type: KeyType,
        rsa_key_size: RsaKeySize,
        elliptic_curve: EllipticCurve,
    ) -> Result<LineagePaths> {
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
            let key_auth = challenge.key_authorization();
            let key_authorization = if challenge_type == ChallengeType::Dns01 {
                key_auth.dns_value()
            } else {
                key_auth.as_str().to_string()
            };

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
                    let _ = auth.cleanup(&domain_ident, &token, &key_authorization);
                }
                challenge
                    .set_ready()
                    .await
                    .context("Failed to set challenge ready after maximum retries")?;
            }

            if let Some(ref mut auth) = authenticator {
                let _ = auth.cleanup(&domain_ident, &token, &key_authorization);
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
        let mut idents = order.identifiers();
        while let Some(result) = idents.next().await {
            names.push(result.map_err(|e| anyhow::anyhow!("Failed to get identifier: {:?}", e))?.to_string());
        }
        let primary_name = names
            .first()
            .cloned()
            .unwrap_or_else(|| lineage_name.to_string());

        let (csr_der, private_key_pem) = generate_csr_der_and_private_key_pem(
            names,
            key_type,
            rsa_key_size,
            elliptic_curve,
        )?;

        order.finalize_csr(&csr_der).await.context("Failed to finalize order with custom CSR")?;

        let cert_chain_pem = order
            .poll_certificate(&RetryPolicy::new())
            .await
            .context("Failed to poll certificate")?;

        let lineage = crate::storage::lineage_paths(&self.config_dir, lineage_name);
        let prior_links = read_live_symlinks(&lineage);
        let lineage = write_lineage(&self.config_dir, lineage_name, &cert_chain_pem, &private_key_pem)?;
        info!("Certificates successfully saved to {}", lineage.live_dir.display());

        if let Some(ref mut inst) = installer {
            info!("🔌 Delegating deployment to Installer plugin...");
            if let Err(e) = (|| -> Result<()> {
                inst.deploy_cert(
                    &primary_name,
                    lineage
                        .fullchain
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("Invalid cert path"))?,
                    lineage
                        .privkey
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("Invalid key path"))?,
                )?;
                inst.save("vouch-renewal")?;
                inst.restart()?;
                Ok(())
            })() {
                error!("❌ Installer failed: {}. Rolling back to previous certificate...", e);
                let _ = restore_live_symlinks(&lineage, &prior_links);
                return Err(e);
            }
        }

        Ok(lineage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_eab_hmac_key() {
        // Empty strings should fail
        assert!(decode_eab_hmac_key("").is_err());
        assert!(decode_eab_hmac_key("hex:").is_err());
        
        // Hex
        assert_eq!(decode_eab_hmac_key("hex:010203").unwrap(), vec![1, 2, 3]);
        assert_eq!(decode_eab_hmac_key("hex: 010203 ").unwrap(), vec![1, 2, 3]);
        
        // Base64 Standard
        assert_eq!(decode_eab_hmac_key("base64:AQID").unwrap(), vec![1, 2, 3]);
        assert_eq!(decode_eab_hmac_key("b64:AQID").unwrap(), vec![1, 2, 3]);
        
        // Base64 URL Safe
        assert_eq!(decode_eab_hmac_key("base64url:AQID").unwrap(), vec![1, 2, 3]);
        assert_eq!(decode_eab_hmac_key("b64url:AQID").unwrap(), vec![1, 2, 3]);
        // Let's test actual URL safe characters
        assert_eq!(decode_eab_hmac_key("base64url:-_8").unwrap(), vec![251, 255]);
        
        // Auto-detect fallback
        assert_eq!(decode_eab_hmac_key("AQID").unwrap(), vec![1, 2, 3]);
        
        // Invalid prefix
        assert!(decode_eab_hmac_key("invalid:AQID").is_err());
    }
}
