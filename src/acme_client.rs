use anyhow::{Context, Result};
use instant_acme::{
    Account, AccountCredentials, Identifier, LetsEncrypt, NewAccount, NewOrder, Order,
};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

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
    pub async fn new(email: &str, config_dir: PathBuf) -> Result<Self> {
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
            println!("🔄 Loading existing ACME account credentials...");
            let creds_json = fs::read_to_string(&creds_path)?;
            let creds: AccountCredentials = serde_json::from_str(&creds_json)?;
            instant_acme::Account::builder()
                .context("Failed to init HTTP client")?
                .from_credentials(creds)
                .await?
        } else {
            println!("🆕 Generating new ACME account instance...");
            let contact = if email.is_empty() {
                vec![]
            } else {
                vec![format!("mailto:{}", email)]
            };
            let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();
            let (account, creds) = instant_acme::Account::builder()
                .context("Failed to init HTTP client")?
                .create(
                    &NewAccount {
                        contact: &contact_refs,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    LetsEncrypt::Staging.url().to_string(),
                    None,
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
                    println!("⚠️ Network/API error: {}. Retrying in {:?}...", e, delay);
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
    pub async fn verify_and_finalize(&self, order: &mut Order) -> Result<()> {
        use instant_acme::{AuthorizationStatus, ChallengeType, OrderStatus, RetryPolicy};
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.context("Failed to get authorization")?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                _ => anyhow::bail!("Invalid authorization status: {:?}", authz.status),
            }
            println!(
                "⚠️ Stub: Authenticator would deploy challenge here for {}...",
                authz.identifier()
            );
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| anyhow::anyhow!("no http01 challenge found"))?;
            println!("Setting challenge ready with backoff...");
            let mut ready = false;
            for delay in Self::dynamic_retry_plan(RETRY_ATTEMPTS) {
                match challenge.set_ready().await {
                    Ok(_) => {
                        ready = true;
                        break;
                    }
                    Err(e) => {
                        println!(
                            "⚠️ API error communicating challenge readiness: {}. Retrying in {:?}...",
                            e, delay
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
            if !ready {
                challenge
                    .set_ready()
                    .await
                    .context("Failed to set challenge ready after maximum retries")?;
            }
        }
        println!("⏳ Polling Let's Encrypt for order status...");
        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .context("Failed to poll order")?;
        if status != OrderStatus::Ready {
            anyhow::bail!("Unexpected order status: {:?}", status);
        }
        println!("📜 Finalizing order and generating private key...");
        let private_key_pem = order.finalize().await.context("Failed to finalize order")?;
        let cert_chain_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .context("Failed to poll certificate")?;
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let key_path = self.config_dir.join("domain.key");
        let mut temp_key = tempfile::Builder::new()
            .prefix("key_tmp_")
            .tempfile_in(&self.config_dir)
            .context("Failed to create temp key file")?;
        let mut perms = fs::metadata(temp_key.path())?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(temp_key.path(), perms)?;
        temp_key.write_all(private_key_pem.as_bytes())?;
        temp_key.flush()?;
        temp_key.persist(&key_path)?;
        let crt_path = self.config_dir.join("domain.crt");
        let mut temp_crt = tempfile::Builder::new()
            .prefix("crt_tmp_")
            .tempfile_in(&self.config_dir)
            .context("Failed to create temp crt file")?;
        let mut perms = fs::metadata(temp_crt.path())?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(temp_crt.path(), perms)?;
        temp_crt.write_all(cert_chain_pem.as_bytes())?;
        temp_crt.flush()?;
        temp_crt.persist(&crt_path)?;
        println!(
            "✅ Certificates successfully saved to {:?}",
            self.config_dir
        );
        Ok(())
    }
}
