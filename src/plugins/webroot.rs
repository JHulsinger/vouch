use crate::interfaces::Authenticator;
use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use tracing::{info, warn};

pub struct WebrootAuthenticator {
    pub webroot_path: PathBuf,
}

impl WebrootAuthenticator {
    pub fn new(webroot_path: PathBuf) -> Self {
        Self { webroot_path }
    }
}

impl Authenticator for WebrootAuthenticator {
    fn perform(&mut self, _domain: &str, token: &str, key_authorization: &str) -> Result<()> {
        let mut path = self.webroot_path.clone();
        path.push(".well-known");
        path.push("acme-challenge");
        fs::create_dir_all(&path)?;
        
        path.push(token);
        info!("📝 Writing challenge to {:?}", path);
        fs::write(&path, key_authorization)?;
        
        Ok(())
    }

    fn cleanup(&mut self, _domain: &str, token: &str) -> Result<()> {
        let mut path = self.webroot_path.clone();
        path.push(".well-known");
        path.push("acme-challenge");
        path.push(token);
        if path.exists() {
            info!("🧹 Cleaning up challenge file {:?}", path);
            if let Err(e) = fs::remove_file(&path) {
                warn!("Failed to clean up challenge file {:?}: {}", path, e);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_webroot_perform_and_cleanup() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let mut auth = WebrootAuthenticator::new(temp_dir.path().to_path_buf());

        let domain = "example.com";
        let token = "test-token-123";
        let key_auth = "test-key-auth-data-xyz";

        // 1. Test Perform
        auth.perform(domain, token, key_auth)?;

        let mut expected_path = temp_dir.path().to_path_buf();
        expected_path.push(".well-known");
        expected_path.push("acme-challenge");
        expected_path.push(token);

        assert!(expected_path.exists(), "Challenge file was not created");
        let content = fs::read_to_string(&expected_path)?;
        assert_eq!(content, key_auth, "Challenge file content mismatch");

        // 2. Test Cleanup
        auth.cleanup(domain, token)?;
        
        assert!(!expected_path.exists(), "Challenge file was not deleted during cleanup");

        // 3. Test Idempotent Cleanup (should not error if already deleted)
        assert!(auth.cleanup(domain, token).is_ok(), "Cleanup should tolerate missing files");

        Ok(())
    }
}
