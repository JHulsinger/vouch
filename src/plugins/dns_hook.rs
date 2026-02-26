use crate::interfaces::Authenticator;
use anyhow::{Context, Result};
use std::process::Command;
use tracing::info;

pub struct DnsHookAuthenticator {
    auth_hook: String,
    cleanup_hook: Option<String>,
}

impl DnsHookAuthenticator {
    pub fn new(auth_hook: String, cleanup_hook: Option<String>) -> Self {
        Self {
            auth_hook,
            cleanup_hook,
        }
    }

    fn run_hook(&self, command: &str, domain: &str, token: &str, validation: &str) -> Result<()> {
        if command.trim().is_empty() {
            anyhow::bail!("Hook command is empty");
        }

        info!("Running DNS hook: {command}");
        let mut cmd = shell_command(command);
        cmd.env("CERTBOT_DOMAIN", domain);
        cmd.env("CERTBOT_VALIDATION", validation);
        cmd.env("CERTBOT_TOKEN", token);
        cmd.env("VOUCH_CHALLENGE", "dns-01");

        let status = cmd
            .status()
            .with_context(|| format!("Failed to spawn hook: {command}"))?;
        if !status.success() {
            anyhow::bail!("Hook failed (exit={status}): {command}");
        }
        Ok(())
    }
}

impl Authenticator for DnsHookAuthenticator {
    fn perform(&mut self, domain: &str, token: &str, key_authorization: &str) -> Result<()> {
        self.run_hook(&self.auth_hook, domain, token, key_authorization)
    }

    fn cleanup(&mut self, domain: &str, token: &str, key_authorization: &str) -> Result<()> {
        if let Some(cmd) = &self.cleanup_hook {
            self.run_hook(cmd, domain, token, key_authorization)
        } else {
            Ok(())
        }
    }
}

fn shell_command(command: &str) -> Command {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("cmd");
        cmd.arg("/C").arg(command);
        cmd
    }

    #[cfg(not(windows))]
    {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(command);
        cmd
    }
}
