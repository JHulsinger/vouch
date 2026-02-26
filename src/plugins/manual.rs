use crate::interfaces::Authenticator;
use anyhow::{Result, bail};
use std::io::{self, BufRead, IsTerminal, Write};
use tracing::info;

/// Implementation of the manual plugin behavior.
/// Note: This plugin requires mandatory user interaction for challenge fulfillment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManualChallenge {
    Http01,
    Dns01,
}

pub struct ManualAuthenticator {
    challenge: ManualChallenge,
}

impl ManualAuthenticator {
    pub fn new(challenge: ManualChallenge) -> Self {
        Self { challenge }
    }

    fn ensure_interactive(&self) -> Result<()> {
        if !io::stdin().is_terminal() {
            bail!("Manual mode requires an interactive TTY on stdin.");
        }
        Ok(())
    }

    fn prompt(&self) -> Result<()> {
        self.ensure_interactive()?;
        eprint!("Press Enter to continue once complete (Ctrl-C to abort): ");
        io::stderr().flush().ok();
        let mut line = String::new();
        let mut stdin = io::stdin().lock();
        stdin.read_line(&mut line)?;
        Ok(())
    }
}

impl Authenticator for ManualAuthenticator {
    fn perform(&mut self, domain: &str, token: &str, key_authorization: &str) -> Result<()> {
        match self.challenge {
            ManualChallenge::Http01 => {
                info!("🛠️ Manual HTTP-01 challenge requested.");
                eprintln!("Create a file served at:");
                eprintln!("  http://{}/.well-known/acme-challenge/{}", domain, token);
                eprintln!("With the exact contents:");
                eprintln!("  {}", key_authorization);
                self.prompt()?;
            }
            ManualChallenge::Dns01 => {
                info!("🛠️ Manual DNS-01 challenge requested.");
                eprintln!("Create a TXT record:");
                eprintln!("  _acme-challenge.{}   TXT   {}", domain, key_authorization);
                self.prompt()?;
            }
        }
        Ok(())
    }

    fn cleanup(&mut self, domain: &str, token: &str) -> Result<()> {
        match self.challenge {
            ManualChallenge::Http01 => {
                eprintln!(
                    "Manual cleanup: remove the file at http://{}/.well-known/acme-challenge/{}",
                    domain, token
                );
            }
            ManualChallenge::Dns01 => {
                eprintln!(
                    "Manual cleanup: remove the TXT record _acme-challenge.{}",
                    domain
                );
            }
        }
        Ok(())
    }
}
