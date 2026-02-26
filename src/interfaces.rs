use anyhow::Result;
/// Matches the Certbot `Authenticator` interface.
/// Responsible for satisfying ACME challenges (e.g., placing HTTP-01 files or setting DNS-01 records).
pub trait Authenticator {
    /// Perform the setup required to satisfy the challenge.
    fn perform(&mut self, domain: &str, token: &str, key_authorization: &str) -> Result<()>;
    /// Clean up the challenge artifacts after verification.
    fn cleanup(&mut self, domain: &str, token: &str) -> Result<()>;
}
/// Matches the Certbot `Installer` interface.
/// Responsible for deploying certificates and modifying web server configurations.
pub trait Installer {
    /// Return a list of all server names recognized by the installer.
    fn get_all_names(&self) -> Result<Vec<String>>;
    /// Deploy the generated certificate to the target host structure.
    fn deploy_cert(&mut self, domain: &str, cert_path: &str, key_path: &str) -> Result<()>;
    /// Enhance the server configuration (e.g., adding HTTP->HTTPS redirects).
    fn enhance(&mut self, domain: &str, enhancement: &str) -> Result<()>;
    /// Save the changes made during the session.
    fn save(&mut self, title: &str) -> Result<()>;
    /// Restart or reload the server to apply changes.
    fn restart(&mut self) -> Result<()>;
}
/// A combined trait for plugins that act as both Authenticator and Installer (e.g., `certbot-nginx`).
pub trait Plugin: Authenticator + Installer {}
/// An IPC-based plugin wrapper.
/// Instead of relying on brittle Rust ABIs for out-of-tree plugins, `vouch` spawns
/// an external helper binary (e.g., `vouch-nginx`) and communicates via JSON-RPC over stdio.
pub struct IpcPlugin {
    pub binary_path: String,
}
impl IpcPlugin {
    pub fn new(binary_path: &str) -> Self {
        Self {
            binary_path: binary_path.to_string(),
        }
    }
    /// Helper to execute the external binary with a specific JSON-RPC command
    fn rpc_call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        use std::io::{BufReader, Read, Write};
        use std::process::{Command, Stdio};

        const MAX_RPC_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

        let payload = serde_json::json!(
            { "jsonrpc" : "2.0", "method" : method, "params" : params, "id" : 1 }
        );
        let mut child = Command::new(&self.binary_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                anyhow::anyhow!("Failed to spawn plugin binary {}: {}", self.binary_path, e)
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            serde_json::to_writer(&mut stdin, &payload)?;
            stdin.write_all(b"\n")?;
        }

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("Plugin stdout was not captured"))?;
        let mut limited_reader = BufReader::new(stdout).take(MAX_RPC_RESPONSE_BYTES);
        let response: serde_json::Value = serde_json::from_reader(&mut limited_reader)?;

        let status = child.wait()?;
        if !status.success() {
            anyhow::bail!(
                "Plugin binary '{}' returned non-zero exit code: {}",
                self.binary_path,
                status
            );
        }

        let mut trailing = [0_u8; 1];
        if limited_reader.read(&mut trailing)? != 0 {
            anyhow::bail!("Plugin response exceeded {} bytes", MAX_RPC_RESPONSE_BYTES);
        }

        if let Some(error) = response.get("error") {
            anyhow::bail!("Plugin error: {}", error);
        }

        response
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Plugin response missing result field"))
    }
}
impl Authenticator for IpcPlugin {
    fn perform(&mut self, domain: &str, token: &str, key_authorization: &str) -> Result<()> {
        println!(
            "🔌 Dispatching Authenticator::perform to {}...",
            self.binary_path
        );
        self.rpc_call(
            "authenticator.perform",
            serde_json::json!({ "domain" : domain, "token": token, "key_authorization": key_authorization }),
        )?;
        Ok(())
    }
    fn cleanup(&mut self, domain: &str, token: &str) -> Result<()> {
        self.rpc_call(
            "authenticator.cleanup",
            serde_json::json!({ "domain" : domain, "token": token }),
        )?;
        Ok(())
    }
}
impl Installer for IpcPlugin {
    fn get_all_names(&self) -> Result<Vec<String>> {
        let res = self.rpc_call("installer.get_all_names", serde_json::json!({}))?;
        Ok(serde_json::from_value(res)?)
    }
    fn deploy_cert(&mut self, domain: &str, cert_path: &str, key_path: &str) -> Result<()> {
        self.rpc_call(
            "installer.deploy_cert",
            serde_json::json!(
                { "domain" : domain, "cert_path" : cert_path, "key_path" : key_path }
            ),
        )?;
        Ok(())
    }
    fn enhance(&mut self, domain: &str, enhancement: &str) -> Result<()> {
        self.rpc_call(
            "installer.enhance",
            serde_json::json!({ "domain" : domain, "enhancement" : enhancement }),
        )?;
        Ok(())
    }
    fn save(&mut self, title: &str) -> Result<()> {
        self.rpc_call("installer.save", serde_json::json!({ "title" : title }))?;
        Ok(())
    }
    fn restart(&mut self) -> Result<()> {
        self.rpc_call("installer.restart", serde_json::json!({}))?;
        Ok(())
    }
}
impl Plugin for IpcPlugin {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_ipc_plugin_rpc_call() {
        // Create a dummy shell script that acts as an IPC plugin
        let mut script = NamedTempFile::new().unwrap();
        let script_content = r#"#!/bin/bash
read -r payload
# Echo back a valid JSON-RPC response based on the "method" requested (if we cared to parse it)
echo '{"jsonrpc": "2.0", "result": {"status": "success"}, "id": 1}'
"#;
        script.write_all(script_content.as_bytes()).unwrap();
        
        // Make it executable
        let mut perms = script.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o755);
        script.as_file().set_permissions(perms).unwrap();
        
        let plugin = IpcPlugin::new(script.path().to_str().unwrap());
        
        let res = plugin.rpc_call("test.method", serde_json::json!({"foo": "bar"}));
        assert!(res.is_ok(), "RPC call to dummy script failed: {:?}", res);
        let val = res.unwrap();
        assert_eq!(val.get("status").unwrap().as_str().unwrap(), "success");
    }
}
