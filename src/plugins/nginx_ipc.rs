use crate::interfaces::IpcPlugin;

/// A scaffold for an Nginx installer that uses the `IpcPlugin` architecture under the hood.
/// In a real deployment, this would point to a separate binary (e.g. `vouch-nginx`).
pub struct NginxIpcInstaller {
    pub internal_plugin: IpcPlugin,
}

impl Default for NginxIpcInstaller {
    fn default() -> Self {
        Self::new("/usr/local/bin/vouch-nginx")
    }
}

impl NginxIpcInstaller {
    pub fn new(executable_path: &str) -> Self {
        Self {
            internal_plugin: IpcPlugin::new(executable_path),
        }
    }
}
