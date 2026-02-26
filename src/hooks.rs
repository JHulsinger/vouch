use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use tracing::{error, info};

#[derive(Clone, Copy, Debug)]
pub enum HookKind {
    Pre,
    Post,
    Deploy,
}

impl HookKind {
    fn as_str(self) -> &'static str {
        match self {
            HookKind::Pre => "pre",
            HookKind::Post => "post",
            HookKind::Deploy => "deploy",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct HookContext {
    env: BTreeMap<String, String>,
}

impl HookContext {
    pub fn new() -> Self {
        Self { env: BTreeMap::new() }
    }

    pub fn with_var(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub fn with_opt_path(mut self, key: &str, value: Option<&Path>) -> Self {
        if let Some(p) = value {
            if let Some(s) = p.to_str() {
                self.env.insert(key.to_string(), s.to_string());
            }
        }
        self
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

pub fn run_hooks(kind: HookKind, hooks: &[String], ctx: &HookContext) -> Result<()> {
    if hooks.is_empty() {
        return Ok(());
    }

    for hook in hooks {
        if hook.trim().is_empty() {
            continue;
        }
        
        info!("🏃 Running {} hook: {}", kind.as_str(), hook);
        let mut cmd = shell_command(hook);
        cmd.env("VOUCH_HOOK", kind.as_str());
        for (k, v) in &ctx.env {
            cmd.env(k, v);
        }

        let status = cmd
            .status()
            .with_context(|| format!("Failed to spawn {kind:?} hook: {hook}"))?;

        if !status.success() {
            error!("❌ {kind:?} hook failed (exit={status}): {hook}");
            anyhow::bail!("{kind:?} hook failed (exit={status}): {hook}");
        } else {
            info!("✅ {kind:?} hook completed successfully");
        }
    }

    Ok(())
}
