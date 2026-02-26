use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct LineagePaths {
    pub name: String,
    pub live_dir: PathBuf,
    pub archive_dir: PathBuf,
    pub renewal_path: PathBuf,
    pub cert: PathBuf,
    pub chain: PathBuf,
    pub fullchain: PathBuf,
    pub privkey: PathBuf,
}

#[derive(Clone, Debug)]
pub struct ArchivePaths {
    pub cert: PathBuf,
    pub chain: PathBuf,
    pub fullchain: PathBuf,
    pub privkey: PathBuf,
}

#[derive(Clone, Debug, Default)]
pub struct LiveSymlinks {
    pub cert: Option<PathBuf>,
    pub chain: Option<PathBuf>,
    pub fullchain: Option<PathBuf>,
    pub privkey: Option<PathBuf>,
}

#[derive(Clone, Debug, Default)]
pub struct RenewalParams {
    pub domains: Vec<String>,
    pub authenticator: Option<String>,
    pub installer: Option<String>,
    pub webroot_path: Option<PathBuf>,
    pub webroot_map: Option<Vec<(String, PathBuf)>>,
    pub preferred_challenges: Option<String>,
    pub server: Option<String>,
    pub account: Option<String>,
    pub key_type: Option<String>,
    pub rsa_key_size: Option<String>,
    pub elliptic_curve: Option<String>,
    pub manual_auth_hook: Option<String>,
    pub manual_cleanup_hook: Option<String>,
}

pub fn default_dirs_linux() -> (PathBuf, PathBuf, PathBuf) {
    (
        PathBuf::from("/etc/letsencrypt"),
        PathBuf::from("/var/lib/letsencrypt"),
        PathBuf::from("/var/log/letsencrypt"),
    )
}

pub fn lineage_paths(config_dir: &Path, name: &str) -> LineagePaths {
    let live_dir = config_dir.join("live").join(name);
    let archive_dir = config_dir.join("archive").join(name);
    let renewal_path = config_dir.join("renewal").join(format!("{name}.conf"));

    LineagePaths {
        name: name.to_string(),
        live_dir: live_dir.clone(),
        archive_dir: archive_dir.clone(),
        renewal_path,
        cert: live_dir.join("cert.pem"),
        chain: live_dir.join("chain.pem"),
        fullchain: live_dir.join("fullchain.pem"),
        privkey: live_dir.join("privkey.pem"),
    }
}

fn next_archive_index(archive_dir: &Path) -> Result<u32> {
    if !archive_dir.exists() {
        return Ok(1);
    }

    let mut max_idx = 0u32;
    for entry in fs::read_dir(archive_dir).context("Failed to read archive dir")? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(num) = name
            .strip_prefix("cert")
            .and_then(|s| s.strip_suffix(".pem"))
            .and_then(|s| s.parse::<u32>().ok())
        {
            max_idx = max_idx.max(num);
        }
    }
    Ok(max_idx + 1)
}

fn split_pem_chain(pem: &str) -> Result<(String, String)> {
    let mut certs = Vec::new();
    let mut current = String::new();
    let mut in_cert = false;
    for line in pem.lines() {
        if line.contains("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current.clear();
            current.push_str(line);
            current.push('\n');
            continue;
        }
        if in_cert {
            current.push_str(line);
            current.push('\n');
            if line.contains("-----END CERTIFICATE-----") {
                certs.push(current.clone());
                in_cert = false;
            }
        }
    }

    if certs.is_empty() {
        anyhow::bail!("No PEM certificates found in chain");
    }

    let leaf = certs[0].clone();
    let chain = if certs.len() > 1 {
        certs[1..].join("")
    } else {
        String::new()
    };

    Ok((leaf, chain))
}

fn write_pem_atomic(path: &Path, pem: &str, mode: u32) -> Result<()> {
    let dir = path.parent().ok_or_else(|| anyhow::anyhow!("Invalid path"))?;
    let temp = tempfile::Builder::new()
        .prefix("vouch_tmp_")
        .tempfile_in(dir)
        .context("Failed to create temp file")?;
    fs::write(temp.path(), pem)?;
    let mut perms = fs::metadata(temp.path())?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(temp.path(), perms)?;
    temp.persist(path).map_err(|e| anyhow::anyhow!(e))?;
    Ok(())
}

fn update_symlink(link: &Path, target_rel: &Path) -> Result<()> {
    if link.exists() || link.is_symlink() {
        fs::remove_file(link).ok();
    }
    symlink(target_rel, link).context("Failed to create symlink")?;
    Ok(())
}

fn archive_paths(archive_dir: &Path, index: u32) -> ArchivePaths {
    ArchivePaths {
        cert: archive_dir.join(format!("cert{index}.pem")),
        chain: archive_dir.join(format!("chain{index}.pem")),
        fullchain: archive_dir.join(format!("fullchain{index}.pem")),
        privkey: archive_dir.join(format!("privkey{index}.pem")),
    }
}

pub fn write_lineage(
    config_dir: &Path,
    name: &str,
    fullchain_pem: &str,
    privkey_pem: &str,
) -> Result<LineagePaths> {
    let lineage = lineage_paths(config_dir, name);
    fs::create_dir_all(lineage.live_dir.parent().unwrap())
        .context("Failed to create live dir root")?;
    fs::create_dir_all(lineage.archive_dir.parent().unwrap())
        .context("Failed to create archive dir root")?;
    fs::create_dir_all(lineage.renewal_path.parent().unwrap())
        .context("Failed to create renewal dir")?;
    fs::create_dir_all(&lineage.live_dir).context("Failed to create live dir")?;
    fs::create_dir_all(&lineage.archive_dir).context("Failed to create archive dir")?;

    let index = next_archive_index(&lineage.archive_dir)?;
    let archive = archive_paths(&lineage.archive_dir, index);

    let (leaf, chain) = split_pem_chain(fullchain_pem)?;

    write_pem_atomic(&archive.privkey, privkey_pem, 0o600)?;
    write_pem_atomic(&archive.cert, &leaf, 0o644)?;
    write_pem_atomic(&archive.chain, &chain, 0o644)?;
    write_pem_atomic(&archive.fullchain, fullchain_pem, 0o644)?;

    let rel = PathBuf::from("../../archive").join(name);
    update_symlink(&lineage.privkey, &rel.join(archive.privkey.file_name().unwrap()))?;
    update_symlink(&lineage.cert, &rel.join(archive.cert.file_name().unwrap()))?;
    update_symlink(&lineage.chain, &rel.join(archive.chain.file_name().unwrap()))?;
    update_symlink(&lineage.fullchain, &rel.join(archive.fullchain.file_name().unwrap()))?;

    Ok(lineage)
}

pub fn read_live_symlinks(lineage: &LineagePaths) -> LiveSymlinks {
    LiveSymlinks {
        cert: fs::read_link(&lineage.cert).ok(),
        chain: fs::read_link(&lineage.chain).ok(),
        fullchain: fs::read_link(&lineage.fullchain).ok(),
        privkey: fs::read_link(&lineage.privkey).ok(),
    }
}

pub fn restore_live_symlinks(lineage: &LineagePaths, prior: &LiveSymlinks) -> Result<()> {
    if let Some(target) = &prior.privkey {
        update_symlink(&lineage.privkey, target)?;
    }
    if let Some(target) = &prior.cert {
        update_symlink(&lineage.cert, target)?;
    }
    if let Some(target) = &prior.chain {
        update_symlink(&lineage.chain, target)?;
    }
    if let Some(target) = &prior.fullchain {
        update_symlink(&lineage.fullchain, target)?;
    }
    Ok(())
}

pub fn write_renewal_config(config_dir: &Path, name: &str, params: &RenewalParams) -> Result<()> {
    let lineage = lineage_paths(config_dir, name);
    if let Some(parent) = lineage.renewal_path.parent() {
        fs::create_dir_all(parent).context("Failed to create renewal dir")?;
    }

    let mut lines = Vec::new();
    lines.push(format!("archive_dir = {}", lineage.archive_dir.display()));
    lines.push(format!("cert = {}", lineage.cert.display()));
    lines.push(format!("privkey = {}", lineage.privkey.display()));
    lines.push(format!("chain = {}", lineage.chain.display()));
    lines.push(format!("fullchain = {}", lineage.fullchain.display()));
    lines.push(String::new());
    lines.push("[renewalparams]".to_string());

    if !params.domains.is_empty() {
        lines.push(format!("domains = {}", params.domains.join(",")));
    }
    if let Some(auth) = &params.authenticator {
        lines.push(format!("authenticator = {auth}"));
    }
    if let Some(installer) = &params.installer {
        lines.push(format!("installer = {installer}"));
    }
    if let Some(path) = &params.webroot_path {
        lines.push(format!("webroot_path = {}", path.display()));
    }
    if let Some(map) = &params.webroot_map {
        let mut obj = serde_json::Map::new();
        for (domain, path) in map {
            obj.insert(domain.clone(), serde_json::Value::String(path.display().to_string()));
        }
        lines.push(format!("webroot_map = {}", serde_json::Value::Object(obj)));
    }
    if let Some(chal) = &params.preferred_challenges {
        lines.push(format!("preferred_challenges = {chal}"));
    }
    if let Some(server) = &params.server {
        lines.push(format!("server = {server}"));
    }
    if let Some(account) = &params.account {
        lines.push(format!("account = {account}"));
    }
    if let Some(k) = &params.key_type {
        lines.push(format!("key_type = {k}"));
    }
    if let Some(k) = &params.rsa_key_size {
        lines.push(format!("rsa_key_size = {k}"));
    }
    if let Some(k) = &params.elliptic_curve {
        lines.push(format!("elliptic_curve = {k}"));
    }
    if let Some(h) = &params.manual_auth_hook {
        lines.push(format!("manual_auth_hook = {h}"));
    }
    if let Some(h) = &params.manual_cleanup_hook {
        lines.push(format!("manual_cleanup_hook = {h}"));
    }

    let content = lines.join("\n") + "\n";
    write_pem_atomic(&lineage.renewal_path, &content, 0o644)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_write_lineage_creates_symlinks() -> Result<()> {
        let tmp = TempDir::new()?;
        let fullchain = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        let privkey = "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n";

        let lineage = write_lineage(tmp.path(), "example.com", fullchain, privkey)?;

        assert!(lineage.live_dir.exists());
        assert!(lineage.archive_dir.exists());
        assert!(lineage.cert.exists());
        assert!(lineage.chain.exists());
        assert!(lineage.fullchain.exists());
        assert!(lineage.privkey.exists());

        let link = fs::read_link(&lineage.cert)?;
        assert!(link.to_string_lossy().contains("archive/example.com/cert1.pem"));
        Ok(())
    }

    #[test]
    fn test_write_renewal_config_basic() -> Result<()> {
        let tmp = TempDir::new()?;
        let mut params = RenewalParams::default();
        params.domains = vec!["example.com".to_string(), "www.example.com".to_string()];
        params.authenticator = Some("webroot".to_string());
        params.webroot_path = Some(PathBuf::from("/var/www/html"));
        params.preferred_challenges = Some("http-01".to_string());

        write_renewal_config(tmp.path(), "example.com", &params)?;
        let path = tmp.path().join("renewal").join("example.com.conf");
        let content = fs::read_to_string(path)?;

        assert!(content.contains("domains = example.com,www.example.com"));
        assert!(content.contains("authenticator = webroot"));
        assert!(content.contains("webroot_path = /var/www/html"));
        Ok(())
    }
}
