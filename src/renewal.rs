use anyhow::{Context, Result};
use std::time::Duration;
use base64::Engine as _;
use time;
use std::path::{Path, PathBuf};
use std::collections::BTreeMap;

pub fn pick_deterministic_ari_renewal_time(
    window: &instant_acme::SuggestedWindow,
    seed: &str,
) -> time::OffsetDateTime {
    use std::hash::{Hash, Hasher};

    let window_seconds = (window.end - window.start).whole_seconds();
    if window_seconds <= 0 {
        return window.start;
    }

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut hasher);
    let offset = (hasher.finish() % (window_seconds as u64)) as i64;
    window.start + time::Duration::seconds(offset)
}

/// Parse Certbot-style `renew_before_expiry` strings.
pub fn parse_renew_before_expiry(input: &str) -> Result<Duration> {
    let s = input.trim();
    if s.is_empty() {
        anyhow::bail!("empty RENEW_BEFORE_EXPIRY");
    }

    if s.bytes().all(|b| b.is_ascii_digit()) {
        let days: u64 = s.parse().context("invalid day count")?;
        return Ok(Duration::from_secs(days.saturating_mul(86_400)));
    }

    let lowered = s.to_ascii_lowercase();
    let first_non_digit = lowered
        .char_indices()
        .find(|&(_, c)| !c.is_ascii_digit())
        .map(|(idx, _)| idx)
        .ok_or_else(|| anyhow::anyhow!("invalid duration: '{input}'"))?;
    let (num_part, unit_part) = lowered.split_at(first_non_digit);

    let value: u64 = num_part
        .parse()
        .with_context(|| format!("invalid duration number: '{input}'"))?;

    let unit = unit_part.trim();
    let seconds_per_unit: u64 = match unit {
        "d" | "day" | "days" => 86_400,
        "h" | "hour" | "hours" => 3_600,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        _ => anyhow::bail!(
            "unsupported duration unit in '{input}' (use days/hours/minutes/seconds)"
        ),
    };

    Ok(Duration::from_secs(value.saturating_mul(seconds_per_unit)))
}

pub fn leaf_cert_der_from_pem_or_der(cert_bytes: &[u8]) -> Result<Vec<u8>> {
    if cert_bytes.windows(27).any(|w| w == b"-----BEGIN CERTIFICATE-----") {
        let pem_str = String::from_utf8_lossy(cert_bytes);
        for part in pem_str.split("-----BEGIN CERTIFICATE-----").skip(1) {
            if let Some(end_idx) = part.find("-----END CERTIFICATE-----") {
                let base64_content = &part[..end_idx].replace('\n', "").replace('\r', "");
                return Ok(base64::engine::general_purpose::STANDARD
                    .decode(base64_content)
                    .context("Failed to decode certificate base64")?);
            }
        }
        anyhow::bail!("Failed to find valid certificate in PEM");
    }
    Ok(cert_bytes.to_vec())
}

pub fn check_expiration(cert_bytes: &[u8], threshold: Duration) -> Result<(bool, i64)> {
    use x509_parser::prelude::FromDer;
    let der = leaf_cert_der_from_pem_or_der(cert_bytes)?;
    let (_, cert) = x509_parser::prelude::X509Certificate::from_der(&der)
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate DER: {e:?}"))?;
    
    let not_after = cert.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let seconds_left = not_after - now;
    let days_left = seconds_left / 86_400;

    Ok((seconds_left <= threshold.as_secs() as i64, days_left))
}

#[derive(Clone, Debug, Default)]
pub struct RenewalConfig {
    pub name: String,
    pub path: PathBuf,
    pub archive_dir: Option<PathBuf>,
    pub cert: Option<PathBuf>,
    pub privkey: Option<PathBuf>,
    pub chain: Option<PathBuf>,
    pub fullchain: Option<PathBuf>,
    pub domains: Vec<String>,
    pub webroot_path: Option<PathBuf>,
    pub webroot_map: Vec<(String, PathBuf)>,
    pub authenticator: Option<String>,
    pub installer: Option<String>,
    pub preferred_challenges: Option<String>,
    pub server: Option<String>,
    pub account: Option<String>,
    pub manual_auth_hook: Option<String>,
    pub manual_cleanup_hook: Option<String>,
}

pub fn load_renewal_configs(config_dir: &Path) -> Result<Vec<RenewalConfig>> {
    let renewal_dir = config_dir.join("renewal");
    if !renewal_dir.exists() {
        return Ok(Vec::new());
    }

    let mut configs = Vec::new();
    for entry in std::fs::read_dir(&renewal_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map(|e| e == "conf").unwrap_or(false) {
            let name = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            configs.push(parse_renewal_config(&path, &name)?);
        }
    }
    Ok(configs)
}

pub fn parse_renewal_config(path: &Path, name: &str) -> Result<RenewalConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read renewal config: {}", path.display()))?;

    let mut root = BTreeMap::new();
    let mut params = BTreeMap::new();
    let mut section = String::new();

    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line.trim_matches(&['[', ']'][..]).to_string();
            continue;
        }
        let (k, v) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };
        if section == "renewalparams" {
            params.insert(k.to_string(), v.to_string());
        } else {
            root.insert(k.to_string(), v.to_string());
        }
    }

    let mut cfg = RenewalConfig {
        name: name.to_string(),
        path: path.to_path_buf(),
        ..Default::default()
    };

    cfg.archive_dir = root.get("archive_dir").map(PathBuf::from);
    cfg.cert = root.get("cert").map(PathBuf::from);
    cfg.privkey = root.get("privkey").map(PathBuf::from);
    cfg.chain = root.get("chain").map(PathBuf::from);
    cfg.fullchain = root.get("fullchain").map(PathBuf::from);

    if let Some(domains) = params.get("domains") {
        cfg.domains = domains
            .split(',')
            .map(|d| d.trim().to_string())
            .filter(|d| !d.is_empty())
            .collect();
    }

    cfg.authenticator = params.get("authenticator").cloned();
    cfg.installer = params.get("installer").cloned();
    cfg.preferred_challenges = params.get("preferred_challenges").cloned();
    cfg.server = params.get("server").cloned();
    cfg.account = params.get("account").cloned();
    cfg.manual_auth_hook = params.get("manual_auth_hook").cloned();
    cfg.manual_cleanup_hook = params.get("manual_cleanup_hook").cloned();

    if let Some(path) = params.get("webroot_path") {
        if !path.is_empty() {
            cfg.webroot_path = Some(PathBuf::from(path));
        }
    }

    if let Some(map) = params.get("webroot_map") {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(map) {
            if let Some(obj) = value.as_object() {
                for (k, v) in obj {
                    if let Some(p) = v.as_str() {
                        cfg.webroot_map.push((k.to_string(), PathBuf::from(p)));
                    }
                }
            }
        }
    }

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_parse_renew_before_expiry() {
        assert!(parse_renew_before_expiry("").is_err());
        assert_eq!(parse_renew_before_expiry("30").unwrap(), Duration::from_secs(30 * 86400));
        assert_eq!(parse_renew_before_expiry("30d").unwrap(), Duration::from_secs(30 * 86400));
        assert_eq!(parse_renew_before_expiry("12h").unwrap(), Duration::from_secs(12 * 3600));
        assert_eq!(parse_renew_before_expiry("5m").unwrap(), Duration::from_secs(5 * 60));
        assert_eq!(parse_renew_before_expiry("90s").unwrap(), Duration::from_secs(90));
        assert!(parse_renew_before_expiry("invalid").is_err());
        assert!(parse_renew_before_expiry("30x").is_err());
    }

    #[test]
    fn test_parse_renewal_config_basic() -> Result<()> {
        let mut tmp = NamedTempFile::new()?;
        let content = r#"
archive_dir = /etc/letsencrypt/archive/example.com
cert = /etc/letsencrypt/live/example.com/cert.pem
privkey = /etc/letsencrypt/live/example.com/privkey.pem
chain = /etc/letsencrypt/live/example.com/chain.pem
fullchain = /etc/letsencrypt/live/example.com/fullchain.pem

[renewalparams]
domains = example.com,www.example.com
authenticator = webroot
webroot_path = /var/www/html
preferred_challenges = http-01
manual_auth_hook = /usr/local/bin/dns-auth.sh
manual_cleanup_hook = /usr/local/bin/dns-cleanup.sh
"#;
        tmp.write_all(content.as_bytes())?;

        let cfg = parse_renewal_config(tmp.path(), "example.com")?;
        assert_eq!(cfg.name, "example.com");
        assert_eq!(cfg.domains.len(), 2);
        assert_eq!(cfg.authenticator.as_deref(), Some("webroot"));
        assert_eq!(cfg.webroot_path.as_deref(), Some(Path::new("/var/www/html")));
        assert_eq!(cfg.preferred_challenges.as_deref(), Some("http-01"));
        assert_eq!(cfg.manual_auth_hook.as_deref(), Some("/usr/local/bin/dns-auth.sh"));
        assert_eq!(cfg.manual_cleanup_hook.as_deref(), Some("/usr/local/bin/dns-cleanup.sh"));
        Ok(())
    }
}
