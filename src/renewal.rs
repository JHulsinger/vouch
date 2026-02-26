use anyhow::{Context, Result};
use std::time::Duration;
use base64::Engine as _;
use time;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
