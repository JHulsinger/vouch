# vouch Certbot Compatibility Contract (Draft)

This document defines the drop-in replacement targets for vouch. It is a compatibility contract, not a marketing doc.

## Scope

Target: Linux-only drop-in replacement for certbot in common production usage.

In scope:
- `certonly` for initial issuance
- `renew` for unattended renewals
- `certificates` for listing
- Webroot and DNS hook authentication
- Certbot-style filesystem layout
- Certbot-style hook environment variables

Out of scope for this phase:
- Native nginx/apache installers
- Windows/macOS compatibility
- Full certbot config parity across every plugin

## CLI Compatibility Targets

Supported (exact or compatible):
- `certonly`
- `renew`
- `certificates`
- `-d/--domain` repeatable
- `--cert-name`
- `--config-dir`, `--work-dir`, `--logs-dir`
- `--dry-run` (maps to staging)
- `--server` (custom ACME directory)
- `--preferred-challenges`
- `--webroot`
- `--manual-auth-hook`, `--manual-cleanup-hook` (DNS hook mode)
- `--pre-hook`, `--post-hook`, `--deploy-hook`, `--renew-hook`

Not yet supported:
- `--nginx`, `--apache`, or plugin-specific installer flags
- Every certbot CLI flag; only the subset above is guaranteed

## Filesystem Layout (Linux)

Default paths:
- Config: `/etc/letsencrypt`
- Work: `/var/lib/letsencrypt`
- Logs: `/var/log/letsencrypt`

Lineage layout:
```
/etc/letsencrypt
  live/<name>/
    cert.pem -> ../../archive/<name>/certN.pem
    chain.pem -> ../../archive/<name>/chainN.pem
    fullchain.pem -> ../../archive/<name>/fullchainN.pem
    privkey.pem -> ../../archive/<name>/privkeyN.pem
  archive/<name>/
    cert1.pem, chain1.pem, fullchain1.pem, privkey1.pem
    cert2.pem, chain2.pem, fullchain2.pem, privkey2.pem
  renewal/<name>.conf
  accounts/...
```

The live symlinks are updated on every successful issuance/renewal.

## Hook Environment Variables

vouch sets Certbot-compatible variables when running hooks:
- `RENEWED_DOMAINS`
- `RENEWED_LINEAGE`
- `RENEWED_CERT`
- `RENEWED_PRIVKEY`
- `RENEWED_CHAIN`
- `RENEWED_FULLCHAIN`

For manual/DNS hook authentication:
- `CERTBOT_DOMAIN`
- `CERTBOT_VALIDATION`
- `CERTBOT_TOKEN` (for HTTP-01 if used)

## Renewal Behavior

- vouch reads existing `/etc/letsencrypt/renewal/*.conf` and renews in place.
- If a renewal config includes webroot settings, those are preferred.
- If manual auth hooks are configured, those are used for DNS challenges.
- If no renewal config exists, vouch will not attempt to renew.

