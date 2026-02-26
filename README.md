# vouch

`vouch` is a **beta** effort to modernize Certbot’s core workflow by rebuilding it in Rust, with the long-term goal of being a practical **drop-in replacement** for Certbot (same mental model: a small ACME core + pluggable “how do I solve challenges?” and “how do I install certs?” integrations).

This exists because, in real deployments, Certbot’s biggest pain points are rarely “ACME is hard” - they’re operational:

- A Python runtime + packaging story that varies across distros/environments.
- Dependency churn and environment drift (system Python vs venv vs container vs snap).
- A heavier deployment footprint than the actual job requires.

`vouch` aims to make the common case boring: a small native binary, explicit filesystem safety, and a plugin boundary that can evolve without coupling everything to one language runtime.

## Status (what works today)

- **Project stage:** beta / production-ready candidate
- **ACME directory:** Let’s Encrypt Staging by default, Production via `--production`
- **Commands:** `certonly` (obtain flow) and `renew` (automated background checking)
- **Challenges:** HTTP-01 (via built-in Webroot) and DNS-01 (via external IPC plugins)
- **Installers:** Full hook support for external binaries (e.g., reloading Nginx)
- **Persistence:** ACME account credentials are stored on disk so identities survive restarts (rate-limit safety)

## What vouch does (current behavior)

At a high level, `vouch certonly`:

1. Resolves a config directory (OS-default or `--config-dir`).
2. Acquires an exclusive lock to prevent concurrent state corruption.
3. Loads existing ACME account credentials, or creates a new account.
4. Creates an order for the requested domain.
5. Invokes the correct Authenticator (e.g., writing to `--webroot` or calling a `--dns-plugin`) to satisfy the challenge.
6. Polls the order until it becomes `Ready`.
7. Finalizes the order and fetches the certificate chain.
8. Writes key/cert to disk atomically with strict permissions (`0600`).
9. Invokes the optional `--installer` plugin to reload services or copy certificates.

For `vouch renew`:
1. Scans the `--config-dir` for existing directories (domains).
2. Parses the `domain.crt` using `x509-parser` to calculate expiration.
3. Only triggers a full ACME run if the cert expires in <= 30 days (non-interactive, cron-safe).

## Files written to disk

By default, `vouch` writes under an OS-specific config directory (via `directories::ProjectDirs`). You can override it explicitly.

Current filenames (in `--config-dir`):

- `account_creds.json` - ACME account credentials
- `account_creds.json.lock` - lock file used to guard concurrent runs
- `domain.key` - private key for the finalized order (permissions `0600`)
- `domain.crt` - certificate chain PEM (permissions `0600`)

Notes:

- Writes use temp files + atomic persist to avoid partial writes on crash.
- Locking is used to avoid two runs racing and corrupting credentials/state.

## Plugin model 

Certbot’s core power is its plugin ecosystem. `vouch` mirrors that structure but completely escapes the "Python monolith" problem. 

- `Authenticator`: responsible for satisfying challenges (HTTP-01/DNS-01).
- `Installer`: responsible for deploying certs / modifying server config.
- `Plugin`: a combined trait when a plugin does both.

### IPC Plugins (The Marketplace Advantage)
To avoid brittle Rust ABI guarantees and slow monolith compiles, `vouch` uses an **IPC-based plugin wrapper**:

- You can write a plugin in **any language** (Bash, Go, Node.js, Python).
- `vouch` spawns the plugin as an external binary.
- Calls are proxied as **JSON-RPC** messages over `stdin`/`stdout`.
- The plugin just reads JSON, fulfills the challenge (e.g., updates a Route53 DNS record), and writes a JSON success response.

This language-agnostic boundary allows us to build a marketplace of isolated, secure executables rather than giant pip packages.

## Install / build

Prerequisites:

- Rust toolchain (stable)

Build:

```bash
cargo build
```

Release build:

```bash
cargo build --release
```

Sanity check:

```bash
cargo check
```

## Usage

### 1. Issue a new certificate
**Using HTTP-01 (Webroot):**
```bash
vouch certonly --domain example.com --email you@example.com --webroot /var/www/html --production
```

**Using DNS-01 (External Plugin):**
```bash
vouch certonly --domain example.com --email you@example.com --dns-plugin /usr/local/bin/vouch-dns-cloudflare --production
```

### 2. Renew existing certificates
Designed to be run repeatedly (e.g., daily) via a systemd timer or cron job.
```bash
vouch renew --days 30 --production
```

### Global Options

- `--config-dir <path>`: where account/cert material is persisted
- `--production`: Use Let's Encrypt Production instead of Staging
- `--server <URL>`: Override the ACME directory entirely (e.g., Pebble)
- `--installer <path>`: Executable to call after successful deployment (e.g., a script executing `systemctl reload nginx`)
- `--log-format <text|json>`: Define stdout output format for parsability by automation.

## Security notes (read this before pointing at production)

- **Staging by default:** this avoids burning real rate limits while iterating. A production toggle should be added before real-world use.
- **Keys on disk:** `domain.key` is sensitive material. Keep the config directory private and backed up appropriately.
- **Concurrency:** locking exists to prevent accidental corruption, but you should still avoid running multiple instances against the same config dir.

## Vulnerability reporting

Security reporting instructions live in `.github/SECURITY.md`.

Important: “GitHub Private Vulnerability Reporting” is a **GitHub repository setting**. The policy file documents the intent, but you still need to enable it in the repo settings on GitHub.

## Project layout

- `src/main.rs` - CLI and orchestration
- `src/acme_client.rs` - ACME account/order/verify/finalize logic
- `src/interfaces.rs` - plugin traits + IPC plugin wrapper
- `src/lib.rs` - public module exports

## Known limitations (beta)

- None currently impacting core automation. All roadmap features (v1) are implemented.

## Roadmap (practical next steps)

1. **Plugin Marketplace:** Build the `vouch plugin` command to download IPC plugins securely over HTTP (using the Git index repository model).
2. **Short-Lived Cert Stability:** Optimize the renewal loop for certificates with 7-day validity (the post-OCSP standard), ensuring zero-downtime hot-reloads.
3. **Enterprise ACME (EAB):** Support External Account Binding for integration with non-LE providers (DigiCert, Sectigo, etc.) using KID/HMAC keys.
