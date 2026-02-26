# vouch

`vouch` is a **beta** effort to modernize Certbot’s core workflow by rebuilding it in Rust, with the long-term goal of being a practical **drop-in replacement** for Certbot (same mental model: a small ACME core + pluggable “how do I solve challenges?” and “how do I install certs?” integrations).

This exists because, in real deployments, Certbot’s biggest pain points are rarely “ACME is hard” — they’re operational:

- A Python runtime + packaging story that varies across distros/environments.
- Dependency churn and environment drift (system Python vs venv vs container vs snap).
- A heavier deployment footprint than the actual job requires.

`vouch` aims to make the common case boring: a small native binary, explicit filesystem safety, and a plugin boundary that can evolve without coupling everything to one language runtime.

## Status (what works today)

- **Project stage:** beta / early scaffold
- **ACME directory:** Let’s Encrypt **Staging** (safe while iterating)
- **Main command:** `certonly` (obtain/renew flow)
- **Persistence:** ACME account credentials are stored on disk so identities survive restarts (rate-limit safety)

It is **not** a drop-in replacement for Certbot yet. The CLI surface, challenge fulfillment, and installer integrations are still incomplete.

## What vouch does (current behavior)

At a high level, `vouch certonly`:

1. Resolves a config directory (OS-default or `--config-dir`).
2. Acquires an exclusive lock to prevent concurrent state corruption.
3. Loads existing ACME account credentials, or creates a new account (staging).
4. Creates an order for the requested domain.
5. Iterates authorizations and marks the HTTP-01 challenge “ready” (currently a stub integration point for real challenge fulfillment).
6. Polls the order until it becomes `Ready`.
7. Finalizes the order and fetches the certificate chain.
8. Writes key/cert to disk atomically with strict permissions.

## Files written to disk

By default, `vouch` writes under an OS-specific config directory (via `directories::ProjectDirs`). You can override it explicitly.

Current filenames (in `--config-dir`):

- `account_creds.json` — ACME account credentials
- `account_creds.json.lock` — lock file used to guard concurrent runs
- `domain.key` — private key for the finalized order (permissions `0600`)
- `domain.crt` — certificate chain PEM (permissions `0600`)

Notes:

- Writes use temp files + atomic persist to avoid partial writes on crash.
- Locking is used to avoid two runs racing and corrupting credentials/state.

## Plugin model (direction)

Certbot’s core power is its plugin ecosystem. `vouch` mirrors that structure so we can reach parity without hardcoding every integration into the core:

- `Authenticator`: responsible for satisfying challenges (HTTP-01/DNS-01).
- `Installer`: responsible for deploying certs / modifying server config.
- `Plugin`: a combined trait when a plugin does both.

To avoid brittle Rust ABI guarantees for out-of-tree plugins, `vouch` includes an IPC-based plugin wrapper:

- `IpcPlugin` spawns an external helper (e.g., a future `vouch-nginx`).
- Calls are proxied as JSON-RPC messages over stdin/stdout.
- Response size is bounded to reduce memory abuse risk.

Today, the ACME flow prints a stub message where an authenticator would actually deploy a challenge response.

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

Run from source:

```bash
cargo run -- certonly --domain example.com --email you@example.com
```

Global path overrides:

- `--config-dir <path>`: where account/cert material is persisted
- `--work-dir <path>`: intended working state dir (parsed; not fully wired yet)
- `--logs-dir <path>`: intended log dir (parsed; not fully wired yet)

## Security notes (read this before pointing at production)

- **Staging by default:** this avoids burning real rate limits while iterating. A production toggle should be added before real-world use.
- **Keys on disk:** `domain.key` is sensitive material. Keep the config directory private and backed up appropriately.
- **Concurrency:** locking exists to prevent accidental corruption, but you should still avoid running multiple instances against the same config dir.

## Vulnerability reporting

Security reporting instructions live in `.github/SECURITY.md`.

Important: “GitHub Private Vulnerability Reporting” is a **GitHub repository setting**. The policy file documents the intent, but you still need to enable it in the repo settings on GitHub.

## Project layout

- `src/main.rs` — CLI and orchestration
- `src/acme_client.rs` — ACME account/order/verify/finalize logic
- `src/interfaces.rs` — plugin traits + IPC plugin wrapper
- `src/lib.rs` — public module exports

## Known limitations (beta)

- Challenge fulfillment is currently a stub integration point (no real HTTP-01/DNS-01 deployment yet).
- Installer integrations (nginx/apache/webroot equivalents) are not implemented yet.
- `--work-dir` and `--logs-dir` are parsed but not fully wired into runtime behavior.
- ACME directory selection is not yet configurable (staging only).

## Roadmap (practical next steps)

1. Add real authenticator plugins for HTTP-01 and/or DNS-01.
2. Add installer plugins for certificate deployment and reload.
3. Add explicit staging/production ACME selection via CLI/config.
4. Add structured logs + stable exit codes for automation.
5. Add integration tests around account persistence and finalize flow.
