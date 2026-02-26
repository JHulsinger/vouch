# Vouch (Certbot Rewrite) Logic Walkthrough

## 1) Project intent

`vouch` is a pure-Rust rewrite of the Certbot core flow, designed to avoid Python runtime packaging and reduce deployment overhead.  
The current state is **beta** and focuses on ACME account/order lifecycle, filesystem safety, and plugin architecture foundations.

## 2) What Antigravity’s sprint established

From the prior sprint notes, the team validated this direction by:

- Scaffolding the Rust project and ACME client flow.
- Integrating with Let’s Encrypt **Staging**.
- Producing a small native release artifact (historical benchmark from the sprint write-up: ~5.1 MB stripped).
- Confirming native OS-linked runtime behavior (no Python venv/container required for execution).

## 3) Current architecture (code-level)

### `src/main.rs`
- Defines CLI via `clap` with global paths:
  - `--config-dir`
  - `--work-dir`
  - `--logs-dir`
- Uses `ProjectDirs::from("io", "vouch", "vouch")` for OS-aware default config location.
- Entry command today is `certonly` with:
  - `--domain`
  - `--email`
  - `--out-dir`
- Orchestrates the runtime sequence:
  1. Initialize/load ACME account
  2. Create ACME order
  3. Verify/finalize order

### `src/acme_client.rs`
- Encapsulates ACME behavior in `AcmeClient`.
- Uses `instant-acme` for:
  - account creation/loading
  - order creation
  - authorization polling
  - finalization/certificate retrieval
- Persists account identity in `account_creds.json`.
- Writes certificate material to:
  - `domain.key`
  - `domain.crt`

### `src/interfaces.rs`
- Defines plugin contracts:
  - `Authenticator`
  - `Installer`
  - combined `Plugin`
- Implements `IpcPlugin` for external plugin binaries over JSON-RPC via stdin/stdout.
- Keeps plugin ABI process-boundary-safe (no Rust ABI coupling across separately built binaries).

### `src/lib.rs`
- Exposes `acme_client` and `interfaces` as reusable modules.

## 4) End-to-end flow (current beta behavior)

1. Parse CLI and resolve config directory.
2. Acquire exclusive lock (`account_creds.json.lock`) to prevent concurrent account writes.
3. Load existing ACME credentials or create new account in LE staging.
4. Create DNS identifier order for requested domain.
5. Iterate authorizations and mark HTTP-01 challenge ready (stubbed integration point for real authenticator plugin behavior).
6. Poll order until `Ready`.
7. Finalize order and fetch cert chain.
8. Atomically persist key/cert files.

## 5) Reliability and safety mechanisms

- **Atomic credential and cert writes** using `tempfile` + `persist`.
- **File permissions hardening** (Unix mode `0600`) for sensitive material.
- **Cross-process locking** with `fs3::FileExt::lock_exclusive`.
- **Retry/backoff wrapper** for network/API operations.
- **Dynamic-programming retry planning** (`dynamic_retry_plan`) chooses delay schedule from predefined options based on expected-cost minimization.
- **Bounded IPC response reads** in `IpcPlugin` (`MAX_RPC_RESPONSE_BYTES`) to reduce memory abuse risk.

## 6) Design parity with Certbot model

The project mirrors Certbot’s core extension points by separating:

- challenge fulfillment (`Authenticator`)
- certificate deployment/config changes (`Installer`)
- orchestration core (ACME + control flow)

This supports future first-class plugins (e.g., nginx/apache/webroot style equivalents) without embedding every integration in the core binary.

## 7) Beta caveats / gaps

Current implementation is intentionally incomplete for full production parity:

- Challenge fulfillment is still a stub in core flow.
- `--work-dir` / `--logs-dir` are parsed but not yet fully wired through runtime behavior.
- Default ACME target is Let’s Encrypt staging in current flow.
- No CI/CD workflows (by project decision for beta).

## 8) Practical next milestones

1. Implement concrete authenticator plugin(s) for HTTP-01 and/or DNS-01.
2. Implement installer plugin(s) for real server config deployment.
3. Separate staging vs production ACME directory selection via CLI/config.
4. Add structured logs and explicit error codes for automation integration.
5. Add integration tests around account persistence and finalize flow.

