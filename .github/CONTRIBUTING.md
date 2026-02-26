# Contributing to Vouch

First off, thank you for considering contributing to Vouch! It's people like you that make Vouch such a great tool.

## Philosophy
Vouch is written entirely in pure Rust. We optimize for memory safety, minimal dependencies, and zero rigid ABIs. The plugin ecosystem primarily operates over cross-process JSON-RPC (`stdio`).

## Development Setup
1. Ensure you have the latest stable Rust compiler installed: `rustup update stable`.
2. Clone the repository and build the project:
   ```bash
   git clone https://github.com/jhulsinger/vouch.git
   cd vouch
   cargo build
   ```

## Pull Request Process
1. Ensure your changes pass strict pedantic linting: `cargo clippy -- -D warnings`.
2. Format your code using `cargo fmt`.
3. Add or update tests as appropriate. Run the test suite with `cargo test`.
4. Submit a Pull Request targeting the `main` branch. A code owner will review your patch.
