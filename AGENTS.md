# Repository Guidelines

## Project Structure & Module Organization
- Source: `src/` (Rust 2021).
- Entry points: `src/lib.rs` (library), `src/bin/main.rs` (CLI).
- Protocol modules: `src/{stir,whir,fri,basefold}.rs`.
- Shared protocol types: `src/protocol/` (sizes, ratios, display helpers).
- Math and utils: `src/{errors,field,utils}.rs`.
- Tests: unit tests inline via `#[cfg(test)] mod tests`; integration tests in `tests/`.

## Build, Test, and Development Commands
- `cargo build [--release]`: compile (release for faster runs).
- `cargo run [--release]`: run CLI; prints protocol summaries.
- `cargo test`: run unit + integration tests.
- `cargo fmt --all -- --check`: verify formatting.
- `cargo clippy -- -D warnings`: lint; deny warnings (CI parity).

## Coding Style & Naming Conventions
- Formatting: rustfmt defaults (4‑space indents, standard wrapping).
- Naming: `snake_case` (fns/vars), `CamelCase` (types/traits), `SCREAMING_SNAKE_CASE` (consts).
- Module cohesion: one protocol per file; small, pure helpers in `utils.rs`.
- Public API: document parameters and units; prefer `Display` impls for human‑readable output.

## Testing Guidelines
- Framework: `cargo test` (Rust’s built-in).
- Placement: unit tests beside code; integration tests in `tests/`.
- Scope: cover parameter edge cases and formatting paths; avoid long numeric sweeps.
- Local practice: run `cargo test` before any PR.

## Commit & Pull Request Guidelines
- Commits: follow Conventional Commits where practical (e.g., `feat(protocol): add query pow_bits`, `fix(errors): correct log_eta`).
- Messages: imperative, concise; include motivation and issue refs (e.g., `Closes #20`).
- PRs to `main`: must pass CI (fmt, clippy, build, tests); include description, linked issues, and sample `cargo run` output when relevant.

## Security & Configuration
- Status: WIP academic prototype; not for production use.
- Secrets: none required; no network config.
- Parameters: presets in `src/*Parameters` and `src/field.rs` (e.g., `GOLDILOCKS_2`).

