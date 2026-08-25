# Contributing to vaultx-cli

vaultx-cli is a security-sensitive project. Before changing behavior, read
[PLAN.md](PLAN.md) — especially §36 (security invariants) and §37 (threat
model) — and [SECURITY.md](SECURITY.md).

## Getting started

Toolchain: stable Rust, pinned by [rust-toolchain.toml](rust-toolchain.toml).
`rustup` picks it up automatically; no separate toolchain input is needed.

Run the full gate chain before every PR:

```sh
cargo build --workspace && \
cargo fmt --all --check && \
cargo clippy --workspace --all-targets --all-features -- -D warnings && \
cargo test --workspace --all-features && \
cargo doc --no-deps
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs the same fmt,
clippy (`-D warnings`), and workspace tests, plus `cargo deny check`,
`cargo audit`, a five-target platform build matrix, and npm installer tests.

npm installer tests:

```sh
cd npm && node --test
```

## Project layout

| Path | Purpose |
| --- | --- |
| `crates/vaultx-types` | Shared strongly typed IDs and DTOs. |
| `crates/vaultx-core` | Application services shared by CLI and TUI. |
| `crates/vaultx-cli` | Clap command surface. |
| `crates/vaultx-tui` | Ratatui application. |
| `crates/vaultx-repository` | Objects, refs, commits, diff, merge. |
| `crates/vaultx-crypto` | AEAD, signatures, fingerprints, secret-safe wrappers. |
| `crates/vaultx-keyring` | Root-key provider seam (file dev fallback today). |
| `crates/vaultx-policy` | Policy model + default-deny rule engine. |
| `crates/vaultx-broker` | Broker service: sessions, injection, egress decisions. |
| `crates/vaultx-broker-client` | IPC/remote broker client. |
| `crates/vaultx-http` | Hardened outbound HTTP engine (canonicalization, SSRF guards). |
| `crates/vaultx-policy-packs` | Semantic pack parser/compiler to generic policies. |
| `crates/vaultx-audit` | Append-only hash-chained audit store. |
| `crates/vaultx-sync-client` | Team sync protocol client. |
| `crates/vaultx-control-plane` | Remote service protocol/store. |
| `crates/vaultx-mcp` | MCP server/tool bridge for agents. |
| `crates/vaultx-testkit` | Security/integration fixtures. |
| `packages/` | npm launcher package scaffold and TypeScript agent SDK scaffold. |
| `policy-packs/` | Declarative provider packs (github, openai, stripe, generic). |
| `fuzz/` | libFuzzer targets with committed seed corpora (workspace-excluded). |

## Conventions

- **Comments**: minimal and rationale-only. Explain *why*; module-level docs
  carry design rationale. No narration of obvious code.
- **Errors**: typed errors with `thiserror` in library crates; binary
  boundaries may attach `anyhow` context without losing redaction.
- **Secret-blind error messages**: error variants and their fields must never
  embed secret values, tokens, or URL query strings. This is pinned by canary
  discipline (INV-012) — see
  `crates/vaultx-broker/src/error.rs` and the test
  `canary_value_never_leaks_through_errors_or_debug_output` in
  `crates/vaultx-core/src/secrets.rs`. If your change renders user-controlled
  or secret-adjacent data anywhere, add a canary assertion.
- **Tests first**: expect TDD. New behavior lands with failing tests written
  first; bug fixes land with a regression test.
- **Commits**: conventional commits with an imperative subject, e.g.
  `fix(broker): reauthorize redirect targets`. Scope by crate or subsystem.

## Security-sensitive changes

Anything touching canonicalization, cryptography, the broker, or the policy
engine must include threat-model reasoning in the PR description: which
adversary from plan §37 you are defending against, which invariants from §36
are exercised, and why the change cannot weaken them.

Property tests exist for spelling-invariance of canonical URLs and the
default-deny posture of the policy engine
(`crates/vaultx-http/src/canonical.rs`,
`crates/vaultx-policy/src/engine.rs`). Extend them when touching those areas;
do not rely on unit tests alone for decision-stability guarantees.

## Pull request process

1. All gates green locally before requesting review.
2. Two-stage review: reviewers first verify **spec compliance** against
   PLAN.md (does it do what the plan says, honestly), then **code quality**
   (structure, style, test coverage).
3. Keep PRs focused; one logical change per PR.

## Fuzzing

Fuzz targets live in [fuzz/](fuzz/) with committed seed corpora. They need a
nightly toolchain and are excluded from the main workspace:

```sh
rustup install nightly
cargo +nightly install cargo-fuzz

cd fuzz
cargo +nightly fuzz run url_canonicalize -- -max_total_time=60
```

Run from the `fuzz/` directory. Crash inputs land in `fuzz/crashes/`;
reproduce one with `cargo +nightly fuzz run <target> <crash-file>`.
See [fuzz/README.md](fuzz/README.md) for the full target list.
