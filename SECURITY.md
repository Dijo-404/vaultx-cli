# Security Policy

vaultx-cli exists to protect credentials. This document states what it protects,
what trust boundary actually ships today, what it explicitly does not protect
against, and how its claims are verified. Every claim here describes shipped
behavior; aspirational boundaries are labeled as such.

## What vaultx protects

| Asset | Mechanism |
| --- | --- |
| Secret plaintext at rest | AES-256-GCM envelope encryption under a root wrapping key; plaintext values are never stored as content-addressed repository objects. |
| Secret values in agent hands | Broker mediation: agent sessions authorize outbound requests only. Credentials are decrypted and injected inside broker memory and never enter agent environments or MCP tool responses (invariants INV-002/INV-003). There is no secret-retrieval API on any agent-facing interface. |
| Audit integrity | Append-only audit events chained by SHA-256 `prev_hash`; verification detects tampering or truncation of recorded decisions. |
| Policy-driven egress | Default-deny policy engine over the canonical request destination; SSRF guards deny loopback, link-local, private, multicast, unspecified, and metadata-service ranges unless explicitly allowed; redirects require independent authorization and never carry credentials to an unauthorized target. |

## Local developer mode versus hardened deployment

This distinction matters. Read both sections before making security decisions.

### What most users run today (local developer mode)

The CLI, TUI, MCP server, and credential broker all run on one machine under
one user account:

- The trust boundary is **same-user**. The broker protects agents *from*
  secrets; it cannot protect secrets *from your own account*.
- The root wrapping key defaults to a development file store at
  `.vaultx/root.key` (mode 0600), unencrypted at rest. `vaultx doctor` warns
  when this fallback is in use. Any process running as your user can read the
  vault files and decrypt secrets.
- Team-sync login tokens live at `$XDG_RUNTIME_DIR/vaultx/session.json`
  (mode 0600 inside a 0700 runtime directory); that directory lives on OS
  runtime storage and is wiped on reboot.
- Broker IPC runs over a Unix domain socket or named pipe under
  `$XDG_RUNTIME_DIR/vaultx/local/broker.sock` (platform pipe equivalent).

In this mode vaultx provides real protection against prompt-injected agents
reading or misusing credentials, and no protection against malware already
running as your user.

### Hardened/isolated deployment (not yet shipped)

The following boundaries are designed for but **not provided by today's
build**. They require future implementation work and/or operator setup:

- **OS keychain or KMS root keys.** The `WrappingKeyProvider` trait seam
  exists so operators can supply such backends; no OS-keychain or KMS
  implementation ships yet.
- **Container/service isolation of the broker** (strict mode, plan §30):
  running the broker where the agent host has no access to key material.
  Remote/isolated broker transport is not implemented.
- **Remote control plane over TLS with device-key attestation**: sync clients
  independently verify object hashes and signatures, but there is no hosted
  remote broker service.

Until these ship, treat local developer mode's same-user boundary as the
actual security envelope.

## Explicit non-goals

vaultx does **not** protect against:

- Malware running as the same user reading process memory or disk contents.
- A child process started via `vaultx agent run` exfiltrating configuration
  values it legitimately received, or any secret exposed to it by other means.
  Policy controls what enters the child environment once; it cannot police the
  child afterward.
- A fully compromised operating system or kernel.
- Semantic harm of authorized actions. Policy constrains destinations and
  request shapes; an allowed action being unsafe remains your responsibility
  (plan §2.2).
- Upstream credential abuse beyond what the provider token itself permits.
  Scope provider tokens narrowly; the broker adds authorization on top, not
  instead.

vaultx is also not an agent sandbox and not a replacement for Git source
control.

## Reporting a vulnerability

Report privately. Do not open public issues for suspected vulnerabilities.

1. Preferred: GitHub security advisory via the repository's
   **Security → Report a vulnerability** flow.
2. Alternative: email the maintainers at `security@TODO-before-release.example`
   *(placeholder — replace before first release)*.

Include reproduction steps, affected version, and impact assessment. We will
acknowledge receipt and coordinate disclosure with you.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| < 0.1 | No |

## How these claims are verified

Security claims are pinned by automated checks, not prose:

- **Canary tests**: synthetic canary secret values are scanned across every
  rendered output, error message, diff, and audit payload to prove redaction
  discipline (INV-012).
- **Property tests**: spelling-invariance of canonical URLs and decision
  stability under alternate spellings (`crates/vaultx-http/src/canonical.rs`),
  plus default-deny posture of the policy engine
  (`crates/vaultx-policy/src/engine.rs`).
- **Fuzz targets**: parsers including the URL canonicalizer and broker
  protocol decoder, with committed seed corpora and CI smoke runs — see
  [fuzz/README.md](fuzz/README.md).
- **Supply chain**: `cargo deny check` and `cargo audit` run in CI
  ([.github/workflows/ci.yml](.github/workflows/ci.yml)) alongside fmt,
  clippy, workspace tests, platform builds, and npm installer tests.
