# vaultx-cli — Engineering Plan

> Engineering specification for a Rust-native, LazyGit-style secret/configuration CLI/TUI with Git-like history, team synchronization, and a provider-neutral credential broker for AI agents.

---

# 1. Product objective

Build `vaultx-cli` as one integrated terminal-native security product with these required capabilities:

1. Configuration management.
2. Encrypted secret storage.
3. Git-style change history.
4. LazyGit-class TUI.
5. Trusted workload secret injection.
6. Agent identities and scoped sessions.
7. Provider-neutral credential brokering.
8. Declarative semantic policy packs.
9. Default-deny authorization.
10. Append-only auditing.
11. Team synchronization.
12. Remote/isolated broker operation.
13. MCP integration for coding agents.
14. npm distribution of native Rust binaries.

The central product requirement is:

> **A brokered credential can be used by an agent without the upstream credential becoming part of the agent environment, prompt context, tool output, or normal process-visible configuration.**

The broker is the primary differentiated subsystem. Repository/versioning features support secure configuration management but must not block or dictate the broker architecture.

---

# 2. Product boundary

## 2.1 What vaultx-cli is

`vaultx-cli` is:

- a CLI.
- an interactive TUI.
- an encrypted local vault.
- a content-addressed configuration repository.
- an authorization engine.
- a local/remote credential broker.
- an agent tool interface.
- a team synchronization client.
- a remote control-plane service.

## 2.2 What vaultx-cli is not

It is not:

- a replacement for Git source control.
- a generic password manager.
- an exhaustive SDK for every SaaS API.
- an agent sandbox.
- a guarantee that an authorized action is semantically harmless.
- a custom cryptography project.

The broker prevents secret disclosure and constrains actions. It cannot make an unsafe allowed action safe merely because the secret remains hidden.

---

# 3. Critical architectural decision: generic broker core

The broker must not depend on hand-writing semantic adapters for every provider endpoint.

## Decision

Implement a **provider-neutral policy-controlled outbound request broker** as the core.

The broker understands:

```text
identity
credential reference
scheme
host
port
HTTP method
canonical path
query
headers
body
response constraints
network destination
policy context
```

Provider semantics are represented using declarative policy packs wherever possible.

Example:

```text
github.pull_request.create
             │
             ▼
Declarative policy pack
             │
             ├─ host = api.github.com
             ├─ method = POST
             ├─ path = /repos/{owner}/{repo}/pulls
             ├─ credential injection = github bearer
             ├─ body schema = github.create_pr.v1
             └─ resource constraints
             │
             ▼
Generic broker request policy
```

## Consequences

- The generic broker is always usable.
- GitHub/OpenAI/etc. coverage does not scale linearly with handwritten Rust endpoints.
- Semantic capability names are ergonomic labels, not the security boundary.
- Provider-specific Rust code is limited to cases requiring special signing/protocol behavior.
- The security claim remains accurate even when no semantic policy pack exists.

---

# 4. System architecture

```text
┌───────────────────────────────────────────────────────────────────────────┐
│                             vaultx-cli                                    │
│                                                                           │
│  ┌─────────────────┐        ┌─────────────────┐                            │
│  │ Clap CLI        │        │ Ratatui TUI     │                            │
│  └────────┬────────┘        └────────┬────────┘                            │
│           └──────────────┬───────────┘                                     │
│                          ▼                                                 │
│                ┌────────────────────┐                                      │
│                │ Application Layer  │                                      │
│                └──────┬──────┬──────┘                                      │
│                       │      │                                             │
│        ┌──────────────┘      └─────────────────┐                           │
│        ▼                                       ▼                           │
│ ┌───────────────┐                       ┌───────────────┐                   │
│ │ Repository    │                       │ Policy        │                   │
│ │ + Vault       │                       │ Engine        │                   │
│ └───────┬───────┘                       └───────┬───────┘                   │
│         │                                       │                           │
└─────────┼───────────────────────────────────────┼───────────────────────────┘
          │                                       │
          │                          ┌────────────┘
          │                          ▼
          │                 ┌──────────────────────┐
          │                 │ vaultx-broker        │
          │                 │ separate trust zone  │
          │                 └──────────┬───────────┘
          │                            │
          │                   ┌────────▼─────────┐
          │                   │ Hardened HTTP    │
          │                   │ Egress Engine    │
          │                   └────────┬─────────┘
          │                            │
          │                            ▼
          │                   External APIs
          │
          ▼
┌───────────────────────┐
│ Local encrypted state │
│ objects + SQLite      │
│ OS keyring / KMS      │
└───────────┬───────────┘
            │
            ▼
┌─────────────────────────────┐
│ Team sync/control plane     │
│ PostgreSQL + object storage │
└─────────────────────────────┘
```

---

# 5. Rust workspace

```text
vaultx-cli/
├── Cargo.toml
├── rust-toolchain.toml
├── deny.toml
├── README.md
├── PLAN.md
├── SECURITY.md
├── CONTRIBUTING.md
│
├── crates/
│   ├── vaultx-cli/
│   ├── vaultx-tui/
│   ├── vaultx-core/
│   ├── vaultx-types/
│   ├── vaultx-repository/
│   ├── vaultx-crypto/
│   ├── vaultx-keyring/
│   ├── vaultx-policy/
│   ├── vaultx-broker/
│   ├── vaultx-broker-client/
│   ├── vaultx-http/
│   ├── vaultx-policy-packs/
│   ├── vaultx-audit/
│   ├── vaultx-sync-client/
│   ├── vaultx-control-plane/
│   ├── vaultx-mcp/
│   └── vaultx-testkit/
│
├── packages/
│   ├── vaultx-cli/
│   └── agent-sdk/
│
└── policy-packs/
    ├── github/
    ├── openai/
    ├── stripe/
    └── generic/
```

## Crate responsibilities

### `vaultx-types`

Shared strongly typed identifiers and DTOs.

```rust
ProjectId
WorkspaceId
EnvironmentId
CommitId
ObjectId
SecretId
SecretRevisionId
CredentialRef
PolicyId
AgentId
SessionId
AuditEventId
```

Avoid using interchangeable raw `String` values for security-sensitive IDs.

### `vaultx-core`

Application services shared by CLI and TUI.

Responsibilities:

- project initialization.
- config operations.
- secret operations.
- staging/commit orchestration.
- environment operations.
- agent lifecycle.
- policy operations.
- broker client orchestration.
- sync orchestration.

### `vaultx-repository`

Responsibilities:

- canonical object encoding.
- object hashing.
- object store.
- refs.
- staging/index.
- commits.
- branch operations.
- diff.
- merge.
- environment refs.
- integrity verification.

### `vaultx-crypto`

Responsibilities:

- authenticated encryption.
- envelope key wrapping.
- signatures.
- keyed fingerprints.
- secret-safe wrapper types.
- key derivation only where explicitly required by design.

### `vaultx-keyring`

Responsibilities:

- macOS Keychain integration.
- Windows Credential Manager integration.
- Linux Secret Service/keyring integration.
- abstract wrapping-key access.
- optional KMS-backed implementation interface.

### `vaultx-policy`

Responsibilities:

- internal authorization trait.
- policy model.
- Cedar schema/entity conversion.
- policy parsing/validation.
- decision diagnostics.
- policy pack compilation target.

### `vaultx-http`

Responsibilities:

- URL canonicalization.
- DNS resolution policy.
- IP classification.
- TLS configuration.
- redirect handling.
- request header filtering.
- request size enforcement.
- response size enforcement.
- response sanitization.
- SSRF defenses.

This crate must not know how to retrieve secret plaintext.

### `vaultx-broker`

Responsibilities:

- session authentication.
- authorization calls.
- credential resolution.
- secret decryption inside broker scope.
- credential injection.
- use of `vaultx-http` for outbound transport.
- audit emission.
- IPC/remote API.

### `vaultx-policy-packs`

Responsibilities:

- declarative pack parser.
- schema validation.
- pack-to-generic-policy compilation.
- reusable credential injection templates.

### `vaultx-audit`

Responsibilities:

- structured event schema.
- local append-only storage interface.
- remote ingestion interface.
- export.
- redaction guarantees.

### `vaultx-sync-client`

Responsibilities:

- workspace auth.
- object exchange.
- ref synchronization.
- signature verification.
- conflict detection.
- policy synchronization.

### `vaultx-control-plane`

Responsibilities:

- workspace membership.
- projects.
- devices/public keys.
- encrypted objects.
- refs.
- environment metadata.
- policy metadata.
- agent identities.
- audit events.

### `vaultx-mcp`

Responsibilities:

- MCP server lifecycle.
- agent session binding.
- structured broker tools.
- public config lookup.
- capability listing.

It must not expose brokered secret plaintext.

---

# 6. Technology stack

| Area | Technology |
|---|---|
| Core language | Rust |
| Async runtime | Tokio |
| CLI parsing | Clap |
| TUI | Ratatui |
| Terminal IO | Crossterm |
| Local IPC | Unix domain sockets / Windows named pipes |
| HTTP server | Axum |
| HTTP client | Reqwest |
| TLS | rustls |
| Serialization | Serde |
| Repository encoding | deterministic CBOR or explicit canonical JSON |
| Local DB/index | SQLite + SQLx |
| Control-plane DB | PostgreSQL + SQLx |
| AEAD | AES-256-GCM |
| Signatures | Ed25519 |
| Secret cleanup | zeroize |
| Authorization | Cedar behind internal trait |
| Password/interactive secret input | rpassword or equivalent no-echo terminal input |
| Logging | tracing |
| Error model | thiserror + anyhow at binary boundaries |
| Testing | cargo test |
| Property tests | proptest |
| Fuzzing | cargo-fuzz |
| Supply chain | cargo-deny + cargo-audit |
| npm packaging | platform package + native binary launcher |

Dependencies are selected behind internal traits wherever replacement affects security or portability.

---

# 7. Domain model

```rust
pub enum VariableKind {
    Config,
    Secret,
    Brokered,
    Dynamic,
}

pub struct VariableDefinition {
    pub name: VariableName,
    pub kind: VariableKind,
    pub environment: EnvironmentId,
    pub source: VariableSource,
}

pub struct BrokeredCredential {
    pub id: CredentialRef,
    pub secret_revision: SecretRevisionId,
    pub injection: InjectionTemplateId,
    pub provider_hint: Option<ProviderName>,
}
```

Required entities:

```text
Workspace
Project
Device
Identity
Environment
BranchRef
Commit
Manifest
VariableDefinition
SecretRevision
Credential
Agent
AgentSession
Policy
PolicyBinding
PolicyPack
AuditEvent
Remote
```

---

# 8. Secret-safe type system

Security-sensitive types must not behave like ordinary strings.

Example:

```rust
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}
```

Rules:

- `SecretBytes` has no `Serialize` implementation.
- secret types do not implement `Display`.
- plaintext access uses narrowly scoped closures/accessors.
- clones are discouraged or prohibited.
- errors cannot embed secret values.
- tracing fields use explicit redacted wrappers.

---

# 9. Repository object model

## Object envelope

```rust
pub struct ObjectEnvelope {
    pub format: u16,
    pub object_type: ObjectType,
    pub payload: Vec<u8>,
}
```

Object ID:

```text
sha256(canonical_object_bytes)
```

Object path:

```text
.vaultx/objects/sha256/ab/cdef...
```

Required object categories:

```text
config_value
manifest
commit
policy
policy_pack_reference
environment_definition
secret_revision_metadata
```

Plaintext secret values are excluded from content-addressed objects.

---

# 10. Commit and manifest design

## Manifest

A manifest maps logical variable names and policy/config references to immutable object/revision IDs.

```rust
pub struct Manifest {
    pub entries: BTreeMap<VariableName, ManifestEntry>,
    pub policies: BTreeMap<PolicyName, ObjectId>,
}

pub enum ManifestEntry {
    Config { object: ObjectId },
    Secret { revision: SecretRevisionId },
    Brokered { credential: CredentialRef, revision: SecretRevisionId },
    Dynamic { provider: DynamicProviderRef },
}
```

## Commit

```rust
pub struct Commit {
    pub format: u16,
    pub parents: Vec<CommitId>,
    pub manifest: ObjectId,
    pub author: IdentityRef,
    pub message: String,
    pub signature: Signature,
}
```

The signed payload excludes mutable storage metadata.

## Refs

```text
refs/heads/main
refs/heads/feature/auth
refs/environments/development
refs/environments/staging
refs/environments/production
```

Environment refs include protection policy metadata rather than behaving as unrestricted branches.

---

# 11. Staging, diff, merge, rollback

## Staging

The staging index records intended manifest changes.

Operations:

```bash
vaultx add <name>
vaultx add --all
vaultx restore <name>
vaultx status
```

## Diff

Diff categories:

```text
config added/removed/changed
secret revision changed
credential binding changed
variable kind changed
policy changed
policy pack changed
environment protection changed
```

Secret diff output contains metadata only.

## Merge

Merge engine rules:

- normal config supports three-way merge.
- secret revisions are atomic values.
- conflicting secret revisions require explicit selection.
- policy conflicts require explicit resolution.
- environment protection metadata cannot silently weaken through merge.

## Rollback

Rollback creates a new state referencing historical objects/revisions rather than mutating history.

If a historical secret revision is crypto-shredded, rollback reports that the revision is unavailable and requires a replacement value.

---

# 12. Encryption and key hierarchy

## Envelope encryption

```text
Root wrapping key
      │
      ├── wraps project key
      │          │
      │          ├── wraps secret revision DEK A
      │          ├── wraps secret revision DEK B
      │          └── wraps fingerprint key
      │
      └── device identity key stored separately according to signature design
```

## Secret revision record

```rust
pub struct EncryptedSecretRevision {
    pub id: SecretRevisionId,
    pub secret_id: SecretId,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub wrapped_dek: Vec<u8>,
    pub aad: SecretRevisionAad,
    pub fingerprint: SecretFingerprint,
}
```

AAD binds:

```text
project ID
secret ID
revision ID
variable kind
format version
```

## Key storage modes

### Local secure-key mode

Root wrapping material is stored using native secure credential storage.

### Client-controlled team encryption

Remote service stores ciphertext and public metadata while clients retain project-unwrapping authority.

### Managed KMS mode

Project key wrapping is delegated to a configured KMS/HSM backend.

All modes satisfy the same `KeyProvider` trait.

---

# 13. Crypto-shredding

Destroying a historical secret revision must not require deleting commit history.

```rust
pub enum SecretRevisionState {
    Active,
    Revoked,
    Destroyed,
}
```

`Destroyed` means the key material required for plaintext recovery has been irreversibly removed according to the configured key backend.

Historical metadata remains auditable.

---

# 14. CLI architecture

Binary:

```text
vaultx
```

Command tree:

```text
vaultx
├── init
├── status
├── doctor
├── set
├── get
├── unset
├── list
├── import
├── secret
│   ├── set
│   ├── metadata
│   ├── rotate
│   └── destroy
├── add
├── restore
├── commit
├── log
├── show
├── diff
├── branch
├── checkout
├── merge
├── rollback
├── env
│   ├── create
│   ├── list
│   ├── protect
│   └── inspect
├── promote
├── run
├── agent
│   ├── create
│   ├── list
│   ├── inspect
│   ├── policy
│   ├── run
│   ├── sessions
│   └── revoke
├── broker
│   ├── serve
│   ├── status
│   └── request
├── policy
│   ├── list
│   ├── edit
│   ├── validate
│   ├── test
│   └── explain
├── pack
│   ├── list
│   ├── add
│   ├── inspect
│   └── validate
├── mcp
│   └── serve
├── audit
│   ├── list
│   ├── inspect
│   └── export
├── remote
│   ├── add
│   ├── list
│   └── remove
├── login
├── workspace
├── push
├── pull
└── sync
```

Every command uses application services; command handlers contain parsing and presentation logic only.

---

# 15. TUI architecture

## Layout

Primary panes:

```text
Environments / Branches
Variables
History
Inspector
```

Switchable functional views:

```text
Dashboard
Diff
Commit
Agents
Agent Sessions
Policy Editor
Audit
Environments
Sync
Doctor
Help
```

## Application model

```rust
pub struct App {
    pub route: Route,
    pub project: ProjectView,
    pub panes: PaneState,
    pub selection: SelectionState,
    pub command_palette: CommandPalette,
    pub modal: Option<Modal>,
    pub notifications: Vec<Notification>,
}
```

Use an event/update/render architecture:

```text
Terminal event
      │
      ▼
Action
      │
      ▼
Update application state
      │
      ├─ synchronous domain result
      └─ async command result
      │
      ▼
Render
```

## TUI rules

- keyboard operation is complete without mouse support.
- each view exposes contextual keybindings.
- destructive actions require explicit confirmation.
- secret values are masked by default.
- brokered credentials are represented as non-revealable in agent context.
- diff views never render plaintext secret content.
- denied agent requests are visually distinct in audit views.
- terminal resize must preserve usable layout.
- small terminals use stacked/detail views rather than clipping critical fields.

---

# 16. Trusted workload execution

`vaultx run -- <command>` is for applications explicitly allowed to receive secret plaintext.

Pipeline:

```text
Resolve environment manifest
        │
        ▼
Authorize workload execution
        │
        ▼
Decrypt permitted normal secrets
        │
        ▼
Construct child environment in memory
        │
        ▼
Spawn child
        │
        ▼
Clear parent secret buffers where practical
```

Brokered credentials are excluded by default from `vaultx run` and require an explicit policy that converts them into normal workload exposure. This keeps "brokered" semantically meaningful.

No plaintext `.env` file is created.

---

# 17. Agent runner

Command:

```bash
vaultx agent run coding-agent -- claude
```

The runner performs:

```text
Load agent identity
      │
      ▼
Resolve project/environment
      │
      ▼
Create scoped broker session
      │
      ▼
Build sanitized child environment
      │
      ├─ public config allowed by policy
      ├─ broker endpoint
      ├─ session capability
      └─ agent identity metadata
      │
      ▼
Spawn agent
```

The runner explicitly strips managed secret names from inherited environment variables when configured as protected/brokered.

The runner cannot prevent an arbitrary same-user process from reading unrelated secrets already present elsewhere on the machine. Strict protection requires broker/key isolation at the OS/container/remote boundary.

---

# 18. Broker process

## Process boundary

Local mode:

```text
Agent process
    │
    │ Unix socket / named pipe
    ▼
vaultx-broker process
    │
    ├─ session auth
    ├─ policy engine
    ├─ vault access
    └─ hardened HTTP client
```

Strict mode:

```text
Agent host/container
    │
    │ authenticated remote broker protocol
    ▼
Isolated vaultx-broker
    │
    ├─ isolated key access
    └─ external provider network
```

## Local endpoint

Unix-like systems:

```text
$XDG_RUNTIME_DIR/vaultx/<project-id>/broker.sock
```

Windows:

```text
\\.\pipe\vaultx-<project-id>
```

The socket/pipe is protected using platform permissions and peer identity checks where available.

---

# 19. Broker protocol

Use a versioned structured protocol over local IPC and HTTPS for remote operation.

Example request:

```json
{
  "protocol": 1,
  "session": "sess_...",
  "credential": "github-work-token",
  "method": "POST",
  "url": "https://api.github.com/repos/acme/backend/pulls",
  "headers": {
    "accept": "application/vnd.github+json"
  },
  "body": {
    "title": "Fix auth bug",
    "head": "fix/auth",
    "base": "main"
  },
  "capability_hint": "github.pull_request.create"
}
```

Important rule:

`capability_hint` is informational/ergonomic. Authorization is performed against the actual canonical request plus policy context.

Response:

```json
{
  "request_id": "req_...",
  "status": 201,
  "headers": {
    "content-type": "application/json"
  },
  "body": {
    "...": "sanitized provider response"
  },
  "decision": "allow"
}
```

Denied response:

```json
{
  "request_id": "req_...",
  "decision": "deny",
  "reason": "path_not_allowed",
  "policy": "coding-agent-github"
}
```

Do not include secret-bearing diagnostics.

---

# 20. Generic HTTP egress engine

This subsystem is security critical.

## Request canonicalization

The engine must establish one canonical representation for authorization and transport.

Normalize/validate:

- scheme.
- host.
- IDNA handling.
- port.
- path.
- percent encoding.
- query parsing.
- duplicate headers.
- authority/Host relationship.

Policy evaluates the same canonical destination that transport uses.

## SSRF protections

Default network deny categories:

```text
loopback
link-local
private address space
multicast
unspecified addresses
metadata-service ranges
Unix/file/custom schemes
```

Explicit policy can enable required private destinations.

DNS resolution must be bound to the validated connection target to reduce rebinding opportunities.

## Redirect handling

Redirects are treated as new destinations requiring authorization.

Credential injection is not copied to a redirect target unless the redirected request independently satisfies policy for that credential.

## Header controls

Agent input cannot control sensitive hop/auth headers such as:

```text
Authorization
Proxy-Authorization
Host
Connection
Transfer-Encoding
```

unless a narrowly defined broker rule permits a specific safe form.

## Body controls

Policies support:

- maximum bytes.
- content-type constraints.
- optional JSON schema.
- JSON field allow/deny constraints.
- semantic pack schema validation.

## Response controls

Policies support:

- maximum bytes.
- header redaction.
- JSON field redaction.
- content-type allowlists.
- binary response policy.

The broker applies global secret-pattern redaction as a defense-in-depth measure but does not rely on redaction as the primary secret protection mechanism.

---

# 21. Credential injection

Credential material enters the request only inside the broker.

Supported injection template interface:

```rust
pub trait CredentialInjector: Send + Sync {
    fn id(&self) -> InjectionTemplateId;
    fn apply(
        &self,
        request: &mut OutboundRequest,
        secret: &SecretBytes,
        metadata: &CredentialMetadata,
    ) -> Result<(), InjectionError>;
}
```

Built-in templates:

```text
bearer
basic_password
api_key_header
github_bearer
query_parameter
aws_sigv4
custom_static_header_plus_secret
```

Specialized code such as AWS SigV4 is justified because the credential participates in request signing rather than simple field injection.

The agent chooses a logical credential reference, not an injection implementation.

---

# 22. Authorization model

Define an internal abstraction:

```rust
pub trait Authorizer: Send + Sync {
    fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision;
}
```

Authorization request:

```rust
pub struct AuthorizationRequest {
    pub principal: Principal,
    pub action: Action,
    pub resource: Resource,
    pub context: AuthorizationContext,
}
```

Broker mapping:

```text
principal = agent/session identity
action    = http.request
resource  = credential logical ID
context   = canonical host/method/path/query/body metadata/environment
```

Default decision is deny.

Cedar is the production policy evaluator behind this trait.

The transport layer still enforces hard invariants that policies cannot disable accidentally.

---

# 23. Policy format

Human-editable YAML can compile into Cedar entities/policies plus broker transport rules.

Example:

```yaml
name: coding-agent-github
principal: agent:coding-agent
credential: github-work-token

environment:
  allow:
    - development

http:
  hosts:
    - api.github.com

  allow:
    - methods: [GET]
      paths:
        - /repos/acme/backend/**

    - methods: [POST]
      paths:
        - /repos/acme/backend/pulls

  deny:
    - methods: [DELETE]
      paths: ["/**"]

request:
  max_body_bytes: 262144
  deny_headers:
    - authorization
    - proxy-authorization

response:
  max_body_bytes: 1048576
  redact_headers:
    - set-cookie
```

CLI:

```bash
vaultx policy validate
vaultx policy test coding-agent-github --fixture tests/policies/create-pr.json
vaultx policy explain --agent coding-agent --request request.json
```

---

# 24. Semantic policy packs

## Pack schema

```rust
pub struct PolicyPack {
    pub name: CapabilityName,
    pub provider: ProviderName,
    pub request: PackRequestTemplate,
    pub credential: PackCredentialBinding,
    pub constraints: PackConstraints,
    pub response: Option<PackResponseRules>,
}
```

Pack examples:

```text
github.repository.read
github.pull_request.create
openai.responses.create
stripe.customer.read
```

## Pack compiler

Compiler output:

```text
semantic name
+ variable constraints
+ request schema
+ credential template
        │
        ▼
generic broker rule set
```

Pack compiler must reject a pack that attempts to weaken global broker invariants.

## Generic path remains first-class

An agent may be permitted to call an API with no semantic pack:

```text
credential = internal-api-token
host       = api.internal.example
method     = POST
path       = /v2/jobs/submit
```

The policy remains explicit and auditable without requiring provider integration code.

---

# 25. Agent sessions and capabilities

## Agent identity

```rust
pub struct AgentIdentity {
    pub id: AgentId,
    pub project: ProjectId,
    pub policy_bindings: Vec<PolicyId>,
    pub enabled: bool,
}
```

## Session

```rust
pub struct AgentSession {
    pub id: SessionId,
    pub agent: AgentId,
    pub environment: EnvironmentId,
    pub capability_token_hash: TokenHash,
    pub revoked: bool,
}
```

Store only a verifier/hash for bearer-style local session tokens where feasible.

## Delegation

```rust
pub struct DelegationRequest {
    pub parent_session: SessionId,
    pub requested_policy_subset: PolicySubset,
}
```

Verification property:

```text
child effective authority ⊆ parent effective authority
```

Delegation can narrow credentials, environments, hosts, paths, methods, and budget constraints.

---

# 26. MCP integration

Command:

```bash
vaultx mcp serve --agent coding-agent
```

Required MCP tools:

## `vaultx.list_capabilities`

Returns logical capabilities and generic scopes visible to the session.

## `vaultx.config_get`

Returns allowed non-sensitive configuration.

## `vaultx.http_request`

Input:

```json
{
  "credential": "github-work-token",
  "method": "GET",
  "url": "https://api.github.com/repos/acme/backend/issues",
  "headers": {},
  "body": null
}
```

Output is the sanitized broker response.

## `vaultx.capability_request`

Allows invocation using a semantic policy-pack name plus structured parameters.

Example:

```json
{
  "capability": "github.pull_request.create",
  "arguments": {
    "owner": "acme",
    "repo": "backend",
    "title": "Fix auth",
    "head": "fix/auth",
    "base": "main"
  }
}
```

The pack generates a concrete broker request and passes it through normal authorization.

No MCP tool returns brokered secret plaintext.

---

# 27. Audit architecture

Audit events must capture decisions without becoming a secret exfiltration surface.

```rust
pub struct AuditEvent {
    pub id: AuditEventId,
    pub correlation_id: CorrelationId,
    pub actor: Principal,
    pub project: ProjectId,
    pub environment: Option<EnvironmentId>,
    pub action: AuditAction,
    pub decision: AuditDecision,
    pub credential: Option<CredentialRef>,
    pub destination: Option<SafeDestinationSummary>,
    pub capability: Option<CapabilityName>,
    pub policy_ids: Vec<PolicyId>,
    pub metadata: SafeAuditMetadata,
}
```

Do not store:

- credential plaintext.
- Authorization header values.
- entire unfiltered request bodies.
- entire unfiltered provider responses.
- session bearer tokens.

Audit integrity can use chained event hashes and signatures where configured.

---

# 28. Team synchronization and control plane

Team use is part of the product scope, not a disconnected add-on.

## Control-plane services

```text
Auth service
Workspace service
Project service
Object sync service
Ref service
Policy service
Device key service
Agent identity service
Audit ingestion/query
```

## PostgreSQL schema

Core tables:

```sql
users
workspaces
workspace_members
projects
devices
project_members
objects
refs
environments
policies
policy_bindings
agent_identities
agent_sessions
audit_events
sync_state
```

Encrypted object payloads can live in object storage with hashes/metadata in PostgreSQL.

## Sync protocol

Client sends:

```text
known object IDs
known refs
signed device identity
requested project
```

Server returns:

```text
missing encrypted objects
remote refs
policy metadata
environment metadata
signature/public-key material
```

Client verifies content hashes and signatures independently.

## Conflict behavior

- immutable objects never conflict by ID.
- refs can conflict.
- ref conflicts require merge/reconciliation.
- protected environment refs reject unauthorized updates.
- sync never silently chooses a secret revision conflict.

---

# 29. Authentication and identity

## Local developer identity

Device identity uses an Ed25519 key pair protected through local secure-key storage.

## Team identity

Remote user authentication obtains a workspace session used for control-plane API access.

Device keys are registered separately so commits and sensitive operations can be cryptographically attributed to a device identity.

## CI/workload identity

Prefer federated/OIDC identity exchange where deployment platforms provide it.

Avoid requiring a permanent vaultx-cli master token as the default CI pattern.

## Agent identity

Agent sessions are subordinate to an authenticated human/workload/project context and a stored agent policy binding.

---

# 30. Remote/isolated broker

The same broker protocol supports an isolated deployment where the agent has no OS-level access to vault keys.

```text
Agent
  │
  │ scoped authenticated request
  ▼
Remote Broker Gateway
  │
  ├─ agent/session auth
  ├─ Cedar decision
  ├─ credential decrypt/KMS operation
  ├─ hardened egress
  └─ audit
  │
  ▼
Provider
```

Strict mode requirements:

- broker key access unavailable to agent host.
- mutually authenticated channel or equivalent workload identity.
- replay protections for session/capability protocol.
- explicit egress policy.
- no secret-returning broker API.
- administrative reveal path separate from agent broker API.

---

# 31. Dynamic credentials

Dynamic credentials implement:

```rust
#[async_trait]
pub trait DynamicCredentialProvider: Send + Sync {
    async fn issue(&self, request: IssueRequest) -> Result<IssuedCredential>;
    async fn revoke(&self, lease: LeaseId) -> Result<()>;
}
```

Examples:

- short-lived database users.
- cloud STS credentials.
- provider-scoped delegated tokens.

Agent access still flows through the broker where possible. A dynamic provider can reduce upstream standing privilege without changing the agent interface.

---

# 32. Local database

SQLite is an index/query store rather than the sole source of repository truth.

Suggested tables:

```sql
variables
secret_revisions
credential_bindings
staging_entries
local_refs
agents
agent_sessions
policies
policy_bindings
policy_packs
audit_events
remotes
sync_state
```

Migrations are versioned and transactional.

Canonical immutable objects remain recoverable independently of the index where design permits.

---

# 33. Config import/export

## Import

```bash
vaultx import .env
```

Classifier uses conservative heuristics.

Likely config:

```text
PORT
LOG_LEVEL
NODE_ENV
PUBLIC_URL
FEATURE_*
```

Likely secret:

```text
*_TOKEN
*_KEY
*_SECRET
*_PASSWORD
DATABASE_URL
```

The UI presents classifications for confirmation.

Known API credential patterns can suggest `brokered` rather than normal `secret`.

## Export

Safe export:

```bash
vaultx export --format env
```

exports config values and placeholders for protected values.

Plaintext secret export requires explicit high-friction authorization and must never include brokered credentials in an agent context.

---

# 34. Logging and redaction

Use `tracing` with structured fields.

Global requirements:

- no secret values.
- no bearer session tokens.
- no Authorization headers.
- no decrypted payload dumps.
- no full request body logging by default.
- credential references are logical IDs only.

Implement redaction wrappers:

```rust
SecretDebug<T>
SafeUrl
SafeHeaders
SafeAuditMetadata
```

Panic/error paths should be tested with synthetic canary secrets and scanned for leakage.

---

# 35. Error model

Library crates define typed errors with `thiserror`.

Binary boundaries can attach context with `anyhow` while preserving redaction.

Security-relevant categories:

```text
AuthenticationDenied
AuthorizationDenied
CredentialUnavailable
SecretDestroyed
PolicyInvalid
DestinationDenied
NetworkInvariantViolation
RepositoryIntegrityError
SignatureInvalid
CryptoError
SyncConflict
```

Provider error payloads pass through sanitization rules rather than being blindly embedded in diagnostic text.

---

# 36. Security invariants

```text
INV-001  Plaintext secrets are never repository content-addressed objects.
INV-002  Brokered credentials are never injected into agent environments.
INV-003  Brokered credentials are never returned by broker/MCP APIs.
INV-004  Agent-controlled Authorization headers cannot override credential injection.
INV-005  Canonical destination used for policy equals transport destination.
INV-006  Redirects require independent authorization.
INV-007  Credentials never cross to an unauthorized redirect target.
INV-008  Private-network egress is default-denied.
INV-009  Policy defaults to deny.
INV-010  Semantic policy packs cannot bypass generic broker invariants.
INV-011  Child agent authority cannot exceed parent authority.
INV-012  Secret values are redacted from logs/errors/audit/diffs.
INV-013  Secret destruction does not require history mutation.
INV-014  Remote objects are hash-verified.
INV-015  Signed objects/commits are verified across trust boundaries.
INV-016  TUI and CLI share application services.
INV-017  The generic broker works without provider-specific endpoint code.
INV-018  Credential injection occurs only inside broker scope.
INV-019  Secret-bearing headers are not agent-controlled.
INV-020  Administrative secret reveal is separate from agent capabilities.
```

These invariants should be encoded in tests wherever technically possible.

---

# 37. Threat model

## Assets

- upstream credentials.
- encryption keys.
- project configuration.
- policy definitions.
- commit history.
- environment refs.
- agent session capabilities.
- audit integrity.

## Adversaries

### Prompt-injected agent

Can intentionally attempt to:

- read secret values.
- call unauthorized hosts.
- call unauthorized paths.
- use redirects.
- target internal metadata endpoints.
- override auth headers.
- encode data into allowed requests.

Mitigations:

- no secret retrieval API.
- broker process separation.
- destination policy.
- body constraints.
- SSRF defense.
- credential injection controls.
- audit.

### Malicious same-user local process

Can potentially access OS resources granted to that account.

Local developer mode does not claim complete isolation from this adversary.

Mitigation for strong guarantees:

- isolated broker identity/container/VM/remote service.
- inaccessible key material.
- strict IPC permissions.

### Compromised sync server

Mitigations:

- content hashes.
- client verification.
- signed metadata.
- client-controlled encryption option.
- server never treated as trusted plaintext storage in E2EE mode.

### Compromised repository files

Mitigations:

- object hashing.
- signature verification.
- authenticated encryption.
- index reconstruction validation.

### Compromised provider credential

vaultx-cli cannot restore upstream least privilege beyond what the provider credential itself allows.

Mitigations:

- narrow upstream tokens where supported.
- dynamic credentials.
- provider rotation/revocation.
- broker policy as an additional authorization layer.

---

# 38. TUI implementation requirements

The TUI must feel closer to LazyGit than to a command launcher.

## Dashboard

```text
┌─ env/branch ──────┬─ variables ───────────┬─ history ──────────────┐
│                   │                       │                        │
│                   │                       │                        │
├───────────────────┴───────────────────────┴────────────────────────┤
│ inspector / diff / selected agent policy                          │
├────────────────────────────────────────────────────────────────────┤
│ contextual key bindings                                           │
└────────────────────────────────────────────────────────────────────┘
```

## Agent view

Show:

```text
identity
session state
environment
credential logical names
allowed hosts
allowed methods
allowed paths
semantic capabilities
recent allow/deny audit entries
```

Never render actual brokered credential values.

## Policy editor

Provide both:

- form/tree editing for common rules.
- raw YAML/Cedar view for advanced users.

Validation occurs continuously on edited state without applying invalid policy.

## Diff view

Secret change:

```diff
 GITHUB_TOKEN
- revision sec_rev_A
+ revision sec_rev_B
```

Policy change:

```diff
 api.github.com
+ POST /repos/acme/backend/pulls
- DELETE /**
```

---

# 39. Control-plane API outline

Example REST resources:

```text
POST   /auth/session
GET    /workspaces
POST   /workspaces
GET    /projects/{id}
POST   /projects/{id}/objects/batch
POST   /projects/{id}/objects/query-missing
GET    /projects/{id}/refs
PUT    /projects/{id}/refs/{name}
GET    /projects/{id}/policies
PUT    /projects/{id}/policies/{name}
GET    /projects/{id}/agents
POST   /projects/{id}/agents
GET    /projects/{id}/audit
```

Remote broker resources are separate from ordinary control-plane management APIs.

Administrative APIs must not accidentally share a route surface that can be reached by an agent session token.

---

# 40. npm distribution

Package name:

```text
vaultx-cli
```

Installer package responsibilities:

- detect OS/architecture.
- select platform artifact.
- verify artifact checksum/signature metadata.
- expose `vaultx` executable.
- provide clear unsupported-platform errors.

Example platform artifacts:

```text
vaultx-linux-x86_64
vaultx-linux-aarch64
vaultx-darwin-x86_64
vaultx-darwin-aarch64
vaultx-windows-x86_64.exe
```

The JavaScript installer contains no secret-management implementation.

---

# 41. CI and supply-chain requirements

Required checks:

```text
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
cargo audit
property tests
fuzz smoke corpus
platform build checks
npm installer tests
```

Security-sensitive dependencies should be minimal and explicitly reviewed.

Use lockfiles and reproducible build practices where supported.

Binary artifacts must carry integrity metadata.

---

# 42. Test matrix

## Repository

- object canonicalization.
- hash stability.
- corrupt object rejection.
- ref update validation.
- merge conflicts.
- secret metadata diffs.
- destroyed revision behavior.

## Crypto

- encrypt/decrypt.
- nonce uniqueness strategy.
- AAD mismatch rejection.
- wrapped-key corruption.
- signature verification.
- wrong project binding.
- zeroization wrappers.

## Broker

- allowed host.
- denied host.
- denied method.
- denied path.
- auth header override attempt.
- redirect host change.
- redirect method change.
- DNS/private IP resolution.
- malformed URL encodings.
- query constraints.
- body schema enforcement.
- response redaction.
- credential injection.

## Agent

- sanitized environment.
- brokered secret absent.
- public config allowed.
- revoked session denied.
- child delegation attenuation.
- MCP tool behavior.

## Sync

- multi-client object exchange.
- signed object verification.
- conflicting refs.
- protected environment ref rejection.
- corrupted remote object.

## TUI

- navigation.
- resize.
- modal confirmation.
- status rendering.
- secret masking.
- diff redaction.
- policy validation state.
- audit filters.

---

# 43. Fuzz/property targets

Fuzz:

```text
repository object decoder
manifest decoder
policy parser
policy pack compiler
broker protocol parser
URL canonicalizer
header parser
response sanitizer
diff/merge engine
```

Properties:

```text
decode(encode(x)) == x for canonical domain objects
hash canonicalization is stable
child_policy ⊆ parent_policy
denied canonical request cannot become allowed through alternate URL spelling
secret Debug/Display never contains plaintext
merge never silently selects conflicting secret revisions
```

---

# 44. Operational commands

## `vaultx doctor`

Checks:

```text
repository integrity
SQLite integrity
keyring availability
signing key availability
broker socket permissions
broker connectivity
policy validity
remote connectivity
registered device identity
sync consistency
```

Output must not expose secret material.

## Recovery

Recovery tooling supports:

- rebuilding SQLite indexes from canonical objects.
- validating refs.
- validating signatures.
- detecting missing secret revisions.
- importing encrypted backups.

Project key recovery design depends on configured key mode and must be explicit in documentation.

---

# 45. Public interfaces

## Rust application services

```rust
#[async_trait]
pub trait VaultService {
    async fn set_config(&self, cmd: SetConfig) -> Result<()>;
    async fn set_secret(&self, cmd: SetSecret) -> Result<SecretRevisionId>;
    async fn stage(&self, cmd: Stage) -> Result<()>;
    async fn commit(&self, cmd: CommitChanges) -> Result<CommitId>;
}

#[async_trait]
pub trait BrokerService {
    async fn create_session(&self, cmd: CreateAgentSession) -> Result<AgentSessionHandle>;
    async fn execute(&self, req: BrokerRequest) -> Result<BrokerResponse>;
    async fn revoke_session(&self, id: SessionId) -> Result<()>;
}

pub trait Authorizer {
    fn authorize(&self, req: &AuthorizationRequest) -> AuthorizationDecision;
}

#[async_trait]
pub trait SyncService {
    async fn push(&self, project: ProjectId) -> Result<SyncResult>;
    async fn pull(&self, project: ProjectId) -> Result<SyncResult>;
}
```

## TypeScript agent SDK

Optional ergonomic layer over the local broker/MCP endpoint:

```typescript
import { VaultxClient } from "@vaultx-cli/agent";

const vaultx = new VaultxClient();

const issues = await vaultx.request({
  credential: "github-work-token",
  method: "GET",
  url: "https://api.github.com/repos/acme/backend/issues"
});
```

SDK intentionally has no `getBrokeredSecret()` function.

---

# 46. Complete implementation workstreams

The codebase is considered complete only when all workstreams below are implemented and integrated. These are parallel architectural workstreams, not staged product versions.

## Repository and configuration

- [x] workspace/crate structure exists.
- [x] `vaultx init` creates repository state.
- [x] config set/get/unset/list works.
- [x] `.env` import works.
- [x] staging works.
- [x] canonical object encoding works.
- [x] content-addressed object storage works.
- [x] signed commits work.
- [x] branches work.
- [x] diff works.
- [x] merge works.
- [x] rollback works.
- [x] environment refs/protection work.
- [x] promotion works.

## Secret vault

- [x] no-echo secret input works.
- [x] AES-GCM secret encryption works.
- [x] envelope keys work.
- [x] platform key store works.
- [x] secret revision metadata works.
- [x] keyed fingerprints work.
- [x] secret rotation works.
- [x] crypto-shredding works.
- [x] secret-safe Rust wrappers are used across boundaries.

## Broker

- [x] broker runs as a separate process/service.
- [x] local IPC works on Unix-like systems.
- [x] local IPC works on Windows.
- [x] agent session authentication works.
- [x] generic broker request API works.
- [x] credential injection templates work.
- [x] canonical URL validation works.
- [x] DNS/IP restrictions work.
- [x] redirect reauthorization works.
- [x] request header restrictions work.
- [x] body constraints work.
- [x] response sanitization works.
- [x] audit events are emitted.
- [ ] isolated/remote broker transport works.

## Authorization

- [x] internal authorizer trait exists.
- [ ] Cedar integration works.
- [x] default-deny behavior is enforced.
- [x] human-readable policy format works.
- [x] validation works.
- [x] policy test fixtures work.
- [x] policy explanation works.
- [ ] child-agent attenuation works.

## Semantic policy packs

- [x] pack format is versioned.
- [x] pack parser works.
- [x] pack schema validation works.
- [x] pack compiler emits generic broker constraints.
- [x] GitHub representative packs exist.
- [x] OpenAI representative packs exist.
- [x] generic custom API packs work.
- [x] packs cannot weaken broker invariants.

## Agent integrations

- [x] `vaultx agent create` works.
- [ ] `vaultx agent run` works.
- [ ] managed secret variables are stripped from agent environment.
- [ ] public config exposure is policy-controlled.
- [x] session revocation works.
- [x] MCP server works.
- [x] generic HTTP MCP tool works.
- [x] semantic capability MCP tool works.
- [x] brokered secret retrieval is impossible through agent interfaces.

## Trusted workload execution

- [x] `vaultx run` works.
- [x] allowed secrets are injected in memory.
- [x] temporary plaintext `.env` files are not created.
- [x] brokered credentials remain non-exposed by default.

## TUI

- [x] main LazyGit-style layout works.
- [x] environment/branch pane works.
- [x] variable pane works.
- [x] history pane works.
- [x] inspector works.
- [x] diff view works.
- [x] commit view works.
- [x] agent view works.
- [x] policy editor works.
- [x] audit view works.
- [ ] environment promotion view works.
- [ ] sync view works.
- [x] keyboard navigation is complete.
- [x] resize behavior is robust.

## Team sync/control plane

- [x] remote authentication works.
- [x] workspaces work.
- [x] membership works.
- [x] project sync works.
- [x] encrypted object transfer works.
- [x] remote refs work.
- [x] signature verification works.
- [ ] policy sync works.
- [ ] agent identity sync works.
- [ ] audit ingestion/query works.
- [x] client-controlled encryption mode works.
- [x] conflict handling works.

## Packaging

- [x] Linux x86_64 binary.
- [x] Linux ARM64 binary.
- [x] macOS x86_64 binary.
- [x] macOS ARM64 binary.
- [x] Windows x86_64 binary.
- [x] `vaultx-cli` npm package.
- [x] artifact integrity verification.
- [x] installer smoke tests.

## Security quality

- [x] unit test matrix passes.
- [x] integration test matrix passes.
- [ ] property tests pass.
- [ ] fuzz targets have seed corpora.
- [x] canary-secret leak tests pass.
- [x] SSRF test suite passes.
- [x] redirect leakage tests pass.
- [x] repository tamper tests pass.
- [x] cargo-deny passes.
- [x] cargo-audit passes.
- [x] threat model matches implemented behavior.
- [ ] security claims distinguish local developer mode from isolated broker mode.

---

# 47. Definition of done

`vaultx-cli` is done only when a clean installation can demonstrate the complete flow below without exposing a brokered secret.

```bash
npm install -g vaultx-cli

mkdir demo && cd demo
vaultx init
vaultx import .env
vaultx secret set GITHUB_TOKEN --brokered
vaultx add --all
vaultx commit -m "configure project"

vaultx agent create coding-agent
vaultx agent policy edit coding-agent
vaultx agent run coding-agent -- claude
```

Inside the agent session:

- allowed config is visible.
- `GITHUB_TOKEN` plaintext is absent from the environment.
- the agent can make a permitted GitHub request through MCP/broker.
- an unauthorized host is denied.
- an unauthorized GitHub operation is denied.
- an attempt to supply its own `Authorization` header is rejected.
- the audit view shows both allowed and denied operations.

The same project can then:

```bash
vaultx branch config-change
vaultx checkout config-change
vaultx set API_URL=https://new.example.com
vaultx add --all
vaultx commit -m "change api endpoint"
vaultx diff main config-change
vaultx merge main
```

and:

```bash
vaultx workspace create acme
vaultx remote add origin <workspace>
vaultx push
vaultx pull
```

with encrypted objects, signed metadata, policy state, and protected refs remaining valid across clients.

The TUI must expose the same repository, secret, agent, policy, audit, environment, and sync operations through keyboard-driven workflows.

---

# 48. Final architecture statement

The final product is intentionally not structured as four loosely connected projects.

```text
                       vaultx-cli
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
   Config/history      Secret vault     Agent authority
          │                │                │
          └──────────┬─────┴───────┬────────┘
                     │             │
                     ▼             ▼
                Policy engine   Credential broker
                     │             │
                     └──────┬──────┘
                            ▼
                     Hardened egress
                            │
                            ▼
                       External API
```

The configuration store gives developers Git-like operational control.

The encrypted vault protects credential material.

The authorization layer defines what an identity may do.

The broker turns that authority into credential-backed actions without handing the upstream credential to the agent.

The TUI makes the whole model usable from one terminal interface.

That combination is the product.
