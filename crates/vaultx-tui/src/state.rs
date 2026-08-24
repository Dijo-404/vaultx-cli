//! Headless application state machine for the vaultx TUI (plan §15).
//!
//! [`App`] owns every mutable UI state and exposes pure transition
//! methods — [`App::handle_key`] / [`App::handle_resize`] — returning an
//! [`Effect`] describing the external action the terminal loop should
//! perform (reload snapshots, persist a policy, revoke a session, quit).
//! Nothing here touches crossterm, ratatui, or the filesystem, so the
//! whole machine is unit-testable without a terminal (plan §42 "TUI").
//!
//! Keyboard operation is complete; mouse events are never read.

use std::collections::BTreeMap;

use vaultx_policy::{HttpMethod, MethodPathRule};

use crate::mask::RedactedLine;

/// Terminal widths at or below this switch the dashboard to stacked mode.
pub const STACKED_MIN_WIDTH: u16 = 100;
/// Terminal heights at or below this switch the dashboard to stacked mode.
pub const STACKED_MIN_HEIGHT: u16 = 22;

// ---------------------------------------------------------------------------
// Input model (backend-agnostic)
// ---------------------------------------------------------------------------

/// Keys the state machine understands; crossterm maps onto this in the
/// terminal loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyCode {
    /// A character key.
    Char(char),
    /// Enter.
    Enter,
    /// Escape.
    Esc,
    /// Tab.
    Tab,
    /// Arrow up.
    Up,
    /// Arrow down.
    Down,
    /// Arrow left.
    Left,
    /// Arrow right.
    Right,
    /// Backspace.
    Backspace,
    /// Delete.
    Delete,
    /// Home.
    Home,
    /// End.
    End,
}

/// One key press with its control modifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyInput {
    /// Physical key.
    pub code: KeyCode,
    /// Ctrl held.
    pub ctrl: bool,
}

// ---------------------------------------------------------------------------
// Views, panes, filters
// ---------------------------------------------------------------------------

/// Top-level switchable views (plan §15); digits 1–5 select them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Route {
    /// LazyGit-style dashboard (env/branch · variables · history ·
    /// inspector · contextual bindings).
    #[default]
    Dashboard,
    /// Redacted staged diff.
    Diff,
    /// Agent identities, sessions, policy surface, recent audit.
    Agents,
    /// Policy editor (form/tree + raw YAML) with continuous validation.
    PolicyEditor,
    /// Local audit trail with outcome filters.
    Audit,
}

impl Route {
    /// All routes in tab order.
    pub const ALL: [Route; 5] = [
        Route::Dashboard,
        Route::Diff,
        Route::Agents,
        Route::PolicyEditor,
        Route::Audit,
    ];

    /// Tab label including its selecting digit.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Dashboard => "1 dashboard",
            Self::Diff => "2 diff",
            Self::Agents => "3 agents",
            Self::PolicyEditor => "4 policy",
            Self::Audit => "5 audit",
        }
    }

    /// Zero-based tab position.
    #[must_use]
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|r| *r == self).unwrap_or(0)
    }

    /// Route selected by a digit key, if any.
    #[must_use]
    pub fn from_digit(c: char) -> Option<Self> {
        let index = match c {
            '1' => 0,
            '2' => 1,
            '3' => 2,
            '4' => 3,
            '5' => 4,
            _ => return None,
        };
        Self::ALL.get(index).copied()
    }
}

/// Focused dashboard pane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pane {
    /// Environments / branch pane.
    Environments,
    /// Variables pane (config plain; secret/brokered masked).
    Variables,
    /// History pane.
    History,
}

const PANES: [Pane; 3] = [Pane::Environments, Pane::Variables, Pane::History];

impl Pane {
    /// Next pane in cycle order.
    #[must_use]
    pub fn next(self) -> Self {
        let i = PANES.iter().position(|p| *p == self).unwrap_or(0);
        PANES[(i + 1) % PANES.len()]
    }

    /// Pane title shown in the block border.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::Environments => "env/branch",
            Self::Variables => "variables",
            Self::History => "history",
        }
    }
}

/// Audit outcome filter (plan §42 "audit filters": allow/deny minimum).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutcomeFilter {
    /// Show every event.
    #[default]
    All,
    /// Show allows only.
    Allow,
    /// Show denies only.
    Deny,
}

impl OutcomeFilter {
    /// Cycles All → Allow → Deny → All.
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::All => Self::Allow,
            Self::Allow => Self::Deny,
            Self::Deny => Self::All,
        }
    }

    /// Maps onto `vaultx_audit::AuditFilter::decision_allow`.
    #[must_use]
    pub fn allows_only(self) -> Option<bool> {
        match self {
            Self::All => None,
            Self::Allow => Some(true),
            Self::Deny => Some(false),
        }
    }

    /// Human label for titles/status.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshot rows (plain owned data loaded from vaultx-core services)
// ---------------------------------------------------------------------------

/// Broker reachability probed through `--socket` (or the platform default
/// endpoint). Offline never fails the UI; panes degrade with notes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerStatus {
    /// The broker answered a ping with this version string.
    Online(String),
    /// The endpoint could not be reached; payload names it.
    Offline(String),
}

impl Default for BrokerStatus {
    fn default() -> Self {
        Self::Offline("not probed yet".to_owned())
    }
}

impl BrokerStatus {
    /// Status-line fragment.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Online(version) => format!("broker online ({version})"),
            Self::Offline(reason) => format!("broker offline — {reason}"),
        }
    }
}

/// One environment row.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct EnvRow {
    /// Bare environment name.
    pub name: String,
    /// Protection flag.
    pub protected: bool,
    /// Short pinned-commit id, when pinned.
    pub commit_short: Option<String>,
}

/// One variable row of the HEAD manifest. Secret/brokered references are
/// pre-masked by the loader; the view masks again defensively.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariableRow {
    /// Variable name.
    pub name: String,
    /// Kind (`config`, `secret`, `brokered`, `dynamic`).
    pub kind: String,
    /// Kind reference (object id / revision id / credential@revision),
    /// already masked for secret kinds.
    pub reference: String,
}

/// One history row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryRow {
    /// Short commit id.
    pub short: String,
    /// First line of the commit message.
    pub message: String,
    /// Author identity.
    pub author: String,
}

/// Everything the chrome and dashboard need from one project load.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Snapshot {
    /// Current branch (`None` on detached HEAD).
    pub branch: Option<String>,
    /// Short HEAD commit id.
    pub head_short: Option<String>,
    /// Selected environment name.
    pub env: Option<String>,
    /// Environment rows.
    pub envs: Vec<EnvRow>,
    /// Variable rows of the HEAD manifest (secret refs masked).
    pub variables: Vec<VariableRow>,
    /// Recent history rows, newest first.
    pub history: Vec<HistoryRow>,
    /// Graceful-degradation notes surfaced on the status line.
    pub notes: Vec<String>,
}

/// Derived session liveness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStatus {
    /// Usable session.
    Active,
    /// Permanently revoked.
    Revoked,
    /// Past its expiry.
    Expired,
}

impl SessionStatus {
    /// Display token.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Revoked => "REVOKED",
            Self::Expired => "EXPIRED",
        }
    }
}

/// One stored agent session (verifier metadata only; raw tokens never
/// live in storage).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRow {
    /// Session id.
    pub session_id: String,
    /// Environment the session operates in.
    pub environment: String,
    /// Derived liveness.
    pub status: SessionStatus,
}

/// One agent list row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRow {
    /// Bare agent name.
    pub name: String,
    /// Enablement flag.
    pub enabled: bool,
}

/// One audit row rendered by audit views. Denied rows stay visually
/// distinct via styling plus the explicit `DENY` token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRow {
    /// Store sequence number.
    pub sequence: u64,
    /// Actor principal string.
    pub actor: String,
    /// Action label.
    pub action: String,
    /// Authorization outcome.
    pub allowed: bool,
    /// Denial category (never request content), when denied.
    pub deny_reason: Option<String>,
    /// Safe host/port/path destination summary, when present.
    pub destination: Option<String>,
}

/// Aggregated per-agent view data (plan §38 "Agent view"). Credential
/// material is represented as logical names marked non-revealable; there
/// is deliberately no code path that could render brokered values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentDetail {
    /// Full prefixed id (`agent_<bare>`).
    pub full_id: String,
    /// Enablement flag.
    pub enabled: bool,
    /// Attached policy names.
    pub policies: Vec<String>,
    /// Logical credential names across attached policies.
    pub credentials: Vec<String>,
    /// Allowed hosts union.
    pub allowed_hosts: Vec<String>,
    /// Allowed methods union (allow rules).
    pub allowed_methods: Vec<String>,
    /// Allowed paths union (allow rules).
    pub allowed_paths: Vec<String>,
    /// Semantic capability names found in the project pack tree.
    pub capabilities: Vec<String>,
    /// Stored sessions, or why they are unavailable.
    pub sessions: Result<Vec<SessionRow>, String>,
    /// Recent allow/deny audit entries for this agent.
    pub audit: Vec<AuditRow>,
}

impl Default for AgentDetail {
    fn default() -> Self {
        Self {
            full_id: String::new(),
            enabled: false,
            policies: Vec::new(),
            credentials: Vec::new(),
            allowed_hosts: Vec::new(),
            allowed_methods: Vec::new(),
            allowed_paths: Vec::new(),
            capabilities: Vec::new(),
            sessions: Ok(Vec::new()),
            audit: Vec::new(),
        }
    }
}

impl AgentDetail {
    /// Session-state summary line used by views and tests.
    #[must_use]
    pub fn session_summary(&self) -> String {
        match &self.sessions {
            Ok(rows) if rows.is_empty() => "no sessions".to_owned(),
            Ok(rows) => rows
                .iter()
                .map(|r| format!("{} {} in {}", r.session_id, r.status.label(), r.environment))
                .collect::<Vec<_>>()
                .join("; "),
            Err(reason) => format!("sessions unavailable: {reason}"),
        }
    }
}

/// Sub-focus inside the agents view.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AgentFocus {
    /// The agent list.
    #[default]
    List,
    /// The selected agent's session list.
    Sessions,
}

/// Agents list plus per-agent details keyed by bare name.
#[derive(Clone, Debug, Default)]
pub struct AgentsData {
    /// List rows in display order.
    pub list: Vec<AgentRow>,
    /// Detail per bare name.
    pub details: BTreeMap<String, AgentDetail>,
}

/// Everything one refresh produces; [`crate::run`] feeds it to [`App::new`]
/// and re-feeds after [`Effect::Refresh`].
#[derive(Clone, Debug, Default)]
pub struct LoadedState {
    /// Project snapshot for the chrome and dashboard.
    pub snapshot: Snapshot,
    /// Redacted staged-diff lines.
    pub diff: Vec<RedactedLine>,
    /// Agent rows and details.
    pub agents: AgentsData,
    /// Filtered audit rows.
    pub audit: Vec<AuditRow>,
    /// Broker probe result.
    pub broker: BrokerStatus,
    /// Stored policy names (sorted); seeds the editor target.
    pub policy_names: Vec<String>,
    /// Initial YAML for the editor (existing document or template).
    pub editor_seed: String,
}

impl LoadedState {
    /// Document name the editor starts on.
    #[must_use]
    pub fn editor_target(&self) -> String {
        self.policy_names
            .first()
            .cloned()
            .unwrap_or_else(|| "new-policy".to_owned())
    }
}

// ---------------------------------------------------------------------------
// Modals and effects
// ---------------------------------------------------------------------------

/// Destructive action awaiting confirmation inside a modal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingAction {
    /// Persist the edited policy document.
    ApplyPolicy,
    /// Revoke one stored session permanently.
    RevokeSession {
        /// Exact session id.
        session_id: String,
    },
}

/// Blocking confirmation modal (plan §15: destructive actions require
/// explicit confirmation). While open every other key is inert except
/// confirm/cancel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Modal {
    /// Title line.
    pub title: String,
    /// Body lines explaining the action.
    pub body: Vec<String>,
    /// Action executed on confirmation.
    pub action: PendingAction,
}

impl Modal {
    /// Footer hint rendered under the body.
    #[must_use]
    pub fn hint(&self) -> &'static str {
        "y confirm · n cancel"
    }
}

/// External action requested by a state transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Nothing external to do.
    None,
    /// Leave the UI loop.
    Quit,
    /// Reload every snapshot from the application services.
    Refresh,
    /// Save the edited policy YAML (already validated and confirmed).
    ApplyPolicy {
        /// File name (and declared name) for the document.
        expected_name: String,
        /// Full YAML text.
        yaml: String,
    },
    /// Revoke one stored session permanently.
    RevokeSession {
        /// Exact session id.
        session_id: String,
    },
}

// ---------------------------------------------------------------------------
// Text buffer + policy editor
// ---------------------------------------------------------------------------

/// Minimal caret-anchored multi-line text buffer shared by the raw YAML
/// editor and form fields.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TextBuffer {
    /// Lines (no trailing newlines).
    pub lines: Vec<String>,
    /// Caret row.
    pub row: usize,
    /// Caret column (char offset).
    pub col: usize,
}

impl TextBuffer {
    /// Builds a buffer from text split on `\n`.
    #[must_use]
    pub fn from_text(text: &str) -> Self {
        let lines: Vec<String> = if text.is_empty() {
            vec![String::new()]
        } else {
            text.split('\n').map(str::to_owned).collect()
        };
        Self {
            lines,
            row: 0,
            col: 0,
        }
    }

    /// Joins lines back into text.
    #[must_use]
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    fn clamp_caret(&mut self) {
        self.row = self.row.min(self.lines.len() - 1);
        let len = self.lines[self.row].chars().count();
        self.col = self.col.min(len);
    }

    /// Inserts one character at the caret.
    pub fn insert_char(&mut self, c: char) {
        let line = &mut self.lines[self.row];
        let byte = char_to_byte(line, self.col);
        line.insert(byte, c);
        self.col += 1;
    }

    /// Deletes backward (joins with the previous line at column 0).
    pub fn backspace(&mut self) {
        if self.col > 0 {
            let line = &mut self.lines[self.row];
            let byte = char_to_byte(line, self.col - 1);
            line.remove(byte);
            self.col -= 1;
        } else if self.row > 0 {
            let prev_len = self.lines[self.row - 1].chars().count();
            let current = self.lines.remove(self.row);
            self.row -= 1;
            self.lines[self.row].push_str(&current);
            self.col = prev_len;
        }
    }

    /// Deletes forward (joins with the next line at end of line).
    pub fn delete(&mut self) {
        let len = self.lines[self.row].chars().count();
        if self.col < len {
            let line = &mut self.lines[self.row];
            let byte = char_to_byte(line, self.col);
            line.remove(byte);
        } else if self.row + 1 < self.lines.len() {
            let next = self.lines.remove(self.row + 1);
            self.lines[self.row].push_str(&next);
        }
    }

    /// Splits the current line at the caret.
    pub fn newline(&mut self) {
        let line = &mut self.lines[self.row];
        let byte = char_to_byte(line, self.col);
        let rest = line.split_off(byte);
        self.row += 1;
        self.col = 0;
        self.lines.insert(self.row, rest);
    }

    /// Moves the caret horizontally, wrapping across line boundaries.
    pub fn move_horizontal(&mut self, delta: i32) {
        match delta.signum() {
            -1 if self.col == 0 && self.row > 0 => {
                self.row -= 1;
                self.col = self.lines[self.row].chars().count();
            }
            1 if self.col == self.lines[self.row].chars().count()
                && self.row + 1 < self.lines.len() =>
            {
                self.row += 1;
                self.col = 0;
            }
            _ => {
                self.col = (self.col as i32 + delta).max(0) as usize;
            }
        }
        self.clamp_caret();
    }

    /// Moves the caret vertically, clamping columns.
    pub fn move_vertical(&mut self, delta: i32) {
        self.row = (self.row as i32 + delta).max(0) as usize;
        self.clamp_caret();
    }

    /// Jumps to start of line.
    pub fn home(&mut self) {
        self.col = 0;
    }

    /// Jumps to end of line.
    pub fn end(&mut self) {
        self.col = self.lines[self.row].chars().count();
    }
}

fn char_to_byte(line: &str, char_index: usize) -> usize {
    line.char_indices()
        .nth(char_index)
        .map_or(line.len(), |(byte, _)| byte)
}

/// Editable form fields (plan §38: form/tree editing for common rules).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FormField {
    /// Principal (`agent:<name>`).
    Principal,
    /// Credential logical ref.
    Credential,
    /// Comma-separated host list.
    Hosts,
    /// Allow rules, one `METHOD PATH` per line.
    AllowRules,
    /// Deny rules, one `METHOD PATH` per line.
    DenyRules,
}

const EDITABLE_FIELDS: [FormField; 5] = [
    FormField::Principal,
    FormField::Credential,
    FormField::Hosts,
    FormField::AllowRules,
    FormField::DenyRules,
];

impl FormField {
    /// Row label shown in the form pane.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Principal => "principal",
            Self::Credential => "credential",
            Self::Hosts => "hosts",
            Self::AllowRules => "allow rules",
            Self::DenyRules => "deny rules",
        }
    }
}

/// Form-side draft mirrored into canonical YAML. Raw-mode edits win once
/// the user switches modes; the draft reloads only from valid raw input.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyDraft {
    /// Principal field.
    pub principal: TextBuffer,
    /// Credential field.
    pub credential: TextBuffer,
    /// Hosts field (comma separated).
    pub hosts: TextBuffer,
    /// Allow rules field (`METHOD PATH` lines).
    pub allow_rules: TextBuffer,
    /// Deny rules field (`METHOD PATH` lines).
    pub deny_rules: TextBuffer,
}

/// Continuous-validation result shown while editing (plan §38: invalid
/// state is visibly flagged and can never be applied).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationState {
    /// The edited document parses and validates.
    Valid,
    /// The edited document is invalid; applying is blocked. Payload is
    /// the parser/validation message (policy documents carry no secrets).
    Invalid(String),
}

/// Initial skeleton inserted into an empty editor.
pub const TEMPLATE_YAML: &str = "\
name: new-policy
principal: agent:my-agent
credential: my-credential
http:
  hosts: [api.example.com]
  allow:
    - methods: [GET]
      paths: [\"/**\"]
";

/// Editor representation toggle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditorMode {
    /// Structured form for common rules.
    Form,
    /// Raw YAML view for advanced users.
    Raw,
}

/// Full editor state: mode, buffers, caret, validation badge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyEditorState {
    /// Declared document name (file stem); fixed while editing.
    pub target_name: String,
    /// Form vs raw editing mode.
    pub mode: EditorMode,
    /// Form fields.
    pub draft: PolicyDraft,
    /// Raw YAML buffer.
    pub raw: TextBuffer,
    /// Selected editable form field.
    pub field_cursor: usize,
    /// Whether keystrokes edit the selected field.
    pub editing_field: bool,
    /// Latest continuous-validation result.
    pub validation: ValidationState,
}

impl PolicyEditorState {
    /// Creates an editor seeded from `base_yaml` (an existing document's
    /// canonical serialization, or [`TEMPLATE_YAML`]).
    #[must_use]
    pub fn new(target_name: impl Into<String>, base_yaml: &str) -> Self {
        let mut editor = Self {
            target_name: target_name.into(),
            mode: EditorMode::Form,
            draft: PolicyDraft::default(),
            raw: TextBuffer::from_text(base_yaml),
            field_cursor: 0,
            editing_field: false,
            validation: ValidationState::Invalid("not validated yet".to_owned()),
        };
        if let Ok(document) = vaultx_policy::parse_policy_yaml(base_yaml) {
            editor.draft = PolicyDraft::from_document(&document);
        }
        editor.revalidate();
        editor
    }

    /// Whether the editor consumes every keystroke (raw mode or active
    /// field editing) instead of letting global keys through.
    #[must_use]
    pub fn capture_all_keys(&self) -> bool {
        self.mode == EditorMode::Raw || self.editing_field
    }

    /// Effective source-of-truth text: the raw buffer in raw mode, the
    /// canonical serialization of the draft in form mode.
    #[must_use]
    pub fn effective_yaml(&self) -> String {
        match self.mode {
            EditorMode::Raw => self.raw.text(),
            EditorMode::Form => self.draft.to_yaml(&self.target_name),
        }
    }

    /// Re-parses the effective document; runs after every mutation so
    /// validation stays continuous (plan §38).
    pub fn revalidate(&mut self) {
        self.validation = match self.mode {
            EditorMode::Form => match self.draft.build_document(&self.target_name) {
                Ok(_) => ValidationState::Valid,
                Err(message) => ValidationState::Invalid(message),
            },
            EditorMode::Raw => match vaultx_policy::parse_policy_yaml(&self.raw.text()) {
                Ok(_) => ValidationState::Valid,
                Err(error) => ValidationState::Invalid(error.to_string()),
            },
        };
    }

    /// True when the current document may be applied.
    #[must_use]
    pub fn can_apply(&self) -> bool {
        self.validation == ValidationState::Valid
    }

    /// Switches to raw mode, regenerating the buffer from the draft.
    pub fn toggle_to_raw(&mut self) {
        self.editing_field = false;
        self.raw = TextBuffer::from_text(&self.effective_yaml());
        self.mode = EditorMode::Raw;
        self.revalidate();
    }

    /// Switches back to form mode. Fails (returning the message) while the
    /// raw buffer is invalid: the draft must never absorb garbage.
    ///
    /// # Errors
    /// Returns the parse/validation message when the raw YAML is invalid.
    pub fn toggle_to_form(&mut self) -> Result<(), String> {
        let document =
            vaultx_policy::parse_policy_yaml(&self.raw.text()).map_err(|e| e.to_string())?;
        self.draft = PolicyDraft::from_document(&document);
        self.mode = EditorMode::Form;
        self.revalidate();
        Ok(())
    }

    /// Applies one key to the active editing surface, then revalidates.
    #[must_use]
    pub fn handle_key(&mut self, k: KeyInput) -> Effect {
        if self.mode == EditorMode::Raw {
            apply_text_key(&mut self.raw, k);
        } else if self.editing_field {
            let field = EDITABLE_FIELDS[self.field_cursor];
            match k.code {
                KeyCode::Esc | KeyCode::Tab => self.editing_field = false,
                KeyCode::Enter
                    if !matches!(field, FormField::AllowRules | FormField::DenyRules) =>
                {
                    self.editing_field = false;
                }
                KeyCode::Enter => self.draft.field_mut(field).newline(),
                _ => apply_text_key(self.draft.field_mut(field), k),
            }
        }
        self.revalidate();
        Effect::None
    }
}

fn apply_text_key(buffer: &mut TextBuffer, k: KeyInput) {
    match k.code {
        KeyCode::Char(c) => buffer.insert_char(c),
        KeyCode::Backspace => buffer.backspace(),
        KeyCode::Delete => buffer.delete(),
        KeyCode::Enter => buffer.newline(),
        KeyCode::Left => buffer.move_horizontal(-1),
        KeyCode::Right => buffer.move_horizontal(1),
        KeyCode::Up => buffer.move_vertical(-1),
        KeyCode::Down => buffer.move_vertical(1),
        KeyCode::Home => buffer.home(),
        KeyCode::End => buffer.end(),
        KeyCode::Esc | KeyCode::Tab => {}
    }
}

impl PolicyDraft {
    /// Builds the draft from an already-validated document.
    #[must_use]
    pub fn from_document(document: &vaultx_policy::PolicyDocument) -> Self {
        let hosts = document.http.hosts.join(", ");
        let rules_text = |rules: &[vaultx_policy::MethodPathRule]| -> String {
            let mut lines = Vec::new();
            for rule in rules {
                for method in &rule.methods {
                    for path in &rule.paths {
                        lines.push(format!("{} {}", method.as_str(), path));
                    }
                }
            }
            lines.join("\n")
        };
        Self {
            principal: TextBuffer::from_text(document.principal.as_str()),
            credential: TextBuffer::from_text(document.credential.as_str()),
            hosts: TextBuffer::from_text(&hosts),
            allow_rules: TextBuffer::from_text(&rules_text(&document.http.allow)),
            deny_rules: TextBuffer::from_text(&rules_text(&document.http.deny)),
        }
    }

    fn field_mut(&mut self, field: FormField) -> &mut TextBuffer {
        match field {
            FormField::Principal => &mut self.principal,
            FormField::Credential => &mut self.credential,
            FormField::Hosts => &mut self.hosts,
            FormField::AllowRules => &mut self.allow_rules,
            FormField::DenyRules => &mut self.deny_rules,
        }
    }

    /// Parses the form fields into a validated document, or a reason the
    /// document cannot be built (surfaced by the validation badge).
    ///
    /// # Errors
    /// Returns a message whenever any field fails identifier parsing or
    /// the assembled document fails semantic validation.
    pub fn build_document(
        &self,
        expected_name: &str,
    ) -> Result<vaultx_policy::PolicyDocument, String> {
        use vaultx_policy::{
            validate_policy, EnvironmentRules, HttpRules, Principal, RequestConstraints,
            ResponseConstraints,
        };
        use vaultx_types::{CredentialRef, PolicyName};

        let name = PolicyName::parse(expected_name).map_err(|e| format!("name: {e}"))?;
        let principal = Principal::parse(self.principal.text().trim())
            .map_err(|e| format!("principal: {e}"))?;
        let credential_raw = self.credential.text().trim().to_owned();
        let credential =
            CredentialRef::parse(&credential_raw).map_err(|e| format!("credential: {e}"))?;
        let hosts: Vec<String> = self
            .hosts
            .text()
            .split(',')
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_owned)
            .collect();
        if hosts.is_empty() {
            return Err("http.hosts: must contain at least one entry".to_owned());
        }
        let allow = parse_rule_lines(&self.allow_rules.text())?;
        let deny = parse_rule_lines(&self.deny_rules.text())?;
        if allow.is_empty() {
            return Err("http.allow: must contain at least one rule".to_owned());
        }
        let document = vaultx_policy::PolicyDocument {
            name,
            principal,
            credential,
            environment: EnvironmentRules::default(),
            http: HttpRules { hosts, allow, deny },
            request: RequestConstraints::default(),
            response: ResponseConstraints::default(),
        };
        validate_policy(&document).map_err(|e| e.to_string())?;
        Ok(document)
    }

    /// Canonical YAML for the draft (raw-mode seed and applies). Falls
    /// back to an empty string when the draft is invalid; the validation
    /// badge explains why.
    #[must_use]
    pub fn to_yaml(&self, expected_name: &str) -> String {
        self.build_document(expected_name)
            .ok()
            .and_then(|doc| serde_yaml::to_string(&doc).ok())
            .unwrap_or_default()
    }
}

fn parse_rule_lines(text: &str) -> Result<Vec<MethodPathRule>, String> {
    let mut rules = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((method_raw, path)) = line.split_once(' ') else {
            return Err(format!("rule `{line}` must be `METHOD PATH`"));
        };
        let method = parse_http_method(method_raw)?;
        rules.push(MethodPathRule {
            methods: vec![method],
            paths: vec![path.trim().to_owned()],
        });
    }
    Ok(rules)
}

fn parse_http_method(raw: &str) -> Result<HttpMethod, String> {
    match raw.to_ascii_uppercase().as_str() {
        "GET" => Ok(HttpMethod::GET),
        "POST" => Ok(HttpMethod::POST),
        "PUT" => Ok(HttpMethod::PUT),
        "PATCH" => Ok(HttpMethod::PATCH),
        "DELETE" => Ok(HttpMethod::DELETE),
        "HEAD" => Ok(HttpMethod::HEAD),
        "OPTIONS" => Ok(HttpMethod::OPTIONS),
        other => Err(format!("unsupported HTTP method `{other}`")),
    }
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

/// Mutable selections for the three dashboard panes.
#[derive(Clone, Copy, Debug, Default)]
struct DashboardSelection {
    focus: Option<Pane>,
    environments: usize,
    variables: usize,
    history: usize,
}

/// The whole TUI state machine (plan §15 application model).
#[derive(Debug)]
pub struct App {
    /// Active route.
    pub route: Route,
    /// Set when the user asked to leave.
    pub quit_requested: bool,
    /// Transient status-line message.
    pub status: String,
    /// Open confirmation modal, if any.
    pub modal: Option<Modal>,
    /// Last observed terminal size (defaults until the first resize).
    pub size: (u16, u16),
    /// Loaded project data.
    pub loaded: LoadedState,
    /// Staged-diff scroll position.
    pub diff_selected: usize,
    /// Selected agent row.
    pub agent_selected: usize,
    /// Agents-view sub-focus.
    pub agent_focus: AgentFocus,
    /// Selected session row within the focused agent.
    pub session_selected: usize,
    /// Policy editor state.
    pub editor: PolicyEditorState,
    /// Audit filter and row selection.
    pub audit_filter: OutcomeFilter,
    pub audit_selected: usize,
    selection: DashboardSelection,
}

impl App {
    /// Builds the app around freshly loaded project data.
    #[must_use]
    pub fn new(loaded: LoadedState) -> Self {
        let base_yaml = if loaded.editor_seed.is_empty() {
            TEMPLATE_YAML.to_owned()
        } else {
            loaded.editor_seed.clone()
        };
        let editor = PolicyEditorState::new(loaded.editor_target(), &base_yaml);
        Self {
            route: Route::Dashboard,
            quit_requested: false,
            status: String::new(),
            modal: None,
            size: (120, 36),
            loaded,
            selection: DashboardSelection::default(),
            diff_selected: 0,
            agent_selected: 0,
            agent_focus: AgentFocus::default(),
            session_selected: 0,
            editor,
            audit_filter: OutcomeFilter::default(),
            audit_selected: 0,
        }
    }

    /// Stacked/detail layout kicks in at or below either size threshold so
    /// critical fields stack instead of clipping (plan §15 TUI rules).
    #[must_use]
    pub fn stacked_layout(&self) -> bool {
        self.size.0 <= STACKED_MIN_WIDTH || self.size.1 <= STACKED_MIN_HEIGHT
    }

    /// Handles one resize event; layout derivation happens on render.
    pub fn handle_resize(&mut self, width: u16, height: u16) {
        self.size = (width.max(1), height.max(1));
    }

    /// Focused dashboard pane (defaults to the first pane).
    #[must_use]
    pub fn focus(&self) -> Pane {
        self.selection.focus.unwrap_or(Pane::Environments)
    }

    /// Selected indices `(environments, variables, history)`.
    #[must_use]
    pub fn selections(&self) -> (usize, usize, usize) {
        (
            self.selection.environments,
            self.selection.variables,
            self.selection.history,
        )
    }

    /// Id of the highlighted session row, when one exists.
    #[must_use]
    pub fn selected_session_id(&self) -> Option<String> {
        let bare = self
            .loaded
            .agents
            .list
            .get(self.agent_selected)?
            .name
            .as_str();
        let rows = self
            .loaded
            .agents
            .details
            .get(bare)?
            .sessions
            .as_ref()
            .ok()?;
        Some(rows.get(self.session_selected)?.session_id.clone())
    }

    /// Pure state transition for one key press.
    #[must_use]
    pub fn handle_key(&mut self, k: KeyInput) -> Effect {
        // Ctrl+C always quits, even inside modals/editors.
        if k.ctrl && k.code == KeyCode::Char('c') {
            self.quit_requested = true;
            return Effect::Quit;
        }

        // Modal: only confirm/cancel are meaningful.
        if self.modal.is_some() {
            return self.handle_modal_key(k);
        }

        // Capture-mode editors swallow everything except the chords above
        // and the two handled here.
        if self.route == Route::PolicyEditor && self.editor.capture_all_keys() {
            if k.ctrl && k.code == KeyCode::Char('s') {
                return self.request_apply_policy();
            }
            if k.code == KeyCode::Esc {
                if self.editor.mode == EditorMode::Raw {
                    if let Err(message) = self.editor.toggle_to_form() {
                        self.status = format!("staying in raw mode: invalid yaml ({message})");
                    } else {
                        self.status = "raw edits accepted into the form".to_owned();
                    }
                    return Effect::None;
                }
                self.editor.editing_field = false;
                return Effect::None;
            }
            return self.editor.handle_key(k);
        }

        // Global navigation.
        if let KeyCode::Char(c) = k.code {
            if !k.ctrl {
                if let Some(route) = Route::from_digit(c) {
                    self.switch_route(route);
                    return Effect::None;
                }
                match c {
                    'q' => {
                        self.quit_requested = true;
                        return Effect::Quit;
                    }
                    'r' => return Effect::Refresh,
                    _ => {}
                }
            }
        }

        match self.route {
            Route::Dashboard => self.dashboard_key(k),
            Route::Diff => {
                scroll(
                    &mut self.diff_selected,
                    self.loaded.diff.len(),
                    vertical_delta(k),
                );
                Effect::None
            }
            Route::Agents => self.agents_key(k),
            Route::Audit => self.audit_key(k),
            Route::PolicyEditor => self.policy_editor_key(k),
        }
    }

    fn switch_route(&mut self, route: Route) {
        self.route = route;
        self.editor.editing_field = false;
        self.status.clear();
    }

    fn dashboard_key(&mut self, k: KeyInput) -> Effect {
        match k.code {
            KeyCode::Tab => self.selection.focus = Some(self.focus().next()),
            KeyCode::Up | KeyCode::Down => {
                let delta = vertical_delta(k);
                let lens = (
                    self.loaded.snapshot.envs.len(),
                    self.loaded.snapshot.variables.len(),
                    self.loaded.snapshot.history.len(),
                );
                let focused = self.focus();
                let selection = &mut self.selection;
                match focused {
                    Pane::Environments => scroll(&mut selection.environments, lens.0, delta),
                    Pane::Variables => scroll(&mut selection.variables, lens.1, delta),
                    Pane::History => scroll(&mut selection.history, lens.2, delta),
                }
            }
            _ => {}
        }
        Effect::None
    }

    fn agents_key(&mut self, k: KeyInput) -> Effect {
        match k.code {
            KeyCode::Tab => {
                self.agent_focus = match self.agent_focus {
                    AgentFocus::List => AgentFocus::Sessions,
                    AgentFocus::Sessions => AgentFocus::List,
                };
            }
            KeyCode::Char('x') if self.agent_focus == AgentFocus::Sessions => {
                if let Some(session_id) = self.selected_session_id() {
                    self.request_revoke_session(session_id);
                }
            }
            KeyCode::Up | KeyCode::Down => {
                let delta = vertical_delta(k);
                match self.agent_focus {
                    AgentFocus::List => {
                        scroll(
                            &mut self.agent_selected,
                            self.loaded.agents.list.len(),
                            delta,
                        );
                        self.session_selected = 0;
                    }
                    AgentFocus::Sessions => {
                        let len = self
                            .focused_agent_detail()
                            .and_then(|detail| detail.sessions.as_ref().ok())
                            .map_or(0, Vec::len);
                        scroll(&mut self.session_selected, len, delta);
                    }
                }
            }
            _ => {}
        }
        Effect::None
    }

    fn audit_key(&mut self, k: KeyInput) -> Effect {
        if k.code == KeyCode::Char('f') && !k.ctrl {
            self.audit_filter = self.audit_filter.next();
            self.audit_selected = 0;
            self.status = format!("audit filter: {}", self.audit_filter.label());
            return Effect::Refresh;
        }
        scroll(
            &mut self.audit_selected,
            self.loaded.audit.len(),
            vertical_delta(k),
        );
        Effect::None
    }

    fn focused_agent_detail(&self) -> Option<&AgentDetail> {
        let bare = self
            .loaded
            .agents
            .list
            .get(self.agent_selected)?
            .name
            .as_str();
        self.loaded.agents.details.get(bare)
    }

    fn policy_editor_key(&mut self, k: KeyInput) -> Effect {
        if k.ctrl && k.code == KeyCode::Char('s') {
            return self.request_apply_policy();
        }
        match k.code {
            KeyCode::Char('t') => match self.editor.mode {
                EditorMode::Form => self.editor.toggle_to_raw(),
                EditorMode::Raw => {
                    if let Err(message) = self.editor.toggle_to_form() {
                        self.status =
                            format!("cannot edit the form while yaml is invalid ({message})");
                    }
                }
            },
            KeyCode::Up => self.move_field_cursor(-1),
            KeyCode::Down => self.move_field_cursor(1),
            KeyCode::Enter | KeyCode::Char('e') => self.editor.editing_field = true,
            _ => {}
        }
        Effect::None
    }

    fn move_field_cursor(&mut self, delta: i32) {
        let len = EDITABLE_FIELDS.len() as i32;
        let next = (self.editor.field_cursor as i32 + delta).rem_euclid(len);
        self.editor.field_cursor = next as usize;
        self.editor.editing_field = false;
    }

    fn request_apply_policy(&mut self) -> Effect {
        if !self.editor.can_apply() {
            self.status = "apply blocked: policy is invalid".to_owned();
            return Effect::None;
        }
        self.modal = Some(Modal {
            title: "apply policy".to_owned(),
            body: vec![
                format!(
                    "overwrite `{}` with the edited document?",
                    self.editor.target_name
                ),
                "this replaces the stored policy file.".to_owned(),
            ],
            action: PendingAction::ApplyPolicy,
        });
        Effect::None
    }

    /// Opens the confirmation modal for revoking one session.
    pub fn request_revoke_session(&mut self, session_id: impl Into<String>) {
        let session_id = session_id.into();
        self.modal = Some(Modal {
            title: "revoke session".to_owned(),
            body: vec![
                format!("revoke {session_id}?"),
                "revocation is permanent; the session can never validate again.".to_owned(),
            ],
            action: PendingAction::RevokeSession {
                session_id: session_id.clone(),
            },
        });
        self.status = format!("awaiting confirmation: revoke {session_id}");
    }

    fn handle_modal_key(&mut self, k: KeyInput) -> Effect {
        let confirmed = matches!(
            k.code,
            KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y')
        );
        let dismissed = matches!(
            k.code,
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N')
        );
        if !confirmed && !dismissed {
            return Effect::None;
        }
        let Some(modal) = self.modal.take() else {
            return Effect::None;
        };
        if dismissed {
            self.status = format!("cancelled: {}", modal.title);
            return Effect::None;
        }
        match modal.action {
            PendingAction::ApplyPolicy => {
                if !self.editor.can_apply() {
                    self.status = "apply blocked: policy is invalid".to_owned();
                    return Effect::None;
                }
                let name = self.editor.target_name.clone();
                let yaml = self.editor.effective_yaml();
                self.status = format!("applying policy `{name}`…");
                Effect::ApplyPolicy {
                    expected_name: name,
                    yaml,
                }
            }
            PendingAction::RevokeSession { session_id } => {
                self.status = format!("revoking {session_id}…");
                Effect::RevokeSession { session_id }
            }
        }
    }
}

fn vertical_delta(k: KeyInput) -> i32 {
    match k.code {
        KeyCode::Up => -1,
        KeyCode::Down => 1,
        _ => 0,
    }
}

fn scroll(selected: &mut usize, len: usize, delta: i32) {
    if len == 0 {
        *selected = 0;
        return;
    }
    *selected = (*selected as i32 + delta).clamp(0, len as i32 - 1) as usize;
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    pub(crate) fn key(c: char) -> KeyInput {
        KeyInput {
            code: KeyCode::Char(c),
            ctrl: false,
        }
    }

    pub(crate) fn press(code: KeyCode) -> KeyInput {
        KeyInput { code, ctrl: false }
    }

    pub(crate) fn ctrl(c: char) -> KeyInput {
        KeyInput {
            code: KeyCode::Char(c),
            ctrl: true,
        }
    }

    /// Feeds one key press to `app`, discarding the returned effect.
    pub(crate) fn send(app: &mut App, k: KeyInput) {
        let _ = app.handle_key(k);
    }

    pub(crate) fn sample_loaded() -> LoadedState {
        LoadedState {
            snapshot: Snapshot {
                branch: Some("main".to_owned()),
                head_short: Some("abc1234".to_owned()),
                env: Some("development".to_owned()),
                envs: vec![
                    EnvRow {
                        name: "development".to_owned(),
                        protected: false,
                        commit_short: Some("abc1234".to_owned()),
                    },
                    EnvRow {
                        name: "production".to_owned(),
                        protected: true,
                        commit_short: None,
                    },
                ],
                variables: vec![
                    VariableRow {
                        name: "API_URL".to_owned(),
                        kind: "config".to_owned(),
                        reference: "obj_manifest_main".to_owned(),
                    },
                    // Deliberately unmasked here: the view layer must
                    // re-mask defensively (see the view tests).
                    VariableRow {
                        name: "STRIPE_KEY".to_owned(),
                        kind: "secret".to_owned(),
                        reference: "hunter2-plaintext-canary".to_owned(),
                    },
                ],
                history: vec![HistoryRow {
                    short: "abc1234".to_owned(),
                    message: "add stripe key".to_owned(),
                    author: "dj".to_owned(),
                }],
                notes: Vec::new(),
            },
            diff: crate::mask::redact_diff(&[]),
            agents: AgentsData::default(),
            audit: vec![
                AuditRow {
                    sequence: 1,
                    actor: "agent:bot".to_owned(),
                    action: "http.request".to_owned(),
                    allowed: true,
                    deny_reason: None,
                    destination: Some("api.example.com:443/v1/charges".to_owned()),
                },
                AuditRow {
                    sequence: 2,
                    actor: "agent:bot".to_owned(),
                    action: "http.request".to_owned(),
                    allowed: false,
                    deny_reason: Some("path_not_allowed".to_owned()),
                    destination: Some("api.example.com:443/admin".to_owned()),
                },
            ],
            broker: BrokerStatus::default(),
            policy_names: Vec::new(),
            editor_seed: TEMPLATE_YAML.to_owned(),
        }
    }

    pub(crate) fn sample_app() -> App {
        App::new(sample_loaded())
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{ctrl, key, press, sample_app, send};
    use super::*;

    #[test]
    fn tab_cycles_dashboard_pane_focus() {
        let mut app = sample_app();
        assert_eq!(app.focus(), Pane::Environments);

        send(&mut app, press(KeyCode::Tab));
        assert_eq!(app.focus(), Pane::Variables);
        send(&mut app, press(KeyCode::Tab));
        assert_eq!(app.focus(), Pane::History);
        send(&mut app, press(KeyCode::Tab));
        assert_eq!(app.focus(), Pane::Environments);
    }

    #[test]
    fn arrow_keys_move_selection_within_focused_pane() {
        let mut app = sample_app();
        assert_eq!(app.selections(), (0, 0, 0));

        send(&mut app, press(KeyCode::Down));
        assert_eq!(app.selections(), (1, 0, 0));

        send(&mut app, press(KeyCode::Tab));
        send(&mut app, press(KeyCode::Down));
        send(&mut app, press(KeyCode::Down));
        // Clamped to the last row of the two-row pane.
        assert_eq!(app.selections(), (1, 1, 0));
        send(&mut app, press(KeyCode::Down));
        assert_eq!(app.selections(), (1, 1, 0));
    }

    #[test]
    fn digit_keys_switch_views_and_tab_toggles_agent_subfocus() {
        let mut app = sample_app();
        assert_eq!(app.route, Route::Dashboard);

        send(&mut app, key('3'));
        assert_eq!(app.route, Route::Agents);
        assert_eq!(app.agent_focus, AgentFocus::List);

        send(&mut app, press(KeyCode::Tab));
        assert_eq!(app.agent_focus, AgentFocus::Sessions);
        send(&mut app, press(KeyCode::Tab));
        assert_eq!(app.agent_focus, AgentFocus::List);

        send(&mut app, key('1'));
        assert_eq!(app.route, Route::Dashboard);
    }

    #[test]
    fn resize_switches_layout_modes_and_preserves_usable_size() {
        let mut app = sample_app();
        assert!(!app.stacked_layout());

        app.handle_resize(80, 24);
        assert!(app.stacked_layout());
        assert_eq!(app.size, (80, 24));

        app.handle_resize(200, 50);
        assert!(!app.stacked_layout());

        app.handle_resize(0, 0);
        assert_eq!(app.size, (1, 1));
        assert!(app.stacked_layout());
    }

    #[test]
    fn modal_decline_cancels_the_pending_action() {
        let mut app = sample_app();
        app.request_revoke_session("sess_abc");

        // While a modal is open every other key is inert.
        assert_eq!(app.handle_key(key('q')), Effect::None);
        assert!(!app.quit_requested);
        assert!(app.modal.is_some());

        let effect = app.handle_key(key('n'));
        assert_eq!(effect, Effect::None);
        assert!(app.modal.is_none());
        assert!(app.status.contains("cancelled"));
    }

    #[test]
    fn modal_confirm_executes_the_revoke_effect() {
        let mut app = sample_app();
        app.request_revoke_session("sess_abc");
        assert!(app.modal.is_some());

        let effect = app.handle_key(key('y'));
        assert_eq!(
            effect,
            Effect::RevokeSession {
                session_id: "sess_abc".to_owned()
            }
        );
        assert!(app.modal.is_none());
    }

    #[test]
    fn invalid_policy_blocks_apply_before_any_modal_opens() {
        let mut loaded = testing::sample_loaded();
        loaded.editor_seed = "name: [unclosed".to_owned();
        let mut app = App::new(loaded);

        send(&mut app, key('4'));
        assert!(!app.editor.can_apply());

        assert_eq!(app.handle_key(ctrl('s')), Effect::None);
        assert!(app.modal.is_none());
        assert!(app.status.contains("apply blocked"));
    }

    #[test]
    fn valid_policy_applies_only_after_modal_confirmation() {
        let mut app = sample_app();

        send(&mut app, key('4'));
        assert!(app.editor.can_apply());

        assert_eq!(app.handle_key(ctrl('s')), Effect::None);
        let modal = app.modal.as_ref().expect("confirm modal open");
        assert_eq!(modal.action, PendingAction::ApplyPolicy);

        let effect = app.handle_key(key('y'));
        match effect {
            Effect::ApplyPolicy {
                expected_name,
                yaml,
            } => {
                assert_eq!(expected_name, app.editor.target_name);
                assert!(yaml.contains("name: new-policy"));
            }
            other => panic!("expected ApplyPolicy, got {other:?}"),
        }
    }

    #[test]
    fn raw_edits_flag_validation_failure_immediately() {
        let mut app = sample_app();
        send(&mut app, key('4'));
        send(&mut app, key('t'));
        assert_eq!(app.editor.mode, EditorMode::Raw);
        assert!(app.editor.can_apply());

        let _ = app.editor.handle_key(key(':'));
        app.editor.revalidate();
        assert!(!app.editor.can_apply());
        assert!(matches!(app.editor.validation, ValidationState::Invalid(_)));
    }
}
