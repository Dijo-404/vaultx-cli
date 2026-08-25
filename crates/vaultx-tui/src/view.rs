//! Pure rendering: layout computation and widget construction.
//!
//! Everything here reads [`state::App`] and paints into a ratatui frame;
//! the functions are backend-agnostic and exercised through
//! `ratatui::backend::TestBackend` in tests, including the stacked
//! small-terminal layout.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Clear, List, ListItem, Paragraph, Row, Table, Tabs, Wrap};
use ratatui::Frame;

use crate::mask::{MASK, NON_REVEALABLE};
use crate::state::{AgentFocus, App, Modal, Pane, PromoteFocus, Route, ValidationState};

const HIGHLIGHT: Style = Style::new().fg(Color::Yellow);
const FOCUSED_BORDER: Style = Style::new().fg(Color::Yellow);
const DENY_STYLE: Style = Style::new().fg(Color::Red);
const ALLOW_STYLE: Style = Style::new().fg(Color::Green);
const ADD_STYLE: Style = Style::new().fg(Color::Green);
const REMOVE_STYLE: Style = Style::new().fg(Color::Red);
const CHANGE_STYLE: Style = Style::new().fg(Color::Yellow);

/// Paints the whole application for one frame.
pub fn render(f: &mut Frame, app: &App) {
    let area = f.area();
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(2),
    ])
    .split(area);

    f.render_widget(
        Tabs::new(Route::ALL.map(Route::label))
            .select(app.route.index())
            .highlight_style(HIGHLIGHT.add_modifier(Modifier::BOLD)),
        rows[0],
    );

    match app.route {
        Route::Dashboard => render_dashboard(f, app, rows[1]),
        Route::Diff => render_diff(f, app, rows[1]),
        Route::Agents => render_agents(f, app, rows[1]),
        Route::PolicyEditor => render_policy_editor(f, app, rows[1]),
        Route::Audit => render_audit(f, app, rows[1]),
        Route::Promote => render_promote(f, app, rows[1]),
        Route::Sync => render_sync(f, app, rows[1]),
    }

    let bottom = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(rows[2]);
    f.render_widget(Paragraph::new(status_text(app)), bottom[0]);
    f.render_widget(
        Paragraph::new(Line::from(binding_spans(app))).style(Style::new().dark_gray()),
        bottom[1],
    );

    if let Some(modal) = &app.modal {
        render_modal(f, modal, area);
    }
}

// ---------------------------------------------------------------------------
// Status + contextual bindings (pure helpers, asserted by tests)
// ---------------------------------------------------------------------------

/// Composes the one-line status: broker state, env/branch, notes, and the
/// last transient message. Broker unavailability is always visible here.
#[must_use]
pub fn status_text(app: &App) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(app.loaded.broker.label());
    match (&app.loaded.snapshot.branch, &app.loaded.snapshot.head_short) {
        (Some(branch), Some(head)) => parts.push(format!("{branch} @ {head}")),
        (Some(branch), None) => parts.push(format!("{branch} @ no commits")),
        (None, other) => parts.push(format!(
            "detached HEAD @ {}",
            other.clone().unwrap_or_else(|| "no commits".to_owned())
        )),
    }
    if let Some(env) = &app.loaded.snapshot.env {
        parts.push(format!("env {env}"));
    }
    for note in &app.loaded.snapshot.notes {
        parts.push(format!("note: {note}"));
    }
    if !app.status.is_empty() {
        parts.push(app.status.clone());
    }
    parts.join("  |  ")
}

/// Key/value pairs of the contextual binding bar; the bar reflects the
/// active view and swaps entirely while a modal is open.
#[must_use]
pub fn binding_pairs(app: &App) -> Vec<(String, String)> {
    if app.modal.is_some() {
        return vec![
            ("y".to_owned(), "confirm".to_owned()),
            ("n/esc".to_owned(), "cancel".to_owned()),
        ];
    }
    if app.route == Route::PolicyEditor && app.editor.capture_all_keys() {
        return vec![
            ("type".to_owned(), "edit yaml".to_owned()),
            ("ctrl+s".to_owned(), "apply".to_owned()),
            (
                "esc".to_owned(),
                if app.editor.mode == crate::state::EditorMode::Raw {
                    "back to form"
                } else {
                    "stop editing"
                }
                .to_owned(),
            ),
            ("ctrl+c".to_owned(), "quit".to_owned()),
        ];
    }
    let mut base = vec![
        ("1-7".to_owned(), "views".to_owned()),
        ("r".to_owned(), "refresh".to_owned()),
        ("q".to_owned(), "quit".to_owned()),
    ];
    match app.route {
        Route::Dashboard => {
            base.insert(0, ("tab".to_owned(), "pane".to_owned()));
            base.insert(1, ("↑↓".to_owned(), "select".to_owned()));
        }
        Route::Diff | Route::Audit => {
            base.insert(0, ("↑↓".to_owned(), "scroll".to_owned()));
            if app.route == Route::Audit {
                base.insert(1, ("f".to_owned(), "filter allow/deny".to_owned()));
            }
        }
        Route::Agents => {
            base.insert(0, ("tab".to_owned(), "list/sessions".to_owned()));
            base.insert(1, ("x".to_owned(), "revoke session".to_owned()));
        }
        Route::PolicyEditor => {
            base.insert(0, ("t".to_owned(), "form/raw".to_owned()));
            base.insert(1, ("enter".to_owned(), "edit field".to_owned()));
            base.insert(2, ("ctrl+s".to_owned(), "apply".to_owned()));
        }
        Route::Promote => {
            base.insert(0, ("tab".to_owned(), "ref/env".to_owned()));
            base.insert(1, ("↑↓".to_owned(), "select".to_owned()));
            base.insert(2, ("enter".to_owned(), "promote".to_owned()));
            base.insert(3, ("esc".to_owned(), "back".to_owned()));
        }
        Route::Sync => {
            if app.sync_busy {
                base.insert(0, ("…".to_owned(), "sync running".to_owned()));
                return base;
            }
            base.insert(0, ("u".to_owned(), "push".to_owned()));
            base.insert(1, ("d".to_owned(), "pull".to_owned()));
            base.insert(2, ("s".to_owned(), "sync".to_owned()));
            base.insert(3, ("esc".to_owned(), "back".to_owned()));
        }
    }
    base
}

fn binding_spans(app: &App) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for (key, label) in binding_pairs(app) {
        spans.push(Span::styled(
            format!(" {key} "),
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(label));
        spans.push(Span::styled(" │", Style::new().dark_gray()));
    }
    spans
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

struct DashboardAreas {
    environments: Rect,
    variables: Rect,
    history: Rect,
    inspector: Rect,
}

fn dashboard_areas(area: Rect, focused: Pane, stacked: bool) -> DashboardAreas {
    if !stacked {
        let outer =
            Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).split(area);
        let cols = Layout::horizontal([
            Constraint::Percentage(25),
            Constraint::Percentage(35),
            Constraint::Percentage(40),
        ])
        .split(outer[0]);
        return DashboardAreas {
            environments: cols[0],
            variables: cols[1],
            history: cols[2],
            inspector: outer[1],
        };
    }

    // Stacked/detail mode: the focused pane expands; the others collapse
    // to title + preview so critical fields stay visible instead of being
    // clipped away.
    let constraint_for = |pane: Pane| {
        if pane == focused {
            Constraint::Min(4)
        } else {
            Constraint::Length(4)
        }
    };
    let chunks = Layout::vertical([
        constraint_for(Pane::Environments),
        constraint_for(Pane::Variables),
        constraint_for(Pane::History),
        Constraint::Min(4),
    ])
    .split(area);
    DashboardAreas {
        environments: chunks[0],
        variables: chunks[1],
        history: chunks[2],
        inspector: chunks[3],
    }
}

fn render_dashboard(f: &mut Frame, app: &App, area: Rect) {
    let focus = app.focus();
    let areas = dashboard_areas(area, focus, app.stacked_layout());

    let (sel_env, sel_var, sel_hist) = app.selections();
    let snapshot = &app.loaded.snapshot;

    let env_items: Vec<ListItem> = snapshot
        .envs
        .iter()
        .map(|env| {
            ListItem::new(Line::from(format!(
                "{}{}  {}",
                if env.protected { "★ " } else { "  " },
                env.name,
                env.commit_short.as_deref().unwrap_or("—")
            )))
        })
        .collect();
    list_block(
        f,
        env_items,
        areas.environments,
        Pane::Environments.title(),
        focus == Pane::Environments,
        Some(sel_env),
    );

    let var_items: Vec<ListItem> = snapshot
        .variables
        .iter()
        .map(|row| {
            // Defensive re-masking: even a loader regression cannot leak a
            // secret/brokered reference through this pane.
            let value = crate::mask::mask_reference(&row.kind, &row.reference);
            ListItem::new(Line::from(format!(
                "{:<24} {:<8} {}",
                row.name, row.kind, value
            )))
        })
        .collect();
    list_block(
        f,
        var_items,
        areas.variables,
        Pane::Variables.title(),
        focus == Pane::Variables,
        Some(sel_var),
    );

    let hist_items: Vec<ListItem> = snapshot
        .history
        .iter()
        .map(|row| ListItem::new(Line::from(format!("{}  {}", row.short, row.message))))
        .collect();
    list_block(
        f,
        hist_items,
        areas.history,
        Pane::History.title(),
        focus == Pane::History,
        Some(sel_hist),
    );

    let inspector_lines = inspector_lines(app);
    f.render_widget(
        Paragraph::new(inspector_lines)
            .block(block_for("inspector", false))
            .wrap(Wrap { trim: true }),
        areas.inspector,
    );
}

fn list_block(
    f: &mut Frame,
    items: Vec<ListItem>,
    area: Rect,
    title: &str,
    focused: bool,
    selected: Option<usize>,
) {
    let mut state = ratatui::widgets::ListState::default();
    state.select(Some(selected.unwrap_or(0)));
    let list = List::new(items)
        .block(block_for(title, focused))
        .highlight_style(HIGHLIGHT.add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");
    f.render_stateful_widget(list, area, &mut state);
}

fn block_for(title: &str, focused: bool) -> Block<'static> {
    let border = if focused {
        FOCUSED_BORDER
    } else {
        Style::new()
    };
    Block::bordered()
        .title(format!(" {title} "))
        .border_style(border)
}

fn inspector_lines(app: &App) -> Vec<Line<'static>> {
    let (env_sel, var_sel, hist_sel) = app.selections();
    let snapshot = &app.loaded.snapshot;
    match app.focus() {
        Pane::Environments => match snapshot.envs.get(env_sel) {
            Some(env) => vec![
                Line::from(format!("environment {}", env.name)),
                Line::from(format!(
                    "protected: {}",
                    if env.protected { "yes" } else { "no" }
                )),
                Line::from(format!(
                    "pinned commit: {}",
                    env.commit_short.as_deref().unwrap_or("—")
                )),
            ],
            None => vec![Line::from("(no environments)")],
        },
        Pane::Variables => match snapshot.variables.get(var_sel) {
            Some(row) if row.kind == "config" || row.kind == "dynamic" => vec![
                Line::from(format!("name:     {}", row.name)),
                Line::from(format!("kind:     {}", row.kind)),
                Line::from(format!("ref:      {}", row.reference)),
                Line::from("values shown are non-secret config metadata"),
            ],
            Some(row) => vec![
                Line::from(format!("name:     {}", row.name)),
                Line::from(format!("kind:     {}", row.kind)),
                Line::from(format!("value:    {MASK}")),
                Line::from("secret values are masked by default"),
            ],
            None => vec![Line::from("(no variables)")],
        },
        Pane::History => match snapshot.history.get(hist_sel) {
            Some(row) => {
                let mut lines = vec![
                    Line::from(format!("commit:   {}", row.short)),
                    Line::from(format!("author:   {}", row.author)),
                    Line::from(format!("message:  {}", row.message)),
                ];
                if row.delta.is_empty() {
                    lines.push(Line::from("delta:     none recorded"));
                } else {
                    lines.push(Line::from(format!(
                        "delta ({} redacted lines):",
                        row.delta.len()
                    )));
                    for line in &row.delta {
                        lines.push(Line::from(Span::styled(
                            format!("{} {}", line.marker, line.text),
                            diff_style(line.marker),
                        )));
                    }
                }
                lines
            }
            None => vec![Line::from("(no commits)")],
        },
    }
}

// ---------------------------------------------------------------------------
// Diff view
// ---------------------------------------------------------------------------

fn render_diff(f: &mut Frame, app: &App, area: Rect) {
    if app.loaded.diff.is_empty() {
        f.render_widget(
            Paragraph::new("no staged changes").block(block_for("staged diff", true)),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = app
        .loaded
        .diff
        .iter()
        .map(|line| {
            let style = diff_style(line.marker);
            ListItem::new(Line::from(Span::styled(
                format!("{} {}", line.marker, line.text),
                style,
            )))
        })
        .collect();
    let mut state = ratatui::widgets::ListState::default();
    let selected = selected_index(app.diff_selected, app.loaded.diff.len());
    state.select(Some(selected));

    if !app.stacked_layout() {
        f.render_stateful_widget(
            List::new(items)
                .block(block_for("staged diff", true))
                .highlight_symbol(">"),
            area,
            &mut state,
        );
        return;
    }

    // Small terminal: the list sits above a wrapped detail of the
    // selected line so long entries stay readable instead of clipping.
    let rows = Layout::vertical([Constraint::Min(4), Constraint::Min(3)]).split(area);
    f.render_stateful_widget(
        List::new(items)
            .block(block_for("staged diff", true))
            .highlight_symbol(">"),
        rows[0],
        &mut state,
    );
    let selected_line = &app.loaded.diff[selected];
    let detail = format!("{} {}", selected_line.marker, selected_line.text);
    f.render_widget(
        Paragraph::new(detail)
            .block(block_for("selected line", false))
            .wrap(Wrap { trim: false }),
        rows[1],
    );
}

/// Selection index clamped into the current row count.
fn selected_index(selected: usize, len: usize) -> usize {
    if len == 0 {
        0
    } else {
        selected.min(len - 1)
    }
}

fn diff_style(marker: char) -> Style {
    match marker {
        '+' => ADD_STYLE,
        '-' => REMOVE_STYLE,
        '~' => CHANGE_STYLE,
        _ => Style::new().add_modifier(Modifier::BOLD),
    }
}

// ---------------------------------------------------------------------------
// Agents view
// ---------------------------------------------------------------------------

fn render_agents(f: &mut Frame, app: &App, area: Rect) {
    let (list_area, detail_area, policy_area) = agents_areas(area, app.stacked_layout());

    let items: Vec<ListItem> = app
        .loaded
        .agents
        .list
        .iter()
        .map(|agent| {
            ListItem::new(Line::from(format!(
                "{}{}",
                agent.name,
                if agent.enabled { "" } else { " (disabled)" }
            )))
        })
        .collect();
    let mut state = ratatui::widgets::ListState::default();
    state.select(Some(app.agent_selected));
    f.render_stateful_widget(
        List::new(items)
            .block(Block::bordered().title(" agents "))
            .highlight_symbol("> ")
            .highlight_style(if app.agent_focus == AgentFocus::List {
                HIGHLIGHT.add_modifier(Modifier::REVERSED)
            } else {
                HIGHLIGHT
            }),
        list_area,
        &mut state,
    );

    let detail = app
        .loaded
        .agents
        .list
        .get(app.agent_selected)
        .and_then(|agent| app.loaded.agents.details.get(&agent.name));

    let lines = match detail {
        Some(detail) => agent_detail_lines(detail, app.session_selected),
        None => vec![Line::from("(no agents registered)")],
    };
    f.render_widget(
        Paragraph::new(lines)
            .block(block_for(
                "agent detail",
                app.agent_focus == AgentFocus::Sessions,
            ))
            .wrap(Wrap { trim: false }),
        detail_area,
    );

    // The inspector's third plan role: the focused agent's effective
    // policy summary (hosts/methods/paths + capabilities), metadata only.
    let policy_lines = match detail {
        Some(detail) => agent_policy_lines(detail),
        None => vec![Line::from("(no agent selected)")],
    };
    f.render_widget(
        Paragraph::new(policy_lines)
            .block(block_for("agent policy", false))
            .wrap(Wrap { trim: false }),
        policy_area,
    );
}

/// Agents-view regions: side-by-side list/detail with the policy
/// inspector below, or fully stacked in small terminals so no section is
/// clipped away.
fn agents_areas(area: Rect, stacked: bool) -> (Rect, Rect, Rect) {
    if !stacked {
        let rows = Layout::vertical([Constraint::Min(4), Constraint::Percentage(35)]).split(area);
        let cols = Layout::horizontal([Constraint::Percentage(25), Constraint::Percentage(75)])
            .split(rows[0]);
        (cols[0], cols[1], rows[1])
    } else {
        let chunks = Layout::vertical([
            Constraint::Length(5),
            Constraint::Min(4),
            Constraint::Min(4),
        ])
        .split(area);
        (chunks[0], chunks[1], chunks[2])
    }
}

/// Builds the per-agent identity/session text (plan §38 "Agent view").
/// Credential names carry the non-revealable marker; no code path can
/// render brokered values because the loader never loads any. The policy
/// surface itself lives in [`agent_policy_lines`].
fn agent_detail_lines(
    detail: &crate::state::AgentDetail,
    session_selected: usize,
) -> Vec<Line<'static>> {
    let mut lines: Vec<Line> = vec![
        Line::from(format!("identity:   {} ", detail.full_id)),
        Line::from(format!(
            "enabled:    {}",
            if detail.enabled {
                "yes"
            } else {
                "no (revoked)"
            }
        )),
        Line::from(format!(
            "session:    [{}] {}",
            session_status_marker(detail, session_selected),
            detail.session_summary()
        )),
        Line::from(format!("environment: {}", detail.environment)),
    ];

    lines.push(Line::from("credentials:"));
    if detail.credentials.is_empty() {
        lines.push(Line::from("  —"));
    }
    for credential in &detail.credentials {
        lines.push(Line::from(format!("  {credential} {NON_REVEALABLE}")));
    }

    lines.push(Line::from("recent audit (allow/deny):"));
    if detail.audit.is_empty() {
        lines.push(Line::from("  —"));
    }
    for row in &detail.audit {
        let token = if row.allowed { "ALLOW" } else { "DENY " };
        let style = if row.allowed { ALLOW_STYLE } else { DENY_STYLE };
        lines.push(Line::from(vec![
            Span::styled(format!("  {token} "), style),
            Span::raw(format!(
                "{} {} {}",
                row.action,
                row.actor,
                row.destination.as_deref().unwrap_or("")
            )),
        ]));
    }
    lines
}

/// Effective policy surface of the focused agent: attached policies plus
/// the allowed host/method/path unions and semantic capabilities.
fn agent_policy_lines(detail: &crate::state::AgentDetail) -> Vec<Line<'static>> {
    vec![
        Line::from(if detail.policies.is_empty() {
            "policies: —".to_owned()
        } else {
            format!("policies: {}", detail.policies.join(", "))
        }),
        list_section("allowed hosts", &detail.allowed_hosts),
        list_section("allowed methods", &detail.allowed_methods),
        list_section("allowed paths", &detail.allowed_paths),
        Line::from(if detail.capabilities.is_empty() {
            "semantic capabilities: —".to_owned()
        } else {
            format!("semantic capabilities: {}", detail.capabilities.join(", "))
        }),
    ]
}

fn session_status_marker(detail: &crate::state::AgentDetail, selected: usize) -> &'static str {
    match detail.sessions.as_ref() {
        Ok(rows) => rows.get(selected).map_or("", |row| row.status.label()),
        Err(_) => "unavailable",
    }
}

fn list_section(title: &str, values: &[String]) -> Line<'static> {
    if values.is_empty() {
        Line::from(format!("{title}: —"))
    } else {
        Line::from(format!("{title}: {}", values.join(", ")))
    }
}

// ---------------------------------------------------------------------------
// Policy editor
// ---------------------------------------------------------------------------

fn render_policy_editor(f: &mut Frame, app: &App, area: Rect) {
    use crate::state::{EditorMode, FormField};

    let form_focused = app.editor.mode == EditorMode::Form;
    let fields = [
        FormField::Principal,
        FormField::Credential,
        FormField::Hosts,
        FormField::AllowRules,
        FormField::DenyRules,
    ];
    let buffers = [
        &app.editor.draft.principal,
        &app.editor.draft.credential,
        &app.editor.draft.hosts,
        &app.editor.draft.allow_rules,
        &app.editor.draft.deny_rules,
    ];

    let mut form_lines: Vec<Line> = Vec::new();
    for (index, field) in fields.iter().enumerate() {
        let active = form_focused && index == app.editor.field_cursor;
        let editing = active && app.editor.editing_field;
        let buffer = buffers[index];
        let caret = if editing { "▏" } else { "" };
        form_lines.push(Line::from(format!(
            "{} {:<12} {}{caret}",
            if active { ">" } else { " " },
            field.label(),
            first_line_or_empty(&buffer.lines),
        )));
    }

    // Small terminals stack the two editing surfaces above the
    // validation banner; large ones keep the side-by-side split with the
    // banner pinned on top.
    let (form_area, raw_area, banner_area) = if app.stacked_layout() {
        let rows = Layout::vertical([
            Constraint::Min(4),
            Constraint::Min(4),
            Constraint::Length(1),
        ])
        .split(area);
        (rows[0], rows[1], rows[2])
    } else {
        let rows = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).split(area);
        let cols = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[1]);
        (cols[0], cols[1], rows[0])
    };

    render_validation_banner(f, &app.editor.validation, banner_area);

    f.render_widget(
        Paragraph::new(form_lines).block(block_for(
            "form/tree (t: raw)",
            form_focused && !app.editor.editing_field,
        )),
        form_area,
    );

    f.render_widget(
        Paragraph::new(app.editor.raw.text())
            .block(block_for(
                "raw yaml",
                !form_focused || app.editor.editing_field,
            ))
            .wrap(Wrap { trim: false }),
        raw_area,
    );
}

fn first_line_or_empty(lines: &[String]) -> String {
    let mut text = lines.first().cloned().unwrap_or_default();
    if lines.len() > 1 {
        text.push_str(&format!(" …(+{})", lines.len() - 1));
    }
    text
}

fn render_validation_banner(f: &mut Frame, validation: &ValidationState, area: Rect) {
    let line = match validation {
        ValidationState::Valid => Line::from(Span::styled(
            "✓ valid policy — apply available via ctrl+s",
            ALLOW_STYLE.add_modifier(Modifier::BOLD),
        )),
        ValidationState::Invalid(reason) => Line::from(Span::styled(
            format!("✗ INVALID — apply blocked ({reason})"),
            DENY_STYLE.add_modifier(Modifier::BOLD),
        )),
    };
    f.render_widget(Paragraph::new(line), area);
}

// ---------------------------------------------------------------------------
// Audit view
// ---------------------------------------------------------------------------

fn render_audit(f: &mut Frame, app: &App, area: Rect) {
    if app.loaded.audit.is_empty() {
        f.render_widget(
            Paragraph::new(format!(
                "no events match filter `{}` (f cycles all/allow/deny)",
                app.audit_filter.label()
            ))
            .block(audit_block(app)),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = app
        .loaded
        .audit
        .iter()
        .map(|row| {
            let (token, style) = if row.allowed {
                ("ALLOW", ALLOW_STYLE)
            } else {
                ("DENY ", DENY_STYLE.add_modifier(Modifier::BOLD))
            };
            let reason = row.deny_reason.as_deref().unwrap_or("");
            ListItem::new(Line::from(vec![
                Span::styled(token.to_owned(), style),
                // Denial category precedes the destination so it stays
                // inside narrow viewports instead of clipping away.
                Span::raw(format!(
                    " #{:<4} {:<14} {:<18}{} {}",
                    row.sequence,
                    row.action,
                    truncate(&row.actor, 18),
                    if reason.is_empty() {
                        String::new()
                    } else {
                        format!("({reason})")
                    },
                    row.destination.as_deref().unwrap_or(""),
                )),
            ]))
        })
        .collect();
    let mut state = ratatui::widgets::ListState::default();
    state.select(Some(app.audit_selected));

    if !app.stacked_layout() {
        f.render_stateful_widget(
            List::new(items)
                .block(audit_block(app))
                .highlight_symbol("> "),
            area,
            &mut state,
        );
        return;
    }

    // Small terminal: the outcome filter stays pinned above the
    // scrolling event list so the active filter is never lost.
    let rows = Layout::vertical([Constraint::Length(3), Constraint::Min(3)]).split(area);
    f.render_widget(
        Paragraph::new(audit_filter_line(app)).block(block_for("audit filters", true)),
        rows[0],
    );
    f.render_stateful_widget(
        List::new(items)
            .block(block_for("audit", true))
            .highlight_symbol("> "),
        rows[1],
        &mut state,
    );
}

/// One-line summary of the active audit outcome filter.
fn audit_filter_line(app: &App) -> String {
    format!(
        "filter: {} · f cycles · {} event(s)",
        app.audit_filter.label(),
        app.loaded.audit.len()
    )
}

fn audit_block(app: &App) -> Block<'static> {
    block_for(
        &format!("audit [filter: {} — f cycles]", app.audit_filter.label()),
        true,
    )
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_owned()
    } else {
        let cut: String = text.chars().take(max_chars.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}

// ---------------------------------------------------------------------------
// Promotion view (plan §38 "environment promotion view")
// ---------------------------------------------------------------------------

fn render_promote(f: &mut Frame, app: &App, area: Rect) {
    let refs_focused = app.promote_focus == PromoteFocus::Refs;
    let envs_focused = !refs_focused;
    let stacked = app.stacked_layout();

    // Wide terminals show the two lists side by side; small ones stack
    // them above the target summary so no section is clipped away.
    let areas: [Rect; 3] = if !stacked {
        let rows = Layout::vertical([Constraint::Min(4), Constraint::Length(3)]).split(area);
        let cols = Layout::horizontal([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(rows[0]);
        [cols[0], cols[1], rows[1]]
    } else {
        let chunks = Layout::vertical([
            Constraint::Min(4),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(area);
        [chunks[0], chunks[1], chunks[2]]
    };

    let ref_items: Vec<ListItem> = app
        .loaded
        .branches
        .iter()
        .map(|name| ListItem::new(Line::from(name.clone())))
        .collect();
    list_block(
        f,
        ref_items,
        areas[0],
        "source refs",
        refs_focused,
        Some(app.promote_ref_selected),
    );

    render_env_table(
        f,
        app,
        areas[1],
        envs_focused,
        Some(app.promote_env_selected),
    );

    f.render_widget(
        Paragraph::new(promotion_target_line(app))
            .block(block_for("promotion target", false))
            .wrap(Wrap { trim: true }),
        areas[2],
    );
}

/// NAME / PROTECTED / PINNED COMMIT table over the environment rows.
fn render_env_table(f: &mut Frame, app: &App, area: Rect, focused: bool, selected: Option<usize>) {
    let header = Row::new(["NAME", "PROTECTED", "PINNED COMMIT"])
        .style(Style::new().add_modifier(Modifier::BOLD));
    let rows = app.loaded.snapshot.envs.iter().map(|env| {
        Row::new(vec![
            Cell::from(env.name.clone()),
            Cell::from(if env.protected { "yes" } else { "no" }),
            Cell::from(env.commit_short.clone().unwrap_or_else(|| "—".to_owned())),
        ])
    });
    let widths = [
        Constraint::Percentage(40),
        Constraint::Percentage(25),
        Constraint::Percentage(35),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(block_for("environments", focused))
        .row_highlight_style(HIGHLIGHT.add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");
    let mut state = ratatui::widgets::TableState::default();
    state.select(selected);
    f.render_stateful_widget(table, area, &mut state);
}

/// One-line description of what Enter would promote right now.
fn promotion_target_line(app: &App) -> String {
    match (app.selected_promote_ref(), app.selected_promote_env()) {
        (Some(from_ref), Some(env)) => {
            let guard = if env.protected {
                " (protected: needs confirm)"
            } else {
                ""
            };
            format!("enter promotes {from_ref} -> {}{guard}", env.name)
        }
        _ => "(nothing selected)".to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Sync view (plan §38)
// ---------------------------------------------------------------------------

fn render_sync(f: &mut Frame, app: &App, area: Rect) {
    let stacked = app.stacked_layout();

    // Both layouts keep the remote/login section pinned above the
    // results log so the control-plane context never scrolls away.
    let (top, results) = if !stacked {
        let rows =
            Layout::vertical([Constraint::Percentage(45), Constraint::Percentage(55)]).split(area);
        (rows[0], rows[1])
    } else {
        let rows = Layout::vertical([Constraint::Min(5), Constraint::Min(4)]).split(area);
        (rows[0], rows[1])
    };

    let login = app.loaded.sync.login_label().to_owned();
    let mut lines: Vec<Line> = vec![Line::from(Span::styled(
        login.clone(),
        if app.loaded.sync.logged_in {
            ALLOW_STYLE
        } else {
            DENY_STYLE.add_modifier(Modifier::BOLD)
        },
    ))];
    // Busy indicator: an operation is running in the background.
    if app.sync_busy {
        lines.push(Line::from(Span::styled(
            "⟳ working…",
            HIGHLIGHT.add_modifier(Modifier::BOLD),
        )));
    }
    if app.loaded.sync.remotes.is_empty() {
        lines.push(Line::from("(no remotes configured)"));
    }
    for (index, remote) in app.loaded.sync.remotes.iter().enumerate() {
        let marker = if index == app.sync_selected {
            "> "
        } else {
            "  "
        };
        lines.push(Line::from(format!(
            "{marker}{}  {}  {}",
            remote.name, remote.project_id, remote.server
        )));
    }
    f.render_widget(
        Paragraph::new(lines).block(block_for("control plane", true)),
        top,
    );

    let result_lines: Vec<Line> = if app.sync_lines.is_empty() {
        vec![Line::from("(no sync run yet — u push · d pull · s sync)")]
    } else {
        app.sync_lines
            .iter()
            .map(|l| Line::from(l.clone()))
            .collect()
    };
    f.render_widget(
        Paragraph::new(result_lines)
            .block(block_for("last sync", false))
            .wrap(Wrap { trim: false }),
        results,
    );
}

// ---------------------------------------------------------------------------
// Modal
// ---------------------------------------------------------------------------

fn render_modal(f: &mut Frame, modal: &Modal, area: Rect) {
    let popup = centered_rect(60, 30, area);
    f.render_widget(Clear, popup);
    let inner_rows = Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).split(popup);
    let mut body: Vec<Line> = modal.body.iter().map(|l| Line::from(l.clone())).collect();
    body.push(Line::from(Span::styled(
        modal.hint(),
        HIGHLIGHT.add_modifier(Modifier::BOLD),
    )));
    let block = Block::bordered()
        .title(format!(" ⚠ {} ", modal.title))
        .border_style(DENY_STYLE);
    f.render_widget(
        Paragraph::new(body).block(block).wrap(Wrap { trim: true }),
        inner_rows[0],
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(vertical[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use vaultx_types::{SecretRevisionId, VariableName};

    use crate::mask;
    use crate::state::testing::{key, press, sample_app, send};
    use crate::state::{
        AgentDetail, AgentRow, AgentsData, App, BrokerStatus, KeyCode, LoadedState, Route,
        SessionRow, SessionStatus, ValidationState, VariableRow, DEFAULT_TERMINAL_SIZE,
    };

    /// One-agent fixture exercising every agents-view section.
    fn agent_fixture() -> AgentsData {
        let detail = AgentDetail {
            full_id: "agent_ci-bot".to_owned(),
            enabled: true,
            environment: "production".to_owned(),
            policies: vec!["stripe".to_owned()],
            credentials: vec!["deploy_token".to_owned()],
            allowed_hosts: vec!["api.example.com".to_owned()],
            allowed_methods: vec!["GET".to_owned()],
            allowed_paths: vec!["/v1/**".to_owned()],
            capabilities: vec!["deploy.http".to_owned()],
            sessions: Ok(vec![SessionRow {
                session_id: "sess_abc".to_owned(),
                environment: "production".to_owned(),
                status: SessionStatus::Active,
            }]),
            audit: Vec::new(),
        };
        AgentsData {
            list: vec![AgentRow {
                name: "ci-bot".to_owned(),
                enabled: true,
            }],
            details: [("ci-bot".to_owned(), detail)].into_iter().collect(),
        }
    }

    /// Secret-revision delta used across the diff/inspector tests.
    fn revision_change_entry() -> vaultx_core::DiffEntry {
        vaultx_core::DiffEntry::SecretRevisionChanged {
            name: VariableName::parse("STRIPE_KEY").unwrap(),
            old_revision: SecretRevisionId::parse("sec_rev_000001").unwrap(),
            new_revision: SecretRevisionId::parse("sec_rev_000002").unwrap(),
        }
    }

    /// Renders one frame into a `TestBackend` and returns the screen text.
    fn render_app(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal.draw(|f| render(f, app)).expect("draw");
        let buffer = terminal.backend().buffer();
        let area = buffer.area;
        (0..area.height)
            .map(|y| {
                (0..area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn status_line_separates_online_offline_and_unprobed_brokers() {
        let mut app = sample_app();

        app.loaded.broker = BrokerStatus::Online("vaultx/9.9".to_owned());
        assert!(status_text(&app).contains("broker online (vaultx/9.9)"));

        app.loaded.broker = BrokerStatus::Offline("socket missing".to_owned());
        assert!(status_text(&app).contains("broker offline"));
        assert!(render_app(&app, 120, 30).contains("broker offline"));

        // Fully default data must render without panicking.
        let unprobed = App::with_size(LoadedState::default(), DEFAULT_TERMINAL_SIZE);
        assert!(status_text(&unprobed).contains("broker offline"));
    }

    #[test]
    fn secret_values_are_masked_in_dashboard_and_inspector() {
        let app = sample_app();
        let screen = render_app(&app, 160, 48);
        assert!(screen.contains(crate::mask::MASK));
        assert!(!screen.contains("hunter2-plaintext-canary"));
    }

    #[test]
    fn large_layout_is_three_columns_and_small_layout_stacks_panes() {
        let wide = Rect::new(0, 0, 160, 48);
        let cols = dashboard_areas(wide, Pane::Variables, false);
        assert_ne!(cols.environments.x, cols.variables.x);
        assert_ne!(cols.variables.x, cols.history.x);
        assert!(cols.environments.width < wide.width);
        assert!(cols.variables.width < wide.width);

        let narrow = Rect::new(0, 0, 60, 20);
        let stacked = dashboard_areas(narrow, Pane::Variables, true);
        assert_eq!(stacked.environments.width, narrow.width);
        assert_eq!(stacked.variables.width, narrow.width);
        assert_eq!(stacked.history.width, narrow.width);
    }

    #[test]
    fn stacked_small_terminal_keeps_every_pane_title_visible() {
        let app = sample_app();

        let large = render_app(&app, 160, 48);
        for title in ["env/branch", "variables", "history", "inspector"] {
            assert!(large.contains(title), "missing `{title}` in large layout");
        }

        let small = render_app(&app, 80, 24);
        for title in ["env/branch", "variables", "history", "inspector"] {
            assert!(small.contains(title), "missing `{title}` in stacked layout");
        }
        assert!(small.contains("development"));
    }

    #[test]
    fn history_selection_surfaces_redacted_delta_in_the_inspector() {
        const CANARY: &str = "hunter2-plaintext-canary";
        let entry = revision_change_entry();

        // Focus the history pane (two tabs) and give its selected commit
        // a loader-produced redacted delta.
        let mut app = sample_app();
        send(&mut app, press(KeyCode::Tab));
        send(&mut app, press(KeyCode::Tab));
        app.loaded.snapshot.history[0].delta = mask::redact_diff(std::slice::from_ref(&entry));

        let screen = render_app(&app, 160, 48);
        assert!(screen.contains("commit:   abc1234"));
        assert!(screen.contains("delta (3 redacted lines)"));
        assert!(screen.contains("- revision sec_rev_000001"));
        assert!(screen.contains("+ revision sec_rev_000002"));
        assert!(!screen.contains(CANARY));
    }

    #[test]
    fn diff_view_stacks_list_above_selected_line_detail_when_small() {
        let mut app = sample_app();
        app.route = Route::Diff;
        app.loaded.diff = mask::redact_diff(std::slice::from_ref(&revision_change_entry()));

        let large = render_app(&app, 110, 30);
        assert!(large.contains("staged diff"));
        assert!(!large.contains("selected line"));

        // Small terminal measurement drives the stacked split.
        app.handle_resize(80, 24);
        let small = render_app(&app, 80, 24);
        assert!(
            small.contains("staged diff"),
            "missing list in stacked diff"
        );
        assert!(
            small.contains("selected line"),
            "missing detail in stacked diff"
        );
        assert!(small.contains("STRIPE_KEY"));
    }

    #[test]
    fn agents_view_stacks_sections_and_shows_effective_policy_when_small() {
        let mut app = sample_app();
        app.loaded.agents = agent_fixture();
        app.route = Route::Agents;

        let large = render_app(&app, 130, 40);
        for token in [
            "agents",
            "agent detail",
            "agent policy",
            "policies: stripe",
            "allowed hosts: api.example.com",
            "environment: production",
        ] {
            assert!(
                large.contains(token),
                "missing `{token}` in large agents view"
            );
        }

        app.handle_resize(80, 24);
        let small = render_app(&app, 80, 24);
        for token in [
            "agents",
            "agent detail",
            "agent policy",
            "ci-bot",
            "environment: production",
            "sess_abc ACTIVE in production",
            "policies: stripe",
            "allowed hosts: api.example.com",
            "allowed methods: GET",
            "allowed paths: /v1/**",
            "semantic capabilities: deploy.http",
        ] {
            assert!(
                small.contains(token),
                "missing `{token}` in stacked agents view"
            );
        }
    }

    #[test]
    fn agent_environment_line_renders_even_without_sessions() {
        let detail = AgentDetail {
            full_id: "agent_bot".to_owned(),
            enabled: false,
            environment: "development".to_owned(),
            ..AgentDetail::default()
        };
        let mut app = sample_app();
        app.loaded.agents = AgentsData {
            list: vec![AgentRow {
                name: "bot".to_owned(),
                enabled: false,
            }],
            details: [("bot".to_owned(), detail)].into_iter().collect(),
        };
        app.route = Route::Agents;

        let screen = render_app(&app, 110, 30);
        assert!(screen.contains("environment: development"));
        assert!(screen.contains("no sessions"));
    }

    #[test]
    fn policy_editor_stacks_buffers_above_validation_banner_when_small() {
        let mut valid = sample_app();
        valid.route = Route::PolicyEditor;

        let large_valid = render_app(&valid, 110, 30);
        assert!(large_valid.contains("valid policy"));

        valid.handle_resize(80, 24);
        let small_valid = render_app(&valid, 80, 24);
        for token in ["form/tree (t: raw)", "raw yaml", "valid policy"] {
            assert!(
                small_valid.contains(token),
                "missing `{token}` in small policy editor"
            );
        }
        let form_row = small_valid
            .lines()
            .position(|l| l.contains("form/tree"))
            .expect("form pane");
        let raw_row = small_valid
            .lines()
            .position(|l| l.contains("raw yaml"))
            .expect("raw pane");
        let banner_row = small_valid
            .lines()
            .position(|l| l.contains("valid policy"))
            .expect("banner");
        assert!(form_row < raw_row && raw_row < banner_row);

        let mut loaded = sample_app().loaded;
        loaded.editor_seed = "name: [unclosed".to_owned();
        let mut invalid = App::with_size(loaded, DEFAULT_TERMINAL_SIZE);
        invalid.route = Route::PolicyEditor;
        invalid.handle_resize(80, 24);
        let small_invalid = render_app(&invalid, 80, 24);
        assert!(small_invalid.contains("INVALID"));
        assert!(small_invalid.contains("apply blocked"));
    }

    #[test]
    fn audit_view_stacks_filters_above_list_when_small() {
        let mut app = sample_app();
        app.route = Route::Audit;

        let large = render_app(&app, 130, 30);
        assert!(large.contains("audit [filter: all"));

        app.handle_resize(80, 24);
        let small = render_app(&app, 80, 24);
        assert!(small.contains("audit filters"));
        assert!(small.contains("filter: all"));
        assert!(small.contains("ALLOW"));
        assert!(small.contains("path_not_allowed"));

        let filter_row = small
            .lines()
            .position(|l| l.contains("audit filters"))
            .expect("filters pane");
        let list_row = small
            .lines()
            .position(|l| l.contains("ALLOW"))
            .expect("list row");
        assert!(filter_row < list_row);
    }

    #[test]
    fn diff_view_shows_revision_labels_but_never_plaintext() {
        const CANARY: &str = "hunter2-plaintext-canary";

        let entry = vaultx_core::DiffEntry::SecretRevisionChanged {
            name: VariableName::parse("STRIPE_KEY").unwrap(),
            old_revision: SecretRevisionId::parse("sec_rev_000001").unwrap(),
            new_revision: SecretRevisionId::parse("sec_rev_000002").unwrap(),
        };

        let mut app = sample_app();
        app.route = Route::Diff;
        app.loaded.diff = mask::redact_diff(&[entry]);
        let screen = render_app(&app, 110, 30);

        assert!(screen.contains("STRIPE_KEY"));
        assert!(screen.contains("revision sec_rev_000002"));
        assert!(!screen.contains(CANARY));

        // The dashboard variables pane masks raw references too.
        let mut dashboard = sample_app();
        dashboard.loaded.snapshot.variables.push(VariableRow {
            name: "STRIPE_KEY".to_owned(),
            kind: "secret".to_owned(),
            reference: CANARY.to_owned(),
        });
        assert!(!render_app(&dashboard, 160, 48).contains(CANARY));
    }

    #[test]
    fn audit_view_marks_denied_entries_distinctly() {
        let mut app = sample_app();
        app.route = Route::Audit;
        let screen = render_app(&app, 130, 30);
        assert!(screen.contains("ALLOW"));
        assert!(screen.contains("DENY"));
        assert!(screen.contains("path_not_allowed"));

        let mut allows_only = sample_app();
        allows_only.route = Route::Audit;
        allows_only.loaded.audit.retain(|row| row.allowed);
        assert!(!render_app(&allows_only, 130, 30).contains("DENY"));
    }

    #[test]
    fn confirmation_modal_renders_over_the_active_view() {
        let mut app = sample_app();
        send(&mut app, key('q'));
        app.request_revoke_session("sess_abc");
        let screen = render_app(&app, 100, 30);
        assert!(screen.contains("revoke session"));
        assert!(screen.contains("y confirm · n/esc cancel"));
    }

    #[test]
    fn rendering_survives_out_of_range_selections_after_a_shrink() {
        let mut app = sample_app();
        // Deliberately stale indices pointing past the lists they index.
        app.agent_selected = 9;
        app.session_selected = 9;
        app.audit_selected = 9;
        app.diff_selected = 9;

        // Shrink the backing data below those indices (a reload that
        // removed rows) and render every route: nothing may panic.
        app.loaded.audit.truncate(1);
        app.loaded.diff.clear();
        app.sync_lines = vec!["stale result line".to_owned()];

        for route in Route::ALL {
            app.route = route;
            let screen = render_app(&app, 110, 30);
            assert!(!screen.is_empty());
        }

        // Same sweep in stacked mode.
        app.handle_resize(80, 24);
        for route in Route::ALL {
            app.route = route;
            let screen = render_app(&app, 80, 24);
            assert!(!screen.is_empty());
        }
    }

    #[test]
    fn promote_view_renders_columns_selection_and_stacks_when_small() {
        let mut app = sample_app();
        app.route = Route::Promote;

        let large = render_app(&app, 130, 40);
        for token in [
            "source refs",
            "environments",
            "NAME",
            "PROTECTED",
            "PINNED COMMIT",
            "feature/login",
            "main",
            "development",
            "production",
            "promotion target",
        ] {
            assert!(
                large.contains(token),
                "missing `{token}` in large promote view"
            );
        }
        assert!(large.contains("yes"), "protected flag must render");
        assert!(large.contains("enter promotes feature/login -> development"));

        // Small terminal: both sections plus the summary stay visible,
        // stacked vertically.
        app.handle_resize(80, 24);
        let small = render_app(&app, 80, 24);
        for token in [
            "source refs",
            "environments",
            "PINNED COMMIT",
            "promotion target",
            "development",
        ] {
            assert!(
                small.contains(token),
                "missing `{token}` in stacked promote view"
            );
        }

        // Selecting the protected env updates the summary guard text.
        send(&mut app, press(KeyCode::Tab));
        send(&mut app, press(KeyCode::Down));
        app.handle_resize(100, 30);
        let guarded = render_app(&app, 100, 30);
        assert!(guarded.contains("protected: needs confirm"));
    }

    #[test]
    fn sync_view_renders_login_remotes_and_last_run_lines() {
        let mut app = sample_app();
        app.route = Route::Sync;
        app.sync_lines = crate::state::sync_result_lines(
            "sync",
            &vaultx_sync_client::SyncResult {
                uploaded: 2,
                downloaded: 1,
                conflicts: Vec::new(),
                policies_applied: 3,
            },
        );

        let large = render_app(&app, 130, 40);
        for token in [
            "control plane",
            "login: present",
            "origin",
            "proj_team",
            "https://cp.example.com",
            "last sync",
            "sync: uploaded 2 object(s), downloaded 1 object(s)",
            "policies applied: 3",
            "refs: converged (no conflicts)",
        ] {
            assert!(
                large.contains(token),
                "missing `{token}` in large sync view"
            );
        }

        // Small terminal keeps every section.
        app.handle_resize(80, 24);
        let small = render_app(&app, 80, 24);
        for token in [
            "control plane",
            "login: present",
            "last sync",
            "policies applied: 3",
        ] {
            assert!(
                small.contains(token),
                "missing `{token}` in stacked sync view"
            );
        }

        // Missing login renders the actionable hint, never any token
        // material (there is deliberately none in state).
        let mut offline = sample_app();
        offline.route = Route::Sync;
        offline.loaded.sync.logged_in = false;
        assert!(render_app(&offline, 110, 30).contains("login: missing"));

        // In-flight operations show the busy indicator and swap the
        // binding bar to a non-actionable hint.
        let mut busy = sample_app();
        busy.route = Route::Sync;
        busy.sync_busy = true;
        let screen = render_app(&busy, 110, 30);
        assert!(screen.contains("⟳ working…"));
        assert!(binding_pairs(&busy).contains(&("…".to_owned(), "sync running".to_owned())));
        assert!(!binding_pairs(&busy).contains(&("u".to_owned(), "push".to_owned())));
    }

    #[test]
    fn binding_bar_lists_actions_for_the_new_views() {
        let mut app = sample_app();
        send(&mut app, key('6'));
        assert!(binding_pairs(&app).contains(&("tab".to_owned(), "ref/env".to_owned())));
        assert!(binding_pairs(&app).contains(&("enter".to_owned(), "promote".to_owned())));

        send(&mut app, key('7'));
        let pairs = binding_pairs(&app);
        assert!(pairs.contains(&("u".to_owned(), "push".to_owned())));
        assert!(pairs.contains(&("d".to_owned(), "pull".to_owned())));
        assert!(pairs.contains(&("s".to_owned(), "sync".to_owned())));
    }

    #[test]
    fn policy_editor_banner_flags_invalid_documents() {
        let mut loaded = sample_app().loaded;
        loaded.editor_seed = "name: [unclosed".to_owned();
        let mut invalid = App::with_size(loaded, DEFAULT_TERMINAL_SIZE);
        invalid.route = Route::PolicyEditor;
        assert!(!matches!(invalid.editor.validation, ValidationState::Valid));
        let bad_screen = render_app(&invalid, 110, 30);
        assert!(bad_screen.contains("INVALID"));
        assert!(bad_screen.contains("apply blocked"));

        let mut valid = App::with_size(sample_app().loaded, DEFAULT_TERMINAL_SIZE);
        valid.route = Route::PolicyEditor;
        assert!(matches!(valid.editor.validation, ValidationState::Valid));
        assert!(render_app(&valid, 110, 30).contains("valid policy"));
    }
}
