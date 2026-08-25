//! Terminal plumbing: crossterm setup/teardown, the event loop, and the
//! mapping from state-machine [`Effect`]s onto application services.
//!
//! This module is deliberately thin — every decision worth testing lives
//! in [`crate::state`] (pure) or [`crate::view`] (TestBackend-driven).

use std::io::{stdout, Stdout};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{Event, KeyCode as CrosstermKeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use vaultx_broker::SessionStore as _;
use vaultx_core::VaultxServices;
use vaultx_sync_client::SyncService as _;

use crate::data::{self, SnapshotSource};
use crate::error::TuiError;
use crate::state::{sync_result_lines, App, Effect, KeyCode, KeyInput};
use crate::view;

/// Launch configuration for [`run`], mirroring sibling CLI commands.
#[derive(Clone, Debug)]
pub struct TuiConfig {
    /// Already-opened project services; the CLI opens them first so its
    /// exit-code mapping stays authoritative and the UI never reopens.
    pub services: Arc<VaultxServices>,
    /// Environment whose pinned commit backs the dashboard.
    pub env: Option<String>,
    /// Broker endpoint override; probed for agent/audit status lines.
    pub socket: Option<PathBuf>,
}

/// Runs the interactive UI until the user quits.
///
/// # Errors
/// * [`TuiError::Terminal`] for terminal setup/render/event failures.
pub fn run(config: &TuiConfig) -> Result<(), TuiError> {
    let services = &config.services;
    let source = SnapshotSource::new(services, config.env.clone());
    // One blocking probe before the loop starts; every refresh reuses
    // this result so the render path never waits on the broker again.
    let broker = data::broker_status(config.socket.as_deref());
    let mut app = App::with_size(source.load(broker), startup_size());

    let _guard = TerminalGuard::new()?;
    let backend = CrosstermBackend::new(stdout());
    let mut terminal = Terminal::new(backend)?;

    loop {
        terminal.draw(|frame| view::render(frame, &app))?;
        if event_ready(Duration::from_millis(250))? {
            match read_event()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if let Some(input) = map_key(key) {
                        let effect = app.handle_key(input);
                        apply_effect(&mut app, effect, &source, services)?;
                    }
                }
                Event::Resize(width, height) => app.handle_resize(width, height),
                // Mouse events are intentionally ignored: keyboard
                // operation is complete without mouse support (plan §15).
                _ => {}
            }
        }
        if app.quit_requested {
            break;
        }
    }

    Ok(())
}

fn event_ready(timeout: Duration) -> Result<bool, TuiError> {
    crossterm::event::poll(timeout).map_err(Into::into)
}

/// Measures the real terminal size once so the first frame already uses
/// the correct layout; falls back to the documented default on failure.
fn startup_size() -> (u16, u16) {
    crossterm::terminal::size().unwrap_or(crate::state::DEFAULT_TERMINAL_SIZE)
}

fn read_event() -> Result<Event, TuiError> {
    crossterm::event::read().map_err(Into::into)
}

fn map_key(key: KeyEvent) -> Option<KeyInput> {
    let code = match key.code {
        CrosstermKeyCode::Char(c) => KeyCode::Char(c),
        CrosstermKeyCode::Enter => KeyCode::Enter,
        CrosstermKeyCode::Esc => KeyCode::Esc,
        CrosstermKeyCode::Tab => KeyCode::Tab,
        CrosstermKeyCode::Up => KeyCode::Up,
        CrosstermKeyCode::Down => KeyCode::Down,
        CrosstermKeyCode::Left => KeyCode::Left,
        CrosstermKeyCode::Right => KeyCode::Right,
        CrosstermKeyCode::Backspace => KeyCode::Backspace,
        CrosstermKeyCode::Delete => KeyCode::Delete,
        _ => return None,
    };
    Some(KeyInput {
        code,
        ctrl: key.modifiers.contains(KeyModifiers::CONTROL),
    })
}

/// Executes one state-machine effect against the real services.
fn apply_effect(
    app: &mut App,
    effect: Effect,
    source: &SnapshotSource<'_>,
    services: &VaultxServices,
) -> Result<(), TuiError> {
    match effect {
        Effect::None | Effect::Quit => {}
        Effect::Refresh => reload(app, source),
        Effect::ApplyPolicy {
            expected_name,
            yaml,
        } => match services.policies().save_policy_yaml(&expected_name, &yaml) {
            Ok(()) => {
                app.status = format!("policy `{expected_name}` applied");
                reload(app, source);
            }
            Err(err) => {
                app.status = format!("apply failed: {err}");
            }
        },
        Effect::RevokeSession { session_id } => match revoke_session(services, &session_id) {
            Ok(()) => {
                app.status = format!("revoked {session_id}");
                reload(app, source);
            }
            Err(err) => {
                app.status = format!("revoke failed: {err}");
            }
        },
        Effect::Promote {
            from_ref,
            to_env,
            force,
        } => match services.environments().promote(&from_ref, &to_env, force) {
            Ok(()) => {
                // Refresh first so the status line can name the commit
                // the target environment now pins.
                reload(app, source);
                let commit = app
                    .loaded
                    .snapshot
                    .envs
                    .iter()
                    .find(|env| env.name == to_env)
                    .and_then(|env| env.commit_short.clone())
                    .unwrap_or_else(|| "?".to_owned());
                app.status = format!("promoted {from_ref} -> {to_env} ({commit})");
            }
            Err(err) => {
                app.status = format!("promote failed: {err}");
            }
        },
        Effect::Push => run_sync_action(app, source, services, "push", SyncAction::Push),
        Effect::Pull => run_sync_action(app, source, services, "pull", SyncAction::Pull),
        Effect::SyncAll => run_sync_action(app, source, services, "sync", SyncAction::SyncAll),
    }
    Ok(())
}

/// Which shared sync operation one action runs.
enum SyncAction {
    Push,
    Pull,
    SyncAll,
}

/// Opens the shared sync context and runs one push/pull/sync through
/// [`vaultx_sync_client`] — the exact same hardened client the CLI uses.
/// Results land as lines in `app.sync_lines`; failures surface on the
/// status line (error text is secret-free by construction).
fn run_sync_action(
    app: &mut App,
    source: &SnapshotSource<'_>,
    services: &VaultxServices,
    label: &str,
    action: SyncAction,
) {
    let ctx = services.context();
    let opened = vaultx_sync_client::open_sync_context(ctx.root(), ctx.vault_dir(), None, false);
    let opened = match opened {
        Ok(opened) => opened,
        Err(err) => {
            app.sync_lines.clear();
            app.status = format!("{label} failed: {err}");
            return;
        }
    };
    let project = opened.project_id.clone();
    let outcome = data::run_blocking(async {
        match action {
            SyncAction::Push => opened.client.push(project).await,
            SyncAction::Pull => opened.client.pull(project).await,
            SyncAction::SyncAll => {
                let pushed = opened.client.push(project.clone()).await?;
                let pulled = opened.client.pull(project).await?;
                Ok(vaultx_sync_client::SyncResult {
                    uploaded: pushed.uploaded,
                    downloaded: pulled.downloaded,
                    conflicts: {
                        let mut all = pushed.conflicts;
                        all.extend(pulled.conflicts);
                        all
                    },
                    policies_applied: pulled.policies_applied,
                })
            }
        }
    });
    match outcome {
        Ok(result) => {
            app.sync_lines = sync_result_lines(label, &result);
            app.status = app.sync_lines.first().cloned().unwrap_or_default();
            if matches!(action, SyncAction::Pull | SyncAction::SyncAll) && result.is_converged() {
                reload(app, source);
            }
        }
        Err(err) => {
            app.sync_lines.clear();
            app.status = format!("{label} failed: {err}");
        }
    }
}

fn reload(app: &mut App, source: &SnapshotSource<'_>) {
    // Refreshes keep the one startup broker probe result; selections are
    // clamped against the fresh lengths so a shrinking snapshot cannot
    // strand an out-of-range index.
    let broker = app.loaded.broker.clone();
    app.swap_loaded(source.load(broker));
}

/// Revokes one session through the persistent session store. Failure
/// messages carry only transport text.
fn revoke_session(services: &VaultxServices, session_id: &str) -> Result<(), String> {
    use vaultx_broker::BrokerError;
    use vaultx_types::SessionId;

    let id = SessionId::parse(session_id)
        .map_err(|_| "expected a full session id (`sess_...`)".to_owned())?;
    let store = data::open_session_store(services)?;
    store.revoke(&id).map_err(|err| match err {
        BrokerError::InvalidSession => "no such session".to_owned(),
        other => other.to_string(),
    })
}

/// RAII terminal restoration: raw mode and the alternate screen are left
/// even when rendering errors unwind the loop.
struct TerminalGuard {
    #[allow(dead_code)]
    stdout: Stdout,
}

impl TerminalGuard {
    fn new() -> Result<Self, TuiError> {
        enable_raw_mode()?;
        let mut stdout = stdout();
        if let Err(err) = crossterm::execute!(stdout, EnterAlternateScreen) {
            // Restore raw mode before surfacing the failure; otherwise
            // the early return strands the terminal without echo.
            let _ = disable_raw_mode();
            return Err(TuiError::Terminal(std::io::Error::other(err.to_string())));
        }
        Ok(Self { stdout })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Leave the alternate screen before dropping raw mode so the
        // shell regains a normal terminal in the correct order.
        let _ = crossterm::execute!(self.stdout, LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}
