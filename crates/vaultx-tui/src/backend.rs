//! Terminal plumbing: crossterm setup/teardown, the event loop, and the
//! mapping from state-machine [`Effect`]s onto application services.
//!
//! This module is deliberately thin — every decision worth testing lives
//! in [`crate::state`] (pure) or [`crate::view`] (TestBackend-driven).

use std::io::{stdout, Stdout};
use std::path::PathBuf;
use std::time::Duration;

use crossterm::event::{Event, KeyCode as CrosstermKeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use vaultx_broker::{FileSessionStore, SessionStore as _};
use vaultx_core::VaultxServices;

use crate::data::SnapshotSource;
use crate::error::TuiError;
use crate::state::{App, Effect, KeyCode, KeyInput};
use crate::view;

/// Launch configuration for [`run`], mirroring sibling CLI commands.
#[derive(Clone, Debug)]
pub struct TuiConfig {
    /// Project directory to open.
    pub project: PathBuf,
    /// Environment whose pinned commit backs the dashboard.
    pub env: Option<String>,
    /// Broker endpoint override; probed for agent/audit status lines.
    pub socket: Option<PathBuf>,
}

/// Runs the interactive UI until the user quits.
///
/// # Errors
/// * [`TuiError::Core`] when `project` is not a vaultx repository.
/// * [`TuiError::Terminal`] for terminal setup/render/event failures.
pub fn run(config: &TuiConfig) -> Result<(), TuiError> {
    let services = VaultxServices::open(&config.project)?;
    let source = SnapshotSource::new(&services, config.env.clone(), config.socket.as_deref());
    let mut app = App::with_size(source.load(), startup_size());

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
                        apply_effect(&mut app, effect, &source, &services)?;
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
        CrosstermKeyCode::Home => KeyCode::Home,
        CrosstermKeyCode::End => KeyCode::End,
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
    }
    Ok(())
}

fn reload(app: &mut App, source: &SnapshotSource<'_>) {
    app.loaded = source.load();
}

/// Revokes one session through the persistent session store. Failure
/// messages carry only transport text.
fn revoke_session(services: &VaultxServices, session_id: &str) -> Result<(), String> {
    use vaultx_broker::BrokerError;
    use vaultx_types::SessionId;

    let id = SessionId::parse(session_id)
        .map_err(|_| "expected a full session id (`sess_...`)".to_owned())?;
    let path = services.context().vault_dir().join("sessions.json");
    let store = FileSessionStore::open(path).map_err(|e| e.to_string())?;
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
        crossterm::execute!(stdout, EnterAlternateScreen)
            .map_err(|e| TuiError::Terminal(std::io::Error::other(e.to_string())))?;
        Ok(Self { stdout })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = crossterm::execute!(self.stdout, LeaveAlternateScreen);
    }
}
