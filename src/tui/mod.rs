pub mod input;
pub mod render;
pub mod state;
pub mod tail;

use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event as CEvent};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::watch;

use crate::events::{Event, EventSink};
use crate::trust::approvals::ApprovalsStore;
use crate::tui::input::{map_key, UiAction};
use crate::tui::render::draw;
use crate::tui::state::UiState;

pub struct UiSink {
    tx: Sender<Event>,
}

impl UiSink {
    pub fn new(tx: Sender<Event>) -> Self {
        Self { tx }
    }
}

impl EventSink for UiSink {
    fn emit(&mut self, event: Event) -> anyhow::Result<()> {
        let _ = self.tx.send(event);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TuiConfig {
    pub refresh_ms: u64,
    pub max_log_lines: usize,
    pub provider: String,
    pub model: String,
    pub caps_source: String,
    pub policy_hash: String,
}

pub fn run_live(
    rx: Receiver<Event>,
    approvals_path: std::path::PathBuf,
    cfg: TuiConfig,
    cancel_tx: watch::Sender<bool>,
) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = UiState::new(cfg.max_log_lines);
    state.provider = cfg.provider;
    state.model = cfg.model;
    state.caps_source = cfg.caps_source;
    state.policy_hash = cfg.policy_hash;
    let mut selected_approval = 0usize;
    let mut last_refresh = Instant::now();

    loop {
        while let Ok(ev) = rx.try_recv() {
            state.apply_event(&ev);
        }
        if last_refresh.elapsed() >= Duration::from_millis(400) {
            if let Err(e) = state.refresh_approvals(&approvals_path) {
                state.push_log(format!("approvals refresh failed: {e}"));
            }
            last_refresh = Instant::now();
            if selected_approval >= state.pending_approvals.len() {
                selected_approval = state.pending_approvals.len().saturating_sub(1);
            }
        }

        terminal.draw(|f| draw(f, &state, selected_approval))?;
        if event::poll(Duration::from_millis(cfg.refresh_ms))? {
            if let CEvent::Key(k) = event::read()? {
                if let Some(action) = map_key(k) {
                    match action {
                        UiAction::Quit => {
                            let _ = cancel_tx.send(true);
                            break;
                        }
                        UiAction::Up => {
                            selected_approval = selected_approval.saturating_sub(1);
                        }
                        UiAction::Down => {
                            if selected_approval + 1 < state.pending_approvals.len() {
                                selected_approval += 1;
                            }
                        }
                        UiAction::Refresh => {
                            if let Err(e) = state.refresh_approvals(&approvals_path) {
                                state.push_log(format!("approvals refresh failed: {e}"));
                            }
                        }
                        UiAction::Approve => {
                            if let Some(row) = state.pending_approvals.get(selected_approval) {
                                let store = ApprovalsStore::new(approvals_path.clone());
                                if let Err(e) = store.approve(&row.id, None, None) {
                                    state.push_log(format!("approve failed: {e}"));
                                } else {
                                    state.push_log(format!("approved {}", row.id));
                                }
                            }
                        }
                        UiAction::Deny => {
                            if let Some(row) = state.pending_approvals.get(selected_approval) {
                                let store = ApprovalsStore::new(approvals_path.clone());
                                if let Err(e) = store.deny(&row.id) {
                                    state.push_log(format!("deny failed: {e}"));
                                } else {
                                    state.push_log(format!("denied {}", row.id));
                                }
                            }
                        }
                        UiAction::ToggleDetails => {
                            state.show_details = !state.show_details;
                        }
                        UiAction::Tab => {}
                    }
                }
            }
        }

        if state.exit_reason.is_some() {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
