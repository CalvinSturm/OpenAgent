use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};

#[derive(Debug, Clone, Copy)]
pub enum UiAction {
    Quit,
    Up,
    Down,
    Approve,
    Deny,
    Refresh,
    Tab,
    ToggleDetails,
}

pub fn map_key(key: KeyEvent) -> Option<UiAction> {
    if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
        return None;
    }
    match key.code {
        KeyCode::Char('q') => Some(UiAction::Quit),
        KeyCode::Char('j') | KeyCode::Down => Some(UiAction::Down),
        KeyCode::Char('k') | KeyCode::Up => Some(UiAction::Up),
        KeyCode::Char('a') => Some(UiAction::Approve),
        KeyCode::Char('d') => Some(UiAction::Deny),
        KeyCode::Char('r') => Some(UiAction::Refresh),
        KeyCode::Char('v') => Some(UiAction::ToggleDetails),
        KeyCode::Tab => Some(UiAction::Tab),
        _ => None,
    }
}
