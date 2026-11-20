//! `doxa dev` in a terminal: each service's output in its own pane, under its status.

mod draw;
mod state;

use std::io::stdout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::DefaultTerminal;

use state::{Mode, State};
pub use state::{Pane, Shared, Status};

/// Whether both ends of the terminal are interactive.
pub fn available() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal() && std::io::stdin().is_terminal()
}

/// The screen while it is up; dropping it gives the terminal back.
pub struct Tui {
    quit: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Tui {
    pub fn start(shared: Arc<Shared>) -> std::io::Result<Tui> {
        let terminal = ratatui::try_init()?;
        execute!(stdout(), EnableMouseCapture)?;
        let quit = Arc::new(AtomicBool::new(false));
        let done = quit.clone();
        let thread = std::thread::spawn(move || run(terminal, &shared, &done));
        Ok(Tui {
            quit,
            thread: Some(thread),
        })
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        self.quit.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        let _ = execute!(stdout(), DisableMouseCapture);
        ratatui::restore();
    }
}

fn run(mut terminal: DefaultTerminal, shared: &Shared, quit: &AtomicBool) {
    while !quit.load(Ordering::Acquire) {
        // A frame at most every 50 ms, however fast lines arrive.
        if event::poll(Duration::from_millis(50)).unwrap_or(false) {
            while let Ok(true) = event::poll(Duration::ZERO) {
                match event::read() {
                    Ok(Event::Key(k)) if k.kind != KeyEventKind::Release => {
                        key(&mut shared.lock(), k)
                    }
                    Ok(Event::Mouse(m)) => mouse(&mut shared.lock(), m),
                    Ok(Event::Resize(..)) => drop(shared.lock()),
                    _ => {}
                }
            }
        }
        if shared.take_dirty() {
            let _ = terminal.draw(|f| draw::draw(f, &mut shared.view()));
        }
    }
}

fn key(s: &mut State, k: KeyEvent) {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    if ctrl && k.code == KeyCode::Char('c') {
        return s.stop();
    }
    match s.mode {
        Mode::Help => s.mode = Mode::Normal,
        Mode::Filter => filter_key(s, k.code),
        Mode::Normal => normal_key(s, k.code),
    }
}

fn filter_key(s: &mut State, code: KeyCode) {
    let done = matches!(code, KeyCode::Enter | KeyCode::Esc);
    if done {
        s.mode = Mode::Normal;
    }
    let p = s.focused();
    match code {
        KeyCode::Char(c) => p.filter.get_or_insert_default().push(c),
        KeyCode::Backspace => {
            if let Some(f) = &mut p.filter {
                f.pop();
            }
        }
        KeyCode::Esc => p.filter = None,
        _ => {}
    }
    if done && p.filter.as_deref() == Some("") {
        p.filter = None;
    }
    p.scroll = 0;
}

fn normal_key(s: &mut State, code: KeyCode) {
    let page = s
        .rects
        .iter()
        .find(|(o, _)| *o == s.focus)
        .map_or(10, |(_, r)| r.height.saturating_sub(2).max(1) as isize);
    match code {
        KeyCode::Char('q') => s.stop(),
        KeyCode::Tab => s.focus_by(1),
        KeyCode::BackTab => s.focus_by(-1),
        KeyCode::Char(d @ '1'..='9') => {
            let i = d as usize - '1' as usize;
            if i < s.order.len() {
                s.focus = i;
            }
        }
        KeyCode::Up | KeyCode::Char('k') => s.focused().scroll_by(1),
        KeyCode::Down | KeyCode::Char('j') => s.focused().scroll_by(-1),
        KeyCode::PageUp => s.focused().scroll_by(page),
        KeyCode::PageDown => s.focused().scroll_by(-page),
        KeyCode::Home | KeyCode::Char('g') => s.focused().scroll_by(isize::MAX),
        KeyCode::End | KeyCode::Char('G' | 'f') => s.focused().scroll = 0,
        KeyCode::Enter | KeyCode::Char('z') => s.zoom = !s.zoom,
        KeyCode::Esc => {
            if s.zoom {
                s.zoom = false;
            } else {
                s.focused().filter = None;
            }
        }
        KeyCode::Char('r') => {
            if let Some(kick) = &s.focused().kick {
                let _ = kick.send(true);
            }
        }
        KeyCode::Char('c') => s.focused().clear(),
        KeyCode::Char('/') => s.mode = Mode::Filter,
        KeyCode::Char('m') => {
            s.mouse = !s.mouse;
            let _ = match s.mouse {
                true => execute!(stdout(), EnableMouseCapture),
                false => execute!(stdout(), DisableMouseCapture),
            };
        }
        KeyCode::Char('?') => s.mode = Mode::Help,
        _ => {}
    }
}

fn mouse(s: &mut State, m: MouseEvent) {
    let hit = s.at(m.column, m.row);
    match m.kind {
        MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
            if let Some((o, _)) = hit {
                let delta = if m.kind == MouseEventKind::ScrollUp {
                    3
                } else {
                    -3
                };
                s.panes[s.order[o]].scroll_by(delta);
            }
        }
        MouseEventKind::Down(MouseButton::Left) => {
            let Some((o, r)) = hit else { return };
            s.focus = o;
            if m.row != r.y {
                return;
            }
            let now = Instant::now();
            let double = s
                .last_click
                .is_some_and(|(at, prev)| prev == o && now - at < Duration::from_millis(400));
            s.last_click = Some((now, o));
            if double {
                s.zoom = !s.zoom;
                s.drag = None;
            } else if !s.zoom && o > 0 {
                s.drag = Some(o);
            }
        }
        MouseEventKind::Drag(MouseButton::Left) => {
            if let Some(lower) = s.drag {
                s.drag_to(lower, m.row);
            }
        }
        MouseEventKind::Up(MouseButton::Left) => s.drag = None,
        _ => {}
    }
}
