//! What the TUI shows: one pane per service, fed from any thread.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use ansi_to_tui::IntoText;
use ratatui::layout::Rect;
use ratatui::style::Color;
use ratatui::text::{Line, Span};
use tokio::sync::{mpsc, watch};

/// Lines kept per pane.
const KEEP: usize = 10_000;

/// Where a service is in its build-and-run cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pending,
    Compiling,
    Patching,
    /// Built, and held until its `after` services listen.
    Waiting,
    /// Listening on the port; `None` for the web crate, whose dist is served.
    Running(Option<u16>),
    /// The build failed; `running` when the last good build still serves.
    Failed {
        running: bool,
    },
    Exited,
    /// Something else already holds the port.
    External(u16),
    Unready,
    Stopping,
    Stopped,
}

impl Status {
    pub fn label(self) -> (String, Color) {
        match self {
            Status::Pending => ("◌ pending".into(), Color::DarkGray),
            Status::Compiling => ("◐ compiling".into(), Color::Yellow),
            Status::Patching => ("◐ patching".into(), Color::Yellow),
            Status::Waiting => ("◌ waiting".into(), Color::DarkGray),
            Status::Running(Some(p)) => (format!("● running :{p}"), Color::Green),
            Status::Running(None) => ("● ready".into(), Color::Green),
            Status::Failed { running: true } => {
                ("✖ build failed · last good running".into(), Color::Red)
            }
            Status::Failed { running: false } => ("✖ build failed".into(), Color::Red),
            Status::Exited => ("✖ exited".into(), Color::Red),
            Status::External(p) => (format!("● external :{p}"), Color::Cyan),
            Status::Unready => ("▲ not listening".into(), Color::Red),
            Status::Stopping => ("◌ stopping".into(), Color::DarkGray),
            Status::Stopped => ("○ stopped".into(), Color::DarkGray),
        }
    }
}

pub struct Entry {
    pub line: Line<'static>,
    /// Lowercased, without ANSI, for the filter.
    plain: String,
}

impl Entry {
    fn new(raw: &str) -> Entry {
        let raw = raw.replace('\t', "    ");
        let line = match raw.into_text() {
            Ok(text) => Line::from(
                text.lines
                    .into_iter()
                    .flat_map(|l| l.spans)
                    .collect::<Vec<Span<'static>>>(),
            ),
            Err(_) => Line::raw(raw),
        };
        let plain = line
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect::<String>()
            .to_lowercase();
        Entry { line, plain }
    }
}

pub struct PaneState {
    pub name: String,
    pub status: Status,
    lines: VecDeque<Entry>,
    /// Lines back from the newest shown one; 0 follows.
    pub scroll: usize,
    pub filter: Option<String>,
    pub weight: u16,
    pub kick: Option<mpsc::UnboundedSender<bool>>,
}

impl PaneState {
    fn new(name: &str) -> PaneState {
        PaneState {
            name: name.to_owned(),
            status: Status::Pending,
            lines: VecDeque::new(),
            scroll: 0,
            filter: None,
            weight: 1,
            kick: None,
        }
    }

    fn push(&mut self, raw: &str) {
        let entry = Entry::new(raw);
        if self.lines.len() == KEEP {
            self.lines.pop_front();
        }
        // A pane scrolled back stays on what it shows.
        if self.scroll > 0 && self.matches(&entry) {
            self.scroll += 1;
        }
        self.lines.push_back(entry);
    }

    fn matches(&self, e: &Entry) -> bool {
        self.filter
            .as_deref()
            .is_none_or(|f| e.plain.contains(&f.to_lowercase()))
    }

    /// The lines the filter lets through, oldest first.
    pub fn shown(&self) -> Vec<&Entry> {
        self.lines.iter().filter(|e| self.matches(e)).collect()
    }

    pub fn scroll_by(&mut self, delta: isize) {
        let max = self.shown().len().saturating_sub(1);
        self.scroll = self.scroll.saturating_add_signed(delta).min(max);
    }

    pub fn clear(&mut self) {
        self.lines.clear();
        self.scroll = 0;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Filter,
    Help,
}

pub struct State {
    pub panes: Vec<PaneState>,
    /// Pane ids top to bottom.
    pub order: Vec<usize>,
    /// Index into `order`.
    pub focus: usize,
    pub zoom: bool,
    pub mode: Mode,
    pub mouse: bool,
    pub header: Vec<String>,
    pub stop: Option<watch::Sender<u32>>,
    pub stops: u32,
    /// Each drawn pane's position in `order` and its area, from the last frame.
    pub rects: Vec<(usize, Rect)>,
    pub drag: Option<usize>,
    pub last_click: Option<(Instant, usize)>,
}

impl State {
    pub fn focused(&mut self) -> &mut PaneState {
        let id = self.order[self.focus];
        &mut self.panes[id]
    }

    pub fn focus_by(&mut self, delta: isize) {
        let n = self.order.len() as isize;
        self.focus = (self.focus as isize + delta).rem_euclid(n) as usize;
    }

    /// The drawn pane under a cell.
    pub fn at(&self, col: u16, row: u16) -> Option<(usize, Rect)> {
        self.rects.iter().copied().find(|(_, r)| {
            (r.x..r.x + r.width).contains(&col) && (r.y..r.y + r.height).contains(&row)
        })
    }

    /// Move the border above pane `lower` (an index into `order`) to `row`.
    pub fn drag_to(&mut self, lower: usize, row: u16) {
        let find = |i: usize| self.rects.iter().find(|(o, _)| *o == i).map(|(_, r)| *r);
        let (Some(up), Some(lo)) = (find(lower - 1), find(lower)) else {
            return;
        };
        let bottom = lo.y + lo.height;
        let row = row.clamp(up.y + 2, bottom.saturating_sub(2).max(up.y + 2));
        for &(o, r) in &self.rects {
            self.panes[self.order[o]].weight = r.height.max(1);
        }
        self.panes[self.order[lower - 1]].weight = row - up.y;
        self.panes[self.order[lower]].weight = (bottom - row).max(1);
    }

    pub fn stop(&mut self) {
        self.stops += 1;
        if let Some(stop) = &self.stop {
            stop.send_modify(|n| *n += 1);
        }
    }
}

/// The TUI's state, and whether it changed since the last frame.
pub struct Shared {
    state: Mutex<State>,
    dirty: AtomicBool,
}

impl Shared {
    /// Starts with the web crate's pane, which doxa's own notes also go to.
    pub fn new() -> Arc<Shared> {
        Arc::new(Shared {
            state: Mutex::new(State {
                panes: vec![PaneState::new("web")],
                order: vec![0],
                focus: 0,
                zoom: false,
                mode: Mode::Normal,
                mouse: true,
                header: Vec::new(),
                stop: None,
                stops: 0,
                rects: Vec::new(),
                drag: None,
                last_click: None,
            }),
            dirty: AtomicBool::new(true),
        })
    }

    /// The state, marked for a redraw.
    pub fn lock(&self) -> MutexGuard<'_, State> {
        self.dirty.store(true, Ordering::Release);
        self.view()
    }

    /// The state, for drawing it.
    pub fn view(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn take_dirty(&self) -> bool {
        self.dirty.swap(false, Ordering::AcqRel)
    }

    pub fn web(self: &Arc<Self>) -> Pane {
        Pane {
            shared: self.clone(),
            id: 0,
        }
    }

    /// A new pane above the web crate's, or below it when `after_web`.
    pub fn add(self: &Arc<Self>, name: &str, after_web: bool) -> Pane {
        let mut s = self.lock();
        let id = s.panes.len();
        s.panes.push(PaneState::new(name));
        let at = match after_web {
            true => s.order.len(),
            false => s.order.iter().position(|&i| i == 0).unwrap_or(0),
        };
        s.order.insert(at, id);
        Pane {
            shared: self.clone(),
            id,
        }
    }
}

/// One pane's handle, for the task that feeds it.
#[derive(Clone)]
pub struct Pane {
    shared: Arc<Shared>,
    id: usize,
}

impl Pane {
    pub fn line(&self, raw: &str) {
        self.shared.lock().panes[self.id].push(raw);
    }

    pub fn status(&self, status: Status) {
        self.shared.lock().panes[self.id].status = status;
    }

    pub fn rename(&self, name: &str) {
        name.clone_into(&mut self.shared.lock().panes[self.id].name);
    }

    /// Where `r` sends a restart: `true` forces one even when the build is fresh.
    pub fn kicks(&self, tx: mpsc::UnboundedSender<bool>) {
        self.shared.lock().panes[self.id].kick = Some(tx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_go_above_the_web_pane_and_the_server_below() {
        let shared = Shared::new();
        shared.add("auth", false);
        shared.add("shop-api", false);
        shared.add("server", true);
        let s = shared.lock();
        let names: Vec<_> = s.order.iter().map(|&i| s.panes[i].name.as_str()).collect();
        assert_eq!(names, ["auth", "shop-api", "web", "server"]);
    }

    #[test]
    fn ansi_is_parsed_and_the_filter_ignores_it_and_case() {
        let mut p = PaneState::new("api");
        p.push("\x1b[31mError\x1b[0m: boom");
        p.push("ok");
        assert_eq!(p.lines[0].line.spans[0].content, "Error");
        assert_eq!(p.lines[0].line.spans[0].style.fg, Some(Color::Red));
        p.filter = Some("ERROR".into());
        assert_eq!(p.shown().len(), 1);
    }

    #[test]
    fn a_scrolled_pane_holds_its_place_and_scrolling_stops_at_the_ends() {
        let mut p = PaneState::new("api");
        (0..5).for_each(|i| p.push(&i.to_string()));
        p.scroll_by(2);
        p.push("5");
        assert_eq!(p.scroll, 3);
        p.scroll_by(100);
        assert_eq!(p.scroll, 5);
        p.scroll_by(-100);
        assert_eq!(p.scroll, 0);
        p.push("6");
        assert_eq!(p.scroll, 0);
    }

    #[test]
    fn dragging_a_border_resizes_only_its_two_panes() {
        let shared = Shared::new();
        shared.add("a", false);
        shared.add("b", false);
        let mut s = shared.lock();
        s.rects = vec![
            (0, Rect::new(0, 1, 80, 10)),
            (1, Rect::new(0, 11, 80, 10)),
            (2, Rect::new(0, 21, 80, 10)),
        ];
        s.drag_to(1, 6);
        let weights: Vec<_> = s.order.iter().map(|&i| s.panes[i].weight).collect();
        assert_eq!(weights, [5, 15, 10]);
        s.drag_to(1, 0);
        assert_eq!(s.panes[s.order[0]].weight, 2);
    }
}
