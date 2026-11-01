//! Themes: named sets of CSS custom properties on the document root.

use std::cell::{Cell, RefCell};

use crate::dom::NodeId;
use crate::runtime::{self, Readers};

/// A theme: a name, written to `data-theme`, and the CSS variables it sets.
///
/// ```ignore
/// pub const DARK: Theme = Theme::new("dark", &[("--bg", "#111"), ("--fg", "#eee")]);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    /// Written to the root's `data-theme` attribute.
    pub name: &'static str,
    /// CSS custom properties, names including the leading `--`.
    pub vars: &'static [(&'static str, &'static str)],
}

impl Theme {
    /// A theme named `name` setting `vars`.
    pub const fn new(name: &'static str, vars: &'static [(&'static str, &'static str)]) -> Self {
        Self { name, vars }
    }
}

struct ThemeCell {
    current: Option<Theme>,
    readers: Readers,
}

thread_local! {
    static THEME: RefCell<ThemeCell> = const { RefCell::new(ThemeCell { current: None, readers: Readers::new() }) };
    static HOST: Cell<Option<NodeId>> = const { Cell::new(None) };
    /// The theme whose variables are on the host now.
    static APPLIED: Cell<Option<Theme>> = const { Cell::new(None) };
}

pub(crate) fn set_host(node: NodeId) {
    HOST.with(|h| h.set(Some(node)));
    APPLIED.with(|a| a.set(None));
    if let Some(t) = THEME.with(|t| t.borrow().current) {
        apply(t);
    }
}

fn apply(theme: Theme) {
    let Some(host) = HOST.with(Cell::get) else {
        return;
    };
    let dom = runtime::dom();
    dom.set_attr(host, "data-theme", theme.name);
    if let Some(old) = APPLIED.with(|a| a.replace(Some(theme))) {
        for (k, _) in old.vars {
            if !theme.vars.iter().any(|(n, _)| n == k) {
                dom.set_style(host, k, None);
            }
        }
    }
    for (k, v) in theme.vars {
        dom.set_style(host, k, Some(v));
    }
}

/// The active theme; the calling component re-renders when it changes.
pub fn theme() -> Option<Theme> {
    THEME.with(|t| {
        let mut t = t.borrow_mut();
        t.readers.track();
        t.current
    })
}

/// Switch to `theme`.
pub fn set_theme(theme: Theme) {
    let readers = THEME.with(|t| {
        let mut t = t.borrow_mut();
        t.current = Some(theme);
        t.readers.live()
    });
    apply(theme);
    runtime::schedule_all(readers);
}
