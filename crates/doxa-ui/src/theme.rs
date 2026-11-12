//! Themes: named sets of CSS custom properties on the document root, or an embedded root's
//! own element.

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
    /// Each element a root put the theme on, and how many roots share it.
    static HOSTS: RefCell<Vec<(NodeId, usize)>> = const { RefCell::new(Vec::new()) };
    /// The theme whose variables are on the hosts now.
    static APPLIED: Cell<Option<Theme>> = const { Cell::new(None) };
}

pub(crate) fn add_host(node: NodeId) {
    let new = HOSTS.with(|h| {
        let mut h = h.borrow_mut();
        match h.iter_mut().find(|(n, _)| *n == node) {
            Some((_, count)) => {
                *count += 1;
                false
            }
            None => {
                h.push((node, 1));
                true
            }
        }
    });
    if let (true, Some(t)) = (new, THEME.with(|t| t.borrow().current)) {
        APPLIED.with(|a| a.set(Some(t)));
        write(node, None, t);
    }
}

pub(crate) fn remove_host(node: NodeId) {
    HOSTS.with(|h| {
        let mut h = h.borrow_mut();
        if let Some(at) = h.iter().position(|(n, _)| *n == node) {
            h[at].1 -= 1;
            if h[at].1 == 0 {
                h.remove(at);
            }
        }
    });
}

/// Forget every host, for a new document.
pub(crate) fn clear_hosts() {
    HOSTS.with(|h| h.borrow_mut().clear());
    APPLIED.with(|a| a.set(None));
}

fn apply(theme: Theme) {
    let old = APPLIED.with(|a| a.replace(Some(theme)));
    let hosts: Vec<NodeId> = HOSTS.with(|h| h.borrow().iter().map(|(n, _)| *n).collect());
    for host in hosts {
        write(host, old, theme);
    }
}

fn write(host: NodeId, old: Option<Theme>, theme: Theme) {
    let dom = runtime::dom();
    dom.set_attr(host, "data-theme", theme.name);
    if let Some(old) = old {
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
