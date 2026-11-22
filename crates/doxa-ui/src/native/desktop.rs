//! What only desktop shells have: the app menu, context menus, the tray, global shortcuts and
//! window controls. Handlers stay in wasm; the shell gets ids and sends them back as events.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use serde_json::{json, Value};

use super::Native;
use crate::browser::hold;
use crate::hooks::{effect, slot};
use doxa_client::native::{invoke, listen, Listener};

type Handler = Rc<dyn Fn()>;

/// A menu: the app menu's top level (usually submenus), a context menu, or the tray's.
#[derive(Clone, Default)]
pub struct Menu {
    nodes: Vec<Node>,
}

#[derive(Clone)]
enum Node {
    Item(Item),
    Separator,
    Standard(Standard),
    Submenu(String, Menu),
}

/// A menu item that runs its handler when chosen.
#[derive(Clone)]
pub struct Item {
    label: String,
    shortcut: Option<String>,
    enabled: bool,
    on: Option<Handler>,
}

/// An item the system provides, labelled and behaving as the platform expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standard {
    /// Quits the app, letting the local server drain.
    Quit,
    About,
    Undo,
    Redo,
    Cut,
    Copy,
    Paste,
    SelectAll,
    Minimize,
    Fullscreen,
    CloseWindow,
    Hide,
    HideOthers,
    ShowAll,
    Services,
}

impl Standard {
    fn name(self) -> &'static str {
        match self {
            Standard::Quit => "quit",
            Standard::About => "about",
            Standard::Undo => "undo",
            Standard::Redo => "redo",
            Standard::Cut => "cut",
            Standard::Copy => "copy",
            Standard::Paste => "paste",
            Standard::SelectAll => "select_all",
            Standard::Minimize => "minimize",
            Standard::Fullscreen => "fullscreen",
            Standard::CloseWindow => "close_window",
            Standard::Hide => "hide",
            Standard::HideOthers => "hide_others",
            Standard::ShowAll => "show_all",
            Standard::Services => "services",
        }
    }
}

impl Menu {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn item(mut self, item: Item) -> Self {
        self.nodes.push(Node::Item(item));
        self
    }

    pub fn separator(mut self) -> Self {
        self.nodes.push(Node::Separator);
        self
    }

    pub fn standard(mut self, s: Standard) -> Self {
        self.nodes.push(Node::Standard(s));
        self
    }

    /// A submenu; in the app menu, one with the same label as another contribution's merges.
    pub fn submenu(mut self, label: impl Into<String>, build: impl FnOnce(Menu) -> Menu) -> Self {
        self.nodes
            .push(Node::Submenu(label.into(), build(Menu::new())));
        self
    }

    /// The shell's JSON, ids `<prefix>/<path>`, and each id's handler.
    fn wire(&self, prefix: &str, handlers: &mut HashMap<String, Handler>) -> Vec<Value> {
        self.nodes
            .iter()
            .enumerate()
            .map(|(i, n)| {
                let id = format!("{prefix}/{i}");
                match n {
                    Node::Item(item) => {
                        if let Some(on) = &item.on {
                            handlers.insert(id.clone(), on.clone());
                        }
                        let mut v = json!({ "kind": "item", "id": id, "label": item.label, "enabled": item.enabled });
                        if let Some(s) = &item.shortcut {
                            v["shortcut"] = s.as_str().into();
                        }
                        v
                    }
                    Node::Separator => json!({ "kind": "separator" }),
                    Node::Standard(s) => json!({ "kind": "standard", "which": s.name() }),
                    Node::Submenu(label, m) => {
                        json!({ "kind": "submenu", "label": label, "items": m.wire(&id, handlers) })
                    }
                }
            })
            .collect()
    }
}

impl Item {
    pub fn new(label: impl Into<String>) -> Self {
        Item {
            label: label.into(),
            shortcut: None,
            enabled: true,
            on: None,
        }
    }

    /// Its accelerator, e.g. `CmdOrCtrl+S`; it works while the app is focused.
    pub fn shortcut(mut self, accelerator: impl Into<String>) -> Self {
        self.shortcut = Some(accelerator.into());
        self
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }

    pub fn on(mut self, f: impl Fn() + 'static) -> Self {
        self.on = Some(Rc::new(f));
        self
    }
}

/// The app's tray icon, with the app's icon.
#[derive(Clone, Default)]
pub struct Tray {
    tooltip: Option<String>,
    on_click: Option<Handler>,
    menu: Option<Menu>,
}

impl Tray {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tooltip(mut self, t: impl Into<String>) -> Self {
        self.tooltip = Some(t.into());
        self
    }

    /// Runs on a left click; the menu opens on a right click.
    pub fn on_click(mut self, f: impl Fn() + 'static) -> Self {
        self.on_click = Some(Rc::new(f));
        self
    }

    pub fn menu(mut self, m: Menu) -> Self {
        self.menu = Some(m);
        self
    }
}

#[derive(Default)]
struct Registry {
    next: u64,
    /// Contributions to the app menu, in mount order.
    menus: Vec<(u64, Menu)>,
    trays: Vec<(u64, Tray)>,
    shortcuts: Vec<(u64, String, Handler)>,
    menu_handlers: HashMap<String, Handler>,
    tray_handlers: HashMap<String, Handler>,
    popup: HashMap<String, Handler>,
    tray_click: Option<Handler>,
    shortcut_handlers: HashMap<String, Handler>,
    /// What changed since the last send.
    dirty: Dirty,
    scheduled: bool,
    listening: Vec<Listener>,
}

#[derive(Default, Clone, Copy)]
struct Dirty {
    menu: bool,
    tray: bool,
    shortcuts: bool,
}

thread_local! {
    static REG: RefCell<Registry> = RefCell::default();
}

fn with<R>(f: impl FnOnce(&mut Registry) -> R) -> R {
    REG.with(|r| f(&mut r.borrow_mut()))
}

fn id() -> u64 {
    with(|r| {
        r.next += 1;
        r.next
    })
}

/// Listens for the shell's menu, tray and shortcut events, once.
fn listening() {
    if with(|r| !r.listening.is_empty()) {
        return;
    }
    let run = |h: Option<Handler>| {
        if let Some(h) = h {
            h()
        }
    };
    let ls = vec![
        listen(MENU_EVENT, move |id: String| {
            run(with(|r| {
                [&r.menu_handlers, &r.tray_handlers, &r.popup]
                    .into_iter()
                    .find_map(|h| h.get(&id))
                    .cloned()
            }))
        }),
        listen(TRAY_EVENT, move |_: String| {
            run(with(|r| r.tray_click.clone()))
        }),
        listen(SHORTCUT_EVENT, move |id: String| {
            run(with(|r| r.shortcut_handlers.get(&id).cloned()))
        }),
    ];
    with(|r| r.listening = ls);
}

const MENU_EVENT: &str = "doxa://menu";
const TRAY_EVENT: &str = "doxa://tray";
const SHORTCUT_EVENT: &str = "doxa://shortcut";

/// The app menu from every contribution: same-label submenus merge, in mount order.
fn merged(menus: &[(u64, Menu)]) -> Menu {
    let mut out = Menu::new();
    for (_, m) in menus {
        for n in &m.nodes {
            match n {
                Node::Submenu(label, sub) => {
                    let same = out.nodes.iter_mut().find_map(|o| match o {
                        Node::Submenu(l, m) if l == label => Some(m),
                        _ => None,
                    });
                    match same {
                        Some(m) => m.nodes.extend(sub.nodes.iter().cloned()),
                        None => out.nodes.push(n.clone()),
                    }
                }
                _ => out.nodes.push(n.clone()),
            }
        }
    }
    out
}

/// Sends what changed once the current task yields, so a commit sends each at most once.
fn schedule(d: Dirty) {
    let start = with(|r| {
        r.dirty.menu |= d.menu;
        r.dirty.tray |= d.tray;
        r.dirty.shortcuts |= d.shortcuts;
        !std::mem::replace(&mut r.scheduled, true)
    });
    if start {
        listening();
        doxa_client::task::spawn(send());
    }
}

async fn send() {
    let (dirty, menu, tray, shortcuts) = with(|r| {
        r.scheduled = false;
        let dirty = std::mem::take(&mut r.dirty);
        let menu = app_menu(r);
        let tray = tray_wire(r);
        r.shortcut_handlers = r
            .shortcuts
            .iter()
            .map(|(id, _, h)| (format!("s{id}"), h.clone()))
            .collect();
        let shortcuts: Vec<Value> = r
            .shortcuts
            .iter()
            .map(|(id, acc, _)| json!({ "id": format!("s{id}"), "accelerator": acc }))
            .collect();
        (dirty, menu, tray, shortcuts)
    });
    if dirty.menu {
        report(invoke::<()>("plugin:doxa|menu_set", &json!({ "menu": menu })).await);
    }
    if dirty.tray {
        report(invoke::<()>("plugin:doxa|tray_set", &json!({ "tray": tray })).await);
    }
    if dirty.shortcuts {
        report(
            invoke::<()>(
                "plugin:doxa|shortcut_set",
                &json!({ "shortcuts": shortcuts }),
            )
            .await,
        );
    }
}

/// The merged app menu's JSON, `null` with no contributions; refreshes its handlers.
fn app_menu(r: &mut Registry) -> Value {
    let mut handlers = HashMap::new();
    let menu = match r.menus.is_empty() {
        true => Value::Null,
        false => Value::Array(merged(&r.menus).wire("m", &mut handlers)),
    };
    r.menu_handlers = handlers;
    menu
}

/// The winning tray's JSON, `null` with none; refreshes its handlers.
fn tray_wire(r: &mut Registry) -> Value {
    let mut handlers = HashMap::new();
    let tray = match r.trays.last() {
        None => {
            r.tray_click = None;
            Value::Null
        }
        Some((_, t)) => {
            r.tray_click = t.on_click.clone();
            let mut v = json!({});
            if let Some(tip) = &t.tooltip {
                v["tooltip"] = tip.as_str().into();
            }
            if let Some(m) = &t.menu {
                v["menu"] = m.wire("t", &mut handlers).into();
            }
            v
        }
    };
    r.tray_handlers = handlers;
    tray
}

fn report(r: Result<(), Native>) {
    if let Err(e) = r {
        crate::runtime::warn(&format!("doxa native: {e}"));
    }
}

/// Removes a contribution when its component unmounts or the contribution changes.
struct Contribution(u64, fn(&mut Registry, u64) -> Dirty);

impl Drop for Contribution {
    fn drop(&mut self) {
        let Ok(d) = REG.try_with(|r| (self.1)(&mut r.borrow_mut(), self.0)) else {
            return;
        };
        schedule(d);
    }
}

/// Adds `m` to the app menu while this component is mounted. Same-label submenus from different
/// components merge, in mount order; on macOS the standard App, Edit and Window menus are kept.
#[track_caller]
pub fn menu(m: Menu) {
    let (_, _, me) = slot("native::menu", id);
    let me = *me;
    let shape = Value::Array(m.wire(&format!("c{me}"), &mut HashMap::new()));
    // Handlers update every render; the shell hears only of shape changes.
    with(|r| {
        if let Some(e) = r.menus.iter_mut().find(|(i, _)| *i == me) {
            e.1 = m.clone();
            app_menu(r);
        }
    });
    effect(&shape, async move |_: &Value| {
        with(|r| r.menus.push((me, m)));
        schedule(Dirty {
            menu: true,
            ..Dirty::default()
        });
        hold(Contribution(me, |r, me| {
            r.menus.retain(|(i, _)| *i != me);
            Dirty {
                menu: true,
                ..Dirty::default()
            }
        }))
        .await
    });
}

/// Shows the tray icon while this component is mounted; the deepest-mounted, latest one wins.
#[track_caller]
pub fn tray(t: Tray) {
    let (_, _, me) = slot("native::tray", id);
    let me = *me;
    let mut handlers = HashMap::new();
    let shape = json!({
        "tooltip": t.tooltip,
        "menu": t.menu.as_ref().map(|m| m.wire("t", &mut handlers)),
    });
    with(|r| {
        if let Some(e) = r.trays.iter_mut().find(|(i, _)| *i == me) {
            e.1 = t.clone();
            tray_wire(r);
        }
    });
    effect(&shape, async move |_: &Value| {
        with(|r| r.trays.push((me, t)));
        schedule(Dirty {
            tray: true,
            ..Dirty::default()
        });
        hold(Contribution(me, |r, me| {
            r.trays.retain(|(i, _)| *i != me);
            Dirty {
                tray: true,
                ..Dirty::default()
            }
        }))
        .await
    });
}

/// Runs `f` on `accelerator` (e.g. `CmdOrCtrl+Shift+Space`) system-wide, even with the app in
/// the background, while this component is mounted.
#[track_caller]
pub fn shortcut(accelerator: &str, f: impl Fn() + 'static) {
    let (_, _, me) = slot("native::shortcut", id);
    let me = *me;
    let f: Handler = Rc::new(f);
    with(|r| {
        if let Some(e) = r.shortcuts.iter_mut().find(|(i, ..)| *i == me) {
            e.2 = f.clone();
            r.shortcut_handlers.insert(format!("s{me}"), f.clone());
        }
    });
    effect(&accelerator.to_owned(), async move |acc: &String| {
        with(|r| r.shortcuts.push((me, acc.clone(), f)));
        schedule(Dirty {
            shortcuts: true,
            ..Dirty::default()
        });
        hold(Contribution(me, |r, me| {
            r.shortcuts.retain(|(i, ..)| *i != me);
            Dirty {
                shortcuts: true,
                ..Dirty::default()
            }
        }))
        .await
    });
}

/// Opens `m` at the pointer, instead of the webview's own context menu.
pub fn context_menu(e: &crate::Event, m: Menu) {
    e.prevent_default();
    let mut popup = HashMap::new();
    let wire = m.wire("p", &mut popup);
    with(|r| r.popup = popup);
    listening();
    doxa_client::task::spawn(async move {
        report(invoke::<()>("plugin:doxa|menu_popup", &json!({ "menu": wire })).await);
    });
}

/// The app's window. Each call returns at once; a failure is logged.
#[derive(Debug, Clone, Copy)]
pub struct Window(());

/// The app's window.
pub fn window() -> Window {
    Window(())
}

impl Window {
    fn act(self, action: Value) {
        doxa_client::task::spawn(async move {
            report(invoke::<()>("plugin:doxa|window", &json!({ "action": action })).await);
        });
    }

    pub fn minimize(self) {
        self.act(json!({ "action": "minimize" }))
    }

    pub fn maximize(self) {
        self.act(json!({ "action": "maximize" }))
    }

    pub fn toggle_maximize(self) {
        self.act(json!({ "action": "toggle_maximize" }))
    }

    pub fn fullscreen(self, on: bool) {
        self.act(json!({ "action": "fullscreen", "on": on }))
    }

    pub fn show(self) {
        self.act(json!({ "action": "show" }))
    }

    pub fn hide(self) {
        self.act(json!({ "action": "hide" }))
    }

    /// Shows, unminimizes and focuses it.
    pub fn focus(self) {
        self.act(json!({ "action": "show" }));
        self.act(json!({ "action": "focus" }))
    }

    pub fn close(self) {
        self.act(json!({ "action": "close" }))
    }

    pub fn set_title(self, title: &str) {
        self.act(json!({ "action": "set_title", "title": title }))
    }
}

/// Opens `path` with its default app. Needs `.allow_open_path(glob)` on the `#[doxa::app]`'s
/// `App` to cover it.
pub async fn open_path(path: &str) -> Result<(), Native> {
    invoke("plugin:opener|open_path", &json!({ "path": path })).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_get_path_ids_and_their_handlers() {
        let m = Menu::new().submenu("File", |m| {
            m.item(Item::new("Save").shortcut("CmdOrCtrl+S").on(|| {}))
                .separator()
                .standard(Standard::Quit)
        });
        let mut h = HashMap::new();
        assert_eq!(
            m.wire("m", &mut h),
            vec![json!({ "kind": "submenu", "label": "File", "items": [
                { "kind": "item", "id": "m/0/0", "label": "Save", "enabled": true, "shortcut": "CmdOrCtrl+S" },
                { "kind": "separator" },
                { "kind": "standard", "which": "quit" },
            ]})]
        );
        assert!(h.contains_key("m/0/0"));
    }

    #[test]
    fn same_label_submenus_merge_in_mount_order() {
        let a = Menu::new().submenu("File", |m| m.item(Item::new("Open")));
        let b = Menu::new()
            .submenu("Edit", |m| m.standard(Standard::Copy))
            .submenu("File", |m| m.item(Item::new("Save")));
        let m = merged(&[(1, a), (2, b)]);
        let wire = m.wire("m", &mut HashMap::new());
        assert_eq!(wire.len(), 2);
        assert_eq!(wire[0]["label"], "File");
        assert_eq!(wire[0]["items"][1]["label"], "Save");
        assert_eq!(wire[1]["label"], "Edit");
    }
}
