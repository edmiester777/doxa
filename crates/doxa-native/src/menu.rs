//! Menus, the tray and global shortcuts the page describes; each choice comes back as an event
//! naming the id the page gave it.

use serde::Deserialize;
use tauri::menu::{
    IsMenuItem, Menu, MenuEvent, MenuItemBuilder, PredefinedMenuItem, Submenu, SubmenuBuilder,
};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Runtime, WebviewWindow};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};

pub(crate) const MENU_EVENT: &str = "doxa://menu";
pub(crate) const TRAY_EVENT: &str = "doxa://tray";
pub(crate) const SHORTCUT_EVENT: &str = "doxa://shortcut";
const TRAY: &str = "doxa";
/// The id `Standard::Quit` gets, so quitting drains the local server.
const QUIT: &str = "doxa:quit";

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Entry {
    Item {
        id: String,
        label: String,
        #[serde(default)]
        shortcut: Option<String>,
        #[serde(default = "yes")]
        enabled: bool,
    },
    Separator,
    Standard {
        which: Standard,
    },
    Submenu {
        label: String,
        items: Vec<Entry>,
    },
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Standard {
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

type Items<R> = Vec<Box<dyn IsMenuItem<R>>>;

fn items<R: Runtime>(app: &AppHandle<R>, entries: &[Entry]) -> tauri::Result<Items<R>> {
    let mut out: Items<R> = Vec::with_capacity(entries.len());
    for e in entries {
        out.push(match e {
            Entry::Item {
                id,
                label,
                shortcut,
                enabled,
            } => {
                let mut b = MenuItemBuilder::with_id(id.as_str(), label).enabled(*enabled);
                if let Some(s) = shortcut {
                    b = b.accelerator(s);
                }
                Box::new(b.build(app)?)
            }
            Entry::Separator => Box::new(PredefinedMenuItem::separator(app)?),
            Entry::Standard { which } => standard(app, *which)?,
            Entry::Submenu { label, items: sub } => Box::new(submenu(app, label, sub)?),
        });
    }
    Ok(out)
}

fn submenu<R: Runtime>(
    app: &AppHandle<R>,
    label: &str,
    entries: &[Entry],
) -> tauri::Result<Submenu<R>> {
    let built = items(app, entries)?;
    let refs: Vec<&dyn IsMenuItem<R>> = built.iter().map(|b| b.as_ref()).collect();
    SubmenuBuilder::new(app, label).items(&refs).build()
}

fn standard<R: Runtime>(
    app: &AppHandle<R>,
    which: Standard,
) -> tauri::Result<Box<dyn IsMenuItem<R>>> {
    let name = app.package_info().name.clone();
    Ok(match which {
        Standard::Quit => Box::new(
            MenuItemBuilder::with_id(QUIT, format!("Quit {name}"))
                .accelerator("CmdOrCtrl+Q")
                .build(app)?,
        ),
        Standard::About => Box::new(PredefinedMenuItem::about(app, None, None)?),
        Standard::Undo => Box::new(PredefinedMenuItem::undo(app, None)?),
        Standard::Redo => Box::new(PredefinedMenuItem::redo(app, None)?),
        Standard::Cut => Box::new(PredefinedMenuItem::cut(app, None)?),
        Standard::Copy => Box::new(PredefinedMenuItem::copy(app, None)?),
        Standard::Paste => Box::new(PredefinedMenuItem::paste(app, None)?),
        Standard::SelectAll => Box::new(PredefinedMenuItem::select_all(app, None)?),
        Standard::Minimize => Box::new(PredefinedMenuItem::minimize(app, None)?),
        Standard::Fullscreen => Box::new(PredefinedMenuItem::fullscreen(app, None)?),
        Standard::CloseWindow => Box::new(PredefinedMenuItem::close_window(app, None)?),
        Standard::Hide => Box::new(PredefinedMenuItem::hide(app, None)?),
        Standard::HideOthers => Box::new(PredefinedMenuItem::hide_others(app, None)?),
        Standard::ShowAll => Box::new(PredefinedMenuItem::show_all(app, None)?),
        Standard::Services => Box::new(PredefinedMenuItem::services(app, None)?),
    })
}

/// The app menu: `entries`, plus on macOS the App, Edit and Window submenus it lacks, without
/// which Cmd+C/V/X/A don't reach the page.
pub(crate) fn app_menu(entries: &[Entry], app_name: &str) -> Vec<Entry> {
    if !cfg!(target_os = "macos") {
        return entries.to_vec();
    }
    with_mac_defaults(entries, app_name)
}

fn with_mac_defaults(entries: &[Entry], app_name: &str) -> Vec<Entry> {
    use Standard::*;
    let has = |l: &str| {
        entries
            .iter()
            .any(|e| matches!(e, Entry::Submenu { label, .. } if label == l))
    };
    let sub = |label: &str, items: Vec<Entry>| Entry::Submenu {
        label: label.into(),
        items,
    };
    let std = |w| Entry::Standard { which: w };
    let mut out = Vec::with_capacity(entries.len() + 3);
    // macOS makes the first submenu the app menu, whatever its label.
    if !has(app_name) {
        out.push(sub(
            app_name,
            vec![
                std(About),
                Entry::Separator,
                std(Services),
                Entry::Separator,
                std(Hide),
                std(HideOthers),
                std(ShowAll),
                Entry::Separator,
                std(Quit),
            ],
        ));
    }
    out.extend(entries.iter().cloned());
    if !has("Edit") {
        let at = out.len().min(2);
        out.insert(
            at,
            sub(
                "Edit",
                vec![
                    std(Undo),
                    std(Redo),
                    Entry::Separator,
                    std(Cut),
                    std(Copy),
                    std(Paste),
                    std(SelectAll),
                ],
            ),
        );
    }
    if !has("Window") {
        out.push(sub(
            "Window",
            vec![
                std(Minimize),
                std(Fullscreen),
                Entry::Separator,
                std(CloseWindow),
            ],
        ));
    }
    out
}

fn build<R: Runtime>(app: &AppHandle<R>, entries: &[Entry]) -> tauri::Result<Menu<R>> {
    let built = items(app, entries)?;
    let refs: Vec<&dyn IsMenuItem<R>> = built.iter().map(|b| b.as_ref()).collect();
    Menu::with_items(app, &refs)
}

/// Every menu choice, from the app menu, a context menu or the tray's.
pub(crate) fn on_menu_event<R: Runtime>(app: &AppHandle<R>, event: MenuEvent) {
    match event.id().as_ref() {
        QUIT => app.exit(0),
        id => {
            let _ = app.emit(MENU_EVENT, id);
        }
    }
}

#[tauri::command]
pub(crate) fn menu_set<R: Runtime>(
    app: AppHandle<R>,
    menu: Option<Vec<Entry>>,
) -> Result<(), String> {
    let name = app.package_info().name.clone();
    let built = match menu {
        Some(entries) => build(&app, &app_menu(&entries, &name)),
        None => Menu::default(&app),
    };
    built
        .and_then(|m| app.set_menu(m))
        .map(drop)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) fn menu_popup<R: Runtime>(
    window: WebviewWindow<R>,
    menu: Vec<Entry>,
) -> Result<(), String> {
    build(window.app_handle(), &menu)
        .and_then(|m| window.popup_menu(&m))
        .map_err(|e| e.to_string())
}

#[derive(Debug, Deserialize)]
pub(crate) struct Tray {
    #[serde(default)]
    tooltip: Option<String>,
    #[serde(default)]
    menu: Option<Vec<Entry>>,
}

#[tauri::command]
pub(crate) fn tray_set<R: Runtime>(app: AppHandle<R>, tray: Option<Tray>) -> Result<(), String> {
    let Some(tray) = tray else {
        app.remove_tray_by_id(TRAY);
        return Ok(());
    };
    let menu = match &tray.menu {
        Some(entries) => Some(build(&app, entries).map_err(|e| e.to_string())?),
        None => None,
    };
    let r = match app.tray_by_id(TRAY) {
        Some(icon) => icon
            .set_tooltip(tray.tooltip.as_deref())
            .and_then(|()| icon.set_menu(menu)),
        None => {
            let mut b = TrayIconBuilder::with_id(TRAY)
                .show_menu_on_left_click(false)
                .on_tray_icon_event(|icon, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        let _ = icon.app_handle().emit(TRAY_EVENT, "click");
                    }
                });
            if let Some(icon) = app.default_window_icon() {
                b = b.icon(icon.clone());
            }
            if let Some(t) = &tray.tooltip {
                b = b.tooltip(t);
            }
            if let Some(m) = &menu {
                b = b.menu(m);
            }
            b.build(&app).map(drop)
        }
    };
    r.map_err(|e| e.to_string())
}

#[derive(Debug, Deserialize)]
pub(crate) struct Shortcut {
    id: String,
    accelerator: String,
}

/// Replaces every global shortcut with `shortcuts`.
#[tauri::command]
pub(crate) fn shortcut_set<R: Runtime>(
    app: AppHandle<R>,
    shortcuts: Vec<Shortcut>,
) -> Result<(), String> {
    let g = app.global_shortcut();
    g.unregister_all().map_err(|e| e.to_string())?;
    let mut failed = Vec::new();
    for s in shortcuts {
        let id = s.id;
        let r = g.on_shortcut(s.accelerator.as_str(), move |app, _, event| {
            if event.state == ShortcutState::Pressed {
                let _ = app.emit(SHORTCUT_EVENT, &id);
            }
        });
        if let Err(e) = r {
            failed.push(format!("{}: {e}", s.accelerator));
        }
    }
    match failed.is_empty() {
        true => Ok(()),
        false => Err(format!("couldn't register {}", failed.join("; "))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_s_menu_json_parses() {
        let m: Vec<Entry> = serde_json::from_value(serde_json::json!([
            { "kind": "submenu", "label": "File", "items": [
                { "kind": "item", "id": "c1/0", "label": "Save", "shortcut": "CmdOrCtrl+S" },
                { "kind": "separator" },
                { "kind": "standard", "which": "quit" },
            ]},
        ]))
        .unwrap();
        let Entry::Submenu { items, .. } = &m[0] else {
            panic!("{m:?}")
        };
        assert!(matches!(
            &items[0],
            Entry::Item {
                enabled: true,
                shortcut: Some(_),
                ..
            }
        ));
        assert_eq!(
            items[2],
            Entry::Standard {
                which: Standard::Quit
            }
        );
    }

    fn labels(m: &[Entry]) -> Vec<&str> {
        m.iter()
            .filter_map(|e| match e {
                Entry::Submenu { label, .. } => Some(label.as_str()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn macos_gets_the_app_edit_and_window_menus_it_lacks() {
        let file = Entry::Submenu {
            label: "File".into(),
            items: vec![],
        };
        assert_eq!(
            labels(&with_mac_defaults(std::slice::from_ref(&file), "Shop")),
            ["Shop", "File", "Edit", "Window"]
        );
        let edit = Entry::Submenu {
            label: "Edit".into(),
            items: vec![],
        };
        assert_eq!(
            labels(&with_mac_defaults(&[file, edit], "Shop")),
            ["Shop", "File", "Edit", "Window"]
        );
    }
}
