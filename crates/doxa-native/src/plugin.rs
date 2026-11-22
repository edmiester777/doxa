//! The `doxa` plugin: what `doxa::ui::native` calls. Its permissions are declared by
//! `doxa_role::client()` as an inlined plugin, under the names in `DOXA_COMMANDS`.

use std::sync::Mutex;

use serde::Deserialize;
use tauri::plugin::{Builder, TauriPlugin};
use tauri::{Emitter, Manager, Runtime, State, WebviewWindow};

/// Emitted with the URLs a deep link opened the app with.
pub(crate) const OPEN_URL_EVENT: &str = "doxa://open-url";

/// Deep-link URLs not yet taken by the page; the first launch's arrive before wasm listens.
#[derive(Default)]
pub(crate) struct OpenUrls(Mutex<Vec<String>>);

/// Records URLs a deep link opened, and tells a listening page.
pub(crate) fn opened<R: Runtime>(app: &tauri::AppHandle<R>, urls: Vec<String>) {
    if urls.is_empty() {
        return;
    }
    if let Some(buf) = app.try_state::<OpenUrls>() {
        buf.0
            .lock()
            .expect("open urls")
            .extend(urls.iter().cloned());
    }
    let _ = app.emit(OPEN_URL_EVENT, urls);
}

#[tauri::command]
fn take_open_urls(urls: State<'_, OpenUrls>) -> Vec<String> {
    std::mem::take(&mut *urls.0.lock().expect("open urls"))
}

/// What `native::window()` does.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case")]
enum WindowAction {
    Minimize,
    Maximize,
    ToggleMaximize,
    Fullscreen { on: bool },
    Show,
    Hide,
    Focus,
    Close,
    SetTitle { title: String },
}

#[tauri::command]
fn window<R: Runtime>(window: WebviewWindow<R>, action: WindowAction) -> Result<(), String> {
    let r = match action {
        WindowAction::Minimize => window.minimize(),
        WindowAction::Maximize => window.maximize(),
        WindowAction::ToggleMaximize => match window.is_maximized() {
            Ok(true) => window.unmaximize(),
            Ok(false) => window.maximize(),
            Err(e) => Err(e),
        },
        WindowAction::Fullscreen { on } => window.set_fullscreen(on),
        WindowAction::Show => window.show(),
        WindowAction::Hide => window.hide(),
        WindowAction::Focus => window.set_focus(),
        WindowAction::Close => window.close(),
        WindowAction::SetTitle { title } => window.set_title(&title),
    };
    r.map_err(|e| e.to_string())
}

/// The commands registered here; each must be in `doxa_role::native::DOXA_COMMANDS`.
#[cfg(test)]
const REGISTERED: &[&str] = &[
    "window",
    "take_open_urls",
    "menu_set",
    "menu_popup",
    "tray_set",
    "shortcut_set",
];

pub(crate) fn init<R: Runtime>() -> TauriPlugin<R> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let b = Builder::new("doxa").invoke_handler(tauri::generate_handler![
        window,
        take_open_urls,
        crate::menu::menu_set,
        crate::menu::menu_popup,
        crate::menu::tray_set,
        crate::menu::shortcut_set
    ]);
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let b = Builder::new("doxa").invoke_handler(tauri::generate_handler![window, take_open_urls]);
    b.setup(|app, _| {
        app.manage(OpenUrls::default());
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        app.on_menu_event(crate::menu::on_menu_event);
        Ok(())
    })
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_command_has_a_declared_permission() {
        for c in REGISTERED {
            assert!(doxa_role::native::DOXA_COMMANDS.contains(c), "{c}");
        }
    }

    #[test]
    fn window_actions_parse_from_the_page_s_json() {
        let parse = |v| serde_json::from_value::<WindowAction>(v).unwrap();
        assert_eq!(
            parse(serde_json::json!({ "action": "toggle_maximize" })),
            WindowAction::ToggleMaximize
        );
        assert_eq!(
            parse(serde_json::json!({ "action": "set_title", "title": "Shop" })),
            WindowAction::SetTitle {
                title: "Shop".into()
            }
        );
        assert_eq!(
            parse(serde_json::json!({ "action": "fullscreen", "on": true })),
            WindowAction::Fullscreen { on: true }
        );
    }
}
