//! The native shell's APIs. Each exists only in builds whose target has it, so using one outside
//! a matching `#[doxa::native]` / `#[doxa::desktop]` gate doesn't compile. They need doxa's
//! `native` feature.

#[cfg(all(feature = "native", doxa_desktop))]
mod desktop;
#[cfg(all(feature = "native", doxa_native))]
mod io;

#[cfg(all(feature = "native", doxa_desktop))]
pub use desktop::{
    context_menu, menu, open_path, shortcut, tray, window, Item, Menu, Standard, Tray, Window,
};

#[cfg(all(feature = "native", doxa_native))]
pub use doxa_client::native::Error as Native;
#[cfg(all(feature = "native", doxa_native))]
pub use io::{clipboard, dialog, notify, on, on_open_url, open_url, Notification};

/// Where the page is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    /// A browser tab: no native shell.
    Web,
    Macos,
    Windows,
    Linux,
    Ios,
    Android,
}

/// Where the page is running; [`Platform::Web`] in a plain web build.
pub fn platform() -> Platform {
    #[cfg(all(doxa_native, target_arch = "wasm32"))]
    {
        let named = web_sys::window()
            .and_then(|w| js_sys::Reflect::get(&w, &"__DOXA_PLATFORM__".into()).ok())
            .and_then(|v| v.as_string());
        match named.as_deref() {
            Some("macos") => Platform::Macos,
            Some("windows") => Platform::Windows,
            Some("linux") => Platform::Linux,
            Some("ios") => Platform::Ios,
            Some("android") => Platform::Android,
            _ => Platform::Web,
        }
    }
    #[cfg(not(all(doxa_native, target_arch = "wasm32")))]
    Platform::Web
}

/// Calls a shell command: one the app's `#[doxa::app]` registers, or a plugin's as
/// `plugin:<name>|<command>`.
#[cfg(all(feature = "native", doxa_native))]
pub async fn invoke<T: serde::de::DeserializeOwned>(
    cmd: &str,
    args: &impl serde::Serialize,
) -> Result<T, Native> {
    doxa_client::native::invoke(cmd, args).await
}
