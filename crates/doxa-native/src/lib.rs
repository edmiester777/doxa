//! The native shell of a doxa app. The web crate's `#[doxa::app] fn app() -> App` builds it;
//! `doxa build --desktop` (and `--ios`, `--android`) bundles it with Tauri.
//!
//! The page is the web crate's own wasm: in `local` mode the in-process server serves it, in
//! `remote` mode Tauri does, and under `doxa dev` the dev server does.

#![deny(missing_docs)]

mod acl;
mod app;
mod guard;
mod local;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod menu;
mod plugin;
mod window;

pub use app::App;
pub use window::Window;

/// The origins a Tauri webview's requests come from, for a remote server's CORS allow-list.
pub const ORIGINS: &[&str] = &[
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
];
