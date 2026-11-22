//! The app's main window.

use tauri::{AppHandle, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder, Wry};

/// The main window's label; the runtime capability is bound to it.
pub(crate) const MAIN: &str = "main";

/// The main window's size and limits, in logical pixels; mobile ignores them. Its title follows
/// the page's `title()`.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(any(target_os = "android", target_os = "ios"), allow(dead_code))]
pub struct Window {
    size: (f64, f64),
    min_size: Option<(f64, f64)>,
    resizable: bool,
}

impl Default for Window {
    fn default() -> Self {
        Window {
            size: (1200.0, 800.0),
            min_size: None,
            resizable: true,
        }
    }
}

impl Window {
    /// A 1200×800 resizable window.
    pub fn new() -> Self {
        Self::default()
    }

    /// The initial size.
    pub fn size(mut self, width: f64, height: f64) -> Self {
        self.size = (width, height);
        self
    }

    /// The smallest size it can be resized to.
    pub fn min_size(mut self, width: f64, height: f64) -> Self {
        self.min_size = Some((width, height));
        self
    }

    /// Whether it can be resized.
    pub fn resizable(mut self, resizable: bool) -> Self {
        self.resizable = resizable;
        self
    }

    /// Opens it on `url`. `origin` is the page's own; links anywhere else open in the browser.
    pub(crate) fn open(
        self,
        app: &AppHandle<Wry>,
        url: WebviewUrl,
        origin: Option<Url>,
        title: &str,
    ) -> tauri::Result<WebviewWindow<Wry>> {
        let mut b = WebviewWindowBuilder::new(app, MAIN, url)
            .title(title)
            .initialization_script(platform_script());
        // On mobile the window is the screen; a size would leave the rest of it black.
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            b = b
                .inner_size(self.size.0, self.size.1)
                .resizable(self.resizable);
            if let Some((w, h)) = self.min_size {
                b = b.min_inner_size(w, h);
            }
        }
        let nav_origin = origin.clone();
        let opener = app.clone();
        b = b.on_navigation(move |url| stay(&opener, nav_origin.as_ref(), url));
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let opener = app.clone();
            b = b.on_new_window(move |url, _| {
                let _ = stay(&opener, None, &url);
                tauri::webview::NewWindowResponse::Deny
            });
        }
        b.build()
    }
}

/// Whether the window may navigate to `url`; anything off the page's origin opens in the browser.
fn stay(app: &AppHandle<Wry>, origin: Option<&Url>, url: &Url) -> bool {
    let same = |o: &Url| o.origin() == url.origin();
    let internal = matches!(
        url.scheme(),
        "tauri" | "about" | "data" | "blob" | "ipc" | "asset"
    ) || url.host_str() == Some("tauri.localhost");
    if internal || origin.is_some_and(same) {
        return true;
    }
    if matches!(url.scheme(), "http" | "https" | "mailto" | "tel") {
        use tauri_plugin_opener::OpenerExt;
        if let Err(e) = app.opener().open_url(url.as_str(), None::<&str>) {
            tracing::warn!(%url, error = %e, "couldn't open a link in the browser");
        }
    }
    false
}

/// `window.__DOXA_PLATFORM__`, read synchronously by `native::platform()`.
fn platform_script() -> String {
    let platform = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else if cfg!(target_os = "android") {
        "android"
    } else {
        "linux"
    };
    format!("window.__DOXA_PLATFORM__ = {platform:?};")
}
