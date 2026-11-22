//! [`App`]: what the web crate's `#[doxa::app]` fn returns, and how it runs.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use doxa::boot::{IntoServe, Stopping};
use doxa_role::native::{Server as Mode, Shell};
use tauri::ipc::Invoke;
use tauri::{AppHandle, Manager, RunEvent, Url, WebviewUrl, Wry};
use tauri_plugin_dialog::{DialogExt, MessageDialogKind};

use crate::acl::{self, Grant};
use crate::local::{self, Server};
use crate::window::{Window, MAIN};
use crate::{guard, plugin};

type Setup = Box<dyn FnOnce(&mut tauri::App<Wry>) -> Result<(), Box<dyn std::error::Error>> + Send>;
type Commands = Box<dyn Fn(Invoke<Wry>) -> bool + Send + Sync>;
type AddPlugin = Box<dyn FnOnce(tauri::Builder<Wry>) -> tauri::Builder<Wry>>;

/// A doxa app's native shell.
#[must_use = "return it from the `#[doxa::app]` fn"]
pub struct App {
    local: Option<local::Start>,
    window: Window,
    commands: Option<Commands>,
    plugins: Vec<AddPlugin>,
    grants: Vec<Grant>,
    setup: Option<Setup>,
    init: Option<fn()>,
    any_host: bool,
    single_instance: bool,
    window_state: bool,
}

impl Default for App {
    fn default() -> Self {
        App {
            local: None,
            window: Window::default(),
            commands: None,
            plugins: Vec::new(),
            grants: Vec::new(),
            setup: None,
            init: None,
            any_host: false,
            single_instance: true,
            window_state: true,
        }
    }
}

impl App {
    /// The defaults: one remembered window, a single instance, the v1 plugins.
    pub fn new() -> Self {
        Self::default()
    }

    /// What `server = "local"` serves: the api's router factory, as its bin's `start` calls it.
    pub fn local<F, Fut>(mut self, start: F) -> Self
    where
        F: FnOnce(Stopping) -> Fut + Send + 'static,
        Fut: Future<Output: IntoServe> + 'static,
    {
        self.local = Some(Box::new(move |stop| {
            Box::pin(async move { start(stop).await.into_serve() })
        }));
        self
    }

    /// The main window's size and limits.
    pub fn window(mut self, window: Window) -> Self {
        self.window = window;
        self
    }

    /// The app's `#[tauri::command]`s, from `tauri::generate_handler!`. List the same names in
    /// `build.rs`'s `doxa_role::Client::commands`, which is what lets the page call them.
    pub fn commands<F>(mut self, handler: F) -> Self
    where
        F: Fn(Invoke<Wry>) -> bool + Send + Sync + 'static,
    {
        self.commands = Some(Box::new(handler));
        self
    }

    /// Any Tauri plugin; grant what the page may call with [`App::permission`].
    pub fn plugin<P: tauri::plugin::Plugin<Wry> + 'static>(mut self, plugin: P) -> Self {
        self.plugins.push(Box::new(move |b| b.plugin(plugin)));
        self
    }

    /// Grants the page a permission, e.g. `"store:default"`.
    pub fn permission(mut self, permission: impl Into<String>) -> Self {
        self.grants.push(Grant::Plain(permission.into()));
        self
    }

    /// Lets `native::open_path` open paths matching `glob`, e.g. `"$DOCUMENT/**"`. Off by default:
    /// opening an arbitrary path can run a program.
    pub fn allow_open_path(mut self, glob: &str) -> Self {
        self.grants.push(acl::open_path(glob));
        self
    }

    /// Raw Tauri setup, after doxa's.
    pub fn setup<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut tauri::App<Wry>) -> Result<(), Box<dyn std::error::Error>> + Send + 'static,
    {
        self.setup = Some(Box::new(f));
        self
    }

    /// Runs first, like `#[doxa::main(init = f)]`; a default tracing subscriber otherwise.
    pub fn init(mut self, f: fn()) -> Self {
        self.init = Some(f);
        self
    }

    /// Lets requests with any `Host`, `Origin` or `Sec-Fetch-Site` reach the local server,
    /// including from tabs in the user's browser.
    pub fn allow_any_host(mut self) -> Self {
        self.any_host = true;
        self
    }

    /// Allows more than one running copy; by default a second launch focuses the first.
    pub fn multi_instance(mut self) -> Self {
        self.single_instance = false;
        self
    }

    /// Doesn't restore the window's size and position from the last run.
    pub fn forget_window_state(mut self) -> Self {
        self.window_state = false;
        self
    }

    #[doc(hidden)]
    pub fn __run(self, ctx: tauri::Context<Wry>, shell: &str) {
        let shell: Shell = serde_json::from_str(shell).expect("doxa_role wrote DOXA_NATIVE_CONFIG");
        match self.init {
            Some(init) => init(),
            None => default_tracing(),
        }
        let title = ctx.config().product_name.clone().unwrap_or_default();
        let page = match (ctx.config().build.dev_url.clone(), shell.config.server) {
            (Some(dev), _) => Page::Dev(dev),
            (None, Mode::Remote) => Page::Remote,
            (None, Mode::Local) => Page::Local(local::bind(shell.config.port())),
        };
        let App {
            local,
            window,
            commands,
            plugins,
            grants,
            setup,
            init: _,
            any_host,
            single_instance,
            window_state,
        } = self;
        let mut b = tauri::Builder::default();
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if single_instance {
            // First, so a second launch exits before anything else starts. Its deep links reach
            // `on_open_url` through the `deep-link` feature.
            b = b.plugin(tauri_plugin_single_instance::init(|app, _, _| {
                if let Some(w) = app.get_webview_window(MAIN) {
                    let _ = w.unminimize();
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }));
        }
        b = b
            .plugin(tauri_plugin_deep_link::init())
            .plugin(tauri_plugin_dialog::init())
            .plugin(tauri_plugin_opener::init())
            .plugin(tauri_plugin_notification::init())
            .plugin(tauri_plugin_clipboard_manager::init())
            .plugin(plugin::init());
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            b = b.plugin(tauri_plugin_global_shortcut::Builder::new().build());
            if window_state {
                b = b.plugin(tauri_plugin_window_state::Builder::default().build());
            }
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        let _ = (single_instance, window_state);
        for add in plugins {
            b = add(b);
        }
        if let Some(handler) = commands {
            b = b.invoke_handler(handler);
        }
        let stopping = Arc::new(AtomicBool::new(false));
        let on_exit = stopping.clone();
        let commands = shell.commands;
        let policy = crate::oidc::Policy {
            schemes: shell.config.schemes.clone(),
            loopback: shell.config.oidc_loopback.clone(),
        };
        let app = b
            .setup(move |app| {
                app.manage(policy);
                deep_links(app);
                let handle = app.handle().clone();
                match page {
                    Page::Dev(url) => {
                        app.add_capability(acl::capability(None, &commands, &grants))?;
                        window.open(&handle, WebviewUrl::App("/".into()), Some(url), &title)?;
                    }
                    Page::Remote => {
                        app.add_capability(acl::capability(None, &commands, &grants))?;
                        window.open(&handle, WebviewUrl::App("index.html".into()), None, &title)?;
                    }
                    Page::Local(bound) => {
                        let start = local.ok_or(
                            "`server = \"local\"` needs `.local(…)` on the `#[doxa::app]`'s App",
                        )?;
                        let bound = bound.map_err(|e| format!("binding the local server: {e}"))?;
                        let (port, moved) = (bound.port, bound.moved);
                        let origin: Url = format!("http://127.0.0.1:{port}/").parse()?;
                        app.add_capability(acl::capability(
                            Some(origin.as_str()),
                            &commands,
                            &grants,
                        ))?;
                        let wrap = move |r| {
                            if any_host {
                                r
                            } else {
                                guard::browser_tabs(r, port)
                            }
                        };
                        let ready = handle.clone();
                        let ended = handle.clone();
                        let stopping = stopping.clone();
                        let server = Server::spawn(
                            start,
                            bound,
                            wrap,
                            move |r| match r {
                                Ok(()) => open_local(&ready, window, origin, title, moved),
                                Err(e) => {
                                    fail(&ready, format!("The app's server didn't start: {e}"))
                                }
                            },
                            move |r| {
                                if !stopping.load(Ordering::SeqCst) {
                                    let why = r.err().unwrap_or_else(|| "it stopped".into());
                                    fail(&ended, format!("The app's server stopped: {why}"));
                                }
                            },
                        )?;
                        app.manage(Running(Mutex::new(server)));
                        exit_on_signal(&handle);
                    }
                }
                if let Some(setup) = setup {
                    setup(app)?;
                }
                Ok(())
            })
            .build(ctx)
            .expect("building the Tauri app");
        app.run(move |app, event| {
            if let RunEvent::ExitRequested { api, code, .. } = event {
                if app.try_state::<Running>().is_some() && !on_exit.swap(true, Ordering::SeqCst) {
                    api.prevent_exit();
                    drain_then_exit(app, code.unwrap_or(0));
                }
            }
        });
    }
}

enum Page {
    Dev(Url),
    Remote,
    Local(std::io::Result<local::Bound>),
}

/// The local server, once started.
struct Running(Mutex<Server>);

fn deep_links(app: &tauri::App<Wry>) {
    use tauri_plugin_deep_link::DeepLinkExt;
    let handle = app.handle().clone();
    // Linux and Windows register schemes at install; a dev build was never installed.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    if tauri::is_dev() {
        if let Err(e) = app.deep_link().register_all() {
            tracing::warn!(error = %e, "couldn't register the deep-link schemes");
        }
    }
    if let Ok(Some(urls)) = app.deep_link().get_current() {
        plugin::opened(&handle, urls.iter().map(Url::to_string).collect());
    }
    app.deep_link().on_open_url(move |e| {
        plugin::opened(&handle, e.urls().iter().map(Url::to_string).collect());
    });
}

fn open_local(app: &AppHandle<Wry>, window: Window, origin: Url, title: String, moved: bool) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        let url = WebviewUrl::External(origin.clone());
        if let Err(e) = window.open(&handle, url, Some(origin.clone()), &title) {
            fail(&handle, format!("The app's window didn't open: {e}"));
            return;
        }
        if moved {
            handle
                .dialog()
                .message(format!(
                    "Another program is using this app's port, so it started on {origin} instead. \
                     Anything stored by the app, including sign-in, is unavailable until it can use \
                     its own port again."
                ))
                .kind(MessageDialogKind::Warning)
                .show(|_| {});
        }
    });
}

/// Ctrl-C or SIGTERM (as `doxa dev` sends) quits like the menu does, so the server drains.
fn exit_on_signal(app: &AppHandle<Wry>) {
    let handle = app.clone();
    std::thread::spawn(move || {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            return;
        };
        rt.block_on(doxa::boot::shutdown_signal());
        handle.exit(0);
    });
}

/// Hides the window, drains the server, then exits with `code`.
fn drain_then_exit(app: &AppHandle<Wry>, code: i32) {
    if let Some(w) = app.get_webview_window(MAIN) {
        let _ = w.hide();
        // A hidden webview keeps its EventSources open, which would hold the drain.
        if let Ok(blank) = "about:blank".parse() {
            let _ = w.navigate(blank);
        }
    }
    let handle = app.clone();
    std::thread::spawn(move || {
        if let Some(running) = handle.try_state::<Running>() {
            let mut server = running.0.lock().expect("server");
            server.stop();
            server.join();
        }
        handle.exit(code);
    });
}

/// Tells the user what went wrong, then exits.
fn fail(app: &AppHandle<Wry>, message: String) {
    tracing::error!("{message}");
    let handle = app.clone();
    app.dialog()
        .message(message)
        .kind(MessageDialogKind::Error)
        .show(move |_| handle.exit(1));
}

fn default_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
