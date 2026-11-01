//! `doxa dev`: build once, run the server behind a reloading proxy, and rebuild only
//! what a change touches.

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use doxa_build::config::{WebCrate, Workspace};
use doxa_build::dist::Dist;
use doxa_build::pipeline::note;
use doxa_build::{BuildOptions, Pipeline};
use notify_debouncer_mini::notify::RecursiveMode;
use notify_debouncer_mini::{new_debouncer, DebounceEventResult};
use tokio::sync::{broadcast, mpsc};

type DynError = Box<dyn std::error::Error>;

const RELOAD_PATH: &str = "/__doxa/reload";
const API_PREFIX: &str = "/api";

const RELOAD_SCRIPT: &str = r#"<script type="module">
const es = new EventSource("/__doxa/reload");
es.addEventListener("reload", () => location.reload());
es.addEventListener("css", (e) => {
  const old = [...document.querySelectorAll("link[data-doxa-css]")];
  for (const href of JSON.parse(e.data)) {
    const link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = href;
    link.setAttribute("data-doxa-css", "");
    link.onload = () => old.forEach((l) => l.remove());
    document.head.append(link);
  }
});
</script>
"#;

/// What a batch of changes needs redone.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    pub wasm: bool,
    pub server: bool,
    pub bundle: bool,
    pub css: bool,
}

impl Plan {
    fn is_empty(self) -> bool {
        self == Plan::default()
    }
}

/// Which directories feed which build.
#[derive(Debug, Clone)]
pub struct Watch {
    root: PathBuf,
    ignore: Vec<PathBuf>,
    wasm_dirs: Vec<PathBuf>,
    server_dirs: Vec<PathBuf>,
    extra_dirs: Vec<PathBuf>,
    public: Option<PathBuf>,
}

fn canonical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_owned())
}

impl Watch {
    fn new(ws: &Workspace, web: &WebCrate, server: &str) -> Watch {
        let root = canonical(&ws.workspace_root);
        let extra_dirs = [
            root.join("style"),
            root.join("ts"),
            web.dir.join("style"),
            web.dir.join("ts"),
        ]
        .iter()
        .filter(|d| d.is_dir())
        .map(|d| canonical(d))
        .collect();
        Watch {
            ignore: vec![canonical(&ws.target_directory)],
            wasm_dirs: ws
                .source_dirs(&web.name)
                .iter()
                .map(|d| canonical(d))
                .collect(),
            server_dirs: ws
                .source_dirs(server)
                .iter()
                .map(|d| canonical(d))
                .collect(),
            extra_dirs,
            public: web
                .config
                .public
                .as_ref()
                .map(|p| canonical(&web.dir.join(p))),
            root,
        }
    }

    /// Directories to watch recursively, outermost only, plus the root itself.
    fn roots(&self) -> Vec<(PathBuf, RecursiveMode)> {
        let mut dirs: Vec<PathBuf> = self
            .wasm_dirs
            .iter()
            .chain(&self.server_dirs)
            .chain(&self.extra_dirs)
            .filter(|d| d.is_dir() && !self.ignore.iter().any(|i| d.starts_with(i)))
            .cloned()
            .collect();
        dirs.sort();
        dirs.dedup();
        let outer: Vec<PathBuf> = dirs
            .iter()
            .filter(|d| !dirs.iter().any(|o| o != *d && d.starts_with(o)))
            .cloned()
            .collect();
        let mut roots: Vec<_> = outer
            .into_iter()
            .map(|d| (d, RecursiveMode::Recursive))
            .collect();
        if !roots.iter().any(|(d, _)| *d == self.root) {
            roots.push((self.root.clone(), RecursiveMode::NonRecursive));
        }
        roots
    }
}

/// Decide what to rebuild for a batch of changed paths.
pub fn classify<'a>(paths: impl IntoIterator<Item = &'a Path>, w: &Watch) -> Plan {
    let mut plan = Plan::default();
    let under = |p: &Path, dirs: &[PathBuf]| dirs.iter().any(|d| p.starts_with(d));
    for p in paths {
        let skipped = w.ignore.iter().any(|i| p.starts_with(i))
            || p.components()
                .any(|c| c.as_os_str() == "node_modules" || c.as_os_str() == ".git");
        if skipped {
            continue;
        }
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        match ext {
            "rs" | "toml" if ext == "rs" || name == "Cargo.toml" => {
                if p.parent() == Some(w.root.as_path()) && name == "Cargo.toml" {
                    plan.wasm = true;
                    plan.server = true;
                }
                plan.wasm |= under(p, &w.wasm_dirs);
                plan.server |= under(p, &w.server_dirs);
            }
            "ts" | "tsx" | "js" | "jsx" | "mjs" => plan.bundle = true,
            "css" => plan.css = true,
            _ if name == "index.html" || w.public.as_deref().is_some_and(|d| p.starts_with(d)) => {
                plan.bundle = true
            }
            _ => {}
        }
    }
    plan
}

fn rebuild(p: &mut Pipeline, plan: Plan) -> doxa_build::Result<Option<Dist>> {
    if plan.wasm {
        p.npm()?;
        p.wasm()?;
        p.js()?;
        p.css()?;
    } else {
        if plan.bundle {
            p.js()?;
        }
        if plan.css {
            p.css()?;
        }
    }
    if plan.wasm || plan.bundle || plan.css {
        p.assemble().map(Some)
    } else {
        Ok(None)
    }
}

/// Run `doxa dev` until interrupted.
pub async fn run(package: Option<String>, port: u16, locked: bool) -> Result<(), DynError> {
    let cwd = std::env::current_dir()?;
    let opts = BuildOptions {
        release: false,
        package,
        locked,
        compress: false,
    };
    let pipeline = tokio::task::spawn_blocking(move || -> doxa_build::Result<Pipeline> {
        let mut p = Pipeline::new(&cwd, opts)?;
        p.build()?;
        Ok(p)
    })
    .await??;
    let server_pkg = pipeline.web.config.server.clone().ok_or(
        "no server to run\n  fix: set server = \"<server package>\" in the web crate's [package.metadata.doxa]",
    )?;
    let dist = canonical(&pipeline.dist_dir());
    let watch = Watch::new(&pipeline.workspace, &pipeline.web, &server_pkg);
    let mut server = Server {
        root: pipeline.workspace.workspace_root.clone(),
        package: server_pkg,
        dist: dist.clone(),
        port: free_port()?,
        child: None,
    };
    let pipeline = Arc::new(Mutex::new(pipeline));
    server.start()?;

    let (reload, _) = broadcast::channel(16);
    let proxy = Arc::new(Proxy {
        dist,
        upstream: format!("http://127.0.0.1:{}", server.port),
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        reload: reload.clone(),
    });
    let app = Router::new()
        .route(RELOAD_PATH, get(reload_events))
        .fallback(forward)
        .with_state(proxy);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    note(format!("serving http://127.0.0.1:{port}"));
    tokio::spawn(async move { axum::serve(listener, app).await });

    let (changed, mut changes) = mpsc::unbounded_channel::<Vec<PathBuf>>();
    let mut debouncer = new_debouncer(
        Duration::from_millis(200),
        move |res: DebounceEventResult| {
            if let Ok(events) = res {
                let _ = changed.send(events.into_iter().map(|e| e.path).collect());
            }
        },
    )?;
    for (dir, mode) in watch.roots() {
        debouncer.watcher().watch(&dir, mode)?;
    }

    loop {
        let mut paths = tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            Some(paths) = changes.recv() => paths,
        };
        while let Ok(more) = changes.try_recv() {
            paths.extend(more);
        }
        let plan = classify(paths.iter().map(PathBuf::as_path), &watch);
        if plan.is_empty() {
            continue;
        }
        let p = pipeline.clone();
        let built =
            tokio::task::spawn_blocking(move || rebuild(&mut p.lock().expect("pipeline"), plan))
                .await?;
        let dist = match built {
            Ok(dist) => dist,
            Err(e) => {
                eprintln!("error: {e}");
                continue;
            }
        };
        if plan.server {
            server.restart().await?;
            server.wait_ready().await;
        }
        let event = match dist {
            Some(d) if !plan.wasm && !plan.bundle && !plan.server => {
                Reload::Css(d.stylesheets.iter().map(|s| format!("/{s}")).collect())
            }
            _ => Reload::Page,
        };
        let _ = reload.send(event);
    }
    server.stop().await;
    Ok(())
}

fn free_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

struct Server {
    root: PathBuf,
    package: String,
    dist: PathBuf,
    port: u16,
    child: Option<tokio::process::Child>,
}

impl Server {
    fn start(&mut self) -> std::io::Result<()> {
        note(format!(
            "starting {} on internal port {}",
            self.package, self.port
        ));
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let child = tokio::process::Command::new(cargo)
            .args(["run", "-p", &self.package])
            .env("DOXA_DIST", &self.dist)
            .env("PORT", self.port.to_string())
            .current_dir(&self.root)
            .kill_on_drop(true)
            .spawn()?;
        self.child = Some(child);
        Ok(())
    }

    async fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
        }
    }

    async fn restart(&mut self) -> std::io::Result<()> {
        self.stop().await;
        self.start()
    }

    /// Until the server accepts connections, it exits, or two minutes pass.
    async fn wait_ready(&mut self) {
        for _ in 0..1200 {
            if tokio::net::TcpStream::connect(("127.0.0.1", self.port))
                .await
                .is_ok()
            {
                return;
            }
            if let Some(Ok(Some(status))) = self.child.as_mut().map(|c| c.try_wait()) {
                eprintln!("error: {} exited with {status}", self.package);
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Reload {
    Page,
    Css(Vec<String>),
}

struct Proxy {
    dist: PathBuf,
    upstream: String,
    client: reqwest::Client,
    reload: broadcast::Sender<Reload>,
}

async fn reload_events(State(p): State<Arc<Proxy>>) -> impl IntoResponse {
    let events = futures::stream::unfold(p.reload.subscribe(), |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(Reload::Page) => {
                    return Some((
                        Ok::<_, Infallible>(Event::default().event("reload").data("")),
                        rx,
                    ))
                }
                Ok(Reload::Css(hrefs)) => {
                    let data = serde_json::to_string(&hrefs).expect("json");
                    return Some((Ok(Event::default().event("css").data(data)), rx));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(events).keep_alive(KeepAlive::default())
}

fn is_api(path: &str) -> bool {
    path.starts_with(API_PREFIX)
        && matches!(path.as_bytes().get(API_PREFIX.len()), None | Some(b'/'))
}

/// A dist file the proxy answers itself; `index.html` goes through the server.
fn asset_rel(path: &str) -> Option<&str> {
    let rel = path.strip_prefix('/')?;
    let safe = !rel.is_empty()
        && rel != "index.html"
        && rel
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != ".." && !s.contains(['\\', ':']));
    safe.then_some(rel)
}

/// `html` with the reload script before `</body>`, or appended.
pub fn inject_reload(html: &str) -> String {
    match html.to_ascii_lowercase().rfind("</body>") {
        Some(at) => format!("{}{RELOAD_SCRIPT}{}", &html[..at], &html[at..]),
        None => format!("{html}{RELOAD_SCRIPT}"),
    }
}

fn content_type(rel: &str) -> &'static str {
    match rel.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "wasm" => "application/wasm",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn html_response(status: StatusCode, mut headers: HeaderMap, html: String) -> Response {
    headers.remove(header::CONTENT_LENGTH);
    headers.remove(header::CONTENT_ENCODING);
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    let mut res = Response::new(Body::from(html));
    *res.status_mut() = status;
    *res.headers_mut() = headers;
    res
}

impl Proxy {
    async fn disk(&self, rel: &str) -> Option<Response> {
        let bytes = tokio::fs::read(self.dist.join(rel)).await.ok()?;
        Some(
            (
                [
                    (header::CONTENT_TYPE, content_type(rel)),
                    (header::CACHE_CONTROL, "no-cache"),
                ],
                bytes,
            )
                .into_response(),
        )
    }

    async fn index(&self) -> Option<Response> {
        let html = tokio::fs::read_to_string(self.dist.join("index.html"))
            .await
            .ok()?;
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        Some(html_response(StatusCode::OK, headers, inject_reload(&html)))
    }

    async fn upstream(&self, req: Request) -> Result<Response, String> {
        let (parts, body) = req.into_parts();
        let url = format!(
            "{}{}",
            self.upstream,
            parts.uri.path_and_query().map_or("/", |p| p.as_str())
        );
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .map_err(|e| e.to_string())?;
        let mut headers = parts.headers;
        strip_hop_by_hop(&mut headers);
        headers.remove(header::HOST);
        // Uncompressed, so HTML can be rewritten.
        headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        let resp = self
            .client
            .request(parts.method, url)
            .headers(headers)
            .body(body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let status = resp.status();
        let mut headers = resp.headers().clone();
        strip_hop_by_hop(&mut headers);
        let html = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/html"));
        if html {
            let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
            return Ok(html_response(
                status,
                headers,
                inject_reload(&String::from_utf8_lossy(&bytes)),
            ));
        }
        let mut res = Response::new(Body::from_stream(resp.bytes_stream()));
        *res.status_mut() = status;
        *res.headers_mut() = headers;
        Ok(res)
    }
}

fn strip_hop_by_hop(h: &mut HeaderMap) {
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
    ] {
        h.remove(name);
    }
}

async fn forward(State(p): State<Arc<Proxy>>, req: Request) -> Response {
    let readable = matches!(*req.method(), Method::GET | Method::HEAD);
    let path = req.uri().path().to_owned();
    let navigation = readable
        && !is_api(&path)
        && req
            .headers()
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("text/html"));
    if readable && !is_api(&path) {
        if let Some(found) = match asset_rel(&path) {
            Some(rel) => p.disk(rel).await,
            None => None,
        } {
            return found;
        }
    }
    match p.upstream(req).await {
        Ok(res) if res.status() == StatusCode::NOT_FOUND && navigation => {
            p.index().await.unwrap_or(res)
        }
        Ok(res) => res,
        Err(e) => match navigation {
            true => match p.index().await {
                Some(index) => index,
                None => bad_gateway(&e),
            },
            false => bad_gateway(&e),
        },
    }
}

fn bad_gateway(e: &str) -> Response {
    (
        StatusCode::BAD_GATEWAY,
        format!("doxa dev: the server is not answering ({e}); it may still be starting"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watch() -> Watch {
        Watch {
            root: "/app".into(),
            ignore: vec!["/app/target".into()],
            wasm_dirs: vec![
                "/app/web".into(),
                "/app/client".into(),
                "/app/api/src".into(),
            ],
            server_dirs: vec!["/app/server".into(), "/app/api".into()],
            extra_dirs: vec!["/app/style".into()],
            public: Some("/app/web/public".into()),
        }
    }

    fn plan(paths: &[&str]) -> Plan {
        classify(paths.iter().map(Path::new), &watch())
    }

    #[test]
    fn rust_changes_rebuild_wasm_and_restart_the_server_they_feed() {
        assert_eq!(
            plan(&["/app/api/src/widgets.rs"]),
            Plan {
                wasm: true,
                server: true,
                ..Plan::default()
            }
        );
        assert_eq!(
            plan(&["/app/web/src/lib.rs"]),
            Plan {
                wasm: true,
                ..Plan::default()
            }
        );
        assert_eq!(
            plan(&["/app/server/src/main.rs"]),
            Plan {
                server: true,
                ..Plan::default()
            }
        );
        assert_eq!(
            plan(&["/app/Cargo.toml"]),
            Plan {
                wasm: true,
                server: true,
                ..Plan::default()
            }
        );
        assert_eq!(
            plan(&["/app/web/Cargo.toml"]),
            Plan {
                wasm: true,
                ..Plan::default()
            }
        );
    }

    #[test]
    fn scripts_bundle_and_styles_rebuild_css() {
        assert_eq!(
            plan(&["/app/web/ts/editor.tsx"]),
            Plan {
                bundle: true,
                ..Plan::default()
            }
        );
        assert_eq!(
            plan(&["/app/style/app.css"]),
            Plan {
                css: true,
                ..Plan::default()
            }
        );
        assert_eq!(
            plan(&["/app/web/public/logo.svg"]),
            Plan {
                bundle: true,
                ..Plan::default()
            }
        );
        assert_eq!(
            plan(&["/app/web/ts/a.ts", "/app/web/style/app.css"]),
            Plan {
                bundle: true,
                css: true,
                ..Plan::default()
            }
        );
    }

    #[test]
    fn build_output_and_noise_are_ignored() {
        assert!(plan(&["/app/target/doxa/stage/css/app.tailwind-in.css"]).is_empty());
        assert!(plan(&["/app/web/node_modules/react/index.js"]).is_empty());
        assert!(plan(&["/app/Cargo.lock", "/app/README.md", "/app/rustfmt.toml"]).is_empty());
    }

    #[test]
    fn roots_are_outermost_dirs_plus_the_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = canonical(dir.path());
        for d in ["api/src", "server", "web", "target/x"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        let w = Watch {
            root: root.clone(),
            ignore: vec![root.join("target")],
            wasm_dirs: vec![
                root.join("web"),
                root.join("api/src"),
                root.join("target/x"),
            ],
            server_dirs: vec![root.join("server"), root.join("api")],
            extra_dirs: vec![],
            public: None,
        };
        let roots: Vec<_> = w.roots().into_iter().map(|(d, _)| d).collect();
        assert_eq!(
            roots,
            [
                root.join("api"),
                root.join("server"),
                root.join("web"),
                root
            ]
        );
    }

    #[test]
    fn reload_script_goes_before_body_close() {
        let html = inject_reload("<html><body><p>x</p></BODY></html>");
        assert!(
            html.starts_with("<html><body><p>x</p><script type=\"module\">"),
            "{html}"
        );
        assert!(html.ends_with("</script>\n</BODY></html>"), "{html}");
        assert!(inject_reload("<p>").starts_with("<p><script"));
    }

    #[test]
    fn asset_paths() {
        assert_eq!(asset_rel("/app-0123abcd.js"), Some("app-0123abcd.js"));
        assert_eq!(asset_rel("/"), None);
        assert_eq!(asset_rel("/index.html"), None);
        assert_eq!(asset_rel("/../x"), None);
        assert!(is_api("/api/x"));
        assert!(!is_api("/apiary"));
    }
}
