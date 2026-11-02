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
/// Where hot patches are fetched from, matching [`Pipeline::patch`]'s jump tables.
const PATCH_PREFIX: &str = "__doxa_patch/";
const API_PREFIX: &str = "/api";

const RELOAD_SCRIPT: &str = r#"<script type="module">
const es = new EventSource("/__doxa/reload");
es.addEventListener("reload", () => location.reload());
es.addEventListener("patch", (e) => {
  // Before the wasm starts, it applies the patch itself.
  if (!globalThis.__doxa_hotpatch) {
    globalThis.__doxa_pending_patch = e.data;
    return;
  }
  try {
    globalThis.__doxa_hotpatch(e.data);
  } catch (err) {
    console.error(err);
    location.reload();
  }
});
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
    /// Every wasm change is a web crate source file, which a hot patch covers.
    pub patch: bool,
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
    web_dir: PathBuf,
    wasm_dirs: Vec<PathBuf>,
    server_dirs: Vec<PathBuf>,
    extra_dirs: Vec<PathBuf>,
    public: Option<PathBuf>,
    /// Extensions a preprocessor turns into CSS.
    styles: Vec<String>,
    /// Absolute `watch` globs of the preprocessors.
    style_globs: Vec<glob::Pattern>,
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
        .collect::<Vec<_>>();
        let web_dir = canonical(&web.dir);
        let globs: Vec<String> = web
            .config
            .preprocess
            .values()
            .flat_map(|p| &p.watch)
            .map(|g| web_dir.join(g).to_string_lossy().into_owned())
            .collect();
        let mut extra_dirs = extra_dirs;
        extra_dirs.extend(globs.iter().map(|g| glob_root(g)).filter(|d| d.is_dir()));
        Watch {
            styles: web.config.preprocess.keys().cloned().collect(),
            style_globs: globs
                .iter()
                .filter_map(|g| glob::Pattern::new(g).ok())
                .collect(),
            ignore: vec![canonical(&ws.target_directory)],
            web_dir: web_dir.clone(),
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

/// The directory a glob starts in: everything before its first wildcard.
fn glob_root(glob: &str) -> PathBuf {
    let fixed = glob.split(['*', '?', '[', '{']).next().unwrap_or(glob);
    let p = Path::new(fixed);
    if fixed.ends_with('/') {
        p.to_owned()
    } else {
        p.parent().unwrap_or(p).to_owned()
    }
}

/// Decide what to rebuild for a batch of changed paths.
pub fn classify<'a>(paths: impl IntoIterator<Item = &'a Path>, w: &Watch) -> Plan {
    let mut plan = Plan::default();
    let mut unpatchable = false;
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
        // A preprocessor's own output, written and removed by the build.
        if w.styles
            .iter()
            .any(|s| name.ends_with(&format!(".{s}.css")))
        {
            continue;
        }
        if w.styles.iter().any(|s| s == ext) || w.style_globs.iter().any(|g| g.matches_path(p)) {
            plan.css = true;
            continue;
        }
        match ext {
            "rs" | "toml" if ext == "rs" || name == "Cargo.toml" => {
                if p.parent() == Some(w.root.as_path()) && name == "Cargo.toml" {
                    plan.wasm = true;
                    plan.server = true;
                    unpatchable = true;
                }
                if under(p, &w.wasm_dirs) {
                    plan.wasm = true;
                    unpatchable |= ext != "rs" || !p.starts_with(&w.web_dir);
                }
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
    plan.patch = plan.wasm && !unpatchable;
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

/// Run `doxa dev` until interrupted; `hot` patches web crate changes into the page.
pub async fn run(
    package: Option<String>,
    port: u16,
    locked: bool,
    hot: bool,
) -> Result<(), DynError> {
    let cwd = std::env::current_dir()?;
    let opts = BuildOptions {
        package,
        locked,
        hot,
        ..BuildOptions::default()
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
    let patches = pipeline.patch_dir();
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
        patches,
        upstream: format!("http://127.0.0.1:{}", server.port),
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        reload: reload.clone(),
        latest_patch: Mutex::new(None),
    });
    let app = Router::new()
        .route(RELOAD_PATH, get(reload_events))
        .fallback(forward)
        .with_state(proxy.clone());
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
        if hot && plan.patch && !plan.bundle && !plan.css && !plan.server {
            let p = pipeline.clone();
            match tokio::task::spawn_blocking(move || p.lock().expect("pipeline").patch()).await? {
                Ok(Some(table)) => {
                    *proxy.latest_patch.lock().expect("patch") = Some(table.clone());
                    let _ = reload.send(Reload::Patch(table));
                    continue;
                }
                Ok(None) => continue,
                Err(e) => {
                    eprintln!("error: {e}");
                    note("rebuilding instead");
                }
            }
        }
        *proxy.latest_patch.lock().expect("patch") = None;
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
    /// A jump table, as JSON.
    Patch(String),
}

struct Proxy {
    dist: PathBuf,
    patches: PathBuf,
    upstream: String,
    client: reqwest::Client,
    reload: broadcast::Sender<Reload>,
    /// What a page loading the base wasm still has to apply.
    latest_patch: Mutex<Option<String>>,
}

async fn reload_events(State(p): State<Arc<Proxy>>) -> impl IntoResponse {
    let latest = p.latest_patch.lock().expect("patch").clone();
    let state = (p.reload.subscribe(), latest);
    let events = futures::stream::unfold(state, |(mut rx, mut pending)| async move {
        if let Some(table) = pending.take() {
            let event = Event::default().event("patch").data(table);
            return Some((Ok::<_, Infallible>(event), (rx, None)));
        }
        loop {
            match rx.recv().await {
                Ok(Reload::Patch(table)) => {
                    return Some((Ok(Event::default().event("patch").data(table)), (rx, None)))
                }
                Ok(Reload::Page) => {
                    return Some((Ok(Event::default().event("reload").data("")), (rx, None)))
                }
                Ok(Reload::Css(hrefs)) => {
                    let data = serde_json::to_string(&hrefs).expect("json");
                    return Some((Ok(Event::default().event("css").data(data)), (rx, None)));
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
        let path = match rel.strip_prefix(PATCH_PREFIX) {
            Some(patch) => self.patches.join(patch),
            None => self.dist.join(rel),
        };
        let bytes = tokio::fs::read(path).await.ok()?;
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

fn is_upgrade(req: &Request) -> bool {
    let has = |name, token: &str| {
        req.headers()
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    };
    has(header::CONNECTION, "upgrade") && req.headers().contains_key(header::UPGRADE)
}

/// Replay an upgrade handshake (a WebSocket, say) to the server, then pipe bytes both ways.
async fn tunnel(p: &Proxy, mut req: Request) -> Result<Response, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let addr = p.upstream.trim_start_matches("http://");
    let mut upstream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| e.to_string())?;
    let target = req.uri().path_and_query().map_or("/", |p| p.as_str());
    let mut head = format!("{} {target} HTTP/1.1\r\nhost: {addr}\r\n", req.method());
    for (name, value) in req.headers() {
        if name != header::HOST {
            let value = value.to_str().map_err(|e| e.to_string())?;
            head.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    head.push_str("\r\n");
    upstream
        .write_all(head.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    // The response head, plus any bytes the server sent after it.
    let mut buf = Vec::new();
    let end = loop {
        let mut chunk = [0u8; 4096];
        let n = upstream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("the server closed the connection during the handshake".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let text = String::from_utf8_lossy(&buf[..end]).into_owned();
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .and_then(|s| StatusCode::from_u16(s).ok())
        .ok_or("the server's handshake response has no status")?;
    let mut res = Response::new(Body::empty());
    *res.status_mut() = status;
    for line in lines.filter(|l| !l.is_empty()) {
        if let Some((name, value)) = line.split_once(':') {
            if let (Ok(n), Ok(v)) = (
                header::HeaderName::from_bytes(name.trim().as_bytes()),
                HeaderValue::from_str(value.trim()),
            ) {
                res.headers_mut().append(n, v);
            }
        }
    }
    if status == StatusCode::SWITCHING_PROTOCOLS {
        let early = buf.split_off(end);
        let upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let Ok(client) = upgrade.await else { return };
            let mut client = hyper_util::rt::TokioIo::new(client);
            if client.write_all(&early).await.is_ok() {
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            }
        });
    }
    Ok(res)
}

async fn forward(State(p): State<Arc<Proxy>>, req: Request) -> Response {
    if is_upgrade(&req) {
        return tunnel(&p, req).await.unwrap_or_else(|e| bad_gateway(&e));
    }
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
            web_dir: "/app/web".into(),
            wasm_dirs: vec![
                "/app/web".into(),
                "/app/client".into(),
                "/app/api/src".into(),
            ],
            server_dirs: vec!["/app/server".into(), "/app/api".into()],
            extra_dirs: vec!["/app/style".into()],
            public: Some("/app/web/public".into()),
            styles: vec!["scss".into()],
            style_globs: vec![glob::Pattern::new("/app/web/theme/**/*.json").unwrap()],
        }
    }

    fn plan(paths: &[&str]) -> Plan {
        classify(paths.iter().map(Path::new), &watch())
    }

    /// Accepts any upgrade, then echoes what it receives.
    async fn echo_server() -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut b = [0u8; 1];
                s.read_exact(&mut b).await.unwrap();
                head.push(b[0]);
            }
            assert!(String::from_utf8_lossy(&head).contains("upgrade: echo"));
            s.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: echo\r\n\r\n",
            )
            .await
            .unwrap();
            let (mut r, mut w) = s.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        port
    }

    #[tokio::test]
    async fn an_upgrade_is_tunnelled_to_the_server() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let upstream = echo_server().await;
        let proxy = Arc::new(Proxy {
            dist: PathBuf::from("/nonexistent"),
            patches: PathBuf::from("/nonexistent"),
            upstream: format!("http://127.0.0.1:{upstream}"),
            client: reqwest::Client::new(),
            reload: broadcast::channel(1).0,
            latest_patch: Mutex::new(None),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = Router::new().fallback(forward).with_state(proxy);
        tokio::spawn(async move { axum::serve(listener, app).await });

        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        c.write_all(
            b"GET /live HTTP/1.1\r\nhost: x\r\nconnection: upgrade\r\nupgrade: echo\r\n\r\n",
        )
        .await
        .unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut b = [0u8; 1];
            c.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
        }
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 101"));
        c.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        c.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"ping");
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
                patch: true,
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
    fn only_web_crate_sources_are_patched() {
        assert!(plan(&["/app/web/src/a.rs", "/app/web/src/b.rs"]).patch);
        assert!(!plan(&["/app/web/src/a.rs", "/app/client/src/lib.rs"]).patch);
        assert!(!plan(&["/app/web/src/a.rs", "/app/web/Cargo.toml"]).patch);
        assert!(!plan(&["/app/web/src/a.rs", "/app/Cargo.toml"]).patch);
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
    fn preprocessed_styles_and_their_globs_rebuild_css_but_not_their_output() {
        let css = Plan {
            css: true,
            ..Plan::default()
        };
        assert_eq!(plan(&["/app/web/style/_vars.scss"]), css);
        assert_eq!(plan(&["/app/web/theme/brand/colors.json"]), css);
        assert!(plan(&["/app/web/style/app.scss.css"]).is_empty());
        assert_eq!(glob_root("/w/style/**/*.scss"), Path::new("/w/style"));
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
            web_dir: root.join("web"),
            wasm_dirs: vec![
                root.join("web"),
                root.join("api/src"),
                root.join("target/x"),
            ],
            server_dirs: vec![root.join("server"), root.join("api")],
            extra_dirs: vec![],
            public: None,
            styles: vec![],
            style_globs: vec![],
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
