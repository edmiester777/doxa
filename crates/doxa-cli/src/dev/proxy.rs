//! The dev server's proxy: dist files, the reload stream, and forwarding to each upstream.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use doxa_build::config::Upstream;
use tokio::sync::broadcast;

pub(super) const RELOAD_PATH: &str = "/__doxa/reload";
/// Where hot patches are fetched from, matching `Pipeline::patch`'s jump tables.
const PATCH_PREFIX: &str = "__doxa_patch/";
const API_PREFIX: &str = "/api";
/// The largest request body the proxy buffers for an upstream, in bytes.
const MAX_BODY: usize = 100 * 1024 * 1024;
const NO_UPSTREAM: &str = "no server or [package.metadata.doxa.proxy] entry answers this path";

const RELOAD_SCRIPT: &str = r#"<script type="module">
// A panic traps the wasm mid-update and leaves the page half-rendered, so start it over,
// unless this load came from such a reload and trapped within 10s of starting.
let reloadedByTrap = false;
try {
  reloadedByTrap = sessionStorage.getItem("__doxa_trapped") !== null;
  sessionStorage.removeItem("__doxa_trapped");
} catch {}
const trapped = (err) => {
  if (!(err instanceof WebAssembly.RuntimeError)) return;
  if (reloadedByTrap && performance.now() < 10000) {
    console.error("[doxa] the wasm trapped again right after reloading for a trap; not reloading");
    return;
  }
  try { sessionStorage.setItem("__doxa_trapped", ""); } catch {}
  location.reload();
};
addEventListener("error", (e) => trapped(e.error));
addEventListener("unhandledrejection", (e) => trapped(e.reason));
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

/// A `[package.metadata.doxa.proxy]` entry with its upstream settled.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Route {
    pub(super) prefix: String,
    pub(super) target: String,
    strip: bool,
}

/// The configured routes, longest prefix first; `ports` maps each dev service to its port. A
/// route to a `skipped` service falls back to `env` and `to`, or is left out.
pub(super) fn routes(
    proxy: &BTreeMap<String, Upstream>,
    ports: &BTreeMap<String, u16>,
    skipped: &[String],
    env: impl Fn(&str) -> Option<String>,
) -> Result<Vec<Route>, String> {
    let mut routes = Vec::with_capacity(proxy.len());
    for (prefix, upstream) in proxy {
        let table = format!("[package.metadata.doxa.proxy] \"{prefix}\"");
        if !prefix.starts_with('/') || prefix.ends_with('/') {
            return Err(format!(
                "{table} isn't a path prefix\n  fix: write it like \"/api\": a leading slash and no trailing one"
            ));
        }
        let from_env = upstream
            .env
            .as_deref()
            .and_then(&env)
            .filter(|v| !v.is_empty());
        let skip = upstream
            .service
            .as_ref()
            .is_some_and(|s| skipped.contains(s));
        let from_service = match upstream.service.as_ref().filter(|_| !skip) {
            Some(s) => Some(ports.get(s).map(|p| format!("http://127.0.0.1:{p}")).ok_or_else(|| {
                format!(
                    "{table} names service `{s}`, which isn't in [workspace.metadata.doxa.dev.services]\n  fix: add it there, or use `to`"
                )
            })?),
            None => None,
        };
        let Some(target) = from_env.or(from_service).or_else(|| upstream.to.clone()) else {
            if skip {
                continue;
            }
            return Err(format!(
                "{table} has no upstream\n  fix: set `to` or `service`, or the variable its `env` names"
            ));
        };
        if !target.starts_with("http://") && !target.starts_with("https://") {
            return Err(format!(
                "{table} goes to `{target}`\n  fix: give an http:// or https:// URL"
            ));
        }
        routes.push(Route {
            prefix: prefix.clone(),
            target: target.trim_end_matches('/').to_owned(),
            strip: upstream.strip,
        });
    }
    routes.sort_by_key(|r| std::cmp::Reverse(r.prefix.len()));
    Ok(routes)
}

/// What follows `prefix` in `path`, when `prefix` ends at a path segment.
fn after_prefix<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(prefix)?;
    (rest.is_empty() || rest.starts_with('/')).then_some(rest)
}

/// Where a browser reaches a server bound to `host`: localhost and the LAN address for
/// `0.0.0.0`, else `host` itself.
pub(super) fn urls(host: IpAddr, lan: Option<IpAddr>, port: u16) -> Vec<String> {
    let hosts = if host.is_unspecified() {
        std::iter::once(IpAddr::from(Ipv4Addr::LOCALHOST))
            .chain(lan)
            .collect()
    } else {
        vec![host]
    };
    hosts
        .into_iter()
        .map(|h| format!("http://{}", std::net::SocketAddr::new(h, port)))
        .collect()
}

/// The hostnames a request may name in `Host` or `Origin`: loopback, the address bound (or the LAN
/// address for `0.0.0.0`), and `$DOXA_ALLOWED_HOSTS` (comma-separated, e.g. a tunnel's).
pub(super) fn allowed_hosts(
    host: IpAddr,
    lan: Option<IpAddr>,
    extra: Option<&str>,
) -> std::collections::HashSet<String> {
    let mut out: std::collections::HashSet<String> = ["localhost", "127.0.0.1", "::1"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if host.is_unspecified() {
        out.extend(lan.map(|ip| ip.to_string()));
    } else {
        out.insert(host.to_string());
    }
    out.extend(
        extra
            .unwrap_or_default()
            .split(',')
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty()),
    );
    out
}

/// The hostname in a `Host` value or an origin, without port or IPv6 brackets.
fn hostname(authority: &str) -> String {
    let authority = authority.rsplit("://").next().unwrap_or(authority);
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(v6),
        None => authority.split(':').next().unwrap_or(authority),
    };
    host.to_ascii_lowercase()
}

/// Refuses a request naming another host, so a page rebinding its DNS to this server can't read it.
pub(super) async fn guard_host(
    State(allowed): State<Arc<std::collections::HashSet<String>>>,
    req: Request,
    next: axum::middleware::Next,
) -> Response {
    let named = [header::HOST, header::ORIGIN].into_iter().filter_map(|h| {
        req.headers()
            .get(h)
            .and_then(|v| v.to_str().ok())
            .map(hostname)
    });
    for name in named.collect::<Vec<_>>() {
        if !allowed.contains(&name) {
            let message = format!("{name} is not this dev server; add it to DOXA_ALLOWED_HOSTS");
            return (StatusCode::FORBIDDEN, message).into_response();
        }
    }
    next.run(req).await
}

/// The address this machine routes outward from; a UDP connect sends nothing.
pub(super) fn lan_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((Ipv4Addr::new(8, 8, 8, 8), 80)).ok()?;
    Some(socket.local_addr().ok()?.ip())
}

#[derive(Debug, Clone, PartialEq)]
pub(super) enum Reload {
    Page,
    Css(Vec<String>),
    /// A jump table, as JSON.
    Patch(String),
}

pub(super) struct Proxy {
    pub(super) dist: PathBuf,
    pub(super) patches: PathBuf,
    /// The server `doxa dev` runs, if any; it answers what no route claims.
    pub(super) upstream: Option<String>,
    pub(super) routes: Vec<Route>,
    pub(super) client: reqwest::Client,
    pub(super) reload: broadcast::Sender<Reload>,
    /// What a page loading the base wasm still has to apply.
    pub(super) latest_patch: Mutex<Option<String>>,
}

pub(super) async fn reload_events(State(p): State<Arc<Proxy>>) -> impl IntoResponse {
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
                    // A browser discards an event whose data is empty.
                    let event = Event::default().event("reload").data("page");
                    return Some((Ok(event), (rx, None)));
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
    fn route(&self, path: &str) -> Option<&Route> {
        self.routes
            .iter()
            .find(|r| after_prefix(path, &r.prefix).is_some())
    }

    /// Whether `path` never names a dist file or a page.
    fn is_backend(&self, path: &str) -> bool {
        after_prefix(path, API_PREFIX).is_some() || self.route(path).is_some()
    }

    /// The URL `uri` is forwarded to, when anything answers it.
    fn target(&self, uri: &Uri) -> Option<String> {
        let path = uri.path();
        let (base, path) = match self.route(path) {
            Some(r) if r.strip => (
                r.target.as_str(),
                match after_prefix(path, &r.prefix) {
                    Some("") | None => "/",
                    Some(rest) => rest,
                },
            ),
            Some(r) => (r.target.as_str(), path),
            None => (self.upstream.as_deref()?, path),
        };
        Some(match uri.query() {
            Some(query) => format!("{base}{path}?{query}"),
            None => format!("{base}{path}"),
        })
    }

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
        let url = self.target(&parts.uri).ok_or(NO_UPSTREAM)?;
        let body = axum::body::to_bytes(body, MAX_BODY)
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

    let url = p.target(req.uri()).ok_or(NO_UPSTREAM)?;
    let url = reqwest::Url::parse(&url).map_err(|e| e.to_string())?;
    if url.scheme() != "http" {
        return Err(format!(
            "can't tunnel an upgrade to {url}: only http:// is supported"
        ));
    }
    let addr = format!(
        "{}:{}",
        url.host_str().unwrap_or("127.0.0.1"),
        url.port_or_known_default().unwrap_or(80)
    );
    let mut upstream = tokio::net::TcpStream::connect(&addr)
        .await
        .map_err(|e| e.to_string())?;
    let target = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    };
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

pub(super) async fn forward(State(p): State<Arc<Proxy>>, req: Request) -> Response {
    if is_upgrade(&req) {
        return tunnel(&p, req).await.unwrap_or_else(|e| bad_gateway(&e));
    }
    let readable = matches!(*req.method(), Method::GET | Method::HEAD);
    let path = req.uri().path().to_owned();
    let backend = p.is_backend(&path);
    let navigation = readable
        && !backend
        && req
            .headers()
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("text/html"));
    if readable && !backend {
        if let Some(found) = match asset_rel(&path) {
            Some(rel) => p.disk(rel).await,
            None => None,
        } {
            return found;
        }
    }
    if p.target(req.uri()).is_none() {
        let page = match navigation {
            true => p.index().await,
            false => None,
        };
        return page.unwrap_or_else(|| StatusCode::NOT_FOUND.into_response());
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
    use axum::routing::get;
    use axum::Router;
    use std::path::Path;

    #[tokio::test]
    async fn a_request_naming_another_host_is_refused() {
        let allowed = Arc::new(allowed_hosts(
            Ipv4Addr::UNSPECIFIED.into(),
            Some(Ipv4Addr::new(192, 168, 1, 9).into()),
            Some("dev.example.test"),
        ));
        let app = Router::new()
            .fallback(|| async { "ok" })
            .layer(axum::middleware::from_fn_with_state(allowed, guard_host));
        let status = |host: &str, origin: Option<&str>| {
            let app = app.clone();
            let mut req = Request::builder().uri("/").header(header::HOST, host);
            if let Some(o) = origin {
                req = req.header(header::ORIGIN, o);
            }
            let req = req.body(Body::empty()).unwrap();
            async move { tower::ServiceExt::oneshot(app, req).await.unwrap().status() }
        };
        assert_eq!(status("localhost:4710", None).await, StatusCode::OK);
        assert_eq!(status("[::1]:4710", None).await, StatusCode::OK);
        assert_eq!(status("192.168.1.9:4710", None).await, StatusCode::OK);
        assert_eq!(status("dev.example.test", None).await, StatusCode::OK);
        assert_eq!(
            status("rebound.attacker.test:4710", None).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status("localhost:4710", Some("http://attacker.test")).await,
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn an_unspecified_host_is_shown_as_localhost_and_the_lan_address() {
        let lan = Some(IpAddr::from([192, 168, 1, 20]));
        assert_eq!(
            urls(Ipv4Addr::UNSPECIFIED.into(), lan, 3000),
            ["http://127.0.0.1:3000", "http://192.168.1.20:3000"]
        );
        assert_eq!(
            urls(Ipv4Addr::UNSPECIFIED.into(), None, 3000),
            ["http://127.0.0.1:3000"]
        );
        assert_eq!(
            urls(Ipv4Addr::LOCALHOST.into(), lan, 4710),
            ["http://127.0.0.1:4710"]
        );
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
            upstream: Some(format!("http://127.0.0.1:{upstream}")),
            routes: Vec::new(),
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

    fn upstream(to: Option<&str>, env: Option<&str>, strip: bool) -> Upstream {
        Upstream {
            to: to.map(Into::into),
            env: env.map(Into::into),
            service: None,
            strip,
        }
    }

    /// Answers each request with its method, target and body.
    async fn reporting_server() -> String {
        async fn report(req: Request) -> String {
            let (method, uri) = (req.method().clone(), req.uri().clone());
            let body = axum::body::to_bytes(req.into_body(), usize::MAX)
                .await
                .unwrap();
            format!("{method} {uri} {}", String::from_utf8_lossy(&body))
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = Router::new().fallback(report);
        tokio::spawn(async move { axum::serve(listener, app).await });
        format!("http://127.0.0.1:{port}")
    }

    /// A serverless proxy over a dist holding `index.html` and `app.js`.
    async fn serverless(routes: Vec<Route>, dist: &Path) -> String {
        std::fs::write(dist.join("index.html"), "<body>shell</body>").unwrap();
        std::fs::write(dist.join("app.js"), "js").unwrap();
        let proxy = Arc::new(Proxy {
            dist: dist.to_owned(),
            patches: dist.to_owned(),
            upstream: None,
            routes,
            client: reqwest::Client::new(),
            reload: broadcast::channel(1).0,
            latest_patch: Mutex::new(None),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = Router::new().fallback(forward).with_state(proxy);
        tokio::spawn(async move { axum::serve(listener, app).await });
        format!("http://127.0.0.1:{port}")
    }

    #[test]
    fn an_env_variable_beats_a_routes_written_upstream() {
        let proxy = BTreeMap::from([
            (
                "/a".to_owned(),
                upstream(Some("http://a/"), Some("A"), false),
            ),
            (
                "/a/b".to_owned(),
                upstream(Some("http://b"), Some("B"), true),
            ),
            ("/c".to_owned(), upstream(None, Some("C"), false)),
        ]);
        let found = routes(&proxy, &BTreeMap::new(), &[], |name| match name {
            "A" => Some(String::new()),
            "B" | "C" => Some(format!("http://{name}.env")),
            _ => None,
        })
        .unwrap();
        let summary: Vec<_> = found
            .iter()
            .map(|r| (r.prefix.as_str(), r.target.as_str(), r.strip))
            .collect();
        assert_eq!(
            summary,
            [
                ("/a/b", "http://B.env", true),
                ("/a", "http://a", false),
                ("/c", "http://C.env", false),
            ],
            "longest prefix first; an empty variable counts as unset"
        );
    }

    #[test]
    fn a_service_route_goes_to_its_dev_port_unless_its_env_is_set() {
        let up = Upstream {
            to: Some("http://fallback".into()),
            env: Some("API".into()),
            service: Some("b-api".into()),
            strip: false,
        };
        let proxy = BTreeMap::from([("/api".to_owned(), up)]);
        let ports = BTreeMap::from([("b-api".to_owned(), 8081)]);
        let target = |env: Option<&str>| {
            let env = env.map(str::to_owned);
            routes(&proxy, &ports, &[], move |_| env.clone()).unwrap()[0]
                .target
                .clone()
        };
        assert_eq!(target(None), "http://127.0.0.1:8081");
        assert_eq!(target(Some("http://override")), "http://override");
    }

    #[test]
    fn a_route_to_a_skipped_service_falls_back_or_is_left_out() {
        let up = |to: Option<&str>| Upstream {
            to: to.map(Into::into),
            service: Some("b-api".into()),
            ..Upstream::default()
        };
        let skipped = ["b-api".to_owned()];
        let found = |up| {
            routes(
                &BTreeMap::from([("/api".to_owned(), up)]),
                &BTreeMap::new(),
                &skipped,
                |_| None,
            )
            .unwrap()
        };
        assert_eq!(
            found(up(Some("http://fallback")))[0].target,
            "http://fallback"
        );
        assert!(found(up(None)).is_empty());
    }

    #[test]
    fn a_route_without_a_usable_upstream_or_prefix_is_refused() {
        let refused = |prefix: &str, up: Upstream| {
            routes(
                &BTreeMap::from([(prefix.to_owned(), up)]),
                &BTreeMap::new(),
                &[],
                |_| None,
            )
            .unwrap_err()
        };
        assert!(refused("/a", upstream(None, Some("A"), false)).contains("no upstream"));
        let unknown = Upstream {
            service: Some("b-api".into()),
            ..Upstream::default()
        };
        assert!(refused("/a", unknown).contains("isn't in [workspace.metadata.doxa.dev.services]"));
        assert!(refused("/a", upstream(Some("a.test"), None, false)).contains("http://"));
        assert!(refused("a", upstream(Some("http://a"), None, false)).contains("path prefix"));
        assert!(refused("/", upstream(Some("http://a"), None, false)).contains("path prefix"));
    }

    #[tokio::test]
    async fn each_prefix_reaches_its_own_upstream() {
        let (one, two) = (reporting_server().await, reporting_server().await);
        let dist = tempfile::tempdir().unwrap();
        let routes = routes(
            &BTreeMap::from([
                ("/api".to_owned(), upstream(Some(&one), None, false)),
                ("/v2".to_owned(), upstream(Some(&two), None, true)),
            ]),
            &BTreeMap::new(),
            &[],
            |_| None,
        )
        .unwrap();
        let base = serverless(routes, dist.path()).await;
        let client = reqwest::Client::new();
        let get = |path: &'static str| {
            let (client, url) = (client.clone(), format!("{base}{path}"));
            async move {
                let resp = client
                    .get(url)
                    .header(header::ACCEPT, "text/html")
                    .send()
                    .await
                    .unwrap();
                (resp.status().as_u16(), resp.text().await.unwrap())
            }
        };

        assert_eq!(get("/api/me?a=1").await.1, "GET /api/me?a=1 ");
        assert_eq!(get("/v2/api/me?a=1").await.1, "GET /api/me?a=1 ");
        assert_eq!(get("/v2").await.1, "GET / ");
        let posted = client
            .post(format!("{base}/v2/q"))
            .body("sql")
            .send()
            .await
            .unwrap();
        assert_eq!(posted.text().await.unwrap(), "POST /q sql");

        assert_eq!(get("/app.js").await.1, "js");
        let (status, page) = get("/v2x/page").await;
        assert_eq!(status, 200);
        assert!(
            page.contains("shell") && page.contains("/__doxa/reload"),
            "{page}"
        );
        let missing = client
            .get(format!("{base}/missing.js"))
            .send()
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_page_reload_event_carries_data_so_a_browser_dispatches_it() {
        let (reload, _) = broadcast::channel(1);
        let proxy = Arc::new(Proxy {
            dist: PathBuf::from("/nonexistent"),
            patches: PathBuf::from("/nonexistent"),
            upstream: None,
            routes: Vec::new(),
            client: reqwest::Client::new(),
            reload: reload.clone(),
            latest_patch: Mutex::new(None),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = Router::new()
            .route(RELOAD_PATH, get(reload_events))
            .with_state(proxy);
        tokio::spawn(async move { axum::serve(listener, app).await });

        let mut events = reqwest::get(format!("http://127.0.0.1:{port}{RELOAD_PATH}"))
            .await
            .unwrap();
        reload.send(Reload::Page).unwrap();
        let chunk = events.chunk().await.unwrap().unwrap();
        let text = String::from_utf8_lossy(&chunk);
        assert!(text.contains("event: reload"), "{text}");
        let data = text.lines().find_map(|l| l.strip_prefix("data:"));
        assert!(data.is_some_and(|d| !d.trim().is_empty()), "{text}");
    }

    #[tokio::test]
    async fn with_no_routes_a_navigation_gets_the_page_with_its_reload_script() {
        let dist = tempfile::tempdir().unwrap();
        let base = serverless(Vec::new(), dist.path()).await;
        let page = reqwest::Client::new()
            .get(format!("{base}/?story=a&theme=light"))
            .header(header::ACCEPT, "text/html")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(
            page.contains("shell") && page.contains(RELOAD_PATH),
            "{page}"
        );
    }

    #[tokio::test]
    async fn an_upgrade_follows_its_route() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let port = echo_server().await;
        let dist = tempfile::tempdir().unwrap();
        let base = serverless(
            vec![Route {
                prefix: "/v2".into(),
                target: format!("http://127.0.0.1:{port}"),
                strip: true,
            }],
            dist.path(),
        )
        .await;
        let mut c = tokio::net::TcpStream::connect(base.trim_start_matches("http://"))
            .await
            .unwrap();
        c.write_all(
            b"GET /v2/live HTTP/1.1\r\nhost: x\r\nconnection: upgrade\r\nupgrade: echo\r\n\r\n",
        )
        .await
        .unwrap();
        let mut head = [0u8; 12];
        c.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 101");
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
        assert_eq!(after_prefix("/api/x", API_PREFIX), Some("/x"));
        assert_eq!(after_prefix("/apiary", API_PREFIX), None);
    }
}
