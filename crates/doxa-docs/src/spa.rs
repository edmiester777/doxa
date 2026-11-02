//! Serve a built single-page app beside the API: hashed assets cached for good,
//! precompressed siblings when the client takes them, and `index.html` for browser
//! navigations outside the API prefix.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::Router;

/// A table of embedded files: dist-relative path to contents.
pub type EmbeddedFiles = &'static [(&'static str, &'static [u8])];

/// Where a build put its dist, as [`dist!`](crate::dist) captured it.
#[derive(Debug, Clone, Copy)]
pub struct Dist {
    /// `DOXA_DIST` at compile time.
    pub dir: Option<&'static str>,
    /// The files, when compiled with the `embed` feature.
    pub embedded: EmbeddedFiles,
}

/// The dist `doxa build` wrote. With `embed`, every file is compiled in when `doxa build`
/// set `DOXA_DIST`; without it, the dist is served from disk.
#[cfg(feature = "embed")]
#[macro_export]
macro_rules! dist {
    () => {
        $crate::Dist {
            dir: ::core::option_env!("DOXA_DIST"),
            embedded: $crate::__private::embedded_dist!(),
        }
    };
}

/// The dist `doxa build` wrote, served from disk.
#[cfg(not(feature = "embed"))]
#[macro_export]
macro_rules! dist {
    () => {
        $crate::Dist {
            dir: ::core::option_env!("DOXA_DIST"),
            embedded: &[],
        }
    };
}

#[derive(Clone)]
enum Source {
    Dir(PathBuf),
    Embedded(Arc<HashMap<&'static str, &'static [u8]>>),
}

/// A built single-page app, mounted with [`MountSpaExt::mount_spa`].
#[derive(Clone)]
pub struct Spa {
    source: Source,
    api_prefix: String,
    services: Option<Arc<BTreeMap<String, String>>>,
}

impl Spa {
    /// Serve the dist in `path`, read per request.
    pub fn dir(path: impl Into<PathBuf>) -> Spa {
        Spa {
            source: Source::Dir(path.into()),
            api_prefix: "/api".into(),
            services: None,
        }
    }

    /// Serve files compiled into the binary.
    pub fn embedded(files: EmbeddedFiles) -> Spa {
        Spa {
            source: Source::Embedded(Arc::new(files.iter().copied().collect())),
            api_prefix: "/api".into(),
            services: None,
        }
    }

    /// Embedded files when there are any; else `DOXA_DIST` at run time, then at
    /// compile time, then `target/doxa/dist`.
    pub fn auto(dist: Dist) -> Spa {
        if !dist.embedded.is_empty() {
            return Spa::embedded(dist.embedded);
        }
        let dir = std::env::var_os("DOXA_DIST")
            .map(PathBuf::from)
            .or_else(|| dist.dir.map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("target/doxa/dist"));
        Spa::dir(dir)
    }

    /// Paths under `prefix` belong to the API and are never answered here.
    pub fn api_prefix(mut self, prefix: &str) -> Spa {
        let p = prefix.trim_end_matches('/');
        self.api_prefix = if p.is_empty() || p.starts_with('/') {
            p.to_owned()
        } else {
            format!("/{p}")
        };
        self
    }

    /// Answer `services.json` with the built defaults overlaid by these client crate base
    /// URLs, so a deployment points its clients without a rebuild.
    pub fn services<K: Into<String>, V: Into<String>>(
        mut self,
        services: impl IntoIterator<Item = (K, V)>,
    ) -> Spa {
        let map = services
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        self.services = Some(Arc::new(map));
        self
    }

    async fn services_json(&self, overrides: &BTreeMap<String, String>, head: bool) -> Response {
        let mut merged: BTreeMap<String, String> = match self.read("services.json").await {
            Some(b) => serde_json::from_slice(&b).unwrap_or_default(),
            None => BTreeMap::new(),
        };
        merged.extend(overrides.iter().map(|(k, v)| (k.clone(), v.clone())));
        let body = serde_json::to_vec(&merged).expect("json");
        let mut res = Response::new(if head {
            Body::empty()
        } else {
            Body::from(body.clone())
        });
        let h = res.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        h.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        res
    }

    fn is_api(&self, path: &str) -> bool {
        let p = &self.api_prefix;
        !p.is_empty()
            && path.starts_with(p.as_str())
            && matches!(path.as_bytes().get(p.len()), None | Some(b'/'))
    }

    async fn read(&self, rel: &str) -> Option<Bytes> {
        match &self.source {
            Source::Embedded(files) => files.get(rel).map(|b| Bytes::from_static(b)),
            Source::Dir(dir) => tokio::fs::read(dir.join(rel)).await.ok().map(Bytes::from),
        }
    }

    async fn file(&self, rel: &str, accept: Accept, head: bool) -> Option<Response> {
        let compressible = [".js", ".wasm", ".css", ".html"]
            .iter()
            .any(|e| rel.ends_with(e));
        let mut found = None;
        if compressible {
            for (ok, enc, ext) in [(accept.br, "br", ".br"), (accept.gzip, "gzip", ".gz")] {
                if ok {
                    if let Some(body) = self.read(&format!("{rel}{ext}")).await {
                        found = Some((body, Some(enc)));
                        break;
                    }
                }
            }
        }
        let (body, encoding) = match found {
            Some(f) => f,
            None => (self.read(rel).await?, None),
        };
        let mut res = Response::new(if head {
            Body::empty()
        } else {
            Body::from(body.clone())
        });
        let h = res.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(content_type(rel)),
        );
        h.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
        h.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(if is_hashed(rel) {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            }),
        );
        if compressible {
            h.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
        }
        if let Some(enc) = encoding {
            h.insert(header::CONTENT_ENCODING, HeaderValue::from_static(enc));
        }
        Some(res)
    }
}

/// Mount a [`Spa`] on a router.
pub trait MountSpaExt {
    /// Answer what the router 404s with the app's files, and browser navigations
    /// outside the API prefix with `index.html`. Call it after adding every route.
    fn mount_spa(self, spa: Spa) -> Self;
}

impl<S> MountSpaExt for Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn mount_spa(self, spa: Spa) -> Self {
        self.layer(axum::middleware::from_fn_with_state(Arc::new(spa), serve))
    }
}

async fn serve(State(spa): State<Arc<Spa>>, req: Request, next: Next) -> Response {
    let head = req.method() == Method::HEAD;
    if (req.method() != Method::GET && !head) || spa.is_api(req.uri().path()) {
        return next.run(req).await;
    }
    let path = req.uri().path().to_owned();
    let accept = Accept::from_headers(req.headers());
    let wants_html = req
        .headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/html"));
    let res = next.run(req).await;
    if res.status() != StatusCode::NOT_FOUND {
        return res;
    }
    if let (Some(overrides), "/services.json") = (&spa.services, path.as_str()) {
        return spa.services_json(overrides, head).await;
    }
    if let Some(rel) = asset_path(&path) {
        if let Some(found) = spa.file(rel, accept, head).await {
            return found;
        }
    }
    if wants_html {
        if let Some(index) = spa.file("index.html", accept, head).await {
            return index;
        }
    }
    res
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Accept {
    br: bool,
    gzip: bool,
}

impl Accept {
    fn from_headers(h: &HeaderMap) -> Accept {
        h.get(header::ACCEPT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .map(Accept::parse)
            .unwrap_or_default()
    }

    fn parse(value: &str) -> Accept {
        let mut out = Accept::default();
        for item in value.split(',') {
            let mut parts = item.split(';');
            let name = parts.next().unwrap_or("").trim().to_ascii_lowercase();
            let zero = parts.any(|p| {
                p.trim()
                    .strip_prefix("q=")
                    .and_then(|q| q.trim().parse::<f32>().ok())
                    == Some(0.0)
            });
            if zero {
                continue;
            }
            match name.as_str() {
                "br" => out.br = true,
                "gzip" => out.gzip = true,
                "*" => {
                    out.br = true;
                    out.gzip = true;
                }
                _ => {}
            }
        }
        out
    }
}

/// The dist-relative file a request path names, refusing anything that could
/// climb out of the dist.
fn asset_path(path: &str) -> Option<&str> {
    let rel = path.strip_prefix('/').unwrap_or(path);
    if rel.is_empty() {
        return Some("index.html");
    }
    let safe = rel
        .split('/')
        .all(|s| !s.is_empty() && s != "." && s != ".." && !s.contains(['\\', ':']));
    safe.then_some(rel)
}

fn is_hashed(rel: &str) -> bool {
    if rel.starts_with("chunks/") || rel.starts_with("assets/") {
        return true;
    }
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let stem = name.split('.').next().unwrap_or(name);
    stem.rsplit_once('-').is_some_and(|(_, h)| {
        h.len() == 8
            && h.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn content_type(rel: &str) -> &'static str {
    let ext = rel.rsplit('.').next().unwrap_or("");
    match ext.to_ascii_lowercase().as_str() {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "wasm" => "application/wasm",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "webmanifest" => "application/manifest+json",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum::Json;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const FILES: EmbeddedFiles = &[
        ("index.html", b"<html>app</html>"),
        ("index.html.br", b"BR-HTML"),
        ("app-0123abcd.js", b"console.log(1)"),
        ("app-0123abcd.js.br", b"BR-JS"),
        ("app-0123abcd.js.gz", b"GZ-JS"),
        ("app-89abcdef.wasm", b"\0asm"),
        ("chunks/chunk-QWERTYUI.js", b"chunk"),
        ("robots.txt", b"User-agent: *"),
        (
            "services.json",
            br#"{"chat-client":"/chat","orders-client":"/orders"}"#,
        ),
    ];

    fn app(spa: Spa) -> Router {
        Router::new()
            .route(
                "/api/widgets",
                get(|| async { Json(serde_json::json!([])) }),
            )
            .route("/health", get(|| async { "ok" }))
            .fallback(|| async {
                (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"code": "not_found"})),
                )
            })
            .mount_spa(spa)
    }

    async fn send(
        router: &Router,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
    ) -> Response {
        let mut req = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        router
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn body(res: Response) -> Vec<u8> {
        res.into_body().collect().await.unwrap().to_bytes().to_vec()
    }

    fn hdr(res: &Response, name: header::HeaderName) -> Option<&str> {
        res.headers().get(name).map(|v| v.to_str().unwrap())
    }

    #[tokio::test]
    async fn hashed_assets_are_immutable_and_typed() {
        let r = app(Spa::embedded(FILES));
        let res = send(&r, Method::GET, "/app-89abcdef.wasm", &[]).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(hdr(&res, header::CONTENT_TYPE), Some("application/wasm"));
        assert_eq!(
            hdr(&res, header::CACHE_CONTROL),
            Some("public, max-age=31536000, immutable")
        );
        assert_eq!(body(res).await, b"\0asm");

        let res = send(&r, Method::GET, "/chunks/chunk-QWERTYUI.js", &[]).await;
        assert_eq!(
            hdr(&res, header::CACHE_CONTROL),
            Some("public, max-age=31536000, immutable")
        );

        let res = send(&r, Method::GET, "/robots.txt", &[]).await;
        assert_eq!(hdr(&res, header::CACHE_CONTROL), Some("no-cache"));
        assert_eq!(
            hdr(&res, header::CONTENT_TYPE),
            Some("text/plain; charset=utf-8")
        );

        let res = send(&r, Method::GET, "/", &[]).await;
        assert_eq!(hdr(&res, header::CACHE_CONTROL), Some("no-cache"));
        assert_eq!(
            hdr(&res, header::CONTENT_TYPE),
            Some("text/html; charset=utf-8")
        );
    }

    #[tokio::test]
    async fn precompressed_siblings_follow_accept_encoding() {
        let r = app(Spa::embedded(FILES));
        let res = send(
            &r,
            Method::GET,
            "/app-0123abcd.js",
            &[("accept-encoding", "gzip, br")],
        )
        .await;
        assert_eq!(hdr(&res, header::CONTENT_ENCODING), Some("br"));
        assert_eq!(hdr(&res, header::VARY), Some("accept-encoding"));
        assert_eq!(
            hdr(&res, header::CONTENT_TYPE),
            Some("text/javascript; charset=utf-8")
        );
        assert_eq!(body(res).await, b"BR-JS");

        let res = send(
            &r,
            Method::GET,
            "/app-0123abcd.js",
            &[("accept-encoding", "gzip, br;q=0")],
        )
        .await;
        assert_eq!(hdr(&res, header::CONTENT_ENCODING), Some("gzip"));
        assert_eq!(body(res).await, b"GZ-JS");

        let res = send(&r, Method::GET, "/app-0123abcd.js", &[]).await;
        assert_eq!(hdr(&res, header::CONTENT_ENCODING), None);
        assert_eq!(hdr(&res, header::VARY), Some("accept-encoding"));
        assert_eq!(body(res).await, b"console.log(1)");

        let res = send(
            &r,
            Method::GET,
            "/app-89abcdef.wasm",
            &[("accept-encoding", "br")],
        )
        .await;
        assert_eq!(hdr(&res, header::CONTENT_ENCODING), None);
    }

    #[tokio::test]
    async fn navigations_get_index_but_the_api_keeps_its_404() {
        let r = app(Spa::embedded(FILES));
        let html = [("accept", "text/html,application/xhtml+xml")];

        let res = send(&r, Method::GET, "/widgets/gear", &html).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(hdr(&res, header::CACHE_CONTROL), Some("no-cache"));
        assert_eq!(body(res).await, b"<html>app</html>");

        let res = send(&r, Method::GET, "/api/typo", &html).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert_eq!(body(res).await, br#"{"code":"not_found"}"#);

        let res = send(
            &r,
            Method::GET,
            "/widgets/gear",
            &[("accept", "application/json")],
        )
        .await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert_eq!(body(res).await, br#"{"code":"not_found"}"#);

        let res = send(&r, Method::POST, "/widgets/gear", &html).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);

        let res = send(&r, Method::GET, "/api/widgets", &html).await;
        assert_eq!(body(res).await, b"[]");
        let res = send(&r, Method::GET, "/health", &html).await;
        assert_eq!(body(res).await, b"ok");
        let res = send(&r, Method::GET, "/../etc/passwd", &[]).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn services_overlay_the_built_defaults() {
        let r = app(Spa::embedded(FILES).services([("orders-client", "https://o.example.com")]));
        let res = send(&r, Method::GET, "/services.json", &[]).await;
        assert_eq!(hdr(&res, header::CACHE_CONTROL), Some("no-cache"));
        assert_eq!(hdr(&res, header::CONTENT_TYPE), Some("application/json"));
        assert_eq!(
            body(res).await,
            br#"{"chat-client":"/chat","orders-client":"https://o.example.com"}"#
        );

        let r = app(Spa::embedded(FILES));
        let res = send(&r, Method::GET, "/services.json", &[]).await;
        assert_eq!(body(res).await, FILES[8].1);
    }

    #[tokio::test]
    async fn head_has_headers_and_no_body() {
        let r = app(Spa::embedded(FILES));
        let res = send(&r, Method::HEAD, "/app-0123abcd.js", &[]).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(hdr(&res, header::CONTENT_LENGTH), Some("14"));
        assert!(body(res).await.is_empty());

        let res = send(&r, Method::HEAD, "/some/page", &[("accept", "text/html")]).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(body(res).await.is_empty());
    }

    #[tokio::test]
    async fn serves_from_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("chunks")).unwrap();
        for (path, bytes) in FILES {
            std::fs::write(dir.path().join(path), bytes).unwrap();
        }
        let r = app(Spa::dir(dir.path()).api_prefix("/v1/"));
        let res = send(
            &r,
            Method::GET,
            "/app-0123abcd.js",
            &[("accept-encoding", "br")],
        )
        .await;
        assert_eq!(hdr(&res, header::CONTENT_ENCODING), Some("br"));
        assert_eq!(body(res).await, b"BR-JS");

        let html = [("accept", "text/html")];
        let res = send(&r, Method::GET, "/v1/nope", &html).await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let res = send(
            &r,
            Method::GET,
            "/api/nope",
            &[("accept", "text/html"), ("accept-encoding", "br")],
        )
        .await;
        assert_eq!(hdr(&res, header::CONTENT_ENCODING), Some("br"));
        assert_eq!(body(res).await, b"BR-HTML");
    }

    #[cfg(not(feature = "embed"))]
    #[test]
    fn dist_without_embed_reads_from_disk() {
        let d = crate::dist!();
        assert!(d.embedded.is_empty());
        let _ = Spa::auto(d);
    }

    #[test]
    fn helpers() {
        assert_eq!(
            Accept::parse("gzip, deflate, br"),
            Accept {
                br: true,
                gzip: true
            }
        );
        assert_eq!(
            Accept::parse("br;q=0, gzip;q=0.5"),
            Accept {
                br: false,
                gzip: true
            }
        );
        assert_eq!(
            Accept::parse("*"),
            Accept {
                br: true,
                gzip: true
            }
        );
        assert_eq!(asset_path("/a/../b"), None);
        assert_eq!(asset_path("//x"), None);
        assert_eq!(asset_path("/chunks/a.js"), Some("chunks/a.js"));
        assert!(is_hashed("app-0123abcd.js.br"));
        assert!(!is_hashed("logo-original.png"));
        assert!(!is_hashed("index.html"));
        let spa = Spa::dir("x");
        assert!(spa.is_api("/api"));
        assert!(spa.is_api("/api/x"));
        assert!(!spa.is_api("/apiary"));
        assert!(!Spa::dir("x").api_prefix("").is_api("/api"));
        assert!(Spa::dir("x").api_prefix("v1").is_api("/v1/a"));
    }
}
