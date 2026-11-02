//! How a request leaves the client: `fetch` in the browser, an in-process
//! router or a mock natively.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use futures_util::future::LocalBoxFuture;
use futures_util::stream::LocalBoxStream;

use doxa_wire::Method;

/// An outgoing HTTP request.
#[derive(Debug, Clone)]
pub struct Request {
    /// HTTP method.
    pub method: Method,
    /// Path and query, relative to the client's base URL.
    pub url: String,
    /// Header names and values.
    pub headers: Vec<(String, String)>,
    /// Request body, if any.
    pub body: Option<Vec<u8>>,
    /// Send the browser's cookies with the request.
    pub credentials: bool,
}

impl Request {
    /// The value of header `name`, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        find(&self.headers, name)
    }
}

/// A response body, buffered or streamed.
pub enum Body {
    /// The whole body.
    Full(Vec<u8>),
    /// Chunks as they arrive.
    Stream(LocalBoxStream<'static, Result<Vec<u8>, String>>),
}

impl Body {
    /// Read the whole body.
    pub async fn bytes(self) -> Result<Vec<u8>, String> {
        use futures_util::StreamExt;
        match self {
            Body::Full(b) => Ok(b),
            Body::Stream(mut s) => {
                let mut out = Vec::new();
                while let Some(chunk) = s.next().await {
                    out.extend_from_slice(&chunk?);
                }
                Ok(out)
            }
        }
    }
}

/// A received response.
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Header names and values.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Body,
}

impl Response {
    /// The value of header `name`, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        find(&self.headers, name)
    }
}

fn find<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Sends requests. Implement it to route calls anywhere.
pub trait Transport: 'static {
    /// Send `request`; `Err` is a network failure, never an HTTP status.
    fn send(&self, request: Request) -> LocalBoxFuture<'static, Result<Response, String>>;
}

/// No transport: every call fails, naming how to configure one.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct Unconfigured;

#[cfg(not(target_arch = "wasm32"))]
impl Transport for Unconfigured {
    fn send(&self, _: Request) -> LocalBoxFuture<'static, Result<Response, String>> {
        Box::pin(async {
            Err("no transport: push a `layer::transport(…)` onto `layers()` first".to_owned())
        })
    }
}

/// Answers from a queue of canned responses and records every request.
///
/// ```
/// use doxa_client::transport::MockTransport;
///
/// let mock = MockTransport::new();
/// mock.json(200, &serde_json::json!({ "id": 1 }));
/// assert_eq!(mock.requests().len(), 0);
/// ```
#[derive(Clone, Default)]
pub struct MockTransport {
    inner: Rc<RefCell<MockState>>,
}

type Canned = (u16, Vec<(String, String)>, Vec<u8>);

#[derive(Default)]
struct MockState {
    queue: VecDeque<Canned>,
    seen: Vec<Request>,
}

impl MockTransport {
    /// An empty mock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a JSON response.
    pub fn json(&self, status: u16, body: &impl serde::Serialize) -> &Self {
        self.respond(
            status,
            vec![("content-type".into(), "application/json".into())],
            serde_json::to_vec(body).expect("serializable body"),
        )
    }

    /// Queue a raw response.
    pub fn respond(&self, status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> &Self {
        self.inner
            .borrow_mut()
            .queue
            .push_back((status, headers, body));
        self
    }

    /// Every request sent so far.
    pub fn requests(&self) -> Vec<Request> {
        self.inner.borrow().seen.clone()
    }
}

impl Transport for MockTransport {
    fn send(&self, request: Request) -> LocalBoxFuture<'static, Result<Response, String>> {
        let mut state = self.inner.borrow_mut();
        state.seen.push(request);
        let next = state.queue.pop_front();
        Box::pin(async move {
            let (status, headers, body) = next.ok_or("MockTransport has no response queued")?;
            Ok(Response {
                status,
                headers,
                body: Body::Full(body),
            })
        })
    }
}

#[cfg(all(feature = "router", not(target_arch = "wasm32")))]
pub use router::RouterTransport;

#[cfg(all(feature = "router", not(target_arch = "wasm32")))]
mod router {
    use futures_util::future::LocalBoxFuture;
    use futures_util::StreamExt;
    use tower::ServiceExt;

    use super::{Body, Request, Response, Transport};

    /// Sends every call through an axum router in-process: the real routes and layers.
    #[derive(Clone)]
    pub struct RouterTransport {
        router: axum::Router,
        headers: Vec<(String, String)>,
    }

    impl RouterTransport {
        /// Route calls through `router`.
        pub fn new(router: axum::Router) -> Self {
            Self {
                router,
                headers: Vec::new(),
            }
        }

        /// Add a header to every request, e.g. a cookie the browser would send.
        pub fn with_header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_owned(), value.to_owned()));
            self
        }
    }

    impl Transport for RouterTransport {
        fn send(&self, request: Request) -> LocalBoxFuture<'static, Result<Response, String>> {
            let router = self.router.clone();
            let extra = self.headers.clone();
            Box::pin(async move {
                let mut builder = http::Request::builder()
                    .method(request.method.as_str())
                    .uri(&request.url);
                for (k, v) in request.headers.iter().chain(&extra) {
                    builder = builder.header(k, v);
                }
                let req = builder
                    .body(axum::body::Body::from(request.body.unwrap_or_default()))
                    .map_err(|e| e.to_string())?;
                let Ok(resp) = router.oneshot(req).await;
                let status = resp.status().as_u16();
                let headers = resp
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_owned()))
                    .collect();
                let stream = resp
                    .into_body()
                    .into_data_stream()
                    .map(|chunk| chunk.map(|b| b.to_vec()).map_err(|e| e.to_string()));
                Ok(Response {
                    status,
                    headers,
                    body: Body::Stream(Box::pin(stream)),
                })
            })
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use browser::BrowserFetch;

#[cfg(target_arch = "wasm32")]
mod browser {
    use futures_util::future::LocalBoxFuture;
    use js_sys::{Reflect, Uint8Array};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{RequestCache, RequestCredentials, RequestInit};

    use super::{Body, Request, Response, Transport};

    /// `window.fetch`, with the browser's HTTP cache bypassed so only doxa's applies.
    #[derive(Clone, Default)]
    pub struct BrowserFetch {
        base: String,
    }

    impl BrowserFetch {
        /// Fetch relative to `base`, e.g. `https://api.example.com`. Empty means same origin.
        pub fn new(base: impl Into<String>) -> Self {
            Self { base: base.into() }
        }
    }

    fn js_err(e: JsValue) -> String {
        e.as_string()
            .or_else(|| Reflect::get(&e, &"message".into()).ok()?.as_string())
            .unwrap_or_else(|| "fetch failed".to_owned())
    }

    impl Transport for BrowserFetch {
        fn send(&self, request: Request) -> LocalBoxFuture<'static, Result<Response, String>> {
            let url = format!("{}{}", self.base, request.url);
            Box::pin(async move {
                let init = RequestInit::new();
                init.set_method(request.method.as_str());
                init.set_cache(RequestCache::NoStore);
                init.set_credentials(if request.credentials {
                    RequestCredentials::Include
                } else {
                    RequestCredentials::SameOrigin
                });
                let headers = web_sys::Headers::new().map_err(js_err)?;
                for (k, v) in &request.headers {
                    headers.append(k, v).map_err(js_err)?;
                }
                init.set_headers(&headers);
                if let Some(body) = &request.body {
                    init.set_body(&Uint8Array::from(body.as_slice()));
                }
                let req = web_sys::Request::new_with_str_and_init(&url, &init).map_err(js_err)?;
                let window = web_sys::window().ok_or("no window")?;
                let resp: web_sys::Response = JsFuture::from(window.fetch_with_request(&req))
                    .await
                    .map_err(js_err)?
                    .dyn_into()
                    .map_err(js_err)?;
                let status = resp.status();
                let mut out_headers = Vec::new();
                if let Ok(Some(iter)) = js_sys::try_iter(&resp.headers()) {
                    for pair in iter.flatten() {
                        let pair: js_sys::Array = pair.unchecked_into();
                        out_headers.push((
                            pair.get(0).as_string().unwrap_or_default(),
                            pair.get(1).as_string().unwrap_or_default(),
                        ));
                    }
                }
                let body = match resp.body() {
                    Some(stream) => Body::Stream(Box::pin(read_stream(stream))),
                    None => Body::Full(Vec::new()),
                };
                Ok(Response {
                    status,
                    headers: out_headers,
                    body,
                })
            })
        }
    }

    /// A body reader that cancels the body, closing the connection, if dropped before the end.
    struct Reader(Option<web_sys::ReadableStreamDefaultReader>);

    impl Reader {
        fn read(&self) -> Option<js_sys::Promise> {
            self.0.as_ref().map(|r| r.read())
        }

        fn finish(mut self) {
            self.0 = None;
        }
    }

    impl Drop for Reader {
        fn drop(&mut self) {
            if let Some(reader) = self.0.take() {
                let _ = reader.cancel();
            }
        }
    }

    fn read_stream(
        stream: web_sys::ReadableStream,
    ) -> impl futures_core::Stream<Item = Result<Vec<u8>, String>> {
        let reader = Reader(Some(stream.get_reader().unchecked_into()));
        futures_util::stream::unfold(Some(reader), |reader| async move {
            let reader = reader?;
            let chunk = match JsFuture::from(reader.read()?).await {
                Ok(chunk) => chunk,
                Err(e) => {
                    reader.finish();
                    return Some((Err(js_err(e)), None));
                }
            };
            let done = Reflect::get(&chunk, &"done".into())
                .ok()
                .and_then(|d| d.as_bool())
                .unwrap_or(true);
            if done {
                reader.finish();
                return None;
            }
            let value = Reflect::get(&chunk, &"value".into()).ok()?;
            Some((Ok(Uint8Array::new(&value).to_vec()), Some(reader)))
        })
    }
}
