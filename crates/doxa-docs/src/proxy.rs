//! `proxy`: serve another server's routes under a path prefix of this one, so the browser
//! reaches it same-origin.

use std::convert::Infallible;
use std::sync::Arc;

use axum::body::{Body, HttpBody};
use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;

/// Forward everything under `prefix` to `upstream`, minus the prefix. Bodies stream both ways,
/// so SSE arrives as it is sent; credentials and doxa's wire headers pass through.
///
/// ```
/// let app: axum::Router = axum::Router::new()
///     .merge(doxa_docs::proxy("/orders", "http://orders.internal:8080"));
/// ```
pub fn proxy<S: Clone + Send + Sync + 'static>(prefix: &str, upstream: &str) -> Router<S> {
    let prefix = format!("/{}", prefix.trim_matches('/'));
    let to = Upstream(Arc::new(Inner {
        base: upstream.trim_end_matches('/').to_owned(),
        prefix: HeaderValue::from_str(&prefix).expect("a prefix is a valid header value"),
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("an HTTP client"),
    }));
    Router::new().nest_service(
        &prefix,
        tower::service_fn(move |req: Request| {
            let to = to.clone();
            async move { Ok::<_, Infallible>(to.forward(req).await) }
        }),
    )
}

#[derive(Clone)]
struct Upstream(Arc<Inner>);

struct Inner {
    base: String,
    prefix: HeaderValue,
    client: reqwest::Client,
}

impl Upstream {
    async fn forward(&self, req: Request) -> Response {
        let (parts, body) = req.into_parts();
        let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
        let mut headers = parts.headers.clone();
        strip_hop_by_hop(&mut headers);
        headers.remove(header::HOST);
        if let Some(host) = parts.headers.get(header::HOST) {
            headers.insert(X_FORWARDED_HOST, host.clone());
        }
        headers.insert(X_FORWARDED_PREFIX, self.0.prefix.clone());
        let mut sent = self
            .0
            .client
            .request(parts.method, format!("{}{path}", self.0.base))
            .headers(headers);
        if body.size_hint().exact() != Some(0) {
            sent = sent.body(reqwest::Body::wrap_stream(body.into_data_stream()));
        }
        let res = match sent.send().await {
            Ok(res) => res,
            Err(e) => {
                tracing::warn!(error = %e, upstream = %self.0.base, "proxy could not reach upstream");
                return StatusCode::BAD_GATEWAY.into_response();
            }
        };
        let status = res.status();
        let mut headers = res.headers().clone();
        strip_hop_by_hop(&mut headers);
        let mut out = Response::new(Body::from_stream(res.bytes_stream()));
        *out.status_mut() = status;
        *out.headers_mut() = headers;
        out
    }
}

const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PREFIX: HeaderName = HeaderName::from_static("x-forwarded-prefix");

/// Remove the headers that describe one connection, including any `Connection` names.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|n| HeaderName::try_from(n.trim()).ok())
        .collect();
    for name in named.iter().chain(&[
        header::CONNECTION,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ]) {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::extract::Request;
    use axum::http::{HeaderMap, StatusCode, Uri};
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use tokio::sync::Notify;
    use tower::ServiceExt;

    use super::proxy;

    /// An upstream on a real socket; `/api/stream` sends one chunk, then waits for `go`.
    async fn upstream(go: Arc<Notify>) -> String {
        let app = Router::new()
            .route(
                "/api/echo",
                get(|uri: Uri, h: HeaderMap| async move {
                    let get = |n: &str| h.get(n).map_or("", |v| v.to_str().unwrap()).to_owned();
                    (
                        [(doxa_wire::SESSION_HEADER, "s1"), ("connection", "close")],
                        format!(
                            "{uri} auth={} host={} prefix={} te={}",
                            get("authorization"),
                            get("x-forwarded-host"),
                            get("x-forwarded-prefix"),
                            get("te"),
                        ),
                    )
                }),
            )
            .route(
                "/api/stream",
                get(move || {
                    let go = go.clone();
                    async move {
                        let s = async_stream(go);
                        (
                            [("content-type", "text/event-stream")],
                            Body::from_stream(s),
                        )
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    fn async_stream(
        go: Arc<Notify>,
    ) -> impl futures_core::Stream<Item = Result<&'static str, std::io::Error>> {
        futures::stream::unfold(0, move |n| {
            let go = go.clone();
            async move {
                match n {
                    0 => Some((Ok("data: 1\n\n"), 1)),
                    1 => {
                        go.notified().await;
                        Some((Ok("data: 2\n\n"), 2))
                    }
                    _ => None,
                }
            }
        })
    }

    #[tokio::test]
    async fn requests_are_forwarded_without_the_prefix() {
        let base = upstream(Arc::new(Notify::new())).await;
        let app: Router = proxy("/orders/", &base);
        let res = app
            .oneshot(
                Request::get("/orders/api/echo?x=1")
                    .header("host", "app.example.com")
                    .header("authorization", "Bearer t")
                    .header("connection", "te")
                    .header("te", "trailers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers()[doxa_wire::SESSION_HEADER], "s1");
        assert!(res.headers().get("connection").is_none());
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            body,
            "/api/echo?x=1 auth=Bearer t host=app.example.com prefix=/orders te="
        );
    }

    #[tokio::test]
    async fn a_stream_arrives_before_the_upstream_finishes() {
        let go = Arc::new(Notify::new());
        let base = upstream(go.clone()).await;
        let app: Router = proxy("/orders", &base);
        let res = app
            .oneshot(
                Request::get("/orders/api/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let mut body = res.into_body();
        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(first, "data: 1\n\n");
        go.notify_one();
        let second = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(second, "data: 2\n\n");
    }

    #[tokio::test]
    async fn an_unreachable_upstream_is_a_bad_gateway() {
        let app: Router = proxy("/orders", "http://127.0.0.1:1");
        let res = app
            .oneshot(Request::get("/orders/x").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_GATEWAY);
    }
}
