//! `ETagLayer`: tag JSON GET responses with a body hash and answer a matching
//! `If-None-Match` with `304`, so a revalidating client skips the download.

use std::convert::Infallible;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{header, HeaderValue, Method, Request, Response, StatusCode};
use tower::{Layer, Service};

/// Tags `200` JSON `GET` responses with a weak `ETag`, plus `Cache-Control: private` and
/// `Vary: Authorization, Cookie` unless the route set its own. Streams pass through.
#[derive(Debug, Clone, Copy, Default)]
pub struct ETagLayer;

impl<S> Layer<S> for ETagLayer {
    type Service = ETagService<S>;

    fn layer(&self, inner: S) -> ETagService<S> {
        ETagService { inner }
    }
}

/// The service [`ETagLayer`] wraps a router in.
#[derive(Debug, Clone)]
pub struct ETagService<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for ETagService<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let get = req.method() == Method::GET;
        let if_none_match = req.headers().get(header::IF_NONE_MATCH).cloned();
        Box::pin(async move {
            let response = inner.call(req).await?;
            if !get || response.status() != StatusCode::OK || !is_json(&response) {
                return Ok(response);
            }
            let (mut parts, body) = response.into_parts();
            let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
                return Ok(Response::from_parts(parts, Body::empty()));
            };
            let tag = etag(&bytes);
            let headers = &mut parts.headers;
            headers
                .entry(header::CACHE_CONTROL)
                .or_insert(HeaderValue::from_static("private, no-cache"));
            headers
                .entry(header::VARY)
                .or_insert(HeaderValue::from_static("Authorization, Cookie"));
            if let Ok(v) = HeaderValue::from_str(&tag) {
                headers.insert(header::ETAG, v);
            }
            if if_none_match.is_some_and(|m| matches(&m, &tag)) {
                parts.status = StatusCode::NOT_MODIFIED;
                parts.headers.remove(header::CONTENT_LENGTH);
                return Ok(Response::from_parts(parts, Body::empty()));
            }
            Ok(Response::from_parts(parts, Body::from(bytes)))
        })
    }
}

fn is_json<B>(response: &Response<B>) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/json") || ct.contains("+json"))
}

fn etag(bytes: &[u8]) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    format!("W/\"{:016x}\"", h.finish())
}

fn matches(header: &HeaderValue, tag: &str) -> bool {
    let bare = |t: &str| t.trim().trim_start_matches("W/").to_owned();
    header
        .to_str()
        .is_ok_and(|v| v.trim() == "*" || v.split(',').any(|t| bare(t) == bare(tag)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum::{Json, Router};
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route(
                "/w",
                get(|| async { Json(serde_json::json!({ "name": "gear" })) }),
            )
            .route("/text", get(|| async { "plain" }))
            .layer(ETagLayer)
    }

    async fn send(uri: &str, tag: Option<&str>) -> Response<Body> {
        let mut req = Request::get(uri);
        if let Some(t) = tag {
            req = req.header(header::IF_NONE_MATCH, t);
        }
        app()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn json_gets_a_tag_and_a_match_is_not_modified() {
        let first = send("/w", None).await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(first.headers()[header::VARY], "Authorization, Cookie");
        let tag = first.headers()[header::ETAG].to_str().unwrap().to_owned();

        let again = send("/w", Some(&tag)).await;
        assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
        let body = axum::body::to_bytes(again.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(body.is_empty());

        assert_eq!(
            send("/w", Some("W/\"other\"")).await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn non_json_is_left_alone() {
        assert!(!send("/text", None)
            .await
            .headers()
            .contains_key(header::ETAG));
    }
}
