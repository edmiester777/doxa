//! `Cors`: let a doxa client on another origin call this server and read its wire headers.

use std::time::Duration;

use axum::http::{HeaderName, HeaderValue, Method};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// A CORS layer that allows the headers a doxa client sends and exposes the ones it reads.
/// Without them a cross-origin client loses session resets, invalidation and `<Can>`.
///
/// ```
/// use axum::Router;
/// use doxa_docs::Cors;
///
/// let app: Router = Router::new().layer(Cors::allow(["https://app.example.com"]).credentials(true));
/// ```
#[derive(Debug, Clone)]
pub struct Cors {
    origins: Vec<HeaderValue>,
    credentials: bool,
    max_age: Duration,
}

impl Cors {
    /// Allow pages served from `origins`, e.g. `https://app.example.com`. Panics on an
    /// origin that is not a valid header value.
    pub fn allow<O: AsRef<str>>(origins: impl IntoIterator<Item = O>) -> Cors {
        let origins = origins
            .into_iter()
            .map(|o| {
                let o = o.as_ref().trim_end_matches('/');
                HeaderValue::from_str(o).unwrap_or_else(|_| panic!("invalid origin `{o}`"))
            })
            .collect();
        Cors {
            origins,
            credentials: false,
            max_age: Duration::from_secs(600),
        }
    }

    /// Let the browser send cookies, for a client using `layer::cookies()`.
    pub fn credentials(mut self, yes: bool) -> Cors {
        self.credentials = yes;
        self
    }

    /// How long a browser may cache a preflight answer.
    pub fn max_age(mut self, max_age: Duration) -> Cors {
        self.max_age = max_age;
        self
    }

    fn layer(&self) -> CorsLayer {
        let names = |list: &'static [&'static str]| -> Vec<HeaderName> {
            list.iter().map(|h| HeaderName::from_static(h)).collect()
        };
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(self.origins.clone()))
            .allow_methods([
                Method::GET,
                Method::HEAD,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
            ])
            .allow_headers(names(doxa_wire::REQUEST_HEADERS))
            .expose_headers(names(doxa_wire::RESPONSE_HEADERS))
            .allow_credentials(self.credentials)
            .max_age(self.max_age)
    }
}

impl<S> tower::Layer<S> for Cors {
    type Service = tower_http::cors::Cors<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Cors::layer(self).layer(inner)
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    use super::Cors;

    fn app() -> Router {
        Router::new()
            .route(
                "/api/w",
                get(|| async { ([(doxa_wire::SESSION_HEADER, "s1")], "{}") }),
            )
            .layer(Cors::allow(["https://app.example.com/"]).credentials(true))
    }

    async fn send(req: Request<Body>) -> axum::response::Response {
        app().oneshot(req).await.unwrap()
    }

    fn hdr<'a>(res: &'a axum::response::Response, name: &str) -> Option<&'a str> {
        res.headers().get(name).map(|v| v.to_str().unwrap())
    }

    #[tokio::test]
    async fn a_preflight_for_a_probe_is_allowed() {
        let res = send(
            Request::options("/api/w")
                .header(header::ORIGIN, "https://app.example.com")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PATCH")
                .header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "x-doxa-dry-run,authorization",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            hdr(&res, "access-control-allow-origin"),
            Some("https://app.example.com")
        );
        assert!(hdr(&res, "access-control-allow-headers")
            .unwrap()
            .contains("x-doxa-dry-run"));
        assert!(hdr(&res, "access-control-allow-methods")
            .unwrap()
            .contains("PATCH"));
        assert_eq!(hdr(&res, "access-control-allow-credentials"), Some("true"));
    }

    #[tokio::test]
    async fn a_response_exposes_the_wire_headers_to_its_origin_only() {
        let res = send(
            Request::get("/api/w")
                .header(header::ORIGIN, "https://app.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let exposed = hdr(&res, "access-control-expose-headers").unwrap();
        for h in doxa_wire::RESPONSE_HEADERS {
            assert!(exposed.contains(h), "{h} in {exposed}");
        }

        let res = send(
            Request::get("/api/w")
                .header(header::ORIGIN, "https://evil.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(hdr(&res, "access-control-allow-origin"), None);
    }
}
