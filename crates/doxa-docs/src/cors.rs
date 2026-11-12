//! `Cors`: let a doxa client on another origin call this server and read its wire headers.

use std::time::Duration;

use axum::http::{HeaderName, HeaderValue, Method};
use tower_http::cors::{AllowOrigin, CorsLayer};
use utoipa::openapi::path::ParameterIn;

/// A CORS layer that allows the headers a doxa client sends and exposes the ones it reads.
/// Without them a cross-origin client loses session resets, invalidation and `<Can>`.
///
/// ```
/// use axum::Router;
/// use doxa_docs::Cors;
///
/// let (router, api) = doxa_docs::OpenApiRouter::<()>::new().split_for_parts();
/// let app: Router = router.layer(Cors::allow(["https://app.example.com"]).routes(&api));
/// ```
#[derive(Debug, Clone)]
pub struct Cors {
    origins: Vec<HeaderValue>,
    credentials: bool,
    max_age: Duration,
    headers: Vec<HeaderName>,
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
            headers: Vec::new(),
        }
    }

    /// Also allow every header parameter the routes in `api` declare.
    pub fn routes(mut self, api: &utoipa::openapi::OpenApi) -> Cors {
        let params = api.paths.paths.values().flat_map(|item| {
            let shared = item.parameters.iter().flatten();
            let own = crate::contribution::path_item_operations(item)
                .flat_map(|op| op.parameters.iter().flatten());
            shared.chain(own)
        });
        for param in params {
            if !matches!(param.parameter_in, ParameterIn::Header) {
                continue;
            }
            let Ok(name) = HeaderName::try_from(param.name.as_str()) else {
                continue;
            };
            if !self.headers.contains(&name) {
                self.headers.push(name);
            }
        }
        self
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
            .allow_headers([names(doxa_wire::REQUEST_HEADERS), self.headers.clone()].concat())
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

    #[tokio::test]
    async fn a_header_a_route_declares_is_allowed() {
        use utoipa::openapi::path::{OperationBuilder, ParameterBuilder, ParameterIn, PathItem};
        use utoipa::openapi::{HttpMethod, OpenApiBuilder, PathsBuilder};

        let op = OperationBuilder::new()
            .parameter(
                ParameterBuilder::new()
                    .name("Idempotency-Key")
                    .parameter_in(ParameterIn::Header),
            )
            .parameter(
                ParameterBuilder::new()
                    .name("page")
                    .parameter_in(ParameterIn::Query),
            )
            .build();
        let api = OpenApiBuilder::new()
            .paths(PathsBuilder::new().path("/api/w", PathItem::new(HttpMethod::Post, op)))
            .build();
        let app = Router::new()
            .route("/api/w", get(|| async { "{}" }))
            .layer(Cors::allow(["https://app.example.com"]).routes(&api));
        let res = app
            .oneshot(
                Request::options("/api/w")
                    .header(header::ORIGIN, "https://app.example.com")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "idempotency-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let allowed = hdr(&res, "access-control-allow-headers").unwrap();
        assert!(allowed.contains("idempotency-key"), "{allowed}");
        assert!(!allowed.contains("page"), "{allowed}");
    }
}
