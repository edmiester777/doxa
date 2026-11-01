//! The router's answer to a `<Can>` dry run of a route with no doxa guard:
//! `204` before any extractor or the handler runs. A guarded route is left
//! alone, so its last guard answers once it has passed.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::MethodRouter;
use utoipa::openapi::path::HttpMethod;

/// Answer dry runs of the unguarded `methods` on `router`. Applied by [`routes!`](crate::routes).
pub fn gate_dry_runs<S>(router: MethodRouter<S>, methods: Vec<HttpMethod>) -> MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    if methods.is_empty() {
        return router;
    }
    let methods: Arc<[Method]> = methods.into_iter().map(http_method).collect();
    router.layer(axum::middleware::from_fn(
        move |req: Request, next: Next| {
            let unguarded = methods.contains(req.method());
            async move {
                if unguarded && req.headers().contains_key(doxa_wire::DRY_RUN_HEADER) {
                    return dry_run_allowed();
                }
                next.run(req).await
            }
        },
    ))
}

/// The `204` a dry run that passed gets.
fn dry_run_allowed() -> Response {
    (
        StatusCode::NO_CONTENT,
        [
            (doxa_wire::DRY_RUN_HEADER, doxa_wire::DRY_RUN_OK),
            ("cache-control", "no-store"),
            ("vary", doxa_wire::DRY_RUN_HEADER),
        ],
    )
        .into_response()
}

fn http_method(m: HttpMethod) -> Method {
    match m {
        HttpMethod::Get => Method::GET,
        HttpMethod::Put => Method::PUT,
        HttpMethod::Post => Method::POST,
        HttpMethod::Delete => Method::DELETE,
        HttpMethod::Options => Method::OPTIONS,
        HttpMethod::Head => Method::HEAD,
        HttpMethod::Patch => Method::PATCH,
        HttpMethod::Trace => Method::TRACE,
    }
}
