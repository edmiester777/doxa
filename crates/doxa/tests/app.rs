//! Handlers mount themselves under the crate's one state, grouped into services by module.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{FromRef, FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use doxa::{DocumentedLayer, LayerContribution, Routes};
use tower::ServiceExt;

#[derive(Clone)]
struct Db(u8);

#[derive(Clone)]
struct Registry(&'static str);

#[derive(Clone, doxa::State)]
struct AppState {
    db: Db,
    registry: Arc<Registry>,
}

impl FromRef<AppState> for Db {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

impl FromRef<AppState> for Arc<Registry> {
    fn from_ref(state: &AppState) -> Self {
        state.registry.clone()
    }
}

/// An extractor written against axum's `FromRef`, as an app has them.
struct RequireDb;

impl<S: Send + Sync> FromRequestParts<S> for RequireDb
where
    Db: FromRef<S>,
{
    type Rejection = StatusCode;

    async fn from_request_parts(_: &mut Parts, state: &S) -> Result<Self, StatusCode> {
        if Db::from_ref(state).0 > 0 {
            Ok(RequireDb)
        } else {
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

#[derive(Default)]
struct AdminDocs;

impl DocumentedLayer for AdminDocs {
    fn contribution(&self) -> LayerContribution {
        LayerContribution::new().with_tag("admin")
    }
}

#[doxa::layers(docs = [AdminDocs])]
fn admin(routes: Routes, _: &AppState) -> Routes {
    routes.layer(axum::middleware::from_fn(
        |req: Request<Body>, next: Next| async move {
            if req.headers().contains_key("x-admin") {
                next.run(req).await
            } else {
                StatusCode::FORBIDDEN.into_response()
            }
        },
    ))
}

#[doxa::service]
pub struct Root;

#[doxa::get("/status")]
async fn status(
    State(db): State<Db>,
    State(registry): State<Arc<Registry>>,
    _: RequireDb,
) -> String {
    format!("db={} registry={}", db.0, registry.0)
}

mod admin_routes {
    use super::*;

    #[doxa::service(layers = super::admin)]
    pub struct Admin;

    #[doxa::post("/purge")]
    async fn purge(State(db): State<Db>) -> String {
        format!("purged {}", db.0)
    }
}

fn state() -> AppState {
    AppState {
        db: Db(7),
        registry: Arc::new(Registry("r")),
    }
}

async fn call(req: Request<Body>) -> (StatusCode, String) {
    let (router, _) = doxa::app(&state()).split_for_parts();
    let res = router.oneshot(req).await.unwrap();
    let status = res.status();
    let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn a_handler_reads_sub_states_and_a_from_ref_extractor_without_naming_the_state() {
    let req = Request::get("/status").body(Body::empty()).unwrap();
    assert_eq!(call(req).await, (StatusCode::OK, "db=7 registry=r".into()));
}

#[tokio::test]
async fn a_service_wraps_only_the_handlers_in_its_module() {
    let refused = Request::post("/purge").body(Body::empty()).unwrap();
    assert_eq!(call(refused).await.0, StatusCode::FORBIDDEN);
    let allowed = Request::post("/purge")
        .header("x-admin", "1")
        .body(Body::empty())
        .unwrap();
    assert_eq!(call(allowed).await, (StatusCode::OK, "purged 7".into()));
}

#[test]
fn the_stateless_spec_is_the_apps_document_with_its_layer_docs() {
    let served = doxa::app(&state()).into_openapi();
    let spec = doxa::spec();
    assert_eq!(
        serde_json::to_value(&served).unwrap(),
        serde_json::to_value(&spec).unwrap()
    );
    let tags = |path: &str| {
        let item = &spec.paths.paths[path];
        let op = item.get.as_ref().or(item.post.as_ref()).unwrap();
        op.tags.clone().unwrap_or_default()
    };
    assert_eq!(tags("/purge"), ["admin"]);
    assert!(!tags("/status").contains(&"admin".to_owned()));
}

#[test]
#[should_panic(expected = "reads another state than `u8`")]
fn another_state_is_refused() {
    let _ = doxa::app(&7u8);
}
