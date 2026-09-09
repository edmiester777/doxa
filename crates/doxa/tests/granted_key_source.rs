//! Where a route's key comes from, and what it is called.
//!
//! Two facts used to be written at every call site. Which parameter feeds
//! the lookup is now the asset's to say — `Granting::KEY_NAMES`, the column
//! the lookup matches — so a route repeats it only when it spells it
//! differently. Where that parameter *lives* is the guard's second type
//! argument, `Path` by default and `Query` when the route says so.
//!
//! Both are read twice: once by the guard, once by the OpenAPI
//! description. These tests assert the two halves agree, which is the
//! failure neither half could catch on its own — a guard reading `?name=`
//! under a spec advertising `/{name}` is two individually correct pieces
//! of code.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;

use async_trait::async_trait;
use tower::ServiceExt;

// Deliberately the *axum* `Query`, which is what a handler reading its own
// query string imports — and exactly the name `Granted<Widget, Query>`
// would pick up if the route macro did not resolve the marker itself.
use axum::extract::Query;
use doxa::auth::{Action, CapabilityContext, FromState, Granted, Granting};
use doxa::policy::{
    AuthError, Capability, CapabilityCheck, CapabilityChecker, ResourceEntity, ResourceId,
};
use doxa::{get, routes, OpenApiRouter, PolicyResource, ToSchema};

// ---- domain -----------------------------------------------------------------

const WIDGETS_READ: Capability = Capability {
    name: "widgets.read",
    description: "Read widgets",
    checks: &[CapabilityCheck {
        action: "read",
        entity_type: "Widget",
        entity_id: ResourceId::Literal("collection"),
    }],
};

#[derive(Debug, Clone, Serialize, ToSchema, PolicyResource)]
#[resource(entity_type = "Widget")]
struct Widget {
    #[resource(id)]
    name: String,
    #[resource(attr)]
    region: String,
}

/// Keyed on `name`, and it says so. That one line is what lets every route
/// below bind `{name}` — or `?name=` — without naming it again.
impl Granting for Widget {
    type Row = Self;
    type Key = String;
    type Ctx = CapabilityContext;
    type State = ();
    type Source = FromState<()>;
    type Error = StatusCode;

    const ACTIONS: &'static [Action] = &[Action::new("read").capability(&WIDGETS_READ)];
    const KEY_NAMES: &'static [&'static str] = &["name"];

    async fn load(
        name: String,
        _state: &(),
        _ctx: &CapabilityContext,
    ) -> Result<Option<Self>, StatusCode> {
        Ok(match name.as_str() {
            "alpha" | "beta" => Some(Widget {
                name,
                region: "us".into(),
            }),
            _ => None,
        })
    }
}

// ---- routes -----------------------------------------------------------------

/// Two path parameters and no annotation. This is the case that used to be
/// rejected as ambiguous: the asset names its key's column, `{name}` is
/// one of the two segments, and nothing else has to be said.
#[get("/folders/{fid}/widgets/{name}", tag = "Widgets")]
async fn get_widget(widget: Granted<Widget>) -> String {
    widget.into_inner().name
}

/// The same object, identified in the query string instead — alongside a
/// real [`axum::extract::Query`] the handler reads for itself, so the two
/// meanings of the word are both in scope at once.
#[get("/widgets", tag = "Widgets")]
async fn find_widget(widget: Granted<Widget, Query>, Query(filters): Query<Filters>) -> String {
    let name = widget.into_inner().name;
    match filters.upper {
        Some(true) => name.to_uppercase(),
        _ => name,
    }
}

/// Whatever else the handler wants off the query string. Nothing to do
/// with the key.
#[derive(serde::Deserialize, doxa::IntoParams)]
struct Filters {
    upper: Option<bool>,
}

/// A segment spelled differently from the column, which is what the
/// annotation is left for.
#[get("/aliases/{slug}", tag = "Widgets")]
async fn get_alias(#[key("slug")] widget: Granted<Widget>) -> String {
    widget.into_inner().name
}

// ---- policy stub ------------------------------------------------------------

struct RegionChecker;

#[async_trait]
impl CapabilityChecker for RegionChecker {
    async fn check(&self, _: &str, roles: &[String], _: &Capability) -> Result<bool, AuthError> {
        Ok(roles.iter().any(|r| r == "viewer"))
    }

    async fn check_instance(
        &self,
        _: &str,
        _: &[String],
        _: &str,
        resource: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        Ok(resource.attrs.get("region") == Some(&json!("us")))
    }
}

fn app() -> axum::Router {
    OpenApiRouter::<()>::new()
        .routes(routes!(get_widget))
        .routes(routes!(find_widget))
        .routes(routes!(get_alias))
        .split_for_parts()
        .0
        .layer(axum::middleware::from_fn(
            |mut request: Request<Body>, next: axum::middleware::Next| async move {
                request.extensions_mut().insert(CapabilityContext {
                    tenant_id: Some("acme".into()),
                    roles: vec!["viewer".into()],
                });
                let checker: Arc<dyn CapabilityChecker> = Arc::new(RegionChecker);
                request.extensions_mut().insert(checker);
                next.run(request).await
            },
        ))
}

async fn call(uri: &str) -> (StatusCode, String) {
    let response = app()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .expect("request");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, String::from_utf8(body.to_vec()).expect("utf-8"))
}

fn api() -> utoipa::openapi::OpenApi {
    let (_router, api) = OpenApiRouter::<()>::new()
        .routes(routes!(get_widget))
        .routes(routes!(find_widget))
        .routes(routes!(get_alias))
        .split_for_parts();
    api
}

fn params(api: &utoipa::openapi::OpenApi, path: &str) -> Vec<utoipa::openapi::path::Parameter> {
    api.paths
        .paths
        .get(path)
        .unwrap_or_else(|| panic!("{path} is routed"))
        .get
        .clone()
        .unwrap_or_else(|| panic!("{path} has a GET"))
        .parameters
        .unwrap_or_default()
}

// ---- the asset's key names answer -------------------------------------------

/// The whole point: two path parameters, no annotation, and the right one
/// binds. The body is the loaded widget's name, so a route that bound
/// `{fid}` instead would 404 rather than quietly pass.
#[tokio::test]
async fn a_multi_parameter_route_binds_the_segment_the_asset_names() {
    assert_eq!(
        call("/folders/f1/widgets/alpha").await,
        (StatusCode::OK, "alpha".into())
    );
}

/// And it is genuinely reading `{name}` rather than taking the last
/// segment: `{fid}` is a name the asset does not know, so binding it would
/// answer 404 with the segments swapped.
#[tokio::test]
async fn the_other_segment_is_not_what_binds() {
    let (status, _) = call("/folders/alpha/widgets/nope").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "`alpha` is in the route, but not in the segment the key names",
    );
}

/// The annotation still wins, for the route whose parameter is spelled
/// differently from the column behind it.
#[tokio::test]
async fn an_annotation_overrides_the_assets_names() {
    assert_eq!(call("/aliases/beta").await, (StatusCode::OK, "beta".into()));
}

// ---- and the source says where to look --------------------------------------

#[tokio::test]
async fn a_query_source_reads_the_key_out_of_the_query_string() {
    assert_eq!(
        call("/widgets?name=alpha").await,
        (StatusCode::OK, "alpha".into())
    );
}

/// Percent-encoding is decoded before the lookup sees it, which is the
/// reason to reach for a query key in the first place — a name a path
/// segment cannot hold.
#[tokio::test]
async fn a_query_key_is_percent_decoded() {
    let (status, _) = call("/widgets?name=al%70ha").await;
    assert_eq!(status, StatusCode::OK, "`%70` is `p`");
}

/// The route said the caller supplies this, and the caller did not. That
/// is the same 400 an unparseable path segment gets — not a 500, which
/// would read as the service being misconfigured.
#[tokio::test]
async fn a_missing_query_key_is_a_bad_request() {
    let (status, _) = call("/widgets").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Other parameters do not stand in for it: the name is matched, not the
/// position.
#[tokio::test]
async fn an_unrelated_query_parameter_does_not_supply_the_key() {
    let (status, _) = call("/widgets?other=alpha").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---- the spec describes the request the guard actually parses ---------------

#[tokio::test]
async fn a_path_key_is_documented_in_the_path() {
    let params = params(&api(), "/folders/{fid}/widgets/{name}");

    assert_eq!(params.len(), 1, "only the key, not every segment");
    assert_eq!(params[0].name, "name");
    assert_eq!(
        serde_json::to_value(&params[0].parameter_in).unwrap(),
        json!("path"),
    );
}

/// The half that would otherwise drift. `Granted<Widget, Query>` reads
/// `?name=`, so the spec says `in: query` — off the same `KeySource::IN`
/// the guard read.
#[tokio::test]
async fn a_query_key_is_documented_in_the_query() {
    let params = params(&api(), "/widgets");
    let key = params
        .iter()
        .find(|p| p.name == "name")
        .expect("the key is declared");

    assert_eq!(
        serde_json::to_value(&key.parameter_in).unwrap(),
        json!("query"),
    );
    assert_eq!(
        serde_json::to_value(&key.required).unwrap(),
        json!(true),
        "the route identifies one object, so its key is not optional",
    );
    // The handler's own query parameter is described alongside it rather
    // than displaced by it: the key is one contribution among several.
    assert!(
        params.iter().any(|p| p.name == "upper"),
        "{:?}",
        params.iter().map(|p| &p.name).collect::<Vec<_>>(),
    );
}

/// An annotated segment documents the name the route uses, not the
/// column's — the resolution is one answer, and the spec gets that one.
#[tokio::test]
async fn an_overridden_name_is_the_one_documented() {
    let params = params(&api(), "/aliases/{slug}");

    assert_eq!(params.len(), 1);
    assert_eq!(params[0].name, "slug");
}
