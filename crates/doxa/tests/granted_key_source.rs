//! A route key's parameter names come from its fields, and its place from `#[key(with = "…")]`.
//! The guard and the OpenAPI description both read them, and these tests check they agree.

mod common;
use common::RegionChecker;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;

use tower::ServiceExt;

// axum's own `Query`: the guard's source is a string on the annotation, not a type in scope.
use axum::extract::Query;
use doxa::auth::{CapabilityContext, FromState, Granted, Granting};
use doxa::policy::{Capability, CapabilityCheck, CapabilityChecker, ResourceId};
use doxa::{get, routes, Actions, OpenApiRouter, PolicyResource, ToSchema};

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

doxa::auth::route_key!(
    /// The field is `name`, so `{name}` and `?name=` both find it.
    pub WidgetKey { name: String }
);

struct WidgetsRead;
impl doxa::policy::Capable for WidgetsRead {
    const CAPABILITY: &'static Capability = &WIDGETS_READ;
}

#[derive(Actions)]
#[actions(resource = "Widget")]
pub enum WidgetActions {
    #[action(verb = get, capable = WidgetsRead)]
    Read,
}

/// Keyed on `name`, and it says so. That one line is what lets every route
/// below bind `{name}` — or `?name=` — without naming it again.
impl Granting for Widget {
    type Row = Self;
    type Key = WidgetKey;
    type Ctx = CapabilityContext;
    type State = ();
    type Source = FromState<()>;
    type Error = StatusCode;

    type Actions = WidgetActions;

    const KEY_NAMES: &'static [&'static str] = &["name"];

    async fn load(
        WidgetKey { name }: WidgetKey,
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

/// Two path parameters and no annotation: `{name}` binds by the key's field.
#[get("/folders/{fid}/widgets/{name}", tag = "Widgets")]
async fn get_widget(widget: Granted<Widget>) -> String {
    widget.into_inner().name
}

/// The key in the query string, beside a real [`axum::extract::Query`] of the handler's own.
#[get("/widgets", tag = "Widgets")]
async fn find_widget(widget: Granted<Widget>, Query(filters): Query<Filters>) -> String {
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

doxa::auth::route_key!(
    /// The same column under another name, renamed once on the key.
    pub AliasKey { slug: String }
);

/// A second way into the same row, addressed by a segment spelled
/// differently from the column behind it.
struct WidgetByAlias;

impl Granting for WidgetByAlias {
    type Row = Widget;
    type Key = AliasKey;
    type Ctx = CapabilityContext;
    type State = ();
    type Source = FromState<()>;
    type Error = StatusCode;

    type Actions = WidgetActions;

    const KEY_NAMES: &'static [&'static str] = &["slug"];

    async fn load(
        AliasKey { slug }: AliasKey,
        state: &(),
        ctx: &CapabilityContext,
    ) -> Result<Option<Widget>, StatusCode> {
        <Widget as Granting>::load(WidgetKey { name: slug }, state, ctx).await
    }
}

#[get("/aliases/{slug}", tag = "Widgets")]
async fn get_alias(widget: Granted<WidgetByAlias>) -> String {
    widget.into_inner().name
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

// ---- the key's field names answer -------------------------------------------

/// The right one of two segments binds; binding `{fid}` would 404.
#[tokio::test]
async fn a_multi_parameter_route_binds_the_segment_the_asset_names() {
    assert_eq!(
        call("/folders/f1/widgets/alpha").await,
        (StatusCode::OK, "alpha".into())
    );
}

/// It reads `{name}`, not the last segment.
#[tokio::test]
async fn the_other_segment_is_not_what_binds() {
    let (status, _) = call("/folders/alpha/widgets/nope").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "`alpha` is in the route, but not in the segment the key names",
    );
}

/// The key's field is `slug`, so `{slug}` binds with nothing on the route.
#[tokio::test]
async fn a_renamed_key_binds_the_segment_its_field_names() {
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

/// A missing key is a 400, like an unparseable segment, not a 500.
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

/// The spec says `in: query`, off the same `GrantSite::IN` the guard read.
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

/// A renamed key documents the name the route uses, not the column's —
/// the key's fields are the one answer, and the spec gets that one.
#[tokio::test]
async fn a_renamed_key_is_documented_under_its_own_name() {
    let params = params(&api(), "/aliases/{slug}");

    assert_eq!(params.len(), 1);
    assert_eq!(params[0].name, "slug");
}

#[derive(Clone, doxa::State)]
struct NoState;

impl axum::extract::FromRef<NoState> for () {
    fn from_ref(_: &NoState) {}
}
