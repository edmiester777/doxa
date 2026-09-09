//! Where a route's key comes from, and what it is called.
//!
//! Two facts used to be written at every call site. What the parameter is
//! *called* is now the key type's to say: its fields are the route's
//! parameters, and `Granting::KEY_NAMES` repeats that list for the spec.
//! So no route names its own segment, and a rename happens once, on the
//! key. Where the parameter *lives* is `#[key(with = "…")]` — the path by
//! default, the query string when the route says so.
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

// The *axum* `Query`, which is what a handler reading its own query string
// imports. It sits beside a key that also comes out of the query string
// without the two having anything to do with each other, since the guard's
// source is a string on the annotation rather than a type in scope.
use axum::extract::Query;
use doxa::auth::{CapabilityContext, FromState, Granted, Granting};
use doxa::policy::{
    AuthError, Capability, CapabilityCheck, CapabilityChecker, ResourceEntity, ResourceId,
};
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
    /// The key every route below binds, and the reason none of them
    /// repeats its name: the field is called `name`, so `{name}` and
    /// `?name=` both find it.
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
    /// The same column reached under another name. The rename lives here,
    /// on the key, rather than on each route that uses it — so a segment
    /// spelled `{slug}` and a spec saying `slug` come from one place.
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

// ---- the key's field names answer -------------------------------------------

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

/// A route whose segment is spelled differently from the column behind
/// it. Nothing on the route says so: the key's field is `slug`, so
/// `{slug}` is what binds.
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

/// The half that would otherwise drift. `#[key(with = "Query")]` reads
/// `?name=`, so the spec says `in: query` — off the same `GrantSite::IN`
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

/// A renamed key documents the name the route uses, not the column's —
/// the key's fields are the one answer, and the spec gets that one.
#[tokio::test]
async fn a_renamed_key_is_documented_under_its_own_name() {
    let params = params(&api(), "/aliases/{slug}");

    assert_eq!(params.len(), 1);
    assert_eq!(params[0].name, "slug");
}
