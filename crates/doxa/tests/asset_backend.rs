//! `#[asset]` over a backend that is not a database.
//!
//! The attribute used to write its loader from `ScopedRow` and its listing
//! from `ScopedTable`, both SeaORM traits, so a row living anywhere else
//! got one of two things: a `load_with` function and a hand-written
//! `Scoping`, or nothing. This file is the same declarations over an
//! in-memory catalog, and the point is that they are the *same*
//! declarations — `profile`, `actions`, `list = tenant`, and no loader.
//!
//! What that buys is not brevity. A hand-written loader takes the caller
//! context and is free to ignore it, and one that does compiles, passes
//! its tests, and serves one tenant's rows to another. The generated one
//! reads the tenant and confines the fetch to it, and there is no way to
//! ask for it not to. Everything below that looks like a routing test is
//! really a test of that.
//!
//! Nothing here names SeaORM, and the file builds with `policy-sea-orm`
//! off.

#![cfg(all(feature = "auth", feature = "macros", feature = "policy"))]

use std::convert::Infallible;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::FromRef;
use axum::http::{Request, StatusCode};
use axum::Extension;
use serde::Serialize;
use tower::ServiceExt;

use doxa::auth::{CapabilityContext, FromState, GrantProfile, Granted, Many, One, Scoped};
use doxa::policy::{
    AuthError, Capability, CapabilityChecker, Fetch, FetchByKey, FetchSubset, ResourceEntity,
};
use doxa::{asset, get, routes, Actions, OpenApiRouter, PolicyResource, ToSchema};

// ---- the row ----------------------------------------------------------------

/// No `#[resource(key)]`, no `#[resource(scope)]` — those are the SeaORM
/// roles, and this row has no table. Cedar identity is all the derive is
/// asked for; the lookups are the impls below.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema, PolicyResource)]
#[resource(entity_type = "Widget")]
pub struct Widget {
    #[resource(id, attr)]
    pub name: String,
    pub tenant: String,
}

#[derive(Debug, Clone, Copy, Actions)]
#[actions(resource = "Widget", prefix = "widgets")]
pub enum WidgetAction {
    /// List and view widgets.
    Read,
}

// ---- the backend ------------------------------------------------------------

/// Rows in a map rather than a table. Cloned freely; the point is that it
/// is not a `ConnectionTrait` and nothing here wishes it were.
#[derive(Clone)]
pub struct Catalog(Arc<Vec<Widget>>);

impl Catalog {
    fn seeded() -> Self {
        Catalog(Arc::new(vec![
            Widget {
                name: "alpha".into(),
                tenant: "acme".into(),
            },
            // Same name, different owner. The row a tenant-confined fetch
            // must not reach, and the one an unconfined fetch returns
            // first if the vector is scanned in order.
            Widget {
                name: "alpha".into(),
                tenant: "globex".into(),
            },
            Widget {
                name: "beta".into(),
                tenant: "globex".into(),
            },
        ]))
    }
}

impl Fetch<Catalog> for Widget {
    type Error = Infallible;
}

impl FetchByKey<Catalog> for Widget {
    type Key = String;

    async fn fetch(key: String, src: &Catalog, scope: &str) -> Result<Option<Self>, Infallible> {
        Ok(src
            .0
            .iter()
            .find(|widget| widget.name == key && widget.tenant == scope)
            .cloned())
    }
}

/// A subset is a description of rows, not the rows: the handler applies it
/// to whatever it is holding at the time. Here that is a tenant name,
/// which is all this backend needs to say "these ones".
impl FetchSubset for Widget {
    type Filter = String;

    fn subset(scope: &str) -> String {
        scope.to_owned()
    }
}

// ---- the same declarations as a SeaORM service would write -------------------

pub struct AppGrants;

impl GrantProfile for AppGrants {
    type Ctx = CapabilityContext;
    type State = Catalog;
    type Source = FromState<Catalog>;
    type Error = Infallible;
}

/// The whole declaration, and not one word of it is about where the row
/// lives.
#[asset(row = Widget, profile = AppGrants, actions = WidgetAction, list = tenant)]
pub struct WidgetByName;

// ---- a request-scoped source ------------------------------------------------

/// A handle that exists for the duration of one request — the shape of an
/// open transaction, which is the case a `FromRef` state cannot serve: a
/// pool does not see rows the request has written and not committed.
#[derive(Clone)]
pub struct Snapshot(Catalog);

impl Fetch<Snapshot> for Widget {
    type Error = Infallible;
}

impl FetchByKey<Snapshot> for Widget {
    type Key = String;

    async fn fetch(key: String, src: &Snapshot, scope: &str) -> Result<Option<Self>, Infallible> {
        <Widget as FetchByKey<Catalog>>::fetch(key, &src.0, scope).await
    }
}

/// The same row, reached through an extractor instead of the router state.
/// `source` is the only line that differs, and the state follows it.
#[asset(
    row = Widget,
    profile = AppGrants,
    actions = WidgetAction,
    source = Extension<Snapshot>
)]
pub struct WidgetFromSnapshot;

// ---- routes -----------------------------------------------------------------

#[get("/widgets/{name}", tag = "Widgets")]
async fn get_widget(widget: Granted<One<WidgetByName>>) -> String {
    format!("{}@{}", widget.name, widget.tenant)
}

#[get("/widgets", tag = "Widgets")]
async fn list_widgets(
    Granted(_, scope, _): Granted<Many<WidgetByName>>,
    axum::extract::State(catalog): axum::extract::State<Catalog>,
) -> String {
    let mut names: Vec<_> = catalog
        .0
        .iter()
        .filter(|widget| widget.tenant == scope)
        .map(|widget| widget.name.as_str())
        .collect();
    names.sort_unstable();
    names.join(",")
}

#[get("/snapshot/{name}", tag = "Widgets")]
async fn get_from_snapshot(widget: Granted<One<WidgetFromSnapshot>>) -> String {
    format!("{}@{}", widget.name, widget.tenant)
}

/// `Scoped` alongside the generated `Scoping`, so the dependency door
/// reaches the same subset the collection guard would.
#[get("/visible", tag = "Widgets")]
async fn visible(scope: Scoped<WidgetByName, widget_action::Read>) -> String {
    scope.into_inner()
}

// ---- harness ----------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    catalog: Catalog,
}

impl FromRef<AppState> for Catalog {
    fn from_ref(state: &AppState) -> Self {
        state.catalog.clone()
    }
}

struct AllowAll;

#[async_trait]
impl CapabilityChecker for AllowAll {
    async fn check(&self, _: &str, _: &[String], _: &Capability) -> Result<bool, AuthError> {
        Ok(true)
    }

    async fn check_instance(
        &self,
        _: &str,
        _: &[String],
        _: &str,
        _: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        Ok(true)
    }
}

/// `tenant` is an `Option` so the no-tenant case is reachable: a caller
/// the layer resolved without one is not a caller with an empty one.
async fn call(uri: &str, tenant: Option<&str>) -> (StatusCode, String) {
    let tenant = tenant.map(str::to_owned);
    let catalog = Catalog::seeded();
    let snapshot = Snapshot(catalog.clone());

    let app = OpenApiRouter::<AppState>::new()
        .routes(routes!(get_widget))
        .routes(routes!(list_widgets))
        .routes(routes!(get_from_snapshot))
        .routes(routes!(visible))
        .split_for_parts()
        .0
        .layer(axum::middleware::from_fn(
            move |mut request: Request<Body>, next: axum::middleware::Next| {
                let tenant = tenant.clone();
                let snapshot = snapshot.clone();
                async move {
                    request.extensions_mut().insert(CapabilityContext {
                        tenant_id: tenant,
                        roles: vec!["viewer".into()],
                    });
                    let checker: Arc<dyn CapabilityChecker> = Arc::new(AllowAll);
                    request.extensions_mut().insert(checker);
                    // The request-scoped handle `WidgetFromSnapshot` reads.
                    request.extensions_mut().insert(snapshot);
                    next.run(request).await
                }
            },
        ))
        .with_state(AppState { catalog });

    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .expect("request");

    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

// ---- the loader the attribute wrote -----------------------------------------

/// The baseline: a generated loader over a backend with no ORM behind it
/// reaches the row.
#[tokio::test]
async fn a_generated_loader_reaches_a_row_that_is_not_in_a_database() {
    let (status, body) = call("/widgets/alpha", Some("acme")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "alpha@acme");
}

/// The property the whole design is for. `alpha` exists in `globex` too,
/// and is the row a lookup that forgot its scope would return — the
/// catalog is scanned in order and `acme`'s copy is first, so this passes
/// for the wrong reason unless the caller is the *second* tenant.
#[tokio::test]
async fn a_key_owned_by_another_tenant_is_absent_rather_than_refused() {
    let (status, body) = call("/widgets/beta", Some("acme")).await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "`beta` is globex's; acme must not be able to tell it exists",
    );
    assert!(!body.contains("globex"), "{body}");
}

/// The same key resolving to a different row per caller, which is what
/// says the scope reached the fetch rather than being checked afterwards.
#[tokio::test]
async fn one_key_resolves_per_tenant() {
    let (_, acme) = call("/widgets/alpha", Some("acme")).await;
    let (_, globex) = call("/widgets/alpha", Some("globex")).await;

    assert_eq!(acme, "alpha@acme");
    assert_eq!(globex, "alpha@globex");
}

/// A caller with no tenant has no scope to be confined to, so the answer
/// is that nothing is there — not a fetch against the empty string, which
/// would match whatever a misconfigured seed put under it.
#[tokio::test]
async fn no_tenant_is_no_row() {
    let (status, _) = call("/widgets/alpha", None).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---- and the listing --------------------------------------------------------

/// `list = tenant` over a `FetchSubset` that is not a `Select`.
#[tokio::test]
async fn a_generated_listing_is_confined_to_the_tenant() {
    let (status, body) = call("/widgets", Some("globex")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "alpha,beta", "globex's two rows and not acme's");
}

/// No tenant, no scope — and `Scoping::empty_scope` defaults to refusing
/// rather than answering with an empty page, so a misconfigured caller is
/// visible instead of looking like an empty catalog.
#[tokio::test]
async fn a_listing_without_a_tenant_is_refused() {
    let (status, _) = call("/widgets", None).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// The dependency door reads the same generated `Scoping`.
#[tokio::test]
async fn the_scoped_extractor_reaches_the_generated_subset() {
    let (status, body) = call("/visible", Some("acme")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "acme");
}

// ---- and the request-scoped source ------------------------------------------

/// `source = Extension<Snapshot>` hands the loader a handle the *request*
/// owns. Before this, `Granting::State` was reached through `FromRef`, so
/// the only thing a loader could be given was a slice of the router state
/// — and a lookup that had to run inside the request's open transaction
/// could not be expressed at all.
#[tokio::test]
async fn a_loader_can_be_handed_a_request_scoped_source() {
    let (status, body) = call("/snapshot/alpha", Some("acme")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "alpha@acme");
}

/// And it is the same generated loader, so it is confined the same way.
#[tokio::test]
async fn a_request_scoped_source_is_confined_like_any_other() {
    let (status, _) = call("/snapshot/beta", Some("acme")).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---- what the declarations say ----------------------------------------------

/// The source override moves the state with it, so this asset's loader is
/// handed a `Snapshot` while the rest of the application keeps `Catalog`.
///
/// Worth asserting rather than leaving to the loader tests above: the two
/// could be set apart, and an asset whose `State` no `Source` produces is
/// a mismatch stated in two places instead of one.
#[test]
fn a_source_override_carries_the_state_with_it() {
    fn same<A, B>()
    where
        A: 'static,
        B: 'static,
    {
        assert_eq!(
            std::any::TypeId::of::<A>(),
            std::any::TypeId::of::<B>(),
            "{} is not {}",
            std::any::type_name::<A>(),
            std::any::type_name::<B>(),
        );
    }

    same::<<WidgetByName as doxa::auth::Granting>::State, Catalog>();
    same::<<WidgetFromSnapshot as doxa::auth::Granting>::State, Snapshot>();
}
