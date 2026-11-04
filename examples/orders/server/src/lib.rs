//! The orders server: the routes `orders-api` declares, served by two services.

mod private;
mod public;

/// What the caller may do, at `GET /doxa/capabilities`.
#[doxa::service(layers = caller)]
pub struct Orders;

pub use private::OrdersPrivate;
pub use public::OrdersPublic;

use std::convert::Infallible;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use axum::extract::{FromRef, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Router;

use doxa::auth::{CapabilityContext, FromState, GrantProfile};
use doxa::policy::{
    AuthError, Capability, CapabilityChecker, Fetch, FetchByKey, FetchSubset, ResourceEntity,
};
use doxa::{asset, PolicyResource, Routes};

use orders_api::{Order, OrderAction, OrderError, OrderKey};

/// An order as the server stores it.
#[derive(Debug, Clone, serde::Serialize, PolicyResource)]
#[resource(entity_type = "Order")]
pub struct OrderRow {
    #[resource(id)]
    pub id: u32,
    #[resource(attr)]
    pub item: String,
    pub quantity: u32,
}

impl From<OrderRow> for Order {
    fn from(row: OrderRow) -> Self {
        Order {
            id: row.id,
            item: row.item,
            quantity: row.quantity,
        }
    }
}

#[asset(
    row = OrderRow,
    key = OrderKey,
    profile = AppGrants,
    actions = OrderAction,
    list = tenant,
    entity = orders_api::Order
)]
pub struct OrderById;

/// Orders in memory.
#[derive(Clone, Default)]
pub struct Store(Arc<RwLock<Vec<OrderRow>>>);

/// A store that has lost an order it was asked for.
pub struct Gone(u32);

impl From<Gone> for OrderError {
    fn from(Gone(id): Gone) -> Self {
        OrderError::NotFound(id)
    }
}

impl Store {
    /// A store holding `orders`.
    pub fn new(orders: Vec<OrderRow>) -> Self {
        Self(Arc::new(RwLock::new(orders)))
    }

    fn remove(&self, id: u32) -> Result<(), Gone> {
        let mut orders = self.0.write().unwrap();
        let at = orders.iter().position(|o| o.id == id).ok_or(Gone(id))?;
        orders.remove(at);
        Ok(())
    }
}

impl Fetch<Store> for OrderRow {
    type Error = Infallible;
}

impl FetchByKey<Store> for OrderRow {
    type Key = OrderKey;

    async fn fetch(key: OrderKey, src: &Store, _scope: &str) -> Result<Option<Self>, Infallible> {
        Ok(src
            .0
            .read()
            .unwrap()
            .iter()
            .find(|o| o.id == key.id)
            .cloned())
    }
}

impl FetchSubset for OrderRow {
    type Filter = String;

    fn subset(scope: &str) -> String {
        scope.to_owned()
    }
}

/// How this app's guards find the caller and the store.
pub struct AppGrants;

impl GrantProfile for AppGrants {
    type Ctx = CapabilityContext;
    type State = Store;
    type Source = FromState<Store>;
    type Error = Infallible;
}

#[derive(Clone, doxa::State)]
struct AppState {
    store: Store,
}

impl FromRef<AppState> for Store {
    fn from_ref(state: &AppState) -> Self {
        state.store.clone()
    }
}

/// `viewer` may read; `clerk` may also cancel and place; `admin` may do anything.
struct RoleChecker;

#[async_trait]
impl CapabilityChecker for RoleChecker {
    async fn check(&self, _: &str, roles: &[String], cap: &Capability) -> Result<bool, AuthError> {
        if roles.iter().any(|r| r == "admin") {
            return Ok(true);
        }
        let clerk = roles.iter().any(|r| r == "clerk");
        Ok(match cap.name {
            "orders.cancel" | "orders.place" => clerk,
            _ => clerk || roles.iter().any(|r| r == "viewer"),
        })
    }

    async fn check_instance(
        &self,
        _: &str,
        roles: &[String],
        action: &str,
        _: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        Ok(action != "cancel" || roles.iter().any(|r| r == "clerk"))
    }
}

/// Who the caller is, read from `x-role` in place of a real token.
#[doxa::layers]
fn caller(routes: Routes, _: &AppState) -> Routes {
    routes.layer(axum::middleware::from_fn(
        |mut req: Request, next: Next| async move {
            let role = req
                .headers()
                .get("x-role")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            if let Some(role) = role {
                req.extensions_mut().insert(CapabilityContext {
                    tenant_id: Some("acme".into()),
                    roles: vec![role],
                });
            }
            let checker: Arc<dyn CapabilityChecker> = Arc::new(RoleChecker);
            req.extensions_mut().insert(checker);
            next.run(req).await
        },
    ))
}

/// [`caller`], and `401` without a role.
#[doxa::layers(docs = [caller, doxa::auth::AuthDocs])]
fn signed_in(routes: Routes, state: &AppState) -> Routes {
    let routes = routes.layer(axum::middleware::from_fn(
        |req: Request, next: Next| async move {
            if req.extensions().get::<CapabilityContext>().is_none() {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            next.run(req).await
        },
    ));
    caller(routes, state)
}

/// The orders API's OpenAPI document.
#[doxa::spec]
pub fn api_doc() -> doxa::ApiDoc {
    doxa::ApiDocBuilder::new()
        .title("Orders")
        .version("0.0.0")
        .bearer_security("bearer")
        .merge(doxa::spec())
        .build()
}

/// The app over `store`.
pub fn app(store: Store) -> Router {
    let (router, _api) = doxa::app(&AppState { store }).split_for_parts();
    router
}

/// Two orders to start with.
pub fn seeded() -> Store {
    Store::new(vec![
        OrderRow {
            id: 1,
            item: "sprocket".into(),
            quantity: 2,
        },
        OrderRow {
            id: 2,
            item: "gear".into(),
            quantity: 5,
        },
    ])
}

/// A handler's own error converts into the declared one:
///
/// ```
/// # #[derive(Clone, doxa::State)] struct NoState;
/// struct Lost;
/// impl From<Lost> for orders_api::OrderError {
///     fn from(_: Lost) -> Self { orders_api::OrderError::NotFound(0) }
/// }
/// #[doxa::implements(orders_api::cancel_order, mount = false)]
/// async fn cancel(_: doxa::auth::Granted<orders_server::OrderById>) -> Result<axum::http::StatusCode, Lost> {
///     Err(Lost)
/// }
/// ```
///
/// One that doesn't is "the trait bound `OrderError: From<Lost>` is not satisfied":
///
/// ```compile_fail
/// # #[derive(Clone, doxa::State)] struct NoState;
/// struct Lost;
/// #[doxa::implements(orders_api::cancel_order, mount = false)]
/// async fn cancel(_: doxa::auth::Granted<orders_server::OrderById>) -> Result<axum::http::StatusCode, Lost> {
///     Err(Lost)
/// }
/// ```
#[doc(hidden)]
pub mod error_diagnostics {}

/// A handler's guards are its declaration's:
///
/// ```
/// # #[derive(Clone, doxa::State)] struct NoState;
/// use doxa::auth::{Granted, Many};
/// use orders_server::OrderById;
/// #[doxa::implements(orders_api::get_order, mount = false)]
/// async fn get(order: Granted<OrderById>) -> Result<axum::Json<orders_api::Order>, orders_api::OrderError> {
///     unimplemented!()
/// }
/// ```
///
/// A list guard the declaration doesn't state is "`get` guards a list of `OrderById`, which
/// `orders_api::get_order` doesn't declare":
///
/// ```compile_fail
/// # #[derive(Clone, doxa::State)] struct NoState;
/// use doxa::auth::{Granted, Many};
/// use orders_server::OrderById;
/// #[doxa::implements(orders_api::get_order, mount = false)]
/// async fn get(_: Granted<Many<OrderById>>, order: Granted<OrderById>) -> Result<axum::Json<orders_api::Order>, orders_api::OrderError> {
///     unimplemented!()
/// }
/// ```
#[doc(hidden)]
pub mod guard_diagnostics {}

/// A handler's capability is its declaration's:
///
/// ```
/// # #[derive(Clone, doxa::State)] struct NoState;
/// use doxa::auth::{Cap, Granted};
/// use orders_api::{order_action, NewOrder, Order, OrderError};
/// #[doxa::implements(orders_api::place_order, mount = false)]
/// async fn place(_: Granted<Cap<order_action::Place>>, _: doxa::Valid<axum::Json<NewOrder>>) -> Result<axum::Json<Order>, OrderError> {
///     unimplemented!()
/// }
/// ```
///
/// Another one is "`place` and `orders_api::place_order` guard different capabilities":
///
/// ```compile_fail
/// # #[derive(Clone, doxa::State)] struct NoState;
/// use doxa::auth::{Cap, Granted};
/// use orders_api::{order_action, NewOrder, Order, OrderError};
/// #[doxa::implements(orders_api::place_order, mount = false)]
/// async fn place(_: Granted<Cap<order_action::Cancel>>, _: doxa::Valid<axum::Json<NewOrder>>) -> Result<axum::Json<Order>, OrderError> {
///     unimplemented!()
/// }
/// ```
#[doc(hidden)]
pub mod capability_diagnostics {}
