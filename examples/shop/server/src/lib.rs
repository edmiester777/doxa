//! The shop server: every route `shop-api` declares, implemented and guarded.

pub mod orders;
pub mod widgets;

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{FromRef, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::{Json, Router};

use doxa::auth::CapabilityContext;
use doxa::policy::{AuthError, Capability, CapabilityChecker, ResourceEntity};
use doxa::{implements, Routes};

use orders::{OrderRow, Store};
use widgets::{Catalog, WidgetRow};

/// The version route, and what the caller may do at `GET /doxa/capabilities`.
#[doxa::service(layers = caller)]
pub struct Shop;

/// Everything the routes read.
#[derive(Clone, doxa::State)]
pub struct ShopState {
    pub orders: Store,
    pub widgets: Catalog,
}

impl FromRef<ShopState> for Store {
    fn from_ref(state: &ShopState) -> Self {
        state.orders.clone()
    }
}

impl FromRef<ShopState> for Catalog {
    fn from_ref(state: &ShopState) -> Self {
        state.widgets.clone()
    }
}

#[implements(shop_api::version)]
async fn version() -> Json<String> {
    Json(env!("CARGO_PKG_VERSION").to_owned())
}

/// `viewer` reads; `editor` renames widgets; `clerk` places and cancels orders; `admin` does
/// anything.
struct RoleChecker;

#[async_trait]
impl CapabilityChecker for RoleChecker {
    async fn check(&self, _: &str, roles: &[String], cap: &Capability) -> Result<bool, AuthError> {
        let has = |r: &str| roles.iter().any(|x| x == r);
        if has("admin") {
            return Ok(true);
        }
        Ok(match cap.name {
            "orders.cancel" | "orders.place" => has("clerk"),
            "widgets.update" => has("editor"),
            _ => has("viewer") || has("editor") || has("clerk"),
        })
    }

    async fn check_instance(
        &self,
        _: &str,
        roles: &[String],
        action: &str,
        _: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        let has = |r: &str| roles.iter().any(|x| x == r);
        Ok(has("admin")
            || match action {
                "cancel" => has("clerk"),
                "update" => has("editor"),
                _ => true,
            })
    }
}

/// Who the caller is, read from `x-role` in place of a real token.
#[doxa::layers]
fn caller(routes: Routes, _: &ShopState) -> Routes {
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
fn signed_in(routes: Routes, state: &ShopState) -> Routes {
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

/// The shop's OpenAPI document.
#[doxa::spec]
pub fn api_doc() -> doxa::ApiDoc {
    doxa::ApiDocBuilder::new()
        .title("Shop")
        .version("0.0.0")
        .bearer_security("bearer")
        .merge(doxa::spec())
        .build()
}

/// The app over `state`.
pub fn app(state: ShopState) -> Router {
    let (router, _api) = doxa::app(&state).split_for_parts();
    router.layer(doxa::ETagLayer)
}

/// Three widgets and two orders to start with.
pub fn seeded() -> ShopState {
    let widget = |id, name: &str| WidgetRow {
        id,
        name: name.into(),
    };
    let order = |id, item: &str, quantity| OrderRow {
        id,
        item: item.into(),
        quantity,
    };
    ShopState {
        widgets: Catalog::new(vec![
            widget(1, "sprocket"),
            widget(2, "gear"),
            widget(3, "cog"),
        ]),
        orders: Store::new(vec![order(1, "sprocket", 2), order(2, "gear", 5)]),
    }
}

/// A handler's own error converts into the declared one:
///
/// ```
/// # #[derive(Clone, doxa::State)] struct NoState;
/// struct Lost;
/// impl From<Lost> for shop_api::orders::OrderError {
///     fn from(_: Lost) -> Self { shop_api::orders::OrderError::NotFound(0) }
/// }
/// #[doxa::implements(shop_api::orders::cancel_order, mount = false)]
/// async fn cancel(_: doxa::auth::Granted<shop_server::orders::OrderById>) -> Result<axum::http::StatusCode, Lost> {
///     Err(Lost)
/// }
/// ```
///
/// One that doesn't is "the trait bound `OrderError: From<Lost>` is not satisfied":
///
/// ```compile_fail
/// # #[derive(Clone, doxa::State)] struct NoState;
/// struct Lost;
/// #[doxa::implements(shop_api::orders::cancel_order, mount = false)]
/// async fn cancel(_: doxa::auth::Granted<shop_server::orders::OrderById>) -> Result<axum::http::StatusCode, Lost> {
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
/// use shop_server::orders::OrderById;
/// #[doxa::implements(shop_api::orders::get_order, mount = false)]
/// async fn get(order: Granted<OrderById>) -> Result<axum::Json<shop_api::orders::Order>, shop_api::orders::OrderError> {
///     unimplemented!()
/// }
/// ```
///
/// A list guard the declaration doesn't state is "`get` guards a list of `OrderById`, which
/// `shop_api::orders::get_order` doesn't declare":
///
/// ```compile_fail
/// # #[derive(Clone, doxa::State)] struct NoState;
/// use doxa::auth::{Granted, Many};
/// use shop_server::orders::OrderById;
/// #[doxa::implements(shop_api::orders::get_order, mount = false)]
/// async fn get(_: Granted<Many<OrderById>>, order: Granted<OrderById>) -> Result<axum::Json<shop_api::orders::Order>, shop_api::orders::OrderError> {
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
/// use shop_api::orders::{order_action, NewOrder, Order, OrderError};
/// #[doxa::implements(shop_api::orders::place_order, mount = false)]
/// async fn place(_: Granted<Cap<order_action::Place>>, _: doxa::Valid<axum::Json<NewOrder>>) -> Result<axum::Json<Order>, OrderError> {
///     unimplemented!()
/// }
/// ```
///
/// Another one is "`place` and `shop_api::orders::place_order` guard different capabilities":
///
/// ```compile_fail
/// # #[derive(Clone, doxa::State)] struct NoState;
/// use doxa::auth::{Cap, Granted};
/// use shop_api::orders::{order_action, NewOrder, Order, OrderError};
/// #[doxa::implements(shop_api::orders::place_order, mount = false)]
/// async fn place(_: Granted<Cap<order_action::Cancel>>, _: doxa::Valid<axum::Json<NewOrder>>) -> Result<axum::Json<Order>, OrderError> {
///     unimplemented!()
/// }
/// ```
#[doc(hidden)]
pub mod capability_diagnostics {}

/// A handler's answer is its declaration's by type, whatever it's imported as:
///
/// ```
/// # #[derive(Clone, doxa::State)] struct NoState;
/// use doxa::SseStream as Events;
/// use futures::stream::{self, Stream};
/// use shop_api::orders::OrderEvent;
/// #[doxa::implements(shop_api::orders::order_events, mount = false)]
/// async fn events() -> Events<OrderEvent, impl Stream<Item = Result<OrderEvent, std::convert::Infallible>>> {
///     Events::new(stream::empty())
/// }
/// ```
///
/// Another answer is "the handler answers `doxa::client::Json<u32>`, and the declaration
/// `doxa::client::SseStream<OrderEvent>`":
///
/// ```compile_fail
/// # #[derive(Clone, doxa::State)] struct NoState;
/// use axum::Json as Body;
/// #[doxa::implements(shop_api::orders::order_events, mount = false)]
/// async fn events() -> Body<u32> {
///     Body(0)
/// }
/// ```
#[doc(hidden)]
pub mod answer_diagnostics {}
