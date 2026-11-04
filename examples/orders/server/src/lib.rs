//! The orders server: the routes `orders-api` declares, served.

use std::convert::Infallible;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use axum::extract::{FromRef, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::{Json, Router};
use futures::stream::{self, Stream};

use doxa::auth::{CapabilityContext, FromState, GrantProfile, Granted, Many};
use doxa::policy::{
    AuthError, Capability, CapabilityChecker, Fetch, FetchByKey, FetchSubset, ResourceEntity,
};
use doxa::{asset, implements, routes, Actions, OpenApiRouter, PolicyResource, SseStream, Valid};

use orders_api::{NewOrder, Order, OrderError, OrderEvent, OrderFilter, OrderKey};

doxa::serves!(orders_api; doc = api_doc);

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

#[derive(Debug, Clone, Copy, Actions)]
#[actions(resource = "Order", prefix = "orders")]
pub enum OrderAction {
    /// View orders.
    #[action(verb = get)]
    Read,
    /// Cancel orders.
    #[action(verb = delete)]
    Cancel,
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

impl From<Gone> for Fail<OrderError> {
    fn from(Gone(id): Gone) -> Self {
        Fail(OrderError::NotFound(id))
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

#[implements(orders_api::get_order)]
async fn get_order(order: Granted<OrderById>) -> Result<Json<Order>, OrderError> {
    Ok(Json(order.into_inner().into()))
}

#[implements(orders_api::cancel_order)]
async fn cancel_order(
    order: Granted<OrderById>,
    State(store): State<Store>,
) -> Result<StatusCode, Fail<OrderError>> {
    store.remove(order.id)?;
    Ok(StatusCode::NO_CONTENT)
}

#[implements(orders_api::list_orders)]
async fn list_orders(
    _scope: Granted<Many<OrderById>>,
    State(store): State<Store>,
    Query(filter): Query<OrderFilter>,
) -> Json<Vec<Order>> {
    let orders = store.0.read().unwrap();
    Json(
        orders
            .iter()
            .filter(|o| filter.item.as_ref().is_none_or(|i| &o.item == i))
            .cloned()
            .map(Order::from)
            .collect(),
    )
}

#[implements(orders_api::place_order)]
async fn place_order(
    State(store): State<Store>,
    Valid(Json(new)): Valid<Json<NewOrder>>,
) -> Result<Json<Order>, OrderError> {
    if new.item == "unobtainium" {
        return Err(OrderError::OutOfStock(new.item));
    }
    let mut orders = store.0.write().unwrap();
    let id = orders.iter().map(|o| o.id).max().unwrap_or(0) + 1;
    let row = OrderRow {
        id,
        item: new.item,
        quantity: new.quantity,
    };
    orders.push(row.clone());
    Ok(Json(row.into()))
}

#[implements(orders_api::order_events)]
async fn order_events() -> SseStream<OrderEvent, impl Stream<Item = Result<OrderEvent, Infallible>>>
{
    SseStream::new(stream::iter([
        Ok(OrderEvent::Placed { id: 1 }),
        Ok(OrderEvent::Cancelled { id: 1 }),
    ]))
}

#[derive(Clone)]
struct AppState {
    store: Store,
}

impl FromRef<AppState> for Store {
    fn from_ref(state: &AppState) -> Self {
        state.store.clone()
    }
}

/// `viewer` may read; `clerk` may also cancel.
struct RoleChecker;

#[async_trait]
impl CapabilityChecker for RoleChecker {
    async fn check(&self, _: &str, roles: &[String], cap: &Capability) -> Result<bool, AuthError> {
        let clerk = roles.iter().any(|r| r == "clerk");
        Ok(match cap.name {
            "orders.cancel" => clerk,
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

fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::<AppState>::new()
        .routes(routes!(get_order, cancel_order))
        .routes(routes!(list_orders, place_order))
        .routes(routes!(order_events))
}

/// The orders API's OpenAPI document.
#[doxa::spec]
pub fn api_doc() -> doxa::ApiDoc {
    let (_, api) = routes().split_for_parts();
    doxa::ApiDocBuilder::new()
        .title("Orders")
        .version("0.0.0")
        .bearer_security("bearer")
        .merge(api)
        .build()
}

/// The app, with the caller's role read from `x-role` in place of a real token.
pub fn app(store: Store) -> Router {
    let (router, _api) = routes().split_for_parts();
    router
        .layer(axum::middleware::from_fn(
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
        .with_state(AppState { store })
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
