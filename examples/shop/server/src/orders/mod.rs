//! Where orders live, and the services that serve them.

mod private;
mod public;

pub use private::OrdersPrivate;
pub use public::OrdersPublic;

use std::convert::Infallible;
use std::sync::{Arc, RwLock};

use doxa::auth::{CapabilityContext, FromState, GrantProfile};
use doxa::policy::{Fetch, FetchByKey, FetchSubset};
use doxa::{asset, PolicyResource};

use shop_api::orders::{Order, OrderAction, OrderError, OrderKey};

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
    profile = OrderGrants,
    actions = OrderAction,
    list = tenant,
    entity = shop_api::orders::Order
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

/// How order guards find the caller and the store.
pub struct OrderGrants;

impl GrantProfile for OrderGrants {
    type Ctx = CapabilityContext;
    type State = Store;
    type Source = FromState<Store>;
    type Error = Infallible;
}
