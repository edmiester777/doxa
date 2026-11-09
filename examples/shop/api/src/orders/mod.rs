//! Orders for widgets: reads anyone may make, and changes that need a role.

mod private;
mod public;

pub use private::*;
pub use public::*;

doxa::prelude!();

route_key!(pub OrderKey { id: u32 });

/// What a caller may do with orders.
#[derive(Debug, Clone, Copy, Actions)]
#[actions(resource = "Order", prefix = "orders")]
pub enum OrderAction {
    /// View orders.
    #[action(verb = get)]
    Read,
    /// Cancel orders.
    #[action(verb = delete)]
    Cancel,
    /// Place orders.
    #[action(verb = post)]
    Place,
}

/// An order.
#[dto]
#[entity(key = OrderKey, actions = OrderAction)]
pub struct Order {
    pub id: u32,
    pub item: String,
    pub quantity: u32,
}

/// A new order; the server and the client check the same rules.
#[dto]
#[derive(garde::Validate)]
pub struct NewOrder {
    #[garde(length(min = 1))]
    pub item: String,
    #[garde(range(min = 1))]
    pub quantity: u32,
}

/// Narrows a listing.
#[dto(query)]
#[derive(Default)]
pub struct OrderFilter {
    pub item: Option<String>,
}

/// What can go wrong with an order.
#[dto]
#[derive(thiserror::Error, ApiError)]
pub enum OrderError {
    #[error("no order {0}")]
    #[api(status = 404, code = "not_found")]
    NotFound(u32),
    #[error("out of {0}")]
    #[api(status = 409, code = "out_of_stock")]
    OutOfStock(String),
    #[error("{0}")]
    #[api(status = 500, internal)]
    Internal(String),
}

#[server]
impl From<std::num::TryFromIntError> for OrderError {
    fn from(e: std::num::TryFromIntError) -> Self {
        OrderError::Internal(e.to_string())
    }
}

/// Something that happened to an order.
#[dto]
#[derive(SseEvent)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum OrderEvent {
    Placed { id: u32 },
    Cancelled { id: u32 },
}
