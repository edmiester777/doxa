//! The orders API: what `orders-server` serves and its clients call.

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

/// One order.
#[get("/api/orders/{id}")]
pub async fn get_order(order: Grant<Order>) -> Result<Json<Order>, OrderError>;

/// Cancel an order.
#[delete("/api/orders/{id}")]
pub async fn cancel_order(order: Grant<Order>) -> Result<StatusCode, OrderError>;

/// Refund an order, if its payment allows; the guard alone can't say, so `<Can>` doesn't ask.
#[post("/api/orders/{id}/refund", dry_run = false)]
pub async fn refund_order(order: Grant<Order>) -> Result<StatusCode, OrderError>;

/// Every order, narrowed by `filter`.
#[get("/api/orders")]
pub async fn list_orders(_: Grant<Many<Order>>, filter: Query<OrderFilter>) -> Json<Vec<Order>>;

/// Place an order.
#[post("/api/orders")]
pub async fn place_order(
    _: Grant<Cap<order_action::Place>>,
    order: Valid<Json<NewOrder>>,
) -> Result<Json<Order>, OrderError>;

/// Orders as they're placed and cancelled.
#[get("/api/orders/events")]
pub async fn order_events() -> SseStream<OrderEvent>;

/// Count every order: at once while there are few, or queued once there are many.
#[post(
    "/api/orders/count",
    responses(
        (status = 200, description = "Counted"),
        (status = 202, description = "Queued; this is the count so far"),
    )
)]
pub async fn count_orders() -> (StatusCode, Json<usize>);
