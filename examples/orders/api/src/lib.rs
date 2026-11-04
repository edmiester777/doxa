//! The orders API: what `orders-server` serves and its clients call.

doxa::prelude!();
doxa::service!();

route_key!(pub OrderKey { id: u32 });

/// An order.
#[dto]
#[entity(key = OrderKey)]
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

/// Every order, narrowed by `filter`.
#[get("/api/orders")]
pub async fn list_orders(filter: Query<OrderFilter>) -> Json<Vec<Order>>;

/// Place an order.
#[post("/api/orders")]
pub async fn place_order(order: Valid<Json<NewOrder>>) -> Result<Json<Order>, OrderError>;

/// Orders as they're placed and cancelled.
#[get("/api/orders/events")]
pub async fn order_events() -> SseStream<OrderEvent>;
