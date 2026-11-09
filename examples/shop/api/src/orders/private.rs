//! What only a signed-in caller may change.

use super::{order_action, NewOrder, Order, OrderError};

doxa::prelude!();

/// Changes, refused without a role.
#[doxa::service(layers = signed_in)]
pub struct OrdersPrivate;

/// Cancel an order.
#[delete("/api/orders/{id}")]
pub async fn cancel_order(
    order: Grant<Order>,
    State(store): State<Store>,
) -> Result<StatusCode, OrderError> {
    store.remove(order.id)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Refund an order, if its payment allows; the guard alone can't say, so `<Can>` doesn't ask.
#[post("/api/orders/{id}/refund", dry_run = false)]
pub async fn refund_order(_: Grant<Order>) -> Result<StatusCode, OrderError> {
    Ok(StatusCode::NO_CONTENT)
}

/// Place an order.
#[post("/api/orders")]
pub async fn place_order(
    _: Grant<Cap<order_action::Place>>,
    State(store): State<Store>,
    Valid(Json(new)): Valid<Json<NewOrder>>,
) -> Result<Json<Order>, OrderError> {
    store.place(new).map(Json)
}
