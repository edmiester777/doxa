//! What only a signed-in caller may change.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use doxa::auth::{Cap, Granted};
use doxa::{implements, Valid};

use orders_api::{order_action, NewOrder, Order, OrderError};

use crate::{Gone, OrderById, OrderRow, Store};

/// Changes, refused without a role.
#[doxa::service(layers = crate::signed_in)]
pub struct OrdersPrivate;

#[implements(orders_api::cancel_order)]
async fn cancel_order(
    order: Granted<OrderById>,
    State(store): State<Store>,
) -> Result<StatusCode, Gone> {
    store.remove(order.id)?;
    Ok(StatusCode::NO_CONTENT)
}

#[implements(orders_api::refund_order)]
async fn refund_order(_: Granted<OrderById>) -> StatusCode {
    StatusCode::NO_CONTENT
}

#[implements(orders_api::place_order)]
async fn place_order(
    _: Granted<Cap<order_action::Place>>,
    State(store): State<Store>,
    Valid(Json(new)): Valid<Json<NewOrder>>,
) -> Result<Json<Order>, OrderError> {
    if new.item == "unobtainium" {
        return Err(OrderError::OutOfStock(new.item));
    }
    let mut orders = store.0.write().unwrap();
    let next = orders.iter().map(|o| u64::from(o.id)).max().unwrap_or(0) + 1;
    let id = u32::try_from(next)?;
    let row = OrderRow {
        id,
        item: new.item,
        quantity: new.quantity,
    };
    orders.push(row.clone());
    Ok(Json(row.into()))
}
