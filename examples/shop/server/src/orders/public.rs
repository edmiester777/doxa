//! What any caller may read.

use std::convert::Infallible;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use futures::stream::{self, Stream};

use doxa::auth::{Granted, Many};
use doxa::{implements, SseStream};

use orders_api::{Order, OrderError, OrderEvent, OrderFilter};

use crate::{OrderById, Store};

/// Reads, behind the caller's role.
#[doxa::service(layers = crate::caller)]
pub struct OrdersPublic;

#[implements(orders_api::get_order)]
async fn get_order(order: Granted<OrderById>) -> Result<Json<Order>, OrderError> {
    Ok(Json(order.into_inner().into()))
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

#[implements(orders_api::order_events)]
async fn order_events() -> SseStream<OrderEvent, impl Stream<Item = Result<OrderEvent, Infallible>>>
{
    SseStream::new(stream::iter([
        Ok(OrderEvent::Placed { id: 1 }),
        Ok(OrderEvent::Cancelled { id: 1 }),
    ]))
}

#[implements(orders_api::count_orders)]
async fn count_orders(State(store): State<Store>) -> (StatusCode, Json<usize>) {
    let count = store.0.read().unwrap().len();
    let status = if count > 1 {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    (status, Json(count))
}
