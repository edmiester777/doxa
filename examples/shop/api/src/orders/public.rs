//! What any caller may read.

use super::{Order, OrderError, OrderEvent, OrderFilter};

doxa::prelude!();

/// Reads, behind the caller's role.
#[doxa::service(layers = caller)]
pub struct OrdersPublic;

/// One order.
#[get("/api/orders/{id}")]
pub async fn get_order(order: Grant<Order>) -> Result<Json<Order>, OrderError> {
    Ok(Json(order.into_inner().into()))
}

/// Every order, narrowed by `filter`.
#[get("/api/orders")]
pub async fn list_orders(
    _: Grant<Many<Order>>,
    State(store): State<Store>,
    Query(filter): Query<OrderFilter>,
) -> Json<Vec<Order>> {
    Json(store.list(filter.item.as_deref()))
}

/// Orders as they're placed and cancelled.
#[get("/api/orders/events")]
pub async fn order_events(
) -> SseStream<OrderEvent, impl futures::Stream<Item = Result<OrderEvent, std::convert::Infallible>>>
{
    SseStream::new(futures::stream::iter([
        Ok(OrderEvent::Placed { id: 1 }),
        Ok(OrderEvent::Cancelled { id: 1 }),
    ]))
}

/// Count every order: at once while there are few, or queued once there are many.
#[post(
    "/api/orders/count",
    responses(
        (status = 200, description = "Counted", body = usize, content_type = "application/json"),
        (
            status = 202,
            description = "Queued; this is the count so far",
            body = usize,
            content_type = "application/json",
        ),
    )
)]
pub async fn count_orders(State(store): State<Store>) -> (StatusCode, Json<usize>) {
    let count = store.count();
    let status = if count > 1 {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    (status, Json(count))
}
