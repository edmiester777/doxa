//! `orders-api`'s calls, sent through `orders-server`'s router in-process.

use std::cell::RefCell;

use doxa::client::layer::{transport, Scoped};
use doxa::client::transport::RouterTransport;
use doxa::client::{Fetch, Permission};
use orders_api::*;

thread_local! {
    static SERVED: RefCell<Option<Scoped>> = const { RefCell::new(None) };
}

fn install(role: &str) {
    let s = orders_api::service();
    SERVED.with(|g| g.borrow_mut().take());
    s.end_session();
    let router = RouterTransport::new(orders_server::app(orders_server::seeded()));
    let guard = s
        .layers()
        .push_scoped(transport(router.with_header("x-role", role)));
    SERVED.with(|g| *g.borrow_mut() = Some(guard));
}

#[tokio::test]
async fn a_declared_route_is_called_by_its_key_and_answers_the_handlers_value() {
    install("viewer");
    let order = get_order(OrderKey { id: 2 }).await.unwrap();
    assert_eq!(order.item, "gear");
}

#[tokio::test]
async fn the_declared_error_comes_back_typed() {
    install("clerk");
    let err = place_order(NewOrder {
        item: "unobtainium".into(),
        quantity: 1,
    })
    .await
    .unwrap_err();
    match err {
        Fetch::Api(body) => assert_eq!(body.error, OrderError::OutOfStock("unobtainium".into())),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_cancelled_order_is_gone() {
    install("clerk");
    cancel_order(OrderKey { id: 1 }).await.unwrap();
    let err = get_order(OrderKey { id: 1 }).await.unwrap_err();
    assert!(matches!(err, Fetch::NotFound(_)), "{err:?}");
}

#[tokio::test]
async fn a_query_and_a_validated_body_reach_the_handler() {
    install("clerk");
    let placed = place_order(NewOrder {
        item: "cog".into(),
        quantity: 3,
    })
    .await
    .unwrap();
    assert_eq!(placed.id, 3);
    let cogs = list_orders(OrderFilter {
        item: Some("cog".into()),
    })
    .await
    .unwrap();
    assert_eq!(cogs.len(), 1);
    let refused = place_order(NewOrder {
        item: String::new(),
        quantity: 0,
    })
    .await
    .unwrap_err();
    assert!(matches!(refused, Fetch::Invalid(_)), "{refused:?}");
}

#[tokio::test]
async fn the_servers_guard_answers_the_declarations_dry_run() {
    install("viewer");
    assert_eq!(
        cancel_order::can(OrderKey { id: 1 }).await,
        Permission::Denied
    );
    install("clerk");
    assert_eq!(
        cancel_order::can(OrderKey { id: 1 }).await,
        Permission::Allowed
    );
}

#[tokio::test]
async fn a_declared_stream_streams() {
    install("viewer");
    let mut events = order_events().await.unwrap();
    assert!(matches!(
        events.next().await.unwrap(),
        Some(OrderEvent::Placed { id: 1 })
    ));
}

#[test]
fn the_document_names_each_route_by_its_declaration() {
    let api = doxa::__private::IntoSpec::into_spec(orders_server::api_doc());
    let op = api.paths.paths["/api/orders/{id}"].delete.as_ref().unwrap();
    assert_eq!(op.operation_id.as_deref(), Some("cancel_order"));
    assert_eq!(op.summary.as_deref(), Some("Cancel an order."));
}

#[test]
#[should_panic(expected = "this server doesn't serve 5 declared route(s)")]
fn a_document_missing_declared_routes_names_them() {
    orders_server::assert_serves(&doxa::OpenApi::default());
}
