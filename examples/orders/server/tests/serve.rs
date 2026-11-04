//! `orders-api`'s calls, sent through `orders-server`'s router in-process.

use std::cell::RefCell;
use std::time::Duration;

use doxa::client::layer::{transport, Scoped};
use doxa::client::transport::RouterTransport;
use doxa::client::{CacheConfig, Fetch, Permission};
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

#[tokio::test]
async fn placing_an_order_refreshes_the_cached_list() {
    install("clerk");
    let s = orders_api::service();
    s.cache(CacheConfig::default().stale_time(Duration::from_secs(60)));
    assert_eq!(list_orders(OrderFilter::default()).await.unwrap().len(), 2);
    place_order(NewOrder {
        item: "cog".into(),
        quantity: 1,
    })
    .await
    .unwrap();
    let before = s.requests_sent();
    list_orders(OrderFilter::default()).await.unwrap();
    doxa::client::task::run_until_stalled();
    assert!(s.requests_sent() > before);
    assert_eq!(list_orders(OrderFilter::default()).await.unwrap().len(), 3);
}

#[tokio::test]
async fn the_capabilities_route_agrees_with_the_guard() {
    for role in ["viewer", "clerk", "admin"] {
        install(role);
        let held = doxa::client::has(order_action::Place).await;
        let placed = place_order(NewOrder {
            item: "cog".into(),
            quantity: 1,
        })
        .await;
        assert_eq!(held, placed.is_ok(), "{role}: {placed:?}");
    }
}

#[tokio::test]
async fn a_capability_only_route_answers_can_from_the_callers_capabilities() {
    install("clerk");
    let s = orders_api::service();
    let before = s.requests_sent();
    for _ in 0..5 {
        assert_eq!(place_order::can().await, Permission::Allowed);
    }
    assert!(doxa::client::has(order_action::Place).await);
    assert_eq!(
        s.requests_sent() - before,
        1,
        "one request for the set, no dry runs"
    );

    install("viewer");
    assert_eq!(place_order::can().await, Permission::Denied);
}
