use doxa::client::{Granted, Json, Query};
use doxa::wire::contract::{Declared, NoError};
use doxa::wire::Method;
use orders_api::*;

trait Same<T> {}
impl<T> Same<T> for T {}
fn same<A: Same<B>, B>() {}

#[test]
fn a_declaration_states_its_arguments_answer_and_error() {
    same::<<get_order::Route as Declared>::Args, (Granted<Order>,)>();
    same::<<get_order::Route as Declared>::Ok, Json<Order>>();
    same::<<get_order::Route as Declared>::Error, OrderError>();

    same::<<list_orders::Route as Declared>::Args, (Query<OrderFilter>,)>();
    same::<<list_orders::Route as Declared>::Error, NoError>();

    same::<<place_order::Route as Declared>::Args, (doxa::Valid<Json<NewOrder>>,)>();
    same::<<order_events::Route as Declared>::Ok, doxa::client::SseStream<OrderEvent>>();
}

#[test]
fn a_granted_declaration_answers_a_dry_run_and_invalidates_its_entity() {
    let spec = <cancel_order::Route as Declared>::SPEC;
    assert!(spec.dry_run);
    assert_eq!(spec.entities, ["Order"]);
    let _probe = cancel_order::can(OrderKey { id: 7 });
}

#[test]
fn a_declaration_carries_its_route_and_docs() {
    let spec = <place_order::Route as Declared>::SPEC;
    assert_eq!((spec.method, spec.path), (Method::Post, "/api/orders"));
    assert_eq!(spec.package, "orders-api");
    assert_eq!(<get_order::Route as Declared>::DOCS, "One order.");
}

#[test]
fn a_declaration_is_a_call_natively_too() {
    let call = get_order(OrderKey { id: 7 });
    assert_eq!(call.url().unwrap(), "/api/orders/7");
}
