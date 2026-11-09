//! Each client crate's routes reach its own service: base URL, layers, cache and session.

use std::cell::RefCell;
use std::future::IntoFuture;
use std::rc::Rc;
use std::time::Duration;

use doxa_client::layer::{layer_fn, layers, transport, Next};
use doxa_client::transport::{MockTransport, Request};
use doxa_client::{service, task, CachedCall, Call, Json, Query};
use doxa_wire::{Keyed, Method, RouteSpec};
use serde::Serialize;
use serde_json::json;

doxa_client::route_key!(OrderKey { id: String });

struct OrderById;

impl Keyed for OrderById {
    type Key = OrderKey;
    const ENTITY_TYPE: &'static str = "Order";
    const PACKAGE: &'static str = "orders-client";
}

const fn route(package: &'static str, method: Method, path: &'static str) -> RouteSpec {
    RouteSpec {
        method,
        path,
        operation_id: path,
        entities: &["Order"],
        dry_run: false,
        invalidates: true,
        package,
    }
}

static ORDERS: RouteSpec = route("orders-client", Method::Get, "/orders");
static CANCEL: RouteSpec = route("orders-client", Method::Post, "/orders/cancel");
static THREADS: RouteSpec = route("chat-client", Method::Get, "/orders");

#[derive(Default, Serialize)]
struct Filter {}

const TTL: Duration = Duration::from_secs(60);

fn orders() -> CachedCall<Json<serde_json::Value>> {
    Call::new(&ORDERS)
        .arg::<Query<Filter>, _>(Filter {})
        .cache(TTL)
}

fn cancel() -> Call<Json<serde_json::Value>> {
    Call::new(&CANCEL)
}

/// A route of another crate that happens to share the path and entity name.
fn threads() -> CachedCall<Json<serde_json::Value>> {
    Call::new(&THREADS)
        .arg::<Query<Filter>, _>(Filter {})
        .cache(TTL)
}

fn wait<F: IntoFuture>(f: F) -> F::Output {
    task::block_on(f.into_future())
}

fn two_servers() -> (MockTransport, MockTransport) {
    let (o, c) = (MockTransport::new(), MockTransport::new());
    for (pkg, mock) in [("orders-client", &o), ("chat-client", &c)] {
        let s = service(pkg);
        s.layers().push(transport(mock.clone()));
    }
    (o, c)
}

fn urls(mock: &MockTransport) -> Vec<String> {
    mock.requests().into_iter().map(|r| r.url).collect()
}

#[test]
fn each_crate_reaches_its_own_server_under_its_base() {
    let (o, c) = two_servers();
    service("orders-client").set_base("https://orders.example.com");
    o.json(200, &json!([]));
    c.json(200, &json!([]));
    wait(orders()).unwrap();
    wait(threads()).unwrap();
    assert_eq!(urls(&o), ["https://orders.example.com/orders"]);
    assert_eq!(urls(&c), ["/orders"], "an unset base is the page's origin");
}

#[test]
fn invalidation_stays_in_the_owning_service() {
    let (o, c) = two_servers();
    for _ in 0..2 {
        o.json(200, &json!([]));
    }
    c.json(200, &json!([]));
    wait(orders()).unwrap();
    wait(threads()).unwrap();
    doxa_client::invalidate_all::<OrderById>();
    wait(orders()).unwrap();
    wait(threads()).unwrap();
    task::run_until_stalled();
    assert_eq!(o.requests().len(), 2);
    assert_eq!(
        c.requests().len(),
        1,
        "the other crate's `Order` was dropped"
    );
}

#[test]
fn a_mutation_invalidates_only_its_own_service() {
    let (o, c) = two_servers();
    o.json(200, &json!([]))
        .json(200, &json!({}))
        .json(200, &json!([]));
    c.json(200, &json!([]));
    wait(orders()).unwrap();
    wait(threads()).unwrap();
    wait(cancel()).unwrap();
    wait(orders()).unwrap();
    wait(threads()).unwrap();
    assert_eq!(o.requests().len(), 3);
    assert_eq!(c.requests().len(), 1);
}

#[test]
fn a_session_change_resets_only_its_service() {
    let (o, c) = two_servers();
    c.json(200, &json!([]));
    wait(threads()).unwrap();
    service("orders-client").end_session();
    wait(threads()).unwrap();
    assert_eq!(c.requests().len(), 1);
    assert!(o.requests().is_empty());
}

#[test]
fn global_layers_run_before_the_services() {
    let o = MockTransport::new();
    o.json(200, &json!([]));
    let seen = Rc::new(RefCell::new(Vec::new()));
    let tag = |name: &'static str| {
        let seen = seen.clone();
        layer_fn(move |req: Request, next: Next| {
            seen.borrow_mut().push(name);
            async move { next.run(req).await }
        })
    };
    let orders_service = service("orders-client");
    orders_service.layers().push(tag("service"));
    orders_service.layers().push(transport(o));
    layers().push(tag("global"));
    wait(orders()).unwrap();
    assert_eq!(*seen.borrow(), ["global", "service"]);
}
