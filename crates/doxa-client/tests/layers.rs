//! What layers see and change: order, credentials, retries, status hooks, scoping.

use std::cell::{Cell, RefCell};
use std::future::IntoFuture;
use std::rc::Rc;
use std::time::Duration;

use doxa_client::layer::{
    bearer, cookies, layer_fn, layers, on_error_code, on_status, transport, Next,
};
use doxa_client::transport::{MockTransport, Request};
use doxa_client::{service, task, Call, Json, Permission, Probe, SseStream};
use doxa_wire::{Method, RouteSpec};
use serde::Deserialize;
use serde_json::json;

const fn route(method: Method, path: &'static str) -> RouteSpec {
    RouteSpec {
        method,
        path,
        operation_id: path,
        entities: &[],
        dry_run: true,
        package: "",
    }
}

static GET: RouteSpec = route(Method::Get, "/w");
static POST: RouteSpec = route(Method::Post, "/w");
static EVENTS: RouteSpec = route(Method::Get, "/events");

fn get() -> Call<Json<serde_json::Value>> {
    Call::new(&GET)
}

fn post() -> Call<Json<serde_json::Value>> {
    Call::new(&POST)
}

#[derive(Debug, Deserialize)]
struct Ev {}

fn wait<F: IntoFuture>(f: F) -> F::Output {
    task::block_on(f.into_future())
}

fn install() -> MockTransport {
    let mock = MockTransport::new();
    service("").layers().push(transport(mock.clone()));
    mock
}

#[test]
fn layers_run_in_the_order_pushed() {
    let mock = install();
    mock.json(200, &json!({}));
    let seen = Rc::new(RefCell::new(Vec::new()));
    for name in ["outer", "inner"] {
        let seen = seen.clone();
        layers().push(layer_fn(move |req: Request, next: Next| {
            seen.borrow_mut().push(name);
            next.run(req)
        }));
    }
    wait(get()).unwrap();
    assert_eq!(*seen.borrow(), ["outer", "inner"]);
}

#[test]
fn bearer_is_asked_on_every_request_including_probes() {
    let mock = install();
    mock.json(200, &json!({})).respond(
        204,
        vec![(
            doxa_wire::DRY_RUN_HEADER.into(),
            doxa_wire::DRY_RUN_OK.into(),
        )],
        vec![],
    );
    let n = Rc::new(Cell::new(0));
    let c = n.clone();
    layers().push(bearer(move || {
        c.set(c.get() + 1);
        Some(format!("t{}", c.get()))
    }));
    wait(get()).unwrap();
    assert_eq!(wait(Probe::new(&POST)), Permission::Allowed);
    let auth: Vec<_> = mock
        .requests()
        .iter()
        .map(|r| r.header("authorization").map(str::to_owned))
        .collect();
    assert_eq!(auth, [Some("Bearer t1".into()), Some("Bearer t2".into())]);
}

#[test]
fn cookies_send_credentials_and_csrf_on_mutations() {
    let mock = install();
    mock.json(200, &json!({})).json(200, &json!({}));
    layers().push(cookies());
    wait(get()).unwrap();
    wait(post()).unwrap();
    let sent = mock.requests();
    assert!(sent.iter().all(|r| r.credentials));
    assert_eq!(sent[0].header(doxa_wire::CSRF_HEADER), None);
    assert_eq!(sent[1].header(doxa_wire::CSRF_HEADER), Some("1"));
}

#[test]
fn a_layer_can_retry_after_refreshing() {
    let mock = install();
    mock.json(401, &json!({})).json(200, &json!({ "ok": true }));
    let refreshed = Rc::new(Cell::new(false));
    let r = refreshed.clone();
    layers().push(layer_fn(move |req: Request, next: Next| {
        let r = r.clone();
        async move {
            let res = next.run(req.clone()).await?;
            if res.status == 401 && !r.replace(true) {
                return next.run(req).await;
            }
            Ok(res)
        }
    }));
    assert_eq!(wait(get()).unwrap()["ok"], true);
    assert!(refreshed.get());
    assert_eq!(mock.requests().len(), 2);
}

#[test]
fn signing_out_on_a_401_reconnect_ends_the_stream() {
    let mock = install();
    mock.respond(200, vec![], b"data: {}\n\n".to_vec())
        .json(401, &json!({}));
    layers().push(on_status(401, |_| service("").end_session()));
    let fails = wait(async {
        let mut s = Call::<SseStream<Ev>>::new(&EVENTS)
            .await
            .unwrap()
            .reconnect(doxa_client::Backoff {
                initial: Duration::from_millis(1),
                max: Duration::from_millis(1),
            });
        s.next().await.unwrap();
        s.next().await.is_err()
    });
    assert!(fails);
}

#[test]
fn an_error_code_hook_sees_the_body_and_leaves_it_for_the_call() {
    let mock = install();
    let body = doxa_wire::ApiErrorBody::new(403, "feature_disabled", "off", json!(null));
    mock.json(403, &body);
    let hit = Rc::new(Cell::new(false));
    let h = hit.clone();
    layers().push(on_error_code(403, "feature_disabled", move |_| h.set(true)));
    let err = wait(get()).unwrap_err();
    assert!(hit.get());
    assert_eq!(err.status(), Some(403));
}

#[test]
fn a_scoped_layer_is_gone_once_its_guard_drops() {
    let mock = install();
    mock.json(200, &json!({ "from": "mock" }));
    let local = MockTransport::new();
    local.json(200, &json!({ "from": "scoped" }));
    let guard = layers().push_scoped(transport(local.clone()));
    assert_eq!(wait(get().fresh()).unwrap()["from"], "scoped");
    drop(guard);
    assert_eq!(wait(get().fresh()).unwrap()["from"], "mock");
    assert_eq!(mock.requests().len(), 1);
}
