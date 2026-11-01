//! What reaches the network: re-reads, revalidation, mutations, streams.

use std::cell::{Cell, RefCell};
use std::future::IntoFuture;
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::Duration;

use doxa_client::cache::{self, Observer};
use doxa_client::transport::{Body, MockTransport, Request, Response, Transport};
use doxa_client::{
    task, CacheConfig, Cached, Call, Client, ClientConfig, Granted, Json, Permission, Probe, Query,
    SseStream,
};
use doxa_wire::{Identity, Keyed, Method, RouteSpec};
use futures_util::future::LocalBoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Widget {
    id: u32,
    name: String,
}

doxa_client::route_key!(WidgetKey { name: String });

impl Identity for Widget {
    type Id = u32;
    const ENTITY_TYPE: &'static str = "Widget";
    fn identity(&self) -> u32 {
        self.id
    }
    fn route_key(&self) -> Option<serde_json::Value> {
        doxa_wire::key_value(&WidgetKey {
            name: self.name.clone(),
        })
    }
}

struct WidgetByName;

impl Keyed for WidgetByName {
    type Key = WidgetKey;
    const ENTITY_TYPE: &'static str = "Widget";
}

const fn route(method: Method, path: &'static str) -> RouteSpec {
    RouteSpec {
        method,
        path,
        operation_id: path,
        entities: &["Widget"],
        dry_run: true,
    }
}

static GET: RouteSpec = route(Method::Get, "/w/{name}");
static LIST: RouteSpec = route(Method::Get, "/w");
static RENAME: RouteSpec = route(Method::Patch, "/w/{name}");
static EVENTS: RouteSpec = route(Method::Get, "/w/{name}/events");

#[derive(Default, Serialize)]
struct Filter {}

fn get(name: &str) -> Call<Json<Widget>> {
    Call::new(&GET).arg::<Granted<WidgetByName>, _>(name)
}

fn list() -> Call<Json<Vec<Widget>>> {
    Call::new(&LIST).arg::<Query<Filter>, _>(Filter {})
}

fn rename(name: &str, to: &str) -> Call<Json<Widget>> {
    Call::new(&RENAME)
        .arg::<Granted<WidgetByName>, _>(name)
        .arg::<Json<serde_json::Value>, _>(json!({ "name": to }))
}

fn widget(id: u32, name: &str) -> serde_json::Value {
    json!({ "id": id, "name": name })
}

fn install(mock: &MockTransport, stale: Duration) -> Rc<Client> {
    ClientConfig::default()
        .transport(mock.clone())
        .cache(CacheConfig::default().stale_time(stale))
        .install()
}

fn wait<F: IntoFuture>(call: F) -> F::Output {
    task::block_on(call.into_future())
}

/// Holds every request until the test answers it.
#[derive(Clone, Default)]
struct Manual(Rc<RefCell<Vec<Rc<Held>>>>);

#[derive(Default)]
struct Held {
    url: String,
    reply: RefCell<Option<Canned>>,
    waker: RefCell<Option<Waker>>,
}

type Canned = (u16, Vec<(String, String)>, Vec<u8>);

impl Manual {
    fn answer(&self, i: usize, status: u16, session: Option<&str>, body: serde_json::Value) {
        let held = self.0.borrow()[i].clone();
        let headers = session
            .map(|s| vec![(doxa_wire::SESSION_HEADER.to_owned(), s.to_owned())])
            .unwrap_or_default();
        *held.reply.borrow_mut() = Some((status, headers, serde_json::to_vec(&body).unwrap()));
        if let Some(w) = held.waker.borrow_mut().take() {
            w.wake();
        }
        task::run_until_stalled();
    }

    fn urls(&self) -> Vec<String> {
        self.0.borrow().iter().map(|h| h.url.clone()).collect()
    }
}

impl Transport for Manual {
    fn send(&self, request: Request) -> LocalBoxFuture<'static, Result<Response, String>> {
        let held = Rc::new(Held {
            url: request.url,
            ..Held::default()
        });
        self.0.borrow_mut().push(held.clone());
        Box::pin(std::future::poll_fn(move |cx| {
            match held.reply.borrow_mut().take() {
                Some((status, headers, body)) => Poll::Ready(Ok(Response {
                    status,
                    headers,
                    body: Body::Full(body),
                })),
                None => {
                    *held.waker.borrow_mut() = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        }))
    }
}

fn spawn<F: IntoFuture + 'static>(call: F) {
    let fut = call.into_future();
    task::spawn(async move {
        let _ = fut.await;
    });
    task::run_until_stalled();
}

#[test]
fn a_late_response_from_the_old_session_is_dropped() {
    let manual = Manual::default();
    let client = ClientConfig::default()
        .transport(manual.clone())
        .cache(CacheConfig::default().stale_time(Duration::from_secs(60)))
        .install();
    let changes = Rc::new(Cell::new(0));
    let c = changes.clone();
    client.on_session_change(move || c.set(c.get() + 1));

    spawn(get("gear"));
    manual.answer(0, 200, Some("a"), widget(2, "gear"));
    spawn(get("cog"));
    spawn(list());
    manual.answer(2, 200, Some("b"), json!([]));
    assert_eq!(changes.get(), 1);
    manual.answer(1, 200, Some("a"), widget(1, "old"));
    assert_eq!(changes.get(), 1, "the old epoch came back");

    // The dropped `cog` call is retried in the new session.
    assert_eq!(manual.urls(), ["/w/gear", "/w/cog", "/w", "/w/cog"]);
    manual.answer(3, 200, Some("b"), widget(1, "cog"));
    assert_eq!(wait(get("cog")).unwrap().name, "cog");
    wait(list()).unwrap();
    assert_eq!(changes.get(), 1);
    assert_eq!(manual.urls().len(), 4);
}

#[test]
fn a_revalidation_from_before_a_clear_does_not_overwrite_the_new_entry() {
    let manual = Manual::default();
    let client = ClientConfig::default()
        .transport(manual.clone())
        .cache(CacheConfig::default().stale_time(Duration::ZERO))
        .install();
    spawn(get("cog"));
    manual.answer(0, 200, None, widget(1, "v1"));
    assert_eq!(wait(get("cog")).unwrap().name, "v1");
    client.clear_cache();
    spawn(get("cog"));
    manual.answer(2, 200, None, widget(1, "v2"));
    manual.answer(1, 200, None, widget(1, "old"));
    assert_eq!(wait(get("cog")).unwrap().name, "v2");
}

fn session(name: &str) -> Vec<(String, String)> {
    vec![(doxa_wire::SESSION_HEADER.into(), name.into())]
}

#[test]
fn signing_in_and_out_clears_the_cache() {
    let mock = MockTransport::new();
    let allowed = vec![
        (doxa_wire::SESSION_HEADER.into(), "u1".into()),
        (
            doxa_wire::DRY_RUN_HEADER.into(),
            doxa_wire::DRY_RUN_OK.into(),
        ),
    ];
    let body = |w| serde_json::to_vec(&w).unwrap();
    mock.respond(401, session("anonymous"), vec![])
        .respond(200, session("u1"), body(widget(1, "cog")))
        .respond(204, allowed, vec![])
        .respond(401, session("anonymous"), vec![])
        .respond(401, session("anonymous"), vec![]);
    let client = install(&mock, Duration::from_secs(60));
    let can = || Probe::new(&GET).arg::<Granted<WidgetByName>, _>("cog");

    assert_eq!(wait(can()), Permission::Denied);
    wait(get("cog")).unwrap();
    assert_eq!(
        wait(can()),
        Permission::Allowed,
        "signing in kept the anonymous answer"
    );
    assert!(wait(list()).is_err());
    assert!(
        wait(get("cog")).is_err(),
        "signing out kept the user's data"
    );
    assert_eq!(client.requests_sent(), 5);
}

/// Read `cog`, let it go stale, and have its revalidation answer `status`.
fn revalidate_with(status: u16) -> (MockTransport, Rc<Client>, Rc<Renders>) {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog")).json(status, &json!({}));
    let client = install(&mock, Duration::from_millis(50));
    let renders = Rc::new(Renders::default());
    cache::set_observer(Some(renders.clone()));
    wait(get("cog")).unwrap();
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(wait(get("cog")).unwrap().name, "cog");
    cache::set_observer(None);
    task::run_until_stalled();
    (mock, client, renders)
}

#[test]
fn a_revalidation_that_finds_nothing_or_is_refused_evicts_the_entry() {
    for status in [404, 401, 403] {
        let (mock, client, renders) = revalidate_with(status);
        assert_eq!(renders.0.get(), 1, "{status}: readers were not told");
        mock.json(status, &json!({}));
        let err = wait(get("cog")).unwrap_err();
        assert_eq!(err.status(), Some(status));
        assert_eq!(client.requests_sent(), 3);
    }
}

#[test]
fn a_failed_revalidation_leaves_the_entry_stale() {
    let (mock, client, renders) = revalidate_with(500);
    assert_eq!(renders.0.get(), 0);
    mock.json(200, &widget(1, "cog"));
    assert_eq!(wait(get("cog")).unwrap().name, "cog");
    task::run_until_stalled();
    assert_eq!(client.requests_sent(), 3, "the next read did not try again");
}

#[derive(Default)]
struct Renders(Cell<u32>);

impl Observer for Renders {
    fn changed(&self) {
        self.0.set(self.0.get() + 1);
    }
}

#[test]
fn re_reading_a_fresh_query_sends_nothing() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"));
    let client = ClientConfig::default().transport(mock.clone()).install();
    task::block_on(async {
        for _ in 0..5 {
            assert_eq!(get("cog").await.unwrap().name, "cog");
        }
    });
    assert_eq!(client.requests_sent(), 1);
}

#[test]
fn a_stale_query_revalidates_once_per_stale_period() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"))
        .json(200, &widget(1, "cog"));
    let client = install(&mock, Duration::from_millis(20));
    wait(get("cog")).unwrap();
    std::thread::sleep(Duration::from_millis(30));
    for _ in 0..5 {
        wait(get("cog")).unwrap();
    }
    task::run_until_stalled();
    for _ in 0..5 {
        wait(get("cog")).unwrap();
    }
    assert_eq!(client.requests_sent(), 2);
    assert_eq!(mock.requests().len(), 2);
}

#[test]
fn a_cached_value_is_shared_until_it_changes() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"))
        .json(200, &widget(1, "cog2"));
    install(&mock, Duration::from_secs(60));
    let a = wait(get("cog")).unwrap();
    let b = wait(get("cog")).unwrap();
    assert!(Cached::ptr_eq(&a, &b));
    cache::invalidate_all::<WidgetByName>();
    wait(get("cog")).unwrap();
    task::run_until_stalled();
    let c = wait(get("cog")).unwrap();
    assert!(!Cached::ptr_eq(&a, &c));
    assert_eq!(c.name, "cog2");
}

#[test]
fn a_mutation_refetches_each_affected_query_once() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"))
        .json(200, &json!([widget(1, "cog"), widget(2, "gear")]))
        .json(200, &widget(1, "sprocket"))
        .json(200, &widget(1, "sprocket"))
        .json(200, &json!([widget(1, "sprocket"), widget(2, "gear")]));
    let client = ClientConfig::default().transport(mock.clone()).install();
    let renders = Rc::new(Renders::default());
    cache::set_observer(Some(renders.clone()));
    task::block_on(async {
        get("cog").await.unwrap();
        list().await.unwrap();
        rename("cog", "sprocket").await.unwrap();
    });
    assert_eq!(client.requests_sent(), 3);
    // Every re-render after the mutation reads both queries again.
    for _ in 0..4 {
        task::block_on(async {
            get("cog").await.unwrap();
            list().await.unwrap();
        });
        task::run_until_stalled();
    }
    cache::set_observer(None);
    assert_eq!(client.requests_sent(), 5);
    let names: Vec<String> = wait(list())
        .unwrap()
        .iter()
        .map(|w| w.name.clone())
        .collect();
    assert_eq!(names, ["sprocket", "gear"]);
}

#[test]
fn invalidating_one_key_leaves_other_instances_fresh() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"))
        .json(200, &widget(2, "gear"))
        .json(200, &json!([]))
        .json(200, &widget(1, "cog"))
        .json(200, &json!([]));
    let client = install(&mock, Duration::from_secs(60));
    let read_all = || {
        task::block_on(async {
            get("cog").await.unwrap();
            get("gear").await.unwrap();
            list().await.unwrap();
        });
        task::run_until_stalled();
    };
    read_all();
    cache::invalidate::<WidgetByName>("cog");
    read_all();
    read_all();
    let urls: Vec<String> = mock.requests().into_iter().map(|r| r.url).collect();
    assert_eq!(urls, ["/w/cog", "/w/gear", "/w", "/w/cog", "/w"]);
    assert_eq!(client.requests_sent(), 5);
}

#[test]
fn apply_patches_instances_and_lists_and_tells_readers() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"))
        .json(200, &json!([widget(1, "cog"), widget(2, "gear")]));
    let client = install(&mock, Duration::from_secs(60));
    let renders = Rc::new(Renders::default());
    cache::set_observer(Some(renders.clone()));
    task::block_on(async {
        get("cog").await.unwrap();
        list().await.unwrap();
    });
    cache::set_observer(None);
    cache::apply::<Widget>(&WidgetKey { name: "cog".into() }, |w| w.id = 9);
    assert_eq!(renders.0.get(), 1);
    task::block_on(async {
        assert_eq!(get("cog").await.unwrap().id, 9);
        assert_eq!(list().await.unwrap()[0].id, 9);
        assert_eq!(list().await.unwrap()[1].id, 2);
    });
    assert_eq!(client.requests_sent(), 2);
}

#[derive(Debug, PartialEq, Deserialize)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
enum Event {
    Renamed { name: String },
}

fn events(name: &str) -> Call<SseStream<Event>> {
    Call::new(&EVENTS).arg::<Granted<WidgetByName>, _>(name)
}

#[test]
fn identical_streams_share_one_connection() {
    let mock = MockTransport::new();
    let body = "data: {\"event\":\"renamed\",\"data\":{\"name\":\"x\"}}\n\n";
    mock.respond(200, vec![], body.into())
        .respond(200, vec![], body.into());
    install(&mock, Duration::from_secs(60));
    task::block_on(async {
        let mut a = events("cog").await.unwrap();
        let mut b = events("cog").await.unwrap();
        let mut other = events("gear").await.unwrap();
        let renamed = Some(Event::Renamed { name: "x".into() });
        assert_eq!(a.next().await.unwrap(), renamed);
        assert_eq!(b.next().await.unwrap(), renamed);
        assert_eq!(other.next().await.unwrap(), renamed);
        assert_eq!(a.next().await.unwrap(), None);
        assert_eq!(b.next().await.unwrap(), None);
    });
    let urls: Vec<String> = mock.requests().into_iter().map(|r| r.url).collect();
    assert_eq!(urls, ["/w/cog/events", "/w/gear/events"]);
}
