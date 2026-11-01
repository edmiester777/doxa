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

#[test]
fn ending_the_session_clears_without_a_request() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"))
        .json(200, &widget(1, "cog"));
    let client = install(&mock, Duration::from_secs(60));
    let reset = Rc::new(Cell::new(0));
    let r = reset.clone();
    client.on_session_change(move || r.set(r.get() + 1));

    wait(get("cog")).unwrap();
    client.end_session();
    assert_eq!(reset.get(), 1, "singletons hear of it");
    assert_eq!(client.requests_sent(), 1, "nothing was sent to end it");
    wait(get("cog")).unwrap();
    assert_eq!(client.requests_sent(), 2, "the cached widget is gone");
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

/// What a route's stub does: look the response type's identity up by autoref.
fn by_identity<R: 'static>(call: Call<R>) -> Call<R>
where
    for<'a> &'a doxa_client::__private::EntityOf<R>: doxa_client::__private::IsEntity,
{
    use doxa_client::__private::{EntityOf, IsEntity as _};
    call.entity((&EntityOf::<R>::new()).entity())
}

#[test]
fn only_a_response_with_an_identity_is_filed_by_it() {
    use doxa_client::__private::{EntityOf, IsEntity as _, NotEntity as _};
    assert!((&EntityOf::<Json<Widget>>::new()).entity().is_some());
    assert!(EntityOf::<Json<String>>::new().entity().is_none());
}

#[test]
fn an_instance_in_a_fresh_list_is_read_without_a_request() {
    let mock = MockTransport::new();
    mock.json(200, &json!([widget(1, "cog"), widget(2, "gear")]))
        .json(200, &widget(3, "flange"));
    let client = install(&mock, Duration::from_secs(60));
    task::block_on(async {
        list().await.unwrap();
        assert_eq!(by_identity(get("gear")).await.unwrap().id, 2);
        assert_eq!(by_identity(get("flange")).await.unwrap().id, 3);
    });
    let urls: Vec<String> = mock.requests().into_iter().map(|r| r.url).collect();
    assert_eq!(urls, ["/w", "/w/flange"]);
    assert_eq!(client.requests_sent(), 2);
}

#[test]
fn a_stale_list_does_not_answer_an_instance() {
    let mock = MockTransport::new();
    mock.json(200, &json!([widget(2, "gear")]))
        .json(200, &widget(2, "gear"));
    let client = install(&mock, Duration::from_secs(60));
    wait(list()).unwrap();
    cache::invalidate_all::<WidgetByName>();
    wait(by_identity(get("gear"))).unwrap();
    assert_eq!(client.requests_sent(), 2);
}

#[test]
fn a_mutation_response_answers_the_renamed_instance() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "sprocket"));
    let client = install(&mock, Duration::from_secs(60));
    task::block_on(async {
        by_identity(rename("cog", "sprocket")).await.unwrap();
        assert_eq!(by_identity(get("sprocket")).await.unwrap().id, 1);
    });
    assert_eq!(client.requests_sent(), 1);
}

#[test]
fn a_failed_optimistic_update_rolls_back() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"))
        .json(409, &json!({ "error": "taken" }));
    install(&mock, Duration::from_secs(60));
    wait(get("cog")).unwrap();
    let renamed = rename("cog", "gear").optimistic(|w: &mut Widget| w.name = "gear".into());
    let pending = Rc::new(RefCell::new(None));
    let out = pending.clone();
    task::spawn(async move {
        *out.borrow_mut() = Some(renamed.await.is_err());
    });
    task::run_until_stalled();
    assert_eq!(*pending.borrow(), Some(true));
    assert_eq!(wait(get("cog")).unwrap().name, "cog");
}

#[test]
fn a_stale_query_sends_its_etag_and_keeps_its_value_on_304() {
    let mock = MockTransport::new();
    let tagged = vec![("etag".to_owned(), "\"v1\"".to_owned())];
    mock.respond(200, tagged, serde_json::to_vec(&widget(1, "cog")).unwrap())
        .respond(304, Vec::new(), Vec::new());
    let client = install(&mock, Duration::from_millis(20));
    let first = wait(get("cog")).unwrap();
    std::thread::sleep(Duration::from_millis(30));
    wait(get("cog")).unwrap();
    task::run_until_stalled();
    let again = wait(get("cog")).unwrap();
    let sent = mock.requests();
    assert_eq!(sent[1].header("if-none-match"), Some("\"v1\""));
    assert!(Cached::ptr_eq(&first, &again));
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

/// Answers from a queue of responses whose bodies may stream.
#[derive(Clone, Default)]
struct Scripted {
    queue: Rc<RefCell<std::collections::VecDeque<Response>>>,
    seen: Rc<RefCell<Vec<Request>>>,
}

impl Scripted {
    fn push(&self, status: u16, headers: Vec<(String, String)>, body: Body) -> &Self {
        self.queue.borrow_mut().push_back(Response {
            status,
            headers,
            body,
        });
        self
    }

    fn text(&self, status: u16, headers: Vec<(String, String)>, body: &str) -> &Self {
        self.push(status, headers, Body::Full(body.into()))
    }
}

impl Transport for Scripted {
    fn send(&self, request: Request) -> LocalBoxFuture<'static, Result<Response, String>> {
        self.seen.borrow_mut().push(request);
        let next = self.queue.borrow_mut().pop_front();
        Box::pin(async move { next.ok_or_else(|| "nothing queued".to_owned()) })
    }
}

/// A body that never ends, and records being dropped.
struct Open(Rc<Cell<bool>>);

impl futures_util::Stream for Open {
    type Item = Result<Vec<u8>, String>;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        self.0.set(true);
    }
}

const RENAMED: &str = "id: 1\ndata: {\"event\":\"renamed\",\"data\":{\"name\":\"x\"}}\n\n";

fn fast() -> doxa_client::Backoff {
    doxa_client::Backoff {
        initial: Duration::from_millis(1),
        max: Duration::from_millis(1),
    }
}

#[test]
fn a_reconnect_sends_the_current_credentials() {
    let script = Scripted::default();
    script.text(200, vec![], RENAMED).text(200, vec![], RENAMED);
    let token = Rc::new(RefCell::new("t1".to_owned()));
    let t = token.clone();
    ClientConfig::default()
        .bearer(move || Some(t.borrow().clone()))
        .transport(script.clone())
        .install();
    task::block_on(async {
        let mut s = events("cog").await.unwrap().reconnect(fast());
        s.next().await.unwrap();
        *token.borrow_mut() = "t2".into();
        s.next().await.unwrap();
    });
    let auth: Vec<_> = script
        .seen
        .borrow()
        .iter()
        .map(|r| r.header("authorization").map(str::to_owned))
        .collect();
    assert_eq!(auth, [Some("Bearer t1".into()), Some("Bearer t2".into())]);
}

#[test]
fn a_refused_reconnect_ends_the_stream_with_the_error() {
    let script = Scripted::default();
    script
        .text(200, vec![], RENAMED)
        .text(403, vec![], "{}")
        .text(200, vec![], RENAMED);
    ClientConfig::default().transport(script.clone()).install();
    task::block_on(async {
        let mut s = events("cog").await.unwrap().reconnect(fast());
        s.next().await.unwrap();
        let err = s.next().await.unwrap_err();
        assert_eq!(err.status(), Some(403), "{err:?}");
        assert_eq!(s.next().await.unwrap(), None);
    });
}

#[test]
fn a_session_change_closes_open_streams() {
    let script = Scripted::default();
    let dropped = Rc::new(Cell::new(false));
    script
        .text(200, session("a"), &widget(2, "gear").to_string())
        .push(200, vec![], Body::Stream(Box::pin(Open(dropped.clone()))))
        .text(200, session("b"), &widget(1, "cog").to_string());
    ClientConfig::default().transport(script.clone()).install();
    wait(get("gear")).unwrap();
    let mut s = wait(events("cog")).unwrap();
    wait(get("cog")).unwrap();
    assert!(dropped.get(), "the old session's connection is still open");
    assert!(wait(s.next()).is_err());
}

#[test]
fn a_reconnect_reports_its_session() {
    let script = Scripted::default();
    script
        .text(200, session("a"), &widget(2, "gear").to_string())
        .text(200, vec![], RENAMED)
        .text(200, session("b"), RENAMED)
        .text(200, session("b"), &widget(2, "gear").to_string());
    let client = ClientConfig::default().transport(script.clone()).install();
    let changes = Rc::new(Cell::new(0));
    let c = changes.clone();
    client.on_session_change(move || c.set(c.get() + 1));
    wait(get("gear")).unwrap();
    task::block_on(async {
        let mut s = events("cog").await.unwrap().reconnect(fast());
        s.next().await.unwrap();
        assert!(s.next().await.is_err());
    });
    assert_eq!(changes.get(), 1);
    wait(get("gear")).unwrap();
    assert_eq!(script.seen.borrow().len(), 4);
}
