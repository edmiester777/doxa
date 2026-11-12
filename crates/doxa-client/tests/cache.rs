//! What reaches the network: cached and uncached reads, mutations, streams.

use std::cell::{Cell, RefCell};
use std::future::IntoFuture;
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::Duration;

use doxa_client::cache::{self, Observer};
use doxa_client::layer::{bearer, layers, transport};
use doxa_client::transport::{Body, MockTransport, Request, Response, Transport};
use doxa_client::{
    service, task, Cached, CachedCall, Call, Granted, Json, Permission, Probe, Query, Service,
    SseOnce, SseStream,
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
        invalidates: true,
        package: "",
    }
}

static GET: RouteSpec = route(Method::Get, "/w/{name}");
static LIST: RouteSpec = route(Method::Get, "/w");
static RENAME: RouteSpec = route(Method::Patch, "/w/{name}");
static EVENTS: RouteSpec = route(Method::Get, "/w/{name}/events");
static SEARCH: RouteSpec = RouteSpec {
    invalidates: false,
    ..route(Method::Post, "/w/search")
};

const TTL: Duration = Duration::from_secs(60);

#[derive(Default, Serialize)]
struct Filter {}

fn get(name: &str) -> Call<Json<Widget>> {
    Call::new(&GET).arg::<Granted<WidgetByName>, _>(name)
}

fn cget(name: &str) -> CachedCall<Json<Widget>> {
    get(name).cache(TTL)
}

fn list() -> Call<Json<Vec<Widget>>> {
    Call::new(&LIST).arg::<Query<Filter>, _>(Filter {})
}

fn clist() -> CachedCall<Json<Vec<Widget>>> {
    list().cache(TTL)
}

fn rename(name: &str, to: &str) -> Call<Json<Widget>> {
    Call::new(&RENAME)
        .arg::<Granted<WidgetByName>, _>(name)
        .arg::<Json<serde_json::Value>, _>(json!({ "name": to }))
}

fn widget(id: u32, name: &str) -> serde_json::Value {
    json!({ "id": id, "name": name })
}

fn serve(t: impl Transport) -> Rc<Service> {
    let s = service("");
    s.layers().push(transport(t));
    s
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
    let client = serve(manual.clone());
    let changes = Rc::new(Cell::new(0));
    let c = changes.clone();
    client.on_session_change(move || c.set(c.get() + 1));

    spawn(cget("gear"));
    manual.answer(0, 200, Some("a"), widget(2, "gear"));
    spawn(cget("cog"));
    spawn(clist());
    manual.answer(2, 200, Some("b"), json!([]));
    assert_eq!(changes.get(), 1);
    manual.answer(1, 200, Some("a"), widget(1, "old"));
    assert_eq!(changes.get(), 1, "the old epoch came back");

    // The dropped `cog` call is retried in the new session.
    assert_eq!(manual.urls(), ["/w/gear", "/w/cog", "/w", "/w/cog"]);
    manual.answer(3, 200, Some("b"), widget(1, "cog"));
    assert_eq!(wait(cget("cog")).unwrap().name, "cog");
    wait(clist()).unwrap();
    assert_eq!(changes.get(), 1);
    assert_eq!(manual.urls().len(), 4);
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
    let client = serve(mock.clone());
    let can = || Probe::new(&GET).arg::<Granted<WidgetByName>, _>("cog");

    assert_eq!(wait(can()), Permission::Denied);
    wait(cget("cog")).unwrap();
    assert_eq!(
        wait(can()),
        Permission::Allowed,
        "signing in kept the anonymous answer"
    );
    assert!(wait(clist()).is_err());
    assert!(
        wait(cget("cog")).is_err(),
        "signing out kept the user's data"
    );
    assert_eq!(client.requests_sent(), 5);
}

#[test]
fn ending_the_session_clears_without_a_request() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"))
        .json(200, &widget(1, "cog"));
    let client = serve(mock.clone());
    let reset = Rc::new(Cell::new(0));
    let r = reset.clone();
    client.on_session_change(move || r.set(r.get() + 1));

    wait(cget("cog")).unwrap();
    client.end_session();
    assert_eq!(reset.get(), 1, "singletons hear of it");
    assert_eq!(client.requests_sent(), 1, "nothing was sent to end it");
    wait(cget("cog")).unwrap();
    assert_eq!(client.requests_sent(), 2, "the cached widget is gone");
}

#[derive(Default)]
struct Renders(Cell<u32>);

impl Observer for Renders {
    fn changed(&self) {
        self.0.set(self.0.get() + 1);
    }
}

#[test]
fn an_uncached_query_is_sent_every_time() {
    let mock = MockTransport::new();
    for _ in 0..3 {
        mock.json(200, &widget(1, "cog"));
    }
    let client = serve(mock.clone());
    task::block_on(async {
        let w: Widget = get("cog").await.unwrap();
        assert_eq!(w.name, "cog");
        cget("cog").await.unwrap();
        get("cog").await.unwrap();
    });
    assert_eq!(
        client.requests_sent(),
        3,
        "only the cached call files its answer"
    );
}

#[test]
fn re_reading_a_fresh_cached_query_sends_nothing() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"));
    let client = serve(mock.clone());
    task::block_on(async {
        for _ in 0..5 {
            assert_eq!(cget("cog").await.unwrap().name, "cog");
        }
    });
    assert_eq!(client.requests_sent(), 1);
}

#[test]
fn an_expired_answer_is_fetched_again() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"))
        .json(200, &widget(1, "cog2"));
    let client = serve(mock.clone());
    let short = || get("cog").cache(Duration::from_millis(20));
    wait(short()).unwrap();
    wait(short()).unwrap();
    std::thread::sleep(Duration::from_millis(30));
    assert_eq!(wait(short()).unwrap().name, "cog2");
    wait(short()).unwrap();
    assert_eq!(client.requests_sent(), 2);
}

#[test]
fn a_cached_value_is_shared_until_it_changes() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"))
        .json(200, &widget(1, "cog2"));
    serve(mock.clone());
    let a = wait(cget("cog")).unwrap();
    let b = wait(cget("cog")).unwrap();
    assert!(Cached::ptr_eq(&a, &b));
    cache::invalidate_all::<WidgetByName>();
    let c = wait(cget("cog")).unwrap();
    assert!(!Cached::ptr_eq(&a, &c));
    assert_eq!(c.name, "cog2");
}

#[test]
fn concurrent_cached_calls_share_one_request() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"));
    let client = serve(mock.clone());
    let (a, b) = task::block_on(async {
        futures_util::future::join(cget("cog").into_future(), cget("cog").into_future()).await
    });
    assert!(Cached::ptr_eq(&a.unwrap(), &b.unwrap()));
    assert_eq!(client.requests_sent(), 1);
}

#[test]
fn a_mutation_refetches_each_affected_query_once_and_tells_readers() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"))
        .json(200, &json!([widget(1, "cog"), widget(2, "gear")]))
        .json(200, &widget(1, "sprocket"))
        .json(200, &widget(1, "sprocket"))
        .json(200, &json!([widget(1, "sprocket"), widget(2, "gear")]));
    let client = serve(mock.clone());
    let renders = Rc::new(Renders::default());
    cache::set_observer(Some(renders.clone()));
    task::block_on(async {
        cget("cog").await.unwrap();
        clist().await.unwrap();
        rename("cog", "sprocket").await.unwrap();
    });
    assert_eq!(client.requests_sent(), 3);
    assert_eq!(renders.0.get(), 1);
    // Every re-render after the mutation reads both queries again.
    for _ in 0..4 {
        task::block_on(async {
            cget("cog").await.unwrap();
            clist().await.unwrap();
        });
    }
    cache::set_observer(None);
    assert_eq!(client.requests_sent(), 5);
    let names: Vec<String> = wait(clist())
        .unwrap()
        .iter()
        .map(|w| w.name.clone())
        .collect();
    assert_eq!(names, ["sprocket", "gear"]);
}

#[test]
fn a_post_that_only_reads_leaves_cached_answers_fresh_and_is_sent_each_time() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"))
        .json(200, &widget(1, "cog"))
        .json(200, &widget(1, "cog"));
    let client = serve(mock.clone());
    let search = || Call::<Json<Widget>>::new(&SEARCH);
    task::block_on(async {
        cget("cog").await.unwrap();
        search().cache(TTL).await.unwrap();
        search().await.unwrap();
        cget("cog").await.unwrap();
    });
    assert_eq!(
        client.requests_sent(),
        3,
        "a POST is never answered from the cache"
    );
}

#[test]
fn a_host_hears_of_mutations_and_its_own_invalidations_stay_quiet() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"))
        .json(200, &widget(1, "sprocket"))
        .json(200, &widget(1, "cog"));
    let client = serve(mock.clone());
    let heard = Rc::new(RefCell::new(Vec::new()));
    let log = heard.clone();
    cache::on_invalidated(move |e| log.borrow_mut().push(e.join(",")));
    wait(cget("cog")).unwrap();
    wait(rename("cog", "sprocket")).unwrap();
    assert_eq!(*heard.borrow(), ["Widget"]);
    cache::invalidate_entities(&["Widget"]);
    assert_eq!(*heard.borrow(), ["Widget"]);
    wait(cget("cog")).unwrap();
    assert_eq!(
        client.requests_sent(),
        3,
        "the mutation dropped the cached cog"
    );
}

#[test]
fn invalidating_one_key_leaves_other_instances_fresh() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"))
        .json(200, &widget(2, "gear"))
        .json(200, &json!([]))
        .json(200, &widget(1, "cog"))
        .json(200, &json!([]));
    let client = serve(mock.clone());
    let read_all = || {
        task::block_on(async {
            cget("cog").await.unwrap();
            cget("gear").await.unwrap();
            clist().await.unwrap();
        });
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
    let client = serve(mock.clone());
    let renders = Rc::new(Renders::default());
    cache::set_observer(Some(renders.clone()));
    task::block_on(async {
        cget("cog").await.unwrap();
        clist().await.unwrap();
    });
    cache::set_observer(None);
    cache::apply::<Widget>(&WidgetKey { name: "cog".into() }, |w| w.id = 9);
    assert_eq!(renders.0.get(), 1);
    task::block_on(async {
        assert_eq!(cget("cog").await.unwrap().id, 9);
        assert_eq!(clist().await.unwrap()[0].id, 9);
        assert_eq!(clist().await.unwrap()[1].id, 2);
    });
    assert_eq!(client.requests_sent(), 2);
}

#[test]
fn a_failed_optimistic_update_rolls_back() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"))
        .json(409, &json!({ "error": "taken" }));
    serve(mock.clone());
    wait(cget("cog")).unwrap();
    let renamed = rename("cog", "gear").optimistic(|w: &mut Widget| w.name = "gear".into());
    let pending = Rc::new(RefCell::new(None));
    let out = pending.clone();
    task::spawn(async move {
        *out.borrow_mut() = Some(renamed.await.is_err());
    });
    task::run_until_stalled();
    assert_eq!(*pending.borrow(), Some(true));
    assert_eq!(wait(cget("cog")).unwrap().name, "cog");
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
    serve(mock.clone());
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
    let _auth = layers().push_scoped(bearer(move || Some(t.borrow().clone())));
    serve(script.clone());
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
    serve(script.clone());
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
    serve(script.clone());
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
    let client = serve(script.clone());
    let changes = Rc::new(Cell::new(0));
    let c = changes.clone();
    client.on_session_change(move || c.set(c.get() + 1));
    wait(cget("gear")).unwrap();
    task::block_on(async {
        let mut s = events("cog").await.unwrap().reconnect(fast());
        s.next().await.unwrap();
        assert!(s.next().await.is_err());
    });
    assert_eq!(changes.get(), 1);
    wait(cget("gear")).unwrap();
    assert_eq!(
        script.seen.borrow().len(),
        4,
        "the new session dropped the cached gear"
    );
}

/// Ends the session from inside the second send, as a sign-out on a 401 would.
struct SignsOut(Scripted);

impl Transport for SignsOut {
    fn send(&self, request: Request) -> LocalBoxFuture<'static, Result<Response, String>> {
        if self.0.seen.borrow().len() == 1 {
            service("").end_session();
        }
        self.0.send(request)
    }
}

#[test]
fn ending_the_session_while_a_stream_reconnects_closes_it() {
    let script = Scripted::default();
    script.text(200, vec![], RENAMED).text(200, vec![], RENAMED);
    serve(SignsOut(script.clone()));
    task::block_on(async {
        let mut s = events("cog").await.unwrap().reconnect(fast());
        s.next().await.unwrap();
        assert!(s.next().await.is_err());
    });
}

static TURN: RouteSpec = route(Method::Post, "/w/{name}/turns");

fn turn(name: &str) -> Call<SseOnce<Event>> {
    Call::new(&TURN).arg::<Granted<WidgetByName>, _>(name)
}

#[test]
fn each_post_stream_is_its_own_request() {
    let script = Scripted::default();
    script.text(200, vec![], RENAMED).text(200, vec![], RENAMED);
    serve(script.clone());
    task::block_on(async {
        let mut a = turn("cog").await.unwrap();
        let mut b = turn("cog").await.unwrap();
        assert!(a.next().await.unwrap().is_some());
        assert!(b.next().await.unwrap().is_some());
    });
    assert_eq!(script.seen.borrow().len(), 2);
}

#[test]
fn a_post_stream_invalidates_its_entities() {
    let mock = MockTransport::new();
    mock.json(200, &widget(1, "cog"))
        .respond(200, vec![], RENAMED.into())
        .json(200, &widget(1, "cog"));
    serve(mock.clone());
    wait(cget("cog")).unwrap();
    wait(turn("cog")).unwrap();
    wait(cget("cog")).unwrap();
    assert_eq!(mock.requests().len(), 3);
}

#[test]
fn dropping_a_post_stream_ends_its_request() {
    let script = Scripted::default();
    let dropped = Rc::new(Cell::new(false));
    script.push(200, vec![], Body::Stream(Box::pin(Open(dropped.clone()))));
    serve(script.clone());
    let s = wait(turn("cog")).unwrap();
    assert!(!dropped.get());
    drop(s);
    assert!(dropped.get());
}

#[test]
fn a_post_stream_from_an_old_session_fails_without_being_resent() {
    let manual = Manual::default();
    serve(manual.clone());
    spawn(get("gear"));
    manual.answer(0, 200, Some("a"), widget(2, "gear"));
    let failed = Rc::new(Cell::new(false));
    let f = failed.clone();
    task::spawn(async move { f.set(turn("cog").await.is_err()) });
    task::run_until_stalled();
    spawn(list());
    manual.answer(2, 200, Some("b"), json!([]));
    manual.answer(1, 200, Some("a"), json!(null));
    assert!(failed.get());
    assert_eq!(manual.urls(), ["/w/gear", "/w/cog/turns", "/w"]);
}
