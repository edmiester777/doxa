//! What reaches the network: re-reads, revalidation, mutations, streams.

use std::cell::Cell;
use std::future::IntoFuture;
use std::rc::Rc;
use std::time::Duration;

use doxa_client::cache::{self, Observer};
use doxa_client::transport::MockTransport;
use doxa_client::{
    task, CacheConfig, Cached, Call, Client, ClientConfig, Granted, Json, Query, SseStream,
};
use doxa_wire::{Identity, Keyed, Method, RouteSpec};
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
