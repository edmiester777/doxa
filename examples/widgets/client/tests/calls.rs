//! The client stubs, sent through the real server router in-process.

use doxa::client::layer::{transport, Scoped};
use doxa::client::transport::RouterTransport;
use doxa::client::{CacheConfig, Cached, Fetch, Permission, Service};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;
use widgets_client::widgets::*;

thread_local! {
    static SERVED: RefCell<Option<Scoped>> = const { RefCell::new(None) };
}

/// Answer this thread's calls with `router`, as `role`, from an empty cache.
fn serve(router: RouterTransport, role: &str) -> Rc<Service> {
    let s = widgets_client::service();
    SERVED.with(|g| g.borrow_mut().take());
    s.end_session();
    let guard = s
        .layers()
        .push_scoped(transport(router.with_header("x-role", role)));
    SERVED.with(|g| *g.borrow_mut() = Some(guard));
    s
}

fn seeded() -> RouterTransport {
    RouterTransport::new(widgets_server::app(widgets_server::seeded()))
}

fn install(role: &str) -> Rc<Service> {
    let s = serve(seeded(), role);
    s.cache(CacheConfig::default().stale_time(Duration::from_secs(60)));
    s
}

#[tokio::test]
async fn a_route_is_called_like_a_function() {
    install("viewer");
    let widget = get_widget("sprocket").await.unwrap();
    assert_eq!(
        widget,
        Widget {
            id: 1,
            name: "sprocket".into()
        }
    );

    let key = WidgetKey {
        name: "gear".into(),
    };
    assert_eq!(get_widget(&key).await.unwrap().id, 2);
}

#[tokio::test]
async fn query_arguments_and_lists() {
    install("viewer");
    let all = list_widgets(Filter::default()).await.unwrap();
    assert_eq!(all.len(), 3);
    let some = list_widgets(Filter {
        contains: Some("o".into()),
    })
    .await
    .unwrap();
    assert_eq!(
        some.iter().map(|w| w.name.as_str()).collect::<Vec<_>>(),
        ["sprocket", "cog"]
    );
}

#[tokio::test]
async fn the_guards_404_is_not_found() {
    install("viewer");
    let err = get_widget("nope").await.unwrap_err();
    assert!(err.is_not_found(), "{err:?}");
}

#[tokio::test]
async fn the_routes_own_error_comes_back_typed() {
    install("editor");
    let err = rename_widget(
        "sprocket",
        Rename {
            name: "gear".into(),
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err.api(), Some(WidgetError::NameTaken(n)) if n == "gear"),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_refused_mutation_is_forbidden() {
    install("viewer");
    let err = rename_widget("sprocket", Rename { name: "x".into() })
        .await
        .unwrap_err();
    assert!(matches!(err, Fetch::Forbidden(_)), "{err:?}");
}

#[tokio::test]
async fn repeated_reads_are_served_from_the_cache() {
    let client = install("viewer");
    get_widget("cog").await.unwrap();
    get_widget("cog").await.unwrap();
    assert_eq!(client.requests_sent(), 1);
}

#[tokio::test]
async fn a_listed_or_renamed_widget_is_read_without_a_request() {
    let client = install("editor");
    list_widgets(Filter::default()).await.unwrap();
    assert_eq!(get_widget("gear").await.unwrap().id, 2);
    assert_eq!(client.requests_sent(), 1);

    rename_widget(
        "gear",
        Rename {
            name: "flange".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(get_widget("flange").await.unwrap().id, 2);
    assert_eq!(client.requests_sent(), 2);
}

#[tokio::test]
async fn a_mutation_marks_its_entity_stale() {
    let client = install("editor");
    get_widget("cog").await.unwrap();
    let renamed = rename_widget(
        "cog",
        Rename {
            name: "cog2".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(renamed.name, "cog2");
    let before = client.requests_sent();
    // Stale: served at once, revalidated in the background.
    get_widget("cog").await.ok();
    doxa::client::task::run_until_stalled();
    assert!(client.requests_sent() > before);
}

#[tokio::test]
async fn a_mutation_refetches_each_query_once_however_often_it_is_read() {
    let client = serve(seeded(), "editor");
    // The default stale time, and the server's `Cache-Control: private, no-cache`.
    get_widget("cog").await.unwrap();
    list_widgets(Filter::default()).await.unwrap();
    rename_widget(
        "gear",
        Rename {
            name: "gear2".into(),
        },
    )
    .await
    .unwrap();
    let before = client.requests_sent();
    for _ in 0..3 {
        get_widget("cog").await.unwrap();
        list_widgets(Filter::default()).await.unwrap();
        doxa::client::task::run_until_stalled();
    }
    assert_eq!(client.requests_sent(), before + 2);
    let names: Vec<String> = list_widgets(Filter::default())
        .await
        .unwrap()
        .iter()
        .map(|w| w.name.clone())
        .collect();
    assert_eq!(names, ["sprocket", "gear2", "cog"]);
}

#[tokio::test]
async fn a_read_returns_the_cached_value_itself() {
    install("viewer");
    let a = get_widget("cog").await.unwrap();
    let b = get_widget("cog").await.unwrap();
    assert!(Cached::ptr_eq(&a, &b));
}

#[tokio::test]
async fn identical_streams_share_one_connection() {
    let client = install("viewer");
    let mut a = widget_events("gear").await.unwrap();
    let mut b = widget_events("gear").await.unwrap();
    assert_eq!(client.requests_sent(), 1);
    let renamed = Some(WidgetEvent::Renamed {
        name: "gear".into(),
    });
    assert_eq!(a.next().await.unwrap(), renamed);
    assert_eq!(b.next().await.unwrap(), renamed);
}

#[tokio::test]
async fn a_probe_of_an_unguarded_route_is_unknown_and_never_runs_it() {
    let catalog = widgets_server::seeded();
    serve(
        RouterTransport::new(widgets_server::app(catalog.clone())),
        "viewer",
    );
    assert_eq!(suggest_name::can().await, Permission::Unknown);
    assert!(catalog.suggestions().is_empty());
    let status = suggest_name(Rename {
        name: "bolt".into(),
    })
    .await
    .unwrap();
    assert_eq!(status, 202);
    assert_eq!(catalog.suggestions(), ["bolt from viewer"]);
}

#[tokio::test]
async fn sse_events_arrive_decoded() {
    install("viewer");
    let mut events = widget_events("gear").await.unwrap();
    assert_eq!(
        events.next().await.unwrap(),
        Some(WidgetEvent::Renamed {
            name: "gear".into()
        })
    );
    assert_eq!(events.next().await.unwrap(), Some(WidgetEvent::Deleted));
    assert_eq!(events.next().await.unwrap(), None);
}

#[tokio::test]
async fn a_dry_run_asks_the_real_guard() {
    install("viewer");
    assert_eq!(rename_widget::can("sprocket").await, Permission::Denied);
    install("editor");
    assert_eq!(rename_widget::can("sprocket").await, Permission::Allowed);
    // The dry run never ran the handler.
    assert_eq!(get_widget("sprocket").await.unwrap().name, "sprocket");
}

#[tokio::test]
async fn an_attachment_arrives_with_its_type_and_name() {
    install("viewer");
    let file = widget_label("gear").await.unwrap();
    assert_eq!(file.bytes, b"gear\n");
    assert_eq!(file.content_type.as_deref(), Some("text/plain"));
    assert_eq!(file.filename.as_deref(), Some("gear label.txt"));
}

#[tokio::test]
async fn bytes_and_multipart_bodies_reach_the_route() {
    install("editor");
    assert_eq!(*upload_photo("gear", vec![0u8; 512]).await.unwrap(), 512);
    let form = doxa::client::Multipart::new().text("title", "Q3").bytes(
        "sheet",
        "q3.csv",
        "text/csv",
        b"a,b\n1,2\n".to_vec(),
    );
    let fields = upload_files(form).await.unwrap();
    assert_eq!(*fields, ["title=2", "sheet:q3.csv=8"]);
}
