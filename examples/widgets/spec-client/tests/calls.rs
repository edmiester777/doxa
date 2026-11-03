//! The client generated from the server's spec, sent through the real server router in-process.
//! It should behave as the shared-source client does.

use doxa::client::layer::{transport, Scoped};
use doxa::client::transport::RouterTransport;
use doxa::client::{CacheConfig, Fetch, Permission, Service};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;
use widgets_spec_client::*;

thread_local! {
    static SERVED: RefCell<Option<Scoped>> = const { RefCell::new(None) };
}

fn install(role: &str) -> Rc<Service> {
    let s = widgets_spec_client::service();
    SERVED.with(|g| g.borrow_mut().take());
    s.end_session();
    let router = RouterTransport::new(widgets_server::app(widgets_server::seeded()));
    let guard = s
        .layers()
        .push_scoped(transport(router.with_header("x-role", role)));
    SERVED.with(|g| *g.borrow_mut() = Some(guard));
    s.cache(CacheConfig::default().stale_time(Duration::from_secs(60)));
    s
}

#[tokio::test]
async fn a_route_is_called_by_its_key() {
    install("viewer");
    let widget = get_widget("sprocket").await.unwrap();
    assert_eq!(widget.id, 1);
    let key = WidgetKey {
        name: "gear".into(),
    };
    assert_eq!(get_widget(&key).await.unwrap().id, 2);
}

#[tokio::test]
async fn the_query_type_keeps_its_name() {
    install("viewer");
    let some = list_widgets(Filter {
        contains: Some("o".into()),
    })
    .await
    .unwrap();
    let names: Vec<&str> = some.iter().map(|w| w.name.as_str()).collect();
    assert_eq!(names, ["sprocket", "cog"]);
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
    rename_widget(
        "cog",
        Rename {
            name: "cog2".into(),
        },
    )
    .await
    .unwrap();
    let before = client.requests_sent();
    get_widget("cog").await.ok();
    doxa::client::task::run_until_stalled();
    assert!(client.requests_sent() > before);
}

#[tokio::test]
async fn a_dry_run_asks_the_real_guard() {
    install("viewer");
    assert_eq!(rename_widget::can("sprocket").await, Permission::Denied);
    install("editor");
    assert_eq!(rename_widget::can("sprocket").await, Permission::Allowed);
    assert_eq!(suggest_name::can().await, Permission::Unknown);
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
async fn bytes_attachments_and_multipart_reach_the_route() {
    install("editor");
    assert_eq!(*upload_photo("gear", vec![0u8; 512]).await.unwrap(), 512);
    let file = widget_label("gear").await.unwrap();
    assert_eq!(file.bytes, b"gear\n");
    let form = doxa::client::Multipart::new().text("title", "Q3");
    assert_eq!(*upload_files(form).await.unwrap(), ["title=2"]);
}

#[tokio::test]
async fn a_route_no_one_guards_is_called_too() {
    install("viewer");
    let status = suggest_name(Rename {
        name: "bolt".into(),
    })
    .await
    .unwrap();
    assert_eq!(status, 202);
    assert!(matches!(
        get_widget("nope").await.unwrap_err(),
        Fetch::NotFound(_)
    ));
}
