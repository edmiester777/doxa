//! Components calling the server's routes, against scripted and mocked answers.

use std::time::Duration;

use doxa::client::layer::{transport, Scoped};
use doxa::client::transport::{scripted, MockTransport};
use doxa::ui::prelude::*;
use doxa::ui::story;
use shop_api::widgets::*;

use super::{widgets, Slow};
use crate::kit::WidgetPicker;
use crate::table::{Column, Table};

/// What happens to a widget, listed as the events arrive.
#[component]
pub fn WidgetFeed(name: String) -> View {
    let seen = state(Vec::<String>::new());
    effect(&name, async move |name: &String| {
        let mut events = widget_events(&WidgetKey { name: name.clone() }).await?;
        while let Some(ev) = events.next().await? {
            let line = match ev {
                WidgetEvent::Renamed { name } => format!("renamed to {name}"),
                WidgetEvent::Deleted => "deleted".to_owned(),
            };
            seen.update(|s| s.push(line));
        }
        Ok(())
    });
    view! {
        <figure class="card">
            <p class="eyebrow">{format!("Live · {name}")}</p>
            <ol class="feed">
                {seen.get().iter().map(|e| view! { <li>{e}</li> }).collect::<View>()}
            </ol>
            {seen.get().is_empty().then(|| view! { <p class="muted">"Waiting for the server…"</p> })}
        </figure>
    }
}

/// The feed as a server streams it, one event every 400 ms.
#[story]
pub fn feed_streaming() -> (View, Scoped) {
    let script = scripted::<WidgetEvent>(include_str!("../../fixtures/feed.jsonl"))
        .every(Duration::from_millis(400));
    let guard = shop_api::service()
        .layers()
        .push_scoped(transport(script.transport()));
    (view! { <WidgetFeed name={"gear".to_owned()}/> }, guard)
}

/// The picker over the list the mock answers.
#[story]
pub fn picker() -> (View, Scoped) {
    let mock = MockTransport::new();
    mock.json(200, &widgets());
    let guard = shop_api::service().layers().push_scoped(transport(mock));
    (view! { <WidgetPicker on_open={|_: String| ()}/> }, guard)
}

/// The picker while its list is on the way: `<Suspense>` shows the fallback for 1.5 s.
#[story]
pub fn picker_loading() -> (View, Scoped) {
    let slow = Slow(serde_json::json!(widgets()), Duration::from_millis(1500));
    let guard = shop_api::service().layers().push_scoped(transport(slow));
    let view = view! {
        <Suspense fallback={view! { <div class="skeleton" aria-busy="true"/> }}>
            <WidgetPicker on_open={|_: String| ()}/>
        </Suspense>
    };
    (view, guard)
}

/// One generic `Table`, its row type inferred from `rows`.
#[story]
pub fn widget_table() -> View {
    view! {
        <figure class="card flush">
            <Table
                rows={widgets()}
                columns={vec![
                    Column { header: "Id", cell: |w: &Widget| format!("#{}", w.id) },
                    Column { header: "Name", cell: |w: &Widget| w.name.clone() },
                    Column { header: "Letters", cell: |w: &Widget| w.name.len().to_string() },
                ]}
                row_key={|w: &Widget| w.id.to_string()}
            />
        </figure>
    }
}
