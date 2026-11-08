//! Widgets shown alone in `doxa gallery`, each against a scripted or mocked server.

use std::time::Duration;

use doxa::client::layer::{transport, Scoped};
use doxa::client::transport::{scripted, MockTransport};
use doxa::ui::prelude::*;
use doxa::ui::story;
use shop_api::widgets::*;

use crate::kit::WidgetPicker;

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
        <ul class="feed">{seen.get().iter().map(|e| view! { <li>{e}</li> }).collect::<View>()}</ul>
    }
}

/// The feed as a server streams it, one event every 400 ms.
#[story]
pub fn feed_streaming() -> (View, Scoped) {
    let script = scripted::<WidgetEvent>(include_str!("../fixtures/feed.jsonl"))
        .every(Duration::from_millis(400));
    let guard = shop_api::service()
        .layers()
        .push_scoped(transport(script.transport()));
    (view! { <WidgetFeed name={"gear".to_owned()}/> }, guard)
}

/// The picker over a list the mock answers.
#[story]
pub fn picker_three() -> (View, Scoped) {
    let mock = MockTransport::new();
    let widgets: Vec<Widget> = ["sprocket", "gear", "cog"]
        .into_iter()
        .zip(1..)
        .map(|(name, id)| Widget {
            id,
            name: name.into(),
        })
        .collect();
    mock.json(200, &widgets);
    let guard = shop_api::service().layers().push_scoped(transport(mock));
    (view! { <WidgetPicker on_open={|_: String| ()}/> }, guard)
}
