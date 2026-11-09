# Stories and the gallery

A story is a component in a particular state: loading, empty, streaming, broken. Write one as a plain function and `doxa gallery` shows them all side by side, live-reloading as you edit. It's Storybook, but your stories are Rust and the gallery comes with the framework.

## Write a story

```rust
use doxa::client::layer::{transport, Scoped};
use doxa::client::transport::{scripted, MockTransport};
use doxa::ui::story;

/// The feed as a server streams it, one event every 400 ms.
#[story]
pub fn feed_streaming() -> (View, Scoped) {
    let script = scripted::<WidgetEvent>(include_str!("../fixtures/feed.jsonl"))
        .every(Duration::from_millis(400));
    let guard = shop_api::service().layers().push_scoped(transport(script.transport()));
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
```

A story returns its view, plus anything it wants kept alive while it's on screen. Here that's a scoped transport, so the component's real calls get scripted or mocked answers instead of a server. No backend needed.

## Browse them

```sh
doxa gallery -p shop-web     # http://127.0.0.1:4710
```

You get a tree of stories by module and a canvas with phone, tablet and desktop sizes plus light and dark, with the story's source beneath. Edits patch into the running page.

[Open the shop's gallery](https://edmiester777.github.io/doxa/gallery/) to try it: the stories above, plus React and npm interop, animations and a validated form.

## Test them

The same functions mount in tests, so a story doubles as a fixture:

```rust
let dom = MemDom::new();
let story = StoryRoot::mount_on(Rc::new(dom.clone()), dom.body(), shop_web::stories::data::feed_streaming);
dom.advance(Duration::from_millis(400));
assert_eq!(dom.text(dom.find("class", "feed").unwrap()), "renamed to gear-2");
```

## Publish them

```sh
doxa gallery -p shop-web --out site/gallery --base /my-repo/gallery/
```

`--out` writes the gallery as plain static files, ready for GitHub Pages or any static host. See [deploying](11-deploy.md).
