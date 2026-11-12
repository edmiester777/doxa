# Stories and the gallery

A story is a component in a particular state: loading, empty, streaming, broken. Write one as a plain function and `doxa gallery` shows them all side by side, live-reloading as you edit. It's Storybook, but your stories are Rust and the gallery comes with the framework.

## Write a story

Start with a component. This one lists a widget's events as the server streams them:

```rust
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
            {seen.get().is_empty().then(|| view! {
                <p class="muted">"Waiting for the server…"</p>
            })}
        </figure>
    }
}
```

Its stories put it in the states worth seeing:

```rust
use doxa::client::layer::{transport, Scoped};
use doxa::client::transport::{scripted, MockTransport};
use doxa::ui::{story, Story};

/// The feed as a server streams it, one event every 400 ms.
#[story]
pub fn feed_streaming() -> Story<View, Scoped> {
    let script = scripted::<WidgetEvent>(include_str!("../fixtures/feed.jsonl"))
        .every(Duration::from_millis(400));
    let guard = shop_api::service().layers().push_scoped(transport(script.transport()));
    Story(view! { <WidgetFeed name={"gear".to_owned()}/> }, guard)
}

/// The picker over the list the mock answers.
#[story]
pub fn picker() -> Story<View, Scoped> {
    let mock = MockTransport::new();
    mock.json(200, &widgets());
    let guard = shop_api::service().layers().push_scoped(transport(mock));
    Story(view! { <WidgetPicker on_open={|_: String| ()}/> }, guard)
}
```

A story returns its view, plus anything it wants kept alive while it's on screen. Here that's a scoped transport, so the component's real calls get scripted or mocked answers instead of a server. No backend needed.

`picker` renders `WidgetPicker`, which takes the list from `list_widgets` and draws a React counter above the buttons:

```rust
/// The widgets whose names contain `contains`; `on_open` gets the name picked.
#[component(export)]
pub async fn WidgetPicker(contains: Option<String>, on_open: impl Fn(String)) -> Result<View> {
    let widgets = list_widgets(Filter { contains }).await?;
    let picks = state(0u32);
    Ok(view! {
        <div class="picker">
            <Count total={widgets.len()} on_pick={move || picks.update(|n| *n += 1)}/>
            <p class="picks">{picks.get()}</p>
            {widgets.iter().map(|w| {
                let (name, open) = (w.name.clone(), on_open.clone());
                view! {
                    <button key={w.id} class="open" on:click={move || open(name.clone())}>
                        {&w.name}
                    </button>
                }
            }).collect::<View>()}
        </div>
    })
}

/// A React component from `ts/count.tsx`; `doxa build` bundles it.
#[react(module = "./ts/count.tsx", export = "Count")]
pub struct Count {
    pub total: usize,
    #[react(event)]
    pub on_pick: impl Fn(bool),
}
```

## Browse them

```sh
doxa gallery -p shop-web     # http://127.0.0.1:4710
```

You get a tree of stories by module and a canvas with phone, tablet and desktop sizes plus light and dark. The panel beneath shows the story's source. Next to it is a tab for each file the story is built from. `picker` gets `kit.rs` for `WidgetPicker`, `lib.rs` for `Count`, `ts/count.tsx` and the `widgets()` helper. The build finds these by following the names the story uses, through `use`, from item to item within your crate, along with the files they point at, such as a `#[react(module)]` or an `include_str!`. Edits patch into the running page.

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
