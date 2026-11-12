# React and npm, from Rust

You don't have to rewrite the JavaScript ecosystem in Rust. Bind an npm module and call it. Drop a React component into a `view!`. Ship your doxa components *to* a React app. `doxa build` installs the packages and bundles it all.

## Call a JS module

```rust
use doxa::ui::{npm, JsError};

#[npm(module = "cronstrue")]
extern "js" {
    #[npm(export = "toString")]
    pub fn describe(expr: &str, opts: &DescribeOpts) -> Result<String, JsError>;
}

#[npm(module = "./ts/render.js", lazy)]   // its own chunk, fetched on first call
extern "js" {
    pub async fn render(src: &str) -> Result<Rendered, JsError>;
}
```

Arguments and results cross through serde. A `Promise` becomes a future, and a thrown error becomes `JsError`. JS classes come along too:

```rust
#[npm(module = "./ts/interop.tsx")]
extern "js" {
    pub type Tally;
    #[npm(constructor)]
    pub fn new(start: u32) -> Tally;
    pub fn bump(this: &Tally) -> u32;
}
```

List what you import in `[package.metadata.doxa.npm]`:

```toml
[package.metadata.doxa.npm]
cronstrue = "^2"
react = "^19"
react-dom = "^19"
```

A dependency crate can list packages too, but they install only once the web crate lists them as well; until then the build names each one.

(This site colours its code that way: [highlight.js](https://highlightjs.org) bound with `#[npm]`.)

## Use a React component

```rust
#[react(module = "./ts/count.tsx", export = "Count")]
pub struct Count {
    pub total: usize,
    #[react(event)]
    pub on_pick: impl Fn(bool),
}

view! { <Count total={widgets.len()} on_pick={move |_: bool| picks.update(|n| *n += 1)}/> }
```

Props go over as JSON, and `#[react(event)]` callbacks come back into Rust. For richer props, `#[react(js)]` passes JS values untouched (plugin lists, class instances), `#[react(component)]` hands React a Rust component to render, and `#[react(element)]` passes a `View` as a React node. A dotted `rename = "components.letter"` targets a nested prop.

Each of these runs live in the gallery's [React stories](https://edmiester777.github.io/doxa/gallery/?show=react_star_rating), with its source beside it, down to the `#[react]` declaration and the `.tsx` it wraps.

## Icons

```rust
#[icons(from = "lucide-static/icons/{kebab}.svg")]   // resolved like an import, read at compile time
pub enum Icon { ChevronDown, Plus, Trash2 }

#[react(module = "lucide-react")]                // each variant a React island
pub enum Lucide { ChevronDown, Plus, #[react(export = "Trash2")] Trash }

view! { <button>{Icon::Plus.size(16)}"Add"</button> {Lucide::Trash.class("muted")} }
```

`from` resolves the way the JS bundle resolves an import, so package `exports` maps and `./` paths from the crate both work. Only the variants you list are compiled in, and one that doesn't resolve fails to compile.

## Ship components to a React app

Mark components `#[component(export)]` and build them as an npm package:

```sh
doxa build --lib -p shop-web     # writes target/doxa/lib
```

```jsx
import { WidgetPicker, WidgetTitle, configure } from "@shop/kit";

configure({
  navigate: (to, { replace }) => router.navigate(to, { replace }),
  invalidated: (entities) => entities.forEach((e) => queryClient.invalidateQueries({ queryKey: [e] })),
});

<WidgetPicker contains={filter} onOpen={setOpen} />
```

`configure` routes doxa's `<Link>`s through the host's router and tells react-query when a doxa mutation made its data stale.

## Talk to APIs elsewhere

A web crate whose APIs live on other servers lists them, and `doxa dev` forwards each prefix, streams and upgrades included:

```toml
[package.metadata.doxa.proxy]
"/api" = { to = "http://localhost:8080", env = "ORDERS_URL" }
"/reports" = { to = "http://localhost:3100", env = "REPORTS_URL", strip = true }
```
