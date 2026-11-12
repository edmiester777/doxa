# Pages and components

doxa's UI is Rust compiled to wasm: components are functions, markup is `view!`, state is hooks, and a page is a component with a route. If you've written React, you already know the shape.

## A page

```rust
use doxa::ui::prelude::*;

#[page("/widgets/{name}", lazy)]
async fn WidgetPage(name: String) -> Result<View> {
    let key = WidgetKey { name };
    let widget = get_widget(&key).await?;
    title(format!("{} · Shop", widget.name));
    let editing = state(false);
    Ok(view! {
        <h1>{&widget.name}</h1>
        <Can route={rename_widget} args={&key}>
            <button on:click={move |_| editing.toggle()}>"Rename"</button>
        </Can>
        {editing.get().then(|| view! { <RenameForm widget={widget.clone()}/> })}
    })
}

#[doxa::start]
fn start() {
    let router = Router::new()
        .layout::<Shell>(|r| r.page::<WidgetsPage>().page::<WidgetPage>())
        .not_found(|| view! { <p>"No such page"</p> });
    App::new(router).mount("#app");
}
```

- `lazy` splits the page into its own wasm chunk, fetched when a link to it is hovered or on first visit.
- `<Can>` sends a [dry run](07-api-crates.md#call): the button appears only for callers the route would let through.
- A layout (`Shell`) stays mounted while pages change inside its `<Outlet/>`, and `<Link>` navigates without a reload.

## Forms that check like the server

```rust
#[component]
fn RenameForm(widget: Widget) -> View {
    let form = form(Rename { name: widget.name.clone() }).rules(rename_widget::check);
    let name = Field::new(form, "name", |r: &Rename| &r.name, |r| &mut r.name);
    let key = WidgetKey::from(&widget);
    let save = form.submit(async move |r: Rename| {
        let to = r.name.clone();
        let w = rename_widget(&key, r)
            .optimistic(move |w: &mut Widget| w.name = to.clone())
            .await?;
        navigate(WidgetPage::route(&w.name));
        Ok(())
    });
    view! {
        <input bind:value={name}/>
        {name.error().map(|e| view! { <p class="invalid">{e}</p> })}
        <button disabled={save.pending()} on:click={move |_| save.run()}>"Save"</button>
    }
}
```

`rename_widget::check` is the route's own validation, so field errors show as you type. `.optimistic` updates the cache at once and rolls back if the server says no.

## Typed query strings

```rust
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RunFilter { pub status: Option<RunStatus>, #[serde(default)] pub page: u32 }

#[page("/widgets/{name}/runs")]
fn RunsPage(name: String, #[query] filter: RunFilter) -> View { /* … */ }

let next = RunsPage::route(&name).query(&RunFilter { page: 2, ..filter.clone() });
set_query_as(|f: &mut RunFilter| f.page += 1);   // replaces the history entry
```

A query that doesn't parse shows the router's `not_found`, just like a bad path parameter.

## Components that compose

```rust
#[component]
pub fn Button(children: View, #[attrs] rest: Attrs) -> View {
    let class = doxa::tailwind::cn!["btn px-3", rest.class()];
    view! { <button type="button" class={class} {..rest}>{children}</button> }
}
```

- `#[attrs] rest` collects every attribute, `on:` handler and `use:` directive the caller passed, and `{..rest}` spreads them.
- `cn![]` (feature `tailwind`) drops Tailwind classes a later one overrides, so `<Button class="px-1">` wins over `px-3`.
- `class:active={on}` toggles one class, and `classes!["btn", (busy, "busy")]` joins the parts that apply.
- Components can be generic: `fn Table<T: Clone + 'static>(rows: Vec<T>, …)`, and `<Table rows={runs}/>` infers `T`.
- `use:` directives hook into an element's life, such as an exit animation or a FLIP move on reorder.

## Theme, storage, the usual

```rust
let dark = stored::<bool>("dark", || false);            // localStorage, synced across tabs
effect(&dark.get(), async |&d| { set_theme(if d { DARK } else { LIGHT }); Ok(()) });
```

## Testing like a user

The same pages render natively into an in-memory document, so tests run with `cargo test`, no browser needed:

```rust
let screen = Screen::app(shop_web::app());
screen.role(Role::Link).name("gear").click().await;
screen.label("Name").type_text("cog").await;
screen.role(Role::Button).name("Save").click().await;
screen.find_text("cog").await?;
```

Point the client at the real router with `RouterTransport`, and every call goes through your actual handlers and guards, in-process. `testing::fake::<Popover>(…)` stands in for a React island. The [shop's page tests](../../shop/web/tests/pages.rs) do all of this.
