//! The shop UI: pages that call the server's routes as functions.

use doxa::ui::prelude::*;
use doxa::ui::{form, Field};
use shop_api::widgets::*;

pub mod button;
pub mod icons;
pub mod interop;
pub mod kit;
pub mod motion;
pub mod runs;
pub mod stories;
pub mod table;
pub mod words;
use motion::{exit, flip};

/// The default look.
pub const LIGHT: Theme = Theme::new("light", &[("--bg", "#fff"), ("--fg", "#111")]);
/// The other look.
pub const DARK: Theme = Theme::new("dark", &[("--bg", "#111"), ("--fg", "#eee")]);

/// Everything the browser runs, ready to mount.
pub fn app() -> App {
    let router = Router::new()
        .layout::<Shell>(|r| {
            r.page::<WidgetsPage>()
                .page::<WidgetPage>()
                .page::<words::WordsPage>()
                .page::<icons::IconsPage>()
                .page::<interop::InteropPage>()
                .page::<runs::RunsPage>()
        })
        .not_found(|| view! { <p class="missing">"No such page"</p> });
    App::new(router).theme(LIGHT)
}

#[doxa::start]
fn start() {
    app().mount("#app");
}

/// The frame around every page; it stays mounted as pages change.
#[page("/")]
fn Shell() -> View {
    view! {
        <header>
            <Link to={WidgetsPage::route()}>"All widgets"</Link>
            <ThemeToggle/>
        </header>
        <main>
            <Outlet/>
        </main>
    }
}

/// Every widget, optionally filtered by `?contains=`.
#[page("/")]
async fn WidgetsPage(contains: Option<String>) -> Result<View> {
    let widgets = list_widgets(Filter { contains }).await?;
    let picks = state(0u32);
    Ok(view! {
        <h1>"Widgets"</h1>
        <Count total={widgets.len()} on_pick={move |_: bool| picks.update(|n| *n += 1)}/>
        <p class="picks">{picks.get()}</p>
        <ul>
            {widgets.iter().map(|w| view! {
                <WidgetRow key={w.id} widget={w.clone()}/>
            }).collect::<View>()}
        </ul>
    })
}

/// A React component from `ts/count.tsx`; `doxa build` bundles it.
#[react(module = "./ts/count.tsx", export = "Count")]
pub struct Count {
    pub total: usize,
    #[react(event)]
    pub on_pick: impl Fn(bool),
}

#[component]
fn WidgetRow(widget: Widget) -> View {
    view! {
        <li use:flip use:exit={"leaving"}>
            <Link to={WidgetPage::route(&widget.name)}>{&widget.name}</Link>
        </li>
    }
}

/// One widget, with a rename form for those allowed to rename it.
#[page("/widgets/{name}", lazy)]
async fn WidgetPage(name: String) -> Result<View> {
    let key = WidgetKey { name };
    let widget = get_widget(&key).await?;
    title(format!("{} · Widgets", widget.name));
    let editing = state(false);
    Ok(view! {
        <h1>{&widget.name}</h1>
        <Can route={rename_widget} args={&key}>
            <button class="edit" on:click={move |_| editing.toggle()}>"Rename"</button>
        </Can>
        {editing.get().then(|| view! { <RenameForm widget={widget.clone()}/> })}
    })
}

/// Checks the same rule as the server before sending.
#[component]
fn RenameForm(widget: Widget) -> View {
    let form = form(Rename {
        name: widget.name.clone(),
    })
    .rules(rename_widget::check);
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
        <input class="name" bind:value={name}/>
        {name.error().map(|e| view! { <p class="invalid">{e}</p> })}
        <button class="save" disabled={save.pending()} on:click={move |_| save.run()}>
            "Save"
        </button>
        {save.error().map(|e| view! { <p class="error">{e.to_string()}</p> })}
    }
}

/// Remembers the choice across visits and tabs.
#[component]
fn ThemeToggle() -> View {
    let dark = stored::<bool>("dark", || false);
    effect(&dark.get(), async |&d| {
        set_theme(if d { DARK } else { LIGHT });
        Ok(())
    });
    view! {
        <button class="theme" on:click={move |_| dark.update(|d| *d = !*d)}>
            {if dark.get() { "Light" } else { "Dark" }}
        </button>
    }
}
