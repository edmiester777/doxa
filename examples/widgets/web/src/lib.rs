//! The widgets UI: pages that call the server's routes as functions.

use doxa::ui::prelude::*;
use widgets_client::widgets::*;

/// The default look.
pub const LIGHT: Theme = Theme::new("light", &[("--bg", "#fff"), ("--fg", "#111")]);
/// The other look.
pub const DARK: Theme = Theme::new("dark", &[("--bg", "#111"), ("--fg", "#eee")]);

/// Everything the browser runs, ready to mount.
pub fn app() -> App {
    let router = Router::new()
        .page::<WidgetsPage>()
        .page::<WidgetPage>()
        .not_found(|| view! { <p class="missing">"No such page"</p> });
    App::new(router).theme(LIGHT)
}

#[doxa::start]
fn start() {
    app().mount("#app");
}

/// Every widget, optionally filtered by `?contains=`.
#[page("/", load = |p| list_widgets(Filter { contains: p.contains.clone() }))]
async fn WidgetsPage(contains: Option<String>) -> Result<View> {
    let widgets = list_widgets(Filter { contains }).await?;
    Ok(view! {
        <h1>"Widgets"</h1>
        <ThemeToggle/>
        <ul>
            {widgets.iter().map(|w| view! { <WidgetRow key={w.id} widget={w.clone()}/> }).collect::<View>()}
        </ul>
    })
}

#[component]
fn WidgetRow(widget: Widget) -> View {
    view! {
        <li>
            <Link to={WidgetPage::route(&widget.name)}>{&widget.name}</Link>
        </li>
    }
}

/// One widget, with a rename form for those allowed to rename it.
#[page("/widgets/{name}", load = |p| get_widget(&p.name))]
async fn WidgetPage(name: String) -> Result<View> {
    let key = WidgetKey { name };
    let widget = get_widget(&key).await?;
    let editing = state(false);
    Ok(view! {
        <h1>{&widget.name}</h1>
        <Can route={rename_widget} args={&key}>
            <button class="edit" on:click={move |_| editing.toggle()}>"Rename"</button>
        </Can>
        {editing.get().then(|| view! { <RenameForm widget={widget.clone()}/> })}
        <Link to={WidgetsPage::route()}>"All widgets"</Link>
    })
}

#[component]
fn RenameForm(widget: Widget) -> View {
    let name = state(widget.name.clone());
    let key = WidgetKey::from(&widget);
    let save = action(async move |name: String| {
        let w = rename_widget(&key, Rename { name: name.clone() })
            .optimistic(move |w: &mut Widget| w.name = name.clone())
            .await?;
        navigate(WidgetPage::route(&w.name));
        Ok(())
    });
    view! {
        <input class="name" bind:value={name}/>
        <button class="save" disabled={save.pending()} on:click={move |_| save.run(name.get())}>"Save"</button>
        {save.error().map(|e| view! { <p class="error">{e.to_string()}</p> })}
    }
}

#[component]
fn ThemeToggle() -> View {
    let dark = theme() == Some(DARK);
    view! {
        <button class="theme" on:click={move |_| set_theme(if dark { LIGHT } else { DARK })}>
            {if dark { "Light" } else { "Dark" }}
        </button>
    }
}
