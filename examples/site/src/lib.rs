//! doxa's own site, built with doxa: a landing page and the guides.

use doxa::ui::prelude::*;
use doxa::ui::{href, npm, DangerousHtml};

mod home;

/// One guide, compiled from `guides/*.md` by `build.rs`.
pub struct Guide {
    pub slug: &'static str,
    pub title: &'static str,
    pub blurb: &'static str,
    pub html: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/guides.rs"));

/// The release this site documents: the workspace's version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[npm(module = "./ts/highlight.js")]
extern "js" {
    /// Colour every code block on the page not yet coloured.
    #[npm(export = "highlightAll")]
    fn highlight_all();
}

/// Everything the browser runs, ready to mount.
pub fn app() -> App {
    let router = Router::new()
        .layout::<Shell>(|r| {
            r.page::<home::Home>()
                .page::<GuidesPage>()
                .page::<GuidePage>()
        })
        .not_found(|| view! { <NotFound/> });
    App::new(router)
}

#[doxa::start]
fn start() {
    app().mount("#app");
}

/// A page outside the app's router: the static gallery or API reference beside it.
fn outside(path: &'static str) -> Route {
    href(&Route::from(path))
}

#[page("/")]
fn Shell() -> View {
    view! {
        <header class="top">
            <Link to={home::Home::route()} class="brand">
                <span class="mark">"δ"</span>
                "doxa"
            </Link>
            <nav>
                <Link to={GuidesPage::route()} active_class="on">"Guides"</Link>
                <a href={outside("/gallery/")}>"Gallery"</a>
                <a href={outside("/api/")}>"API"</a>
                <a href="https://github.com/edmiester777/doxa" class="gh">"GitHub"</a>
            </nav>
        </header>
        <main>
            <Outlet/>
        </main>
        <footer>
            <p>
                {format!("doxa {VERSION} · Apache-2.0 · ")}
                <a href="https://github.com/edmiester777/doxa">"source"</a>
                " · built with doxa, naturally"
            </p>
        </footer>
    }
}

/// Every guide, in reading order.
#[page("/guides")]
fn GuidesPage() -> View {
    title("Guides · doxa");
    view! {
        <section class="guides">
            <h1>"Guides"</h1>
            <p class="lede">
                "Short, runnable, in order. Start at the top or jump to what you need."
            </p>
            <ol class="cards">
                {GUIDES.iter().map(|g| view! {
                    <li key={g.slug}>
                        <Link to={GuidePage::route(g.slug)}>
                            <h3>{g.title}</h3>
                            <p>{g.blurb}</p>
                        </Link>
                    </li>
                }).collect::<View>()}
            </ol>
        </section>
    }
}

/// One guide, beside the list of all of them.
#[page("/guides/{slug}")]
fn GuidePage(slug: String) -> View {
    let Some(at) = GUIDES.iter().position(|g| g.slug == slug) else {
        return view! { <NotFound/> };
    };
    let guide = &GUIDES[at];
    title(format!("{} · doxa", guide.title));
    effect(&slug, async |_: &String| highlight_all());
    let next = GUIDES.get(at + 1);
    view! {
        <div class="guide">
            <aside>
                <ol>
                    {GUIDES.iter().map(|g| view! {
                        <li key={g.slug}>
                            <Link to={GuidePage::route(g.slug)} active_class="on" exact={true}>
                                {g.title}
                            </Link>
                        </li>
                    }).collect::<View>()}
                </ol>
            </aside>
            <article>
                <h1>{guide.title}</h1>
                <div class="prose" on:click={follow} inner_html={DangerousHtml::trust(guide.html)}/>
                {next.map(|n| view! {
                    <Link to={GuidePage::route(n.slug)} class="next">
                        <span>"Next"</span>
                        {n.title}
                    </Link>
                })}
            </article>
        </div>
    }
}

/// Send a plain click on a guide's link to another page of the site through the router.
#[cfg_attr(not(target_arch = "wasm32"), allow(unused_variables))]
fn follow(e: Event) {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast;
        if e.button() != 0 || e.ctrl_key() || e.meta_key() || e.shift_key() || e.alt_key() {
            return;
        }
        let Some(a) = e
            .target()
            .and_then(|n| n.raw())
            .and_then(|n| n.dyn_into::<web_sys::Element>().ok())
            .and_then(|el| el.closest("a[href]").ok().flatten())
            .and_then(|a| a.dyn_into::<web_sys::HtmlAnchorElement>().ok())
        else {
            return;
        };
        let here = web_sys::window().map(|w| w.location());
        let same_origin = here.and_then(|l| l.origin().ok()) == Some(a.origin());
        let base = href(&Route::from("/"))
            .as_str()
            .trim_end_matches('/')
            .to_owned();
        let Some(path) = a.pathname().strip_prefix(&base).map(str::to_owned) else {
            return;
        };
        if same_origin && path.starts_with("/guides/") {
            e.prevent_default();
            navigate(Route::from(path));
        }
    }
}

#[component]
fn NotFound() -> View {
    view! {
        <section class="missing">
            <h1>"404"</h1>
            <p>"No route matched. Even the router is surprised."</p>
            <Link to={home::Home::route()}>"Back home"</Link>
        </section>
    }
}
