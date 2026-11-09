//! The landing page.

use doxa::ui::prelude::*;

use crate::{highlight_all, outside, GuidePage, GuidesPage, VERSION};

const HERO: &str = r#"// api: the contract, built for the server *and* the browser
#[get("/api/widgets/{name}")]
pub async fn get_widget(widget: Grant<Widget>) -> Json<Widget>;

// server: implement it. The guard, the OpenAPI entry and the audit trail come along.
#[implements(shop_api::widgets::get_widget)]
async fn get_widget(widget: Granted<WidgetByName>) -> Json<Widget> {
    Json(widget.into_inner().into())
}

// browser: call it like a function. Cached, deduplicated, typed errors and all.
let gear = get_widget("gear").await?;"#;

const START: &str = "cargo install doxa-cli
doxa new shop && cd shop
doxa dev            # http://127.0.0.1:3000, rebuilt on save";

/// What a card says and which guide it opens.
const FEATURES: &[(&str, &str, &str)] = &[
    ("📜", "OpenAPI from signatures", "routes"),
    ("🔐", "OIDC, your own claims", "auth"),
    ("⚖️", "Cedar, per object", "authorization"),
    ("🧾", "Audit you can't forget", "audit"),
    ("🙈", "Secrets that won't leak", "secrets"),
    ("🔗", "Routes as functions", "api-crates"),
    ("🧱", "Pages and components", "pages"),
    ("⚛️", "React and npm, from Rust", "js-interop"),
    ("📚", "A story gallery", "stories"),
    ("🚀", "Ship one binary, or static", "deploy"),
];

#[page("/")]
pub fn Home() -> View {
    title("doxa · write the route once");
    effect((), async |_| highlight_all());
    view! {
        <section class="hero">
            <p class="badge">{format!("v{VERSION}")}</p>
            <h1>
                "Write the route once."
                <br/>
                <em>"Get everything else for free."</em>
            </h1>
            <p class="lede">
                "doxa is a full-stack Rust framework on axum. One signature gives you the handler, "
                "its OpenAPI docs, its auth guard, its audit trail, and a typed call the browser "
                "makes like any other function."
            </p>
            <div class="cta">
                <Link to={GuidePage::route("getting-started")} class="primary">"Get started"</Link>
                <a href={outside("/gallery/")}>"See the gallery"</a>
                <a href={outside("/api/")}>"Browse the API"</a>
            </div>
        </section>

        <section class="code">
            <pre>
                <code class="language-rust">{HERO}</code>
            </pre>
        </section>

        <section class="features">
            <h2>"Batteries, included and optional"</h2>
            <ul>
                {FEATURES.iter().map(|&(icon, name, slug)| view! {
                    <li key={slug}>
                        <Link to={GuidePage::route(slug)}>
                            <span class="icon">{icon}</span>
                            {name}
                        </Link>
                    </li>
                }).collect::<View>()}
            </ul>
        </section>

        <section class="start">
            <h2>"Thirty seconds to a running app"</h2>
            <pre>
                <code class="language-sh">{START}</code>
            </pre>
            <p>
                "Then read the "
                <Link to={GuidesPage::route()}>"guides"</Link>
                ", poke the components in the "
                <a href={outside("/gallery/")}>"gallery"</a>
                ", or try the example shop's routes in its "
                <a href={outside("/api/")}>"API reference"</a>
                "."
            </p>
        </section>

        <section class="name">
            <p>
                <em>"δόξα"</em>
                " (Greek): accepted teaching. The root of "
                <em>"orthodoxy"</em>
                " and "
                <em>"paradox"</em>
                ". This framework is opinionated so your handlers don't have to be."
            </p>
        </section>
    }
}
