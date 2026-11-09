//! A form that runs the server's own validation rule before it sends.

use std::time::Duration;

use doxa::client::layer::{transport, Scoped};
use doxa::client::transport::{Request, Response, Transport};
use doxa::ui::prelude::*;
use doxa::ui::{form, story, Field};
use futures::future::LocalBoxFuture;
use shop_api::widgets::*;

use super::Slow;

/// Rename `widget`, checked by the same `garde` rule as `rename_widget` on the server.
#[component]
pub fn RenameCard(widget: Widget) -> View {
    let saved = state(None::<String>);
    let form = form(Rename {
        name: widget.name.clone(),
    })
    .rules(rename_widget::check);
    let name = Field::new(form, "name", |r: &Rename| &r.name, |r| &mut r.name);
    let key = WidgetKey::from(&widget);
    let save = form.submit(async move |r: Rename| {
        let w = rename_widget(&key, r).await?;
        saved.set(Some(w.name.clone()));
        Ok(())
    });
    view! {
        <figure class="card">
            <p class="eyebrow">"Validated with the server's rule"</p>
            <label class="field">
                <span>"Name"</span>
                <input class="name" bind:value={name} placeholder="1 to 40 characters"/>
            </label>
            {name.error().map(|e| view! { <p class="invalid">{e}</p> })}
            <button class="btn save" disabled={save.pending()} on:click={move |_| save.run()}>
                {if save.pending() { "Saving…" } else { "Save" }}
            </button>
            {save.error().map(|e| view! { <p class="invalid">{e.to_string()}</p> })}
            {saved.get().map(|n| view! { <p class="saved">{format!("Saved as {n}")}</p> })}
        </figure>
    }
}

/// A server that renames whatever it is asked to, after `.0`.
struct Echo(Duration);

impl Transport for Echo {
    fn send(&self, request: Request) -> LocalBoxFuture<'static, Result<Response, String>> {
        let rename: Option<Rename> = (request.body.as_ref())
            .and_then(|b| b.bytes())
            .and_then(|b| serde_json::from_slice(b).ok());
        let name = rename.map_or_else(String::new, |r| r.name);
        Slow(serde_json::json!(Widget { id: 2, name }), self.0).send(request)
    }
}

/// Clear the name and the rule fails before anything is sent; save and the button waits.
#[story]
pub fn rename_form() -> (View, Scoped) {
    let guard = shop_api::service()
        .layers()
        .push_scoped(transport(Echo(Duration::from_millis(800))));
    let gear = Widget {
        id: 2,
        name: "gear".into(),
    };
    (view! { <RenameCard widget={gear}/> }, guard)
}
