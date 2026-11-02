//! # doxa
//!
//! Facade crate for the doxa family. Enable only the features you need:
//!
//! | Feature | Crate | What you get |
//! |---------|-------|--------------|
//! | `docs` (default) | `doxa-docs` | [`ApiDocBuilder`], Scalar UI, [`ProblemDetails`], OpenAPI routing |
//! | `macros` (default) | `doxa-macros` | `#[derive(ApiError)]`, `#[derive(SseEvent)]`, `#[get]`/`#[post]`/… |
//! | `docs-scalar` (default) | `doxa-docs` | Scalar API reference UI |
//! | `protected` | `doxa-protected` | `ProtectedString` — zeroize-on-drop secret type |
//! | `audit` | `doxa-audit` | Append-only audit logging primitives |
//! | `auth` | `doxa-auth` | OIDC / JWT auth middleware with Cedar policy integration |
//! | `policy` | `doxa-policy` | Cedar-based authorization policy engine |
//! | `client` | `doxa-client` | Call routes from the browser as async functions |
//! | `ui` | `doxa-ui` | Components, `view!`, hooks and a router, rendered in the browser |
//! | `react` | `doxa-ui` | `#[react]`: React components used inside `view!` |
//! | `embed` | `doxa-docs` | `dist!()` compiles the built SPA into the binary |
//! | `full` | all of the above | Everything |
//!
//! A crate whose `build.rs` calls `doxa_role::client()` sees every route as a
//! typed call; `doxa::prelude!()` brings in the names for whichever half it is.
//!
//! ```toml
//! doxa = "0.1"
//! doxa = { version = "0.1", features = ["auth", "policy"] }
//! doxa = { version = "0.1", features = ["full"] }
//! ```

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

#[cfg(all(feature = "docs", not(target_arch = "wasm32")))]
pub use doxa_docs::*;

#[cfg(all(feature = "docs", not(target_arch = "wasm32")))]
pub use doxa_docs::dist;

/// Types the server and its browser client agree on.
pub use doxa_wire as wire;

/// Zeroize-on-drop secret string type with `[REDACTED]` Debug/Display.
#[cfg(feature = "protected")]
pub use doxa_protected as protected;

/// SOC 2-flavored append-only audit logging primitives.
#[cfg(all(feature = "audit", not(target_arch = "wasm32")))]
pub use doxa_audit as audit;

/// Provider-agnostic OIDC / JWT auth middleware with Cedar policy integration.
#[cfg(all(feature = "auth", not(target_arch = "wasm32")))]
pub use doxa_auth as auth;

/// Cedar-based authorization policy engine.
#[cfg(all(feature = "policy", not(target_arch = "wasm32")))]
pub use doxa_policy as policy;

#[cfg(any(feature = "macros", feature = "client"))]
pub use doxa_macros::{client, client_only, prelude, server, server_only, service, Identity};

/// The server half: what `doxa::prelude!()` brings in where the crate is the server.
#[cfg(all(feature = "docs", feature = "macros", not(target_arch = "wasm32")))]
pub mod server {
    /// Names a shared route file needs when compiled as the server.
    pub mod prelude {
        pub use crate::{
            asset, capability, client, client_only, delete, get, operation, patch, post, put,
            server, server_only, Actions, ApiError, Attachment, Identity, IntoParams,
            PolicyResource, SseEvent, SseStream, ToSchema,
        };
        pub use axum::extract::{Extension, Form, Path, Query, State};
        pub use axum::http::StatusCode;
        pub use axum::Json;
        pub use serde::{Deserialize, Serialize};

        #[cfg(feature = "auth")]
        pub use doxa_auth::{route_key, Cap, Granted, Many, One, Require};
    }
}

/// Components, hooks and routing for the browser.
#[cfg(feature = "ui")]
pub use doxa_ui as ui;

#[cfg(feature = "ui")]
pub use doxa_ui::start;

/// Every prop given compiles:
///
/// ```
/// use doxa::ui::prelude::*;
/// #[component]
/// fn Row(name: String) -> View { view! { <li>{name}</li> } }
/// let _ = view! { <Row name="a"/> };
/// ```
///
/// A required prop left out is "`<Row>` is missing the `name` prop":
///
/// ```compile_fail
/// use doxa::ui::prelude::*;
/// #[component]
/// fn Row(name: String) -> View { view! { <li>{name}</li> } }
/// let _ = view! { <Row/> };
/// ```
///
/// A prop named anything but `key` compiles:
///
/// ```
/// use doxa::ui::prelude::*;
/// #[component]
/// fn Row(id: u32) -> View { view! { <li>{id}</li> } }
/// ```
///
/// `key` is reserved for list identity:
///
/// ```compile_fail
/// use doxa::ui::prelude::*;
/// #[component]
/// fn Row(key: u32) -> View { view! { <li>{key}</li> } }
/// ```
///
/// Spawning from an event handler compiles:
///
/// ```
/// use doxa::ui::prelude::*;
/// #[component]
/// fn Ticker() -> View {
///     let tick = move |_| doxa::client::task::spawn(async {});
///     view! { <button on:click={tick}>"tick"</button> }
/// }
/// ```
///
/// Spawning in the render itself asks for `effect`:
///
/// ```compile_fail
/// use doxa::ui::prelude::*;
/// #[component]
/// fn Ticker() -> View {
///     doxa::client::task::spawn(async {});
///     view! { <button>"tick"</button> }
/// }
/// ```
#[cfg(feature = "ui")]
#[doc(hidden)]
pub mod ui_diagnostics {}

/// An event prop that is a `Callback` compiles:
///
/// ```
/// use doxa::ui::prelude::*;
/// #[react(module = "./ts/editor.tsx", export = "Editor")]
/// pub struct Editor {
///     pub value: String,
///     #[react(event)]
///     pub on_change: Callback<String>,
/// }
/// ```
///
/// One that isn't names the field:
///
/// ```compile_fail
/// use doxa::ui::prelude::*;
/// #[react(module = "./ts/editor.tsx", export = "Editor")]
/// pub struct Editor {
///     pub value: String,
///     #[react(event)]
///     pub on_change: fn(String),
/// }
/// ```
///
/// An element prop React renders itself is a `View`, and the export may be dotted:
///
/// ```
/// use doxa::ui::prelude::*;
/// #[react(module = "./ts/popover.tsx", export = "Popover.Trigger")]
/// pub struct Trigger {
///     #[react(element)]
///     pub render: View,
/// }
/// ```
///
/// Anything else is "`#[react(element)]` field `render` must be a `View`":
///
/// ```compile_fail
/// use doxa::ui::prelude::*;
/// #[react(module = "./ts/popover.tsx", export = "Popover.Trigger")]
/// pub struct Trigger {
///     #[react(element)]
///     pub render: String,
/// }
/// ```
///
/// React calls a `func` for a value, and places a `render`:
///
/// ```
/// use doxa::ui::prelude::*;
/// use doxa::ui::react::{Func, Render};
/// #[react(module = "./ts/table.tsx", export = "Table")]
/// pub struct Table {
///     #[react(func)]
///     pub row_id: Func<u32, String>,
///     #[react(render)]
///     pub cell: Render<u32>,
/// }
/// ```
///
/// A `func` that isn't one is "`#[react(func)]` field `row_id` must be a `Func<A, R>` or `AsyncFunc<A, R>`":
///
/// ```compile_fail
/// use doxa::ui::prelude::*;
/// #[react(module = "./ts/table.tsx", export = "Table")]
/// pub struct Table {
///     #[react(func)]
///     pub row_id: fn(u32) -> String,
/// }
/// ```
///
/// `handle = Api` adds a `handle={h}` prop for React's `ref`:
///
/// ```
/// use doxa::ui::prelude::*;
/// #[derive(Clone)]
/// pub struct EditorApi;
/// #[react(module = "./ts/editor.tsx", export = "Editor", handle = EditorApi)]
/// pub struct Editor {
///     pub value: String,
/// }
/// ```
///
/// so a field of that name is "`handle` is the prop `#[react(handle = …)]` adds":
///
/// ```compile_fail
/// use doxa::ui::prelude::*;
/// #[derive(Clone)]
/// pub struct EditorApi;
/// #[react(module = "./ts/editor.tsx", export = "Editor", handle = EditorApi)]
/// pub struct Editor {
///     pub handle: String,
/// }
/// ```
///
/// Bulk numbers go as `raw`, copied once into a typed array:
///
/// ```
/// use std::rc::Rc;
/// use doxa::ui::prelude::*;
/// #[react(module = "./ts/plot.tsx", export = "Plot")]
/// pub struct Plot {
///     #[react(raw)]
///     pub ys: Rc<[f64]>,
/// }
/// ```
///
/// A `Vec` is "`#[react(raw)]` field `ys` must be an `Rc<[f64]>`":
///
/// ```compile_fail
/// use doxa::ui::prelude::*;
/// #[react(module = "./ts/plot.tsx", export = "Plot")]
/// pub struct Plot {
///     #[react(raw)]
///     pub ys: Vec<f64>,
/// }
/// ```
///
/// An npm module this crate doesn't declare is rejected; the local module above compiles:
///
/// ```compile_fail
/// use doxa::ui::prelude::*;
/// #[react(module = "@monaco-editor/react", export = "default")]
/// pub struct Monaco {
///     pub value: String,
/// }
/// ```
#[cfg(feature = "react")]
#[doc(hidden)]
pub mod react_diagnostics {}

/// `use:name={value}` attaches what `name(value)` returns:
///
/// ```
/// use doxa::ui::prelude::*;
/// #[derive(Clone)]
/// struct Fade(&'static str);
/// impl Directive for Fade {}
/// fn fade(class: &'static str) -> Fade { Fade(class) }
/// let _ = view! { <p use:fade={"out"}>"hi"</p> };
/// ```
///
/// A function returning anything else is refused as "`String` isn't a `Directive`":
///
/// ```compile_fail
/// use doxa::ui::prelude::*;
/// fn fade(class: &'static str) -> String { class.to_owned() }
/// let _ = view! { <p use:fade={"out"}>"hi"</p> };
/// ```
#[cfg(feature = "ui")]
#[doc(hidden)]
pub mod directive_diagnostics {}

/// A portal names where it renders:
///
/// ```
/// use doxa::ui::prelude::*;
/// let _ = view! { <Portal to="body"><p>"over"</p></Portal> };
/// ```
///
/// Without `to` it is "`<Portal>` is missing the `to` prop":
///
/// ```compile_fail
/// use doxa::ui::prelude::*;
/// let _ = view! { <Portal><p>"over"</p></Portal> };
/// ```
#[cfg(feature = "ui")]
#[doc(hidden)]
pub mod portal_diagnostics {}

/// A radio button binds to a group by its own `value`:
///
/// ```
/// use doxa::ui::prelude::*;
/// #[component]
/// fn Size() -> View {
///     let size = state(String::from("s"));
///     view! { <input type="radio" value="m" bind:group={size}/> }
/// }
/// ```
///
/// Without one it is "`bind:group` goes on a radio button with a `value`":
///
/// ```compile_fail
/// use doxa::ui::prelude::*;
/// #[component]
/// fn Size() -> View {
///     let size = state(String::from("s"));
///     view! { <input type="radio" bind:group={size}/> }
/// }
/// ```
#[cfg(feature = "ui")]
#[doc(hidden)]
pub mod bind_diagnostics {}

/// A listener takes `capture`, `passive` and `once` modifiers:
///
/// ```
/// use doxa::ui::prelude::*;
/// let _ = view! { <div on:scroll.passive={|_| ()} on:click.once.capture={|_| ()}/> };
/// ```
///
/// Any other is "unknown `on:` modifier `stop`":
///
/// ```compile_fail
/// use doxa::ui::prelude::*;
/// let _ = view! { <div on:click.stop={|_| ()}/> };
/// ```
#[cfg(feature = "ui")]
#[doc(hidden)]
pub mod listener_diagnostics {}

/// An exported component's props come from JS:
///
/// ```
/// use doxa::ui::prelude::*;
/// #[component(export)]
/// fn Badge(label: String, on_close: Callback) -> View {
///     view! { <span>{label}</span> }
/// }
/// ```
///
/// so a `View` prop is "an exported component's props come from JS, which can't pass a `View`":
///
/// ```compile_fail
/// use doxa::ui::prelude::*;
/// #[component(export)]
/// fn Badge(children: View) -> View {
///     children
/// }
/// ```
#[cfg(feature = "export")]
#[doc(hidden)]
pub mod export_diagnostics {}

/// A route that returns JSON is called from the browser:
///
/// ```
/// doxa::client::__as_client! {
///     #[get("/count")]
///     pub async fn count() -> Json<u32> { unreachable!() }
/// }
/// async fn page() -> Result<(), doxa::client::Fetch> {
///     let n = count().await?;
///     assert_eq!(*n, 3);
///     Ok(())
/// }
/// ```
///
/// One that returns HTML is not, and the error says so at the call:
///
/// ```compile_fail
/// doxa::client::__as_client! {
///     #[get("/")]
///     pub async fn home() -> Html<String> { unreachable!() }
/// }
/// async fn page() -> Result<(), doxa::client::Fetch> {
///     home().await?;
///     Ok(())
/// }
/// ```
///
/// With `client = false` it has no client half to call:
///
/// ```
/// doxa::client::__as_client! {
///     #[get("/", client = false)]
///     pub async fn home() -> Html<String> { unreachable!() }
/// }
/// ```
///
/// An extractor only the server reads is marked `#[server]`, and the call leaves it out:
///
/// ```
/// pub struct CallerToken;
/// doxa::client::__as_client! {
///     #[post("/ping")]
///     pub async fn ping(#[server] t: CallerToken, Json(n): Json<u32>) -> StatusCode { unreachable!() }
/// }
/// async fn page() -> Result<(), doxa::client::Fetch> {
///     ping(1).await?;
///     Ok(())
/// }
/// ```
///
/// Unmarked, it is a parameter the browser can't send:
///
/// ```compile_fail
/// pub struct CallerToken;
/// doxa::client::__as_client! {
///     #[post("/ping")]
///     pub async fn ping(t: CallerToken, Json(n): Json<u32>) -> StatusCode { unreachable!() }
/// }
/// async fn page() -> Result<(), doxa::client::Fetch> {
///     ping(CallerToken, 1).await?;
///     Ok(())
/// }
/// ```
#[cfg(feature = "client")]
#[doc(hidden)]
pub mod client_diagnostics {}

/// The client half: typed calls to the server's routes.
#[cfg(feature = "client")]
pub mod client {
    pub use doxa_client::*;

    #[doc(hidden)]
    pub use doxa_macros::__as_client;

    /// Names a shared route file needs when compiled as the client.
    pub mod prelude {
        pub use doxa_client::route_key;
        pub use doxa_client::{Form, Granted, Json, Path, Query, SseStream, StatusCode};
        pub use doxa_macros::{
            asset, capability, client, client_only, delete, get, operation, patch, post, put,
            server, server_only, Actions, ApiError, ClientIntoParams as IntoParams,
            ClientToSchema as ToSchema, Identity, PolicyResource, SseEvent,
        };
        pub use serde::{Deserialize, Serialize};
    }
}
