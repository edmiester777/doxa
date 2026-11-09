# Routes as functions

This is the full-stack part. Write a route in a crate both halves build. The server runs it, and the browser calls it like any `async fn`. The URL, method, query, body, response and error type are written once, so the two sides can't disagree.

## Write

An API crate's `build.rs` is one line:

```rust
// shop-api/build.rs
fn main() { doxa_role::api() }
```

```rust
// shop-api/src/widgets.rs
doxa::prelude!();

route_key!(pub WidgetKey { name: String });

#[dto]
#[entity(key = WidgetKey, actions = WidgetAction)]
pub struct Widget { pub id: u32, pub name: String }

#[dto]
#[derive(garde::Validate)]
pub struct Rename {
    #[garde(length(min = 1, max = 40))]
    pub name: String,
}

/// One widget, by name.
#[get("/api/widgets/{name}")]
pub async fn get_widget(widget: Grant<Widget>) -> Json<Widget> {
    Json(widget.into_inner().into())
}

/// Rename a widget.
#[patch("/api/widgets/{name}")]
pub async fn rename_widget(
    widget: Grant<Widget>,
    State(catalog): State<Catalog>,
    Valid(Json(rename)): Valid<Json<Rename>>,
) -> Result<Json<Widget>, WidgetError> {
    catalog.rename(widget.id, &rename.name).map(Json)
}
```

`#[dto]` derives serde both ways, `ToSchema`, `Debug`, `Clone` and `PartialEq` (`#[dto(query)]` adds `IntoParams`). `Catalog` and the `#[asset(…, entity = Widget)]` that guards `Grant<Widget>` live in `src/server/`, which `server_only` keeps out of the browser build. [Routes both halves build](02-routes.md#routes-both-halves-build) covers what goes where. `doxa check --wire -p shop-api` builds the crate for the browser and names whatever dependency gets in the way.

## Call

```rust
let gear = get_widget("gear").await?;   // or get_widget(&WidgetKey { name })

match rename_widget("gear", Rename { name: "cog".into() }).await {
    Ok(w) => { /* … */ }
    Err(e) if e.is_not_found() => { /* … */ }
    Err(e) => match e.api() {
        Some(WidgetError::NameTaken(n)) => { /* the route's own error, typed */ }
        _ => { /* … */ }
    },
}
```

What you get for free:

- **Caching, when you ask.** `get_widget(&key).cache(Duration::from_secs(60))` keeps the answer for a minute, shared by every caller of that URL. Without `.cache`, every call asks the server.
- **Invalidation.** A mutation drops the cached answers it touches. Components that read one re-render and fetch it once.
- **Validation.** `Valid<Json<Rename>>` runs the same `garde` rules in the browser before sending. An invalid body never leaves, and the server answers `422` with the same fields if something else sends one.
- **Dry runs.** `rename_widget::can("gear").await` runs the route's guards and stops before the handler. `<Can>` in a page uses it to show a button only to callers who may press it.
- **Streams.** An `SseStream<T>` route is a stream you `.next().await`, and identical streams share one connection.
- **Files.** `Bytes`, `Multipart` and `Attachment` work both ways.

## Capabilities in the browser

A route guarded by a capability states it: `_: Grant<Cap<order_action::Place>>`. `GET /doxa/capabilities` answers the caller's set, and the client asks once per session:

```rust
if has(order_action::Place).await { /* … */ }
view! { <Can cap={order_action::Place}><button>"Order"</button></Can> }
router.guard(requires(order_action::Place, "/orders"))
```

## Where requests go

Each API crate gets its own `service()`, with its own base URL, cache, session and layers. Base URLs default to `[package.metadata.doxa.services]` on the web crate, and `services.json` changes them per deployment without a rebuild. Credentials are layers:

```rust
layers().push(bearer(|| session::token()));          // every crate's requests
shop_api::service().layers().push(cookies());         // one crate's requests
```

Across origins, add `.layer(doxa::Cors::allow([app_origin]))` to the server (feature `cors`). Or stay same-origin and forward a prefix with `.merge(doxa::proxy("/orders", orders_url))` (feature `proxy`).

## Other ways to share routes

**A separate client crate.** The server crate keeps its routes, and a client crate is the same source with `[lib] path = "../server/src/lib.rs"` and `doxa_role::client()` in its `build.rs`. Every server-only item then takes `#[server]` or `doxa::server_only! { … }`, one by one, which is what an API crate's `server_only` directories save you.

**From an OpenAPI document.** For a server you don't control, generate the client crate from its spec at build time:

```rust
// orders-client/build.rs
fn main() {
    doxa_build::ClientSpec::from_server(orders_server::__doxa_spec())
        .types(|t| t.format("uuid", "uuid::Uuid"))
        .generate()
        .unwrap_or_else(|e| panic!("{e}"));
}

// orders-client/src/lib.rs
doxa::prelude!();
doxa::include_client!();
```

A saved `openapi.json` goes through `doxa_build::openapi_from_json(&text)?` first. The calls are made by the same machinery, so they cache, invalidate, dry-run and stream the same way.

The [shop example](../../shop) writes every route this way. Its tests call every route through the real router, in-process.
