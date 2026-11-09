# Routes and docs

A doxa route is an axum handler with an attribute on it. The attribute mounts it, documents it, and checks at compile time that it fits the app. You never keep a route list or an OpenAPI file in sync by hand.

## The attribute

```rust
/// One widget, by id. (This becomes the operation's summary.)
#[get("/widgets/{id}", tag = "Widgets")]
async fn get_widget(Path(id): Path<u32>) -> Result<Json<Widget>, WidgetError> {
    /* ... */
}
```

`#[get]`, `#[post]`, `#[put]`, `#[patch]` and `#[delete]` read the signature: the path parameters, the query and body extractors, the success body and the error type. Each becomes part of the OpenAPI operation. The doc comment becomes its summary and description.

## Routes both halves build

In an API crate (one whose `build.rs` calls `doxa_role::api()`), every route is compiled twice. Off wasm it's the handler. On wasm the body is dropped and the same name becomes a typed call the browser makes. So the server's code has to stay out of the browser build without a `#[cfg]` on every line.

### Server-only directories

List them in the API crate's `Cargo.toml`:

```toml
[package.metadata.doxa]
server_only = ["src/server"]   # stores, queries, assets, layers
client_only = ["src/browser"]  # anything only the browser compiles

# Their dependencies, likewise: wasm never builds these.
[target.'cfg(not(target_arch = "wasm32"))'.dependencies]
sqlx = { version = "0.8", features = ["postgres"] }
```

Each entry is a directory beside `lib.rs` with a `mod.rs`. You don't write `mod server;`: the crate root's `doxa::prelude!()` declares it, and every module's `doxa::prelude!()` imports its `pub` items on the side that compiles it. A route file can name `Catalog` from `src/server/` with no `use`, and the wasm build never opens a file in that directory. Editing one under `doxa dev` rebuilds only the server.

### Keep the body thin

The body is the one place in a shared file that can name anything server-side, because the browser never compiles it. Make it a wrapper that calls into `src/server/`:

```rust
// src/widgets.rs, shared
#[patch("/api/widgets/{name}")]
pub async fn rename_widget(
    widget: Grant<Widget>,
    State(catalog): State<Catalog>,
    Valid(Json(rename)): Valid<Json<Rename>>,
) -> Result<Json<Widget>, WidgetError> {
    catalog.rename(widget.id, &rename.name).map(Json)
}

// src/server/widgets.rs, server only
impl Catalog {
    pub fn rename(&self, id: u32, name: &str) -> Result<Widget, WidgetError> { /* … */ }
}
```

The logic, its tests and its dependencies sit where the browser never looks. The shared file holds what both halves agree on: the path, the arguments and the answer. `doxa dev` also hashes each shared file with its route bodies removed, so an edit that only touches a body skips the wasm rebuild too.

### Imports go inside the body

A `use` at the top of a shared file is compiled for both halves, so `use sqlx::PgPool;` there breaks the browser build. Put it in the body, which the browser drops:

```rust
#[get("/api/widgets/{name}/events")]
pub async fn widget_events(widget: Grant<Widget>)
    -> SseStream<WidgetEvent, impl futures::Stream<Item = Result<WidgetEvent, std::convert::Infallible>>>
{
    use futures::stream;
    let name = widget.into_inner().name;
    SseStream::new(stream::iter([Ok(WidgetEvent::Renamed { name })]))
}
```

Server-only names can also be re-exported from `src/server/mod.rs` (`pub use axum::extract::Multipart;`), and they come in with the rest of it.

### What a signature may name

The browser reads the signature, so it names what both halves have: your `#[dto]` types, `Json`, `Query`, `Path`, `Form`, `Bytes`, `Multipart`, `SseStream`, `Attachment` and `StatusCode`, which `doxa::prelude!()` gives each half its own version of. The browser drops `State<…>`, `Extension<…>` and the other extractors only the server reads. For one doxa doesn't know, mark the argument `#[server]`:

```rust
pub async fn suggest_name(#[server] Caller(who): Caller, Json(s): Json<Rename>) -> StatusCode
```

### Guards by entity

The browser knows entities, not the server's assets, so a route guards with `Grant<…>`. `Grant<Widget>` uses the asset whose `#[asset(…)]` says `entity = Widget`, and `Grant<Many<Widget>>` scopes a listing by it. When an entity has a second asset, give that one `default = false` and name it on the route that uses it:

```rust
pub async fn widget_by_id(widget: Grant<Widget, by = WidgetById>) -> Json<Widget> { /* … */ }
```

The browser sends the entity's key either way. `Grant<Cap<order_action::Place>>` asks for a capability instead.

## Typed errors, grouped by status

Derive `ApiError` and each variant becomes a response. Variants that share a status merge into one response with an example each:

```rust
#[derive(Debug, thiserror::Error, Serialize, ToSchema, ApiError)]
enum CheckoutError {
    #[error("validation failed: {0}")]
    #[api(status = 400, code = "validation_error")]
    Validation(String),

    #[error("duplicate order: {0}")]
    #[api(status = 400, code = "duplicate_order")]
    Duplicate(String),

    #[error("item not found")]
    #[api(status = 404, code = "not_found", outcome = "allowed")]
    NotFound, // a legitimate miss, not a security event

    #[error("payment declined")]
    #[api(status = 403, code = "payment_declined", outcome = "denied")]
    PaymentDeclined,
}
```

That one derive gives you the `IntoResponse` impl, the `400`/`403`/`404` entries in the spec, and an audit outcome per variant (the [audit layer](05-audit.md) reads it, so you don't). `#[api(status = 500, internal)]` marks the variant an internal failure turns into, and the client only ever sees its message.

## Server-Sent Events

```rust
#[derive(Serialize, ToSchema, SseEvent)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
enum Progress {
    Started { job_id: u64 },
    Tick { percent: u8 },
    Completed { job_id: u64 },
}

#[get("/jobs/{id}/progress")]
async fn progress(Path(id): Path<u64>)
    -> SseStream<Progress, impl Stream<Item = Result<Progress, Infallible>>>
{
    SseStream::new(async_stream::stream! {
        yield Ok(Progress::Started { job_id: id });
        yield Ok(Progress::Tick { percent: 50 });
        yield Ok(Progress::Completed { job_id: id });
    })
}
```

The spec says `text/event-stream`, lists the frame names (`started`, `tick`, `completed`) in the description and in an `x-sse-event-names` extension, and carries the payload schema. In the browser the same route is a stream you `.next().await`.

## Services and layer stacks

A `#[doxa::service]` owns every route in its module and the modules below it. The deepest service wins. To move a route to another service, move it to another module.

Middleware lives in a `#[doxa::layers]` function, which any number of services can share:

```rust
use doxa::auth::{AuthDocs, AuthLayer};
use doxa::Routes;

#[derive(Clone, FromRef, doxa::State)]
pub struct AppState { pub db: DatabaseConnection, pub auth: Arc<AuthState> }

#[doxa::layers(docs = [AuthDocs])]
fn protected(routes: Routes, state: &AppState) -> Routes {
    routes.layer(AuthLayer::new(state.auth.clone()))
}

#[doxa::layers(docs = [protected, AdminDocs])]
fn admin(routes: Routes, state: &AppState) -> Routes {
    protected(routes.layer(AdminLayer::new()), state)
}

// widgets/admin.rs
#[doxa::service(layers = crate::admin)]
pub struct WidgetsAdmin;

#[get("/widgets/purge")]
async fn purge(State(db): State<DatabaseConnection>) -> StatusCode { /* ... */ }
```

The body is plain `.layer()` calls. `docs = [...]` says what the stack adds to each operation, such as the bearer requirement and `401` that `AuthDocs` describes. So `/docs` shows the lock icon on exactly the routes that have it.

## One state, checked

`#[derive(doxa::State)]` marks the crate's state. Every handler's `State<T>` is checked against it with `FromRef` at compile time, so there's no state type to name on each route. `doxa::app(&state)` and `doxa::spec()` stop with a clear message on a route under no service, two services in one module, or two types claiming one schema name.

## Putting it together

```rust
#[tokio::main]
async fn main() {
    let state = AppState { db: connect().await, auth: build_auth().await };
    let (router, api) = doxa::app(&state).split_for_parts();

    let docs = ApiDocBuilder::new()
        .title("My Service")
        .version("0.1.0")
        .bearer_security("bearer") // the scheme AuthDocs names
        .merge(api)
        .build();

    let app = router.mount_docs(docs, MountOpts::default());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

Want the document without a running server, for codegen or CI? Put `#[doxa::spec]` on a function that builds it, and it's available with no state and no I/O.
