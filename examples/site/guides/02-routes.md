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

`#[derive(doxa::State)]` marks the crate's state. Every handler's `State<T>` is checked against it with `FromRef` at compile time, so there's no state type to name on each route. `doxa::app(&state)` and `doxa::spec()` stop with a clear message on a route under no service, two services in one module, two types claiming one schema name, or a declared route nothing implements.

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
