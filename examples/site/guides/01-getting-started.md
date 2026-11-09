# Getting started

Two ways in: bolt doxa onto an axum API you already have, or let `doxa new` scaffold a full-stack app. Both take about a minute.

## Just an API

Add doxa and utoipa. utoipa has to be a direct dependency, because doxa's macros expand to `::utoipa::…` paths in your crate.

```sh
cargo add doxa utoipa axum thiserror
cargo add serde --features derive
cargo add tokio --features full
```

Then write a route the way you'd write any axum handler, with one attribute on top:

```rust
use axum::{extract::Path, Json};
use doxa::{get, ApiDocBuilder, ApiError, MountDocsExt, MountOpts, ToSchema};
use serde::Serialize;

// The state every route mounts under. This server has none.
#[derive(Clone, doxa::State)]
struct NoState;

// Owns every route in this module and below.
#[doxa::service]
struct Api;

#[derive(Debug, thiserror::Error, Serialize, ToSchema, ApiError)]
enum WidgetError {
    #[error("widget not found")]
    #[api(status = 404, code = "not_found")]
    NotFound,
}

/// A widget. This comment shows up in the docs.
#[derive(Serialize, ToSchema)]
struct Widget {
    id: u32,
    name: String,
}

/// One widget, by id.
#[get("/widgets/{id}")]
async fn get_widget(Path(id): Path<u32>) -> Result<Json<Widget>, WidgetError> {
    if id == 0 {
        return Err(WidgetError::NotFound);
    }
    Ok(Json(Widget { id, name: "sprocket".into() }))
}

#[tokio::main]
async fn main() {
    // Every route mounts itself: no route list to keep in sync.
    let (router, api) = doxa::app(&NoState).split_for_parts();
    let docs = ApiDocBuilder::new().title("Widgets").version("0.1.0").merge(api).build();
    let app = router.mount_docs(docs, MountOpts::default());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

`cargo run`, then open `http://127.0.0.1:3000/docs`. There's your route in the Scalar UI with its path parameter, its `200` body, its `404` and the doc comments, with the spec itself at `/openapi.json`. You didn't write any of it twice.

## Full stack

Install the CLI and scaffold an app:

```sh
cargo install doxa-cli
doxa new hello && cd hello
doxa dev
```

`doxa new` writes three crates:

| Crate | What it is |
|---|---|
| `hello-api` | The routes, declared: signatures and types, built for the server and the browser. |
| `hello-server` | The axum app: implements each route and serves the built web app. |
| `hello-web` | The pages, compiled to wasm. |

The API crate declares the route, with no body:

```rust
#[get("/api/greeting")]
pub async fn greeting(who: Query<Who>) -> Json<Greeting>;
```

The server implements it:

```rust
#[implements(hello_api::greeting)]
async fn greeting(Query(who): Query<Who>) -> Json<Greeting> {
    let name = who.name.unwrap_or_else(|| "world".into());
    Json(Greeting { message: format!("Hello, {name}!") })
}
```

`doxa dev` builds everything, runs the server at `http://127.0.0.1:3000` and patches each change to the web crate into the running page. The home page calls the route like this:

```rust
#[page("/")]
async fn Home(name: Option<String>) -> Result<View> {
    let hello = greeting(Who { name }).await?;
    Ok(view! { <h1>{&hello.message}</h1> })
}
```

`greeting` is the declared route, called like an `async fn`. The URL, query string, JSON and error type all come from its signature, and the compiler checks the server's implementation against it.

## Pick features

`doxa` is one dependency with feature flags. Defaults give you the docs and the macros; add what you need:

| Feature | Gives you |
|---|---|
| `docs` (default) | Route attributes, OpenAPI, Scalar, typed errors, SSE |
| `auth` | OIDC/JWT over your own claims, `Granted<T>` guards |
| `policy` | Cedar authorization with pluggable storage |
| `audit` | A non-blocking audit log, filled in by a layer |
| `protected` | `ProtectedString`, redacted everywhere |
| `client`, `ui` | Typed calls and pages for the browser |
| `full` | All of the server-side ones |

## Where next

- [Routes and docs](02-routes.md): errors, streams, services and layers.
- [Routes as functions](07-api-crates.md): the full-stack model properly.
- The [shop example](../../shop) is a whole app, with tests.
