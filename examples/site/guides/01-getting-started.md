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

`doxa new` writes two crates:

| Crate | What it is |
|---|---|
| `hello-api` | The routes and their types, built for the server and the browser, and the server binary that serves them with the built web app. |
| `hello-web` | The pages, compiled to wasm. |

The API crate writes the route once:

```rust
#[get("/api/greeting")]
pub async fn greeting(Query(who): Query<Who>) -> Json<Greeting> {
    Json(greet(who.name))
}
```

The server runs the body. `greet` is in `hello-api/src/server/`, which the crate's `Cargo.toml` lists as `server_only`, so the browser build never compiles it.

`doxa dev` builds everything, runs the server at `http://127.0.0.1:3000` and patches each change to the web crate into the running page. The home page calls the route like this:

```rust
#[page("/")]
async fn Home(name: Option<String>) -> Result<View> {
    let hello = greeting(Who { name }).await?;
    Ok(view! { <h1>{&hello.message}</h1> })
}
```

In the browser, `greeting` is the same route, called like an `async fn`. The URL, query string, JSON and error type all come from its signature, so the call and the handler can't disagree.

## Several services

A web app can call backends that live in other workspaces. List them at the web app's workspace root, and `doxa dev` builds, runs and watches each one beside the page:

```toml
# the web app's workspace Cargo.toml
[workspace.metadata.doxa.dev.services]
billing-api = { path = "../billing" }

# the web crate's Cargo.toml
[package.metadata.doxa.proxy]
"/billing" = { service = "billing-api", strip = true }
```

Each service names its own port, in its API crate's `Cargo.toml`:

```toml
[package.metadata.doxa.dev]
port = 8081
```

The service's binary hands its `start` function to doxa, which binds the port `doxa dev` passes:

```rust
#[doxa::main]
async fn start() -> axum::Router {
    billing_api::server::app()
}
```

A service with its own CLI passes its `clap::Parser` as `#[doxa::main(Cli)]` on `async fn main(cli: Cli)`, and doxa adds `start`. It needs its own `clap` dependency with the `derive` and `env` features.

At startup `doxa dev` compiles up to four things at once, then starts each service once its build is done. The web app's server builds after the web app. A service that needs another one running first names it, as in `billing-api = { path = "../billing", after = ["ledger-api"] }`. It won't start until `ledger-api` is listening. If memory is tight, `--max-parallel-build 2` lowers the limit and `--serial` compiles one at a time, in `after` order. To set a workspace default, put `max_parallel_build = 2` under `[workspace.metadata.doxa.dev]`.

Every line a service prints is tagged with its name, and so is each rebuild. A compile error leaves the last good build running until the next save fixes it. Editing a service's shared routes rebuilds both the service and the page, against the local source: doxa patches the web app's git dependency for the session and restores `Cargo.lock` when it exits. A service inherits `doxa dev`'s environment, which a `.env` loaded with `init =` doesn't override.

In a terminal, `doxa dev` gives each service, the web app and its server a pane of their own, titled with its status: pending, compiling, running or failed. `?` lists the keys; the mouse focuses, scrolls and resizes panes, and `m` turns it off so you can select text. `--no-tui` prints plain tagged lines instead, as `doxa dev` does when its output isn't a terminal.

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
| `main` | `#[doxa::main]`, a server binary `doxa dev` can run |
| `full` | All of the server-side ones |

## Where next

- [Routes and docs](02-routes.md): errors, streams, services and layers.
- [Routes as functions](07-api-crates.md): the full-stack model properly.
- The [shop example](../../shop) is a whole app, with tests.
