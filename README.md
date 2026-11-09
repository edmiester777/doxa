# doxa

[![crates.io](https://img.shields.io/crates/v/doxa.svg)](https://crates.io/crates/doxa)
[![docs.rs](https://img.shields.io/docsrs/doxa)](https://docs.rs/doxa)
[![CI](https://github.com/edmiester777/doxa/actions/workflows/rust.yml/badge.svg)](https://github.com/edmiester777/doxa/actions/workflows/rust.yml)
[![License](https://img.shields.io/crates/l/doxa.svg)](https://github.com/edmiester777/doxa/blob/main/LICENSE)

**Write the route once. Get everything else for free.**

doxa is a full-stack Rust framework. The server is [axum](https://github.com/tokio-rs/axum), the browser runs your pages as wasm, and one route signature connects them: it is the handler's contract, its OpenAPI entry, its auth guard, its audit trail, and a typed call the browser makes like any other function. Rust from the database to the DOM, shipped as one binary.

**[Website](https://edmiester777.github.io/doxa/)** · **[Guides](https://edmiester777.github.io/doxa/guides)** · **[Story gallery](https://edmiester777.github.io/doxa/gallery/)** · **[API reference](https://edmiester777.github.io/doxa/api/)** · **[docs.rs](https://docs.rs/doxa)**

## One route, both sides

A doxa app is two crates. This is the app `doxa new` writes.

**`api`** holds the route, written once. The server runs its body, and the browser's build drops the body and keeps a typed call:

```rust
doxa::prelude!();

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct Greeting {
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema, IntoParams)]
pub struct Who {
    pub name: Option<String>,
}

/// Say hello.
#[get("/api/greeting")]
pub async fn greeting(Query(who): Query<Who>) -> Json<Greeting> {
    Json(greet(who.name))
}
```

`greet` lives in `api/src/server/`, which `server_only = ["src/server"]` in the crate's `Cargo.toml` keeps out of the browser build. That's where the database, the stores and anything else server-only go.

**`web`** calls it. A page, compiled to wasm, awaiting the server like a local function:

```rust
#[page("/")]
async fn Home(name: Option<String>) -> Result<View> {
    let hello = greeting(Who { name }).await?;
    Ok(view! { <h1>{&hello.message}</h1> })
}
```

No client to generate, no URL strings, no JSON by hand. Rename a field and both sides stop compiling until they agree. The route shows up in the server's OpenAPI document, and `.cache(ttl)` on a call keeps its answer in the browser.

## Quick start

```sh
cargo install doxa-cli
doxa new hello && cd hello
doxa dev            # http://127.0.0.1:3000, rebuilt and hot-patched on save
```

`doxa dev` runs the server and patches each change to the web crate into the running page. When you're done, `doxa build --release` compiles the web app into the server, so you deploy one binary. Or `doxa build --out dist` writes static files for any host.

### Just the API

Already have an axum app? doxa works there too, server-side only:

```sh
cargo add doxa utoipa axum thiserror
cargo add serde --features derive
cargo add tokio --features full
```

```rust
use axum::{extract::Path, Json};
use doxa::{get, ApiDocBuilder, ApiError, MountDocsExt, MountOpts, ToSchema};

#[derive(Clone, doxa::State)]
struct NoState;

#[doxa::service]
struct Api;

#[derive(Debug, thiserror::Error, serde::Serialize, ToSchema, ApiError)]
enum WidgetError {
    #[error("widget not found")]
    #[api(status = 404, code = "not_found")]
    NotFound,
}

/// One widget, by id.
#[get("/widgets/{id}")]
async fn get_widget(Path(id): Path<u32>) -> Result<Json<String>, WidgetError> {
    if id == 0 { return Err(WidgetError::NotFound); }
    Ok(Json(format!("widget {id}")))
}

#[tokio::main]
async fn main() {
    let (router, api) = doxa::app(&NoState).split_for_parts();
    let app = router.mount_docs(
        ApiDocBuilder::new().title("Widgets").version("0.1.0").merge(api).build(),
        MountOpts::default(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

Open `http://127.0.0.1:3000/docs`. Your route is there with its parameter, its body and its `404`, and you didn't write any of it twice.

## What's in the box

**On the server**

| | | |
|---|---|---|
| **OpenAPI from signatures** | Route attributes, typed errors, SSE, Scalar UI | [Guide](https://edmiester777.github.io/doxa/guides/routes) |
| **Authentication** | OIDC/JWT over your own claim struct | [Guide](https://edmiester777.github.io/doxa/guides/auth) |
| **Authorization** | Cedar policies, guards that load and check the object | [Guide](https://edmiester777.github.io/doxa/guides/authorization) |
| **Audit** | A non-blocking log, filled in by a layer | [Guide](https://edmiester777.github.io/doxa/guides/audit) |
| **Secrets** | `ProtectedString`, redacted everywhere | [Guide](https://edmiester777.github.io/doxa/guides/secrets) |

**Between them**

| | | |
|---|---|---|
| **Routes as functions** | Write the route once, served by the server and called from the browser | [Guide](https://edmiester777.github.io/doxa/guides/api-crates) |
| **Permissions in the UI** | A capability guards the route on the server; `<Can>` and `has()` ask the same question in the browser | [Guide](https://edmiester777.github.io/doxa/guides/api-crates#capabilities-in-the-browser) |

**In the browser**

| | | |
|---|---|---|
| **Pages and components** | `view!`, hooks, a router, forms, and tests without a browser | [Guide](https://edmiester777.github.io/doxa/guides/pages) |
| **React and npm** | Bind JS modules, embed React components, ship components to React | [Guide](https://edmiester777.github.io/doxa/guides/js-interop) |
| **Story gallery** | Storybook-style, in Rust, built in | [Guide](https://edmiester777.github.io/doxa/guides/stories) |

**Shipping**

| | | |
|---|---|---|
| **Deploy** | One binary with the app inside, or static files anywhere | [Guide](https://edmiester777.github.io/doxa/guides/deploy) |

## Features and crates

`doxa` is one dependency with feature flags, re-exporting the family. Each crate also works on its own.

| Feature | Crate | Does |
|---|---|---|
| `docs` (default) | [`doxa-docs`](https://github.com/edmiester777/doxa/tree/main/crates/doxa-docs) | Route attributes, OpenAPI, Scalar, typed errors, SSE |
| `macros` (default) | [`doxa-macros`](https://github.com/edmiester777/doxa/tree/main/crates/doxa-macros) | The proc macros |
| `auth` | [`doxa-auth`](https://github.com/edmiester777/doxa/tree/main/crates/doxa-auth) | OIDC/JWT over your claims, `Granted<T>` guards |
| `policy` | [`doxa-policy`](https://github.com/edmiester777/doxa/tree/main/crates/doxa-policy) | Cedar authorization with pluggable storage |
| `audit` | [`doxa-audit`](https://github.com/edmiester777/doxa/tree/main/crates/doxa-audit) | Non-blocking audit log, optional SeaORM sink |
| `protected` | [`doxa-protected`](https://github.com/edmiester777/doxa/tree/main/crates/doxa-protected) | `ProtectedString`: zeroized, redacted |
| `client` | `doxa-client` | Typed calls from the browser, with a cache |
| `ui` | `doxa-ui` | Components, `view!`, hooks and a router |
| `embed` | `doxa-docs` | The built web app inside the server binary |
| `full` | | Every server-side feature |

The `doxa` CLI (`cargo install doxa-cli`) scaffolds (`doxa new`), develops with hot patching (`doxa dev`), builds (`doxa build`, `--lib`, `--out`), shows stories (`doxa gallery`) and formats `view!` markup (`doxa fmt`).

> utoipa must be a direct dependency: doxa's macros expand to `::utoipa::…` paths in your crate.

## Examples

- [`examples/shop`](https://github.com/edmiester777/doxa/tree/main/examples/shop): a full-stack widget shop in two crates (API and web), with page tests, stories, React interop and a Vite host app.
- [`examples/site`](https://github.com/edmiester777/doxa/tree/main/examples/site): the website above, built with doxa and published by a GitHub Actions workflow.

## Why

> *δόξα*: Greek for "accepted teaching." The root of *doctrine*, *orthodoxy* and *paradox*.

doxa came out of a production enterprise stack where the same plumbing (OpenAPI docs, OIDC middleware, Cedar authorization, audit trails) kept getting rebuilt service after service. Rather than copy it a fourth time, the generic parts got a proper API and a home here. It's been earning its keep in production since.

- **Framework-neutral cores.** Auth, policy and audit work without axum; the axum integration is a feature.
- **Generic over your domain.** Claims, sessions, resources and audit events are all yours.
- **Typed end to end.** Errors become OpenAPI responses, SSE events carry their names into the spec, and secrets carry their redaction into their schema.
- **Cheap defaults.** Audit writes are async, specs are served from shared bytes, and Scalar loads from a CDN you can override.

## Acknowledgements

Huge thanks to the [axum](https://github.com/tokio-rs/axum) and [utoipa](https://github.com/juhaku/utoipa) teams. doxa stands on their foundations.

## License

Apache 2.0. See [LICENSE](https://github.com/edmiester777/doxa/blob/main/LICENSE).
