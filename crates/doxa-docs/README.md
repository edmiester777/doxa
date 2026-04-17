# doxa-docs

Ergonomic OpenAPI documentation and Scalar UI hosting for axum. Built on [utoipa](https://crates.io/crates/utoipa) + [utoipa-axum](https://crates.io/crates/utoipa-axum) with minimal handler attributes and in-memory spec serving.

Most users should depend on [`doxa`](https://crates.io/crates/doxa) rather than pulling this crate directly.

## Usage

```rust
use doxa_docs::{ApiDocBuilder, MountDocsExt, MountOpts, OpenApiRouter, ToSchema};
use axum::Json;
use serde::Serialize;

#[derive(Serialize, ToSchema)]
struct Widget { id: u32, name: String }

let (router, openapi) = OpenApiRouter::new()
    .routes(doxa_docs::routes!(get_widget))
    .split_for_parts();

let docs = ApiDocBuilder::new()
    .title("Widgets API")
    .version("0.1.0")
    .merge(openapi)
    .build();

let app = router.mount_docs(docs, MountOpts::default());
// Scalar UI at /docs, JSON spec at /openapi.json
```

## Key types

| Type | Purpose |
|------|---------|
| `ApiDocBuilder` | Fluent builder for constructing an OpenAPI document |
| `ApiDoc` | Immutable, pre-serialized in-memory OpenAPI document |
| `MountOpts` | Configuration for mounting the docs UI |
| `ScalarConfig` | Scalar UI customization (layout, theme, dark mode) |
| `SseStream<E, S>` | SSE response wrapper with OpenAPI `text/event-stream` content type |
| `Header<H>` | Typed header extractor with OpenAPI parameter metadata |
| `DocumentedLayer` | Trait for middleware that contributes OpenAPI metadata |
| `OpenApiRouter` | Re-export from utoipa-axum |

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `docs-scalar` | yes | Serves the Scalar UI from CDN (small HTML template, no binary overhead) |
| `macros` | yes | Re-exports `doxa-macros` proc macros (`#[derive(ApiError)]`, `#[get]`, etc.) |

## License

Apache 2.0
