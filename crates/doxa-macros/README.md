# doxa-macros

Procedural macros for the [doxa](https://crates.io/crates/doxa) ecosystem. Derive macros, HTTP method attributes, and a capability declaration macro — all designed to eliminate boilerplate when building OpenAPI-documented axum services.

Most users should depend on [`doxa`](https://crates.io/crates/doxa) with the `macros` feature (enabled by default) rather than pulling this crate directly.

## Derive macros

### `#[derive(ApiError)]`

Turns an error enum into three trait implementations from a single `#[api(...)]` annotation per variant:

- `axum::response::IntoResponse` — maps each variant to its HTTP status code and emits a typed `ApiErrorBody<Self>` JSON envelope with `message`, `status`, `code`, and `error` fields.
- `utoipa::IntoResponses` — produces an OpenAPI response map. Variants sharing a status code are grouped into one response with per-variant named examples and a `oneOf` schema for the `error` field.
- `HasAuditOutcome` — maps each variant to an audit outcome (`allowed`, `denied`, or `error`) for automatic audit trail integration via `AuditLayer`.

The generated `IntoResponse` also emits structured tracing: `error!` for 5xx, `warn!` for 4xx, `debug!` for everything else.

```rust
#[derive(Debug, thiserror::Error, Serialize, ToSchema, ApiError)]
enum WidgetError {
    #[error("not found")]
    #[api(status = 404, code = "not_found", outcome = "allowed")]
    NotFound,

    #[error("validation failed: {0}")]
    #[api(status = 400, code = "validation_error")]
    Validation(String),

    #[error("conflict: {0}")]
    #[api(status = 400, code = "conflict")]  // grouped with Validation under one 400 response
    Conflict(String),

    #[error("internal error")]
    #[api(status = 500, code = "internal")]   // outcome defaults to "error" when omitted
    Internal,
}
```

#### `#[api(...)]` attributes

| Key | Required | Description |
|-----|----------|-------------|
| `status` | yes | HTTP status code (`u16`) |
| `code` | no | Application error code string; defaults to snake_case of variant name |
| `outcome` | no | Audit outcome: `"allowed"`, `"denied"`, or `"error"` (default) |

### `#[derive(SseEvent)]`

Implements `SseEventMeta` for internally-tagged enums so Server-Sent Event frames carry the variant name as the SSE event type. Pair with `#[serde(tag = "event", content = "data", rename_all = "snake_case")]` to keep wire format and OpenAPI schema aligned.

```rust
#[derive(Serialize, ToSchema, SseEvent)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
enum Progress {
    Started { job_id: u64 },
    Tick { percent: u8 },
    #[sse(name = "finished")]  // override the default snake_case name
    Completed { job_id: u64 },
}
```

## HTTP method attribute macros

`#[get]`, `#[post]`, `#[put]`, `#[patch]`, `#[delete]` delegate to `utoipa::path` with automatic inference from the handler's function signature. Use `#[operation]` for custom or multi-method routes.

```rust
#[get("/widgets/{id}", tag = "Widgets")]
async fn get_widget(Path(id): Path<u32>) -> Result<Json<Widget>, WidgetError> {
    // ...
}

#[post("/widgets", tags("Widgets", "Public"))]
async fn create_widget(
    Json(req): Json<CreateWidget>,
) -> Result<(StatusCode, Json<Widget>), WidgetError> {
    // ...
}
```

### What the macros infer

The method macros read the handler signature and automatically populate `utoipa::path` attributes:

| Inference | How it works |
|-----------|-------------|
| **`operation_id`** | Defaults to the function name |
| **`request_body`** | Detected from the first `Json<T>` parameter, including through transparent wrappers like `Valid<Json<T>>` |
| **Path parameters** | `{name}` segments in the route are matched to `Path<T>` extractors (scalar, tuple, struct) |
| **Query parameters** | `Query<T>` extractors contribute query parameters via trait dispatch |
| **Header parameters** | `Header<H>` extractors contribute header parameters; `headers(H1, H2)` documents headers without extracting |
| **Success response** | `Json<T>` → 200; `(StatusCode, Json<T>)` → 201; `SseStream<E, _>` → `text/event-stream` |
| **Error responses** | `E` from `Result<_, E>` folded into `responses(...)` as `IntoResponses` |
| **Tags** | `tag = "Name"` for one, `tags("A", "B")` for multiple |

**Explicit overrides always win.** Supplying `request_body = ...`, `params(...)`, or `responses(...)` by hand suppresses inference for that field. Any additional `key = value` pairs are forwarded to `utoipa::path` verbatim.

### Header documentation

Two equivalent ways to declare a header on a handler — both use the `DocumentedHeader` trait and deduplicate:

```rust
// Via extractor — extracts the value AND documents it
#[get("/widgets")]
async fn list(Header(key, ..): Header<XApiKey>) -> Json<Vec<Widget>> { /* ... */ }

// Via attribute — documents without extracting
#[get("/health", headers(XApiKey))]
async fn health() -> &'static str { "ok" }
```

## Capability attribute macro

`#[capability]` declares a `Capable` marker type backed by a `Capability` constant, for use with `doxa_auth::Require<M>`. Requires `doxa-policy` in the consumer's dependency tree.

```rust
use doxa_macros::capability;

#[capability(
    name = "widgets.read",
    description = "Read widget definitions",
    checks(action = "read", entity_type = "Widget", entity_id = "collection"),
)]
pub struct WidgetsRead;

// Use in a handler — enforces at runtime AND stamps OpenAPI security metadata
#[get("/widgets")]
async fn list_widgets(_: Require<WidgetsRead>) -> Json<Vec<Widget>> {
    Json(load().await)
}
```

Multiple `checks(...)` blocks are supported — all must pass for the capability to be granted.

### `#[capability]` attributes

| Key | Required | Description |
|-----|----------|-------------|
| `name` | yes | Stable client-facing capability identifier (e.g. `"widgets.read"`) |
| `description` | yes | Human-readable description, displayed in UI badges |
| `checks(...)` | yes (1+) | One or more check blocks with `action`, `entity_type`, `entity_id` |

## License

Apache 2.0
