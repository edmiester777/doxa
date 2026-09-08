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

`entity_id` takes a string literal, or the bare word `tenant` for a gate whose resource *is* the caller's partition — `entity_id = tenant`. That is an instruction to substitute the request's tenant, carried out before the consumer's UID builder is reached, which is why it is not spelled `"tenant"`.

## Authorization macros

Three macros cover what a guarded route needs: what the row *is* to Cedar, what may be *done* to it, and how a route *reaches* it. Used together with `doxa-auth`'s `Granted<T>`.

### `#[derive(PolicyResource)]`

Gives a domain type its Cedar identity — entity type, instance id, the attributes policies may reference, and its parents. The entity type doubles as the audit `resource_type`, so an audit row and the decision that produced it share one string.

```rust
#[derive(PolicyResource)]
#[resource(entity_type = "Widget")]
pub struct Model {
    pub id: Uuid,

    /// The Cedar id, an attribute policies can name, and the route's key.
    #[resource(id, attr, key)]
    pub name: String,

    /// Every generated lookup is confined to this column.
    #[resource(parent = "Tenant", scope)]
    pub tenant_id: String,
}
```

| Container key | Description |
|---------------|-------------|
| `entity_type` | Cedar entity type (required) |
| `id_with` | Method producing the Cedar id, when no single field is it |
| `attrs_with` | Method producing attributes no field backs |
| `tenant_parent` | Entity type this resource is `in` by virtue of the request rather than of any column |
| `filter` | A condition every query carries on top of the scope — repeatable, `AND`ed (needs `sea-orm`) |

| Field role | Description |
|------------|-------------|
| `id` | This field is the Cedar instance id |
| `attr` | Expose as `resource.<field>` to policies |
| `parent = "Type"` | This field holds the id of a parent entity |
| `key` | The value a route's key segment matches (needs `sea-orm`) |
| `key(Name, …)` | This column takes part in the named lookups (needs `sea-orm`) |
| `scope` | The column every query is confined to (needs `sea-orm`) |

With the `sea-orm` feature, `scope` emits a `ScopedTable` impl — the confinement column, plus the column behind each Cedar attribute so a policy residual can be translated — and `key` adds `ScopedRow` on top of it. Marking only `scope` is a table nothing addresses by a column: it can still be listed, still have a residual read against it, and still take `key = pk`, because a primary key belongs to the table rather than to a route. The key and the Cedar id are deliberately independent, so a row addressed by `{id}` and the same row addressed by `{name}` stay one Cedar entity reached two ways.

Bare `key` is the *unnamed* lookup, and there is one per struct. A row reached three ways runs out of it, so name them instead — a column may carry several names, and several columns may carry one, which makes a composite key and a column serving two routes the same declaration:

```rust
#[resource(entity_type = "Version", filter = Column::DeletedAt.is_null())]
pub struct Model {
    #[sea_orm(primary_key)]                         pub id: Uuid,
    #[resource(id, key(FindByDataset, FindByPair))] pub dataset: String,
    #[resource(key(FindByPair))]                    pub version: i64,
    #[resource(scope)]                              pub tenant_id: String,
    pub deleted_at: Option<DateTimeUtc>,
}
```

Each name emits a `Lookup` marker; a composite also gets a key struct — `FindByPairKey`, with a field per column and the `RouteKey` impl that parses it out of the route's path segments. A struct rather than a tuple, because every hand-written call site builds the key by position and two segments of the same type transpose silently. Route parsing stays positional in declaration order, since path segments are. A single-column lookup keys on the bare scalar.

`filter` is spliced rather than interpreted, so it is whatever SeaORM accepts. It hangs on the table, which is what makes it unforgettable: the key lookup, the id lookup, the listing and the residual filter all inherit it, and a soft delete applied to three of those four is not a compile error but a deleted row coming back on the fourth.

### `#[derive(Actions)]`

The vocabulary of what may be done to an asset. Each variant becomes a Cedar action, a `Capable` marker, and a capability whose description is the variant's doc comment.

```rust
#[derive(Actions)]
#[actions(resource = "Widget", prefix = "widgets")]
pub enum WidgetAction {
    /// List and view widgets.
    #[action(event = "data_access")]
    Read,
    /// Remove widgets.
    #[action(event = "admin_delete")]
    Delete,
}
```

That yields the `widgets.read` and `widgets.delete` capabilities as markers under `widget_action::`, usable as `Granted<Cap<widget_action::Delete>>`, plus the `ACTIONS` table `#[asset]` reads.

| Container key | Default | Description |
|---------------|---------|-------------|
| `resource` | enum name minus an `Action` / `Actions` suffix | The thing being acted on |
| `prefix` | `snake_case(resource)` | Capability name prefix — `{prefix}.{action}` |
| `entity_type` | `{resource}Collection` | Cedar entity type for the coarse check |
| `entity_id` | `"collection"` | Cedar id for the coarse check; also takes `tenant` |

| Variant key | Description |
|-------------|-------------|
| `name` | Cedar action name (default: snake_case of the variant) |
| `event` | Audit category, as an expression — `EventType::DataAccess.as_static()` |
| `description` | Capability description (default: the doc comment) |
| `capability` | Capability name, overriding `{prefix}.{action}` |
| `capable` | Gate on an existing `Capable` marker instead of minting one |
| `instance_only` | No coarse capability at all — this action is only ever checked per object |
| `entity_type` / `entity_id` | Override the coarse check's resource for this variant |

`event` is parsed as an expression, not a string literal, so it also accepts `EventType::DataAccess.as_static()` — worth preferring where you have the enum in scope. A bare `"data_acess"` compiles happily and files every event of that action under a category nothing reads.

### `#[asset]`

Writes the `Granting` impl. Six of its seven items are not decisions — `Ctx`, `State`, `Source` and `Error` belong to the application and are stated once on a `GrantProfile`; `Key` and `load` are the lookup the row already declared through `FetchByKey`. Only the vocabulary is a fact about this asset.

Nothing it writes names a backend. `FetchByKey` / `FetchById` / `FetchSubset` are `doxa-policy`'s and know about no ORM, so the declarations below read the same whether the row is a SeaORM model or a document behind an HTTP API. `#[derive(PolicyResource)]` answers those traits for a SeaORM model; anything else answers them itself.

```rust
#[asset(row = Model, profile = AppGrants, actions = WidgetAction, list = tenant)]
pub struct WidgetByName;

// A second route key over the same row: a unit struct naming it, not a
// newtype wrapping it, so both share one PolicyResource impl and cannot
// come to disagree about the object's Cedar identity.
#[asset(row = Model, key = pk, profile = AppGrants, actions = WidgetAction)]
pub struct WidgetById;
```

| Key | Description |
|-----|-------------|
| `row` | The row this descriptor reaches (default: `Self`) |
| `profile` | The application's `GrantProfile`, supplying `Ctx` / `State` / `Source` / `Error` |
| `actions` | The `#[derive(Actions)]` enum holding the vocabulary |
| `key` | Route key type, or `pk` for the row's own identifier (default: `<Row as FetchByKey<State>>::Key`) |
| `with` | A named `Lookup` to reach the row through — carries the row and the key, so `row` is implied |
| `load_with` | A loader to call instead of `FetchByKey::fetch` |
| `source` | Where the loader's state comes from, and therefore what it is (default: the profile's) |
| `ctx` / `error` | Override the profile, for the one asset that genuinely differs |
| `list = tenant` | Also emit a `Scoping` impl confined to the caller's tenant |

`key = pk` rather than a hand-written primary-key loader, because the obvious version is wrong in a way that passes every test: `Entity::find_by_id(id).one(db)` drops the tenant filter, and an instance check that then refuses it has already answered `403` where it would have answered `404` — confirming the row exists.

It calls `FetchById`, not `FetchByKey`, so it is reachable from a row marked `#[resource(scope)]` and nothing else. That is the case it most needs to cover: a table whose name route resolves through logic has no key column to mark, and would otherwise be left writing out the very lookup this exists to replace.

`with` is for the row reached more ways than `FetchByKey` and `FetchById` can spell between them. Those two are facets of the row, so a row gets one of each; a version addressed by uuid, by name and by `(dataset, version)` runs out. `#[resource(key(FindByPair))]` emits a marker per named way in, and `with = FindByPair` selects one — carrying the row and the key with it, so nothing else is restated:

```rust
#[asset(with = FindByPair, profile = AppGrants, actions = VersionAction)]
pub struct VersionByPair;
```

A named lookup is handed the same `&str` scope as an unnamed one, so it buys a second way in rather than a way out. Reach for it before `load_with`, which does not.

`load_with` is the same trade one level up, and the difference is one argument. `FetchByKey::fetch` is handed a `&str` scope and nothing else — that is the guarantee, not a thin signature, because a lookup that cannot see the caller cannot ignore the caller's tenant. `load_with` is handed the whole `Ctx`, which is what makes a role-dependent lookup expressible *and* what makes confinement yours to write.

Both halves are real. Use it when the lookup genuinely needs more than the scope, and write the tenant filter: a `load_with` that takes `_ctx` and means it compiles, passes its tests, and serves one tenant's rows to another — through the capability gate and the instance check, recorded in the trail as a legitimate grant. Nothing else about the chain changes: the coarse gate still runs first and costs no load, the instance check still runs on whatever came back, and the verdict still names the row's Cedar identity.

`source` is what the loader is handed and where it comes from, which move together. `source = Extension<Txn>` means the guard extracts the request's transaction and `load` receives `&Txn` — the case a router-state loader cannot serve, since a pool does not see rows the request has written and not committed.

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `sea-orm` | no | Emit the `ScopedTable` / `ScopedRow` half of `#[derive(PolicyResource)]` — the loader built from `#[resource(scope)]` and `#[resource(key)]` |

Off by default so the derive costs no ORM dependency for consumers that only need Cedar identity. With it off, using either role is an error naming the feature rather than a missing impl at the call site. Through the `doxa` facade it is reached as `policy-sea-orm`.

## License

Apache 2.0
