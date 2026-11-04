# doxa

**Enterprise API plumbing for [axum](https://github.com/tokio-rs/axum) — OpenAPI docs, auth, authorization, and audit — without the boilerplate.**

```rust
use axum::{extract::Path, Json};
use doxa::{get, ApiDocBuilder, ApiError, MountDocsExt, MountOpts, ToSchema};
use serde::Serialize;

// The state every route is mounted under; this server has none
#[derive(Clone, doxa::State)]
struct NoState;

// Every route in this module and below
#[doxa::service]
struct Api;

// Derive once → typed HTTP errors + OpenAPI responses + audit outcomes
#[derive(Debug, thiserror::Error, Serialize, ToSchema, ApiError)]
enum WidgetError {
    #[error("widget not found")]
    #[api(status = 404, code = "not_found", outcome = "allowed")]
    NotFound,
}

/// A widget in the system. ← shows up in the OpenAPI schema docs.
#[derive(Serialize, ToSchema)]
struct Widget {
    /// Unique widget identifier.
    id: u32,
    /// Human-readable display name.
    name: String,
}

// Declare a permission — becomes an OpenAPI security requirement + badge
#[capability(name = "widgets.read", description = "Read widgets")]
struct WidgetsRead;

// Attribute macro → OpenAPI path + handler in one shot
// Require<WidgetsRead> enforces the permission at runtime AND documents it in the spec
#[get("/widgets/{id}", tag = "Widgets")]
async fn get_widget(
    _: Require<WidgetsRead>,
    Path(id): Path<u32>,
) -> Result<Json<Widget>, WidgetError> {
    if id == 0 { return Err(WidgetError::NotFound); }
    Ok(Json(Widget { id, name: "sprocket".into() }))
}

#[tokio::main]
async fn main() {
    // Every route mounts itself; no route lists
    let (router, api) = doxa::app(&NoState).split_for_parts();

    // One-liner: Scalar UI at /docs, JSON spec at /openapi.json
    let app = router.mount_docs(
        ApiDocBuilder::new().title("My API").version("0.1.0").merge(api).build(),
        MountOpts::default(),
    );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

That's a complete, runnable API server with interactive docs. When you're ready, enable more features:

```rust
// OIDC auth — generic over your claim struct
async fn list_widgets(Auth(ctx): Auth<MySession, MyClaims>) -> Json<Vec<Widget>> { /* ... */ }

// Cedar authorization — badge + security metadata in the OpenAPI spec
async fn delete_widget(_: Require<WidgetsAdmin>) -> StatusCode { /* ... */ }

// Or guard on the object itself — loads it, checks the policy against its
// attributes, and hands it to the handler already authorized
async fn get_widget(widget: Granted<Widget>) -> Json<Widget> { /* ... */ }

// Auth and append-only audit for every route in a module
#[doxa::layers(docs = [doxa::auth::AuthDocs])]
fn protected(routes: Routes, state: &AppState) -> Routes {
    routes
        .layer(AuthLayer::new(state.auth.clone()))
        .layer(AuditLayer::new(state.audit.clone()))
}

#[doxa::service(layers = protected)]
pub struct Widgets;

// Secrets that never leak into logs
let key: ProtectedString = load_secret();
tracing::info!(?key);  // logs [REDACTED]
key.expose();           // explicit, grep-able access
```

> *δόξα* — Greek for "accepted teaching." Root of *doctrine*, *orthodoxy*, *paradox*.

Born from a production enterprise stack where the same plumbing — OpenAPI docs, OIDC middleware, Cedar authorization, audit trails — kept getting reimplemented service after service. Rather than copy-paste it a fourth time, I extracted the generic parts, gave them a proper API, and published them so nobody else has to redo this work. These crates aren't greenfield experiments; they've been earning their keep in prod.

---

## Install

```toml
[dependencies]
doxa   = "0.1"           # OpenAPI docs + Scalar UI (default features)
utoipa = "5"             # required — see note below

# Enable the features you need:
# doxa = { version = "0.1", features = ["auth", "policy", "audit", "protected"] }
#
# Or everything at once:
# doxa = { version = "0.1", features = ["full"] }
```

> **`utoipa` must be a direct dependency.** doxa's macros (`#[get]`, `doxa::routes!`, etc.) expand to code that references `::utoipa::…` paths — we can't re-export those from doxa without breaking trait-resolution at the expansion site. Add `utoipa` to your `[dependencies]`; you don't need to `use` it directly.

## The crates

`doxa` is a facade that re-exports the family behind feature flags. You only need one dependency line.

| Feature | Crate | Does |
|---|---|---|
| `docs` (default) | [`doxa-docs`](https://github.com/edmiester777/doxa/tree/main/crates/doxa-docs) | OpenAPI docs, Scalar UI, `#[get]` / `#[post]` / `#[derive(ApiError)]`, SSE |
| `macros` (default) | [`doxa-macros`](https://github.com/edmiester777/doxa/tree/main/crates/doxa-macros) | Proc macros — re-exported from `doxa` by default |
| `auth` | [`doxa-auth`](https://github.com/edmiester777/doxa/tree/main/crates/doxa-auth) | OIDC / JWT middleware generic over your claim struct, and `Granted<T>` route guards |
| `policy` | [`doxa-policy`](https://github.com/edmiester777/doxa/tree/main/crates/doxa-policy) | Cedar authorization with pluggable storage |
| `audit` | [`doxa-audit`](https://github.com/edmiester777/doxa/tree/main/crates/doxa-audit) | Non-blocking audit log with auto-capture and trait-based outcomes, optional SeaORM sink |
| `protected` | [`doxa-protected`](https://github.com/edmiester777/doxa/tree/main/crates/doxa-protected) | `ProtectedString` — zeroize-on-drop, redacted everywhere |
| `client` | `doxa-client` | Call your routes from the browser as the functions they are, with a cache |
| `ui` | `doxa-ui` | Client-rendered components, `view!`, hooks and a router |
| `embed` | `doxa-docs` | Compile the built web app into the server binary |

The `doxa` binary (`cargo install doxa-cli`) scaffolds an app (`doxa new`), builds the browser half (`doxa build`), serves it with reload, hot-patching web crate changes into the running page (`doxa dev`), and formats `view!` markup (`doxa fmt`).

Each crate also works standalone if you prefer fine-grained control over your dependency graph.

## What you get

| Feature | Example |
|---|---|
| Minimal handler attributes | [1](#1-a-documented-endpoint) |
| Typed errors → OpenAPI responses + audit outcomes | [2](#2-typed-errors-grouped-by-status) |
| Documented Server-Sent Events | [3](#3-server-sent-events) |
| Redacted secret strings | [4](#4-secrets-that-dont-leak) |
| OIDC over your own claim struct | [5](#5-oidc-with-your-own-claims) |
| Auth layer with auto-documented OpenAPI | [6](#6-auth-layer--documented-middleware) |
| Putting it all together | [7](#7-full-app-assembly) |
| Cedar authorization, your storage | [8](#8-cedar-authorization) |
| Capabilities → OpenAPI badges | [9](#9-capabilities--openapi-badges) |
| Per-object guards, derived from the row | [10](#10-guard-a-route-on-the-object-it-is-about) |
| Non-blocking audit log | [11](#11-non-blocking-audit-log) |
| Router with audited + unaudited routes | [12](#12-audited-router-with-public-routes) |
| Handler-level audit enrichment | [13](#13-audit-enrichment-in-handlers) |
| Custom audit middleware | [14](#14-custom-middleware-that-emits-audit-events) |
| Custom audit event types | [15](#15-custom-audit-event-types) |
| Call a route from the browser | [16](#16-call-a-route-from-the-browser) |
| Pages that call routes | [17](#17-pages-that-call-routes) |
| Routes declared in an API crate, implemented by the server | [21](#21-declare-routes-in-an-api-crate) |

---

## Examples

### 1. A documented endpoint

```rust
use axum::{extract::Path, Json};
use doxa::{get, ApiError, ApiDocBuilder, MountDocsExt, MountOpts, ToSchema};
use serde::Serialize;

#[derive(Clone, doxa::State)]
struct NoState;

#[doxa::service]
struct Api;

#[derive(Debug, thiserror::Error, Serialize, ToSchema, ApiError)]
enum WidgetError {
    #[error("not found")]
    #[api(status = 404, code = "not_found")]
    NotFound,
}

#[derive(Debug, Serialize, ToSchema)]
struct Widget { id: u32, name: String }

#[get("/widgets/{id}")]
async fn get_widget(Path(id): Path<u32>) -> Result<Json<Widget>, WidgetError> {
    if id == 0 { return Err(WidgetError::NotFound); }
    Ok(Json(Widget { id, name: "gadget".into() }))
}

#[tokio::main]
async fn main() {
    let (router, openapi) = doxa::app(&NoState).split_for_parts();
    let docs = ApiDocBuilder::new().title("Widgets API").version("0.1.0").merge(openapi).build();
    let app = router.mount_docs(docs, MountOpts::default());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

Scalar UI at `/docs`, spec at `/openapi.json`.

### 2. Typed errors, grouped by status

Multiple variants can share a status; doxa groups them into one OpenAPI response with distinct examples. The `outcome` attribute declares the audit trail outcome for each variant — `AuditLayer` reads it from response extensions automatically. When omitted, the outcome defaults to `"error"`.

```rust
#[derive(Debug, thiserror::Error, Serialize, ToSchema, ApiError)]
enum CheckoutError {
    #[error("validation failed: {0}")]
    #[api(status = 400, code = "validation_error", outcome = "error")]
    Validation(String),

    #[error("duplicate order: {0}")]
    #[api(status = 400, code = "duplicate_order", outcome = "error")]
    Duplicate(String),

    #[error("item not found")]
    #[api(status = 404, code = "not_found", outcome = "allowed")]
    NotFound,  // legitimate miss — not a security event

    #[error("payment declined")]
    #[api(status = 403, code = "payment_declined", outcome = "denied")]
    PaymentDeclined,
}
```

One derive → two OpenAPI responses (`400`, `404`), `IntoResponse` impl, and `HasAuditOutcome` impl. The audit layer picks up the outcome from the response — no manual `emit_error` needed.

### 3. Server-Sent Events

```rust
#[derive(Serialize, ToSchema, SseEvent)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
enum Progress {
    Started { job_id: u64 },
    Tick { percent: u8 },
    Completed { job_id: u64 },
}

#[get("/jobs/{id}/progress")]
async fn stream_progress(Path(id): Path<u64>)
    -> SseStream<Progress, impl Stream<Item = Result<Progress, Infallible>>>
{
    SseStream::new(async_stream::stream! {
        yield Ok(Progress::Started { job_id: id });
        yield Ok(Progress::Tick { percent: 50 });
        yield Ok(Progress::Completed { job_id: id });
    })
}
```

The spec reflects `text/event-stream` and the three event names: the 200
response gets a description enumerating the `event:` frame names (`started`,
`tick`, `completed`) and an `x-sse-event-names` extension carrying the same
list machine-readably, alongside the event-payload schema (`itemSchema` in
3.2, `schema` in 3.1).

### 4. Secrets that don't leak

```rust
use doxa::protected::ProtectedString;

#[derive(Deserialize)]
struct Config { api_key: ProtectedString }

let cfg: Config = serde_yaml::from_str("api_key: sk-live-abc123").unwrap();
tracing::info!(?cfg, "loaded");         // logs `[REDACTED]`
connect(cfg.api_key.expose());          // explicit, grep-able
```

`Debug` / `Display` / `serde::Serialize` all emit `[REDACTED]`. Zeroized on drop. OpenAPI schema uses `format: password`.

### 5. OIDC with your own claims

```rust
use doxa::auth::{Auth, Claims};

#[derive(Debug, Clone, Deserialize)]
struct MyClaims {
    sub: String,
    email: String,
    tenant_id: String,
    roles: Vec<String>,
}

impl Claims for MyClaims {
    fn sub(&self) -> &str { &self.sub }
    fn roles(&self) -> &[String] { &self.roles }
    fn scope(&self) -> Option<&str> { Some(&self.tenant_id) }
}

async fn whoami(Auth(ctx): Auth<MySession, MyClaims>) -> String {
    format!("hello {} from tenant {}", ctx.claims.email, ctx.claims.tenant_id)
}
```

JWKS fetch and caching, JWT signature verification, RFC 7662 introspection fallback. Works with Keycloak, Auth0, Cognito, Okta, Azure AD, or any RFC-compliant IdP. Drop the `axum` feature to use the pipeline standalone.

### 6. Services and layer stacks

A route attribute mounts its handler, and a `#[doxa::service]` owns every handler in its module and the modules below it, a deeper service winning. A handler joins another service by moving to its module. Its layers are a `#[doxa::layers]` function, which services share and stacks call:

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

// widgets/public.rs
#[doxa::service]
pub struct WidgetsPublic;

// widgets/admin.rs
#[doxa::service(layers = crate::admin)]
pub struct WidgetsAdmin;

#[get("/widgets/purge")]
async fn purge(State(db): State<DatabaseConnection>) -> StatusCode { /* ... */ }
```

The stack's body is plain `.layer()` calls. `docs = [...]` is what it adds to each operation, named once for the served document and for `doxa::spec()`, which builds the same document with no state: a `DocumentedLayer + Default` type, or another stack for its docs. `AuthDocs` is the bearer requirement and `401` that `AuthLayer` adds.

Handlers name no state type: `#[derive(doxa::State)]` marks the crate's one state, and each handler's `State<T>` and `FromRef` extractors are checked against it at compile time. A crate with routes and no derive is "routes in this crate share a state: add `#[derive(doxa::State)]` to it"; a server with none derives it on a unit struct. `#[get("/x", mount = false)]` leaves a handler to `routes!`.

`doxa::app(&state)` and `doxa::spec()` stop, naming each, on a handler under no service, two services in one module, a declared route nothing implements, a schema name two types claim, or another state type.

### 7. Full app assembly

```rust
#[tokio::main]
async fn main() {
    let state = AppState { db: connect().await, auth: build_auth_state().await };
    let (router, openapi) = doxa::app(&state).split_for_parts();

    // bearer_security registers the scheme AuthDocs names
    let api_doc = ApiDocBuilder::new()
        .title("My Service")
        .version("0.1.0")
        .bearer_security("bearer")
        .merge(openapi)
        .build();

    let app = router.mount_docs(api_doc, MountOpts::default());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

`/docs` shows Scalar with the auth lock icon on the operations a `protected` service owns, and the `401` response and `security` requirement on those alone.

### 8. Cedar authorization

```rust
use doxa::auth::Auth;
use doxa::policy::{PolicyRouter, uid::build_uid};

// At startup — build the router from your store implementation
let store  = MyPolicyStore::from_database(&db).await?;
let router = PolicyRouter::new(Arc::new(store), MyExtension);

// In a handler — pull tenant + roles from the auth context
async fn check_document(
    Auth(ctx): Auth<MySession, MyClaims>,
    State(router): State<Arc<PolicyRouter<MyExtension>>>,
    Path(doc_id): Path<String>,
) -> Result<Json<Document>, MyError> {
    // The tenant is the partition the policy store is keyed by, so there
    // is nothing to evaluate without one. A single-tenant deployment
    // returns a constant from `Claims::scope` rather than `None`.
    let tenant = ctx.tenant_id().ok_or(MyError::Unscoped)?;

    let resource = build_uid("Document", &doc_id)?;
    let decision = router
        .check(tenant, ctx.roles(), "read", resource)
        .await?;
    // decision.allowed is true/false, decision.reason explains why
    // ...
}
```

Implement `PolicyStore` for your backend. `PolicyExtension` plugs in domain-specific post-evaluation (e.g., row-level filters from Cedar residuals). `PolicyRouter` is the centralized slow-path PEP.

This is the manual form, and it is worth seeing once because everything below is built on it. You rarely write it: `Granted<T>` (example 10) runs this same chain from the route signature and hands back the loaded object, and `Require<M>` (example 9) does it for a fixed capability.

### 9. Capabilities → OpenAPI badges

Declare a capability, bind it to a marker, and gate the route. doxa ships the `Require<M>` extractor — it enforces at runtime *and* stamps the OpenAPI security + badge metadata automatically.

```rust
use doxa::auth::Require;
use doxa::policy::{Capable, Capability, CapabilityCheck, ResourceId};

pub const WIDGETS_READ: Capability = Capability {
    name: "widgets.read",
    description: "Read widget definitions",
    checks: &[CapabilityCheck { action: "read", entity_type: "Widget", entity_id: ResourceId::Literal("collection") }],
};

pub struct WidgetsRead;
impl Capable for WidgetsRead {
    const CAPABILITY: &'static Capability = &WIDGETS_READ;
}

#[get("/widgets")]
async fn list_widgets(_: Require<WidgetsRead>) -> Json<Vec<Widget>> {
    Json(load().await)
}
```

Or with the `#[capability]` attribute macro (enable the `policy` feature on `doxa-macros`):

```rust
use doxa::auth::Require;
use doxa_macros::capability;

#[capability(
    name = "widgets.read",
    description = "Read widget definitions",
    checks(action = "read", entity_type = "Widget", entity_id = "collection"),
)]
pub struct WidgetsRead;

#[get("/widgets")]
async fn list_widgets(_: Require<WidgetsRead>) -> Json<Vec<Widget>> {
    Json(load().await)
}
```

Output in the rendered spec: a standard `security` requirement for codegen, an `x-required-permissions` extension for downstream tooling, and an `x-badges` chip rendered on the operation in Scalar. To use a custom OpenAPI scheme name instead of `"bearer"`, write `Require<WidgetsRead, MyScheme>` with a `SchemeName` impl.

### 10. Guard a route on the object it is about

A capability answers *may they call this at all*. Most routes need the narrower question — *may they do this to **this** object* — which means loading the object first and checking against its attributes. `Granted<T>` covers both, plus the collection case in between:

| Form | Asks | Yields |
|------|------|--------|
| `Granted<Widget>` | may this caller act on **this object** | the loaded object |
| `Granted<Many<Widget>>` | what **subset** may they see | a query filter |
| `Granted<Cap<M>>` | may they call this at all | `()` |

```rust
use doxa::auth::{Cap, Granted, Many};

// Loads the widget, checks `read` against its Cedar attributes, 404s if
// it does not exist, 403s if the policy refuses. Derefs to the object.
#[get("/widgets/{id}")]
async fn get_widget(widget: Granted<Widget>) -> Json<Widget> {
    Json(widget.into_inner())
}

// The subset, as a filter the handler pushes into its own query
#[get("/widgets")]
async fn list_widgets(scope: Granted<Many<Widget>>) -> Json<Vec<Widget>> {
    Json(load_where(scope.into_inner()).await)
}

// The coarse gate, same as `Require<M>` but on the same guard
#[post("/flush")]
async fn flush(_: Granted<Cap<WidgetsRead>>) -> StatusCode { StatusCode::OK }
```

Destructure for the caller alongside the object — no second `Auth<S, C>` extractor, and the context is shared rather than copied:

```rust
async fn transfer(Granted(caller, widget): Granted<Widget>) -> StatusCode { /* ... */ }
```

**Where the key comes from, and what it is called.** Neither is stated. The source is inferred — an instance route whose template names no parameter can only be reading its key from the query string — and the OpenAPI parameter moves with it:

```rust
// /widgets/{name}
#[get("/widgets/{name}")]
async fn get(w: Granted<WidgetByName>) -> Json<Widget> { /* ... */ }

// /widgets?name=…
#[get("/widgets")]
async fn find(w: Granted<WidgetByName>) -> Json<Widget> { /* ... */ }
```

*Which* parameter it reads is the key's, not the route's. A key is a struct deriving `Deserialize` and the guard reads it with axum's own `Path` / `Query`, so the field names are the route parameters — even with several segments to choose from:

```rust
// binds {name}, because that is the field `WidgetByName`'s key has
#[get("/widgets/{name}/revisions/{rev}")]
async fn get_revision(widget: Granted<WidgetByName>, /* ... */) -> Json<Revision> { /* ... */ }
```

To spell a segment differently, rename the field at the row — `#[resource(key = "slug")]` — rather than per route. A route whose parameters do not include the key's fails the build.

**What the route owes.** One trait says what the asset is and what may be done to it:

```rust
doxa::auth::route_key!(pub WidgetKey { id: u32 });

impl Granting for Widget {
    type Row = Self;              // the Cedar identity, from #[derive(PolicyResource)]
    type Key = WidgetKey;         // one named field per segment: {id}
    type Ctx = CapabilityContext; // tenant + roles, or your own Auth context
    type State = DatabaseConnection;      // what load() is handed
    type Source = FromState<DatabaseConnection>; // how the guard gets hold of it
    type Error = DbLoadError;

    /// The whole vocabulary, as a type. Every form bounds its action on
    /// `Table = Self::Actions`, so an action from another asset does not
    /// compile here — even where the two spell it the same.
    type Actions = WidgetAction;

    async fn load(WidgetKey { id }: WidgetKey, db: &Self::State, ctx: &Self::Ctx)
        -> Result<Option<Self>, Self::Error> { /* ... */ }
}
```

The action is a type, one of the markers `#[derive(Actions)]` emits per variant. A route that names none resolves through its method — `get` → `ReadAction`, `post` → `CreateAction`, `put` / `patch` → `UpdateAction`, `delete` → `DeleteAction` — against the mapping the vocabulary itself declares with `#[action(verb = get)]`. Nothing is derived from a name, so a vocabulary calling its read action `View` needs no special case. `#[grant(action = Archive)]` names one the method does not imply. The spec gets the same treatment `Require<M>` gives: `security`, the `x-badges` chip, and the `401` / `403` responses the guard itself can return — plus `400` and `404` on the instance form, which is the only one that parses a key and loads an object.

**Most of that is derivable.** With the `policy-sea-orm` feature, `#[derive(PolicyResource)]` writes both the Cedar identity and the scoped lookup from field roles, and `#[asset]` writes the `Granting` impl:

```rust
#[derive(DeriveEntityModel, PolicyResource)]
#[resource(entity_type = "Widget")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: Uuid,
    #[resource(id, attr, key)]     // Cedar id, policy attribute, and route key
    pub name: String,
    #[resource(parent = "Tenant", scope)]  // every lookup is confined to this
    pub tenant_id: String,
}

#[derive(Actions)]
#[actions(resource = "Widget", prefix = "widgets")]
pub enum WidgetAction {
    /// List and view widgets.
    Read,
    /// Remove widgets.
    Delete,
}

// The application's caller, state and error, stated once for every asset
impl GrantProfile for AppGrants {
    type Ctx = CapabilityContext;
    type State = DatabaseConnection;
    type Source = FromState<DatabaseConnection>;
    type Error = DbLoadError;
}

#[asset(row = Model, profile = AppGrants, actions = WidgetAction, list = tenant)]
pub struct WidgetByName;

// A second route key over the same row — a unit struct, not a newtype, so
// the row keeps one Cedar identity and two routes cannot disagree about it
#[asset(row = Model, key = pk, profile = AppGrants, actions = WidgetAction)]
pub struct WidgetById;
```

`#[resource(scope)]` is the security property: every generated lookup carries the scope column, so another tenant's row is *absent* rather than refused — the route answers `404` where a primary-key lookup would have leaked its existence with a `403`. `#[derive(Actions)]` generates the `widgets.read` / `widgets.delete` capabilities from the variants and their doc comments, registering each so `doxa::policy::capabilities()` lists them without a hand-maintained catalog.

**When the guard cannot see it.** A guard runs before the request body exists. For what a handler finds in that body — or loads inside an open transaction — the same chain is reachable directly, recording exactly as the guard does:

```rust
// an object the handler already holds
let widget = find_widget(&txn, tenant, &name).await?
    .authorize::<WidgetByName, _>(widget_action::Read, &parts.extensions).await?;

// several of them, in one pass through the policy — the refusal still
// names the one that caused it
let folders = Folder::load_all_scoped(body.folders, &txn, tenant).await?
    .authorize_all_dependency::<FolderByName, _>(folder_action::Read, &parts.extensions).await?;
```

### 11. Non-blocking audit log

```rust
let logger = spawn_audit_writer(db, 4096);   // background mpsc → SeaORM

let audit = AuditEventBuilder::new(logger.clone());
audit.set_actor(Some(&principal), &roles, json!({ "tenant": tenant }));
audit.set_event(EventType::DataAccess, "read");
audit.set_resource("document", "doc-42");

let result = run_query().await;
audit.set_outcome(if result.is_ok() { Outcome::Allowed } else { Outcome::Error });
audit.emit();   // non-blocking
```

Events buffer onto a bounded channel; a background task persists them to the `doxa_audit_log` table. Applications define their own `AuditEventType` enum — the built-in one is a reference impl. Disable the `sea-orm` feature to ship events elsewhere.

When used with `AuditLayer` (example 12), most of this is automatic: HTTP metadata is captured from the request/response, and error outcomes propagate through the `#[api(outcome = "...")]` attribute on `ApiError` variants (example 2). Manual builder usage is only needed outside the HTTP request lifecycle.

### 12. Audited router with public routes

`AuditLayer` is a tower middleware that creates an `AuditEventBuilder` per request, injects it into extensions, and **auto-emits with `Outcome::Allowed`** after the response completes. Handlers on the happy path just enrich the builder and return — no terminal call needed.

Stack it **outside** the auth layer so the builder exists before auth runs. Auth failures are recorded automatically. Routes outside both layers are unaudited.

```rust
use doxa::auth::{AuthDocs, AuthLayer};
use doxa::audit::AuditLayer;
use doxa::Routes;

// Layer order matters: AuditLayer wraps AuthLayer.
#[doxa::layers(docs = [AuthDocs])]
fn audited(routes: Routes, state: &AppState) -> Routes {
    routes
        .layer(AuthLayer::new(state.auth.clone()))
        .layer(AuditLayer::new(state.audit.clone()))
}

// documents.rs: audited and authenticated
#[doxa::service(layers = crate::audited)]
pub struct Documents;

// health.rs: no layers, no audit events
#[doxa::service]
pub struct Health;
```

The split is by module: handlers in `documents` get auth and audit, and health checks and readiness probes stay silent. `AuthState::audit` can be `None` when `AuditLayer` is in the stack.

### 13. Audit enrichment in handlers

`AuditLayer` injects an `AuditEventBuilder` into request extensions with request metadata (method, path, source IP, user-agent, request ID) already populated. The auth layer stamps actor info (sub, roles, tenant). Handlers enrich the builder with domain context and return — the layer handles everything else.

**Outcome propagation is automatic.** When an `ApiError` is returned, its `outcome` attribute (from example 2) is attached to the response and the layer reads it. Handlers only need `emit_denied`/`emit_error` for non-`ApiError` error paths.

**A guarded route needs none of this.** `Granted<T>` (example 10) already resolved which action it checked and which object it checked against, and the audit category sits beside the action in the same `ACTIONS` table:

```rust
#[derive(Actions)]
#[actions(resource = "Document")]
pub enum DocumentAction {
    #[action(verb = get, event = EventType::DataAccess.as_static())]
    Read,
    #[action(verb = delete, event = EventType::AdminDelete.as_static())]
    Delete,
}

#[get("/documents/{id}")]
async fn get_document(doc: Granted<Document>) -> Json<Document> {
    Json(doc.into_inner())
    // event_type = data_access, action = read, resource = Document/<id>,
    // outcome, status and duration from the layer. Nothing to call.
}
```

The guard deposits all three and the layer folds them in after the response, so the handler writes nothing. A refusal takes the same path, so the grant and the denial name the same action and the same resource. `#[derive(Actions)]` writes the table, the markers and the verb mapping from the variants; `#[action(…)]` appears only where a default is wrong. Writing an `ActionTable` impl and its markers by hand is the other option.

What follows is the unguarded case — a route with no `Granted` on it, or a handler that knows something the guard cannot. Anything set here wins over the deposit, in any order:

```rust
use axum::{extract::Path, Extension, Json};
use doxa::audit::{AuditEventBuilder, EventType};

#[get("/documents/{id}")]
async fn get_document(
    Path(id): Path<String>,
    Extension(audit): Extension<AuditEventBuilder>,
) -> Result<Json<Document>, DocumentError> {
    audit.set_event(EventType::DataAccess, "read");
    audit.set_resource("document", &id);

    let doc = db::find_document(&id).await?;
    // ↑ If this returns Err(DocumentError::NotFound), the outcome attribute
    //   on that variant (e.g. outcome = "allowed") propagates automatically.

    audit.set_response_summary(serde_json::json!({
        "size_bytes": doc.body.len(),
    }));

    Ok(Json(doc))
    // ← Success: AuditLayer auto-emits Outcome::Allowed
    // ← Error: AuditLayer reads the outcome from DocumentError's ApiError derive
}
```

All clones of a builder share state behind an `Arc`, so exactly one emission occurs regardless of how many extractors or middleware touch it.

The layer also auto-captures `http_method`, `http_path`, and `http_status` on every request — no handler code needed for HTTP metadata.

### 14. Custom middleware that emits audit events

For cross-cutting concerns that aren't tied to a single handler — rate limiting, IP blocking, request validation — write a tower middleware that pulls the `AuditEventBuilder` from extensions and emits before short-circuiting.

```rust
use axum::{extract::Request, middleware::Next, response::Response, http::StatusCode};
use doxa::audit::{AuditEventBuilder, EventType};

/// Middleware that audits requests blocked by an IP denylist.
async fn ip_denylist_audit(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let ip = request
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");

    if is_blocked(ip) {
        // Pull the builder the auth layer injected (if present)
        if let Some(audit) = request.extensions().get::<AuditEventBuilder>().cloned() {
            audit.emit_permission_denied(
                EventType::AuthFailure,
                "ip_blocked",
                "api",
                "global",
                &format!("IP {ip} is on the denylist"),
            );
        }
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}

/// Middleware that tags every mutation request for auditing.
async fn tag_mutations(
    request: Request,
    next: Next,
) -> Response {
    if let Some(audit) = request.extensions().get::<AuditEventBuilder>() {
        let is_mutation = matches!(
            *request.method(),
            axum::http::Method::POST | axum::http::Method::PUT
                | axum::http::Method::PATCH | axum::http::Method::DELETE
        );
        if is_mutation {
            // All clones share state — safe to enrich from middleware
            audit.set_event(EventType::AdminUpdate, request.method().as_str());
        }
    }
    next.run(request).await
}
```

Stack custom middleware between `AuditLayer` (outermost) and the routes:

```rust
use axum::middleware;

#[doxa::layers(docs = [AuthDocs])]
fn audited(routes: Routes, state: &AppState) -> Routes {
    routes
        .layer(AuthLayer::new(state.auth.clone()))
        .layer(middleware::from_fn(ip_denylist_audit))
        .layer(AuditLayer::new(state.audit.clone()))
}
```

`AuditLayer` creates the builder first. Auth stamps actor info. Your custom middleware can inspect it, enrich it, or record a terminal outcome and short-circuit.

**A terminal called inside the request records; it doesn't send.** Emitting *takes* the builder, so a call from a handler or middleware would land before the response exists — costing `http_status`, truncating `duration_ms`, and vouching for anything fallible that came after it. When an `AuditLayer` owns the builder, `emit`, `emit_denied`, `emit_error` and friends record their outcome and leave the sending to the layer's auto-emit moments later. Nothing is lost and the timing is right, so the denylist middleware above gets its event *with* the 403 it returned.

Without an `AuditLayer` in the stack there is nobody else to send it, and those calls emit exactly as they always did.

### 15. Custom audit event types

The built-in `EventType` covers common CRUD + auth patterns, but you define the vocabulary for your domain by implementing `AuditEventType`.

```rust
use doxa::audit::AuditEventType;

#[derive(Debug, Clone, Copy)]
enum BillingEvent {
    InvoiceGenerated,
    PaymentProcessed,
    SubscriptionChanged,
    RefundIssued,
}

impl AuditEventType for BillingEvent {
    fn as_str(&self) -> &str {
        match self {
            Self::InvoiceGenerated   => "billing.invoice_generated",
            Self::PaymentProcessed   => "billing.payment_processed",
            Self::SubscriptionChanged => "billing.subscription_changed",
            Self::RefundIssued       => "billing.refund_issued",
        }
    }
}

// Use it exactly like the built-in EventType
audit.set_event(BillingEvent::PaymentProcessed, "charge");
audit.set_resource("invoice", &invoice_id);
// AuditLayer auto-emits with Outcome::Allowed after the response
```

The `event_type` column stores whatever `as_str()` returns (up to 50 bytes). This means you can query the audit log by domain — `WHERE event_type LIKE 'billing.%'` — without schema changes.

---

### 16. Call a route from the browser

Routes live in a crate both halves share. The client crate is the same source with a one-line `build.rs`, and in it every route is a function that sends the request the route expects:

```toml
# client/Cargo.toml
[lib]
path = "../api/src/lib.rs"
```

```rust
// client/build.rs
fn main() { doxa_role::client() }
```

```rust
// api/src/widgets.rs — compiled by both
doxa::prelude!();

#[get("/api/widgets/{name}")]
pub async fn get_widget(widget: Granted<WidgetByName>) -> Json<Widget> {
    Json(widget.into_inner())
}

// anywhere in the client: the same name, minus server-only arguments
let w: Widget = get_widget("sprocket").await?;
```

Wire types take `#[dto]`, which derives serde both ways, `ToSchema`, `Debug`, `PartialEq` and `Clone` (`#[dto(query)]` adds `IntoParams`, `#[dto(skip(Debug))]` drops one). In the client half it strips derives the browser has no use for, such as an ORM's, along with their attributes:

```rust
#[dto]
#[derive(garde::Validate)]
pub struct Rename { #[garde(length(min = 1))] pub name: String }
```

A validating extractor runs the same rules in both halves. The server answers `422` with each failing field, and the call refuses with those fields before anything is sent. `doxa::Valid` (feature `garde`), `doxa::validator::Valid` (`validator`) and `doxa::serde_valid::Valid` (`serde-valid`) ship. An app's own wrapper implements `doxa::wire::Validates` and derives `doxa::Validator`:

```rust
#[patch("/api/widgets/{name}")]
pub async fn rename_widget(w: Granted<WidgetByName>, Valid(Json(r)): Valid<Json<Rename>>) -> Json<Widget> { … }

let form = form(Rename::default()).rules(rename_widget::check);   // live field errors, by the route's rules
```

Server-only items in a shared file take `#[server]`, or `doxa::server_only! { mod store; }` for a module. A call is always `pub`, and `doxa::client_pub! { mod api; }` makes a module the server keeps private public in the client half. GETs are cached and deduplicated, mutations invalidate what they touch, and `rename_widget::can(&key)` dry-runs the route's own guard.

A server whose routes can't be shared as source still gets a client crate. Its `build.rs` reads the server's own OpenAPI document, and the frontend depends only on the generated crate:

```rust
// orders-server: the document, built without state or I/O
#[doxa::spec]
pub fn api_doc() -> doxa::ApiDoc { /* ApiDocBuilder::new()…merge(api).build() */ }

// orders-client/build.rs, with orders-server and doxa-build (feature `client`) as build-dependencies
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

A document that isn't a dependency, such as a saved `openapi.json`, goes through `doxa_build::openapi_from_json(&text)?` first. `.exhaustive()` drops `#[non_exhaustive]` from its enums, and `.forms()` derives `Form` and `Default` on its structs and enums (doxa feature `forms`; a `.types()` mapping must be `Default` too). Its calls are made by the same stub, so they cache, invalidate, probe with `::can` and stream as a shared-source client's do. The route macros stamp what OpenAPI can't say (entities, keys, dry runs, streams, error types) as `x-doxa`.

Each client crate's routes go to its own server. `doxa::prelude!();` at the root of the shared `lib.rs` gives the client crate a `service()`, with its own cache, session and layers. Base URLs default to `[package.metadata.doxa.services]` on the web crate, and a deployment can change them in `services.json` without a rebuild. Credentials are layers:

```rust
layers().push(bearer(|| session::token()));             // every crate's requests
orders_client::service().layers().push(cookies());      // one crate's requests
```

Feature `oidc` signs in with an OpenID Connect issuer (authorization code with PKCE). It refreshes ahead of expiry, and one tab refreshes for all of them:

```rust
let auth = Oidc::<Claims>::issuer("https://id.example.com/realms/acme").client_id("web").install();
layers().push(auth.bearer()).push(on_status(401, move |_| auth.sign_in()));
App::new(router().guard(auth.required())).mount("#app");

// in a component; re-renders when the session changes
if let Some(t) = doxa::ui::oidc::session::<Claims>().tokens() { /* t.claims().name */ }
```

A server the browser reaches cross-origin needs `.layer(doxa::Cors::allow([app_origin]))` (feature `cors`) so the client can read doxa's wire headers. Or keep it same-origin: `.merge(doxa::proxy("/orders", orders_url))` (feature `proxy`) forwards a prefix and streams SSE through.

### 17. Pages that call routes

```rust
use doxa::ui::prelude::*;

#[page("/widgets/{name}", load = |p| get_widget(&p.name))]
async fn WidgetPage(name: String) -> Result<View> {
    let key = WidgetKey { name };
    let widget = get_widget(&key).await?;
    let editing = state(false);
    Ok(view! {
        <h1>{&widget.name}</h1>
        <Can route={rename_widget} args={&key}>
            <button on:click={move |_| editing.toggle()}>"Rename"</button>
        </Can>
    })
}

#[doxa::start]
fn start() {
    App::new(Router::new().page::<WidgetPage>()).mount("#app");
}
```

A component can be generic, `fn Table<T: Clone + 'static>(rows: Vec<T>, …)`, and `<Table rows={runs}/>` infers `T`. An `#[attrs] rest: Attrs` prop collects every attribute, `on:` handler and `use:` directive the tag passes that isn't a prop, and `<button {..rest}>` spreads them; `rest.class()` reads the class to merge, and the element's own attributes win. `class:active={on}` toggles one class without touching the others, and `classes!["btn", (pending, "busy"), rest.class()]` joins the parts that are there. With feature `tailwind`, `doxa::tailwind::cn!["px-4 py-2", rest.class()]` also drops each Tailwind class a later one overrides (`px-4` given `p-2`), by tailwind-merge's rules; `Merger::extend` adds theme scales and groups. The same pages render natively into an in-memory document for tests, and `doxa::ui::testing::Screen` finds what a user would: `screen.role(Role::Button).name("Save").click().await`, `screen.label("Title").type_text("Q3").await`, `screen.find_text("Saved").await?`, running tasks and due timers on the manual clock until a match shows. `testing::fake::<Popover>(|p| view! { … })` renders a stand-in where a React island would. [`examples/widgets`](examples/widgets) has the whole app: `api` (shared routes), `client` (their client half), `server`, and `web` (the pages, tested against the real router).

### 18. Plain JS modules as Rust

```rust
use doxa::ui::{npm, JsError};

#[npm(module = "cronstrue")]
extern "js" {
    #[npm(export = "toString")]
    pub fn describe(expr: &str, opts: &DescribeOpts) -> Result<String, JsError>;
}

#[npm(module = "./ts/render.js", lazy)]          // fetched on first call, in its own chunk
extern "js" {
    pub async fn render(src: &str) -> Result<Rendered, JsError>;
}
```

Arguments and returns cross through serde (feature `npm`); JS types declared with `type X;` and `JsValue` pass through untouched, and a `Promise` becomes a future.

### 19. Icons

```rust
use doxa::ui::{icons, prelude::*};

#[icons(npm = "lucide-static", dir = "icons")]        // icons/chevron-down.svg …, read at compile time
pub enum Icon { ChevronDown, Plus, Trash2 }

#[react(module = "lucide-react")]                     // each variant an island of its export
pub enum Lucide { ChevronDown, Plus, #[react(export = "Trash2")] Trash }

view! { <button>{Icon::Plus.size(16)}"Add"</button> {Lucide::Trash.class("muted")} }
```

Only the listed variants are compiled in, and one with no file fails to compile. `doxa build` tells the macro where `node_modules` is; `dir = "./assets/icons"` reads SVGs under the crate.

### 20. Typed query strings

```rust
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RunFilter { pub status: Option<RunStatus>, #[serde(default)] pub page: u32 }

#[page("/widgets/{name}/runs")]
fn RunsPage(name: String, #[query] filter: RunFilter) -> View { … }

let next = RunsPage::route(&name).query(&RunFilter { page: 2, ..filter.clone() });
set_query_as(|f: &mut RunFilter| f.page += 1);             // replaces the history entry
```

A query that doesn't parse renders the router's `not_found`, as a path parameter that doesn't parse does.

### 21. Declare routes in an API crate

When handlers depend on crates the browser can't build, the routes go in an API crate as declarations: the signature without a body. Its `build.rs` calls `doxa_role::api()`, and one crate is both the client and the contract the server implements:

```rust
// orders-api/src/lib.rs
doxa::prelude!();

route_key!(pub OrderKey { id: u32 });

#[dto]
#[entity(key = OrderKey)]
pub struct Order { pub id: u32, pub item: String }

#[get("/api/orders/{id}")]
pub async fn get_order(order: Grant<Order>) -> Result<Json<Order>, OrderError>;

// orders-server/src/lib.rs
#[derive(Clone, FromRef, doxa::State)]
pub struct AppState { db: Db }

#[doxa::service]
pub struct Orders;

#[asset(row = OrderRow, key = OrderKey, profile = AppGrants, actions = OrderAction, entity = orders_api::Order)]
pub struct OrderById;

#[implements(orders_api::get_order)]
async fn get_order(order: Granted<OrderById>, State(db): State<Db>) -> Result<Json<Order>, DbErr> { … }

// the client: as with a shared route
let o: Order = orders_api::get_order(OrderKey { id: 7 }).await?;
```

`#[implements]` mounts the handler at the declared method and path, and fails to compile when it takes or answers other than the declaration does; server-only extractors go anywhere. `Grant<Order>` is held to an asset whose `entity =` names `Order`, with the same key. The declaration's docs, tags and operation id become the operation's.

A route's entities are what the client caches its answer under and what its other calls invalidate: the entity its guard names (`Grant<Order>`, `Grant<Many<Order>>`), the entity it answers (`Order`, `Vec<Order>` or `Option<Order>`), and `touches = [Customer]` for any other it changes. So `place_order` answering `Json<Order>` refreshes `list_orders(_: Grant<Many<Order>>, …)`. A handler guarding with `Granted<Many<OrderById>>` where the declaration doesn't state `Grant<Many<Order>>` doesn't compile, since its clients couldn't dry-run or refresh it.

A handler may fail with its own error when it converts into the declared one, and answers the declared one. The conversion goes beside the error, compiled for the server only, with the server's dependency under `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]`:

```rust
#[server]
impl From<sea_orm::DbErr> for OrderError {
    fn from(e: sea_orm::DbErr) -> Self { OrderError::Internal(e.to_string()) }
}
```

`doxa::app(&state)` stops naming each route an API crate declares that no handler implements, once the server implements any route of that crate. `#[api(status = 500, internal)]` names the variant `doxa::Internal(msg)` converts into.

A type whose definition needs a server crate, such as an ORM enum, keeps a wire copy in the API crate, and `#[doxa::mirror(orders_api::Status)]` on the server's converts both ways; a variant or field only one side has doesn't compile. `doxa check --wire -p orders-api` builds the API crate for wasm and names a dependency that stops it, with the path that pulls it in.

## Design

- **Framework-neutral cores.** Auth, policy, and audit work without axum. Axum integration is feature-gated.
- **Generic over your domain.** Claim struct, session type, resource taxonomy, audit event variants — all consumer-defined.
- **Typed end to end.** Errors map to OpenAPI responses. SSE events carry their discriminator into the spec. `ProtectedString` carries redaction into its schema.
- **Cheap defaults.** Scalar loads from a CDN (overridable). Audit writes are async. OpenAPI specs are served from a shared `Bytes`.

## Acknowledgements

Huge thanks to the [axum](https://github.com/tokio-rs/axum) and [utoipa](https://github.com/juhaku/utoipa) teams. doxa is built on top of their work — this crate exists because their foundations are solid and we wanted to make it easier to build enterprise applications on them.

## License

Apache 2.0 — see [LICENSE](https://github.com/edmiester777/doxa/blob/main/LICENSE).
