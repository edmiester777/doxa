# doxa

**Enterprise API plumbing for [axum](https://github.com/tokio-rs/axum) — OpenAPI docs, auth, authorization, and audit — without the boilerplate.**

```rust
use axum::{extract::Path, Json};
use doxa::{get, routes, ApiDocBuilder, ApiError, MountDocsExt, MountOpts, OpenApiRouter, ToSchema};
use serde::Serialize;

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
    // Build router — routes! collects schemas automatically
    let (router, api) = OpenApiRouter::new()
        .routes(routes!(get_widget))
        .split_for_parts();

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

// Append-only audit — non-blocking, auto-emits after each response
let audited = OpenApiRouter::new()
    .routes(routes!(list_widgets, delete_widget))
    .layer_documented(AuthLayer::new(auth_state))  // auth + OpenAPI metadata
    .layer(AuditLayer::new(audit_logger));          // audit trail

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
| `docs` (default) | [`doxa-docs`](crates/doxa-docs) | OpenAPI docs, Scalar UI, `#[get]` / `#[post]` / `#[derive(ApiError)]`, SSE |
| `macros` (default) | [`doxa-macros`](crates/doxa-macros) | Proc macros — re-exported from `doxa` by default |
| `auth` | [`doxa-auth`](crates/doxa-auth) | OIDC / JWT middleware, generic over your claim struct |
| `policy` | [`doxa-policy`](crates/doxa-policy) | Cedar authorization with pluggable storage |
| `audit` | [`doxa-audit`](crates/doxa-audit) | Non-blocking audit log with auto-capture and trait-based outcomes, optional SeaORM sink |
| `protected` | [`doxa-protected`](crates/doxa-protected) | `ProtectedString` — zeroize-on-drop, redacted everywhere |

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
| Non-blocking audit log | [10](#10-non-blocking-audit-log) |
| Router with audited + unaudited routes | [11](#11-audited-router-with-public-routes) |
| Handler-level audit enrichment | [12](#12-audit-enrichment-in-handlers) |
| Custom audit middleware | [13](#13-custom-middleware-that-emits-audit-events) |
| Custom audit event types | [14](#14-custom-audit-event-types) |

---

## Examples

### 1. A documented endpoint

```rust
use axum::{extract::Path, Json};
use doxa::{get, ApiError, ApiDocBuilder, MountDocsExt, MountOpts, OpenApiRouter, ToSchema};
use serde::Serialize;

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
    let api = OpenApiRouter::new().routes(doxa::routes!(get_widget));
    let (router, openapi) = api.split_for_parts();
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

The spec reflects `text/event-stream` and the three event names.

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

### 6. Auth layer + documented middleware

`AuthLayer` is a tower layer that runs the full auth pipeline (validate → resolve claims → evaluate policy) on every request. Apply it with `layer_documented` and the OpenAPI spec is annotated automatically — Authorization header, 401 response, bearer security scheme — no manual wiring.

```rust
use doxa::auth::{AuthLayer, AuthState, Claims, OidcClaims};
use doxa::OpenApiRouterExt; // provides layer_documented

// Build auth state once at startup
let auth_state = Arc::new(AuthState {
    validator: Arc::new(jwks_validator),
    resolver: Arc::new(claim_resolver),
    policy: Box::new(policy_router),
    audit: Some(audit_logger),
});

// Apply to routes — layer_documented applies the middleware AND
// injects the layer's OpenAPI contribution (headers, security,
// responses) onto every operation it covers.
let api = OpenApiRouter::new()
    .routes(routes!(list_widgets, get_widget))
    .layer_documented(AuthLayer::new(auth_state));
```

`layer_documented` is the key idea: any layer implementing `DocumentedLayer` contributes its OpenAPI metadata alongside its runtime behavior. Routes added *before* the call get the annotation; routes merged *after* don't. This lets you protect `/api/v1/*` behind auth while leaving `/health` unauthenticated — and the spec reflects both.

```rust
// Unauthenticated routes
let public = OpenApiRouter::new()
    .routes(routes!(healthcheck));

// Authenticated routes
let protected = OpenApiRouter::new()
    .routes(routes!(list_widgets, get_widget))
    .layer_documented(AuthLayer::new(auth_state));

// Merge — /health has no auth metadata, /widgets does
let (router, openapi) = public.merge(protected).split_for_parts();
```

### 7. Full app assembly

Putting docs, auth, and the Scalar UI together:

```rust
use std::sync::Arc;
use doxa::{
    get, routes, ApiDocBuilder, MountDocsExt, MountOpts,
    OpenApiRouter, OpenApiRouterExt, ToSchema, ApiError,
};
use doxa::auth::{Auth, AuthContext, AuthLayer, AuthState, OidcClaims};

#[get("/widgets")]
async fn list_widgets(
    Auth(ctx): Auth<MySession, MyClaims>,
) -> Json<Vec<Widget>> {
    let tenant = ctx.claims.scope().unwrap_or("default");
    Json(db::list_widgets(tenant).await)
}

#[tokio::main]
async fn main() {
    let auth_state = build_auth_state().await;

    let public = OpenApiRouter::new()
        .routes(routes!(healthcheck));

    let protected = OpenApiRouter::new()
        .routes(routes!(list_widgets))
        .layer_documented(
            AuthLayer::new(auth_state)
                .with_scheme_name("bearer")
        );

    let (router, openapi) = public.merge(protected).split_for_parts();

    // bearer_security registers the security scheme that with_scheme_name references
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

`/docs` shows Scalar with the auth lock icon on protected operations. The spec has the `Authorization` header, `401` response, and `security` requirement on `/widgets` but not on `/health`.

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
    let resource = build_uid("Document", &doc_id)?;
    let decision = router
        .check(ctx.company_id(), ctx.roles(), "read", resource)
        .await?;
    // decision.allowed is true/false, decision.reason explains why
    // ...
}
```

Implement `PolicyStore` for your backend. `PolicyExtension` plugs in domain-specific post-evaluation (e.g., row-level filters from Cedar residuals). `PolicyRouter` is the centralized slow-path PEP. For the common case of gating a route on a fixed capability, `Require<M>` (example 9) is simpler — it calls the policy check automatically.

### 9. Capabilities → OpenAPI badges

Declare a capability, bind it to a marker, and gate the route. doxa ships the `Require<M>` extractor — it enforces at runtime *and* stamps the OpenAPI security + badge metadata automatically.

```rust
use doxa::auth::Require;
use doxa::policy::{Capable, Capability, CapabilityCheck};

pub const WIDGETS_READ: Capability = Capability {
    name: "widgets.read",
    description: "Read widget definitions",
    checks: &[CapabilityCheck { action: "read", entity_type: "Widget", entity_id: "collection" }],
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

### 10. Non-blocking audit log

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

When used with `AuditLayer` (example 11), most of this is automatic: HTTP metadata is captured from the request/response, and error outcomes propagate through the `#[api(outcome = "...")]` attribute on `ApiError` variants (example 2). Manual builder usage is only needed outside the HTTP request lifecycle.

### 11. Audited router with public routes

`AuditLayer` is a tower middleware that creates an `AuditEventBuilder` per request, injects it into extensions, and **auto-emits with `Outcome::Allowed`** after the response completes. Handlers on the happy path just enrich the builder and return — no terminal call needed.

Stack it **outside** the auth layer so the builder exists before auth runs. Auth failures are recorded automatically. Routes outside both layers are unaudited.

```rust
use std::sync::Arc;
use doxa::{get, routes, ApiDocBuilder, MountDocsExt, MountOpts, OpenApiRouter, OpenApiRouterExt};
use doxa::auth::{AuthLayer, AuthState};
use doxa::audit::{AuditLayer, spawn_audit_writer};

#[tokio::main]
async fn main() {
    let db = connect_to_database().await;
    let audit_logger = spawn_audit_writer(db.clone(), 4096);

    let auth_state = Arc::new(AuthState {
        validator: Arc::new(jwks_validator),
        resolver: Arc::new(claim_resolver),
        policy: Box::new(policy_router),
        audit: None, // ← not needed when AuditLayer is in the stack
    });

    // These routes are audited + authenticated.
    // Layer order matters: AuditLayer wraps AuthLayer.
    let audited = OpenApiRouter::new()
        .routes(routes!(list_documents, get_document, delete_document))
        .layer_documented(AuthLayer::new(auth_state))
        .layer(AuditLayer::new(audit_logger));

    // These routes skip auditing entirely — no layers, no audit events
    let public = OpenApiRouter::new()
        .routes(routes!(healthcheck, readiness, openapi_spec));

    let (router, openapi) = public.merge(audited).split_for_parts();
    let docs = ApiDocBuilder::new()
        .title("My API")
        .version("0.1.0")
        .bearer_security("bearer")
        .merge(openapi)
        .build();

    let app = router.mount_docs(docs, MountOpts::default());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

The split is natural: routes registered *before* the layers get auth + audit; routes merged *after* don't. Health checks, readiness probes, and the OpenAPI spec endpoint stay silent.

### 12. Audit enrichment in handlers

`AuditLayer` injects an `AuditEventBuilder` into request extensions with request metadata (method, path, source IP, user-agent, request ID) already populated. The auth layer stamps actor info (sub, roles, tenant). Handlers enrich the builder with domain context and return — the layer handles everything else.

**Outcome propagation is automatic.** When an `ApiError` is returned, its `outcome` attribute (from example 2) is attached to the response and the layer reads it. Handlers only need `emit_denied`/`emit_error` for non-`ApiError` error paths.

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

### 13. Custom middleware that emits audit events

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

Stack custom middleware between `AuditLayer` (outermost) and the router:

```rust
use axum::middleware;

let audited = OpenApiRouter::new()
    .routes(routes!(list_documents, get_document, delete_document))
    .layer_documented(AuthLayer::new(auth_state))
    .layer(middleware::from_fn(ip_denylist_audit))
    .layer(AuditLayer::new(audit_logger));
```

`AuditLayer` creates the builder first. Auth stamps actor info. Your custom middleware can inspect it, enrich it, or emit early to short-circuit. If the denylist middleware calls `emit_permission_denied`, the auto-emit after the response is a no-op.

### 14. Custom audit event types

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

## Design

- **Framework-neutral cores.** Auth, policy, and audit work without axum. Axum integration is feature-gated.
- **Generic over your domain.** Claim struct, session type, resource taxonomy, audit event variants — all consumer-defined.
- **Typed end to end.** Errors map to OpenAPI responses. SSE events carry their discriminator into the spec. `ProtectedString` carries redaction into its schema.
- **Cheap defaults.** Scalar loads from a CDN (overridable). Audit writes are async. OpenAPI specs are served from a shared `Bytes`.

## Acknowledgements

Huge thanks to the [axum](https://github.com/tokio-rs/axum) and [utoipa](https://github.com/juhaku/utoipa) teams. doxa is built on top of their work — this crate exists because their foundations are solid and we wanted to make it easier to build enterprise applications on them.

## License

Apache 2.0 — see [LICENSE](LICENSE).
