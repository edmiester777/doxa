//! A complete doxa example covering every feature: OpenAPI docs, typed errors,
//! SSE, auth, Cedar capabilities, audit trail, and protected secrets.
//!
//! Build: `cargo build --example full_test -p doxa --features full`
//! Run:   `cargo run --example full_test -p doxa --features full`
//!
//! Once running:
//!   - Scalar docs at http://localhost:3000/docs
//!   - OpenAPI spec at http://localhost:3000/openapi.json
//!   - Health check at http://localhost:3000/health
//!   - Protected routes require `Authorization: Bearer good-token`

use std::convert::Infallible;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::Extension;
use axum::Json;
use serde::{Deserialize, Serialize};

use doxa::audit::{AuditEventBuilder, AuditLayer, EventType};
use doxa::auth::{Auth, AuthLayer, AuthState, Claims, Require};
use doxa::policy::{Capability, CapabilityCheck, CapabilityChecker, Capable};
use doxa::protected::ProtectedString;
use doxa::{
    get, post, routes, ApiDocBuilder, ApiError, MountDocsExt, MountOpts, OpenApiRouter,
    OpenApiRouterExt, SseEvent, SseStream, ToSchema,
};

// ═══════════════════════════════════════════════════════════════════════
// Domain types
// ═══════════════════════════════════════════════════════════════════════

/// A widget in the system.
#[derive(Debug, Serialize, ToSchema)]
struct Widget {
    /// Unique widget identifier.
    id: u32,
    /// Human-readable display name.
    name: String,
    /// Owner tenant.
    tenant: String,
}

/// Request payload for creating a widget.
#[derive(Debug, Deserialize, ToSchema)]
struct CreateWidget {
    name: String,
}

/// Application configuration loaded at startup.
#[derive(Deserialize)]
struct AppConfig {
    /// Secret API key — never logged, redacted everywhere.
    api_key: ProtectedString,
}

// ═══════════════════════════════════════════════════════════════════════
// Typed errors → OpenAPI responses
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error, Serialize, ToSchema, ApiError)]
enum WidgetError {
    #[error("widget not found")]
    #[api(status = 404, code = "not_found", outcome = "allowed")]
    NotFound, // legitimate miss — not a security event

    #[error("validation failed: {0}")]
    #[api(status = 400, code = "validation_error", outcome = "error")]
    Validation(String),

    #[error("duplicate widget: {0}")]
    #[api(status = 400, code = "duplicate", outcome = "error")]
    #[allow(dead_code)]
    Duplicate(String),

    #[error("internal error")]
    #[api(status = 500, code = "internal")] // outcome defaults to "error"
    #[allow(dead_code)]
    Internal,
}

// ═══════════════════════════════════════════════════════════════════════
// Server-Sent Events
// ═══════════════════════════════════════════════════════════════════════

#[allow(dead_code)]
#[derive(Serialize, ToSchema, SseEvent)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
enum WidgetProgress {
    Started { widget_id: u32 },
    Processing { percent: u8 },
    Completed { widget_id: u32 },
}

// ═══════════════════════════════════════════════════════════════════════
// Claims + Auth
// ═══════════════════════════════════════════════════════════════════════

/// Consumer-defined claim type parsed from the JWT.
#[derive(Debug, Clone, Deserialize)]
struct MyClaims {
    sub: String,
    tenant_id: String,
    roles: Vec<String>,
}

impl Claims for MyClaims {
    fn sub(&self) -> &str {
        &self.sub
    }
    fn roles(&self) -> &[String] {
        &self.roles
    }
    fn scope(&self) -> Option<&str> {
        Some(&self.tenant_id)
    }
    fn audit_attrs(&self) -> serde_json::Value {
        serde_json::json!({ "tenant_id": &self.tenant_id })
    }
}

/// Stub validator — accepts "good-token", rejects everything else.
struct StubValidator;

#[async_trait]
impl doxa::auth::TokenValidator for StubValidator {
    async fn validate(
        &self,
        token: &str,
    ) -> Result<doxa::auth::MinimalClaims, doxa::policy::AuthError> {
        if token == "good-token" {
            Ok(doxa::auth::MinimalClaims {
                sub: Some("user-1".into()),
                exp: None,
                extra: Default::default(),
            })
        } else {
            Err(doxa::policy::AuthError::InvalidToken("bad token".into()))
        }
    }
}

/// Stub resolver — returns fixed claims for any valid token.
struct StubResolver;

#[async_trait]
impl doxa::auth::ClaimResolver<MyClaims> for StubResolver {
    async fn resolve(
        &self,
        _token: &str,
        _minimal: &doxa::auth::MinimalClaims,
    ) -> Result<MyClaims, doxa::policy::AuthError> {
        Ok(MyClaims {
            sub: "user-1".into(),
            tenant_id: "acme".into(),
            roles: vec!["reader".into(), "writer".into()],
        })
    }
}

/// Stub policy — returns unit session output for any tenant/roles.
struct StubPolicy;

#[async_trait]
impl doxa::policy::Policy<()> for StubPolicy {
    async fn resolve(
        &self,
        _scope: Option<&str>,
        _roles: &[String],
    ) -> Result<(), doxa::policy::AuthError> {
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Capabilities (Cedar-style permissions)
// ═══════════════════════════════════════════════════════════════════════

pub const WIDGETS_READ: Capability = Capability {
    name: "widgets.read",
    description: "Read widget data",
    checks: &[CapabilityCheck {
        action: "read",
        entity_type: "Widget",
        entity_id: "collection",
    }],
};

pub const WIDGETS_WRITE: Capability = Capability {
    name: "widgets.write",
    description: "Create and modify widgets",
    checks: &[CapabilityCheck {
        action: "write",
        entity_type: "Widget",
        entity_id: "collection",
    }],
};

struct WidgetsRead;
impl Capable for WidgetsRead {
    const CAPABILITY: &'static Capability = &WIDGETS_READ;
}

struct WidgetsWrite;
impl Capable for WidgetsWrite {
    const CAPABILITY: &'static Capability = &WIDGETS_WRITE;
}

/// Stub capability checker — allows everything.
struct AllowAll;

#[async_trait]
impl CapabilityChecker for AllowAll {
    async fn check(
        &self,
        _tenant_id: &str,
        _roles: &[String],
        _cap: &Capability,
    ) -> Result<bool, doxa::policy::AuthError> {
        Ok(true)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Custom audit event type
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy)]
enum BillingEvent {
    WidgetProvisioned,
}

impl doxa::audit::AuditEventType for BillingEvent {
    fn as_str(&self) -> &str {
        match self {
            Self::WidgetProvisioned => "billing.widget_provisioned",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Handlers
// ═══════════════════════════════════════════════════════════════════════

/// Public health check — no auth, no audit.
#[get("/health", tag = "Ops")]
async fn healthcheck() -> &'static str {
    "ok"
}

/// List all widgets for the authenticated tenant.
/// `Require<WidgetsRead>` enforces the capability at runtime and
/// documents it in the OpenAPI spec.
#[get("/widgets", tag = "Widgets")]
async fn list_widgets(
    _: Require<WidgetsRead>,
    Auth(ctx): Auth<(), MyClaims>,
    Extension(audit): Extension<AuditEventBuilder>,
) -> Json<Vec<Widget>> {
    let tenant = ctx.company_id();
    audit.set_event(EventType::DataAccess, "list");
    audit.set_resource("widget", "collection");
    // AuditLayer auto-emits with Outcome::Allowed after the response
    Json(vec![Widget {
        id: 1,
        name: "sprocket".into(),
        tenant: tenant.into(),
    }])
}

/// Fetch a single widget by ID.
#[get("/widgets/{id}", tag = "Widgets")]
async fn get_widget(
    _: Require<WidgetsRead>,
    Auth(ctx): Auth<(), MyClaims>,
    Path(id): Path<u32>,
    Extension(audit): Extension<AuditEventBuilder>,
) -> Result<Json<Widget>, WidgetError> {
    audit.set_event(EventType::DataAccess, "read");
    audit.set_resource("widget", &id.to_string());

    if id == 0 {
        // Error path — emit explicitly so the outcome is Denied
        audit.emit_denied("widget not found");
        return Err(WidgetError::NotFound);
    }

    audit.set_response_summary(serde_json::json!({ "widget_id": id }));
    // Happy path — AuditLayer auto-emits Allowed
    Ok(Json(Widget {
        id,
        name: "gadget".into(),
        tenant: ctx.company_id().into(),
    }))
}

/// Create a new widget.
#[post("/widgets", tag = "Widgets")]
async fn create_widget(
    _: Require<WidgetsWrite>,
    Extension(audit): Extension<AuditEventBuilder>,
    Json(body): Json<CreateWidget>,
) -> Result<(StatusCode, Json<Widget>), WidgetError> {
    if body.name.is_empty() {
        audit.emit_error("empty widget name");
        return Err(WidgetError::Validation("name must not be empty".into()));
    }

    // Use a custom audit event type for billing
    audit.set_event(BillingEvent::WidgetProvisioned, "create");
    audit.set_resource("widget", "new");
    audit.set_request_body(serde_json::json!({ "name": &body.name }));

    let widget = Widget {
        id: 42,
        name: body.name,
        tenant: "acme".into(),
    };
    Ok((StatusCode::CREATED, Json(widget)))
}

/// Stream progress updates for a widget operation.
/// (Not mounted on the router — demonstrates the SseStream type.)
#[allow(dead_code)]
#[get("/widgets/{id}/progress", tag = "Widgets")]
async fn widget_progress(
    Path(id): Path<u32>,
) -> SseStream<WidgetProgress, impl futures_core::Stream<Item = Result<WidgetProgress, Infallible>>>
{
    SseStream::new(async_stream::stream! {
        yield Ok(WidgetProgress::Started { widget_id: id });
        yield Ok(WidgetProgress::Processing { percent: 50 });
        yield Ok(WidgetProgress::Completed { widget_id: id });
    })
}

// ═══════════════════════════════════════════════════════════════════════
// Custom audit middleware
// ═══════════════════════════════════════════════════════════════════════

/// Middleware that tags mutation requests in the audit trail.
async fn tag_mutations(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(audit) = request.extensions().get::<AuditEventBuilder>() {
        if matches!(
            *request.method(),
            axum::http::Method::POST
                | axum::http::Method::PUT
                | axum::http::Method::PATCH
                | axum::http::Method::DELETE
        ) {
            audit.set_event(EventType::AdminUpdate, request.method().as_str());
        }
    }
    next.run(request).await
}

// ═══════════════════════════════════════════════════════════════════════
// App assembly
// ═══════════════════════════════════════════════════════════════════════

#[tokio::main]
async fn main() {
    // ── Secrets ────────────────────────────────────────────────
    // ProtectedString redacts in Debug/Display/Serialize
    let cfg: AppConfig = serde_json::from_str(r#"{"api_key": "sk-live-abc123"}"#).unwrap();
    println!("Loaded config: api_key={:?}", cfg.api_key); // prints [REDACTED]
    let _secret: &str = cfg.api_key.expose(); // explicit access

    // ── Audit logger ──────────────────────────────────────────
    // In production: spawn_audit_writer(db, 4096)
    // For this example we create a channel manually.
    let (tx, mut rx) = tokio::sync::mpsc::channel(256);
    let audit_logger = doxa::audit::AuditLogger::from_sender(tx);

    // Drain audit events in the background (stand-in for SeaORM writer)
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            println!(
                "[audit] {} / {} → {}",
                event.event_type, event.action, event.outcome
            );
        }
    });

    // ── Auth ──────────────────────────────────────────────────
    let auth_state: Arc<AuthState<(), MyClaims>> = Arc::new(AuthState {
        validator: Arc::new(StubValidator),
        resolver: Arc::new(StubResolver),
        policy: Box::new(StubPolicy),
        audit: None, // AuditLayer handles it
    });

    // ── Routes ────────────────────────────────────────────────
    // Public routes — no auth, no audit
    let public = OpenApiRouter::new().routes(routes!(healthcheck)).route(
        "/favicon.ico",
        axum::routing::get(|| async { StatusCode::NO_CONTENT }),
    );

    // Protected routes — auth + audit + capability enforcement
    let protected = OpenApiRouter::new()
        .routes(routes!(list_widgets, create_widget))
        .routes(routes!(get_widget))
        .layer(axum::middleware::from_fn(tag_mutations))
        .layer_documented(
            AuthLayer::new(auth_state)
                .with_scheme_name("bearer")
                .with_capability_checker(Arc::new(AllowAll)),
        )
        .layer(AuditLayer::new(audit_logger));

    // ── Docs ──────────────────────────────────────────────────
    let (router, openapi) = public.merge(protected).split_for_parts();

    let api_doc = ApiDocBuilder::new()
        .title("doxa Full Example")
        .version("0.1.0")
        .server("http://localhost:3000", "Local dev server")
        .bearer_security("bearer")
        .merge(openapi)
        .build();

    let app = router.mount_docs(api_doc, MountOpts::default());

    // ── Serve ─────────────────────────────────────────────────
    println!("Listening on http://localhost:3000");
    println!("Scalar docs at http://localhost:3000/docs");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
