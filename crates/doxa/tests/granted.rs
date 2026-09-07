//! The three forms of `Granted<T>` run one chain: a coarse capability
//! gate, then whatever the subject is about. These exercise it with
//! hand-written `GrantSite` impls, which is what the route macro will
//! generate per call site.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use serde::Serialize;
use serde_json::json;
use tower::ServiceExt;

use doxa::audit::{AuditEvent, AuditEventBuilder, AuditLayer, AuditLogger, Outcome};
use doxa::auth::{Action, Cap, CapabilityContext, GrantSite, Granted, Granting, Many, One};
use doxa::policy::{
    AuthError, Capability, CapabilityCheck, CapabilityChecker, Capable, ResourceEntity,
};
use doxa::{PolicyResource, ToSchema};

// ---- domain -----------------------------------------------------------------

const WIDGETS_READ: Capability = Capability {
    name: "widgets.read",
    description: "Read widgets",
    checks: &[CapabilityCheck {
        action: "read",
        entity_type: "Widget",
        entity_id: "collection",
    }],
};

struct WidgetsRead;
impl Capable for WidgetsRead {
    const CAPABILITY: &'static Capability = &WIDGETS_READ;
}

#[derive(Debug, Clone, Serialize, ToSchema, PolicyResource)]
#[resource(entity_type = "Widget")]
struct Widget {
    #[resource(id)]
    id: u32,
    #[resource(attr)]
    region: String,
}

/// Stands in for a consumer's query filter — what a listing handler
/// narrows its query by.
#[derive(Debug, PartialEq)]
struct Filter(&'static str);

impl Granting for Widget {
    type Key = u32;
    type Ctx = CapabilityContext;
    type State = ();
    type Error = StatusCode;
    type Filter = Filter;

    const ACTIONS: &'static [Action] = &[
        Action::new("read").capability(&WIDGETS_READ),
        // Behind the same coarse capability as `read`, so the only thing
        // separating listing widgets from bulk-purging them is what
        // `scope` makes of the action.
        Action::new("purge").capability(&WIDGETS_READ),
    ];

    async fn load(
        id: u32,
        _state: &(),
        _ctx: &CapabilityContext,
    ) -> Result<Option<Self>, StatusCode> {
        Ok(match id {
            1 => Some(Widget {
                id: 1,
                region: "us".into(),
            }),
            2 => Some(Widget {
                id: 2,
                region: "eu".into(),
            }),
            _ => None,
        })
    }

    /// A real impl reads the session the policy assembled. This one keys
    /// off a role so a test can produce a caller who clears the coarse
    /// gate but has no scope.
    ///
    /// A collection route runs no instance check, so an impl that ignored
    /// the action would hand a purge the same rows it hands a listing.
    fn scope(action: &str, ctx: &CapabilityContext) -> Result<Option<Filter>, AuthError> {
        if !ctx.roles.iter().any(|r| r == "viewer") {
            return Ok(None);
        }
        Ok(match action {
            "purge" => None,
            _ => Some(Filter("tenant = acme")),
        })
    }
}

/// An asset that answers an unauthorized listing with an empty page
/// rather than a refusal — the opt-in side of `empty_scope`.
#[derive(Debug, Clone, Serialize, ToSchema, PolicyResource)]
#[resource(entity_type = "Gadget")]
struct Gadget {
    #[resource(id)]
    id: u32,
}

impl Granting for Gadget {
    type Key = u32;
    type Ctx = CapabilityContext;
    type State = ();
    type Error = StatusCode;
    type Filter = Filter;

    const ACTIONS: &'static [Action] = &[Action::new("read")];

    async fn load(
        _id: u32,
        _state: &(),
        _ctx: &CapabilityContext,
    ) -> Result<Option<Self>, StatusCode> {
        Ok(None)
    }

    fn empty_scope() -> Option<Filter> {
        Some(Filter("matches nothing"))
    }
}

// ---- sites (what the route macro will generate) -----------------------------

struct GetWidget;
impl GrantSite for GetWidget {
    const PARAMS: &'static [&'static str] = &["id"];
    const ACTION: &'static str = "read";
}

struct Listing;
impl GrantSite for Listing {
    const PARAMS: &'static [&'static str] = &[];
    const ACTION: &'static str = "read";
}

/// The same collection asked about under a different action, which is the
/// only difference between these two routes.
struct Purging;
impl GrantSite for Purging {
    const PARAMS: &'static [&'static str] = &[];
    const ACTION: &'static str = "purge";
}

// ---- policy stub ------------------------------------------------------------

/// Grants the capability to `viewer` and `lister`, and `read` only on
/// widgets in region `us` — so a wrong instance decision means the
/// object's attributes never reached the policy.
struct RegionChecker;

#[async_trait]
impl CapabilityChecker for RegionChecker {
    async fn check(&self, _: &str, roles: &[String], cap: &Capability) -> Result<bool, AuthError> {
        assert_eq!(cap.name, "widgets.read");
        Ok(roles.iter().any(|r| r == "viewer" || r == "lister"))
    }

    async fn check_instance(
        &self,
        _: &str,
        _: &[String],
        action: &str,
        resource: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        assert_eq!(action, "read", "the action comes from the site");
        assert_eq!(resource.entity_type, "Widget");
        Ok(resource.attrs.get("region") == Some(&json!("us")))
    }
}

// ---- harness ----------------------------------------------------------------

fn caller(request: &mut Request<Body>, roles: &[&str]) {
    request.extensions_mut().insert(CapabilityContext {
        tenant_id: Some("acme".into()),
        roles: roles.iter().map(|r| r.to_string()).collect(),
    });
    let checker: Arc<dyn CapabilityChecker> = Arc::new(RegionChecker);
    request.extensions_mut().insert(checker);
}

/// Request parts as `AuthLayer` would leave them. Enough for the forms
/// that take no key.
fn parts(
    roles: &[&str],
) -> (
    axum::http::request::Parts,
    tokio::sync::mpsc::Receiver<AuditEvent>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
    caller(&mut request, roles);
    request
        .extensions_mut()
        .insert(AuditEventBuilder::new(AuditLogger::from_sender(tx)));
    let (parts, _) = request.into_parts();
    (parts, rx)
}

// ---- collections ------------------------------------------------------------

/// The collection form yields the caller's authorized scope, and reaches
/// no instance check to do it.
#[tokio::test]
async fn a_collection_yields_the_authorized_scope() {
    let (mut parts, _rx) = parts(&["viewer"]);
    let Granted(caller, scope) =
        Granted::<Many<Widget, Listing>>::from_request_parts(&mut parts, &())
            .await
            .expect("viewer may list");

    assert_eq!(scope, Filter("tenant = acme"));
    assert_eq!(
        caller.tenant_id.as_deref(),
        Some("acme"),
        "the caller comes back with the value it was authorized against",
    );
}

/// Two collection routes over one asset, differing only in the action.
///
/// The coarse capability is the same for both, and a collection form runs
/// no instance check, so if the action did not reach
/// [`Granting::scope`](doxa::auth::Granting::scope) a caller cleared to
/// list widgets would be cleared to purge them.
#[tokio::test]
async fn the_scope_is_per_action_not_per_asset() {
    let (mut listing, _rx) = parts(&["viewer"]);
    Granted::<Many<Widget, Listing>>::from_request_parts(&mut listing, &())
        .await
        .expect("a viewer may list");

    let (mut purging, mut rx) = parts(&["viewer"]);
    let rejection = Granted::<Many<Widget, Purging>>::from_request_parts(&mut purging, &())
        .await
        .err()
        .expect("the same viewer may not purge");

    assert_eq!(rejection.into_response().status(), StatusCode::FORBIDDEN);
    let event = rx.try_recv().expect("recorded");
    assert_eq!(event.action, "purge");
    assert_eq!(event.error_message.as_deref(), Some("no authorized scope"));
}

/// An action the asset never declared is refused before anything is
/// loaded and before `scope` is consulted.
///
/// A route cannot reach this — `Subject::SITE_DECLARED` fails the build
/// first — but a handler authorizing an action it assembled at runtime
/// can, and that is the path where a collection would otherwise be
/// answered with a filter no policy ever approved.
#[tokio::test]
async fn an_undeclared_action_is_refused_rather_than_scoped() {
    let (parts, mut rx) = parts(&["viewer"]);

    let refused = doxa::auth::authorize::<Many<Widget>>((), "raed", &(), &parts.extensions)
        .await
        .err()
        .expect("Widget declares no `raed`");

    assert_eq!(refused.into_response().status(), StatusCode::FORBIDDEN);
    let event = rx.try_recv().expect("recorded");
    assert_eq!(event.outcome, Outcome::Denied);
    assert_eq!(event.action, "raed");
    assert_eq!(event.resource_type.as_deref(), Some("Widget"));
    assert_eq!(event.error_message.as_deref(), Some("action not declared"));
}

/// The coarse gate runs first, so a caller without the capability never
/// reaches the scope lookup.
#[tokio::test]
async fn the_coarse_gate_refuses_before_the_scope_lookup() {
    let (mut parts, mut rx) = parts(&["stranger"]);
    let rejection = Granted::<Many<Widget, Listing>>::from_request_parts(&mut parts, &())
        .await
        .err()
        .expect("no capability");

    assert_eq!(rejection.into_response().status(), StatusCode::FORBIDDEN);
    let event = rx.try_recv().expect("the refusal is recorded");
    assert_eq!(event.outcome, Outcome::Denied);
    assert_eq!(event.action, "widgets.read");
    assert_eq!(event.error_message.as_deref(), Some("capability denied"));
}

/// Clearing the coarse gate is not the same as having a scope: an asset
/// the policy granted nothing on refuses by default, so a misconfigured
/// policy cannot pass for an empty table.
#[tokio::test]
async fn a_caller_with_no_scope_is_refused_by_default() {
    // `lister` satisfies the capability but `Widget::scope` returns None.
    let (mut parts, mut rx) = parts(&["lister"]);
    let rejection = Granted::<Many<Widget, Listing>>::from_request_parts(&mut parts, &())
        .await
        .err()
        .expect("no scope");

    assert_eq!(rejection.into_response().status(), StatusCode::FORBIDDEN);
    let event = rx.try_recv().expect("recorded");
    assert_eq!(event.error_message.as_deref(), Some("no authorized scope"));
    assert_eq!(event.resource_id.as_deref(), Some("collection"));
}

/// The opt-in: an asset may answer with a filter that matches nothing
/// instead of a 403.
#[tokio::test]
async fn empty_scope_can_be_an_empty_page_instead_of_a_refusal() {
    let (mut parts, _rx) = parts(&["stranger"]);
    let granted = Granted::<Many<Gadget, Listing>>::from_request_parts(&mut parts, &())
        .await
        .expect("Gadget opts into an empty page");

    assert_eq!(granted.1, Filter("matches nothing"));
}

// ---- bare capability --------------------------------------------------------

#[tokio::test]
async fn a_bare_capability_gate_records_its_refusal() {
    let (mut parts, mut rx) = parts(&["stranger"]);
    let rejection = Granted::<Cap<WidgetsRead, Listing>>::from_request_parts(&mut parts, &())
        .await
        .err()
        .expect("no capability");

    assert_eq!(rejection.into_response().status(), StatusCode::FORBIDDEN);
    let event = rx.try_recv().expect("recorded");
    assert_eq!(
        (event.resource_type.as_deref(), event.resource_id.as_deref()),
        (Some("Widget"), Some("collection")),
        "the capability's first check is what short-circuits",
    );
}

// ---- instances --------------------------------------------------------------

/// The instance form needs real path parameters, so it runs through a
/// router.
async fn get_widget(roles: &'static [&'static str], path: &str) -> (StatusCode, AuditEvent) {
    async fn handler(guard: Granted<One<Widget, GetWidget>>) -> String {
        guard.into_inner().region
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    let app = axum::Router::new()
        .route("/widgets/{id}", axum::routing::get(handler))
        .layer(axum::middleware::from_fn(
            move |mut request: Request<Body>, next: axum::middleware::Next| async move {
                caller(&mut request, roles);
                next.run(request).await
            },
        ))
        .layer(AuditLayer::new(AuditLogger::from_sender(tx)));

    let response = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .expect("request");
    let status = response.status();
    let event = rx.recv().await.expect("an event per request");
    (status, event)
}

/// The object's own attributes reach the policy — `us` is granted.
#[tokio::test]
async fn an_allowed_instance_reaches_the_handler() {
    let (status, event) = get_widget(&["viewer"], "/widgets/1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(event.outcome, Outcome::Allowed);
}

/// `eu` is refused, and the refusal names the object rather than the
/// capability's static sentinel.
#[tokio::test]
async fn a_denied_instance_names_the_object() {
    let (status, event) = get_widget(&["viewer"], "/widgets/2").await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(event.outcome, Outcome::Denied);
    assert_eq!(event.action, "read");
    assert_eq!(event.resource_id.as_deref(), Some("2"));
    assert_eq!(event.error_message.as_deref(), Some("instance denied"));
}

/// The coarse gate runs before the load, so a caller who may not touch
/// widgets at all cannot tell a missing object from a forbidden one.
#[tokio::test]
async fn the_coarse_gate_runs_before_the_load() {
    let (status, _) = get_widget(&["stranger"], "/widgets/999").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a 404 here would confirm which ids exist",
    );
}

/// A key that does not parse is a 400 before any policy call.
#[tokio::test]
async fn an_unparseable_key_is_rejected_early() {
    let (status, _) = get_widget(&["viewer"], "/widgets/not-a-number").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ---- authorizing what the extractor cannot reach -----------------------------

/// A guard runs in `FromRequestParts`, which sees no request body, so an
/// id named in a payload can only be authorized from inside the handler
/// that parsed it. `authorize` is the extractor's own body, callable.
#[tokio::test]
async fn a_handler_can_authorize_an_id_from_its_body() {
    let (parts, _rx) = parts(&["viewer"]);

    let widget = doxa::auth::authorize::<One<Widget>>(1, "read", &(), &parts.extensions)
        .await
        .expect("region us is granted");

    assert_eq!(widget.region, "us");
}

/// `authorize` is the only door onto a policy decision — the chain
/// itself is sealed — so the manual path and the guard path cannot
/// disagree about whether a denial is auditable. There is no third path
/// that reaches a verdict and records nothing.
#[tokio::test]
async fn a_manual_refusal_is_recorded_like_the_extractors() {
    let (parts, mut rx) = parts(&["viewer"]);

    let refused = doxa::auth::authorize::<One<Widget>>(2, "read", &(), &parts.extensions)
        .await
        .expect_err("region eu is denied");

    assert_eq!(refused.into_response().status(), StatusCode::FORBIDDEN);

    let event = rx.try_recv().expect("the refusal is recorded");
    assert_eq!(event.outcome, Outcome::Denied);
    assert_eq!(event.action, "read");
    assert_eq!(event.resource_id.as_deref(), Some("2"));
    assert_eq!(event.error_message.as_deref(), Some("instance denied"));
}

/// A grant is recorded through the same door, so a handler authorizing
/// an id no extractor could see owes the audit trail nothing either.
#[tokio::test]
async fn a_manual_grant_is_recorded_like_the_extractors() {
    let (parts, mut rx) = parts(&["viewer"]);

    doxa::auth::authorize::<One<Widget>>(1, "read", &(), &parts.extensions)
        .await
        .expect("region us is granted");

    // Nothing else touched the event, so the deposit is all of it. The
    // layer would do this after the response.
    parts
        .extensions
        .get::<AuditEventBuilder>()
        .expect("the harness installed one")
        .auto_emit();

    let event = rx.try_recv().expect("the grant is recorded");
    assert_eq!(event.outcome, Outcome::Allowed);
    assert_eq!(event.action, "read");
    assert_eq!(event.resource_type.as_deref(), Some("Widget"));
    assert_eq!(event.resource_id.as_deref(), Some("1"));
}
