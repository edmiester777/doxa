//! `Granted<T>` at a route: the macro generates the site, and the guard
//! documents itself.
//!
//! The unit tests in `doxa-macros` cover the rewrite in isolation. These
//! run it through the real `#[get]` / `routes!` path and assert on the
//! OpenAPI document that comes out, which is the thing a consumer
//! actually ships.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;

use async_trait::async_trait;
use tower::ServiceExt;

use doxa::auth::{Cap, CapabilityContext, Granted, Granting, Many};
use doxa::policy::{
    AuthError, Capability, CapabilityCheck, CapabilityChecker, Capable, ResourceEntity,
};
use doxa::{delete, get, routes, OpenApiRouter, PolicyResource, ToSchema};

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

impl Granting for Widget {
    type Key = u32;
    type Ctx = CapabilityContext;
    type State = ();
    type Error = StatusCode;
    type Filter = ();

    fn capability(_action: &str) -> Option<&'static Capability> {
        Some(&WIDGETS_READ)
    }

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
            _ => None,
        })
    }

    fn scope(_ctx: &CapabilityContext) -> Result<Option<()>, AuthError> {
        Ok(Some(()))
    }
}

// ---- routes, written the way a consumer writes them -------------------------

/// The whole point: no annotation, no marker type, no mode wrapper. One
/// path parameter means there is nothing to choose between.
#[get("/widgets/{id}", tag = "Widgets")]
async fn get_widget(widget: Granted<Widget>) -> String {
    widget.into_inner().region
}

/// Two path parameters, so the key segment has to be named.
#[delete("/folders/{fid}/widgets/{id}", tag = "Widgets")]
async fn drop_widget(#[key("id")] widget: Granted<Widget>) -> StatusCode {
    let _ = widget.into_inner();
    StatusCode::NO_CONTENT
}

#[get("/widgets", tag = "Widgets")]
async fn list_widgets(scope: Granted<Many<Widget>>) -> &'static str {
    scope.into_inner();
    "ok"
}

#[get("/flush", tag = "Widgets")]
async fn flush(gate: Granted<Cap<WidgetsRead>>) -> &'static str {
    gate.into_inner();
    "ok"
}

// ---- policy stub ------------------------------------------------------------

/// Grants the capability to `viewer`, and `read` only on widgets in
/// region `us`.
struct RegionChecker;

#[async_trait]
impl CapabilityChecker for RegionChecker {
    async fn check(&self, _: &str, roles: &[String], _: &Capability) -> Result<bool, AuthError> {
        Ok(roles.iter().any(|r| r == "viewer"))
    }

    async fn check_instance(
        &self,
        _: &str,
        _: &[String],
        _: &str,
        resource: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        Ok(resource.attrs.get("region") == Some(&json!("us")))
    }
}

fn api() -> utoipa::openapi::OpenApi {
    let (_router, api) = OpenApiRouter::<()>::new()
        .routes(routes!(get_widget))
        .routes(routes!(drop_widget))
        .routes(routes!(list_widgets))
        .routes(routes!(flush))
        .split_for_parts();
    api
}

fn operation(
    api: &utoipa::openapi::OpenApi,
    path: &str,
    method: utoipa::openapi::path::HttpMethod,
) -> utoipa::openapi::path::Operation {
    use utoipa::openapi::path::HttpMethod;

    let item = api
        .paths
        .paths
        .get(path)
        .unwrap_or_else(|| panic!("{path} is routed"));

    match method {
        HttpMethod::Get => item.get.clone(),
        HttpMethod::Delete => item.delete.clone(),
        _ => panic!("only GET and DELETE are exercised here"),
    }
    .unwrap_or_else(|| panic!("{path} has the operation"))
}

// ---- the route macro generates the site -------------------------------------

/// `Granted<Widget>` with one path parameter needs no annotation at all
/// — the same call-site shape the guard it replaced had.
#[tokio::test]
async fn the_bare_form_authorizes_through_the_route_macro() {
    let app = OpenApiRouter::<()>::new()
        .routes(routes!(get_widget))
        .split_for_parts()
        .0
        .layer(axum::middleware::from_fn(
            |mut request: Request<Body>, next: axum::middleware::Next| async move {
                request.extensions_mut().insert(CapabilityContext {
                    tenant_id: Some("acme".into()),
                    roles: vec!["viewer".into()],
                });
                let checker: Arc<dyn CapabilityChecker> = Arc::new(RegionChecker);
                request.extensions_mut().insert(checker);
                next.run(request).await
            },
        ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/widgets/1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("request");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the generated site bound `{{id}}` to the key",
    );
}

// ---- and the guard documents itself -----------------------------------------

/// The instance form declares the path parameter with the schema its
/// `ID_TYPE` implies — the site is authoritative, not the template's
/// positional list.
#[test]
fn the_instance_form_documents_its_key() {
    let api = api();
    let op = operation(
        &api,
        "/widgets/{id}",
        utoipa::openapi::path::HttpMethod::Get,
    );

    let params = op.parameters.expect("the key is declared");
    assert_eq!(params.len(), 1);
    assert_eq!(params[0].name, "id");
    assert_eq!(
        params[0].description.as_deref(),
        Some("Identifier of the Widget"),
    );
}

/// A named segment on a multi-parameter route documents that segment,
/// not the first one in the template.
#[test]
fn a_named_segment_documents_the_segment_it_names() {
    let api = api();
    let op = operation(
        &api,
        "/folders/{fid}/widgets/{id}",
        utoipa::openapi::path::HttpMethod::Delete,
    );

    let params = op.parameters.expect("the key is declared");
    assert_eq!(params.len(), 1, "only the key segment, not every parameter");
    assert_eq!(params[0].name, "id");
}

/// Guards reject before the handler runs, so response inference cannot
/// see these statuses — the contribution is what puts them in the spec.
#[test]
fn the_instance_form_documents_what_it_can_refuse_with() {
    let api = api();
    let op = operation(
        &api,
        "/widgets/{id}",
        utoipa::openapi::path::HttpMethod::Get,
    );

    let statuses: Vec<_> = op.responses.responses.keys().cloned().collect();
    for expected in ["400", "401", "403", "404"] {
        assert!(
            statuses.contains(&expected.to_string()),
            "{expected} missing from {statuses:?}",
        );
    }
}

/// The collection and capability forms load nothing and read no key, so
/// a 400 or 404 from them would be a lie.
#[test]
fn the_keyless_forms_document_no_key_and_no_404() {
    let api = api();

    for (path, method) in [
        ("/widgets", utoipa::openapi::path::HttpMethod::Get),
        ("/flush", utoipa::openapi::path::HttpMethod::Get),
    ] {
        let op = operation(&api, path, method);
        assert!(
            op.parameters.is_none_or(|p| p.is_empty()),
            "{path} declares no path parameter",
        );

        let statuses: Vec<_> = op.responses.responses.keys().cloned().collect();
        assert!(
            statuses.contains(&"403".to_string()),
            "{path}: {statuses:?}"
        );
        assert!(
            !statuses.contains(&"404".to_string()),
            "{path} cannot 404: {statuses:?}",
        );
    }
}

/// The security requirement carries the consumer's own capability name,
/// which is a `const` they already declare — so the scope resolves.
#[test]
fn the_permission_badge_names_the_declared_capability() {
    let api = api();
    let op = operation(
        &api,
        "/widgets/{id}",
        utoipa::openapi::path::HttpMethod::Get,
    );

    // Read it back off the serialized document — that is the artifact a
    // validator or SDK generator actually consumes.
    let security = serde_json::to_value(op.security.expect("a requirement is stamped")).unwrap();
    assert_eq!(
        security,
        json!([{ "bearer": ["widgets.read"] }]),
        "the asset's declared capability is the scope, not a composed string",
    );

    let badge = op
        .extensions
        .as_ref()
        .and_then(|e| e.get("x-required-permissions"))
        .expect("badge extension");
    assert_eq!(badge, &json!(["read on Widget (instance)"]));
}

/// The three forms word themselves differently, so a reader can tell an
/// instance route from a listing at a glance.
#[test]
fn each_form_words_its_own_badge() {
    let api = api();

    let badge = |path: &str| {
        operation(&api, path, utoipa::openapi::path::HttpMethod::Get)
            .extensions
            .as_ref()
            .and_then(|e| e.get("x-required-permissions"))
            .cloned()
            .expect("badge")
    };

    assert_eq!(badge("/widgets/{id}"), json!(["read on Widget (instance)"]));
    assert_eq!(badge("/widgets"), json!(["read on Widget (collection)"]));
    assert_eq!(badge("/flush"), json!(["`widgets.read` capability"]));
}

// ---- the scheme declares what the guards stamped -----------------------------

/// A guard composes its scope string per call site, so the security
/// scheme — declared separately by the consumer — has no way to know
/// about it. Left alone the document references scopes it never defines,
/// which strict validators reject and SDK generators cannot resolve.
#[test]
fn stamped_scopes_are_declared_on_the_scheme() {
    use utoipa::openapi::security::{AuthorizationCode, Flow, Scopes};

    let (_router, api) = OpenApiRouter::<()>::new()
        .routes(routes!(get_widget))
        .split_for_parts();

    // An OAuth2 scheme that declares no vocabulary of its own — the
    // worst case, and the one a consumer reaches for first.
    let doc = doxa::ApiDocBuilder::new()
        .title("test")
        .version("0.1")
        .oauth2_security(
            "bearer",
            [Flow::AuthorizationCode(AuthorizationCode::new(
                "https://idp.example/authorize",
                "https://idp.example/token",
                Scopes::new(),
            ))],
        )
        .merge(api)
        .build();

    let spec: serde_json::Value = serde_json::from_slice(&doc.spec_json).unwrap();
    let declared =
        &spec["components"]["securitySchemes"]["bearer"]["flows"]["authorizationCode"]["scopes"];

    assert_eq!(
        declared["widgets.read"],
        json!("read on Widget (instance)"),
        "the scope the guards stamped is declared, described by the operation's own badge",
    );
}

/// A description the consumer wrote is theirs — doxa fills gaps, it does
/// not overwrite.
#[test]
fn a_consumer_declaration_is_not_overwritten() {
    use utoipa::openapi::security::{AuthorizationCode, Flow, Scopes};

    let (_router, api) = OpenApiRouter::<()>::new()
        .routes(routes!(get_widget))
        .split_for_parts();

    let doc = doxa::ApiDocBuilder::new()
        .title("test")
        .version("0.1")
        .oauth2_security(
            "bearer",
            [Flow::AuthorizationCode(AuthorizationCode::new(
                "https://idp.example/authorize",
                "https://idp.example/token",
                Scopes::one("widgets.read", "Read widget definitions"),
            ))],
        )
        .merge(api)
        .build();

    let spec: serde_json::Value = serde_json::from_slice(&doc.spec_json).unwrap();
    let declared =
        &spec["components"]["securitySchemes"]["bearer"]["flows"]["authorizationCode"]["scopes"];

    assert_eq!(declared["widgets.read"], json!("Read widget definitions"));
}

/// `Granted<Widget>` and `Granted<Many<Widget>>` share a capability, so
/// both stamp `widgets.read` — with different labels. Neither label is
/// the scope's description, and path order deciding it would be a coin
/// flip that reads like a fact, so the scope names itself.
#[test]
fn a_scope_described_two_ways_falls_back_to_its_own_name() {
    use utoipa::openapi::security::{AuthorizationCode, Flow, Scopes};

    let (_router, api) = OpenApiRouter::<()>::new()
        .routes(routes!(get_widget))
        .routes(routes!(list_widgets))
        .split_for_parts();

    let doc = doxa::ApiDocBuilder::new()
        .title("test")
        .version("0.1")
        .oauth2_security(
            "bearer",
            [Flow::AuthorizationCode(AuthorizationCode::new(
                "https://idp.example/authorize",
                "https://idp.example/token",
                Scopes::new(),
            ))],
        )
        .merge(api)
        .build();

    let spec: serde_json::Value = serde_json::from_slice(&doc.spec_json).unwrap();
    let declared =
        &spec["components"]["securitySchemes"]["bearer"]["flows"]["authorizationCode"]["scopes"];

    assert_eq!(declared["widgets.read"], json!("widgets.read"));
}

// ---- composite keys ----------------------------------------------------------

/// A folder-scoped widget: the key is both segments, so authorizing it
/// means both reach the loader.
#[derive(Debug, Clone, Serialize, ToSchema, PolicyResource)]
#[resource(entity_type = "Filed")]
struct Filed {
    #[resource(id)]
    id: String,
}

impl Granting for Filed {
    type Key = (String, u32);
    type Ctx = CapabilityContext;
    type State = ();
    type Error = StatusCode;
    type Filter = ();

    async fn load(
        (folder, id): (String, u32),
        _state: &(),
        _ctx: &CapabilityContext,
    ) -> Result<Option<Self>, StatusCode> {
        // The id alone is not the identity — the folder is half of it.
        Ok(Some(Filed {
            id: format!("{folder}/{id}"),
        }))
    }
}

#[get("/folders/{fid}/filed/{id}", tag = "Widgets")]
async fn get_filed(#[key("fid", "id")] filed: Granted<Filed>) -> String {
    filed.into_inner().id
}

async fn call_filed(uri: &str) -> (StatusCode, String) {
    struct AllowAll;
    #[async_trait]
    impl CapabilityChecker for AllowAll {
        async fn check(&self, _: &str, _: &[String], _: &Capability) -> Result<bool, AuthError> {
            Ok(true)
        }
        async fn check_instance(
            &self,
            _: &str,
            _: &[String],
            _: &str,
            _: &ResourceEntity,
        ) -> Result<bool, AuthError> {
            Ok(true)
        }
    }

    let app = OpenApiRouter::<()>::new()
        .routes(routes!(get_filed))
        .split_for_parts()
        .0
        .layer(axum::middleware::from_fn(
            |mut request: Request<Body>, next: axum::middleware::Next| async move {
                request.extensions_mut().insert(CapabilityContext {
                    tenant_id: Some("acme".into()),
                    roles: vec!["viewer".into()],
                });
                let checker: Arc<dyn CapabilityChecker> = Arc::new(AllowAll);
                request.extensions_mut().insert(checker);
                next.run(request).await
            },
        ));

    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .expect("request");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

/// Both named segments reach the loader, in the order `#[key]` named
/// them. Before tuples were implemented the second was silently dropped.
#[tokio::test]
async fn a_composite_key_carries_every_segment() {
    let (status, body) = call_filed("/folders/inbox/filed/7").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "inbox/7", "the folder is half the identity");
}

/// The segments are typed independently, so a bad one is a 400 naming
/// its own position rather than a wrong-object load.
#[tokio::test]
async fn a_bad_segment_in_a_composite_key_is_rejected() {
    let (status, _) = call_filed("/folders/inbox/filed/not-a-number").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Both segments are documented, each with the schema its own type
/// implies — not just the first.
#[test]
fn a_composite_key_documents_every_segment() {
    let (_router, api) = OpenApiRouter::<()>::new()
        .routes(routes!(get_filed))
        .split_for_parts();
    let op = operation(
        &api,
        "/folders/{fid}/filed/{id}",
        utoipa::openapi::path::HttpMethod::Get,
    );

    let params = op.parameters.expect("both segments are declared");
    let named: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(named, ["fid", "id"]);

    let kinds: Vec<serde_json::Value> = params
        .iter()
        .map(|p| serde_json::to_value(p.schema.as_ref().unwrap()).unwrap()["type"].clone())
        .collect();
    assert_eq!(
        kinds,
        vec![json!("string"), json!("integer")],
        "each segment carries its own type",
    );
}

/// A site and a key that disagree about how many segments there are used
/// to truncate silently. `DefaultSite` names none, so an instance key is
/// exactly that mismatch.
#[tokio::test]
async fn a_site_that_names_too_few_segments_is_refused() {
    let (mut parts, _rx) = {
        let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
        request.extensions_mut().insert(CapabilityContext {
            tenant_id: Some("acme".into()),
            roles: vec!["viewer".into()],
        });
        let checker: Arc<dyn CapabilityChecker> = Arc::new(RegionChecker);
        request.extensions_mut().insert(checker);
        let (parts, _) = request.into_parts();
        (parts, ())
    };

    use axum::extract::FromRequestParts;
    use axum::response::IntoResponse;

    let rejection =
        Granted::<doxa::auth::One<Widget>, doxa::auth::DefaultSite>::from_request_parts(
            &mut parts,
            &(),
        )
        .await
        .err()
        .expect("the site names no segments but the key takes one");

    assert_eq!(
        rejection.into_response().status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "a route/key mismatch is a misconfiguration, not a bad request",
    );
}
