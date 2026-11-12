//! Authorizing several rows at once as one query: the policy's residual becomes a `WHERE`
//! clause ([`condition_from_residual`]), `Scoping` adds the tenant, and `Scoped` hands the
//! handler the filter without the coarse listing question.

#![cfg(all(feature = "full", feature = "policy-sea-orm"))]

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::http::Request;
use doxa::audit::{AuditEvent, AuditEventBuilder, AuditLogger};
use doxa::auth::{
    AuthContext, AuthorizeScope, Claims, Denial, FromAuthExtensions, FromState, GrantProfile,
    Granted, Many, Scoped, Scoping,
};
use doxa::policy::{
    condition_from_residual, AuthError, Capability, CapabilityChecker, DbLoadError, ResourceEntity,
    ScopedTable,
};
use doxa::{asset, get, routes, Actions, OpenApiRouter, PolicyResource};
use sea_orm::entity::prelude::*;
use sea_orm::{Condition, DatabaseConnection, DbBackend, MockDatabase, QueryTrait, Select};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ---- the row ----------------------------------------------------------------

/// `region` is both the Cedar attribute the policy names and the column it resolves to.
#[derive(
    Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize, PolicyResource,
)]
#[sea_orm(table_name = "widgets")]
#[resource(entity_type = "Widget")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,

    #[resource(id, attr, key)]
    pub name: String,

    #[resource(attr)]
    pub region: String,

    #[resource(parent = "Tenant", scope)]
    pub tenant_id: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Debug, Clone, Copy, Actions)]
#[actions(resource = "Widget", prefix = "widgets")]
pub enum WidgetAction {
    /// List and view widgets.
    #[action(verb = get)]
    Read,
}

// ---- what the consumer's extension assembles --------------------------------

/// The application's session: here, one filter per asset.
#[derive(Clone)]
pub struct Grants {
    /// The condition the policy left on widgets, or `None` where it granted
    /// nothing at all.
    pub widgets: Option<Condition>,
}

impl Grants {
    /// What `PolicyExtension::extract_residual_attrs` does with the `when` body.
    fn from_residual(body: &Value) -> Result<Self, AuthError> {
        Ok(Grants {
            widgets: Some(condition_from_residual::<Model>(body)?),
        })
    }

    /// A caller the policy granted nothing to.
    fn none() -> Self {
        Grants { widgets: None }
    }
}

/// The claims the layer would have resolved.
#[derive(Clone)]
pub struct TestClaims {
    roles: Vec<String>,
}

impl Claims for TestClaims {
    fn sub(&self) -> &str {
        "someone"
    }

    fn roles(&self) -> &[String] {
        &self.roles
    }

    fn scope(&self) -> Option<&str> {
        Some("acme")
    }
}

pub type Caller = Arc<AuthContext<Grants, TestClaims>>;

// ---- the application --------------------------------------------------------

pub struct AppGrants;

impl GrantProfile for AppGrants {
    type Ctx = Caller;
    type State = DatabaseConnection;
    type Source = FromState<DatabaseConnection>;
    type Error = DbLoadError;
}

#[asset(row = Model, profile = AppGrants, actions = WidgetAction)]
pub struct WidgetByName;

/// The tenant column and the policy's residual; dropping either widens the listing.
impl Scoping for WidgetByName {
    type Filter = Select<Entity>;

    fn scope(_action: &str, ctx: &Self::Ctx) -> Result<Option<Self::Filter>, AuthError> {
        let tenant = FromAuthExtensions::tenant(ctx).unwrap_or_default();

        Ok(ctx
            .session
            .widgets
            .clone()
            .map(|condition| Model::scoped(tenant).filter(condition)))
    }

    /// An unrestricted caller's subset: this door never asks the checker, so it can't see admin.
    fn unscoped() -> Option<Self::Filter> {
        Some(Entity::find())
    }
}

// ---- policy stub ------------------------------------------------------------

/// Coarse by role. Nothing here answers instance questions: the point of
/// this path is that it never asks one.
struct Roles;

#[async_trait]
impl CapabilityChecker for Roles {
    async fn check(&self, _: &str, roles: &[String], cap: &Capability) -> Result<bool, AuthError> {
        Ok(roles.iter().any(|role| role == cap.name))
    }

    async fn check_instance(
        &self,
        _: &str,
        _: &[String],
        _: &str,
        _: &ResourceEntity,
    ) -> Result<bool, AuthError> {
        panic!("a filter is not an instance check: this path must not evaluate rows");
    }
}

// ---- harness ----------------------------------------------------------------

/// The residual Cedar leaves behind for `when { resource.region == "us" }`.
fn residual() -> Value {
    json!({"==": {
        "left": {".": {"left": {"Var": "resource"}, "attr": "region"}},
        "right": {"Value": "us"},
    }})
}

fn parts(
    roles: &[&str],
    grants: Grants,
) -> (
    axum::http::request::Parts,
    tokio::sync::mpsc::Receiver<AuditEvent>,
) {
    parts_as(roles, grants, false)
}

fn parts_as(
    roles: &[&str],
    grants: Grants,
    is_admin: bool,
) -> (
    axum::http::request::Parts,
    tokio::sync::mpsc::Receiver<AuditEvent>,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();

    let ctx: Caller = Arc::new(AuthContext {
        claims: TestClaims {
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        },
        session: grants,
        is_admin,
    });
    request.extensions_mut().insert(ctx);

    let checker: Arc<dyn CapabilityChecker> = Arc::new(Roles);
    request.extensions_mut().insert(checker);
    request
        .extensions_mut()
        .insert(AuditEventBuilder::new(AuditLogger::from_sender(tx)));

    let (parts, _) = request.into_parts();
    (parts, rx)
}

fn emitted(
    parts: &axum::http::request::Parts,
    rx: &mut tokio::sync::mpsc::Receiver<AuditEvent>,
) -> AuditEvent {
    parts
        .extensions
        .get::<AuditEventBuilder>()
        .expect("the harness installed one")
        .auto_emit();
    rx.try_recv().expect("the decision was recorded")
}

fn sql(query: Select<Entity>) -> String {
    query.build(DbBackend::Postgres).to_string()
}

fn granted() -> Grants {
    Grants::from_residual(&residual()).expect("the residual translates")
}

// ---- the filter -------------------------------------------------------------

/// Both halves reach the query: the tenant the row declares, and the
/// condition the policy left behind.
#[test]
fn the_scope_composes_the_tenant_and_the_policys_own_condition() {
    let (parts, _rx) = parts(&[], granted());

    let scope = WidgetByName::authorize_scope_dependency(widget_action::Read, &parts.extensions)
        .expect("the action is declared and the policy granted a subset");

    let sql = sql(scope);
    assert!(sql.contains(r#""tenant_id" = 'acme'"#), "{sql}");
    assert!(sql.contains(r#""region" = 'us'"#), "{sql}");
}

#[test]
fn an_admin_is_scoped_to_everything_rather_than_to_the_policys_condition() {
    let (parts, _rx) = parts_as(&[], granted(), true);

    let scope = WidgetByName::authorize_scope_dependency(widget_action::Read, &parts.extensions)
        .expect("the action is declared");

    let sql = sql(scope);
    assert!(
        !sql.contains(r#""region" = 'us'"#),
        "an unrestricted caller must not carry the policy's row condition: {sql}",
    );
    assert!(
        !sql.contains(r#""tenant_id" = 'acme'"#),
        "nor the tenant, which is what this asset's `unscoped` chose to mean: {sql}",
    );
}

/// The mirror, and the reason the seat is not simply "admins skip the
/// scope": a caller the policy did *not* mark is scoped exactly as before.
#[test]
fn an_ordinary_caller_is_unaffected_by_the_admin_seat() {
    let (parts, _rx) = parts(&[], granted());

    let sql = sql(
        WidgetByName::authorize_scope_dependency(widget_action::Read, &parts.extensions)
            .expect("granted a subset"),
    );

    assert!(sql.contains(r#""region" = 'us'"#), "{sql}");
    assert!(sql.contains(r#""tenant_id" = 'acme'"#), "{sql}");
}

#[test]
fn an_admin_is_not_refused_by_an_empty_grant() {
    let (parts, _rx) = parts_as(&[], Grants::none(), true);

    assert!(
        WidgetByName::authorize_scope_dependency(widget_action::Read, &parts.extensions).is_ok(),
        "an unrestricted caller must not be refused for holding no per-row grant",
    );
}

/// Several names in one query, with no instance check (the stub panics on one).
#[test]
fn several_names_resolve_in_one_query_the_policy_has_already_narrowed() {
    let (parts, _rx) = parts(&[], granted());

    let scope = WidgetByName::authorize_scope_dependency(widget_action::Read, &parts.extensions)
        .expect("granted a subset");

    let named = ["primary".to_owned(), "replica".to_owned()];
    let sql = sql(scope.filter(Column::Name.is_in(named)));

    assert!(sql.contains(r#""name" IN ('primary', 'replica')"#), "{sql}");
    assert!(sql.contains(r#""tenant_id" = 'acme'"#), "{sql}");
    assert!(sql.contains(r#""region" = 'us'"#), "{sql}");
}

/// The plural lookup the derive writes, for the same request without a
/// policy condition to add: one `IN`, still confined to the owner.
#[test]
fn the_scoped_plural_lookup_is_one_statement() {
    let keys = ["primary".to_owned(), "replica".to_owned()];
    let sql = sql(Model::scoped("acme").filter(Column::Name.is_in(keys)));

    assert!(sql.contains(r#""tenant_id" = 'acme'"#), "{sql}");
    assert!(sql.contains(r#""name" IN ('primary', 'replica')"#), "{sql}");
}

// ---- the door ---------------------------------------------------------------

#[test]
fn a_dependency_skips_the_coarse_gate() {
    let (parts, _rx) = parts(&[], granted());

    assert!(
        WidgetByName::authorize_scope_dependency(widget_action::Read, &parts.extensions).is_ok(),
        "the caller holds no capability and should not need one",
    );
}

/// The gated form is the one `Granted<Many<R>>` runs, and it does ask.
#[tokio::test]
async fn the_gated_form_still_wants_the_capability() {
    let (parts, _rx) = parts(&[], granted());

    let denial = WidgetByName::authorize_scope(widget_action::Read, &parts.extensions)
        .await
        .expect_err("does not hold widgets.read");

    let Denial::Denied { action, .. } = denial else {
        panic!("expected a denial");
    };
    assert_eq!(action, "widgets.read");
}

#[tokio::test]
async fn the_gated_form_passes_with_the_capability() {
    let (parts, _rx) = parts(&["widgets.read"], granted());

    assert!(
        WidgetByName::authorize_scope(widget_action::Read, &parts.extensions)
            .await
            .is_ok(),
    );
}

/// The listing route must answer an admin as the `Scoped` door does.
#[tokio::test]
async fn the_listing_route_seats_an_admin_the_way_the_dependency_does() {
    let (mut parts, _rx) = parts_as(&["widgets.read"], granted(), true);
    let db = MockDatabase::new(DbBackend::Postgres).into_connection();

    let granted =
        Granted::<Many<WidgetByName, widget_action::Read>>::from_request_parts(&mut parts, &db)
            .await
            .expect("holds widgets.read");

    let sql = sql(granted.into_inner());
    assert!(
        !sql.contains(r#""region" = 'us'"#),
        "the listing carried the policy's row condition an admin is exempt from: {sql}",
    );
}

#[tokio::test]
async fn the_listing_route_scopes_an_ordinary_caller() {
    let (mut parts, _rx) = parts(&["widgets.read"], granted());
    let db = MockDatabase::new(DbBackend::Postgres).into_connection();

    let granted =
        Granted::<Many<WidgetByName, widget_action::Read>>::from_request_parts(&mut parts, &db)
            .await
            .expect("holds widgets.read");

    let sql = sql(granted.into_inner());
    assert!(sql.contains(r#""region" = 'us'"#), "{sql}");
    assert!(sql.contains(r#""tenant_id" = 'acme'"#), "{sql}");
}

/// The default `empty_scope` refuses rather than handing back an empty page.
#[test]
fn a_caller_granted_nothing_is_refused() {
    let (parts, _rx) = parts(&[], Grants::none());

    let denial = WidgetByName::authorize_scope_dependency(widget_action::Read, &parts.extensions)
        .expect_err("no scope");

    let Denial::Denied { reason, .. } = denial else {
        panic!("expected a denial");
    };
    assert_eq!(reason, "no authorized scope");
}

#[test]
fn an_unauthenticated_request_reaches_no_verdict() {
    let extensions = axum::http::Extensions::new();

    let denial = WidgetByName::authorize_scope_dependency(widget_action::Read, &extensions)
        .expect_err("nothing installed a caller");

    assert!(matches!(denial, Denial::Auth(_)));
}

// ---- the trail --------------------------------------------------------------

/// Recorded under the resource a listing would use.
#[test]
fn the_subset_is_recorded() {
    let (parts, mut rx) = parts(&[], granted());

    WidgetByName::authorize_scope_dependency(widget_action::Read, &parts.extensions)
        .expect("granted");

    let event = emitted(&parts, &mut rx);
    assert_eq!(event.resource_type.as_deref(), Some("Widget"));
    assert_eq!(event.resource_id.as_deref(), Some("collection"));
}

#[test]
fn a_refusal_is_recorded_too() {
    let (parts, mut rx) = parts(&[], Grants::none());

    let _ = WidgetByName::authorize_scope_dependency(widget_action::Read, &parts.extensions);

    let event = emitted(&parts, &mut rx);
    assert_eq!(event.resource_type.as_deref(), Some("Widget"));
    assert_eq!(event.error_message.as_deref(), Some("no authorized scope"));
}

// ---- the extractor ----------------------------------------------------------

/// It mounts on `()`: there is no loader on this path, so no `FromRef` bound applies.
#[tokio::test]
async fn the_extractor_hands_over_the_filter() {
    let (mut parts, _rx) = parts(&["widgets.read"], granted());

    let scoped = Scoped::<WidgetByName, widget_action::Read>::from_request_parts(&mut parts, &())
        .await
        .expect("granted a subset");

    let sql = sql(scoped.into_inner());
    assert!(sql.contains(r#""region" = 'us'"#), "{sql}");
}

/// It carries the caller too, so a handler needing the tenant does not pay
/// for a second extractor to read back what this one already had.
#[tokio::test]
async fn the_extractor_carries_the_caller() {
    let (mut parts, _rx) = parts(&["widgets.read"], granted());

    let scoped = Scoped::<WidgetByName, widget_action::Read>::from_request_parts(&mut parts, &())
        .await
        .expect("granted a subset");

    assert_eq!(FromAuthExtensions::tenant(scoped.caller()), Some("acme"));
}

/// Unlike the dependency door, the extractor asks the capability first.
#[tokio::test]
async fn the_extractor_refuses_a_caller_without_the_capability() {
    let (mut parts, mut rx) = parts(&[], granted());

    let Err(Denial::Denied { action, reason, .. }) =
        Scoped::<WidgetByName, widget_action::Read>::from_request_parts(&mut parts, &()).await
    else {
        panic!("does not hold widgets.read");
    };
    assert_eq!(action, "widgets.read");
    assert_eq!(reason, "capability denied");
    assert!(emitted(&parts, &mut rx).error_message.is_some());
}

// ---- at a route -------------------------------------------------------------

/// Through the real `#[get]` / `routes!` path, for the OpenAPI half.
#[get("/widgets", tag = "Widgets")]
async fn list_widgets(widgets: Scoped<WidgetByName, widget_action::Read>) -> &'static str {
    widgets.into_inner();
    "ok"
}

#[test]
fn the_route_documents_the_permission_a_dependency_needs() {
    let (_router, api) = OpenApiRouter::<()>::new()
        .routes(routes!(list_widgets))
        .split_for_parts();

    let op = api
        .paths
        .paths
        .get("/widgets")
        .and_then(|item| item.get.as_ref())
        .expect("the route is in the document");

    let security = serde_json::to_value(op.security.clone().expect("a requirement is stamped"))
        .expect("serializes");
    assert_eq!(security, json!([{ "bearer": ["widgets.read"] }]));

    let badge = op
        .extensions
        .as_ref()
        .and_then(|extensions| extensions.get("x-required-permissions"))
        .expect("badge extension");
    // Worded as a subset, so a reader can tell it from the instance and
    // collection forms at a glance.
    assert_eq!(badge, &json!(["read on Widget (subset)"]));

    let documented: Vec<&str> = op.responses.responses.keys().map(String::as_str).collect();
    assert!(documented.contains(&"401"), "{documented:?}");
    assert!(documented.contains(&"403"), "{documented:?}");
}

// ---- what the translation refuses -------------------------------------------

/// An untranslatable residual is an error, never a filter missing that clause.
#[test]
fn an_untranslatable_residual_is_an_error_rather_than_a_wider_filter() {
    let unsupported = json!({"like": {
        "left": {".": {"left": {"Var": "resource"}, "attr": "region"}},
        "right": {"Value": "us%"},
    }});

    assert!(Grants::from_residual(&unsupported).is_err());
}

#[test]
fn an_attribute_that_is_not_a_column_is_refused() {
    let computed = json!({"==": {
        "left": {".": {"left": {"Var": "resource"}, "attr": "reachable"}},
        "right": {"Value": true},
    }});

    assert!(Grants::from_residual(&computed).is_err());
}

#[derive(Clone, doxa::State)]
struct NoState;
