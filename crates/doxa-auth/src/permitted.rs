//! Instance-level authorization extractor.
//!
//! [`Require<M>`](crate::Require) answers "may this caller use this
//! endpoint at all". [`Permitted<R, S>`] answers "may they touch *this
//! object*": it reads the id from a named path parameter, loads the
//! object, and evaluates the policy with the object's own attributes in
//! scope — so `when { resource.owner == … }` resolves instead of
//! collapsing to a residual denial.
//!
//! The resource is stamped onto the audit builder **before** the check
//! runs, so a denial records which object was refused.

use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts, RawPathParams};
use axum::response::{IntoResponse, Response};
use http::request::Parts;

use doxa_policy::{AuthError, CapabilityChecker, PolicyResource, ResourceEntity, ResourceIdType};

use crate::context::CapabilityContext;

/// Everything the route macro knows about one `Permitted` argument:
/// which path parameter carries the id, which Cedar action to check,
/// and which OpenAPI security scheme to reference.
///
/// The macro generates an impl per call site. Hand-written routes
/// implement it directly — it is three consts.
pub trait PermitSite: Send + Sync + 'static {
    /// Path parameter holding the resource id, as named in the route
    /// template.
    const PARAM: &'static str;
    /// Cedar action to authorize, baked in from the HTTP verb.
    const ACTION: &'static str;
    /// OpenAPI security scheme name for the emitted requirement.
    const SCHEME: &'static str = "bearer";
}

/// How to fetch one [`PolicyResource`] by id.
///
/// `Ok(None)` means no such object — [`Permitted`] turns that into a
/// 404 without consulting the policy.
pub trait LoadResource: PolicyResource {
    /// State the loader needs, reached from the router state via
    /// [`FromRef`].
    type State: Send + Sync;
    /// Error type for load failures. Its `IntoResponse` is returned
    /// verbatim, preserving any audit outcome it attaches.
    type Error: IntoResponse;

    /// Fetch the object, or `None` if it does not exist.
    ///
    /// `caller` carries the tenant, so a multi-tenant loader can scope
    /// the lookup instead of resolving an id another tenant owns.
    fn load(
        id: Self::Id,
        state: &Self::State,
        caller: &CapabilityContext,
    ) -> impl Future<Output = Result<Option<Self>, Self::Error>> + Send;
}

/// A loaded resource the caller is authorized to act on.
///
/// Extraction fails with 400 (unparseable id), 401 (no auth context),
/// 403 (policy denial), or 404 (no such object).
pub struct Permitted<R, S: PermitSite>(pub R, PhantomData<fn() -> S>);

impl<R, S: PermitSite> Permitted<R, S> {
    /// Consume the guard and return the loaded resource.
    pub fn into_inner(self) -> R {
        self.0
    }
}

impl<R, S: PermitSite> std::ops::Deref for Permitted<R, S> {
    type Target = R;
    fn deref(&self) -> &R {
        &self.0
    }
}

impl<R: std::fmt::Debug, S: PermitSite> std::fmt::Debug for Permitted<R, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Permitted")
            .field("resource", &self.0)
            .field("param", &S::PARAM)
            .field("action", &S::ACTION)
            .finish()
    }
}

impl<R, S, St> FromRequestParts<St> for Permitted<R, S>
where
    R: LoadResource,
    S: PermitSite,
    St: Send + Sync,
    R::State: FromRef<St>,
{
    // `Response` rather than a concrete error: the loader's error type
    // belongs to the consumer, and returning it untouched preserves the
    // audit outcome its `IntoResponse` attaches.
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &St) -> Result<Self, Response> {
        // `RawPathParams` borrows `UrlParams` out of extensions rather
        // than removing it, so a handler may still take its own `Path`.
        let params = RawPathParams::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;

        let raw = params
            .iter()
            .find(|(name, _)| *name == S::PARAM)
            .map(|(_, value)| value)
            .ok_or_else(|| {
                AuthError::PolicyFailed(format!(
                    "route has no path parameter `{}` for {}",
                    S::PARAM,
                    R::ENTITY_TYPE,
                ))
                .into_response()
            })?;

        let id = raw.parse::<R::Id>().map_err(|_| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                format!("invalid {} id: {raw}", R::ENTITY_TYPE),
            )
                .into_response()
        })?;

        // Stamp before authorizing so a denial names the object.
        stamp_audit::<R, S>(parts, raw);

        // Resolved before the load so an unauthenticated caller cannot
        // tell a missing object from one they may not see.
        let ctx = parts
            .extensions
            .get::<CapabilityContext>()
            .ok_or_else(|| AuthError::MissingCredentials.into_response())?;
        let checker = parts
            .extensions
            .get::<Arc<dyn CapabilityChecker>>()
            .ok_or_else(|| {
                AuthError::PolicyFailed("capability checker not configured on AuthLayer".into())
                    .into_response()
            })?;

        let resource = R::load(id, &R::State::from_ref(state), ctx)
            .await
            .map_err(IntoResponse::into_response)?
            .ok_or_else(|| {
                (
                    axum::http::StatusCode::NOT_FOUND,
                    format!("{} not found", R::ENTITY_TYPE),
                )
                    .into_response()
            })?;

        let entity = ResourceEntity::of(&resource);

        let allowed = checker
            .check_instance(
                ctx.tenant_id.as_deref().unwrap_or(""),
                &ctx.roles,
                S::ACTION,
                &entity,
            )
            .await
            .map_err(IntoResponse::into_response)?;

        if !allowed {
            return Err(AuthError::Forbidden.into_response());
        }

        // The loaded object's id is authoritative — it may differ from
        // the path segment when the route keys on a slug.
        restamp_audit::<R>(parts, &entity.entity_id);

        Ok(Permitted(resource, PhantomData))
    }
}

#[cfg(feature = "audit")]
fn stamp_audit<R: PolicyResource, S: PermitSite>(parts: &Parts, id: &str) {
    if let Some(audit) = parts.extensions.get::<doxa_audit::AuditEventBuilder>() {
        audit.set_resource(R::ENTITY_TYPE, id);
        audit.set_action(S::ACTION);
    }
}

#[cfg(not(feature = "audit"))]
fn stamp_audit<R: PolicyResource, S: PermitSite>(_parts: &Parts, _id: &str) {}

#[cfg(feature = "audit")]
fn restamp_audit<R: PolicyResource>(parts: &Parts, id: &str) {
    if let Some(audit) = parts.extensions.get::<doxa_audit::AuditEventBuilder>() {
        audit.set_resource(R::ENTITY_TYPE, id);
    }
}

#[cfg(not(feature = "audit"))]
fn restamp_audit<R: PolicyResource>(_parts: &Parts, _id: &str) {}

// ---------------------------------------------------------------------------
// OpenAPI
// ---------------------------------------------------------------------------

/// Map a [`ResourceIdType`] to the OpenAPI schema for the path
/// parameter.
fn id_schema(kind: ResourceIdType) -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
    use utoipa::openapi::schema::{KnownFormat, SchemaFormat};
    use utoipa::openapi::{ObjectBuilder, RefOr, Schema, Type};

    let mut b = ObjectBuilder::new();
    b = match kind {
        ResourceIdType::String => b.schema_type(Type::String),
        ResourceIdType::Integer => b
            .schema_type(Type::Integer)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Int64))),
        ResourceIdType::Uuid => b
            .schema_type(Type::String)
            .format(Some(SchemaFormat::KnownFormat(KnownFormat::Uuid))),
    };
    RefOr::T(Schema::Object(b.build()))
}

/// The path parameter comes from [`PermitSite::PARAM`], never from the
/// positional template list — the annotation is authoritative.
impl<R, S> doxa::DocPathParams for Permitted<R, S>
where
    R: PolicyResource,
    S: PermitSite,
{
    fn describe(op: &mut utoipa::openapi::path::Operation, _positional: &[&'static str]) {
        use utoipa::openapi::path::{ParameterBuilder, ParameterIn};
        use utoipa::openapi::Required;

        let param = ParameterBuilder::new()
            .name(S::PARAM)
            .parameter_in(ParameterIn::Path)
            .required(Required::True)
            .description(Some(format!("Identifier of the {}", R::ENTITY_TYPE)))
            .schema(Some(id_schema(R::ID_TYPE)))
            .build();
        op.parameters.get_or_insert_with(Vec::new).push(param);
    }
}

impl<R, S> doxa::DocOperationSecurity for Permitted<R, S>
where
    R: PolicyResource,
    S: PermitSite,
{
    fn describe(op: &mut utoipa::openapi::path::Operation) {
        doxa::record_required_permission(
            op,
            S::SCHEME,
            &format!("{}:{}", R::ENTITY_TYPE, S::ACTION),
            &format!("{} on {} (instance)", S::ACTION, R::ENTITY_TYPE),
        );
    }
}

impl<R, S> doxa::DocOperationContribution for Permitted<R, S>
where
    R: PolicyResource,
    S: PermitSite,
{
    fn contribution() -> doxa::OperationContribution {
        doxa::OperationContribution::new()
            .with_response(doxa::ResponseContribution::new(
                "400",
                format!("Malformed {} identifier", R::ENTITY_TYPE),
            ))
            .with_response(doxa::ResponseContribution::unauthorized())
            .with_response(doxa::ResponseContribution::new(
                "403",
                format!("Policy denied `{}` on this {}", S::ACTION, R::ENTITY_TYPE),
            ))
            .with_response(doxa::ResponseContribution::new(
                "404",
                format!("No such {}", R::ENTITY_TYPE),
            ))
    }
}
