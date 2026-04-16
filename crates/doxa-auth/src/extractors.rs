//! Axum extractors for authentication + capability gating.
//!
//! - [`Auth<S, C>`] pulls the typed authenticated-user context. Generic
//!   over the session output type `S` and the claim type `C: Claims` so
//!   it works with any [`Policy<S>`](doxa_policy::Policy) and any claim
//!   shape.
//! - [`Require<M, S>`] enforces a single [`Capable`]
//!   capability against the request's Cedar policy and stamps the
//!   corresponding OpenAPI security / badge metadata onto the
//!   operation. The marker type `M` carries the `Capability` through
//!   type generics; the optional scheme marker `S: SchemeName` names
//!   the OpenAPI security scheme the badge references (defaults to
//!   `"bearer"` — [`BearerScheme`]).
//!
//! Both extractors read only type-erased request-extension entries
//! ([`AuthContext<S, C>`] and [`CapabilityContext`] respectively), so
//! they compose freely with any [`AuthLayer`](crate::AuthLayer) setup.

use std::marker::PhantomData;
use std::sync::Arc;

use http::request::Parts;

use doxa_policy::{AuthError, CapabilityChecker, Capable};

use crate::claims::Claims;
use crate::context::{AuthContext, CapabilityContext};

/// Extracts the authenticated user context. Returns 401 if missing.
#[derive(Debug, Clone)]
pub struct Auth<S: Clone + Send + Sync + 'static, C: Claims>(pub AuthContext<S, C>);

impl<S, C, ST> axum::extract::FromRequestParts<ST> for Auth<S, C>
where
    S: Clone + Send + Sync + 'static,
    C: Claims,
    ST: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &ST) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthContext<S, C>>()
            .cloned()
            .map(Auth)
            .ok_or(AuthError::MissingCredentials)
    }
}

// ---------------------------------------------------------------------------
// Capability gating: `Require<M, S>`
// ---------------------------------------------------------------------------

/// Compile-time security-scheme name for the OpenAPI metadata emitted
/// by [`Require`]'s `DocOperationSecurity` impl.
///
/// Implementors pair a zero-sized marker type with a scheme name
/// registered on the [`doxa::ApiDocBuilder`]. The default marker
/// [`BearerScheme`] carries the conventional `"bearer"` name. Deployments
/// that register their bearer scheme under a different name define their
/// own marker (one line) and write `Require<Foo, MyScheme>`.
pub trait SchemeName: Send + Sync + 'static {
    /// The security-scheme name as it appears in the rendered OpenAPI
    /// spec's `components.securitySchemes` map.
    const NAME: &'static str;
}

/// Default [`SchemeName`] marker carrying the name `"bearer"`, matching
/// [`AuthLayer`](crate::AuthLayer)'s default. Used when `Require<M>` is
/// written without an explicit scheme parameter.
#[derive(Debug, Clone, Copy, Default)]
pub struct BearerScheme;

impl SchemeName for BearerScheme {
    const NAME: &'static str = "bearer";
}

/// Capability-gated axum extractor.
///
/// On every request `Require<M, S>`:
/// 1. Pulls the [`CapabilityContext`] and the type-erased
///    `Arc<dyn CapabilityChecker>` inserted by
///    [`AuthLayer`](crate::AuthLayer).
/// 2. Calls [`CapabilityChecker::check`] with the tenant + roles and
///    the [`Capability`](doxa_policy::Capability) attached to `M`.
/// 3. Returns [`AuthError::Forbidden`] on deny,
///    [`AuthError::MissingCredentials`] if the layer never ran, or
///    [`AuthError::PolicyFailed`] if the layer ran but no checker was
///    configured.
///
/// On OpenAPI generation the same type stamps
/// [`record_required_permission`](doxa::record_required_permission)
/// against the operation — the scheme name comes from `S::NAME`, the
/// required-permission badge from `M::CAPABILITY.name` /
/// `.description`.
///
/// Because both type parameters are zero-sized, `Require<M, S>` is
/// zero-cost at runtime and decomposes to a single async function call.
///
/// # Example
///
/// ```ignore
/// use doxa_auth::Require;
/// use doxa_policy::{Capable, Capability, CapabilityCheck};
///
/// pub const WIDGETS_READ: Capability = Capability {
///     name: "widgets.read",
///     description: "Read widget definitions",
///     checks: &[CapabilityCheck {
///         action: "read",
///         entity_type: "Widget",
///         entity_id: "collection",
///     }],
/// };
///
/// pub struct WidgetsRead;
/// impl Capable for WidgetsRead {
///     const CAPABILITY: &'static Capability = &WIDGETS_READ;
/// }
///
/// #[doxa::get("/widgets")]
/// async fn list_widgets(_: Require<WidgetsRead>) -> &'static str { "ok" }
/// ```
pub struct Require<M: Capable, S: SchemeName = BearerScheme>(PhantomData<fn() -> (M, S)>);

impl<M: Capable, S: SchemeName> std::fmt::Debug for Require<M, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Require")
            .field("capability", &M::CAPABILITY.name)
            .field("scheme", &S::NAME)
            .finish()
    }
}

impl<M: Capable, S: SchemeName> Clone for Require<M, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<M: Capable, S: SchemeName> Copy for Require<M, S> {}

impl<M, Sch, St> axum::extract::FromRequestParts<St> for Require<M, Sch>
where
    M: Capable,
    Sch: SchemeName,
    St: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &St) -> Result<Self, Self::Rejection> {
        let ctx = parts
            .extensions
            .get::<CapabilityContext>()
            .ok_or(AuthError::MissingCredentials)?
            .clone();
        let checker = parts
            .extensions
            .get::<Arc<dyn CapabilityChecker>>()
            .cloned()
            .ok_or_else(|| {
                AuthError::PolicyFailed("capability checker not configured on AuthLayer".into())
            })?;
        let tenant = ctx.tenant_id.as_deref().unwrap_or("");
        let allowed = checker.check(tenant, &ctx.roles, M::CAPABILITY).await?;
        if allowed {
            Ok(Require(PhantomData))
        } else {
            Err(AuthError::Forbidden)
        }
    }
}

impl<M: Capable, S: SchemeName> doxa::DocOperationSecurity for Require<M, S> {
    fn describe(op: &mut utoipa::openapi::path::Operation) {
        doxa::record_required_permission(
            op,
            S::NAME,
            M::CAPABILITY.name,
            M::CAPABILITY.description,
        );
    }
}
