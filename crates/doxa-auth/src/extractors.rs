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
use crate::context::{AuthContext, CapabilityContext, SuperAdmin, TenantAdmin};
use crate::granted::Reach;
use crate::record::{self, Denied};

/// The authenticated caller's context, shared with [`AuthLayer`](crate::AuthLayer); 401 if missing.
#[derive(Debug, Clone)]
pub struct Auth<S: Send + Sync + 'static, C: Claims>(pub Arc<AuthContext<S, C>>);

impl<S, C, ST> axum::extract::FromRequestParts<ST> for Auth<S, C>
where
    S: Send + Sync + 'static,
    C: Claims,
    ST: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &ST) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Arc<AuthContext<S, C>>>()
            .cloned()
            .map(Auth)
            .ok_or(AuthError::MissingCredentials)
    }
}

/// The caller's tenant from [`Claims::scope`], parsed as `T`: 401 without auth, 403 without a
/// scope, 401 when it doesn't parse.
///
/// ```ignore
/// async fn list(tenant: Tenant) -> String { format!("{tenant}") }
/// async fn typed(Tenant(id): Tenant<TenantId>) {}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tenant<T = String>(pub T);

impl<T> std::ops::Deref for Tenant<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: std::fmt::Display> std::fmt::Display for Tenant<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T, St> axum::extract::FromRequestParts<St> for Tenant<T>
where
    T: std::str::FromStr + Send,
    T::Err: std::fmt::Display,
    St: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &St) -> Result<Self, Self::Rejection> {
        let ctx = parts
            .extensions
            .get::<CapabilityContext>()
            .ok_or(AuthError::MissingCredentials)?;
        let scope = ctx.tenant_id.as_deref().ok_or(AuthError::Forbidden)?;
        scope
            .parse()
            .map(Tenant)
            .map_err(|e| AuthError::InvalidToken(format!("scope `{scope}` is not a tenant: {e}")))
    }
}

impl<T> doxa::DocOperationContribution for Tenant<T> {
    fn contribution() -> doxa::OperationContribution {
        doxa::OperationContribution::new()
            .with_response(doxa::ResponseContribution::unauthorized())
            .with_response(doxa::ResponseContribution::new(
                "403",
                "Caller has no tenant",
            ))
    }
}

/// `_: SuperAdmin` gates a route to super admins: 401 without auth, 403 for anyone else.
impl<St: Send + Sync> axum::extract::FromRequestParts<St> for SuperAdmin {
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &St) -> Result<Self, Self::Rejection> {
        let ctx = parts
            .extensions
            .get::<CapabilityContext>()
            .ok_or(AuthError::MissingCredentials)?;
        if parts.extensions.get::<SuperAdmin>().is_some() {
            record::via(&parts.extensions, Reach::Super);
            return Ok(SuperAdmin);
        }
        Err(refuse_gate(parts, ctx, "super_admin", "not a super admin"))
    }
}

/// `_: TenantAdmin` gates a route to tenant admins with a tenant, or super admins: 401 without
/// auth, 403 for anyone else.
impl<St: Send + Sync> axum::extract::FromRequestParts<St> for TenantAdmin {
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &St) -> Result<Self, Self::Rejection> {
        let ctx = parts
            .extensions
            .get::<CapabilityContext>()
            .ok_or(AuthError::MissingCredentials)?;
        if parts.extensions.get::<SuperAdmin>().is_some() {
            record::via(&parts.extensions, Reach::Super);
            return Ok(TenantAdmin);
        }
        if parts.extensions.get::<TenantAdmin>().is_some() && ctx.tenant_id.is_some() {
            record::via(&parts.extensions, Reach::Tenant);
            return Ok(TenantAdmin);
        }
        Err(refuse_gate(
            parts,
            ctx,
            "tenant_admin",
            "not a tenant admin",
        ))
    }
}

/// Record an admin gate's refusal as [`Require`] records a denied capability.
fn refuse_gate(
    parts: &Parts,
    ctx: &CapabilityContext,
    gate: &'static str,
    reason: &'static str,
) -> AuthError {
    record::record(
        &parts.extensions,
        Denied {
            tenant: ctx.tenant_id.as_deref(),
            action: gate,
            resource_type: "route",
            resource_id: gate,
            reason,
            status: 403,
        },
    );
    AuthError::Forbidden
}

impl doxa::DocOperationContribution for SuperAdmin {
    fn contribution() -> doxa::OperationContribution {
        doxa::OperationContribution::new()
            .with_response(doxa::ResponseContribution::unauthorized())
            .with_response(doxa::ResponseContribution::new(
                "403",
                "Caller is not a super admin",
            ))
    }
}

impl doxa::DocOperationContribution for TenantAdmin {
    fn contribution() -> doxa::OperationContribution {
        doxa::OperationContribution::new()
            .with_response(doxa::ResponseContribution::unauthorized())
            .with_response(doxa::ResponseContribution::new(
                "403",
                "Caller is not a tenant admin",
            ))
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

/// Requires `M`'s capability: 403 on deny, logged and recorded; 401 without
/// [`AuthLayer`](crate::AuthLayer). Documents the permission under scheme `S`.
///
/// ```ignore
/// use doxa_auth::Require;
/// use doxa_policy::{Capable, Capability, CapabilityCheck, ResourceId};
///
/// pub const WIDGETS_READ: Capability = Capability {
///     name: "widgets.read",
///     description: "Read widget definitions",
///     checks: &[CapabilityCheck {
///         action: "read",
///         entity_type: "Widget",
///         entity_id: ResourceId::Literal("collection"),
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
        if parts.extensions.get::<SuperAdmin>().is_some() {
            record::via(&parts.extensions, Reach::Super);
            return Ok(Require(PhantomData));
        }
        if crate::context::unscoped(ctx.tenant_id.as_deref(), &parts.extensions) {
            return Err(AuthError::Forbidden);
        }
        if parts.extensions.get::<TenantAdmin>().is_some() {
            record::via(&parts.extensions, Reach::Tenant);
            return Ok(Require(PhantomData));
        }
        let tenant = ctx.tenant_id.clone().unwrap_or_default();
        let checker = parts
            .extensions
            .get::<Arc<dyn CapabilityChecker>>()
            .cloned()
            .ok_or_else(|| {
                AuthError::PolicyFailed("capability checker not configured on AuthLayer".into())
            })?;
        let allowed = checker.check(&tenant, &ctx.roles, M::CAPABILITY).await?;
        if allowed {
            return Ok(Require(PhantomData));
        }

        let (resource_type, resource_id) =
            crate::granted::capability_resource(M::CAPABILITY, &tenant);

        record::record(
            &parts.extensions,
            Denied {
                tenant: ctx.tenant_id.as_deref(),
                action: M::CAPABILITY.name,
                resource_type,
                resource_id: &resource_id,
                reason: "capability denied",
                status: 403,
            },
        );
        Err(AuthError::Forbidden)
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

/// Documents the statuses the capability gate itself can return, which
/// the handler's own error type never mentions.
impl<M: Capable, S: SchemeName> doxa::DocOperationContribution for Require<M, S> {
    fn contribution() -> doxa::OperationContribution {
        doxa::OperationContribution::new()
            .with_response(doxa::ResponseContribution::unauthorized())
            .with_response(doxa::ResponseContribution::new(
                "403",
                format!("Caller lacks the `{}` capability", M::CAPABILITY.name),
            ))
            .with_response(doxa::ResponseContribution::new(
                "500",
                "Policy evaluation failed",
            ))
    }
}

#[cfg(test)]
mod tests {
    use axum::extract::FromRequestParts;
    use doxa_policy::{Capability, CapabilityCheck, ResourceEntity, ResourceId};

    use super::*;

    struct DenyAll;

    #[async_trait::async_trait]
    impl CapabilityChecker for DenyAll {
        async fn check(&self, _: &str, _: &[String], _: &Capability) -> Result<bool, AuthError> {
            Ok(false)
        }
        async fn check_instance(
            &self,
            _: &str,
            _: &[String],
            _: &str,
            _: &ResourceEntity,
        ) -> Result<bool, AuthError> {
            Ok(false)
        }
    }

    struct WidgetsRead;
    impl Capable for WidgetsRead {
        const CAPABILITY: &'static Capability = &Capability {
            name: "widgets.read",
            description: "Read widgets",
            checks: &[CapabilityCheck {
                action: "read",
                entity_type: "Widget",
                entity_id: ResourceId::Literal("collection"),
            }],
        };
    }

    #[derive(Clone, Copy)]
    enum Mark {
        None,
        Super,
        Tenant,
    }

    fn parts(tenant: Option<&str>, mark: Mark) -> Parts {
        let (mut parts, ()) = http::Request::new(()).into_parts();
        parts.extensions.insert(CapabilityContext {
            tenant_id: tenant.map(str::to_owned),
            roles: vec![],
        });
        parts
            .extensions
            .insert(Arc::new(DenyAll) as Arc<dyn CapabilityChecker>);
        match mark {
            Mark::None => {}
            Mark::Super => {
                parts.extensions.insert(SuperAdmin);
            }
            Mark::Tenant => {
                parts.extensions.insert(TenantAdmin);
            }
        }
        parts
    }

    async fn gate<E: FromRequestParts<(), Rejection = AuthError>>(
        mut parts: Parts,
    ) -> Result<(), AuthError> {
        E::from_request_parts(&mut parts, &()).await.map(drop)
    }

    #[tokio::test]
    async fn only_a_super_admin_passes_the_super_admin_gate() {
        assert!(gate::<SuperAdmin>(parts(None, Mark::Super)).await.is_ok());
        for mark in [Mark::Tenant, Mark::None] {
            let refused = gate::<SuperAdmin>(parts(Some("acme"), mark)).await;
            assert!(matches!(refused, Err(AuthError::Forbidden)));
        }
    }

    #[tokio::test]
    async fn the_tenant_admin_gate_wants_a_tenant_or_a_super_admin() {
        assert!(gate::<TenantAdmin>(parts(Some("acme"), Mark::Tenant))
            .await
            .is_ok());
        assert!(gate::<TenantAdmin>(parts(None, Mark::Super)).await.is_ok());
        for (tenant, mark) in [(Some("acme"), Mark::None), (None, Mark::Tenant)] {
            let refused = gate::<TenantAdmin>(parts(tenant, mark)).await;
            assert!(matches!(refused, Err(AuthError::Forbidden)));
        }
    }

    #[tokio::test]
    async fn either_gate_without_auth_is_unauthenticated() {
        let (bare, ()) = http::Request::new(()).into_parts();
        let (bare2, ()) = http::Request::new(()).into_parts();
        assert!(matches!(
            gate::<SuperAdmin>(bare).await,
            Err(AuthError::MissingCredentials)
        ));
        assert!(matches!(
            gate::<TenantAdmin>(bare2).await,
            Err(AuthError::MissingCredentials)
        ));
    }

    #[test]
    fn both_gates_document_401_and_403() {
        use doxa::DocOperationContribution;
        let super_doc = format!("{:?}", SuperAdmin::contribution());
        let tenant_doc = format!("{:?}", TenantAdmin::contribution());
        for (doc, refusal) in [
            (super_doc, "Caller is not a super admin"),
            (tenant_doc, "Caller is not a tenant admin"),
        ] {
            assert!(doc.contains("\"401\"") && doc.contains("\"403\""), "{doc}");
            assert!(doc.contains(refusal), "{doc}");
        }
    }

    #[tokio::test]
    async fn require_lets_either_tier_past_a_denied_capability() {
        type Read = Require<WidgetsRead>;
        assert!(gate::<Read>(parts(Some("acme"), Mark::Super)).await.is_ok());
        assert!(gate::<Read>(parts(Some("acme"), Mark::Tenant))
            .await
            .is_ok());
        assert!(gate::<Read>(parts(None, Mark::Super)).await.is_ok());
        for (tenant, mark) in [(None, Mark::Tenant), (Some("acme"), Mark::None)] {
            let refused = gate::<Read>(parts(tenant, mark)).await;
            assert!(matches!(refused, Err(AuthError::Forbidden)));
        }
    }
}
