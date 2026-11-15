//! [`AuthContext`]: the caller's claims `C` and the session `S` their
//! [`Policy<S>`](doxa_policy::Policy) resolved, put in request extensions by the auth middleware.

use crate::claims::Claims;

/// Authenticated user context attached to request extensions.
///
/// Generic over the session output type `S` produced by the configured
/// [`Policy<S>`](doxa_policy::Policy) and the consumer's concrete
/// claim type `C: `[`Claims`]. Handlers that need richer claim fields read
/// [`AuthContext::claims`] directly.
#[derive(Debug, Clone)]
pub struct AuthContext<S, C: Claims> {
    /// Resolved claims returned by the configured
    /// [`ClaimResolver`](crate::provider::ClaimResolver).
    pub claims: C,
    /// Resolved session output produced by the
    /// [`Policy<S>`](doxa_policy::Policy) implementation. Holds
    /// whatever per-request authorization state the consumer's extension
    /// produces.
    pub session: S,
}

/// Type-erased capability-check context inserted into request extensions
/// alongside the typed [`AuthContext<S, C>`].
///
/// [`AuthLayer`](crate::AuthLayer) populates this whenever it runs, so
/// extractors that need tenant + roles but must not be generic over
/// `S`/`C` (notably the ship-ready `Require<M>` capability gate) can
/// reach the values through a single concrete key.
#[derive(Debug, Clone)]
pub struct CapabilityContext {
    /// Tenant / scope identifier, as exposed by [`Claims::scope`].
    pub tenant_id: Option<String>,
    /// Roles asserted for the caller.
    pub roles: Vec<String>,
}

/// Every guard allows it, any tenant or none; loaders stay tenant-confined and listings widen
/// only through `Scoping::unscoped`. Set by the app's layer inside `AuthLayer`.
///
/// ```ignore
/// async fn admins(mut req: Request, next: Next) -> Response {
///     match role_of(&req) {
///         Some("sysadmin") => { req.extensions_mut().insert(doxa::auth::SuperAdmin); }
///         Some("tadmin") => { req.extensions_mut().insert(doxa::auth::TenantAdmin); }
///         _ => {}
///     }
///     next.run(req).await
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuperAdmin;

/// Marks the caller unrestricted within their own tenant: Cedar is never asked, but tenant and
/// owner confinement still apply, and a caller with no tenant is refused. Set as [`SuperAdmin`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantAdmin;

/// `Claims::scope`'s contract: no scope refuses every check, except for a super admin.
pub(crate) fn unscoped(tenant: Option<&str>, extensions: &http::Extensions) -> bool {
    tenant.is_none() && extensions.get::<SuperAdmin>().is_none()
}

impl<S, C: Claims> AuthContext<S, C> {
    /// Returns the JWT `sub` claim for the authenticated user.
    pub fn actor_subject(&self) -> Option<&str> {
        Some(self.claims.sub())
    }

    /// Roles asserted for the caller.
    pub fn roles(&self) -> &[String] {
        self.claims.roles()
    }

    /// Policy scope (tenant / organization / workspace identifier) for
    /// the caller. `None` for unscoped deployments or when the consumer's
    /// claim type does not populate a scope.
    pub fn tenant_id(&self) -> Option<&str> {
        self.claims.scope()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::OidcClaims;

    fn ctx(roles: Vec<&str>, scope: Option<&str>) -> AuthContext<(), OidcClaims> {
        AuthContext {
            claims: OidcClaims {
                sub: "alice".to_string(),
                scope: scope.map(String::from),
                roles: roles.into_iter().map(String::from).collect(),
            },
            session: (),
        }
    }

    #[test]
    fn accessors_forward_to_claims() {
        let c = ctx(vec!["viewer", "editor"], Some("acme"));
        assert_eq!(c.actor_subject(), Some("alice"));
        assert_eq!(c.tenant_id(), Some("acme"));
        assert_eq!(c.roles(), &["viewer".to_string(), "editor".to_string()]);
    }

    #[test]
    fn a_caller_without_a_scope_has_no_tenant() {
        let c = ctx(vec!["viewer"], None);
        assert!(c.tenant_id().is_none());
    }

    #[test]
    fn only_a_super_admin_waives_the_scope() {
        let mut extensions = http::Extensions::new();
        assert!(unscoped(None, &extensions));
        assert!(!unscoped(Some("acme"), &extensions));
        extensions.insert(TenantAdmin);
        assert!(unscoped(None, &extensions), "a tenant admin needs a tenant");
        extensions.insert(SuperAdmin);
        assert!(!unscoped(None, &extensions));
    }
}
