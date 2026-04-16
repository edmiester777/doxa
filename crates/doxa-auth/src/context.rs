//! Authenticated caller context injected into request extensions.
//!
//! [`AuthContext`] is injected into axum request extensions by the auth
//! middleware. It carries the caller's resolved claims ([`Claims`]), a
//! domain-specific resolved session of type `S`, and an optional admin
//! flag. Handlers and extractors read this to enforce access control.
//!
//! `AuthContext` is generic over **two** type parameters:
//!
//! - `S` — the resolved session output produced by
//!   [`Policy<S>`](doxa_policy::Policy). Consumers choose whatever session
//!   shape their service needs (a query-engine `SessionConfig`, a rate-limit
//!   token, an OAuth scope set, …). `S = ()` is a reasonable default for
//!   services that don't need a session beyond the identity.
//! - `C` — the consumer-defined claim type implementing [`Claims`]. Deployments
//!   own the full claim vocabulary; the library only reads the trait methods
//!   (`sub`, `scope`, `roles`, `audit_attrs`) and never inspects the concrete
//!   type.

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
    /// Convenience flag mirroring whatever the policy considered to be
    /// "admin" — extensions that don't model admin can leave this `false`.
    pub is_admin: bool,
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

    /// Policy scope, falling back to the literal string `"default"` when
    /// the caller has no scope. Convenience accessor for legacy code
    /// paths that need a non-optional tenant string.
    pub fn company_id(&self) -> &str {
        self.tenant_id().unwrap_or("default")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::OidcClaims;

    fn ctx(roles: Vec<&str>, is_admin: bool, scope: Option<&str>) -> AuthContext<(), OidcClaims> {
        AuthContext {
            claims: OidcClaims {
                sub: "alice".to_string(),
                scope: scope.map(String::from),
                roles: roles.into_iter().map(String::from).collect(),
            },
            session: (),
            is_admin,
        }
    }

    #[test]
    fn accessors_forward_to_claims() {
        let c = ctx(vec!["viewer", "editor"], false, Some("acme"));
        assert_eq!(c.actor_subject(), Some("alice"));
        assert_eq!(c.tenant_id(), Some("acme"));
        assert_eq!(c.roles(), &["viewer".to_string(), "editor".to_string()]);
        assert!(!c.is_admin);
    }

    #[test]
    fn is_admin_flag_is_independent_of_claims() {
        let c = ctx(vec!["root"], true, Some("acme"));
        assert!(c.is_admin);
    }

    #[test]
    fn company_id_falls_back_to_default_when_scope_missing() {
        let c = ctx(vec!["viewer"], false, None);
        assert!(c.tenant_id().is_none());
        assert_eq!(c.company_id(), "default");
    }
}
