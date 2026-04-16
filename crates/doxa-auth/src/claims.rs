//! Consumer-defined claim types.
//!
//! The auth pipeline is generic over a consumer-supplied claim type `C`
//! that implements the [`Claims`] trait. The library forwards `C` from the
//! validator through the resolver, policy engine, and request extensions
//! without ever reading domain-specific fields — every deployment decides
//! what its claim shape looks like.
//!
//! Most consumers define their own struct (e.g. `MyClaims { sub, tenant,
//! roles, department, is_admin, ... }`) and implement [`Claims`] on it. The
//! stock [`OidcClaims`] type in this module is a quick-start default that
//! covers the three universally meaningful fields — `sub`, `scope`, and
//! `roles` — and is sufficient for deployments whose IdP produces a
//! standard OIDC claim triple.

use serde::{Deserialize, Serialize};

/// Minimal contract the auth pipeline needs from a consumer-defined claim
/// type.
///
/// The library uses these methods to:
///
/// - pass `scope` + `roles` into the [`Policy`](doxa_policy::Policy)
///   evaluation stage,
/// - record `sub` + `roles` + optional `audit_attrs` on audit events emitted by
///   the middleware, and
/// - expose convenience accessors on
///   [`AuthContext`](crate::context::AuthContext) that handlers can call
///   without downcasting to the concrete claim type.
///
/// Handlers that need richer fields (e.g. `department`, `is_admin`) read
/// [`AuthContext::claims`](crate::context::AuthContext::claims) directly
/// and operate on the concrete `C` type — the library never hides those
/// fields behind a trait method.
pub trait Claims: Clone + Send + Sync + 'static {
    /// Stable subject identifier for the principal. Used as the actor id
    /// in audit events and — when the consumer opts in — as the Cedar
    /// principal entity's UID.
    fn sub(&self) -> &str;

    /// Roles / groups asserted on the principal. Passed directly to the
    /// [`Policy`](doxa_policy::Policy) evaluator. An empty slice is
    /// valid.
    fn roles(&self) -> &[String];

    /// Policy partition key. The library forwards this into
    /// [`Policy::resolve`](doxa_policy::Policy::resolve) as the
    /// `scope` parameter. Deployments that evaluate one global policy set
    /// should return `None`; multi-tenant deployments return whichever
    /// field represents the tenancy boundary (tenant id, organization id,
    /// workspace id, …).
    fn scope(&self) -> Option<&str> {
        None
    }

    /// Attributes to record on audit events alongside the actor's `sub`
    /// and `roles`. The default is [`Value::Null`](serde_json::Value::Null)
    /// — consumers that want richer audit attribution override this to
    /// return a JSON map of whatever fields their claim type exposes.
    ///
    /// Returning [`Value::Null`](serde_json::Value::Null) means the audit
    /// event's `actor_attrs` column is left empty.
    fn audit_attrs(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
}

/// Quick-start OIDC claim type.
///
/// Covers the three fields that every OIDC-style auth deployment needs
/// — `sub`, a tenant / organization identifier, and a role list. Useful
/// as a starting point for deployments whose IdP produces a standard OIDC
/// claim triple and who don't need to carry additional attributes into
/// policy evaluation.
///
/// Consumers with richer needs should define their own struct and
/// implement [`Claims`] directly — `OidcClaims` is intentionally
/// minimal.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OidcClaims {
    /// Stable subject identifier for the principal (e.g. the IdP user id).
    pub sub: String,
    /// Optional tenant / organization / workspace identifier used as the
    /// policy partition key.
    #[serde(default)]
    pub scope: Option<String>,
    /// Roles / groups asserted on the principal.
    #[serde(default)]
    pub roles: Vec<String>,
}

impl Claims for OidcClaims {
    fn sub(&self) -> &str {
        &self.sub
    }

    fn roles(&self) -> &[String] {
        &self.roles
    }

    fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_claims_default_has_empty_fields() {
        let c = OidcClaims::default();
        assert_eq!(c.sub(), "");
        assert!(c.scope().is_none());
        assert!(c.roles().is_empty());
        assert!(c.audit_attrs().is_null());
    }

    #[test]
    fn oidc_claims_exposes_scope_and_roles() {
        let c = OidcClaims {
            sub: "alice".into(),
            scope: Some("acme".into()),
            roles: vec!["viewer".into(), "editor".into()],
        };
        assert_eq!(c.sub(), "alice");
        assert_eq!(c.scope(), Some("acme"));
        assert_eq!(c.roles(), &["viewer".to_string(), "editor".to_string()][..]);
    }
}
