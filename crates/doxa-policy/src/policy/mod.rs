//! Authorization policy resolution.
//!
//! The [`Policy`] trait maps a tenant context (`tenant_id`) and role list
//! into a session output of type `T` that governs access control. The output
//! type is determined by the
//! [`PolicyExtension`](crate::extension::PolicyExtension) used with the Cedar
//! implementation.
//!
//! Implementations:
//! - [`cedar::CedarPolicy`] — Cedar-based resolution with tenant-scoped roles
//!   and pluggable post-evaluation via
//!   [`PolicyExtension`](crate::extension::PolicyExtension)

pub mod cedar;

use async_trait::async_trait;

use crate::error::AuthError;

/// Resolve role names into a session output of type `T`.
///
/// Accepts an optional `tenant_id` (from the caller's identity context)
/// and the user's role names. Implementations map these to authorization
/// policies and produce a session output that downstream middleware uses
/// for access control.
///
/// The type parameter `T` is the session output type — determined by the
/// [`PolicyExtension`](crate::extension::PolicyExtension) in use. For
/// example, a query-engine consumer might produce a `SessionConfig`-style
/// struct holding allowed-resource sets and forced filters; an API gateway
/// consumer might produce a rate-limit token; a feature-flag service might
/// produce a `HashMap<String, bool>` of feature toggles.
#[async_trait]
pub trait Policy<T: Send + Sync>: Send + Sync {
    /// Resolve the given tenant and roles into a session output.
    async fn resolve(&self, tenant_id: Option<&str>, roles: &[String]) -> Result<T, AuthError>;

    /// Flush all cached authorization state. Called by the admin cache-flush
    /// endpoint for emergency policy revocation. Default is a no-op for
    /// implementations without caching.
    async fn flush_cache(&self) {}

    /// Invalidate cached authorization state for a single tenant after a
    /// CRUD mutation on that tenant's policies or entities. Pass `None` for
    /// system-wide changes (flushes everything since all tenants are affected).
    /// Default is a no-op for implementations without caching.
    async fn invalidate_tenant(&self, _tenant_id: Option<&str>) {}
}
