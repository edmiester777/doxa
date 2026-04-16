//! Cedar-based authorization policy engine.
//!
//! `doxa-policy` is a framework-neutral, domain-neutral authorization
//! library built on top of Cedar's partial evaluation. It exposes the
//! [`Policy`] trait for resolving user roles into a consumer-defined session
//! output, the [`PolicyExtension`] trait for plugging in domain-specific
//! post-evaluation behavior, the [`PolicyStore`] trait for plugging in any
//! storage backend, and the [`PolicyRouter`] for centralized slow-path
//! enforcement of arbitrary `(action, resource)` pairs.
//!
//! The crate has zero domain-specific assumptions baked in — no hardcoded
//! resource taxonomy, no SQL schema dependency, no HTTP framework
//! dependency. Consumers wire it up to their own storage and resource model
//! via the trait surface.
//!
//! ## Module Overview
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`policy`] | [`Policy`] trait + [`CedarPolicy`](policy::cedar::CedarPolicy) impl |
//! | [`extension`] | [`PolicyExtension`] trait + [`ResourceAccess`] / [`ResourceGrants`](extension::ResourceGrants) |
//! | [`store`] | [`PolicyStore`] trait — pluggable storage backend |
//! | [`router`] | [`PolicyRouter`] — centralized slow-path PEP |
//! | [`error`] | [`AuthError`] enum (no HTTP response mapping) |
//! | [`uid`] | Cedar entity UID builder with input validation |

pub mod capability;
pub mod cedar_core;
pub mod error;
pub mod extension;
pub mod policy;
pub mod router;
pub mod store;
pub mod uid;

#[cfg(feature = "axum")]
pub mod http;

#[cfg(test)]
mod test_support;

pub use capability::{Capability, CapabilityCheck, CapabilityChecker, Capable};
pub use cedar_core::{TenantStoreCache, DEFAULT_TENANT_CACHE_TTL};
pub use error::AuthError;
pub use extension::{PolicyExtension, ResourceAccess};
pub use policy::Policy;
pub use router::{AccessDecision, PolicyRouter};
pub use store::{PolicyStore, SharedPolicyStore};
