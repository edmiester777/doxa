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
//! | [`resource`] | [`PolicyResource`] — instance-level resource identity |
//! | `scoped` | `ScopedRow` — SeaORM lookup confined to an owner (needs `sea-orm`; not linked, as the module is absent without it) |

pub mod capability;
pub mod cedar_core;
pub mod error;
pub mod extension;
pub mod policy;
pub mod resource;
pub mod router;
pub mod store;
pub mod uid;

#[cfg(feature = "axum")]
pub mod http;

#[cfg(feature = "sea-orm")]
pub mod scoped;

#[cfg(test)]
mod test_support;

/// Re-exported so `#[capability]`'s output can register itself without
/// the declaring crate taking a direct dependency on `inventory`.
#[cfg(feature = "catalog")]
#[doc(hidden)]
pub use inventory;

/// Stand-in for the above when the `catalog` feature is off, so
/// `#[capability]` expands to the same tokens either way and the
/// registration simply evaporates.
#[cfg(not(feature = "catalog"))]
#[doc(hidden)]
pub mod inventory {
    #[doc(hidden)]
    pub use crate::__doxa_capability_submit as submit;
}

#[cfg(not(feature = "catalog"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __doxa_capability_submit {
    ($($tt:tt)*) => {};
}

#[cfg(feature = "catalog")]
pub use capability::capabilities;
pub use capability::{Capability, CapabilityCheck, CapabilityChecker, Capable, ResourceId};
pub use cedar_core::{TenantStoreCache, DEFAULT_TENANT_CACHE_CAPACITY, DEFAULT_TENANT_CACHE_TTL};
pub use error::AuthError;
pub use extension::{PolicyExtension, ResourceAccess};
pub use policy::Policy;
pub use resource::{PolicyResource, ResourceEntity, ResourceIdType};
pub use router::{AccessDecision, PolicyRouter};
#[cfg(feature = "sea-orm")]
pub use scoped::ScopedRow;
pub use store::{PolicyStore, SharedPolicyStore};

/// Re-exported so `#[derive(PolicyResource)]`'s generated [`ScopedRow`]
/// impl can name SeaORM's traits without assuming the deriving crate
/// spells the dependency `sea_orm`.
#[cfg(feature = "sea-orm")]
#[doc(hidden)]
pub mod __private {
    pub use sea_orm;
}
