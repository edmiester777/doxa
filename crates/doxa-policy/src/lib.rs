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
//! | [`session`] | [`SessionChecker`] — the router bound to one caller's session |
//! | [`error`] | [`AuthError`] enum (no HTTP response mapping) |
//! | [`uid`] | Cedar entity UID builder with input validation |
//! | [`resource`] | [`PolicyResource`] — instance-level resource identity |
//! | [`fetch`] | [`Fetch`] / [`FetchByKey`] / [`FetchById`] / [`FetchSubset`] / [`Lookup`] — backend-neutral scoped lookups |
//! | `scoped` | `ScopedTable` / `ScopedRow` / `DbLoadError` — SeaORM loaders (needs `sea-orm`) |
//! | `residual` | `condition_from_residual` — a residual as a SeaORM `Condition` (needs `sea-orm`) |

pub mod capability;
pub mod cedar_core;
pub mod error;
pub mod extension;
pub mod fetch;
pub mod policy;
pub mod resource;
pub mod router;
pub mod session;
pub mod store;
pub mod uid;

#[cfg(feature = "axum")]
pub mod http;

#[cfg(feature = "sea-orm")]
pub mod residual;

#[cfg(feature = "sea-orm")]
pub mod scoped;

#[cfg(test)]
mod test_support;

/// Re-exported so `#[capability]`'s output can register itself without
/// the declaring crate taking a direct dependency on `inventory`.
#[cfg(feature = "catalog")]
#[doc(hidden)]
pub use inventory;

/// Without `catalog`, `#[capability]`'s registration expands to nothing.
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
pub use fetch::{Fetch, FetchById, FetchByKey, FetchSubset, Lookup};
pub use policy::Policy;
#[cfg(feature = "sea-orm")]
pub use residual::condition_from_residual;
pub use resource::{PolicyResource, ResourceEntity, ResourceIdType};
pub use router::{AccessDecision, PolicyRouter};
#[cfg(feature = "sea-orm")]
pub use scoped::{DbLoadError, PrimaryKeyOf, ScopedRow, ScopedTable};
pub use session::SessionChecker;
pub use store::{PolicyStore, SharedPolicyStore};

/// For derived impls, whatever the deriving crate calls its SeaORM dependency.
#[cfg(feature = "sea-orm")]
#[doc(hidden)]
pub mod __private {
    pub use sea_orm;
}
