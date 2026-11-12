//! Named capability primitive for grouping `(action, resource)` policy
//! checks under a stable, client-facing identifier.
//!
//! A [`Capability`] is a static bundle of one or more [`CapabilityCheck`]
//! pairs. All checks must pass for the capability to be granted. The
//! [`PolicyRouter`](crate::router::PolicyRouter) gains
//! [`check_capability`](crate::router::PolicyRouter::check_capability) and
//! [`evaluate_capabilities`](crate::router::PolicyRouter::evaluate_capabilities)
//! so consumers can answer "can this caller do X?" without composing raw
//! action/resource pairs themselves — the router delegates Cedar UID
//! construction to
//! [`PolicyExtension::build_resource_uid`](crate::extension::PolicyExtension::build_resource_uid),
//! so each consumer's existing UID hierarchy is honored.
//!
//! The [`Capable`] trait and [`CapabilityChecker`] trait below are the
//! building blocks that let `doxa-auth` ship a reusable `Require<M>`
//! axum extractor without needing to know the consumer's extension type.
//!
//! Capabilities are intentionally `'static` so they can be defined as
//! `const` items in a per-consumer catalog module and shared across the
//! codebase without allocation or lifetime gymnastics.
//!
//! # Example
//!
//! ```ignore
//! use doxa_policy::capability::{Capability, CapabilityCheck, ResourceId};
//!
//! pub const ADMIN_SETTINGS: Capability = Capability {
//!     name: "admin_settings",
//!     description: "Manage application settings",
//!     checks: &[CapabilityCheck {
//!         action: "admin_write",
//!         entity_type: "AdminConfig",
//!         entity_id: ResourceId::Literal("singleton"),
//!     }],
//! };
//! ```

/// Stable client-facing capability bundling one or more [`CapabilityCheck`]
/// pairs. All checks must pass for the capability to be granted.
#[derive(Debug, Clone, Copy)]
pub struct Capability {
    /// Stable client-facing identifier (e.g. `"models.read"`). Used as
    /// the lookup key in `/me`-style responses.
    pub name: &'static str,
    /// Human-readable description for documentation and audit logs.
    pub description: &'static str,
    /// All checks must be `Allow` for the capability to be granted.
    pub checks: &'static [CapabilityCheck],
}

/// Zero-sized marker type bound to a [`Capability`] constant.
///
/// Implementors pair a type with a capability so extractors and other
/// type-level machinery (for example `doxa_auth::Require<M>`) can carry
/// the capability through generics without runtime lookups. The
/// associated [`CAPABILITY`](Self::CAPABILITY) const is resolved at
/// compile time; there is no allocation and no dynamic dispatch.
///
/// Consumers normally implement this by hand or via a proc macro such
/// as `#[doxa_macros::capability(...)]`.
///
/// # Example
///
/// ```
/// use doxa_policy::capability::{Capability, CapabilityCheck, Capable, ResourceId};
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
/// ```
pub trait Capable: Send + Sync + 'static {
    /// The capability this marker type represents.
    const CAPABILITY: &'static Capability;
}

/// Type-erased capability-check abstraction.
///
/// [`PolicyRouter`](crate::router::PolicyRouter) implements this via a
/// blanket impl so any router can be carried through axum request
/// extensions as `Arc<dyn CapabilityChecker>` without exposing the
/// consumer's [`PolicyExtension`](crate::extension::PolicyExtension)
/// type parameter. This is what lets the ship-ready
/// `doxa_auth::Require<M>` extractor call into the router without
/// being generic over the extension.
#[async_trait::async_trait]
pub trait CapabilityChecker: Send + Sync {
    /// Evaluate `cap` against the given tenant + roles and return
    /// `Ok(true)` if every underlying [`CapabilityCheck`] is allowed.
    async fn check(
        &self,
        tenant_id: &str,
        roles: &[String],
        cap: &Capability,
    ) -> Result<bool, crate::AuthError>;

    /// Evaluate `action` against one concrete object, with its attributes in scope.
    async fn check_instance(
        &self,
        tenant_id: &str,
        roles: &[String],
        action: &str,
        resource: &crate::ResourceEntity,
    ) -> Result<bool, crate::AuthError>;

    /// [`check_instance`](Self::check_instance) for each resource, in order; override to build
    /// the entity set once.
    async fn check_instance_many(
        &self,
        tenant_id: &str,
        roles: &[String],
        action: &str,
        resources: &[crate::ResourceEntity],
    ) -> Result<Vec<bool>, crate::AuthError> {
        let mut out = Vec::with_capacity(resources.len());
        for resource in resources {
            out.push(
                self.check_instance(tenant_id, roles, action, resource)
                    .await?,
            );
        }
        Ok(out)
    }

    /// [`check`](Self::check) for each of `caps`, in order; override to share one evaluation.
    async fn check_capabilities(
        &self,
        tenant_id: &str,
        roles: &[String],
        caps: &[&Capability],
    ) -> Result<Vec<bool>, crate::AuthError> {
        let mut out = Vec::with_capacity(caps.len());
        for cap in caps {
            out.push(self.check(tenant_id, roles, cap).await?);
        }
        Ok(out)
    }
}

#[cfg(feature = "catalog")]
inventory::collect!(&'static Capability);

/// Every capability `#[capability]` declared in the linked binary, sorted by name. A crate that
/// isn't linked is silently absent.
#[cfg(feature = "catalog")]
pub fn capabilities() -> Vec<&'static Capability> {
    let mut all: Vec<&'static Capability> = inventory::iter::<&'static Capability>
        .into_iter()
        .copied()
        .collect();
    all.sort_unstable_by_key(|cap| cap.name);
    all
}

/// The Cedar id a coarse check asks about. [`Tenant`](Self::Tenant) is resolved before
/// [`build_resource_uid`](crate::extension::PolicyExtension::build_resource_uid) sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceId {
    /// A fixed id: `"collection"` for a whole collection, `"singleton"`
    /// for a resource there is only one of.
    Literal(&'static str),
    /// The tenant the request is being made in, substituted by doxa.
    Tenant,
}

impl ResourceId {
    /// The id as the policy engine should see it.
    pub const fn resolve<'a>(&'a self, tenant_id: &'a str) -> &'a str {
        match self {
            ResourceId::Literal(id) => id,
            ResourceId::Tenant => tenant_id,
        }
    }
}

/// One `(action, entity_type, entity_id)` triple inside a [`Capability`].
///
/// `entity_type` and the resolved `entity_id` are passed to the consumer's
/// [`PolicyExtension::build_resource_uid`](crate::extension::PolicyExtension::build_resource_uid),
/// so the same UID hierarchy used by every other policy check applies.
#[derive(Debug, Clone, Copy)]
pub struct CapabilityCheck {
    /// Cedar action name (e.g. `"admin_write"`).
    pub action: &'static str,
    /// Cedar entity type (e.g. `"AdminConfig"`).
    pub entity_type: &'static str,
    /// Cedar entity id — a constant, or the request's tenant.
    pub entity_id: ResourceId,
}
