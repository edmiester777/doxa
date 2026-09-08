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

    /// Evaluate `action` against one concrete object, with its
    /// attributes in scope. The instance-level counterpart to
    /// [`check`](Self::check), whose resource ids are constants or the tenant.
    async fn check_instance(
        &self,
        tenant_id: &str,
        roles: &[String],
        action: &str,
        resource: &crate::ResourceEntity,
    ) -> Result<bool, crate::AuthError>;

    /// The same question about several objects at once, in order.
    ///
    /// A request that names its resources in a body names several of them:
    /// a pipeline declaring the models it reads, a document declaring the
    /// folders it links. Asked one at a time that is one entity-set
    /// assembly per object, and the set is the same every time — so an
    /// implementation that can hoist the assembly should override this,
    /// and one that cannot loses nothing by the default.
    ///
    /// Returns one verdict per resource, positionally. Whether a refusal
    /// anywhere refuses the whole request is the caller's to decide; this
    /// only answers.
    ///
    /// The default asks [`check_instance`](Self::check_instance) in turn,
    /// so every existing implementation keeps working and gains the batch
    /// the day it wants to.
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
}

// ---------------------------------------------------------------------------
// The catalog
// ---------------------------------------------------------------------------

#[cfg(feature = "catalog")]
inventory::collect!(&'static Capability);

/// Every capability declared anywhere in the linked binary, sorted by
/// name.
///
/// `#[capability]` registers each declaration as it defines it, so this
/// answers without anyone maintaining a list — which is the point. A
/// hand-written catalog const is a third place the same facts live, and
/// the failure mode of forgetting an entry is silent: the capability
/// works everywhere it is named in code and is simply missing from
/// whatever the client is told it has.
///
/// The usual consumers are a `/me`-style endpoint reporting what the
/// caller holds, and an OAuth2 scope vocabulary. Both want the whole set
/// and neither can name it.
///
/// Ordering is by name rather than by link order, which is unspecified —
/// a published OpenAPI document that reshuffled between builds would be
/// unreadable in review.
///
/// ## What it cannot see
///
/// A crate that is not linked. Capabilities behind a disabled feature, or
/// in a dependency the binary never pulls in, are absent with no error,
/// because there is nothing left to ask. Assert the count in a test if
/// the set matters.
///
/// Requires the `catalog` feature, on by default.
#[cfg(feature = "catalog")]
pub fn capabilities() -> Vec<&'static Capability> {
    let mut all: Vec<&'static Capability> = inventory::iter::<&'static Capability>
        .into_iter()
        .copied()
        .collect();
    all.sort_unstable_by_key(|cap| cap.name);
    all
}

/// The Cedar id a coarse check asks about.
///
/// A coarse gate runs before anything is loaded, so there is no object to
/// name: the id is either a constant the application chose, or the tenant
/// the request is being made in. Those are the only two forms because the
/// tenant is the only identity doxa holds at that point — roles are a
/// list, and whatever sits behind them is the consumer's own session
/// type.
///
/// [`Tenant`](Self::Tenant) is resolved before
/// [`PolicyExtension::build_resource_uid`](crate::extension::PolicyExtension::build_resource_uid)
/// is called, so that hook receives a real id and never a marker to
/// decode. It is the extension point for the *consumer's* UID hierarchy —
/// `{tenant}::{name}` composition, flat namespaces, per-type prefixes —
/// and it keeps all of that. What it no longer has to do is recognize a
/// sentinel doxa invented and substitute a value doxa had already passed
/// it as an argument.
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
    ///
    /// Borrows from whichever side supplied it, so resolving costs
    /// nothing for either form.
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
