//! Instance-level resource identity.
//!
//! [`Capability`](crate::Capability) checks name a resource with a
//! [`ResourceId`](crate::ResourceId), which can only describe a
//! collection, a singleton or the tenant. A [`PolicyResource`] names one
//! concrete object, so a policy can be evaluated against the row the
//! request actually touches — and the same
//! [`ENTITY_TYPE`](PolicyResource::ENTITY_TYPE) becomes the audit trail's
//! `resource_type`, joining the audit row to the decision that produced
//! it.
//!
//! Identity is not entirely intrinsic to the object, though, which is why
//! [`ResourceEntity::of`] takes the tenant: see
//! [`TENANT_PARENT`](PolicyResource::TENANT_PARENT).

use serde_json::{Map, Value};

/// Primitive an id serializes as in OpenAPI.
///
/// Named rather than expressed as a `utoipa` schema so this crate stays
/// framework-neutral; the doc layer maps it to a real schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceIdType {
    /// `type: string`.
    String,
    /// `type: integer, format: int64`.
    Integer,
    /// `type: string, format: uuid`.
    Uuid,
}

/// A domain type Cedar can authorize by instance.
///
/// [`ENTITY_TYPE`](Self::ENTITY_TYPE) doubles as the audit
/// `resource_type`, so both sides of a decision use one string.
pub trait PolicyResource: Send + Sync + Sized + 'static {
    /// Cedar entity type (e.g. `"Widget"`).
    const ENTITY_TYPE: &'static str;

    /// Cedar entity type this instance is `in` by virtue of the *request*
    /// rather than of any column, if any.
    ///
    /// [`cedar_parents`](Self::cedar_parents) reads parents off the
    /// object, which is right for a parent the row records — a folder id,
    /// an owner. It cannot express the tenant. A request is made *in* a
    /// tenant, and a row belonging to no tenant at all is still decided
    /// about inside the asking one, so there may be no column to read and
    /// a nullable one would not answer the question anyway.
    ///
    /// Naming the type here lets doxa supply that parent from the
    /// request, where it is known:
    ///
    /// ```
    /// # use doxa_policy::{PolicyResource, ResourceEntity};
    /// # struct Rule;
    /// impl PolicyResource for Rule {
    ///     const ENTITY_TYPE: &'static str = "Rule";
    ///     const TENANT_PARENT: Option<&'static str> = Some("Tenant");
    ///     fn resource_id(&self) -> String { "nightly".to_owned() }
    /// }
    ///
    /// let entity = ResourceEntity::of(&Rule, "acme");
    /// assert_eq!(entity.parents, [("Tenant".to_owned(), "acme".to_owned())]);
    /// ```
    const TENANT_PARENT: Option<&'static str> = None;

    /// This instance's id, as Cedar and the audit trail see it.
    fn resource_id(&self) -> String;

    /// Attributes a policy may reference as `resource.<name>`. Empty by
    /// default — a policy with no `when` clause needs none.
    fn cedar_attrs(&self) -> Map<String, Value> {
        Map::new()
    }

    /// `(entity_type, id)` pairs this instance is `in`, for hierarchy
    /// checks like `resource in Folder::"reports"`.
    fn cedar_parents(&self) -> Vec<(&'static str, String)> {
        Vec::new()
    }
}

/// One instance injected into the request-scoped Cedar entity set.
///
/// The evaluator builds its entity set per request, so adding an object
/// the policy store does not hold costs one more JSON value. Without
/// it, a `when { resource.owner == … }` clause has nothing to
/// dereference and survives partial evaluation as a residual — which
/// [`check_action`](crate::PolicyRouter::check_instance) reads as a
/// denial.
#[derive(Debug, Clone)]
pub struct ResourceEntity {
    /// Cedar entity type.
    pub entity_type: String,
    /// Cedar entity id, before the extension maps it into its UID space.
    pub entity_id: String,
    /// Attributes exposed to policies as `resource.<name>`.
    pub attrs: Map<String, Value>,
    /// `(entity_type, id)` parents for `in` checks.
    pub parents: Vec<(String, String)>,
}

impl ResourceEntity {
    /// An entity with no attributes and no parents.
    pub fn new(entity_type: impl Into<String>, entity_id: impl Into<String>) -> Self {
        Self {
            entity_type: entity_type.into(),
            entity_id: entity_id.into(),
            attrs: Map::new(),
            parents: Vec::new(),
        }
    }

    /// Describe a loaded [`PolicyResource`], attributes and parents
    /// included.
    ///
    /// The tenant is a parameter because half of a resource's Cedar
    /// identity comes from the request rather than from the row — see
    /// [`PolicyResource::TENANT_PARENT`], which is what consumes it. An
    /// empty tenant adds no parent: there is no tenant to be `in`.
    pub fn of<R: PolicyResource>(resource: &R, tenant_id: &str) -> Self {
        let mut parents: Vec<(String, String)> = resource
            .cedar_parents()
            .into_iter()
            .map(|(ty, id)| (ty.to_owned(), id))
            .collect();

        if let Some(ty) = R::TENANT_PARENT {
            if !tenant_id.is_empty() {
                parents.push((ty.to_owned(), tenant_id.to_owned()));
            }
        }

        Self {
            entity_type: R::ENTITY_TYPE.to_owned(),
            entity_id: resource.resource_id(),
            attrs: resource.cedar_attrs(),
            parents,
        }
    }

    /// Replace the attributes exposed to policies.
    pub fn with_attrs(mut self, attrs: Map<String, Value>) -> Self {
        self.attrs = attrs;
        self
    }

    /// Replace the parent list.
    pub fn with_parents(mut self, parents: Vec<(String, String)>) -> Self {
        self.parents = parents;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A row that records its own parent *and* belongs to a tenant. The
    /// two are different kinds of fact, which is the whole reason one is
    /// a method and the other a const.
    struct Report {
        folder: Option<String>,
    }

    impl PolicyResource for Report {
        const ENTITY_TYPE: &'static str = "Report";
        const TENANT_PARENT: Option<&'static str> = Some("Tenant");

        fn resource_id(&self) -> String {
            "q3".to_owned()
        }

        fn cedar_parents(&self) -> Vec<(&'static str, String)> {
            self.folder
                .iter()
                .map(|folder| ("Folder", folder.clone()))
                .collect()
        }
    }

    fn report(folder: Option<&str>) -> Report {
        Report {
            folder: folder.map(str::to_owned),
        }
    }

    #[test]
    fn the_tenant_joins_the_parents_the_row_records() {
        let entity = ResourceEntity::of(&report(Some("finance")), "acme");

        assert_eq!(
            entity.parents,
            [
                ("Folder".to_owned(), "finance".to_owned()),
                ("Tenant".to_owned(), "acme".to_owned()),
            ],
        );
    }

    /// The case the column could not express. A row with no parent of its
    /// own is still decided about inside the asking tenant, so the
    /// hierarchy check has something to resolve against — where a
    /// nullable `parent` column would have contributed nothing.
    #[test]
    fn a_row_with_no_parent_of_its_own_still_has_the_tenant() {
        let entity = ResourceEntity::of(&report(None), "acme");

        assert_eq!(entity.parents, [("Tenant".to_owned(), "acme".to_owned())]);
    }

    /// No tenant, no parent. An unscoped caller is not `in` the empty
    /// tenant, and naming `Tenant::""` would be a real entity that no
    /// policy means to match.
    #[test]
    fn an_empty_tenant_adds_nothing() {
        let entity = ResourceEntity::of(&report(None), "");

        assert!(entity.parents.is_empty());
    }

    /// The default is off: an asset that says nothing gets the behaviour
    /// it had before there was anything to say.
    #[test]
    fn an_asset_that_declares_no_tenant_parent_is_unchanged() {
        struct Loose;
        impl PolicyResource for Loose {
            const ENTITY_TYPE: &'static str = "Loose";
            fn resource_id(&self) -> String {
                "x".to_owned()
            }
        }

        assert!(ResourceEntity::of(&Loose, "acme").parents.is_empty());
    }
}
