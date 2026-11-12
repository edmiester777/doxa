//! Instance-level resource identity: a [`PolicyResource`] names one concrete object, and its
//! [`ENTITY_TYPE`](PolicyResource::ENTITY_TYPE) is also the audit trail's `resource_type`.

use serde_json::{Map, Value};

/// Primitive an id serializes as in OpenAPI; the doc layer maps it to a schema.
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

    /// The entity type this instance is `in` by virtue of the request's tenant, not a column.
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

/// One instance injected into the request's Cedar entity set, so `resource.<attr>` resolves.
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

    /// Describe a loaded [`PolicyResource`]; `tenant_id` becomes its `TENANT_PARENT` unless empty.
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

    /// A row that records its own parent and belongs to a tenant.
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

    #[test]
    fn a_row_with_no_parent_of_its_own_still_has_the_tenant() {
        let entity = ResourceEntity::of(&report(None), "acme");

        assert_eq!(entity.parents, [("Tenant".to_owned(), "acme".to_owned())]);
    }

    /// `Tenant::""` would be a real entity no policy means to match.
    #[test]
    fn an_empty_tenant_adds_nothing() {
        let entity = ResourceEntity::of(&report(None), "");

        assert!(entity.parents.is_empty());
    }

    /// Off by default.
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
