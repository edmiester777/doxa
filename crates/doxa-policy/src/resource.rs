//! Instance-level resource identity.
//!
//! [`Capability`](crate::Capability) checks name a resource with a
//! `&'static str` id, which can only describe a collection or a
//! singleton. A [`PolicyResource`] names one concrete object, so a
//! policy can be evaluated against the row the request actually
//! touches — and the same [`ENTITY_TYPE`](PolicyResource::ENTITY_TYPE)
//! becomes the audit trail's `resource_type`, joining the audit row to
//! the decision that produced it.

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

    /// How the id appears in the OpenAPI path parameter.
    const ID_TYPE: ResourceIdType = ResourceIdType::String;

    /// Type this resource's id parses from in a URL path segment.
    type Id: std::str::FromStr + Send;

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
    pub fn of<R: PolicyResource>(resource: &R) -> Self {
        Self {
            entity_type: R::ENTITY_TYPE.to_owned(),
            entity_id: resource.resource_id(),
            attrs: resource.cedar_attrs(),
            parents: resource
                .cedar_parents()
                .into_iter()
                .map(|(ty, id)| (ty.to_owned(), id))
                .collect(),
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
