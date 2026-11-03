//! `x-doxa` on each operation: what a client generated from the spec needs that OpenAPI can't
//! say, such as the entities a route touches and whether its guard answers a dry run.

use std::marker::PhantomData;

use serde_json::{json, Value};
use utoipa::openapi::extensions::ExtensionsBuilder;
use utoipa::openapi::path::Operation;

/// A route's `x-doxa` value, written by its method macro.
pub trait ClientMeta {
    /// The value, as JSON.
    fn meta() -> Value;
}

/// Put `meta` on `op` as `x-doxa`.
pub fn stamp(op: &mut Operation, meta: Value) {
    let ext = ExtensionsBuilder::new().add("x-doxa", meta).build();
    match op.extensions.as_mut() {
        Some(existing) => existing.merge(ext),
        None => op.extensions = Some(ext),
    }
}

/// What a `#[doxa::spec]` function may return.
pub trait IntoSpec {
    /// The document.
    fn into_spec(self) -> utoipa::openapi::OpenApi;
}

impl IntoSpec for utoipa::openapi::OpenApi {
    fn into_spec(self) -> utoipa::openapi::OpenApi {
        self
    }
}

impl IntoSpec for crate::ApiDoc {
    fn into_spec(self) -> utoipa::openapi::OpenApi {
        std::sync::Arc::unwrap_or_clone(self.openapi)
    }
}

/// Asks which entity type a guard's asset is about, when it says.
pub struct EntityOf<A>(PhantomData<fn() -> A>);

impl<A> EntityOf<A> {
    /// The question.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        EntityOf(PhantomData)
    }
}

/// The asset is `Keyed`.
pub trait EntityKnown {
    /// Its entity type.
    fn entity(&self) -> Option<&'static str>;
}

impl<A: doxa_wire::Keyed> EntityKnown for EntityOf<A> {
    fn entity(&self) -> Option<&'static str> {
        Some(A::ENTITY_TYPE)
    }
}

/// The asset isn't `Keyed`.
pub trait EntityUnknown {
    /// `None`.
    fn entity(&self) -> Option<&'static str> {
        None
    }
}

impl<A> EntityUnknown for &EntityOf<A> {}

/// Asks for a type's schema name, when it has one.
pub struct SchemaOf<T>(PhantomData<fn() -> T>);

impl<T> SchemaOf<T> {
    /// The question.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        SchemaOf(PhantomData)
    }
}

/// `T` has a schema.
pub trait SchemaKnown {
    /// Its name.
    fn name(&self) -> Option<String>;
}

impl<T: utoipa::ToSchema> SchemaKnown for SchemaOf<T> {
    fn name(&self) -> Option<String> {
        Some(T::name().into_owned())
    }
}

/// `T` has none.
pub trait SchemaUnknown {
    /// `None`.
    fn name(&self) -> Option<String> {
        None
    }
}

impl<T> SchemaUnknown for &SchemaOf<T> {}

/// Asks whether `T` is an entity the client cache stores by identity.
pub struct IdentityOf<T>(PhantomData<fn() -> T>);

impl<T> IdentityOf<T> {
    /// The question.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        IdentityOf(PhantomData)
    }
}

/// `T` is an entity: its schema, entity type, id field and key.
pub trait IdentityKnown {
    /// The description, as JSON.
    fn describe(&self) -> Value;
}

impl<T: doxa_wire::Identity + utoipa::ToSchema> IdentityKnown for IdentityOf<T> {
    fn describe(&self) -> Value {
        json!({
            "schema": T::name(),
            "entity": T::ENTITY_TYPE,
            "id": T::ID_FIELD,
            "key": T::KEY_TYPE.map(|ty| json!({ "type": ty, "fields": T::KEY_FIELDS })),
        })
    }
}

/// `T` is not an entity.
pub trait IdentityUnknown {
    /// `null`.
    fn describe(&self) -> Value {
        Value::Null
    }
}

impl<T> IdentityUnknown for &IdentityOf<T> {}
