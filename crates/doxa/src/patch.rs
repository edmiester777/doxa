//! Partial updates: a `#[derive(Patch)]` DTO writes the `#[derive(PatchTarget)]` columns its
//! fields name, each checked at compile time against the column's type.

/// A partial update a DTO applies to an `ActiveModel`.
pub trait Patch<A> {
    /// Writes each sent field; a value equal to the loaded row's stays unchanged.
    fn apply(&self, active: &mut A);
}

/// One patchable column of an `ActiveModel`, keyed by its field name spelled as a type.
#[diagnostic::on_unimplemented(
    message = "`{Self}` has no patchable column for this DTO field",
    note = "rename it with `#[patch(column = \"…\")]`, or `#[patch(skip)]` it and set it in the handler"
)]
pub trait Field<Name> {
    /// The column's Rust type.
    type Value;
    /// Sets the column, unless it already holds `value`.
    fn set(&mut self, value: Self::Value);
}

/// A column that holds NULL: what a `Nullable<T>` field may write.
#[diagnostic::on_unimplemented(
    message = "a `Nullable` field needs a nullable column, but this one is `{Self}`"
)]
pub trait NullableColumn {
    /// The value a non-null column holds.
    type Inner;
    /// NULL.
    fn null() -> Self;
    /// A value.
    fn value(v: Self::Inner) -> Self;
}

impl<U> NullableColumn for Option<U> {
    type Inner = U;

    fn null() -> Self {
        None
    }

    fn value(v: U) -> Self {
        Some(v)
    }
}

/// One character of a field name in a [`Field`] key.
#[doc(hidden)]
pub struct Ch<const C: char>;

/// A DTO field compiles only against a column of a type it converts into:
///
/// ```
/// # use doxa::{Nullable, Patch, PatchTarget};
/// # use sea_orm::entity::prelude::*;
/// # #[derive(Clone, Debug, PartialEq, DeriveEntityModel, PatchTarget)]
/// # #[sea_orm(table_name = "orders")]
/// # pub struct Model { #[sea_orm(primary_key)] pub id: i32, pub quantity: i32, pub name: String, pub note: Option<String> }
/// # #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)] pub enum Relation {}
/// # impl ActiveModelBehavior for ActiveModel {}
/// # fn check<P: Patch<ActiveModel>>() {}
/// #[derive(serde::Deserialize, Patch)]
/// pub struct UpdateOrder {
///     pub quantity: Option<i32>,
///     #[serde(default)]
///     pub note: Nullable<String>,
///     #[patch(skip)]
///     pub reason: String,
/// }
/// fn main() { check::<UpdateOrder>() }
/// ```
///
/// No such column:
///
/// ```compile_fail
/// # use doxa::{Patch, PatchTarget};
/// # use sea_orm::entity::prelude::*;
/// # #[derive(Clone, Debug, PartialEq, DeriveEntityModel, PatchTarget)]
/// # #[sea_orm(table_name = "orders")]
/// # pub struct Model { #[sea_orm(primary_key)] pub id: i32, pub quantity: i32 }
/// # #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)] pub enum Relation {}
/// # impl ActiveModelBehavior for ActiveModel {}
/// # fn check<P: Patch<ActiveModel>>() {}
/// #[derive(Patch)]
/// pub struct UpdateOrder { pub missing: Option<i32> }
/// fn main() { check::<UpdateOrder>() }
/// ```
///
/// The primary key:
///
/// ```compile_fail
/// # use doxa::{Patch, PatchTarget};
/// # use sea_orm::entity::prelude::*;
/// # #[derive(Clone, Debug, PartialEq, DeriveEntityModel, PatchTarget)]
/// # #[sea_orm(table_name = "orders")]
/// # pub struct Model { #[sea_orm(primary_key)] pub id: i32, pub quantity: i32 }
/// # #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)] pub enum Relation {}
/// # impl ActiveModelBehavior for ActiveModel {}
/// # fn check<P: Patch<ActiveModel>>() {}
/// #[derive(Patch)]
/// pub struct UpdateOrder { pub id: Option<i32> }
/// fn main() { check::<UpdateOrder>() }
/// ```
///
/// A type that doesn't convert:
///
/// ```compile_fail
/// # use doxa::{Patch, PatchTarget};
/// # use sea_orm::entity::prelude::*;
/// # #[derive(Clone, Debug, PartialEq, DeriveEntityModel, PatchTarget)]
/// # #[sea_orm(table_name = "orders")]
/// # pub struct Model { #[sea_orm(primary_key)] pub id: i32, pub quantity: i32 }
/// # #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)] pub enum Relation {}
/// # impl ActiveModelBehavior for ActiveModel {}
/// # fn check<P: Patch<ActiveModel>>() {}
/// #[derive(Patch)]
/// pub struct UpdateOrder { pub quantity: Option<u32> }
/// fn main() { check::<UpdateOrder>() }
/// ```
///
/// `Nullable` on a NOT NULL column:
///
/// ```compile_fail
/// # use doxa::{Nullable, Patch, PatchTarget};
/// # use sea_orm::entity::prelude::*;
/// # #[derive(Clone, Debug, PartialEq, DeriveEntityModel, PatchTarget)]
/// # #[sea_orm(table_name = "orders")]
/// # pub struct Model { #[sea_orm(primary_key)] pub id: i32, pub name: String }
/// # #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)] pub enum Relation {}
/// # impl ActiveModelBehavior for ActiveModel {}
/// # fn check<P: Patch<ActiveModel>>() {}
/// #[derive(serde::Deserialize, Patch)]
/// pub struct UpdateOrder { #[serde(default)] pub name: Nullable<String> }
/// fn main() { check::<UpdateOrder>() }
/// ```
///
/// A field that is neither `Option` nor `Nullable`, and isn't skipped:
///
/// ```compile_fail
/// # use doxa::{Patch, PatchTarget};
/// # use sea_orm::entity::prelude::*;
/// # #[derive(Clone, Debug, PartialEq, DeriveEntityModel, PatchTarget)]
/// # #[sea_orm(table_name = "orders")]
/// # pub struct Model { #[sea_orm(primary_key)] pub id: i32, pub quantity: i32 }
/// # #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)] pub enum Relation {}
/// # impl ActiveModelBehavior for ActiveModel {}
/// # fn check<P: Patch<ActiveModel>>() {}
/// #[derive(Patch)]
/// pub struct UpdateOrder { pub quantity: i32 }
/// fn main() { check::<UpdateOrder>() }
/// ```
///
/// A `Nullable` without `serde(default)`, which serde would read as `Null` when left out:
///
/// ```compile_fail
/// # use doxa::{Nullable, Patch, PatchTarget};
/// # use sea_orm::entity::prelude::*;
/// # #[derive(Clone, Debug, PartialEq, DeriveEntityModel, PatchTarget)]
/// # #[sea_orm(table_name = "orders")]
/// # pub struct Model { #[sea_orm(primary_key)] pub id: i32, pub note: Option<String> }
/// # #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)] pub enum Relation {}
/// # impl ActiveModelBehavior for ActiveModel {}
/// # fn check<P: Patch<ActiveModel>>() {}
/// #[derive(serde::Deserialize, Patch)]
/// pub struct UpdateOrder { pub note: Nullable<String> }
/// fn main() { check::<UpdateOrder>() }
/// ```
///
/// A policy resource column warns until it is skipped:
///
/// ```compile_fail
/// #![deny(deprecated)]
/// # use doxa::{PatchTarget, PolicyResource};
/// # use sea_orm::entity::prelude::*;
/// #[derive(Clone, Debug, PartialEq, DeriveEntityModel, PolicyResource, PatchTarget)]
/// #[sea_orm(table_name = "orders")]
/// #[resource(entity_type = "Order")]
/// pub struct Model {
///     #[sea_orm(primary_key)] #[resource(id)] pub id: i32,
///     #[resource(attr)] pub quantity: i32,
/// }
/// # #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)] pub enum Relation {}
/// # impl ActiveModelBehavior for ActiveModel {}
/// fn main() {}
/// ```
///
/// ```
/// #![deny(deprecated)]
/// # use doxa::{PatchTarget, PolicyResource};
/// # use sea_orm::entity::prelude::*;
/// #[derive(Clone, Debug, PartialEq, DeriveEntityModel, PolicyResource, PatchTarget)]
/// #[sea_orm(table_name = "orders")]
/// #[resource(entity_type = "Order")]
/// pub struct Model {
///     #[sea_orm(primary_key)] #[resource(id)] pub id: i32,
///     #[resource(attr)] #[patch(skip)] pub quantity: i32,
/// }
/// # #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)] pub enum Relation {}
/// # impl ActiveModelBehavior for ActiveModel {}
/// fn main() {}
/// ```
#[cfg(all(feature = "full", not(target_arch = "wasm32")))]
#[doc(hidden)]
pub mod diagnostics {}

/// The columns `active` will write, for `OnConflict::update_columns` or an audit record.
#[cfg(all(feature = "sea-orm", not(target_arch = "wasm32")))]
pub fn changed_columns<A: sea_orm::ActiveModelTrait>(
    active: &A,
) -> Vec<<A::Entity as sea_orm::EntityTrait>::Column> {
    use sea_orm::Iterable;
    <<A::Entity as sea_orm::EntityTrait>::Column as Iterable>::iter()
        .filter(|c| active.get(*c).is_set())
        .collect()
}
