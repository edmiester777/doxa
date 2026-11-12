//! How a route names its guard by entity, which both halves understand.

use std::marker::PhantomData;

use crate::{names_covered, Keyed};

/// In a route, the guard that authorizes a call to this one `E`: the client passes `E`'s key,
/// and the server guards with `E`'s asset, or the one `Grant<E, by = Asset>` names.
pub struct Grant<E: ?Sized>(PhantomData<fn() -> E>);

/// In a route, `Grant<Many<E>>`: the call lists `E`s the server's guard scopes.
pub struct Many<E: ?Sized>(PhantomData<fn() -> E>);

/// In a route, `Grant<Cap<M>>`: the call needs the capability `M` names.
pub struct Cap<M: ?Sized>(PhantomData<fn() -> M>);

/// The entity a server asset guards, from `#[doxa::asset(entity = …)]`.
#[diagnostic::on_unimplemented(
    message = "`{Self}` doesn't say which entity it guards",
    note = "add `entity = …` to its `#[doxa::asset(…)]`, naming the `#[doxa::entity]`"
)]
pub trait OfEntity {
    /// The entity.
    type Entity: Keyed;
}

/// Compiles only when the asset `A` guards the entity `E`, as `Grant<E, by = A>` claims.
#[doc(hidden)]
pub fn guards<A: OfEntity<Entity = E>, E>() {}

/// Whether two keys name the same route parameters, in any order.
pub const fn same_names(a: &[&str], b: &[&str]) -> bool {
    names_covered(a, &[b]) && names_covered(b, &[a])
}
