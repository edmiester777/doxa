//! What `#[doxa::implements]` holds a handler to, as the client sees the route.

use crate::response::{SseOnce, SseStream};

/// A handler's client arguments, against its declaration's.
#[diagnostic::on_unimplemented(
    message = "the handler takes `{Self}` from the client, and the declaration `{T}`",
    note = "take the declared arguments in their order; server-only extractors go anywhere"
)]
pub trait Takes<T> {}
impl<T> Takes<T> for T {}

/// A handler's success, against its declaration's.
#[diagnostic::on_unimplemented(message = "the handler answers `{Self}`, and the declaration `{T}`")]
pub trait Answers<T> {}
impl<T> Answers<T> for T {}
impl<E> Answers<SseOnce<E>> for SseStream<E> {}

/// A handler's error, against its declaration's.
#[diagnostic::on_unimplemented(
    message = "the handler fails with `{Self}`, and the declaration with `{E}`",
    note = "return the declared error, or `Fail<…>` of it from `doxa::serves!`"
)]
pub trait FailsWith<E> {}
impl<E> FailsWith<E> for E {}

#[doc(hidden)]
pub fn takes<A: Takes<B>, B>() {}
#[doc(hidden)]
pub fn answers<A: Answers<B>, B>() {}
#[doc(hidden)]
pub fn fails<A: FailsWith<B>, B>() {}

/// A server guard, as the declaration that names its entity states it.
#[diagnostic::on_unimplemented(
    message = "`{Self}` doesn't guard a declared entity",
    note = "add `entity = …` to the asset's `#[doxa::asset(…)]`"
)]
pub trait Guarded {
    /// `Granted<E>` for the entity `E` the asset guards.
    type Declared;
}

impl<A: doxa_wire::contract::OfEntity> Guarded for crate::Granted<A> {
    type Declared = crate::Granted<A::Entity>;
}
