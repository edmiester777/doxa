//! [`Answer`]: what a handler's return type is to the client, found by type rather than name.

use std::future::Future;

/// A handler's return type, as the client decodes it.
#[diagnostic::on_unimplemented(
    message = "the browser can't decode `{Self}`",
    note = "return `Json<…>`, `SseStream<…>`, `StatusCode`, `Attachment`, `String` or a `Result` \
            of one, or implement `doxa::Answer` for it"
)]
pub trait Answer {
    /// The client's type for it.
    type Client;
}

impl<T> Answer for axum::Json<T> {
    type Client = doxa_client::Json<T>;
}

impl Answer for axum::http::StatusCode {
    type Client = doxa_client::StatusCode;
}

impl<E, S> Answer for doxa_docs::SseStream<E, S> {
    type Client = doxa_client::SseStream<E>;
}

impl Answer for doxa_docs::Attachment {
    type Client = doxa_client::Attachment;
}

impl Answer for String {
    type Client = String;
}

impl Answer for () {
    type Client = ();
}

/// The success side; the error is held to the declaration's separately.
impl<T: Answer, E> Answer for Result<T, E> {
    type Client = T::Client;
}

impl<A: Answer, B: Answer> Answer for (A, B) {
    type Client = (A::Client, B::Client);
}

/// The output of an async handler taking `Args`, inferred from the fn item.
#[doc(hidden)]
pub trait Answering<Args> {
    type Output;
}

macro_rules! answering {
    ($($a:ident),*) => {
        impl<F, Fut, $($a),*> Answering<($($a,)*)> for F
        where
            F: FnOnce($($a),*) -> Fut,
            Fut: Future,
        {
            type Output = Fut::Output;
        }
    };
}

answering!();
answering!(A1);
answering!(A1, A2);
answering!(A1, A2, A3);
answering!(A1, A2, A3, A4);
answering!(A1, A2, A3, A4, A5);
answering!(A1, A2, A3, A4, A5, A6);
answering!(A1, A2, A3, A4, A5, A6, A7);
answering!(A1, A2, A3, A4, A5, A6, A7, A8);
answering!(A1, A2, A3, A4, A5, A6, A7, A8, A9);
answering!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10);
answering!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11);
answering!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12);
answering!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13);
answering!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14);
answering!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15);
answering!(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16);

/// Holds handler `f`'s answer, as the client sees it, to the declaration's `Ok`.
#[doc(hidden)]
pub fn answers_as<Ok, F, Args>(_: &F)
where
    F: Answering<Args>,
    F::Output: Answer,
    <F::Output as Answer>::Client: doxa_client::contract::Answers<Ok>,
{
}
