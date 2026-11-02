//! `Valid<Json<T>>`: run `T`'s garde rules and answer `422` with each failing field.

use axum::extract::{FromRequest, FromRequestParts, Query, Request};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use doxa_wire::{FieldError, FieldErrors, INVALID};
use utoipa::openapi::path::Operation;

use crate::{ApiErrorBody, DocHeaderParams, DocPathParams, DocQueryParams, DocRequestBody};

/// An extractor whose value passed its garde rules; the same rules a doxa form checks first.
///
/// ```ignore
/// #[post("/api/orders")]
/// async fn create_order(Valid(Json(o)): Valid<Json<NewOrder>>) -> Json<Order> {
///     Json(save(o).await)
/// }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Valid<E>(pub E);

/// Why a [`Valid`] refused the request: the inner extractor's own rejection, or invalid fields.
#[derive(Debug)]
pub enum ValidRejection<R> {
    /// The inner extractor refused.
    Inner(R),
    /// `422`, with each failing field.
    Invalid(FieldErrors),
}

impl<R: IntoResponse> IntoResponse for ValidRejection<R> {
    fn into_response(self) -> Response {
        match self {
            ValidRejection::Inner(r) => r.into_response(),
            ValidRejection::Invalid(fields) => {
                let body = ApiErrorBody::new(422, INVALID, fields.to_string(), fields);
                (StatusCode::UNPROCESSABLE_ENTITY, Json(body)).into_response()
            }
        }
    }
}

fn check<T: garde::Validate>(value: &T) -> Result<(), FieldErrors>
where
    T::Context: Default,
{
    value.validate().map_err(|report| {
        FieldErrors(
            report
                .iter()
                .map(|(path, e)| FieldError {
                    path: path.to_string(),
                    message: e.message().to_owned(),
                })
                .collect(),
        )
    })
}

impl<S, T> FromRequest<S> for Valid<Json<T>>
where
    S: Send + Sync,
    Json<T>: FromRequest<S>,
    T: garde::Validate,
    T::Context: Default,
{
    type Rejection = ValidRejection<<Json<T> as FromRequest<S>>::Rejection>;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let json = Json::<T>::from_request(req, state)
            .await
            .map_err(ValidRejection::Inner)?;
        check(&json.0).map_err(ValidRejection::Invalid)?;
        Ok(Valid(json))
    }
}

impl<S, T> FromRequestParts<S> for Valid<Query<T>>
where
    S: Send + Sync,
    Query<T>: FromRequestParts<S>,
    T: garde::Validate,
    T::Context: Default,
{
    type Rejection = ValidRejection<<Query<T> as FromRequestParts<S>>::Rejection>;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let query = Query::<T>::from_request_parts(parts, state)
            .await
            .map_err(ValidRejection::Inner)?;
        check(&query.0).map_err(ValidRejection::Invalid)?;
        Ok(Valid(query))
    }
}

impl<E: DocQueryParams> DocQueryParams for Valid<E> {
    fn describe(op: &mut Operation) {
        E::describe(op)
    }
}

impl<E: DocPathParams> DocPathParams for Valid<E> {
    fn describe(op: &mut Operation, names: &[&'static str]) {
        E::describe(op, names)
    }
}

impl<E: DocHeaderParams> DocHeaderParams for Valid<E> {
    fn describe(op: &mut Operation) {
        E::describe(op)
    }
}

impl<E: DocRequestBody> DocRequestBody for Valid<E> {
    fn describe(op: &mut Operation) {
        E::describe(op)
    }
}
