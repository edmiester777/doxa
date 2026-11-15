//! `#[doxa::faults]` gives an error enum the classes it names, and a registered set's
//! conversions.

use axum::response::IntoResponse;
use serde::Serialize;
use utoipa::ToSchema;

/// What a store fails with, before it's sorted into classes.
#[derive(Debug)]
pub enum StoreError {
    Busy,
    Gone(u32),
    Broken(&'static str),
}

doxa::fault_set! {
    /// How a store fails.
    pub StoreFaults from crate::StoreError {
        /// Someone else holds the row.
        conflict: Contended = 409 "conflict",
        not_found: NotFound = 404 "not_found",
        internal: Internal = 500 "internal" (redact),
    }
}

impl From<StoreError> for StoreFaults {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::Busy => Self::Contended("the row is busy".into()),
            StoreError::Gone(id) => Self::NotFound(format!("no widget {id}")),
            StoreError::Broken(why) => Self::Internal(why.into()),
        }
    }
}

#[doxa::faults(common, crate::StoreFaults)]
#[derive(Debug, thiserror::Error, Serialize, ToSchema, doxa::ApiError)]
pub enum WidgetError {
    #[error("the name is taken")]
    #[api(status = 409, code = "name_taken")]
    NameTaken,
}

#[doxa::faults(crate::StoreFaults, wire)]
#[derive(Debug, thiserror::Error, Serialize, ToSchema, doxa::ApiError)]
pub enum WireError {}

/// A source with no conversion: `wire` means this impl doesn't collide with one doxa wrote.
impl From<StoreError> for WireError {
    fn from(error: StoreError) -> Self {
        StoreFaults::from(error).into()
    }
}

async fn answer(error: WidgetError) -> (u16, serde_json::Value) {
    let response = error.into_response();
    let status = response.status().as_u16();
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .unwrap()
        .to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

#[tokio::test]
async fn a_source_error_answers_through_its_class() {
    let (status, body) = answer(StoreError::Busy.into()).await;
    assert_eq!(status, 409);
    assert_eq!(body["code"], "conflict");
    assert_eq!(body["message"], "the row is busy");

    let (status, body) = answer(StoreError::Gone(7).into()).await;
    assert_eq!(status, 404);
    assert_eq!(body["code"], "not_found");
    assert_eq!(body["message"], "no widget 7");
}

#[tokio::test]
async fn an_internal_failure_keeps_its_cause_off_the_wire() {
    let error: WidgetError = StoreError::Broken("disk on fire").into();
    assert!(format!("{error:?}").contains("disk on fire"));
    let (status, body) = answer(error).await;
    assert_eq!(status, 500);
    assert_eq!(body["code"], "internal");
    assert!(!body.to_string().contains("disk on fire"), "{body}");
}

#[tokio::test]
async fn common_classes_and_the_enum_s_own_variants_live_side_by_side() {
    let (status, body) = answer(WidgetError::Forbidden("not yours".into())).await;
    assert_eq!(status, 403);
    assert_eq!(body["code"], "forbidden");

    let (status, body) = answer(WidgetError::Validation("too long".into())).await;
    assert_eq!(status, 400);
    assert_eq!(body["code"], "validation_error");

    assert_eq!(answer(WidgetError::NameTaken).await.0, 409);
}

#[test]
fn a_wire_enum_converts_from_the_set_only() {
    let error: WireError = StoreError::Busy.into();
    assert!(matches!(error, WireError::Contended(_)));
}
