//! Each validation library, and an app's own wrapper, refuse the same input with the same fields
//! on the server (`422`) and in the client (unsent).

use axum::routing::post;
use axum::Json;
use doxa::client::{Fetch, FieldErrors};
use doxa::wire::Validates;
use http_body_util::BodyExt;
use tower::ServiceExt;
use validator::Validate;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Validate)]
pub struct ByValidator {
    #[validate(length(min = 1, message = "required"))]
    pub name: String,
    #[validate(nested)]
    pub lines: Vec<Line>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Validate)]
pub struct Line {
    #[validate(range(min = 1, message = "at least one"))]
    pub quantity: u32,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, serde_valid::Validate)]
pub struct BySerdeValid {
    #[validate(min_length = 1)]
    pub name: String,
}

/// An app's own wrapper, over `validator`.
#[derive(doxa::Validator)]
pub struct Checked<E>(pub E);

impl<T: validator::Validate> Validates for Checked<Json<T>> {
    type Value = T;
    fn check(v: &T) -> Result<(), FieldErrors> {
        v.validate().map_err(FieldErrors::from)
    }
}

impl<T: validator::Validate> Validates for Checked<doxa::client::Json<T>> {
    type Value = T;
    fn check(v: &T) -> Result<(), FieldErrors> {
        v.validate().map_err(FieldErrors::from)
    }
}

mod calls {
    use super::*;
    doxa::client::__as_client! {
        #[post("/validator")]
        pub async fn by_validator(doxa::validator::Valid(Json(v)): doxa::validator::Valid<Json<ByValidator>>) -> StatusCode { unreachable!() }

        #[post("/serde_valid")]
        pub async fn by_serde_valid(doxa::serde_valid::Valid(Json(v)): doxa::serde_valid::Valid<Json<BySerdeValid>>) -> StatusCode { unreachable!() }

        #[post("/checked")]
        pub async fn by_checked(Checked(Json(v)): Checked<Json<ByValidator>>) -> StatusCode { unreachable!() }
    }
}

async fn by_validator(doxa::validator::Valid(Json(_)): doxa::validator::Valid<Json<ByValidator>>) {}
async fn by_serde_valid(
    doxa::serde_valid::Valid(Json(_)): doxa::serde_valid::Valid<Json<BySerdeValid>>,
) {
}
async fn by_checked(Checked(Json(_)): Checked<Json<ByValidator>>) {}

/// What the server answers `body` with at `path`: its status and, for a `422`, the fields.
async fn served(path: &str, body: String) -> (u16, Option<FieldErrors>) {
    let app = axum::Router::new()
        .route("/validator", post(by_validator))
        .route("/serde_valid", post(by_serde_valid))
        .route("/checked", post(by_checked));
    let req = axum::http::Request::post(path)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    let status = res.status().as_u16();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let fields = (status == 422).then(|| {
        serde_json::from_slice::<doxa::wire::ApiErrorBody<FieldErrors>>(&bytes)
            .unwrap()
            .error
    });
    (status, fields)
}

fn refused<E: std::fmt::Debug>(r: Result<impl std::fmt::Debug, Fetch<E>>) -> FieldErrors {
    match r {
        Err(Fetch::Invalid(fields)) => fields,
        other => panic!("{other:?}"),
    }
}

fn bad_order() -> ByValidator {
    ByValidator {
        name: String::new(),
        lines: vec![Line { quantity: 2 }, Line { quantity: 0 }],
    }
}

#[tokio::test]
async fn validator_refuses_alike_in_both_halves() {
    let client = refused(calls::by_validator(bad_order()).await);
    assert_eq!(client.get("name"), Some("required"));
    assert_eq!(client.get("lines[1].quantity"), Some("at least one"));
    let body = serde_json::to_string(&bad_order()).unwrap();
    assert_eq!(served("/validator", body).await, (422, Some(client)));
}

#[tokio::test]
async fn serde_valid_refuses_alike_in_both_halves() {
    let bad = BySerdeValid {
        name: String::new(),
    };
    let client = refused(calls::by_serde_valid(bad.clone()).await);
    assert!(client.get("name").is_some(), "{client:?}");
    let body = serde_json::to_string(&bad).unwrap();
    assert_eq!(served("/serde_valid", body).await, (422, Some(client)));
}

#[tokio::test]
async fn an_apps_own_wrapper_refuses_alike_in_both_halves() {
    let client = refused(calls::by_checked(bad_order()).await);
    assert_eq!(calls::by_checked::check(&bad_order()), Err(client.clone()));
    let body = serde_json::to_string(&bad_order()).unwrap();
    assert_eq!(served("/checked", body).await, (422, Some(client)));
}

#[tokio::test]
async fn a_valid_body_passes_the_server() {
    let good = ByValidator {
        name: "bolts".into(),
        lines: vec![Line { quantity: 1 }],
    };
    let body = serde_json::to_string(&good).unwrap();
    assert_eq!(served("/checked", body).await, (200, None));
}
