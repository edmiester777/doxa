//! `Json`, `Query`, `Path` and `Form`: axum's extractors, refusing in the [`ApiErrorBody`]
//! envelope every other error uses, with axum's status and the code `malformed`.

use axum::extract::rejection::{FormRejection, JsonRejection, PathRejection, QueryRejection};
use axum::extract::{
    FromRequest, FromRequestParts, OptionalFromRequest, OptionalFromRequestParts, Request,
};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use doxa_wire::MALFORMED;
use serde::de::DeserializeOwned;
use serde::Serialize;
use utoipa::openapi::path::Operation;
use utoipa::openapi::{RefOr, Schema};

use crate::{
    ApiErrorBody, DocOperationContribution, DocPathParams, DocPathScalar, DocQueryParams,
    DocRequestBody, DocResponseBody, InnerRejection, InnerToSchema, OperationContribution,
    ResponseContribution,
};

/// Why one of these extractors refused the request.
#[derive(Debug, Clone)]
pub struct Rejection {
    status: StatusCode,
    message: String,
}

impl Rejection {
    /// The status axum assigned.
    pub fn status(&self) -> StatusCode {
        self.status
    }
}

macro_rules! from_axum {
    ($($rejection:ty),*) => {$(
        impl From<$rejection> for Rejection {
            fn from(r: $rejection) -> Self {
                let (status, message) = (r.status(), r.body_text());
                tracing::warn!(status = status.as_u16(), error = %message, "request refused by an extractor");
                Rejection { status, message }
            }
        }
    )*};
}

from_axum!(JsonRejection, QueryRejection, PathRejection, FormRejection);

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        let body = ApiErrorBody::new(self.status.as_u16(), MALFORMED, self.message, ());
        (self.status, axum::Json(body)).into_response()
    }
}

impl InnerRejection for Rejection {
    fn status(&self) -> StatusCode {
        self.status
    }

    fn body_text(&self) -> String {
        self.message.clone()
    }
}

fn refusals(statuses: &[&str]) -> OperationContribution {
    statuses.iter().fold(OperationContribution::new(), |c, s| {
        c.with_response(ResponseContribution::new(*s, MALFORMED))
    })
}

macro_rules! wrapper {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
        pub struct $name<T>(pub T);

        impl<T> std::ops::Deref for $name<T> {
            type Target = T;
            fn deref(&self) -> &T {
                &self.0
            }
        }

        impl<T> std::ops::DerefMut for $name<T> {
            fn deref_mut(&mut self) -> &mut T {
                &mut self.0
            }
        }

        impl<T> From<T> for $name<T> {
            fn from(value: T) -> Self {
                $name(value)
            }
        }
    };
}

wrapper!(
    /// A JSON body, and a JSON response.
    Json
);
wrapper!(
    /// The query string.
    Query
);
wrapper!(
    /// The path's parameters.
    Path
);
wrapper!(
    /// A URL-encoded body, or the query string on a `GET`.
    Form
);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for Json<T> {
    type Rejection = Rejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Rejection> {
        let axum::Json(value) = <axum::Json<T> as FromRequest<S>>::from_request(req, state).await?;
        Ok(Json(value))
    }
}

impl<T: DeserializeOwned, S: Send + Sync> OptionalFromRequest<S> for Json<T> {
    type Rejection = Rejection;

    async fn from_request(req: Request, state: &S) -> Result<Option<Self>, Rejection> {
        let found = <axum::Json<T> as OptionalFromRequest<S>>::from_request(req, state).await?;
        Ok(found.map(|axum::Json(value)| Json(value)))
    }
}

impl<T: Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

impl<T: DeserializeOwned, S: Send + Sync> FromRequestParts<S> for Query<T> {
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Rejection> {
        let axum::extract::Query(value) =
            axum::extract::Query::<T>::from_request_parts(parts, state).await?;
        Ok(Query(value))
    }
}

impl<T: DeserializeOwned + Send, S: Send + Sync> FromRequestParts<S> for Path<T> {
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Rejection> {
        let axum::extract::Path(value) =
            <axum::extract::Path<T> as FromRequestParts<S>>::from_request_parts(parts, state)
                .await?;
        Ok(Path(value))
    }
}

impl<T: DeserializeOwned + Send + 'static, S: Send + Sync> OptionalFromRequestParts<S> for Path<T> {
    type Rejection = Rejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Option<Self>, Rejection> {
        let found = <axum::extract::Path<T> as OptionalFromRequestParts<S>>::from_request_parts(
            parts, state,
        )
        .await?;
        Ok(found.map(|axum::extract::Path(value)| Path(value)))
    }
}

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for Form<T> {
    type Rejection = Rejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Rejection> {
        let axum::extract::Form(value) = axum::extract::Form::<T>::from_request(req, state).await?;
        Ok(Form(value))
    }
}

// ---- OpenAPI: as axum's own, plus the refusals ----

impl<T> DocResponseBody for Json<T>
where
    axum::Json<T>: DocResponseBody,
{
    fn describe(op: &mut Operation, schemas: &mut Vec<(String, RefOr<Schema>)>) {
        <axum::Json<T> as DocResponseBody>::describe(op, schemas)
    }
}

impl<T> DocRequestBody for Json<T>
where
    axum::Json<T>: DocRequestBody,
{
    fn describe(op: &mut Operation) {
        <axum::Json<T> as DocRequestBody>::describe(op)
    }
}

impl<T> DocQueryParams for Query<T>
where
    axum::extract::Query<T>: DocQueryParams,
{
    fn describe(op: &mut Operation) {
        <axum::extract::Query<T> as DocQueryParams>::describe(op)
    }
}

impl<T> DocPathParams for Path<T>
where
    axum::extract::Path<T>: DocPathParams,
{
    fn describe(op: &mut Operation, names: &[&'static str]) {
        <axum::extract::Path<T> as DocPathParams>::describe(op, names)
    }
}

impl<T> DocPathScalar for Path<T>
where
    axum::extract::Path<T>: DocPathScalar,
{
    fn describe_scalar(op: &mut Operation, names: &[&'static str]) {
        <axum::extract::Path<T> as DocPathScalar>::describe_scalar(op, names)
    }
}

macro_rules! inner_schema {
    ($($ours:ident => $theirs:ty),*) => {$(
        impl<T> InnerToSchema for $ours<T>
        where
            $theirs: InnerToSchema,
        {
            fn inner_schemas(out: &mut Vec<(String, RefOr<Schema>)>) {
                <$theirs as InnerToSchema>::inner_schemas(out)
            }
        }
    )*};
}

inner_schema!(
    Json => axum::Json<T>,
    Query => axum::extract::Query<T>,
    Path => axum::extract::Path<T>
);

impl<T> DocOperationContribution for Json<T> {
    fn contribution() -> OperationContribution {
        refusals(&["400", "413", "415", "422"])
    }
}

impl<T> DocOperationContribution for Form<T> {
    fn contribution() -> OperationContribution {
        refusals(&["400", "413", "415", "422"])
    }
}

impl<T> DocOperationContribution for Query<T> {
    fn contribution() -> OperationContribution {
        refusals(&["400"])
    }
}

impl<T> DocOperationContribution for Path<T> {
    fn contribution() -> OperationContribution {
        refusals(&["400"])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    async fn envelope(response: Response) -> (StatusCode, Value) {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&body).expect("a JSON envelope"),
        )
    }

    #[tokio::test]
    async fn a_malformed_body_answers_the_envelope() {
        let request = Request::post("/")
            .header("content-type", "application/json")
            .body(axum::body::Body::from("{"))
            .unwrap();
        let rejection = <Json<Value> as FromRequest<()>>::from_request(request, &())
            .await
            .expect_err("not JSON");
        let (status, body) = envelope(rejection.into_response()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], MALFORMED);
        assert_eq!(body["status"], 400);
    }

    /// Every `WARN` event's fields, as `name=value`.
    #[derive(Clone, Default)]
    struct Warnings(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    struct Fields<'a>(&'a mut Vec<String>);

    impl tracing::field::Visit for Fields<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push(format!("{}={value:?}", field.name()));
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Warnings {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::WARN {
                event.record(&mut Fields(&mut self.0.lock().unwrap()));
            }
        }
    }

    #[test]
    fn a_refusal_is_logged_with_its_status_and_cause() {
        use tracing_subscriber::layer::SubscriberExt;

        let warnings = Warnings::default();
        let subscriber = tracing_subscriber::registry().with(warnings.clone());
        let uri: axum::http::Uri = "/?n=abc".parse().unwrap();
        #[derive(Debug, serde::Deserialize)]
        struct Q {
            #[allow(dead_code)]
            n: u32,
        }
        // With a lone dispatcher, tracing caches a callsite's interest from whichever
        // thread registers it first; a parallel test without a subscriber would cache "never".
        let _second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        let refused = tracing::subscriber::with_default(subscriber, || {
            let rejection =
                <axum::extract::Query<Q>>::try_from_uri(&uri).expect_err("not a number");
            Rejection::from(rejection)
        });

        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        let fields = warnings.0.lock().unwrap();
        assert!(fields.contains(&"status=400".to_owned()), "{fields:?}");
        assert!(
            fields
                .iter()
                .any(|f| f.starts_with("error=") && f.contains("invalid digit")),
            "{fields:?}"
        );
    }

    #[tokio::test]
    async fn a_missing_content_type_keeps_axum_s_status() {
        let request = Request::post("/")
            .body(axum::body::Body::from("{}"))
            .unwrap();
        let rejection = <Json<Value> as FromRequest<()>>::from_request(request, &())
            .await
            .expect_err("no content type");
        let (status, body) = envelope(rejection.into_response()).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(body["code"], MALFORMED);
    }

    #[tokio::test]
    async fn an_unparseable_query_answers_the_envelope() {
        let (mut parts, ()) = Request::get("/?n=abc").body(()).unwrap().into_parts();
        #[derive(serde::Deserialize)]
        struct Q {
            #[allow(dead_code)]
            n: u32,
        }
        let rejection = Query::<Q>::from_request_parts(&mut parts, &())
            .await
            .err()
            .expect("not a number");
        let (status, body) = envelope(rejection.into_response()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["message"].as_str().unwrap().contains('n'), "{body}");
    }

    #[tokio::test]
    async fn a_json_response_is_axum_s() {
        let response = Json(serde_json::json!({ "a": 1 })).into_response();
        let (status, body) = envelope(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["a"], 1);
    }
}
