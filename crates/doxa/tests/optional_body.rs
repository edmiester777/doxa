//! An optional body: `None` sends none and isn't checked; `Some` is checked and sent.

use axum::Json;
use doxa::{post, routes, OpenApiRouter, Valid};
use serde::{Deserialize, Serialize};

#[derive(Clone, doxa::State)]
struct NoState;

#[derive(Debug, Clone, Serialize, Deserialize, garde::Validate, utoipa::ToSchema)]
pub struct Note {
    #[garde(length(min = 1))]
    pub text: String,
}

#[post("/notes")]
async fn add(Valid(note): Valid<Option<Json<Note>>>) -> Json<String> {
    Json(note.map_or("none".into(), |Json(n)| n.text))
}

#[post("/plain")]
async fn plain(note: Option<Json<Note>>) -> Json<String> {
    Json(note.map_or("none".into(), |Json(n)| n.text))
}

mod client {
    use super::Note;
    use doxa::Valid;

    doxa::client::__as_client! {
        #[post("/notes")]
        pub async fn add(Valid(note): Valid<Option<Json<Note>>>) -> Json<String> { unreachable!() }

        #[post("/plain")]
        pub async fn plain(note: Option<Json<Note>>) -> Json<String> { unreachable!() }
    }
}

fn router() -> axum::Router {
    let (router, _) = OpenApiRouter::<()>::new()
        .routes(routes!(add))
        .routes(routes!(plain))
        .split_for_parts();
    router
}

#[tokio::test]
async fn none_sends_no_body_and_some_is_checked_first() {
    use doxa::client::transport::RouterTransport;
    use doxa::client::{layer::transport, service, Fetch};

    let s = service("doxa");
    s.layers().push(transport(RouterTransport::new(router())));

    assert_eq!(*client::add(None).await.unwrap(), "none");
    let note = Note { text: "hi".into() };
    assert_eq!(*client::add(Some(note.clone())).await.unwrap(), "hi");
    assert_eq!(*client::plain(None).await.unwrap(), "none");
    assert_eq!(*client::plain(Some(note)).await.unwrap(), "hi");

    let before = s.requests_sent();
    let refused = client::add(Some(Note {
        text: String::new(),
    }))
    .await
    .unwrap_err();
    assert!(matches!(refused, Fetch::Invalid(_)), "{refused:?}");
    assert_eq!(s.requests_sent(), before, "refused before it was sent");
}

#[test]
fn the_document_says_the_body_may_be_left_out() {
    use utoipa::openapi::Required;

    let api = OpenApiRouter::<()>::new()
        .routes(routes!(add))
        .routes(routes!(plain))
        .into_openapi();
    for path in ["/notes", "/plain"] {
        let op = api.paths.paths[path].post.as_ref().unwrap();
        let body = op.request_body.as_ref().expect(path);
        assert!(matches!(body.required, Some(Required::False)), "{path}");
    }
}
