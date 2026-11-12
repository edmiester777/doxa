//! What `doxa gallery` shows, a folder per module, each story against a mocked server.

use std::time::Duration;

use doxa::client::transport::{MockTransport, Request, Response, Transport};
use futures::future::LocalBoxFuture;
use shop_api::widgets::Widget;

pub mod data;
pub mod forms;
pub mod motion;
pub mod react;

/// A server that answers every request with `.0` after `.1`, so a story shows its loading state.
pub struct Slow(pub serde_json::Value, pub Duration);

impl Transport for Slow {
    fn send(&self, request: Request) -> LocalBoxFuture<'static, Result<Response, String>> {
        let mock = MockTransport::new();
        mock.json(200, &self.0);
        let (answer, delay) = (mock.send(request), self.1);
        Box::pin(async move {
            doxa::client::clock::sleep(delay).await;
            answer.await
        })
    }
}

/// The widgets the stories list.
pub fn widgets() -> Vec<Widget> {
    ["sprocket", "gear", "cog", "flange"]
        .into_iter()
        .zip(1..)
        .map(|(name, id)| Widget {
            id,
            name: name.into(),
        })
        .collect()
}
