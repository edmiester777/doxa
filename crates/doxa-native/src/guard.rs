//! Keeps tabs in the user's own browser away from the local server: DNS rebinding sends a
//! foreign `Host`, and a cross-site request a foreign `Origin` or `Sec-Fetch-Site`. Other
//! processes send neither header, so they pass.

use std::sync::Arc;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::Router;
use http::{HeaderMap, StatusCode};

/// `router` behind the check, for a server bound on `port`.
pub(crate) fn browser_tabs(router: Router, port: u16) -> Router {
    let hosts: Arc<[String]> = [format!("127.0.0.1:{port}"), format!("localhost:{port}")].into();
    router.layer(axum::middleware::from_fn(
        move |req: Request, next: Next| {
            let hosts = hosts.clone();
            async move {
                match check(req.headers(), &hosts) {
                    Ok(()) => next.run(req).await,
                    Err(status) => status.into_response(),
                }
            }
        },
    ))
}

fn check(headers: &HeaderMap, hosts: &[String]) -> Result<(), StatusCode> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if !header("host").is_some_and(|h| hosts.iter().any(|a| a == h)) {
        return Err(StatusCode::MISDIRECTED_REQUEST);
    }
    if let Some(origin) = header("origin") {
        let ours = hosts
            .iter()
            .any(|h| origin.strip_prefix("http://") == Some(h.as_str()));
        if !ours {
            return Err(StatusCode::FORBIDDEN);
        }
    }
    // Another loopback port counts as `same-site`, so only these two pass.
    if header("sec-fetch-site").is_some_and(|s| s != "same-origin" && s != "none") {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    async fn status(headers: &[(&str, &str)]) -> StatusCode {
        let app = browser_tabs(
            Router::new().route("/", axum::routing::get(|| async { "ok" })),
            4000,
        );
        let mut req = http::Request::builder().uri("/");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        app.oneshot(req.body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn local_processes_and_the_app_s_own_page_pass() {
        assert_eq!(status(&[("host", "127.0.0.1:4000")]).await, StatusCode::OK);
        assert_eq!(status(&[("host", "localhost:4000")]).await, StatusCode::OK);
        assert_eq!(
            status(&[
                ("host", "127.0.0.1:4000"),
                ("origin", "http://127.0.0.1:4000"),
                ("sec-fetch-site", "same-origin"),
            ])
            .await,
            StatusCode::OK
        );
        assert_eq!(
            status(&[("host", "127.0.0.1:4000"), ("sec-fetch-site", "none")]).await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn a_rebound_host_is_misdirected() {
        assert_eq!(
            status(&[("host", "evil.test")]).await,
            StatusCode::MISDIRECTED_REQUEST
        );
        assert_eq!(
            status(&[("host", "127.0.0.1:4001")]).await,
            StatusCode::MISDIRECTED_REQUEST
        );
        assert_eq!(status(&[]).await, StatusCode::MISDIRECTED_REQUEST);
    }

    #[tokio::test]
    async fn another_site_or_port_is_forbidden() {
        let host = ("host", "127.0.0.1:4000");
        assert_eq!(
            status(&[host, ("origin", "https://evil.test")]).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(&[host, ("sec-fetch-site", "cross-site")]).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(&[host, ("sec-fetch-site", "same-site")]).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(&[host, ("origin", "http://127.0.0.1:5000")]).await,
            StatusCode::FORBIDDEN
        );
    }
}
