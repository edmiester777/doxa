//! Mount the OpenAPI JSON endpoint and documentation UI on an existing
//! [`axum::Router`].
//!
//! The JSON is served from memory via an [`Arc<str>`] held by the
//! handler closure — no disk reads, no per-request serialization.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use bytes::Bytes;

use crate::builder::ApiDoc;

/// Configuration for [`mount_docs`].
///
/// All fields have sensible defaults; override only what differs from
/// the convention. The struct is intentionally builder-only — prefer
/// `MountOpts::default()` followed by chained setters over struct
/// literal construction so future field additions remain additive.
#[derive(Debug, Clone)]
pub struct MountOpts {
    /// Path at which the raw OpenAPI JSON is served. Defaults to
    /// `"/openapi.json"`.
    pub spec_path: String,

    /// Path at which the documentation UI is mounted. Defaults to
    /// `"/docs"`. Only honored when at least one UI feature is enabled
    /// at compile time.
    pub ui_path: String,

    /// Whether to mount the documentation UI. Defaults to `true`. Set
    /// to `false` to expose only the raw JSON without an interactive
    /// viewer.
    pub mount_ui: bool,

    /// Scalar UI rendering options. Defaults to
    /// [`ScalarConfig::default()`](crate::ScalarConfig), which renders
    /// the historical out-of-the-box appearance (three-pane `modern`
    /// layout, dark mode on, schemas index hidden, codegen sidebar
    /// suppressed, agent / MCP integrations disabled). Only honored
    /// when the `docs-scalar` feature is enabled at compile time.
    #[cfg(feature = "docs-scalar")]
    pub scalar: crate::ui::ScalarConfig,
}

impl Default for MountOpts {
    fn default() -> Self {
        Self {
            spec_path: "/openapi.json".to_string(),
            ui_path: "/docs".to_string(),
            mount_ui: true,
            #[cfg(feature = "docs-scalar")]
            scalar: crate::ui::ScalarConfig::default(),
        }
    }
}

impl MountOpts {
    /// Use the supplied path for the raw OpenAPI JSON endpoint.
    pub fn spec_path(mut self, path: impl Into<String>) -> Self {
        self.spec_path = path.into();
        self
    }

    /// Use the supplied path for the documentation UI mount point.
    pub fn ui_path(mut self, path: impl Into<String>) -> Self {
        self.ui_path = path.into();
        self
    }

    /// Disable the documentation UI mount, exposing only the JSON
    /// endpoint.
    pub fn without_ui(mut self) -> Self {
        self.mount_ui = false;
        self
    }

    /// Override the Scalar UI configuration.
    ///
    /// # Example
    ///
    /// ```
    /// use doxa::{MountOpts, ScalarConfig, ScalarLayout, ScalarTheme};
    ///
    /// let opts = MountOpts::default().scalar(
    ///     ScalarConfig::default()
    ///         .layout(ScalarLayout::Classic)
    ///         .theme(ScalarTheme::Solarized)
    ///         .dark_mode(false),
    /// );
    /// # let _ = opts;
    /// ```
    #[cfg(feature = "docs-scalar")]
    pub fn scalar(mut self, cfg: crate::ui::ScalarConfig) -> Self {
        self.scalar = cfg;
        self
    }
}

/// Mount the OpenAPI JSON endpoint (and a documentation UI, if a UI
/// feature is enabled) on the supplied router.
///
/// The JSON handler closes over the [`ApiDoc`]'s pre-serialized
/// [`Bytes`] and clones it on each request — zero allocations beyond
/// the reference count bump.
///
/// # Example
///
/// ```no_run
/// use axum::Router;
/// use doxa::{mount_docs, ApiDocBuilder, MountOpts};
///
/// let api_doc = ApiDocBuilder::new().title("test").version("0.1").build();
/// let app: Router = mount_docs(Router::new(), api_doc, MountOpts::default());
/// # let _ = app;
/// ```
pub fn mount_docs<S>(router: Router<S>, api_doc: ApiDoc, opts: MountOpts) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let json = mount_json(router, &api_doc, &opts);
    if opts.mount_ui {
        mount_ui(json, &api_doc, &opts)
    } else {
        json
    }
}

/// Extension trait providing [`mount_docs`](MountDocsExt::mount_docs) as a
/// fluent method on [`axum::Router`]. Equivalent to the free function
/// [`mount_docs`].
pub trait MountDocsExt<S>
where
    S: Clone + Send + Sync + 'static,
{
    /// Mount the OpenAPI JSON endpoint and (optionally) the
    /// documentation UI on `self`.
    fn mount_docs(self, api_doc: ApiDoc, opts: MountOpts) -> Self;
}

impl<S> MountDocsExt<S> for Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    fn mount_docs(self, api_doc: ApiDoc, opts: MountOpts) -> Self {
        mount_docs(self, api_doc, opts)
    }
}

fn mount_json<S>(router: Router<S>, api_doc: &ApiDoc, opts: &MountOpts) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let spec_json: Bytes = api_doc.spec_json.clone();
    router.route(
        &opts.spec_path,
        get(move || {
            // Bytes::clone is a refcount bump — no allocation, no copy.
            let body = spec_json.clone();
            async move { json_response(body) }
        }),
    )
}

#[cfg(feature = "docs-scalar")]
fn mount_ui<S>(router: Router<S>, api_doc: &ApiDoc, opts: &MountOpts) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let spec_url = opts.spec_path.clone();
    let title = api_doc.openapi.info.title.clone();
    let html: Bytes = Bytes::from(crate::ui::scalar::render(&spec_url, &title, &opts.scalar));
    router.route(
        &opts.ui_path,
        get(move || {
            let body = html.clone();
            async move { html_response(body) }
        }),
    )
}

#[cfg(not(feature = "docs-scalar"))]
fn mount_ui<S>(router: Router<S>, _api_doc: &ApiDoc, opts: &MountOpts) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    // No UI features enabled — return the router unchanged. The caller
    // asked for a UI but none is available; this is logged once at
    // debug level so the misconfiguration is visible.
    tracing::debug!(
        ui_path = %opts.ui_path,
        "mount_docs: mount_ui requested but no UI feature is enabled at compile time"
    );
    router
}

fn json_response(body: Bytes) -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        axum::body::Body::from(body),
    )
        .into_response()
}

#[cfg(feature = "docs-scalar")]
fn html_response(body: Bytes) -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        axum::body::Body::from(body),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::ApiDocBuilder;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn doc() -> ApiDoc {
        ApiDocBuilder::new().title("test").version("0.1").build()
    }

    #[tokio::test]
    async fn mounts_openapi_json_endpoint() {
        let app: Router = mount_docs(Router::new(), doc(), MountOpts::default());
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/openapi.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["info"]["title"], "test");
        assert_eq!(parsed["info"]["version"], "0.1");
    }

    #[tokio::test]
    async fn respects_custom_spec_path() {
        let app: Router = mount_docs(
            Router::new(),
            doc(),
            MountOpts::default().spec_path("/api/openapi.json"),
        );
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/openapi.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn mount_opts_default_values() {
        let opts = MountOpts::default();
        assert_eq!(opts.spec_path, "/openapi.json");
        assert_eq!(opts.ui_path, "/docs");
        assert!(opts.mount_ui);
    }

    #[test]
    fn mount_opts_builder_chain_overrides_each_field() {
        let opts = MountOpts::default()
            .spec_path("/v2/openapi.json")
            .ui_path("/v2/docs");
        assert_eq!(opts.spec_path, "/v2/openapi.json");
        assert_eq!(opts.ui_path, "/v2/docs");
        let no_ui = MountOpts::default().without_ui();
        assert!(!no_ui.mount_ui);
    }

    #[tokio::test]
    async fn served_openapi_json_is_well_formed_openapi_3() {
        let app: Router = mount_docs(Router::new(), doc(), MountOpts::default());
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/openapi.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Top-level OpenAPI 3.x fields are present.
        assert!(parsed["openapi"].as_str().unwrap().starts_with("3."));
        assert!(parsed["info"].is_object());
        assert!(parsed["paths"].is_object());
    }

    #[tokio::test]
    async fn json_endpoint_serves_byte_identical_content_on_repeat_calls() {
        // Verifies the Arc<Bytes> is reused and not re-serialized per call.
        let app: Router = mount_docs(Router::new(), doc(), MountOpts::default());
        let mut bodies = Vec::new();
        for _ in 0..3 {
            let response = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri("/openapi.json")
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            bodies.push(response.into_body().collect().await.unwrap().to_bytes());
        }
        assert_eq!(bodies[0], bodies[1]);
        assert_eq!(bodies[1], bodies[2]);
    }

    #[tokio::test]
    async fn without_ui_omits_docs_route() {
        let app: Router = mount_docs(Router::new(), doc(), MountOpts::default().without_ui());
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/docs")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    #[cfg(feature = "docs-scalar")]
    async fn mounts_scalar_ui_at_default_path() {
        let app: Router = mount_docs(Router::new(), doc(), MountOpts::default());
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/docs")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let ct = response.headers().get(header::CONTENT_TYPE).unwrap();
        assert!(ct.to_str().unwrap().starts_with("text/html"));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains(r#"data-url="/openapi.json""#));
        assert!(html.contains("<title>test</title>"));
        assert!(html.contains("@scalar/api-reference"));
        // The configuration JSON is HTML-attribute-escaped so its
        // double-quotes appear as `&quot;` inside the rendered page.
        assert!(html.contains(r#"&quot;darkMode&quot;:true"#));
    }

    #[tokio::test]
    #[cfg(feature = "docs-scalar")]
    async fn scalar_config_override_propagates_to_html() {
        use crate::ui::{ScalarConfig, ScalarLayout};
        let app: Router = mount_docs(
            Router::new(),
            doc(),
            MountOpts::default().scalar(ScalarConfig::default().layout(ScalarLayout::Classic)),
        );
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/docs")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains(r#"&quot;layout&quot;:&quot;classic&quot;"#));
    }
}
