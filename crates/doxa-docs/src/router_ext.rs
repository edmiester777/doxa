//! Extension trait that lets [`OpenApiRouter`] attach a
//! [`DocumentedLayer`] in one call. The contribution is read off the
//! layer itself and stamped onto every operation currently present in
//! the router — same snapshot semantic as
//! [`axum::Router::layer`](axum::Router::layer), so the headers,
//! responses, and security entries land on exactly the routes the
//! layer covers.

use std::convert::Infallible;

use axum::extract::Request;
use axum::response::IntoResponse;
use axum::routing::Route;
use tower::{Layer, Service};
use utoipa_axum::router::OpenApiRouter;

use crate::contribution::{apply_contribution, DocumentedLayer, LayerContribution};

/// Adds [`OpenApiRouterExt::layer_documented`] and
/// [`OpenApiRouterExt::tag_all`] to [`OpenApiRouter`]. Implemented
/// for every state type the underlying router supports.
pub trait OpenApiRouterExt<S>: Sized {
    /// Apply `layer` exactly like
    /// [`OpenApiRouter::layer`](OpenApiRouter::layer), and stamp
    /// `layer.contribution()` onto every operation **currently
    /// present** in the router. Routes added after this call (via
    /// further [`merge`](OpenApiRouter::merge),
    /// [`nest`](OpenApiRouter::nest), or
    /// [`route`](OpenApiRouter::route)) are unaffected — same
    /// semantic as [`axum::Router::layer`].
    ///
    /// Convention: build the router up with all routes first, then
    /// call `layer_documented` last. The
    /// `layer_documented_only_affects_routes_present_before_call`
    /// regression test pins this behavior in CI.
    fn layer_documented<L>(self, layer: L) -> Self
    where
        L: Layer<Route> + DocumentedLayer + Clone + Send + Sync + 'static,
        L::Service: Service<Request> + Clone + Send + Sync + 'static,
        <L::Service as Service<Request>>::Response: IntoResponse + 'static,
        <L::Service as Service<Request>>::Error: Into<Infallible> + 'static,
        <L::Service as Service<Request>>::Future: Send + 'static;

    /// Stamp `tag` onto every operation **currently present** in the
    /// router. Same snapshot semantic as [`Self::layer_documented`] —
    /// routes added after this call are unaffected.
    ///
    /// Typical use is inside a module's `routes()` function so the
    /// tag is declared once per module rather than on every handler:
    ///
    /// ```rust,ignore
    /// pub fn routes() -> OpenApiRouter<AppState> {
    ///     OpenApiRouter::new()
    ///         .routes(routes!(list_models, get_model))
    ///         .tag_all("Models")
    /// }
    /// ```
    ///
    /// Handler-level tags (from `tag = "..."` or `tags(...)` in the
    /// macro) merge with the router-level tag — they do not replace
    /// each other. Duplicate tags are deduplicated.
    fn tag_all(self, tag: impl Into<String>) -> Self;
}

impl<S: Clone + Send + Sync + 'static> OpenApiRouterExt<S> for OpenApiRouter<S> {
    fn layer_documented<L>(mut self, layer: L) -> Self
    where
        L: Layer<Route> + DocumentedLayer + Clone + Send + Sync + 'static,
        L::Service: Service<Request> + Clone + Send + Sync + 'static,
        <L::Service as Service<Request>>::Response: IntoResponse + 'static,
        <L::Service as Service<Request>>::Error: Into<Infallible> + 'static,
        <L::Service as Service<Request>>::Future: Send + 'static,
    {
        let contribution = layer.contribution();
        if !contribution.is_empty() {
            apply_contribution(self.get_openapi_mut(), &contribution);
        }
        self.layer(layer)
    }

    fn tag_all(mut self, tag: impl Into<String>) -> Self {
        let contribution = LayerContribution::new().with_tag(tag);
        apply_contribution(self.get_openapi_mut(), &contribution);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contribution::LayerContribution;
    use crate::headers::HeaderParam;

    use std::task::{Context, Poll};

    use axum::body::Body;
    use axum::http::Response as HttpResponse;
    use tower::Layer;
    use utoipa::openapi::path::{HttpMethod, OperationBuilder, PathItem};
    use utoipa::openapi::response::Responses;
    use utoipa::openapi::PathsBuilder;
    use utoipa_axum::router::OpenApiRouter;

    /// Mock layer + service that does nothing on the runtime side but
    /// announces a known contribution. Lets us assert what
    /// `layer_documented` injects without spinning up real middleware.
    #[derive(Clone)]
    struct MockDocLayer {
        header_name: &'static str,
    }

    impl DocumentedLayer for MockDocLayer {
        fn contribution(&self) -> LayerContribution {
            LayerContribution::new().with_header(HeaderParam::required(self.header_name))
        }
    }

    impl<Inner> Layer<Inner> for MockDocLayer {
        type Service = MockDocService<Inner>;
        fn layer(&self, inner: Inner) -> Self::Service {
            MockDocService { inner }
        }
    }

    #[derive(Clone)]
    struct MockDocService<Inner> {
        inner: Inner,
    }

    impl<Inner> Service<Request> for MockDocService<Inner>
    where
        Inner: Service<Request, Response = HttpResponse<Body>, Error = Infallible>
            + Clone
            + Send
            + 'static,
        Inner::Future: Send + 'static,
    {
        type Response = HttpResponse<Body>;
        type Error = Infallible;
        type Future = Inner::Future;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.poll_ready(cx)
        }
        fn call(&mut self, req: Request) -> Self::Future {
            self.inner.call(req)
        }
    }

    fn router_with_path(path: &str) -> OpenApiRouter {
        let item = PathItem::new(HttpMethod::Get, OperationBuilder::new().build());
        let paths = PathsBuilder::new().path(path, item).build();
        let openapi = utoipa::openapi::OpenApiBuilder::new().paths(paths).build();
        OpenApiRouter::with_openapi(openapi)
    }

    fn op_for(router: &OpenApiRouter, path: &str) -> utoipa::openapi::path::Operation {
        router
            .get_openapi()
            .paths
            .paths
            .get(path)
            .expect("path present")
            .get
            .as_ref()
            .expect("get operation present")
            .clone()
    }

    fn header_names(op: &utoipa::openapi::path::Operation) -> Vec<String> {
        op.parameters
            .as_ref()
            .map(|params| params.iter().map(|p| p.name.clone()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn layer_documented_stamps_contribution_on_current_operations() {
        let router =
            router_with_path("/widgets").layer_documented(MockDocLayer { header_name: "X-A" });

        let op = op_for(&router, "/widgets");
        assert!(header_names(&op).iter().any(|n| n == "X-A"));
    }

    #[test]
    fn layer_documented_only_affects_routes_present_before_call() {
        let router_a = router_with_path("/a");
        let router_b = router_with_path("/b");

        // Apply the documented layer BEFORE merging /b in.
        let merged = router_a
            .layer_documented(MockDocLayer { header_name: "X-A" })
            .merge(router_b);

        let op_a = op_for(&merged, "/a");
        let op_b = op_for(&merged, "/b");

        assert!(
            header_names(&op_a).iter().any(|n| n == "X-A"),
            "/a should have the layer's header"
        );
        assert!(
            !header_names(&op_b).iter().any(|n| n == "X-A"),
            "/b was merged after the layer; must not carry its header"
        );
    }

    #[test]
    fn multiple_layer_documented_calls_accumulate_per_route() {
        let router = router_with_path("/widgets")
            .layer_documented(MockDocLayer { header_name: "X-A" })
            .layer_documented(MockDocLayer { header_name: "X-B" });

        let op = op_for(&router, "/widgets");
        let names = header_names(&op);
        assert!(names.iter().any(|n| n == "X-A"), "X-A from first layer");
        assert!(names.iter().any(|n| n == "X-B"), "X-B from second layer");
    }

    /// Regression test for the common merge pattern: build a base
    /// router (`public`), build a separate group, apply a documented
    /// layer to the group, then merge the layered group INTO the base
    /// (`app = public; app.merge(protected.layer_documented(...))`).
    /// Confirms the stamped contribution survives merging from the
    /// "source" side into a receiver that never saw the layer.
    #[test]
    fn layer_documented_contribution_survives_merge_into_base() {
        let base = router_with_path("/health");
        let protected = router_with_path("/api/v1/models")
            .layer_documented(MockDocLayer { header_name: "X-A" });

        let merged = base.merge(protected);

        let health_op = op_for(&merged, "/health");
        let models_op = op_for(&merged, "/api/v1/models");

        assert!(
            !header_names(&health_op).iter().any(|n| n == "X-A"),
            "base route /health must not carry the layer's contribution",
        );
        assert!(
            header_names(&models_op).iter().any(|n| n == "X-A"),
            "merged-in route /api/v1/models must carry the layer's contribution",
        );
    }

    #[test]
    fn documented_layer_with_empty_contribution_is_pure_layer_application() {
        #[derive(Clone)]
        struct EmptyLayer;
        impl DocumentedLayer for EmptyLayer {
            fn contribution(&self) -> LayerContribution {
                LayerContribution::new()
            }
        }
        impl<Inner> Layer<Inner> for EmptyLayer {
            type Service = MockDocService<Inner>;
            fn layer(&self, inner: Inner) -> Self::Service {
                MockDocService { inner }
            }
        }

        let router = router_with_path("/widgets").layer_documented(EmptyLayer);
        let op = op_for(&router, "/widgets");
        assert!(op.parameters.is_none(), "no parameters injected");
    }

    fn op_tags(op: &utoipa::openapi::path::Operation) -> Vec<String> {
        op.tags.clone().unwrap_or_default()
    }

    #[test]
    fn tag_all_stamps_tag_on_current_operations() {
        let router = router_with_path("/widgets").tag_all("Widgets");

        let op = op_for(&router, "/widgets");
        assert_eq!(op_tags(&op), vec!["Widgets".to_string()]);
    }

    #[test]
    fn tag_all_does_not_affect_routes_merged_after() {
        let router_a = router_with_path("/a").tag_all("A");
        let router_b = router_with_path("/b");

        let merged = router_a.merge(router_b);

        let op_a = op_for(&merged, "/a");
        let op_b = op_for(&merged, "/b");

        assert_eq!(op_tags(&op_a), vec!["A".to_string()]);
        assert!(
            op_tags(&op_b).is_empty(),
            "/b was merged after tag_all; must not carry the tag"
        );
    }

    #[test]
    fn tag_all_deduplicates_when_called_twice() {
        let router = router_with_path("/widgets")
            .tag_all("Widgets")
            .tag_all("Widgets");

        let op = op_for(&router, "/widgets");
        assert_eq!(op_tags(&op), vec!["Widgets".to_string()]);
    }

    #[test]
    fn tag_all_merges_with_existing_tags() {
        // Simulate a handler that already declared a tag by
        // pre-populating the operation's tags.
        let mut item = PathItem::new(
            HttpMethod::Get,
            OperationBuilder::new().tag("FromHandler").build(),
        );
        item.get.as_mut().unwrap().responses = Responses::new();
        let paths = PathsBuilder::new().path("/widgets", item).build();
        let openapi = utoipa::openapi::OpenApiBuilder::new().paths(paths).build();
        let router = OpenApiRouter::with_openapi(openapi).tag_all("FromRouter");

        let op = op_for(&router, "/widgets");
        let tags = op_tags(&op);
        assert!(tags.contains(&"FromHandler".to_string()));
        assert!(tags.contains(&"FromRouter".to_string()));
    }
}
