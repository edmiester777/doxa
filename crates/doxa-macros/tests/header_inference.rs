//! Tests for typed-header inference and the `headers(...)` macro
//! argument added in commit 7. Two angles:
//!
//! 1. Handlers that take a [`doxa::Header<H>`] extractor must end up
//!    with the corresponding header parameter on their operation in the
//!    rendered spec — entirely from inference, no macro arguments.
//! 2. Handlers that document a header without extracting it can use the
//!    explicit `#[get("/x", headers(MyHeader))]` form.

#![allow(dead_code)]

use axum::body::Body;
use axum::http::Request;
use axum::Router;
use doxa::{
    routes, ApiDocBuilder, DocumentedHeader, Header, MountDocsExt, MountOpts, OpenApiRouter,
};
use doxa_macros::get;
use http_body_util::BodyExt;
use tower::ServiceExt;

/// `X-Api-Key` marker. Title-case is intentional — Scalar / Swagger
/// renders it verbatim.
struct XApiKey;
impl DocumentedHeader for XApiKey {
    fn name() -> &'static str {
        "X-Api-Key"
    }
    fn description() -> &'static str {
        "Tenant API key"
    }
}

/// `X-Trace-Id` marker — declared but not extracted in the
/// `documented_only` handler.
struct XTraceId;
impl DocumentedHeader for XTraceId {
    fn name() -> &'static str {
        "X-Trace-Id"
    }
    fn description() -> &'static str {
        "Caller-supplied trace correlation id"
    }
}

// --- handlers ---

/// Handler that extracts the header AND has it documented in the
/// spec by virtue of using the `Header<H>` extractor. No macro
/// arguments mention the header — pure inference.
#[get("/with-extractor")]
async fn with_extractor(Header(_key, ..): Header<XApiKey>) -> &'static str {
    "ok"
}

/// Handler that documents the header via the `headers(...)` macro
/// argument without taking the extractor — useful when the value is
/// read from `HeaderMap` somewhere else.
#[get("/documented-only", headers(XTraceId))]
async fn documented_only() -> &'static str {
    "ok"
}

/// Handler that uses BOTH forms for two different headers. Asserts
/// the params block carries both entries.
#[get("/both", headers(XTraceId))]
async fn both(Header(_key, ..): Header<XApiKey>) -> &'static str {
    "ok"
}

/// Handler that names the same marker via signature AND macro arg.
/// Dedup must collapse to a single entry.
#[get("/dedupe", headers(XApiKey))]
async fn dedupe(Header(_key, ..): Header<XApiKey>) -> &'static str {
    "ok"
}

fn build_app() -> Router {
    let (router, openapi) = OpenApiRouter::<()>::new()
        .routes(routes!(with_extractor))
        .routes(routes!(documented_only))
        .routes(routes!(both))
        .routes(routes!(dedupe))
        .split_for_parts();
    let api_doc = ApiDocBuilder::new()
        .title("Header Inference API")
        .version("1.0.0")
        .merge(openapi)
        .build();
    router.mount_docs(api_doc, MountOpts::default())
}

async fn fetch_spec(app: Router) -> serde_json::Value {
    let response = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn header_params(spec: &serde_json::Value, path: &str) -> Vec<(String, String)> {
    let params = spec["paths"][path]["get"]["parameters"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    params
        .into_iter()
        .filter(|p| p["in"] == "header")
        .map(|p| {
            (
                p["name"].as_str().unwrap_or_default().to_string(),
                p["description"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

#[tokio::test]
async fn header_extractor_in_signature_emits_doc_header_entry() {
    let spec = fetch_spec(build_app()).await;
    let params = header_params(&spec, "/with-extractor");
    assert!(
        params.iter().any(|(n, _)| n == "X-Api-Key"),
        "X-Api-Key header parameter missing: {params:?}"
    );
}

#[tokio::test]
async fn header_extractor_runtime_name_resolution_carries_description() {
    let spec = fetch_spec(build_app()).await;
    let params = header_params(&spec, "/with-extractor");
    let (_, desc) = params
        .iter()
        .find(|(n, _)| n == "X-Api-Key")
        .expect("X-Api-Key present");
    assert_eq!(desc, "Tenant API key");
}

#[tokio::test]
async fn headers_macro_arg_emits_doc_header_entry() {
    let spec = fetch_spec(build_app()).await;
    let params = header_params(&spec, "/documented-only");
    assert!(
        params.iter().any(|(n, _)| n == "X-Trace-Id"),
        "X-Trace-Id header parameter missing: {params:?}"
    );
}

#[tokio::test]
async fn headers_macro_arg_combines_with_signature_inference() {
    let spec = fetch_spec(build_app()).await;
    let params = header_params(&spec, "/both");
    assert!(params.iter().any(|(n, _)| n == "X-Api-Key"));
    assert!(params.iter().any(|(n, _)| n == "X-Trace-Id"));
}

#[tokio::test]
async fn headers_macro_arg_dedupes_against_signature_extractor() {
    let spec = fetch_spec(build_app()).await;
    let params = header_params(&spec, "/dedupe");
    let api_key_count = params.iter().filter(|(n, _)| n == "X-Api-Key").count();
    assert_eq!(
        api_key_count, 1,
        "X-Api-Key listed in both signature and headers(...) — should dedupe to one entry"
    );
}
