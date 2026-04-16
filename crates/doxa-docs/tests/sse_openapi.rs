//! Integration tests for SSE OpenAPI emission.
//!
//! Covers both the default OpenAPI 3.2 output (`itemSchema` under
//! `text/event-stream`, root `openapi: "3.2.0"`) and the 3.1 opt-out
//! (`schema` under `text/event-stream`, root unchanged).

use std::convert::Infallible;

use axum::Json;
use doxa::{routes, ApiDocBuilder, OpenApiRouter, SseEvent, SseSpecVersion, SseStream, ToSchema};
use doxa_macros::get;
use futures::stream;
use serde::Serialize;

// ---- fixtures ---------------------------------------------------------------

#[derive(Serialize, ToSchema)]
struct StartedPayload {
    pipeline: String,
}

#[derive(Serialize, ToSchema)]
struct ProgressPayload {
    done: u64,
    total: u64,
}

#[derive(Serialize, ToSchema, SseEvent)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
#[allow(dead_code)]
enum MigrationEvent {
    Started(StartedPayload),
    Progress(ProgressPayload),
    #[sse(name = "finished")]
    Completed,
    Heartbeat,
}

#[derive(Serialize, ToSchema)]
struct Hello {
    message: String,
}

#[get("/migrations/stream")]
async fn stream_migration(
) -> SseStream<MigrationEvent, impl futures::Stream<Item = Result<MigrationEvent, Infallible>>> {
    SseStream::new(stream::iter(
        Vec::<Result<MigrationEvent, Infallible>>::new(),
    ))
}

#[get("/hello")]
async fn hello() -> Json<Hello> {
    Json(Hello {
        message: "hi".to_string(),
    })
}

fn build(version: SseSpecVersion) -> serde_json::Value {
    let (_router, openapi) = OpenApiRouter::<()>::new()
        .routes(routes!(stream_migration))
        .routes(routes!(hello))
        .split_for_parts();

    let doc = ApiDocBuilder::new()
        .title("t")
        .version("0.1")
        .sse_openapi_version(version)
        .merge(openapi)
        .build();
    serde_json::from_slice(&doc.spec_json).unwrap()
}

// ---- default (3.2)
// -----------------------------------------------------------

#[test]
fn default_output_is_openapi_3_2_with_item_schema() {
    let v = build(SseSpecVersion::V3_2);
    assert_eq!(v["openapi"].as_str().unwrap(), "3.2.0");

    let sse = &v["paths"]["/migrations/stream"]["get"]["responses"]["200"]["content"]
        ["text/event-stream"];
    assert!(
        sse["itemSchema"].is_object(),
        "expected itemSchema under text/event-stream: {sse:#?}"
    );
    assert!(
        sse.get("schema").is_none(),
        "schema should be replaced by itemSchema: {sse:#?}"
    );
    assert!(
        sse.get("x-sse-stream").is_none(),
        "marker must be stripped: {sse:#?}"
    );

    // itemSchema references the event enum component.
    let ref_path = sse["itemSchema"]["$ref"].as_str().unwrap();
    assert_eq!(ref_path, "#/components/schemas/MigrationEvent");

    // Component schema is a oneOf tagged on `event`.
    let component = &v["components"]["schemas"]["MigrationEvent"];
    assert!(
        component["oneOf"].is_array() || component["discriminator"].is_object(),
        "expected oneOf/discriminator on tagged enum: {component:#?}",
    );
}

#[test]
fn default_output_leaves_non_sse_endpoints_alone() {
    let v = build(SseSpecVersion::V3_2);
    let hello_200 = &v["paths"]["/hello"]["get"]["responses"]["200"]["content"]["application/json"];
    assert!(hello_200["schema"].is_object());
    assert!(hello_200.get("itemSchema").is_none());
    assert!(hello_200.get("x-sse-stream").is_none());
}

// ---- 3.1 opt-out
// -------------------------------------------------------------

#[test]
fn v3_1_opt_out_keeps_schema_and_does_not_upgrade_version() {
    let v = build(SseSpecVersion::V3_1);
    // utoipa emits 3.1 by default; we must not rewrite it.
    let version = v["openapi"].as_str().unwrap();
    assert!(version.starts_with("3.1"), "expected 3.1.x, got {version}",);

    let sse = &v["paths"]["/migrations/stream"]["get"]["responses"]["200"]["content"]
        ["text/event-stream"];
    assert!(
        sse["schema"].is_object(),
        "schema must stay at top level in 3.1 mode: {sse:#?}",
    );
    assert!(
        sse.get("itemSchema").is_none(),
        "itemSchema must NOT be set in 3.1 mode: {sse:#?}",
    );
    assert!(
        sse.get("x-sse-stream").is_none(),
        "marker must be stripped in both modes: {sse:#?}",
    );
}
