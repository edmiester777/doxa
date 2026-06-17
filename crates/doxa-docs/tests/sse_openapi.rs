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

// Generic payload: utoipa erases the type argument in `name()`, so the macro
// must compose the monomorphized component name (`Wrap_WrappedOnly`).
#[derive(Serialize, ToSchema)]
struct Wrap<T> {
    inner: T,
}

// Used *only* as a generic argument, so it is registered solely by the macro's
// recursive generic-argument registration (utoipa's generic `schemas()` skips
// the argument itself).
#[derive(Serialize, ToSchema)]
struct WrappedOnly {
    value: u8,
}

// `SseEvent` now owns `ToSchema` for the event enum (so it can emit the
// discriminated oneOf utoipa won't), so the `ToSchema` derive is dropped and
// variants must be unit or newtype.
#[derive(Serialize, SseEvent)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
#[allow(dead_code)]
enum MigrationEvent {
    Started(StartedPayload),
    Progress(ProgressPayload),
    #[sse(name = "finished")]
    Completed,
    Heartbeat,
    // Inline struct variant: fields are emitted directly (no payload type).
    Reticulated {
        splines: u32,
    },
    // Generic newtype payload: the component must $ref the monomorphized name.
    Wrapped(Wrap<WrappedOnly>),
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

    // Component is a discriminated oneOf of per-variant component $refs.
    let component = &v["components"]["schemas"]["MigrationEvent"];
    let one_of = component["oneOf"].as_array().expect("oneOf array");
    let refs: Vec<&str> = one_of
        .iter()
        .map(|b| b["$ref"].as_str().expect("oneOf branch is a $ref"))
        .collect();
    assert!(
        refs.contains(&"#/components/schemas/MigrationEvent_Started")
            && refs.contains(&"#/components/schemas/MigrationEvent_Heartbeat"),
        "oneOf should reference per-variant components: {refs:?}"
    );

    // Discriminator keyed on the serde tag, mapping serde tag values (not SSE
    // frame names) to the per-variant components.
    let disc = &component["discriminator"];
    assert_eq!(disc["propertyName"], "event");
    assert_eq!(
        disc["mapping"]["completed"], "#/components/schemas/MigrationEvent_Completed",
        "discriminator maps the serde tag value (`completed`), not the SSE name (`finished`): {disc:#?}"
    );

    // The Started variant component carries the tag literal + a $ref to the
    // payload type (which is itself registered).
    let started = &v["components"]["schemas"]["MigrationEvent_Started"];
    assert_eq!(started["properties"]["event"]["enum"][0], "started");
    assert_eq!(
        started["properties"]["data"]["$ref"],
        "#/components/schemas/StartedPayload"
    );
    assert!(v["components"]["schemas"]["StartedPayload"].is_object());

    // Inline struct variant: fields emitted directly under the content object,
    // no separate payload component.
    let retic = &v["components"]["schemas"]["MigrationEvent_Reticulated"];
    assert_eq!(retic["properties"]["event"]["enum"][0], "reticulated");
    assert!(
        retic["properties"]["data"]["properties"]["splines"].is_object(),
        "struct-variant fields are inlined under `data`: {retic:#?}"
    );

    // Generic newtype variant: utoipa's `name()` erases the type argument, so
    // the macro composes the monomorphized component name and registers it.
    let wrapped = &v["components"]["schemas"]["MigrationEvent_Wrapped"];
    assert_eq!(
        wrapped["properties"]["data"]["$ref"], "#/components/schemas/Wrap_WrappedOnly",
        "generic payload must $ref the monomorphized component, not bare `Wrap`: {wrapped:#?}"
    );
    let wrap = &v["components"]["schemas"]["Wrap_WrappedOnly"];
    assert!(
        wrap.is_object(),
        "the monomorphized generic payload component must be registered"
    );
    // The inner generic argument must also be registered — utoipa's generic
    // `schemas()` skips it, so the macro registers it under the name the
    // payload's own schema references.
    assert_eq!(
        wrap["properties"]["inner"]["$ref"], "#/components/schemas/WrappedOnly",
        "the generic argument is referenced by its own name: {wrap:#?}"
    );
    assert!(
        v["components"]["schemas"]["WrappedOnly"].is_object(),
        "the generic argument component must be registered so its $ref resolves"
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

#[test]
fn sse_response_documents_event_names() {
    let v = build(SseSpecVersion::V3_2);
    let resp = &v["paths"]["/migrations/stream"]["get"]["responses"]["200"];

    // Machine-readable event vocabulary on the content entry — the discrete
    // `event:` frame names the schema's payload union can't express.
    let names: Vec<&str> = resp["content"]["text/event-stream"]["x-sse-event-names"]
        .as_array()
        .expect("x-sse-event-names present")
        .iter()
        .map(|n| n.as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "started",
            "progress",
            "finished",
            "heartbeat",
            "reticulated",
            "wrapped"
        ]
    );

    // Human-readable description enumerates the frame names (the `#[sse(name)]`
    // override is honored).
    let desc = resp["description"].as_str().unwrap();
    assert!(
        desc.contains("`started`") && desc.contains("`finished`"),
        "description should enumerate event names: {desc}"
    );
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
    // The event-name vocabulary is version-independent — it documents the
    // stream, not the 3.1-vs-3.2 schema placement.
    assert!(
        sse["x-sse-event-names"].is_array(),
        "x-sse-event-names must survive in 3.1 mode too: {sse:#?}",
    );
}
