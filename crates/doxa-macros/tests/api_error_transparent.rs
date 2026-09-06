//! `#[api(transparent)]` — a variant that delegates its status, code and
//! audit outcome to a nested error type.
//!
//! Without it, "one shared error taxonomy" and "typed per-variant status
//! codes" are mutually exclusive: a cross-cutting set of failure modes
//! either gets copy-pasted into every endpoint enum, or gets nested under
//! one variant whose single literal status flattens all of them.

use axum::body::to_bytes;
use axum::response::IntoResponse;
use serde::Serialize;
use utoipa::{IntoResponses, ToSchema};

use doxa::ApiError;

/// The shared taxonomy: raised by a middleware stack, not by any one
/// endpoint, and reused across every endpoint enum.
#[derive(Debug, thiserror::Error, Serialize, ApiError, ToSchema)]
enum ApiFault {
    #[error("rate limited")]
    #[api(status = 429, code = "rate_limited", outcome = "denied")]
    RateLimited,

    #[error("table busy")]
    #[api(status = 409, code = "table_busy")]
    TableBusy(String),
}

/// One endpoint's errors, sharing the taxonomy rather than restating it.
#[derive(Debug, thiserror::Error, Serialize, ApiError, ToSchema)]
enum SyncError {
    #[error("no such pipeline: {0}")]
    #[api(status = 404, code = "pipeline_not_found")]
    PipelineNotFound(String),

    /// Same status as a nested variant, so the two have to merge rather
    /// than one winning.
    #[error("pipeline is already running")]
    #[api(status = 409, code = "pipeline_running")]
    PipelineRunning,

    // serde requires untagged variants last, which is also where a
    // catch-all belongs.
    #[error(transparent)]
    #[api(transparent)]
    #[serde(untagged)]
    Fault(ApiFault),
}

// ---- IntoResponse delegates ------------------------------------------------

async fn rendered(error: SyncError) -> (u16, serde_json::Value) {
    let response = error.into_response();
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

/// The whole point: the nested variant's own status reaches the wire,
/// rather than collapsing to whatever the wrapper declared.
#[tokio::test]
async fn a_nested_variant_keeps_its_own_status_and_code() {
    let (status, body) = rendered(SyncError::Fault(ApiFault::RateLimited)).await;

    assert_eq!(status, 429);
    assert_eq!(body["status"], 429);
    assert_eq!(body["code"], "rate_limited");
}

/// Two nested variants with different statuses stay different — the bug
/// this replaces rendered both with one status.
#[tokio::test]
async fn nested_variants_do_not_collapse_to_one_status() {
    let (busy, _) = rendered(SyncError::Fault(ApiFault::TableBusy("t".into()))).await;
    let (limited, _) = rendered(SyncError::Fault(ApiFault::RateLimited)).await;

    assert_eq!((busy, limited), (409, 429));
}

/// The outer enum's own variants are untouched by delegation.
#[tokio::test]
async fn the_outer_variants_still_use_their_literals() {
    let (status, body) = rendered(SyncError::PipelineNotFound("p".into())).await;

    assert_eq!(status, 404);
    assert_eq!(body["code"], "pipeline_not_found");
}

/// At a status both sides declare, each still renders as itself — the
/// merge is a documentation concern, not a runtime one.
#[tokio::test]
async fn a_shared_status_still_renders_each_side_distinctly() {
    let (outer_status, outer) = rendered(SyncError::PipelineRunning).await;
    let (nested_status, nested) =
        rendered(SyncError::Fault(ApiFault::TableBusy("orders".into()))).await;

    assert_eq!((outer_status, nested_status), (409, 409));
    assert_eq!(outer["code"], "pipeline_running");
    assert_eq!(nested["code"], "table_busy");
}

/// Pairing `#[api(transparent)]` with `#[serde(untagged)]` keeps the
/// body flat, so consolidating shared modes into a nested enum is not an
/// SDK-visible change: `{"error": {"TableBusy": …}}`, not
/// `{"error": {"Fault": {"TableBusy": …}}}`.
#[tokio::test]
async fn the_wire_shape_does_not_gain_a_wrapper_level() {
    let (_, body) = rendered(SyncError::Fault(ApiFault::TableBusy("orders".into()))).await;

    assert_eq!(
        body["error"],
        serde_json::json!({ "TableBusy": "orders" }),
        "the nested variant serializes as itself",
    );
}

// ---- IntoResponses merges --------------------------------------------------

/// A status only the nested type declares still reaches the document —
/// otherwise the endpoint's spec omits statuses it can actually return.
#[test]
fn a_nested_only_status_is_documented() {
    let responses = SyncError::responses();
    assert!(
        responses.contains_key("429"),
        "declared only by the nested type: {:?}",
        responses.keys().collect::<Vec<_>>(),
    );
}

/// A status both sides declare merges: the `code` enum carries both
/// codes rather than whichever half was inserted last.
#[test]
fn a_shared_status_unions_both_sides() {
    let responses = SyncError::responses();
    let merged = serde_json::to_value(responses.get("409").expect("409 is declared")).unwrap();

    let codes = &merged["content"]["application/json"]["schema"]["properties"]["code"]["enum"];
    let codes: Vec<&str> = codes
        .as_array()
        .expect("code is an enum")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    assert!(codes.contains(&"pipeline_running"), "{codes:?}");
    assert!(codes.contains(&"table_busy"), "{codes:?}");
}

/// The `error` schema at a shared status offers both sides' variants.
#[test]
fn a_shared_status_unions_the_error_variants() {
    let responses = SyncError::responses();
    let merged = serde_json::to_value(responses.get("409").expect("409 is declared")).unwrap();

    let one_of = &merged["content"]["application/json"]["schema"]["properties"]["error"]["oneOf"];
    assert_eq!(
        one_of.as_array().map(Vec::len),
        Some(2),
        "both the outer and the nested variant are reachable: {merged}",
    );
}

/// The transparent variant contributes no status of its own — it is a
/// wrapper, not a failure mode.
#[test]
fn the_transparent_variant_declares_no_status_itself() {
    let responses = SyncError::responses();
    let mut statuses: Vec<&str> = responses.keys().map(String::as_str).collect();
    statuses.sort_unstable();

    assert_eq!(statuses, ["404", "409", "429"]);
}
