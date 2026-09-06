//! Unioning the response maps of nested `ApiError` enums.
//!
//! `#[api(transparent)]` lets one variant delegate to a nested error
//! type. `IntoResponses` then has to answer for both: the outer enum's
//! own variants *and* everything the nested type can return. Statuses
//! that appear in only one side are a plain insert; a status both sides
//! declare has to be merged, or the document loses whichever half lost
//! the race.
//!
//! Merging happens here, on built `utoipa` values, rather than in the
//! derive — the shape is the same envelope
//! `#[derive(ApiError)]` emits, so the union is ordinary code over
//! ordinary structs instead of `quote!` generating it.

use std::collections::BTreeMap;

use utoipa::openapi::schema::{OneOf, Schema};
use utoipa::openapi::{RefOr, Response};

/// Response map as `IntoResponses` returns it.
type ResponseMap = BTreeMap<String, RefOr<Response>>;

/// Merge `inner` into `outer`, unioning any status both declare.
///
/// The outer enum owns its statuses: on a collision the outer response's
/// description and examples stay, and the inner's `code` enum values and
/// `error` variants are added to them. That keeps an endpoint's own
/// documentation authoritative while making the nested type's failure
/// modes reachable.
pub fn merge_response_maps(outer: &mut ResponseMap, inner: ResponseMap) {
    for (status, incoming) in inner {
        match outer.remove(&status) {
            None => {
                outer.insert(status, incoming);
            }
            Some(existing) => {
                outer.insert(status, merge_responses(existing, incoming));
            }
        }
    }
}

/// Union two responses at one status.
///
/// A `Ref` on either side has nothing to merge into — the schema lives
/// elsewhere in the document — so the outer one is kept rather than
/// silently replaced.
fn merge_responses(outer: RefOr<Response>, inner: RefOr<Response>) -> RefOr<Response> {
    let (mut outer_response, inner_response) = match (outer, inner) {
        (RefOr::T(outer), RefOr::T(inner)) => (outer, inner),
        (outer, _) => return outer,
    };

    for (media_type, inner_content) in inner_response.content {
        let Some(outer_content) = outer_response.content.get_mut(&media_type) else {
            outer_response.content.insert(media_type, inner_content);
            continue;
        };

        // Examples are keyed by error code, so a union is safe: two
        // codes cannot collide unless they are the same failure.
        for (name, example) in inner_content.examples {
            outer_content.examples.entry(name).or_insert(example);
        }

        if let (Some(outer_schema), Some(inner_schema)) =
            (outer_content.schema.as_mut(), inner_content.schema)
        {
            merge_envelopes(outer_schema, inner_schema);
        }
    }

    RefOr::T(outer_response)
}

/// Union the `code` enum and the `error` `oneOf` of two envelopes.
///
/// Anything that is not the object envelope this derive emits is left
/// alone — a consumer who replaced the schema wholesale meant it.
fn merge_envelopes(outer: &mut RefOr<Schema>, inner: RefOr<Schema>) {
    let (RefOr::T(Schema::Object(outer_object)), RefOr::T(Schema::Object(inner_object))) =
        (outer, inner)
    else {
        return;
    };

    for (property, inner_value) in inner_object.properties {
        match property.as_str() {
            "code" => {
                if let Some(outer_value) = outer_object.properties.get_mut("code") {
                    union_enum_values(outer_value, inner_value);
                }
            }
            "error" => {
                if let Some(outer_value) = outer_object.properties.get_mut("error") {
                    union_one_of(outer_value, inner_value);
                }
            }
            // `message` and `status` are identical across envelopes at
            // the same status — nothing to union.
            _ => {}
        }
    }
}

/// Append the inner property's `enum` values to the outer's, in order,
/// without duplicating.
fn union_enum_values(outer: &mut RefOr<Schema>, inner: RefOr<Schema>) {
    let (RefOr::T(Schema::Object(outer_object)), RefOr::T(Schema::Object(inner_object))) =
        (outer, inner)
    else {
        return;
    };

    let Some(incoming) = inner_object.enum_values else {
        return;
    };
    let existing = outer_object.enum_values.get_or_insert_with(Vec::new);
    for value in incoming {
        if !existing.contains(&value) {
            existing.push(value);
        }
    }
}

/// Append the inner property's `oneOf` items to the outer's.
///
/// A non-`oneOf` schema on either side is treated as a single item, so a
/// status carrying exactly one variant still merges.
fn union_one_of(outer: &mut RefOr<Schema>, inner: RefOr<Schema>) {
    let mut items = match std::mem::replace(outer, RefOr::T(Schema::OneOf(OneOf::new()))) {
        RefOr::T(Schema::OneOf(one_of)) => one_of.items,
        other => vec![other],
    };

    match inner {
        RefOr::T(Schema::OneOf(one_of)) => items.extend(one_of.items),
        other => items.push(other),
    }

    let mut merged = OneOf::new();
    merged.items = items;
    *outer = RefOr::T(Schema::OneOf(merged));
}
