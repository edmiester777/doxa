//! Unioning the response maps of nested `ApiError` enums, for `#[api(transparent)]`:
//! a status both sides declare is merged rather than overwritten.

use std::collections::BTreeMap;

use utoipa::openapi::schema::{OneOf, Schema};
use utoipa::openapi::{RefOr, Response};

/// Response map as `IntoResponses` returns it.
type ResponseMap = BTreeMap<String, RefOr<Response>>;

/// Merge `inner` into `outer`; on a shared status the outer description stays and the
/// inner's `code` values and `error` variants are added.
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

/// Union two responses at one status; a `Ref` on either side keeps the outer.
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

/// Union the `code` enum and `error` `oneOf` of two envelopes; any other schema is left alone.
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

/// Append the inner `oneOf` items to the outer's; a non-`oneOf` schema counts as one item.
fn union_one_of(outer: &mut RefOr<Schema>, inner: RefOr<Schema>) {
    let mut items = match std::mem::replace(outer, RefOr::T(Schema::OneOf(OneOf::new()))) {
        RefOr::T(Schema::OneOf(one_of)) => one_of.items,
        other => vec![other],
    };

    let incoming = match inner {
        RefOr::T(Schema::OneOf(one_of)) => one_of.items,
        other => vec![other],
    };
    for item in incoming {
        if !items.contains(&item) {
            items.push(item);
        }
    }

    let mut merged = OneOf::new();
    merged.items = items;
    *outer = RefOr::T(Schema::OneOf(merged));
}
