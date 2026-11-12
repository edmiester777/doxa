//! A JSON document rewritten into the forms utoipa's deserializer accepts.

use serde_json::{Map, Value};

/// Keys that make a schema something other than any value.
const SHAPED: &[&str] = &["type", "$ref", "oneOf", "allOf", "anyOf"];

pub(super) fn document(doc: &mut Value) {
    let Some(root) = doc.as_object_mut() else {
        return;
    };
    if root
        .get("openapi")
        .and_then(Value::as_str)
        .is_some_and(|v| v.starts_with("3.2"))
    {
        root.insert("openapi".into(), "3.1.0".into());
    }
    if let Some(Value::Object(paths)) = root.get_mut("paths") {
        for item in paths.values_mut().filter_map(Value::as_object_mut) {
            for (key, op) in item.iter_mut() {
                match key.as_str() {
                    "parameters" => parameters(op),
                    _ => operation(op),
                }
            }
        }
    }
    if let Some(Value::Object(components)) = root.get_mut("components") {
        for (kind, entries) in components.iter_mut() {
            let Some(entries) = entries.as_object_mut() else {
                continue;
            };
            for entry in entries.values_mut() {
                match kind.as_str() {
                    "schemas" => schema(entry),
                    "responses" | "requestBodies" => body(entry),
                    "parameters" | "headers" => parameter(entry),
                    _ => {}
                }
            }
        }
    }
}

fn operation(op: &mut Value) {
    let Some(op) = op.as_object_mut() else {
        return;
    };
    if let Some(p) = op.get_mut("parameters") {
        parameters(p);
    }
    if let Some(b) = op.get_mut("requestBody") {
        body(b);
    }
    if let Some(Value::Object(responses)) = op.get_mut("responses") {
        responses.values_mut().for_each(body);
    }
}

fn parameters(list: &mut Value) {
    if let Some(list) = list.as_array_mut() {
        list.iter_mut().for_each(parameter);
    }
}

fn parameter(p: &mut Value) {
    if let Some(s) = p.get_mut("schema") {
        schema(s);
    }
}

/// A request body or response: its media types, and a response's headers.
fn body(b: &mut Value) {
    let Some(b) = b.as_object_mut() else {
        return;
    };
    if let Some(Value::Object(content)) = b.get_mut("content") {
        content
            .values_mut()
            .filter_map(Value::as_object_mut)
            .for_each(media);
    }
    if let Some(Value::Object(headers)) = b.get_mut("headers") {
        headers.values_mut().for_each(parameter);
    }
}

fn media(m: &mut Map<String, Value>) {
    if let Some(item) = m.remove("itemSchema") {
        m.insert("schema".into(), item);
    }
    if let Some(s) = m.get_mut("schema") {
        schema(s);
    }
}

fn schema(s: &mut Value) {
    let Some(obj) = s.as_object_mut() else {
        return;
    };
    // utoipa writes any value by leaving `type` out, and reads it back only from `null`.
    if !SHAPED.iter().any(|k| obj.contains_key(*k)) {
        obj.insert("type".into(), Value::Null);
    }
    for key in ["items", "not", "additionalProperties"] {
        if let Some(v) = obj.get_mut(key).filter(|v| v.is_object()) {
            schema(v);
        }
    }
    for key in ["oneOf", "allOf", "anyOf", "prefixItems"] {
        if let Some(Value::Array(list)) = obj.get_mut(key) {
            list.iter_mut().for_each(schema);
        }
    }
    if let Some(Value::Object(props)) = obj.get_mut("properties") {
        props.values_mut().for_each(schema);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn a_3_2_document_with_any_values_and_item_schemas_reads() {
        let doc = json!({
            "openapi": "3.2.0",
            "info": { "title": "t", "version": "0" },
            "paths": { "/events": { "get": {
                "responses": { "200": { "description": "", "content": {
                    "text/event-stream": { "itemSchema": { "$ref": "#/components/schemas/Ev" } }
                } } }
            } } },
            "components": { "schemas": {
                "Ev": { "type": "object", "properties": {
                    "anything": { "description": "free-form" },
                    "list": { "type": "array", "items": {} }
                } },
                "Value": {}
            } }
        });
        let api = super::super::openapi_from_json(&doc.to_string()).unwrap();
        let back = serde_json::to_value(&api).unwrap();
        assert_eq!(
            back["paths"]["/events"]["get"]["responses"]["200"]["content"]["text/event-stream"]
                ["schema"]["$ref"],
            "#/components/schemas/Ev"
        );
        assert_eq!(back["components"]["schemas"]["Value"], json!({}));
        assert_eq!(
            back["components"]["schemas"]["Ev"]["properties"]["anything"],
            json!({ "description": "free-form" })
        );
    }
}
