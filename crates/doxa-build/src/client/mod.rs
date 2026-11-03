//! A client crate generated from a server's OpenAPI document, in the crate's `build.rs`.
//!
//! ```ignore
//! fn main() {
//!     doxa_build::ClientSpec::from_server(orders_server::__doxa_spec())
//!         .types(|t| t.format("uuid", "uuid::Uuid"))
//!         .generate()
//!         .unwrap_or_else(|e| panic!("{e}"));
//! }
//! ```

mod readable;
mod routes;
mod spec;
mod types;

use std::collections::BTreeMap;
use std::path::PathBuf;

use proc_macro2::TokenStream;

/// What the client's types are where the spec alone would guess wrong.
#[derive(Debug, Default, Clone)]
pub struct TypeMap {
    formats: BTreeMap<String, String>,
    schemas: BTreeMap<String, String>,
}

impl TypeMap {
    /// Strings of `format` as the Rust type at `path`, e.g. `("uuid", "uuid::Uuid")`.
    pub fn format(mut self, format: &str, path: &str) -> Self {
        self.formats.insert(format.to_owned(), path.to_owned());
        self
    }

    /// The component schema `name` as a hand-written type instead of a generated one.
    pub fn schema(mut self, name: &str, path: &str) -> Self {
        self.schemas.insert(name.to_owned(), path.to_owned());
        self
    }
}

/// Why a client couldn't be generated.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GenerateError {
    /// The document isn't one the generator can read.
    #[error("the server's OpenAPI document doesn't parse: {0}")]
    Unreadable(String),
    /// A schema has a shape no Rust type is generated for.
    #[error(
        "schema `{schema}`, used by `{operation}`, {reason}\n  \
         fix: map it to a hand-written type with `.types(|t| t.schema(\"{schema}\", \"my_crate::Type\"))`"
    )]
    Unsupported {
        /// The schema's name, or where it sits inline.
        schema: String,
        /// The operation that reaches it.
        operation: String,
        /// What about it isn't supported.
        reason: String,
    },
    /// Several schemas have no Rust type, each named.
    #[error("{}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n"))]
    Many(Vec<GenerateError>),
    /// A path given to [`TypeMap`] isn't a Rust type.
    #[error("`{0}` given to `.types(…)` isn't a Rust type path")]
    BadPath(String),
    /// `OUT_DIR` is unset, so this isn't running in a build script.
    #[error("`OUT_DIR` is unset; call `generate()` from the client crate's build.rs")]
    NoOutDir,
    /// The generated file couldn't be written.
    #[error("writing {path}: {source}")]
    Write {
        /// Where.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
}

/// A document in JSON, such as a server's `/openapi.json`, read for [`ClientSpec::from_server`].
///
/// utoipa can't read back an any-value schema (`{}`), a 3.2 document, or 3.2's `itemSchema`, so
/// these are rewritten to the 3.1 forms it reads first.
pub fn openapi_from_json(json: &str) -> Result<utoipa::openapi::OpenApi, GenerateError> {
    let mut doc: serde_json::Value =
        serde_json::from_str(json).map_err(|e| GenerateError::Unreadable(e.to_string()))?;
    readable::document(&mut doc);
    serde_json::from_value(doc).map_err(|e| GenerateError::Unreadable(e.to_string()))
}

/// A client to generate from a server's OpenAPI document.
pub struct ClientSpec {
    spec: Result<spec::Spec, String>,
    types: TypeMap,
}

impl ClientSpec {
    /// The document a server's `#[doxa::spec]` function builds, read as `__doxa_spec()`.
    pub fn from_server(spec: utoipa::openapi::OpenApi) -> Self {
        let parsed = serde_json::to_value(&spec)
            .and_then(serde_json::from_value)
            .map_err(|e| e.to_string());
        ClientSpec {
            spec: parsed,
            types: TypeMap::default(),
        }
    }

    /// Override how schemas map to Rust types.
    pub fn types(mut self, f: impl FnOnce(TypeMap) -> TypeMap) -> Self {
        self.types = f(self.types);
        self
    }

    /// The client's source, for `doxa::include_client!()` to include.
    pub fn render(&self) -> Result<String, GenerateError> {
        let spec = self
            .spec
            .as_ref()
            .map_err(|e| GenerateError::Unreadable(e.clone()))?;
        let mut types = types::Types::new(spec, &self.types)?;
        let routes: TokenStream = routes::render(spec, &mut types)?;
        let defs = types.render()?;
        types.finish()?;
        Ok(quote::quote! {
            #defs
            #routes
        }
        .to_string())
    }

    /// Write the client to `OUT_DIR` and mark this crate as the client half.
    pub fn generate(self) -> Result<(), GenerateError> {
        let source = self.render()?;
        let dir = std::env::var_os("OUT_DIR").ok_or(GenerateError::NoOutDir)?;
        let path = PathBuf::from(dir).join("doxa_client.rs");
        std::fs::write(&path, source).map_err(|source| GenerateError::Write { path, source })?;
        println!("cargo::rustc-env=DOXA_ROLE=client");
        println!("cargo::rustc-cfg=doxa_client");
        println!("cargo::rustc-check-cfg=cfg(doxa_client)");
        println!("cargo::rerun-if-changed=build.rs");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(doc: serde_json::Value) -> Result<String, GenerateError> {
        ClientSpec::from_server(openapi_from_json(&doc.to_string()).unwrap()).render()
    }

    fn doc(body: serde_json::Value, schemas: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "openapi": "3.1.0",
            "info": { "title": "t", "version": "0" },
            "paths": { "/orders": { "post": {
                "operationId": "create_order",
                "requestBody": { "content": { "application/json": { "schema": body } } },
                "responses": { "204": { "description": "" } },
                "x-doxa": { "entities": [], "dry_run": false, "body": "json" }
            } } },
            "components": { "schemas": schemas }
        })
    }

    #[test]
    fn a_body_is_checked_against_its_schemas_constraints() {
        let out = client(doc(
            serde_json::json!({ "$ref": "#/components/schemas/NewOrder" }),
            serde_json::json!({ "NewOrder": {
                "type": "object",
                "required": ["name"],
                "properties": { "name": { "type": "string", "minLength": 1, "maxLength": 40 } }
            } }),
        ))
        .unwrap();
        assert!(out.contains("pub struct NewOrder"), "{out}");
        assert!(out.contains("length is lower than {}"), "{out}");
        assert!(
            out.contains("Spec (Json (body)) : Spec < Json < NewOrder >>"),
            "{out}"
        );
    }

    #[test]
    fn a_shape_with_no_rust_type_names_the_schema_and_the_route() {
        let err = client(doc(
            serde_json::json!({ "$ref": "#/components/schemas/Either" }),
            serde_json::json!({ "Either": { "allOf": [
                { "type": "string" },
                { "type": "object", "properties": { "a": { "type": "string" } } }
            ] } }),
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("schema `Either`, used by `create_order`"),
            "{err}"
        );
        assert!(err.contains(".types(|t| t.schema(\"Either\""), "{err}");
    }

    #[test]
    fn a_tag_every_branch_holds_a_different_constant_of_is_inferred() {
        let branch = |kind: &str, field: &str| {
            serde_json::json!({ "type": "object", "required": ["kind", field], "properties": {
                "kind": { "type": "string", "enum": [kind] },
                field: { "type": "string" }
            } })
        };
        let out = client(doc(
            serde_json::json!({ "$ref": "#/components/schemas/Location" }),
            serde_json::json!({ "Location": { "oneOf": [
                branch("chunk", "path"),
                branch("http", "url")
            ] } }),
        ))
        .unwrap();
        assert!(out.contains("# [serde (tag = \"kind\")]"), "{out}");
        assert!(
            out.contains(
                "# [serde (rename = \"chunk\")] Chunk { path : :: std :: string :: String , }"
            ),
            "{out}"
        );
    }

    #[test]
    fn a_one_of_told_apart_only_by_shape_is_untagged() {
        let out = client(doc(
            serde_json::json!({ "$ref": "#/components/schemas/Cursor" }),
            serde_json::json!({
                "Cursor": { "oneOf": [
                    { "type": "integer" },
                    { "type": "string" },
                    { "$ref": "#/components/schemas/Page" },
                    { "type": "null" }
                ] },
                "Page": { "type": "object", "properties": { "a": { "type": "string" }, "b": { "type": "string" } } }
            }),
        ))
        .unwrap();
        assert!(
            out.contains(
                "# [serde (untagged)] # [non_exhaustive] pub enum Cursor { Integer (i64) , \
                 String (:: std :: string :: String) , Page (Page) , Null , }"
            ),
            "{out}"
        );
    }

    #[test]
    fn every_schema_without_a_rust_type_is_named_in_one_run() {
        let missing = |name: &str| {
            serde_json::json!({ "type": "object", "properties": {
                "amount": { "$ref": format!("#/components/schemas/{name}") }
            } })
        };
        let err = client(doc(
            serde_json::json!({ "$ref": "#/components/schemas/Order" }),
            serde_json::json!({
                "Order": { "type": "object", "properties": {
                    "first": { "$ref": "#/components/schemas/First" },
                    "second": { "$ref": "#/components/schemas/Second" }
                } },
                "First": missing("Money"),
                "Second": missing("Currency")
            }),
        ))
        .unwrap_err();
        assert!(
            matches!(&err, GenerateError::Many(e) if e.len() == 2),
            "{err}"
        );
        let err = err.to_string();
        assert!(err.contains("schema `Money`"), "{err}");
        assert!(err.contains("schema `Currency`"), "{err}");
    }

    #[test]
    fn an_all_of_merges_its_objects_and_flattens_its_enums() {
        let out = client(doc(
            serde_json::json!({ "$ref": "#/components/schemas/Settings" }),
            serde_json::json!({
                "Settings": { "allOf": [
                    { "$ref": "#/components/schemas/Sampling" },
                    { "type": "object", "required": ["model"], "properties": { "model": { "type": "string" } } },
                    { "oneOf": [
                        { "type": "object", "required": ["Fast"], "properties": { "Fast": { "type": "integer" } } },
                        { "type": "object", "required": ["Slow"], "properties": { "Slow": { "type": "integer" } } }
                    ] }
                ] },
                "Sampling": {
                    "type": "object",
                    "description": "How tokens are picked.",
                    "properties": { "top_k": { "type": "integer" } }
                }
            }),
        ))
        .unwrap();
        assert!(
            out.contains("# [doc = \" How tokens are picked.\"] # [derive"),
            "{out}"
        );
        assert!(out.contains("pub struct Settings"), "{out}");
        assert!(
            out.contains("pub model : :: std :: string :: String"),
            "{out}"
        );
        assert!(
            out.contains("pub top_k : :: core :: option :: Option < i64 >"),
            "{out}"
        );
        assert!(
            out.contains("# [serde (flatten)] pub kind : SettingsKind"),
            "{out}"
        );
        assert!(out.contains("pub enum SettingsKind"), "{out}");
    }

    #[test]
    fn a_tagged_branch_of_another_type_and_the_tag_is_a_newtype_variant() {
        let tag = |v: &str| {
            serde_json::json!({ "type": "object", "required": ["type"], "properties": {
                "type": { "type": "string", "enum": [v] }
            } })
        };
        let out = client(doc(
            serde_json::json!({ "$ref": "#/components/schemas/Event" }),
            serde_json::json!({
                "Event": {
                    "oneOf": [
                        { "$ref": "#/components/schemas/Event_Started" },
                        { "$ref": "#/components/schemas/Event_Failed" }
                    ],
                    "discriminator": { "propertyName": "type" }
                },
                "Event_Started": { "allOf": [{ "$ref": "#/components/schemas/Started" }, tag("started")] },
                "Event_Failed": { "allOf": [
                    { "type": "object", "required": ["reason"], "properties": { "reason": { "type": "string" } } },
                    tag("failed")
                ] },
                "Started": { "type": "object", "properties": { "run": { "type": "string" } } }
            }),
        ))
        .unwrap();
        assert!(out.contains("# [serde (tag = \"type\")]"), "{out}");
        assert!(
            out.contains("# [serde (rename = \"started\")] Started (Started)"),
            "{out}"
        );
        assert!(
            out.contains(
                "# [serde (rename = \"failed\")] Failed { reason : :: std :: string :: String , }"
            ),
            "{out}"
        );
        assert!(out.contains("pub struct Started"), "{out}");
    }

    #[test]
    fn a_variant_named_self_is_no_keyword() {
        let out = client(doc(
            serde_json::json!({ "$ref": "#/components/schemas/Target" }),
            serde_json::json!({ "Target": { "type": "string", "enum": ["self_", "other"] } }),
        ))
        .unwrap();
        assert!(
            out.contains("# [serde (rename = \"self_\")] Self_ ,"),
            "{out}"
        );
    }

    #[test]
    fn required_and_nullable_choose_the_fields_type() {
        let out = client(doc(
            serde_json::json!({ "$ref": "#/components/schemas/Patch" }),
            serde_json::json!({
                "Patch": {
                    "type": "object",
                    "required": ["id", "parent"],
                    "properties": {
                        "id": { "type": "string" },
                        "parent": { "type": ["string", "null"] },
                        "name": { "type": "string" },
                        "note": { "type": ["string", "null"] },
                        "line": { "oneOf": [{ "type": "null" }, { "$ref": "#/components/schemas/Line" }] }
                    }
                },
                "Line": { "type": "object", "properties": { "n": { "type": "integer" } } }
            }),
        ))
        .unwrap();
        let opt = ":: core :: option :: Option";
        let double = "with = \"::doxa::wire::double_option\"";
        assert!(out.contains("pub id : :: std :: string :: String"), "{out}");
        assert!(
            out.contains(&format!(
                "pub parent : {opt} < :: std :: string :: String >"
            )),
            "{out}"
        );
        assert!(
            out.contains(&format!("pub name : {opt} < :: std :: string :: String >")),
            "{out}"
        );
        assert!(
            out.contains(&format!(
                "{double})] pub note : {opt} < {opt} < :: std :: string :: String > >"
            )),
            "{out}"
        );
        assert!(
            out.contains(&format!("{double})] pub line : {opt} < {opt} < Line > >")),
            "{out}"
        );
        assert_eq!(out.matches(double).count(), 2, "{out}");
    }

    #[test]
    fn a_nullable_component_is_an_option_of_its_branch() {
        let out = client(doc(
            serde_json::json!({ "$ref": "#/components/schemas/Wrap" }),
            serde_json::json!({
                "Wrap": {
                    "type": "object",
                    "required": ["line"],
                    "properties": { "line": { "$ref": "#/components/schemas/MaybeLine" } }
                },
                "MaybeLine": { "oneOf": [{ "$ref": "#/components/schemas/Line" }, { "type": "null" }] },
                "Line": { "type": "object", "properties": { "n": { "type": "integer" } } }
            }),
        ))
        .unwrap();
        assert!(
            out.contains("pub line : :: core :: option :: Option < Line >"),
            "{out}"
        );
        assert!(!out.contains("MaybeLine"), "{out}");
    }

    #[test]
    fn a_query_parameter_is_never_null() {
        let mut d = doc(serde_json::json!({}), serde_json::json!({}));
        d["paths"]["/orders"]["post"]["parameters"] = serde_json::json!([{
            "name": "contains", "in": "query", "required": false,
            "schema": { "type": ["string", "null"] }
        }]);
        let out = client(d).unwrap();
        assert!(
            out.contains(
                "pub contains : :: core :: option :: Option < :: std :: string :: String >"
            ),
            "{out}"
        );
        assert!(!out.contains("double_option"), "{out}");
    }

    #[test]
    fn a_mapped_schema_is_used_as_written() {
        let out = ClientSpec::from_server(
            openapi_from_json(
                &doc(
                    serde_json::json!({ "$ref": "#/components/schemas/NewOrder" }),
                    serde_json::json!({ "NewOrder": { "type": "object", "properties": {} } }),
                )
                .to_string(),
            )
            .unwrap(),
        )
        .types(|t| t.schema("NewOrder", "my_crate::Order"))
        .render()
        .unwrap();
        assert!(out.contains("Spec < Json < my_crate :: Order >>"), "{out}");
        assert!(!out.contains("pub struct NewOrder"), "{out}");
    }
}
