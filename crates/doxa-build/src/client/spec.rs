//! The parts of an OpenAPI document a client is generated from, parsed once into types.

use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct Spec {
    #[serde(default)]
    pub paths: BTreeMap<String, PathItem>,
    #[serde(default)]
    pub components: Components,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct Components {
    #[serde(default)]
    pub schemas: BTreeMap<String, Schema>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PathItem {
    pub get: Option<Operation>,
    pub put: Option<Operation>,
    pub post: Option<Operation>,
    pub delete: Option<Operation>,
    pub patch: Option<Operation>,
}

impl PathItem {
    pub fn operations(&self) -> impl Iterator<Item = (&'static str, &Operation)> {
        [
            ("get", &self.get),
            ("put", &self.put),
            ("post", &self.post),
            ("delete", &self.delete),
            ("patch", &self.patch),
        ]
        .into_iter()
        .filter_map(|(m, op)| op.as_ref().map(|op| (m, op)))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Operation {
    pub operation_id: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub parameters: Vec<Parameter>,
    pub request_body: Option<RequestBody>,
    #[serde(default)]
    pub responses: BTreeMap<String, Response>,
    #[serde(rename = "x-doxa")]
    pub doxa: Option<Meta>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Location {
    Path,
    Query,
    Header,
    Cookie,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Parameter {
    pub name: String,
    #[serde(rename = "in")]
    pub location: Location,
    #[serde(default)]
    pub required: bool,
    pub schema: Option<Schema>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RequestBody {
    #[serde(default)]
    pub content: BTreeMap<String, Media>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Response {
    #[serde(default)]
    pub content: BTreeMap<String, Media>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Media {
    pub schema: Option<Schema>,
}

/// `x-doxa`, as the server's method macros stamp it.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct Meta {
    #[serde(default = "yes")]
    pub client: bool,
    #[serde(default)]
    pub entities: Vec<String>,
    pub key: Option<KeyMeta>,
    #[serde(default)]
    pub dry_run: bool,
    pub stream: Option<String>,
    pub identity: Option<IdentityMeta>,
    pub error: Option<String>,
    pub body: Option<String>,
    pub query: Option<String>,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub(crate) struct KeyMeta {
    pub asset: String,
    pub entity: Option<String>,
    #[serde(rename = "type")]
    pub ty: String,
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct IdentityMeta {
    pub schema: String,
    pub entity: String,
    pub id: String,
    pub key: Option<IdentityKey>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct IdentityKey {
    #[serde(rename = "type")]
    pub ty: String,
    pub fields: Vec<String>,
}

/// One JSON Schema, as utoipa writes them.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Schema {
    #[serde(rename = "$ref")]
    pub reference: Option<String>,
    #[serde(rename = "type")]
    pub ty: Option<Types>,
    pub format: Option<String>,
    #[serde(default)]
    pub properties: BTreeMap<String, Schema>,
    #[serde(default)]
    pub required: Vec<String>,
    pub items: Option<Box<Schema>>,
    #[serde(default)]
    pub one_of: Vec<Schema>,
    #[serde(default)]
    pub all_of: Vec<Schema>,
    #[serde(default, rename = "enum")]
    pub values: Vec<Scalar>,
    pub discriminator: Option<Discriminator>,
    pub additional_properties: Option<Additional>,
    pub description: Option<String>,
    pub min_length: Option<u64>,
    pub max_length: Option<u64>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub min_items: Option<u64>,
    pub max_items: Option<u64>,
}

/// `type`: one name, or several with `"null"` among them.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub(crate) enum Types {
    One(String),
    Many(Vec<String>),
}

impl Types {
    /// The non-null type, and whether `null` is allowed too.
    pub fn split(&self) -> (Option<&str>, bool) {
        match self {
            Types::One(t) if t == "null" => (None, true),
            Types::One(t) => (Some(t), false),
            Types::Many(ts) => (
                ts.iter().map(String::as_str).find(|t| *t != "null"),
                ts.iter().any(|t| t == "null"),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub(crate) enum Scalar {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Null(()),
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Discriminator {
    pub property_name: String,
    #[serde(default)]
    pub mapping: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub(crate) enum Additional {
    Allowed(bool),
    Schema(Box<Schema>),
}

impl Schema {
    /// `#/components/schemas/Widget` as `Widget`.
    pub fn ref_name(&self) -> Option<&str> {
        self.reference
            .as_deref()
            .and_then(|r| r.strip_prefix("#/components/schemas/"))
    }
}
