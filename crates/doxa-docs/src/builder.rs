//! Build an [`ApiDoc`] from project metadata plus a
//! [`utoipa::openapi::OpenApi`].
//!
//! [`ApiDocBuilder`] is the assembly point that takes title / version /
//! description / servers / security schemes plus an existing
//! [`utoipa::openapi::OpenApi`] (typically obtained from
//! [`utoipa_axum::router::OpenApiRouter::split_for_parts`]) and produces
//! an immutable [`ApiDoc`] whose JSON serialization lives in an
//! [`Arc<str>`] — built once at startup, shared across requests with
//! zero copying.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use bytes::Bytes;
use utoipa::openapi::security::{Flow, HttpAuthScheme, HttpBuilder, OAuth2, SecurityScheme};
use utoipa::openapi::{
    ContactBuilder, InfoBuilder, License, OpenApi, OpenApiBuilder, ServerBuilder,
};

/// Immutable, in-memory OpenAPI document with its serialized JSON form
/// pre-rendered into a [`Bytes`] buffer.
///
/// Cloning is cheap (`Bytes` is reference-counted, `openapi` is wrapped
/// in [`Arc`]). The JSON is serialized exactly once when
/// [`ApiDocBuilder::build`] is called and shared across all subsequent
/// reads — handlers built by [`crate::mount_docs`] hand the same
/// [`Bytes`] to every response with zero copying.
#[derive(Clone)]
pub struct ApiDoc {
    /// The structured OpenAPI document.
    pub openapi: Arc<OpenApi>,
    /// The serialized JSON form of [`Self::openapi`], pre-rendered for
    /// zero-copy serving from memory.
    pub spec_json: Bytes,
}

impl fmt::Debug for ApiDoc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiDoc")
            .field("title", &self.openapi.info.title)
            .field("version", &self.openapi.info.version)
            .field("paths", &self.openapi.paths.paths.len())
            .field("spec_json_bytes", &self.spec_json.len())
            .finish()
    }
}

/// Errors that can occur while [`ApiDocBuilder::build`]ing an [`ApiDoc`].
#[derive(Debug)]
pub enum BuildError {
    /// The structured OpenAPI document could not be serialized to JSON.
    /// In practice this only fails if a custom schema produced
    /// non-finite floats or otherwise invalid JSON values.
    Serialize(serde_json::Error),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Serialize(e) => write!(f, "failed to serialize OpenAPI document: {e}"),
        }
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialize(e) => Some(e),
        }
    }
}

/// Builder for an [`ApiDoc`].
///
/// Typical use:
///
/// ```no_run
/// use doxa::ApiDocBuilder;
/// use utoipa_axum::router::OpenApiRouter;
///
/// let (router, openapi) = OpenApiRouter::<()>::new().split_for_parts();
///
/// let api_doc = ApiDocBuilder::new()
///     .title("Example API")
///     .version(env!("CARGO_PKG_VERSION"))
///     .description("Example service")
///     .server("/", "current host")
///     .bearer_security("bearer")
///     .merge(openapi)
///     .build();
/// # let _ = (router, api_doc);
/// ```
#[derive(Default)]
pub struct ApiDocBuilder {
    title: Option<String>,
    version: Option<String>,
    description: Option<String>,
    contact_name: Option<String>,
    contact_email: Option<String>,
    contact_url: Option<String>,
    license_name: Option<String>,
    license_url: Option<String>,
    servers: Vec<(String, Option<String>)>,
    security_schemes: Vec<(String, SecurityScheme)>,
    /// Explicit tag metadata (name → description). When present, these
    /// descriptions override the auto-generated ones.
    tags: Vec<(String, String)>,
    /// Explicit tag groups. When non-empty, auto-grouping is disabled.
    tag_groups: Vec<(String, Vec<String>)>,
    /// Name for the default tag group that collects tags without a
    /// prefix delimiter. Defaults to `"API"` when auto-grouping.
    default_tag_group: Option<String>,
    /// Delimiter used to split tag names into `(group, name)` for
    /// auto-generated tag groups. Defaults to `": "`.
    tag_group_delimiter: Option<String>,
    schema_tags: Vec<(String, String)>,
    base: Option<OpenApi>,
    /// OpenAPI version used to render `text/event-stream` responses.
    /// Defaults to [`SseSpecVersion::V3_2`].
    sse_spec_version: SseSpecVersion,
}

/// OpenAPI spec version used to render Server-Sent Event (SSE) responses
/// in the generated document.
///
/// The runtime layer ([`crate::SseStream`], [`crate::SseEventMeta`])
/// is version-agnostic — the only effect of this choice is the shape
/// of the `text/event-stream` response in the rendered OpenAPI JSON
/// and, with [`Self::V3_2`], the document's root `openapi` field.
///
/// | Variant | Root `openapi` | SSE response key | Typical consumer |
/// |---|---|---|---|
/// | [`Self::V3_2`] | `"3.2.0"` | `itemSchema` | Scalar, Swagger UI 5.32+ |
/// | [`Self::V3_1`] | `"3.1.0"` | `schema` | Redoc, openapi-generator, older tooling |
///
/// Default is [`Self::V3_2`] because Scalar — the UI this crate mounts —
/// supports it natively and `itemSchema` is the documented way to
/// describe SSE streams. Downstream consumers that still need 3.1
/// (Redoc, openapi-generator, anything on swagger-parser < 3.2) should
/// opt out via [`ApiDocBuilder::sse_openapi_version`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SseSpecVersion {
    /// Emit OpenAPI 3.1-compatible SSE responses (`schema` under
    /// `text/event-stream`, root `openapi` left at utoipa's default
    /// `"3.1.0"`).
    V3_1,
    /// Emit OpenAPI 3.2 SSE responses (`itemSchema` under
    /// `text/event-stream`, root `openapi` set to `"3.2.0"`).
    #[default]
    V3_2,
}

impl ApiDocBuilder {
    /// Construct an empty builder. Title, version, and at least one path
    /// (via [`Self::merge`]) should be supplied before [`Self::build`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the API title that appears in the document's `info.title`.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set the API version that appears in the document's `info.version`.
    /// Conventionally `env!("CARGO_PKG_VERSION")`.
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set the API description that appears in the document's
    /// `info.description`. Markdown is supported by most viewers.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the contact name on the document's `info.contact`.
    pub fn contact_name(mut self, name: impl Into<String>) -> Self {
        self.contact_name = Some(name.into());
        self
    }

    /// Set the contact email on the document's `info.contact`.
    pub fn contact_email(mut self, email: impl Into<String>) -> Self {
        self.contact_email = Some(email.into());
        self
    }

    /// Set the contact URL on the document's `info.contact`.
    pub fn contact_url(mut self, url: impl Into<String>) -> Self {
        self.contact_url = Some(url.into());
        self
    }

    /// Set the license name on the document's `info.license`.
    pub fn license(mut self, name: impl Into<String>) -> Self {
        self.license_name = Some(name.into());
        self
    }

    /// Set the license URL on the document's `info.license`.
    pub fn license_url(mut self, url: impl Into<String>) -> Self {
        self.license_url = Some(url.into());
        self
    }

    /// Append a server entry. The first call sets the primary server;
    /// additional calls add alternates (staging, regional endpoints).
    pub fn server(mut self, url: impl Into<String>, description: impl Into<String>) -> Self {
        let description = description.into();
        let description = if description.is_empty() {
            None
        } else {
            Some(description)
        };
        self.servers.push((url.into(), description));
        self
    }

    /// Register an HTTP bearer security scheme under the given name,
    /// advertising the bearer format as `JWT`.
    ///
    /// The name is what handlers reference in their `security(...)`
    /// blocks (e.g., `security(("bearer" = []))`). Use
    /// [`bearer_security_with_format`](Self::bearer_security_with_format)
    /// to override the format (for example for opaque,
    /// introspection-based tokens).
    pub fn bearer_security(self, name: impl Into<String>) -> Self {
        self.bearer_security_with_format(name, "JWT")
    }

    /// Register an HTTP bearer security scheme under the given name with
    /// an explicit `bearerFormat` value.
    ///
    /// Use this when the bearer token format is not `JWT` — for example
    /// RFC 7662 opaque tokens validated by introspection, SAML bearer
    /// assertions, or a proprietary token format that clients should not
    /// attempt to decode locally.
    pub fn bearer_security_with_format(
        mut self,
        name: impl Into<String>,
        bearer_format: impl Into<String>,
    ) -> Self {
        let scheme = SecurityScheme::Http(
            HttpBuilder::new()
                .scheme(HttpAuthScheme::Bearer)
                .bearer_format(bearer_format)
                .build(),
        );
        self.security_schemes.push((name.into(), scheme));
        self
    }

    /// Register an arbitrary security scheme under the given name. Use
    /// this for OAuth flows, API keys, OpenID Connect, etc.
    pub fn security_scheme(mut self, name: impl Into<String>, scheme: SecurityScheme) -> Self {
        self.security_schemes.push((name.into(), scheme));
        self
    }

    /// Register an OAuth2 security scheme under the given name with
    /// the supplied [`Flow`] entries.
    ///
    /// Prefer this over [`Self::bearer_security`] when handlers
    /// declare per-operation scope requirements (e.g. via
    /// [`crate::DocOperationSecurity`] impls). The bearer-only HTTP
    /// scheme has no scope vocabulary, so OpenAPI client codegen
    /// (`openapi-generator`, `oapi-codegen`, etc.) silently drops any
    /// scopes attached to operation security entries. With an OAuth2
    /// scheme that publishes the scope vocabulary in
    /// `flows.<flow>.scopes`, generated clients carry the required
    /// scopes through to the token request.
    pub fn oauth2_security(
        mut self,
        name: impl Into<String>,
        flows: impl IntoIterator<Item = Flow>,
    ) -> Self {
        self.security_schemes
            .push((name.into(), SecurityScheme::OAuth2(OAuth2::new(flows))));
        self
    }

    /// Register a tag with a display name and description. Tags are
    /// auto-discovered from operations at build time, so this is only
    /// needed when you want to **override the description** shown in
    /// the docs UI for a specific tag.
    ///
    /// When provided, the tag's position in the `.tag()` call order
    /// determines its display order in the sidebar. Auto-discovered
    /// tags without an explicit `.tag()` entry appear after any
    /// explicitly registered ones, sorted alphabetically.
    pub fn tag(mut self, name: impl Into<String>, description: impl Into<String>) -> Self {
        self.tags.push((name.into(), description.into()));
        self
    }

    /// Manually group tags into a named section via the `x-tagGroups`
    /// vendor extension (Scalar + Redoc).
    ///
    /// **When any `.tag_group()` call is present, auto-grouping is
    /// disabled** — the caller takes full control of the grouping.
    /// Tags not assigned to any group may be hidden by some renderers
    /// (notably Redoc).
    ///
    /// When no `.tag_group()` calls are present, the builder
    /// auto-generates groups by splitting tag names on the delimiter
    /// (default `": "`). For example, `"Admin: Models"` is placed in
    /// the `"Admin"` group. Tags without the delimiter go into the
    /// default group (see [`Self::default_tag_group`]).
    pub fn tag_group(
        mut self,
        name: impl Into<String>,
        tags: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.tag_groups
            .push((name.into(), tags.into_iter().map(Into::into).collect()));
        self
    }

    /// Set the name of the default tag group for tags that don't
    /// contain the group delimiter. Defaults to `"API"` when
    /// auto-grouping is active.
    ///
    /// Only meaningful when no explicit `.tag_group()` calls are
    /// present (i.e., auto-grouping is active).
    pub fn default_tag_group(mut self, name: impl Into<String>) -> Self {
        self.default_tag_group = Some(name.into());
        self
    }

    /// Set the delimiter used to split tag names into
    /// `(group, display_name)` for auto-generated tag groups.
    /// Defaults to `": "`.
    ///
    /// For example, with delimiter `": "`, the tag `"Admin: Models"`
    /// is placed in the `"Admin"` group. With delimiter `"/"`, the
    /// tag `"Admin/Models"` would be placed in the `"Admin"` group.
    pub fn tag_group_delimiter(mut self, delimiter: impl Into<String>) -> Self {
        self.tag_group_delimiter = Some(delimiter.into());
        self
    }

    /// Manually assign a tag to a schema. The tag is injected as an
    /// `x-tags` vendor extension on the schema in
    /// `components.schemas`. Manual tags merge with auto-inferred
    /// tags (schemas automatically inherit tags from the operations
    /// that reference them).
    pub fn schema_tag(mut self, schema: impl Into<String>, tag: impl Into<String>) -> Self {
        self.schema_tags.push((schema.into(), tag.into()));
        self
    }

    /// Choose the OpenAPI spec version used to render `text/event-stream`
    /// responses produced by handlers returning [`crate::SseStream`].
    ///
    /// Defaults to [`SseSpecVersion::V3_2`] — the rendered document
    /// will carry `openapi: "3.2.0"` and SSE responses will place the
    /// event schema under `itemSchema`, matching the OpenAPI 3.2
    /// first-class SSE support. Call with [`SseSpecVersion::V3_1`] to
    /// downgrade for consumers that still require the 3.1 shape
    /// (Redoc, openapi-generator, swagger-parser < 3.2).
    ///
    /// # Example
    ///
    /// ```
    /// use doxa::{ApiDocBuilder, SseSpecVersion};
    ///
    /// // Render against OpenAPI 3.1 for consumers that don't yet
    /// // understand the 3.2 `itemSchema` keyword.
    /// let doc = ApiDocBuilder::new()
    ///     .title("Compat")
    ///     .version("1.0.0")
    ///     .sse_openapi_version(SseSpecVersion::V3_1)
    ///     .build();
    /// # let _ = doc;
    /// ```
    pub fn sse_openapi_version(mut self, version: SseSpecVersion) -> Self {
        self.sse_spec_version = version;
        self
    }

    /// Merge an existing [`OpenApi`] (typically from
    /// [`utoipa_axum::router::OpenApiRouter::split_for_parts`]) into the
    /// document. The merged document inherits paths, components, and
    /// tags from the supplied value.
    pub fn merge(mut self, openapi: OpenApi) -> Self {
        match self.base.as_mut() {
            Some(base) => base.merge(openapi),
            None => self.base = Some(openapi),
        }
        self
    }

    /// Finalize the builder, producing an [`ApiDoc`] with its JSON
    /// representation pre-serialized into an [`Arc<str>`]. Returns an
    /// error only if JSON serialization itself fails — which in practice
    /// requires a malformed custom schema to be present in the merged
    /// document.
    pub fn try_build(self) -> Result<ApiDoc, BuildError> {
        let mut doc = self.base.unwrap_or_else(|| OpenApiBuilder::new().build());

        // Apply info fields. We always rebuild `info` to ensure the
        // builder-supplied values win over whatever the merged base
        // brought along, since `merge` doesn't touch `info`.
        let mut info = InfoBuilder::new()
            .title(self.title.unwrap_or_else(|| doc.info.title.clone()))
            .version(self.version.unwrap_or_else(|| doc.info.version.clone()));
        if let Some(description) = self.description.or(doc.info.description.clone()) {
            info = info.description(Some(description));
        }
        if self.contact_name.is_some() || self.contact_email.is_some() || self.contact_url.is_some()
        {
            let mut contact = ContactBuilder::new();
            if let Some(name) = self.contact_name {
                contact = contact.name(Some(name));
            }
            if let Some(email) = self.contact_email {
                contact = contact.email(Some(email));
            }
            if let Some(url) = self.contact_url {
                contact = contact.url(Some(url));
            }
            info = info.contact(Some(contact.build()));
        }
        if let Some(name) = self.license_name {
            let mut license = License::new(name);
            if let Some(url) = self.license_url {
                license.url = Some(url);
            }
            info = info.license(Some(license));
        }
        doc.info = info.build();

        // Servers — replace whatever the merged document had if the
        // builder supplied any.
        if !self.servers.is_empty() {
            let servers = self
                .servers
                .into_iter()
                .map(|(url, description)| {
                    let mut server = ServerBuilder::new().url(url);
                    if let Some(description) = description {
                        server = server.description(Some(description));
                    }
                    server.build()
                })
                .collect::<Vec<_>>();
            doc.servers = Some(servers);
        }

        // Security schemes are stored under components. Initialize the
        // components container if it's missing.
        if !self.security_schemes.is_empty() {
            let components = doc
                .components
                .get_or_insert_with(utoipa::openapi::Components::new);
            for (name, scheme) in self.security_schemes {
                components.security_schemes.insert(name, scheme);
            }
        }

        // --- Tag discovery and grouping ---
        //
        // 1. Walk all operations to discover every tag in use.
        // 2. Build the top-level `tags` array: explicit `.tag()` entries first
        //    (preserving order), then auto-discovered tags sorted alphabetically.
        // 3. Build `x-tagGroups`: if the caller supplied explicit `.tag_group()`
        //    entries, use those verbatim. Otherwise, auto-generate groups by splitting
        //    tag names on the delimiter (default `": "`).
        {
            use utoipa::openapi::tag::TagBuilder;

            // Discover all tags from operations.
            let mut discovered: BTreeSet<String> = BTreeSet::new();
            for path_item in doc.paths.paths.values() {
                for op in crate::contribution::path_item_operations(path_item) {
                    if let Some(ref tags) = op.tags {
                        discovered.extend(tags.iter().cloned());
                    }
                }
            }

            // Build the explicit description map for lookups.
            let explicit_descs: HashMap<String, String> = self.tags.iter().cloned().collect();
            let explicit_order: Vec<String> = self.tags.iter().map(|(n, _)| n.clone()).collect();

            // Ordered tag list: explicit first (in call order), then
            // remaining discovered tags alphabetically.
            let mut ordered_tags: Vec<String> =
                Vec::with_capacity(explicit_order.len() + discovered.len());
            let mut seen: HashSet<&str> = HashSet::with_capacity(ordered_tags.capacity());
            for name in explicit_order.iter().chain(discovered.iter()) {
                if seen.insert(name.as_str()) {
                    ordered_tags.push(name.clone());
                }
            }

            // Emit top-level tags array.
            if !ordered_tags.is_empty() {
                doc.tags = Some(
                    ordered_tags
                        .iter()
                        .map(|name| {
                            let mut b = TagBuilder::new().name(name);
                            if let Some(desc) = explicit_descs.get(name) {
                                b = b.description(Some(desc.clone()));
                            }
                            b.build()
                        })
                        .collect(),
                );
            }

            // Emit x-tagGroups.
            let groups_json: Vec<serde_json::Value> = if !self.tag_groups.is_empty() {
                // Explicit groups — use verbatim.
                self.tag_groups
                    .into_iter()
                    .map(|(name, tags)| serde_json::json!({ "name": name, "tags": tags }))
                    .collect()
            } else if !ordered_tags.is_empty() {
                // Auto-generate groups from tag naming convention.
                let delimiter = self.tag_group_delimiter.as_deref().unwrap_or(": ");
                let default_group = self.default_tag_group.as_deref().unwrap_or("API");
                auto_tag_groups(&ordered_tags, delimiter, default_group)
            } else {
                Vec::new()
            };

            if !groups_json.is_empty() {
                use utoipa::openapi::extensions::ExtensionsBuilder;
                let ext = ExtensionsBuilder::new()
                    .add("x-tagGroups", serde_json::Value::Array(groups_json))
                    .build();
                match doc.extensions.as_mut() {
                    Some(existing) => existing.merge(ext),
                    None => doc.extensions = Some(ext),
                }
            }
        }

        // The `#[derive(ApiError)]`-generated `IntoResponses` impl
        // emits responses that reference `#/components/schemas/ApiErrorBody`
        // — register the actual schema here so the `$ref`s resolve.
        // Same for `ProblemDetails` because consumers may opt into it
        // for individual responses.
        //
        // `serde_json::Value` is the default `E` type parameter for
        // `ApiErrorBody<E>` on layer contributions and hand-rolled
        // error responses that don't carry a concrete error enum.
        // utoipa gives it the name `"Value"` but its
        // `ToSchema::schemas` impl is an empty default — register the
        // schema manually so `$ref: #/components/schemas/Value`
        // resolves.
        {
            use utoipa::PartialSchema;
            let components = doc
                .components
                .get_or_insert_with(utoipa::openapi::Components::new);
            components
                .schemas
                .entry("ApiErrorBody".to_string())
                .or_insert_with(<crate::ApiErrorBody as utoipa::PartialSchema>::schema);
            components
                .schemas
                .entry("ProblemDetails".to_string())
                .or_insert_with(crate::ProblemDetails::schema);
            components
                .schemas
                .entry("Value".to_string())
                .or_insert_with(<serde_json::Value as utoipa::PartialSchema>::schema);
        }

        // Auto-infer x-tags on schemas: walk operations, follow $ref
        // links in request bodies and responses, and assign each
        // referenced schema the tags of the operations that use it.
        // Manual `.schema_tag()` overrides merge with the inferred set.
        {
            use utoipa::openapi::RefOr;

            let mut schema_tag_map: HashMap<String, BTreeSet<String>> = HashMap::new();

            // Collect manual schema tags first.
            for (schema, tag) in self.schema_tags {
                schema_tag_map.entry(schema).or_default().insert(tag);
            }

            // Walk operations and collect $ref → tags.
            for path_item in doc.paths.paths.values() {
                for op in crate::contribution::path_item_operations(path_item) {
                    let op_tags = match &op.tags {
                        Some(t) if !t.is_empty() => t,
                        _ => continue,
                    };

                    // Collect refs from request body.
                    if let Some(ref body) = op.request_body {
                        collect_content_refs(body.content.values(), op_tags, &mut schema_tag_map);
                    }

                    // Collect refs from responses.
                    for resp in op.responses.responses.values() {
                        if let RefOr::T(ref response) = resp {
                            collect_content_refs(
                                response.content.values(),
                                op_tags,
                                &mut schema_tag_map,
                            );
                        }
                    }
                }
            }

            // Inject x-tags into each schema.
            if let Some(ref mut components) = doc.components {
                for (schema_name, tags) in &schema_tag_map {
                    if let Some(RefOr::T(ref mut schema)) = components.schemas.get_mut(schema_name)
                    {
                        if let Some(slot) = schema_extensions_mut(schema) {
                            let tags_json: Vec<serde_json::Value> = tags
                                .iter()
                                .map(|t| serde_json::Value::String(t.clone()))
                                .collect();
                            let ext = utoipa::openapi::extensions::ExtensionsBuilder::new()
                                .add("x-tags", serde_json::Value::Array(tags_json))
                                .build();
                            match slot.as_mut() {
                                Some(existing) => existing.merge(ext),
                                None => *slot = Some(ext),
                            }
                        }
                    }
                }
            }
        }

        // Serialize to a `Value` first so the SSE post-process can
        // inject OpenAPI 3.2 `itemSchema` entries without having to
        // model that field on utoipa's typed `OpenApi` (utoipa targets
        // 3.1 and has no `itemSchema` support as of 5.4). The rewrite
        // is isolated to a single function and operates on the same
        // representation we're about to freeze into `Bytes`, so the
        // cost is one intermediate `Value` tree — paid once at
        // startup, amortized over every doc request.
        let mut value = serde_json::to_value(&doc).map_err(BuildError::Serialize)?;
        apply_sse_spec_version(&mut value, self.sse_spec_version);
        let spec_json = serde_json::to_vec(&value).map_err(BuildError::Serialize)?;
        Ok(ApiDoc {
            openapi: Arc::new(doc),
            spec_json: Bytes::from(spec_json),
        })
    }

    /// Convenience wrapper around [`Self::try_build`] that panics on
    /// serialization failure. Suitable for startup code where a failed
    /// build is unrecoverable.
    pub fn build(self) -> ApiDoc {
        self.try_build().expect("OpenAPI document serialization")
    }
}

/// Post-process the serialized OpenAPI document's `Value` tree to
/// apply the selected [`SseSpecVersion`].
///
/// Walks every `paths.*.*.responses.*.content["text/event-stream"]`
/// entry. Entries marked with `x-sse-stream: true` are the ones
/// emitted by the method-shortcut macros for handlers returning
/// [`crate::SseStream`] — those are the only entries this function
/// rewrites. The marker is stripped in both version modes so it
/// never leaks to downstream consumers.
///
/// When targeting [`SseSpecVersion::V3_2`], the function also moves
/// the `schema` value under the key `itemSchema` and sets the
/// document root `openapi` field to `"3.2.0"`. The event-enum
/// schema itself is unchanged between the two modes — only its
/// location in the content entry differs — because utoipa already
/// emits a valid `oneOf`-of-tagged-variants shape under either
/// version.
///
/// TODO: when utoipa ships native OpenAPI 3.2 / `itemSchema`
/// emission, collapse this post-process into a thin shim (or remove
/// it entirely if utoipa exposes the selection at build time).
fn apply_sse_spec_version(value: &mut serde_json::Value, version: SseSpecVersion) {
    use serde_json::Value;

    let Some(obj) = value.as_object_mut() else {
        return;
    };

    let mut any_sse = false;
    if let Some(Value::Object(paths)) = obj.get_mut("paths") {
        for path_item in paths.values_mut() {
            let Some(path_obj) = path_item.as_object_mut() else {
                continue;
            };
            for op in path_obj.values_mut() {
                let Some(op_obj) = op.as_object_mut() else {
                    continue;
                };
                let Some(Value::Object(responses)) = op_obj.get_mut("responses") else {
                    continue;
                };
                for resp in responses.values_mut() {
                    let Some(resp_obj) = resp.as_object_mut() else {
                        continue;
                    };
                    let Some(Value::Object(content)) = resp_obj.get_mut("content") else {
                        continue;
                    };
                    let Some(Value::Object(sse_entry)) = content.get_mut("text/event-stream")
                    else {
                        continue;
                    };

                    // Only rewrite entries our macros marked — avoids
                    // mangling text/event-stream responses users
                    // declared by hand without going through
                    // `SseStream<E, …>`.
                    if !matches!(sse_entry.remove("x-sse-stream"), Some(Value::Bool(true))) {
                        continue;
                    }
                    any_sse = true;

                    if matches!(version, SseSpecVersion::V3_2) {
                        if let Some(schema) = sse_entry.remove("schema") {
                            sse_entry.insert("itemSchema".to_string(), schema);
                        }
                    }
                }
            }
        }
    }

    if any_sse && matches!(version, SseSpecVersion::V3_2) {
        obj.insert("openapi".to_string(), Value::String("3.2.0".to_string()));
    }
}

/// Auto-generate `x-tagGroups` JSON from a list of tag names by
/// splitting each tag on `delimiter`. Tags whose name contains the
/// delimiter are placed in a group named after the prefix; tags
/// without the delimiter go into `default_group`. Group order
/// follows first-seen order of prefixes; within each group, tags
/// appear in input order.
fn auto_tag_groups(
    tags: &[String],
    delimiter: &str,
    default_group: &str,
) -> Vec<serde_json::Value> {
    // LinkedHashMap-like: preserve insertion order of group names.
    let mut group_order: Vec<String> = Vec::new();
    let mut group_map: HashMap<String, Vec<String>> = HashMap::new();

    for tag in tags {
        let group_name = match tag.find(delimiter) {
            Some(idx) => &tag[..idx],
            None => default_group,
        };
        let entry = group_map.entry(group_name.to_string()).or_insert_with(|| {
            group_order.push(group_name.to_string());
            Vec::new()
        });
        entry.push(tag.clone());
    }

    group_order
        .into_iter()
        .map(|name| {
            let tags = group_map.remove(&name).unwrap_or_default();
            serde_json::json!({ "name": name, "tags": tags })
        })
        .collect()
}

/// Extract schema names from `$ref` entries in a content map and
/// record the given `op_tags` against each one. Only direct `$ref`
/// links to `#/components/schemas/<Name>` are followed — deeply
/// nested refs are not chased to keep the pass simple and
/// predictable.
fn collect_content_refs<V>(
    content: impl IntoIterator<Item = V>,
    op_tags: &[String],
    out: &mut HashMap<String, BTreeSet<String>>,
) where
    V: std::borrow::Borrow<utoipa::openapi::content::Content>,
{
    use utoipa::openapi::RefOr;

    for c in content {
        let c = c.borrow();
        let schema = match &c.schema {
            Some(s) => s,
            None => continue,
        };
        if let RefOr::Ref(r) = schema {
            if let Some(name) = r.ref_location.strip_prefix("#/components/schemas/") {
                let entry = out.entry(name.to_string()).or_default();
                entry.extend(op_tags.iter().cloned());
            }
        }
    }
}

/// Get a mutable reference to the extensions on any
/// [`utoipa::openapi::schema::Schema`] variant. All variants carry
/// `extensions`. Get a mutable reference to the extensions on any known
/// [`utoipa::openapi::schema::Schema`] variant. Returns [`None`]
/// for future variants added to the non-exhaustive enum.
fn schema_extensions_mut(
    schema: &mut utoipa::openapi::schema::Schema,
) -> Option<&mut Option<utoipa::openapi::extensions::Extensions>> {
    use utoipa::openapi::schema::Schema;
    match schema {
        Schema::Object(o) => Some(&mut o.extensions),
        Schema::Array(a) => Some(&mut a.extensions),
        Schema::OneOf(o) => Some(&mut o.extensions),
        Schema::AllOf(a) => Some(&mut a.extensions),
        Schema::AnyOf(a) => Some(&mut a.extensions),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_minimal_document() {
        let doc = ApiDocBuilder::new().title("test").version("1.2.3").build();
        assert_eq!(doc.openapi.info.title, "test");
        assert_eq!(doc.openapi.info.version, "1.2.3");
        // Spec JSON is non-empty and parses as valid JSON.
        assert!(!doc.spec_json.is_empty());
        let _: serde_json::Value = serde_json::from_slice(&doc.spec_json).unwrap();
    }

    #[test]
    fn description_appears_in_serialized_spec() {
        let doc = ApiDocBuilder::new()
            .title("test")
            .version("0.1")
            .description("hello world")
            .build();
        let parsed: serde_json::Value = serde_json::from_slice(&doc.spec_json).unwrap();
        assert_eq!(parsed["info"]["description"], "hello world");
    }

    #[test]
    fn server_entry_is_recorded() {
        let doc = ApiDocBuilder::new()
            .title("test")
            .version("0.1")
            .server("/api", "primary")
            .build();
        let servers = doc.openapi.servers.as_ref().unwrap();
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].url, "/api");
        assert_eq!(servers[0].description.as_deref(), Some("primary"));
    }

    #[test]
    fn bearer_security_scheme_is_registered() {
        let doc = ApiDocBuilder::new()
            .title("test")
            .version("0.1")
            .bearer_security("bearer")
            .build();
        let parsed: serde_json::Value = serde_json::from_slice(&doc.spec_json).unwrap();
        let schemes = &parsed["components"]["securitySchemes"]["bearer"];
        assert_eq!(schemes["type"], "http");
        assert_eq!(schemes["scheme"], "bearer");
    }

    #[test]
    fn bearer_security_defaults_to_jwt_format() {
        let doc = ApiDocBuilder::new()
            .title("test")
            .version("0.1")
            .bearer_security("bearer")
            .build();
        let parsed: serde_json::Value = serde_json::from_slice(&doc.spec_json).unwrap();
        let schemes = &parsed["components"]["securitySchemes"]["bearer"];
        assert_eq!(schemes["bearerFormat"], "JWT");
    }

    #[test]
    fn bearer_security_with_format_overrides_bearer_format() {
        let doc = ApiDocBuilder::new()
            .title("test")
            .version("0.1")
            .bearer_security_with_format("jwt", "opaque")
            .build();
        let parsed: serde_json::Value = serde_json::from_slice(&doc.spec_json).unwrap();
        let schemes = &parsed["components"]["securitySchemes"]["jwt"];
        assert_eq!(schemes["type"], "http");
        assert_eq!(schemes["scheme"], "bearer");
        assert_eq!(schemes["bearerFormat"], "opaque");
    }

    #[test]
    fn merge_preserves_paths_from_base() {
        // Build a small OpenApi with one path manually and merge it.
        use utoipa::openapi::{
            path::{HttpMethod, OperationBuilder},
            PathItem, PathsBuilder,
        };
        let path_item = PathItem::new(HttpMethod::Get, OperationBuilder::new().build());
        let paths = PathsBuilder::new().path("/example", path_item).build();
        let base = OpenApiBuilder::new().paths(paths).build();
        let doc = ApiDocBuilder::new()
            .title("test")
            .version("0.1")
            .merge(base)
            .build();
        assert!(doc.openapi.paths.paths.contains_key("/example"));
    }

    #[test]
    fn license_appears_in_serialized_spec() {
        let doc = ApiDocBuilder::new()
            .title("test")
            .version("0.1")
            .license("MIT")
            .license_url("https://opensource.org/licenses/MIT")
            .build();
        let parsed: serde_json::Value = serde_json::from_slice(&doc.spec_json).unwrap();
        assert_eq!(parsed["info"]["license"]["name"], "MIT");
        assert_eq!(
            parsed["info"]["license"]["url"],
            "https://opensource.org/licenses/MIT"
        );
    }

    #[test]
    fn contact_block_appears_when_any_field_set() {
        let doc = ApiDocBuilder::new()
            .title("test")
            .version("0.1")
            .contact_name("Ops")
            .contact_email("ops@example.com")
            .contact_url("https://example.com/contact")
            .build();
        let parsed: serde_json::Value = serde_json::from_slice(&doc.spec_json).unwrap();
        assert_eq!(parsed["info"]["contact"]["name"], "Ops");
        assert_eq!(parsed["info"]["contact"]["email"], "ops@example.com");
        assert_eq!(
            parsed["info"]["contact"]["url"],
            "https://example.com/contact"
        );
    }

    #[test]
    fn multiple_servers_are_recorded_in_order() {
        let doc = ApiDocBuilder::new()
            .title("test")
            .version("0.1")
            .server("/", "primary")
            .server("https://staging.example.com", "staging")
            .build();
        let servers = doc.openapi.servers.as_ref().unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].url, "/");
        assert_eq!(servers[1].url, "https://staging.example.com");
        assert_eq!(servers[1].description.as_deref(), Some("staging"));
    }

    #[test]
    fn merge_then_override_uses_builder_info_fields() {
        // Build a base with its own title; the builder's title should
        // win over the merged base's title.
        let base = OpenApiBuilder::new()
            .info(
                InfoBuilder::new()
                    .title("from-base")
                    .version("9.9.9")
                    .build(),
            )
            .build();
        let doc = ApiDocBuilder::new()
            .title("from-builder")
            .version("0.1")
            .merge(base)
            .build();
        assert_eq!(doc.openapi.info.title, "from-builder");
        assert_eq!(doc.openapi.info.version, "0.1");
    }

    #[test]
    fn build_without_title_inherits_from_merged_base() {
        // When the builder doesn't supply title/version, the merged
        // base's values are preserved.
        let base = OpenApiBuilder::new()
            .info(
                InfoBuilder::new()
                    .title("base-title")
                    .version("3.0.0")
                    .build(),
            )
            .build();
        let doc = ApiDocBuilder::new().merge(base).build();
        assert_eq!(doc.openapi.info.title, "base-title");
        assert_eq!(doc.openapi.info.version, "3.0.0");
    }

    #[test]
    fn server_with_empty_description_omits_the_field() {
        let doc = ApiDocBuilder::new()
            .title("t")
            .version("0.1")
            .server("/api", "")
            .build();
        let servers = doc.openapi.servers.as_ref().unwrap();
        assert_eq!(servers.len(), 1);
        assert!(servers[0].description.is_none());
    }

    #[test]
    fn spec_json_clone_is_shallow() {
        let doc = ApiDocBuilder::new().title("t").version("0.1").build();
        let cloned = doc.clone();
        // Bytes::clone is a refcount bump — both clones must point at
        // the same underlying buffer.
        assert_eq!(doc.spec_json.as_ptr(), cloned.spec_json.as_ptr());
        assert!(Arc::ptr_eq(&doc.openapi, &cloned.openapi));
    }

    #[test]
    fn tag_metadata_appears_in_serialized_spec() {
        let doc = ApiDocBuilder::new()
            .title("test")
            .version("0.1")
            .tag("Models", "CRUD operations for data models")
            .tag("Compute", "Query execution and charting")
            .build();
        let parsed: serde_json::Value = serde_json::from_slice(&doc.spec_json).unwrap();
        let tags = parsed["tags"].as_array().expect("tags array present");
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0]["name"], "Models");
        assert_eq!(tags[0]["description"], "CRUD operations for data models");
        assert_eq!(tags[1]["name"], "Compute");
        assert_eq!(tags[1]["description"], "Query execution and charting");
    }

    #[test]
    fn tag_order_is_preserved() {
        let doc = ApiDocBuilder::new()
            .title("t")
            .version("0.1")
            .tag("Z", "last")
            .tag("A", "first")
            .build();
        let tags = doc.openapi.tags.as_ref().unwrap();
        assert_eq!(tags[0].name, "Z");
        assert_eq!(tags[1].name, "A");
    }

    #[test]
    fn explicit_tag_groups_disable_auto_grouping() {
        let doc = ApiDocBuilder::new()
            .title("t")
            .version("0.1")
            .tag_group("Public", ["Models", "Compute"])
            .tag_group("Admin", ["Admin: Models"])
            .build();
        let parsed: serde_json::Value = serde_json::from_slice(&doc.spec_json).unwrap();
        let groups = parsed["x-tagGroups"]
            .as_array()
            .expect("x-tagGroups present");
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["name"], "Public");
        assert_eq!(groups[0]["tags"], serde_json::json!(["Models", "Compute"]));
        assert_eq!(groups[1]["name"], "Admin");
        assert_eq!(groups[1]["tags"], serde_json::json!(["Admin: Models"]));
    }

    /// Helper: build an OpenApi with tagged operations.
    fn openapi_with_tagged_ops(tag_pairs: &[(&str, &str)]) -> OpenApi {
        use utoipa::openapi::path::{HttpMethod, OperationBuilder, PathItem};
        use utoipa::openapi::PathsBuilder;

        let mut paths = PathsBuilder::new();
        for (path, tag) in tag_pairs {
            let op = OperationBuilder::new().tag(*tag).build();
            paths = paths.path(*path, PathItem::new(HttpMethod::Get, op));
        }
        OpenApiBuilder::new().paths(paths.build()).build()
    }

    #[test]
    fn auto_discovers_tags_from_operations() {
        let base = openapi_with_tagged_ops(&[("/a", "Alpha"), ("/b", "Beta")]);
        let doc = ApiDocBuilder::new()
            .title("t")
            .version("0.1")
            .merge(base)
            .build();
        let tags = doc.openapi.tags.as_ref().expect("tags present");
        let names: Vec<&str> = tags.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"Alpha"));
        assert!(names.contains(&"Beta"));
    }

    #[test]
    fn explicit_tags_appear_before_discovered_tags() {
        let base = openapi_with_tagged_ops(&[("/a", "Alpha"), ("/b", "Beta")]);
        let doc = ApiDocBuilder::new()
            .title("t")
            .version("0.1")
            .tag("Beta", "explicitly first")
            .merge(base)
            .build();
        let tags = doc.openapi.tags.as_ref().expect("tags present");
        // Beta was explicitly registered first, so it appears before Alpha.
        assert_eq!(tags[0].name, "Beta");
        assert_eq!(
            tags[0].description.as_deref(),
            Some("explicitly first"),
            "explicit description wins"
        );
        assert_eq!(tags[1].name, "Alpha");
        assert!(
            tags[1].description.is_none(),
            "auto-discovered tag has no description"
        );
    }

    #[test]
    fn auto_groups_tags_by_colon_delimiter() {
        let base = openapi_with_tagged_ops(&[
            ("/models", "Models"),
            ("/compute", "Compute"),
            ("/admin/models", "Admin: Models"),
            ("/admin/auth", "Admin: Auth"),
        ]);
        let doc = ApiDocBuilder::new()
            .title("t")
            .version("0.1")
            .default_tag_group("Public API")
            .merge(base)
            .build();
        let parsed: serde_json::Value = serde_json::from_slice(&doc.spec_json).unwrap();
        let groups = parsed["x-tagGroups"]
            .as_array()
            .expect("x-tagGroups present");

        // Two groups: "Admin" (from prefix, first alphabetically) and
        // "Public API" (default group for tags without delimiter).
        assert_eq!(groups.len(), 2);

        // Groups appear in first-seen order of prefixes. Since tags
        // are sorted alphabetically, "Admin: Auth" is first →
        // "Admin" group appears before "Public API".
        let group_names: Vec<&str> = groups.iter().map(|g| g["name"].as_str().unwrap()).collect();
        assert!(group_names.contains(&"Admin"));
        assert!(group_names.contains(&"Public API"));

        let admin_group = groups.iter().find(|g| g["name"] == "Admin").unwrap();
        let admin_tags = admin_group["tags"].as_array().unwrap();
        assert!(admin_tags.iter().any(|t| t == "Admin: Models"));
        assert!(admin_tags.iter().any(|t| t == "Admin: Auth"));

        let public_group = groups.iter().find(|g| g["name"] == "Public API").unwrap();
        let public_tags = public_group["tags"].as_array().unwrap();
        assert!(public_tags.iter().any(|t| t == "Compute"));
        assert!(public_tags.iter().any(|t| t == "Models"));
    }

    #[test]
    fn custom_delimiter_splits_tags() {
        let base = openapi_with_tagged_ops(&[("/a", "team/models"), ("/b", "team/auth")]);
        let doc = ApiDocBuilder::new()
            .title("t")
            .version("0.1")
            .tag_group_delimiter("/")
            .merge(base)
            .build();
        let parsed: serde_json::Value = serde_json::from_slice(&doc.spec_json).unwrap();
        let groups = parsed["x-tagGroups"]
            .as_array()
            .expect("x-tagGroups present");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["name"], "team");
    }
}
