//! [`LayerContribution`] — bundle of OpenAPI metadata that a tower
//! [`Layer`](tower::Layer) adds to the routes it covers, plus the
//! [`DocumentedLayer`] trait that lets a layer announce its own
//! contribution.
//!
//! A single layer can contribute headers, extra response codes,
//! security requirements, and tags in one declaration. Apply by
//! calling [`crate::OpenApiRouterExt::layer_documented`] (which reads
//! the contribution off the layer via [`DocumentedLayer`]) or, for
//! callers that hold an [`utoipa::openapi::OpenApi`] directly, by
//! calling [`apply_contribution`] explicitly.

use utoipa::openapi::content::Content;
use utoipa::openapi::path::Operation;
use utoipa::openapi::response::{Response, ResponseBuilder};
use utoipa::openapi::security::SecurityRequirement;
use utoipa::openapi::{Ref, RefOr};

use crate::headers::{apply_headers_to_operation, HeaderParam};

/// What a layer contributes to the OpenAPI contract for the
/// operations it covers. Build with [`LayerContribution::new`] and
/// the chainable `with_*` setters; empty fields are zero-cost.
#[derive(Clone, Debug, Default)]
pub struct LayerContribution {
    pub(crate) headers: Vec<HeaderParam>,
    pub(crate) responses: Vec<ResponseContribution>,
    pub(crate) security: Vec<SecurityContribution>,
    pub(crate) tags: Vec<String>,
    pub(crate) badges: Vec<BadgeContribution>,
}

/// One badge entry the layer attaches to every operation it covers.
/// Surfaces in doc UIs that render the `x-badges` vendor extension
/// (Scalar): a colored chip with the supplied name.
#[derive(Clone, Debug)]
pub struct BadgeContribution {
    /// Badge name rendered in the UI. Serialized as the `name` key in
    /// the emitted `x-badges` entry to match Scalar's schema.
    pub name: String,
    /// Badge color. CSS color values are accepted by Scalar (keyword,
    /// hex, rgb, hsl).
    pub color: String,
}

impl BadgeContribution {
    /// Build a badge contribution with the given name and color.
    pub fn new(name: impl Into<String>, color: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            color: color.into(),
        }
    }
}

/// One extra response status the layer can return (e.g. 401 from auth
/// middleware, 429 from a rate limiter). Skipped on operations that
/// already declare a response with the same status — handler-level
/// declarations always win.
#[derive(Clone, Debug)]
pub struct ResponseContribution {
    /// Status code as a string (e.g. `"401"`, `"default"`).
    pub status: String,
    /// Human description rendered in the docs UI.
    pub description: String,
    /// Optional `$ref` path for the response body schema (e.g.
    /// `"#/components/schemas/ApiErrorBody"`). Set via
    /// [`ResponseContribution::with_schema_ref`].
    pub schema_ref: Option<String>,
}

impl ResponseContribution {
    /// Build a response contribution with the given status and
    /// description.
    pub fn new(status: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            status: status.into(),
            description: description.into(),
            schema_ref: None,
        }
    }

    /// Convenience constructor for the standard 401 Unauthorized
    /// response.
    pub fn unauthorized() -> Self {
        Self::new("401", "Authentication required")
    }

    /// Convenience constructor for the standard 403 Forbidden
    /// response.
    pub fn forbidden() -> Self {
        Self::new("403", "Permission denied")
    }

    /// Set the `$ref` path for the response body schema.
    pub fn with_schema_ref(mut self, ref_path: impl Into<String>) -> Self {
        self.schema_ref = Some(ref_path.into());
        self
    }

    /// Build the utoipa [`Response`] for this contribution.
    pub(crate) fn to_response(&self) -> Response {
        let mut b = ResponseBuilder::new().description(self.description.clone());
        if let Some(ref_path) = &self.schema_ref {
            b = b.content(
                "application/json",
                Content::new(Some(RefOr::Ref(Ref::new(ref_path.clone())))),
            );
        }
        b.build()
    }
}

/// One security requirement entry the layer enforces. References a
/// scheme that has been registered with
/// [`crate::ApiDocBuilder::bearer_security`] or
/// [`crate::ApiDocBuilder::security_scheme`] — a dangling reference
/// produces an invalid spec, so make sure the scheme name matches.
#[derive(Clone, Debug)]
pub struct SecurityContribution {
    /// Name of the security scheme as registered on the
    /// [`crate::ApiDocBuilder`].
    pub scheme: String,
    /// Required scopes. Empty for non-OAuth schemes.
    pub scopes: Vec<String>,
}

impl SecurityContribution {
    /// Build a security contribution naming the scheme to enforce.
    /// No scopes by default — use [`SecurityContribution::with_scopes`]
    /// for OAuth flows.
    pub fn new(scheme: impl Into<String>) -> Self {
        Self {
            scheme: scheme.into(),
            scopes: Vec::new(),
        }
    }

    /// Set the OAuth scopes required by this requirement.
    pub fn with_scopes(mut self, scopes: impl IntoIterator<Item = String>) -> Self {
        self.scopes = scopes.into_iter().collect();
        self
    }
}

impl LayerContribution {
    /// Construct an empty contribution.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a single header to the contribution.
    pub fn with_header(mut self, h: HeaderParam) -> Self {
        self.headers.push(h);
        self
    }

    /// Add multiple headers to the contribution.
    pub fn with_headers(mut self, hs: impl IntoIterator<Item = HeaderParam>) -> Self {
        self.headers.extend(hs);
        self
    }

    /// Add a response status the layer can produce.
    pub fn with_response(mut self, r: ResponseContribution) -> Self {
        self.responses.push(r);
        self
    }

    /// Add a security requirement the layer enforces.
    pub fn with_security(mut self, s: SecurityContribution) -> Self {
        self.security.push(s);
        self
    }

    /// Add a tag the layer applies to its operations.
    pub fn with_tag(mut self, t: impl Into<String>) -> Self {
        self.tags.push(t.into());
        self
    }

    /// Add a badge the layer attaches to every operation it covers.
    /// Renders as a colored chip on doc UIs that surface
    /// `x-badges` (Scalar).
    pub fn with_badge(mut self, b: BadgeContribution) -> Self {
        self.badges.push(b);
        self
    }

    /// Whether the contribution adds nothing to operations.
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
            && self.responses.is_empty()
            && self.security.is_empty()
            && self.tags.is_empty()
            && self.badges.is_empty()
    }

    /// Merge another contribution into this one. Order-preserving;
    /// dedup happens at apply time, not merge time.
    pub fn merge(&mut self, other: LayerContribution) {
        self.headers.extend(other.headers);
        self.responses.extend(other.responses);
        self.security.extend(other.security);
        self.tags.extend(other.tags);
        self.badges.extend(other.badges);
    }
}

/// A tower [`Layer`](tower::Layer) that declares its own OpenAPI
/// contribution.
///
/// Implement this on the same struct that implements
/// [`tower::Layer`](tower::Layer), so call sites can use
/// [`crate::OpenApiRouterExt::layer_documented`] with a single
/// argument and the contribution is inferred from the layer's type.
///
/// ```rust,ignore
/// use doxa::{
///     DocumentedLayer, HeaderParam, LayerContribution,
///     ResponseContribution, SecurityContribution,
/// };
///
/// pub struct MyAuthLayer { /* … */ }
/// impl<S> tower::Layer<S> for MyAuthLayer {
///     /* … */
/// #   type Service = S;
/// #   fn layer(&self, inner: S) -> Self::Service { inner }
/// }
/// impl DocumentedLayer for MyAuthLayer {
///     fn contribution(&self) -> LayerContribution {
///         LayerContribution::new()
///             .with_header(HeaderParam::required("Authorization"))
///             .with_response(ResponseContribution::unauthorized())
///             .with_security(SecurityContribution::new("bearer"))
///     }
/// }
/// ```
pub trait DocumentedLayer {
    /// Return the OpenAPI contribution this layer adds to every
    /// operation it covers. Called once at router-build time, on
    /// every [`crate::OpenApiRouterExt::layer_documented`] invocation.
    fn contribution(&self) -> LayerContribution;
}

/// Apply a contribution to a single operation. Each kind dedupes
/// against existing entries so handler-level declarations always win
/// and repeated layer applications are idempotent.
pub(crate) fn apply_contribution_to_operation(op: &mut Operation, c: &LayerContribution) {
    apply_headers_to_operation(op, &c.headers);

    // Responses — skip statuses the handler already declared.
    for r in &c.responses {
        if op.responses.responses.contains_key(&r.status) {
            continue;
        }
        op.responses
            .responses
            .insert(r.status.clone(), RefOr::T(r.to_response()));
    }

    // Security — merge by scheme. Multiple contributions for the same
    // scheme are combined into a single SecurityRequirement with the
    // union of their scopes, rather than producing duplicate entries.
    if !c.security.is_empty() {
        let security = op.security.get_or_insert_with(Vec::new);
        for s in &c.security {
            merge_security_requirement(security, &s.scheme, &s.scopes);
        }
    }

    // Tags — additive, dedup on string equality.
    if !c.tags.is_empty() {
        let tags = op.tags.get_or_insert_with(Vec::new);
        for t in &c.tags {
            if !tags.iter().any(|existing| existing == t) {
                tags.push(t.clone());
            }
        }
    }

    // Badges — append via the shared `x-badges` writer; dedup by name.
    for b in &c.badges {
        apply_badge_to_operation(op, &b.name, &b.color);
    }
}

/// Merge a security requirement into `security`, combining scopes by
/// scheme. If an entry for `scheme` already exists, any new `scopes`
/// are appended to it. Otherwise a new entry is created.
///
/// This produces one `SecurityRequirement` per scheme with the union
/// of all contributed scopes, rather than duplicating entries.
fn merge_security_requirement(
    security: &mut Vec<SecurityRequirement>,
    scheme: &str,
    scopes: &[String],
) {
    // SecurityRequirement's inner BTreeMap is private, so we round-trip
    // through serde to inspect existing entries for this scheme.
    if let Some(pos) = security.iter().position(|req| {
        serde_json::to_value(req)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .is_some_and(|map| map.contains_key(scheme))
    }) {
        // Found an existing entry for this scheme — merge scopes.
        if !scopes.is_empty() {
            let existing = &security[pos];
            let mut map: std::collections::BTreeMap<String, Vec<String>> =
                serde_json::from_value(serde_json::to_value(existing).unwrap_or_default())
                    .unwrap_or_default();
            if let Some(existing_scopes) = map.get_mut(scheme) {
                for scope in scopes {
                    if !existing_scopes.contains(scope) {
                        existing_scopes.push(scope.clone());
                    }
                }
            }
            // Rebuild the SecurityRequirement with merged scopes.
            let merged_scopes = map.get(scheme).cloned().unwrap_or_default();
            security[pos] = SecurityRequirement::new(scheme.to_string(), merged_scopes);
        }
        // If scopes is empty, the existing scoped entry already subsumes
        // the bare requirement — nothing to do.
    } else {
        security.push(SecurityRequirement::new(
            scheme.to_string(),
            scopes.to_vec(),
        ));
    }
}

/// Record a per-operation permission requirement on `op`, emitting:
///
/// - A standard [`SecurityRequirement`] referencing `scheme` with the supplied
///   `scope` — so OpenAPI client codegen sees a required OAuth scope and
///   threads it through to the token request.
/// - An `x-required-permissions` vendor extension entry containing `display` —
///   a machine-readable list of the actions a request must satisfy, available
///   to tooling that walks the spec.
/// - An `x-badges` vendor extension entry shaped for Scalar's native badge
///   renderer (`{name, color}`) — surfaces the permission as a colored chip on
///   each operation header, no markdown injection. Scalar accepts any CSS color
///   value; we use the Scalar CSS custom property `var(--scalar-color-accent)`
///   so badges adopt whatever accent color the active theme defines.
///
/// All three writes are idempotent — repeated calls with the same
/// arguments don't duplicate. The `scope` is the canonical machine
/// identifier (e.g. an OAuth2 scope string); `display` is the human
/// label rendered in badges and in `x-required-permissions`.
pub fn record_required_permission(op: &mut Operation, scheme: &str, scope: &str, display: &str) {
    use utoipa::openapi::extensions::ExtensionsBuilder;

    let security = op.security.get_or_insert_with(Vec::new);
    merge_security_requirement(security, scheme, &[scope.to_string()]);

    // Round-trip through `serde_json::Value` because
    // `utoipa::openapi::extensions::Extensions` does not expose its
    // inner map by reference. Idempotent on `display`.
    let existing_ext = op
        .extensions
        .as_ref()
        .and_then(|ext| serde_json::to_value(ext).ok());

    let mut perms = extract_extension_array(existing_ext.as_ref(), "x-required-permissions");
    let perm_entry = serde_json::Value::String(display.to_string());
    if !perms.contains(&perm_entry) {
        perms.push(perm_entry);
    }

    let mut badges = extract_extension_array(existing_ext.as_ref(), "x-badges");
    let badge_entry = serde_json::json!({
        "name": display,
        "color": "var(--scalar-color-accent)",
    });
    let already_badged = badges
        .iter()
        .any(|b| b.get("name") == badge_entry.get("name"));
    if !already_badged {
        badges.push(badge_entry);
    }

    let ext = ExtensionsBuilder::new()
        .add("x-required-permissions", serde_json::Value::Array(perms))
        .add("x-badges", serde_json::Value::Array(badges))
        .build();
    match op.extensions.as_mut() {
        Some(existing) => existing.merge(ext),
        None => op.extensions = Some(ext),
    }
}

/// Append an `x-badges` entry shaped for Scalar's native badge
/// renderer (`{name, color}`) to a single operation. Idempotent on
/// `name` — calling twice with the same name leaves a single
/// badge entry. `color` accepts any CSS color value (keyword, hex,
/// rgb, hsl, or a Scalar CSS custom property like
/// `var(--scalar-color-accent)`).
///
/// Applied internally when a [`LayerContribution`] carries one or
/// more [`BadgeContribution`] entries — the right tool when the
/// gating signal lives at a layer/middleware level rather than on
/// a per-extractor basis (e.g. an admin-only route group behind a
/// tower `Layer` that implements [`DocumentedLayer`] with a badge
/// contribution).
pub fn apply_badge_to_operation(op: &mut Operation, name: &str, color: &str) {
    use utoipa::openapi::extensions::ExtensionsBuilder;

    let existing_ext = op
        .extensions
        .as_ref()
        .and_then(|ext| serde_json::to_value(ext).ok());
    let mut badges = extract_extension_array(existing_ext.as_ref(), "x-badges");
    let entry = serde_json::json!({ "name": name, "color": color });
    let already = badges.iter().any(|b| b.get("name") == entry.get("name"));
    if !already {
        badges.push(entry);
    }
    let ext = ExtensionsBuilder::new()
        .add("x-badges", serde_json::Value::Array(badges))
        .build();
    match op.extensions.as_mut() {
        Some(existing) => existing.merge(ext),
        None => op.extensions = Some(ext),
    }
}

/// Pull a `Vec<Value>` out of a serialized [`Extensions`] map at
/// `key`, returning an empty vec when the key is missing or not an
/// array. Used by [`record_required_permission`] to merge into
/// existing entries idempotently.
fn extract_extension_array(
    serialized: Option<&serde_json::Value>,
    key: &str,
) -> Vec<serde_json::Value> {
    serialized
        .and_then(|v| match v {
            serde_json::Value::Object(map) => map.get(key).and_then(|v| v.as_array().cloned()),
            _ => None,
        })
        .unwrap_or_default()
}

/// Apply a contribution to **every** operation in `openapi`. Public
/// so callers who hold an [`utoipa::openapi::OpenApi`] directly can
/// also annotate it without going through
/// [`crate::OpenApiRouterExt`].
pub fn apply_contribution(openapi: &mut utoipa::openapi::OpenApi, c: &LayerContribution) {
    if c.is_empty() {
        return;
    }
    for path_item in openapi.paths.paths.values_mut() {
        for op in path_item_operations_mut(path_item) {
            apply_contribution_to_operation(op, c);
        }
    }
}

/// Iterate the eight HTTP-method [`Operation`] slots on a
/// [`utoipa::openapi::PathItem`] by shared reference.
pub(crate) fn path_item_operations(
    path_item: &utoipa::openapi::path::PathItem,
) -> impl Iterator<Item = &Operation> {
    [
        path_item.get.as_ref(),
        path_item.put.as_ref(),
        path_item.post.as_ref(),
        path_item.delete.as_ref(),
        path_item.options.as_ref(),
        path_item.head.as_ref(),
        path_item.patch.as_ref(),
        path_item.trace.as_ref(),
    ]
    .into_iter()
    .flatten()
}

/// Iterate the eight HTTP-method [`Operation`] slots on a
/// [`utoipa::openapi::PathItem`]. utoipa models each verb as a
/// distinct `Option<Operation>` field rather than a map, so we
/// flatten them here for callers that want method-agnostic mutation.
pub(crate) fn path_item_operations_mut(
    path_item: &mut utoipa::openapi::path::PathItem,
) -> impl Iterator<Item = &mut Operation> {
    [
        path_item.get.as_mut(),
        path_item.put.as_mut(),
        path_item.post.as_mut(),
        path_item.delete.as_mut(),
        path_item.options.as_mut(),
        path_item.head.as_mut(),
        path_item.patch.as_mut(),
        path_item.trace.as_mut(),
    ]
    .into_iter()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use utoipa::openapi::path::OperationBuilder;
    use utoipa::openapi::response::Responses;

    fn empty_op() -> Operation {
        let mut op = OperationBuilder::new().build();
        op.responses = Responses::new();
        op
    }

    #[test]
    fn apply_contribution_adds_headers_responses_security_tags_to_operation() {
        let mut op = empty_op();
        let c = LayerContribution::new()
            .with_header(HeaderParam::required("Authorization"))
            .with_response(ResponseContribution::unauthorized())
            .with_security(SecurityContribution::new("bearer"))
            .with_tag("auth");

        apply_contribution_to_operation(&mut op, &c);

        let params = op.parameters.expect("parameters set");
        assert!(params.iter().any(|p| p.name == "Authorization"));
        assert!(op.responses.responses.contains_key("401"));
        let security = op.security.expect("security set");
        assert_eq!(security.len(), 1);
        let tags = op.tags.expect("tags set");
        assert_eq!(tags, vec!["auth".to_string()]);
    }

    #[test]
    fn apply_contribution_skips_response_status_already_declared_by_handler() {
        let mut op = empty_op();
        op.responses.responses.insert(
            "401".to_string(),
            RefOr::T(Response::new("handler-declared 401")),
        );

        let c = LayerContribution::new().with_response(ResponseContribution::unauthorized());
        apply_contribution_to_operation(&mut op, &c);

        let resp = op
            .responses
            .responses
            .get("401")
            .expect("401 still present");
        match resp {
            RefOr::T(r) => assert_eq!(r.description, "handler-declared 401"),
            RefOr::Ref(_) => panic!("expected inline response"),
        }
    }

    #[test]
    fn apply_contribution_dedupes_security_requirement_when_called_twice() {
        let mut op = empty_op();
        let c = LayerContribution::new().with_security(SecurityContribution::new("bearer"));

        apply_contribution_to_operation(&mut op, &c);
        apply_contribution_to_operation(&mut op, &c);

        let security = op.security.expect("security set");
        assert_eq!(security.len(), 1, "duplicate security requirement");
    }

    #[test]
    fn apply_contribution_dedupes_tag() {
        let mut op = empty_op();
        let c = LayerContribution::new().with_tag("auth");

        apply_contribution_to_operation(&mut op, &c);
        apply_contribution_to_operation(&mut op, &c);

        let tags = op.tags.expect("tags set");
        assert_eq!(tags, vec!["auth".to_string()]);
    }

    #[test]
    fn merge_contribution_concatenates_each_kind_in_order() {
        let mut a = LayerContribution::new()
            .with_header(HeaderParam::required("X-A"))
            .with_tag("a");
        let b = LayerContribution::new()
            .with_header(HeaderParam::required("X-B"))
            .with_tag("b");
        a.merge(b);

        assert_eq!(a.headers.len(), 2);
        assert_eq!(a.headers[0].name, "X-A");
        assert_eq!(a.headers[1].name, "X-B");
        assert_eq!(a.tags, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn default_contribution_is_empty_no_op() {
        let c = LayerContribution::default();
        assert!(c.is_empty());

        let mut openapi = utoipa::openapi::OpenApiBuilder::new().build();
        apply_contribution(&mut openapi, &c);
        assert!(openapi.paths.paths.is_empty());
    }

    #[test]
    fn response_contribution_with_schema_ref_emits_json_content() {
        let r = ResponseContribution::unauthorized()
            .with_schema_ref("#/components/schemas/ApiErrorBody");
        let resp = r.to_response();
        let content = resp
            .content
            .get("application/json")
            .expect("application/json content present");
        match &content.schema {
            Some(RefOr::Ref(_)) => {}
            _ => panic!("expected $ref schema"),
        }
    }

    #[test]
    fn scoped_extractor_then_bare_layer_produces_single_entry() {
        let mut op = empty_op();

        // Simulate Require<M> adding a scoped security entry first.
        record_required_permission(&mut op, "bearer", "widgets.read", "Read widgets");

        // Then AuthLayer contributes a bare scheme entry via layer_documented.
        let c = LayerContribution::new().with_security(SecurityContribution::new("bearer"));
        apply_contribution_to_operation(&mut op, &c);

        let security = op.security.expect("security set");
        assert_eq!(
            security.len(),
            1,
            "bare layer entry should merge into scoped extractor entry"
        );

        // Verify the single entry has the scope from the extractor.
        let json = serde_json::to_value(&security[0]).unwrap();
        let scopes = json.get("bearer").unwrap().as_array().unwrap();
        assert_eq!(scopes, &[serde_json::json!("widgets.read")]);
    }

    #[test]
    fn bare_layer_then_scoped_extractor_produces_single_entry() {
        let mut op = empty_op();

        // Layer contribution first (bare scheme).
        let c = LayerContribution::new().with_security(SecurityContribution::new("bearer"));
        apply_contribution_to_operation(&mut op, &c);

        // Then extractor adds a scoped entry.
        record_required_permission(&mut op, "bearer", "widgets.write", "Write widgets");

        let security = op.security.expect("security set");
        assert_eq!(
            security.len(),
            1,
            "scoped extractor entry should merge into bare layer entry"
        );

        let json = serde_json::to_value(&security[0]).unwrap();
        let scopes = json.get("bearer").unwrap().as_array().unwrap();
        assert_eq!(scopes, &[serde_json::json!("widgets.write")]);
    }

    #[test]
    fn multiple_scopes_merge_into_single_entry() {
        let mut op = empty_op();

        record_required_permission(&mut op, "bearer", "widgets.read", "Read");
        record_required_permission(&mut op, "bearer", "widgets.write", "Write");

        let c = LayerContribution::new().with_security(SecurityContribution::new("bearer"));
        apply_contribution_to_operation(&mut op, &c);

        let security = op.security.expect("security set");
        assert_eq!(security.len(), 1);

        let json = serde_json::to_value(&security[0]).unwrap();
        let scopes = json.get("bearer").unwrap().as_array().unwrap();
        assert!(scopes.contains(&serde_json::json!("widgets.read")));
        assert!(scopes.contains(&serde_json::json!("widgets.write")));
    }
}
