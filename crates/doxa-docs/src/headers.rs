//! Type-safe declaration of request headers, modeled after
//! [`axum_extra::TypedHeader`](https://docs.rs/axum-extra/latest/axum_extra/typed_header/struct.TypedHeader.html).
//!
//! A marker struct implements [`DocumentedHeader`] and exposes the
//! wire name plus optional metadata via runtime methods (not
//! associated consts), which keeps the door open for a future blanket
//! impl over the foreign [`headers::Header`](https://docs.rs/headers)
//! trait — its `name()` is also a runtime fn, so the two can compose
//! behind a feature flag without breaking changes here.
//!
//! Marker types compose freely across crates with zero runtime
//! overhead. The same marker can be reused on the layer side via
//! [`HeaderParam::typed`] and on the handler side via
//! [`crate::Header`] / the `headers(...)` macro argument.

use utoipa::openapi::path::{Operation, Parameter, ParameterBuilder, ParameterIn};
use utoipa::openapi::{Object, RefOr, Required, Schema, Type};

/// Type-level descriptor for one HTTP header.
///
/// Implementations are typically zero-sized marker structs:
///
/// ```rust
/// use doxa::DocumentedHeader;
///
/// pub struct BearerAuthorization;
/// impl DocumentedHeader for BearerAuthorization {
///     fn name() -> &'static str { "Authorization" }
///     fn description() -> &'static str {
///         "Bearer JWT issued by the configured identity provider."
///     }
///     fn example() -> Option<&'static str> {
///         Some("Bearer eyJhbGc...")
///     }
/// }
/// ```
///
/// All accessors are runtime functions (not associated consts) so a
/// future blanket impl can adapt foreign traits whose names are only
/// available through methods — e.g. `impl<H: headers::Header>
/// DocumentedHeader for H` behind an opt-in cargo feature.
pub trait DocumentedHeader {
    /// Wire name of the header. HTTP header names are case-insensitive,
    /// but OpenAPI viewers (Scalar, Swagger UI) render the name
    /// verbatim — use the title-cased form your consumers expect to
    /// see (`Authorization`, not `authorization`).
    fn name() -> &'static str;

    /// Human description rendered in the docs UI. Empty string omits
    /// the description from the spec.
    fn description() -> &'static str {
        ""
    }

    /// Optional example value rendered alongside the parameter.
    fn example() -> Option<&'static str> {
        None
    }
}

/// One header parameter descriptor. Construct via
/// [`HeaderParam::typed`] / [`HeaderParam::typed_optional`] for
/// type-safe declarations driven by [`DocumentedHeader`], or via
/// [`HeaderParam::required`] / [`HeaderParam::optional`] for ad-hoc
/// string names.
#[derive(Clone, Debug)]
pub struct HeaderParam {
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) required: bool,
    pub(crate) example: Option<String>,
}

impl HeaderParam {
    /// Build a required header from a [`DocumentedHeader`] marker.
    /// Resolves the name and metadata at the time of the call.
    pub fn typed<H: DocumentedHeader>() -> Self {
        let desc = H::description();
        Self {
            name: H::name().to_string(),
            description: (!desc.is_empty()).then(|| desc.to_string()),
            required: true,
            example: H::example().map(str::to_string),
        }
    }

    /// Build an optional header from a [`DocumentedHeader`] marker.
    pub fn typed_optional<H: DocumentedHeader>() -> Self {
        Self {
            required: false,
            ..Self::typed::<H>()
        }
    }

    /// Build an ad-hoc required header from a string name. Prefer
    /// [`HeaderParam::typed`] when a marker type is available.
    pub fn required(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            required: true,
            example: None,
        }
    }

    /// Build an ad-hoc optional header from a string name.
    pub fn optional(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            required: false,
            example: None,
        }
    }

    /// Set the description (chainable).
    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }

    /// Set the example value (chainable).
    pub fn example(mut self, e: impl Into<String>) -> Self {
        self.example = Some(e.into());
        self
    }

    /// Build the utoipa [`Parameter`] for this header.
    pub(crate) fn to_parameter(&self) -> Parameter {
        let mut b = ParameterBuilder::new()
            .name(&self.name)
            .parameter_in(ParameterIn::Header)
            .required(if self.required {
                Required::True
            } else {
                Required::False
            })
            .schema(Some(RefOr::T(Schema::Object(Object::with_type(
                Type::String,
            )))));
        if let Some(d) = &self.description {
            b = b.description(Some(d.clone()));
        }
        if let Some(e) = &self.example {
            b = b.example(Some(serde_json::Value::String(e.clone())));
        }
        b.build()
    }
}

/// Append `headers` as `in: header` parameters on `op`. Skips any
/// header whose name (case-insensitive) is already present on the
/// operation — handler-level declarations always win over
/// layer-injected defaults.
pub(crate) fn apply_headers_to_operation(op: &mut Operation, headers: &[HeaderParam]) {
    if headers.is_empty() {
        return;
    }
    let existing = op.parameters.get_or_insert_with(Vec::new);
    for h in headers {
        let dup = existing.iter().any(|p| {
            matches!(p.parameter_in, ParameterIn::Header) && p.name.eq_ignore_ascii_case(&h.name)
        });
        if !dup {
            existing.push(h.to_parameter());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utoipa::openapi::path::OperationBuilder;

    struct XApiKey;
    impl DocumentedHeader for XApiKey {
        fn name() -> &'static str {
            "X-Api-Key"
        }
        fn description() -> &'static str {
            "Tenant API key"
        }
        fn example() -> Option<&'static str> {
            Some("ak_live_42")
        }
    }

    struct BareHeader;
    impl DocumentedHeader for BareHeader {
        fn name() -> &'static str {
            "X-Bare"
        }
    }

    #[test]
    fn header_param_typed_calls_runtime_name_fn() {
        let p = HeaderParam::typed::<XApiKey>();
        assert_eq!(p.name, "X-Api-Key");
        assert!(p.required);
    }

    #[test]
    fn header_param_typed_picks_up_description_and_example() {
        let p = HeaderParam::typed::<XApiKey>();
        assert_eq!(p.description.as_deref(), Some("Tenant API key"));
        assert_eq!(p.example.as_deref(), Some("ak_live_42"));
    }

    #[test]
    fn header_param_typed_omits_description_when_empty() {
        let p = HeaderParam::typed::<BareHeader>();
        assert!(p.description.is_none());
        assert!(p.example.is_none());
    }

    #[test]
    fn header_param_typed_optional_serializes_required_false() {
        let p = HeaderParam::typed_optional::<XApiKey>();
        assert!(!p.required);
        let param = p.to_parameter();
        assert!(matches!(param.required, Required::False));
    }

    #[test]
    fn header_param_required_serializes_required_true() {
        let param = HeaderParam::typed::<XApiKey>().to_parameter();
        assert!(matches!(param.required, Required::True));
        assert!(matches!(param.parameter_in, ParameterIn::Header));
    }

    #[test]
    fn apply_headers_appends_in_header_parameter() {
        let mut op = OperationBuilder::new().build();
        apply_headers_to_operation(&mut op, &[HeaderParam::typed::<XApiKey>()]);
        let params = op.parameters.expect("parameters set");
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "X-Api-Key");
        assert!(matches!(params[0].parameter_in, ParameterIn::Header));
    }

    #[test]
    fn apply_headers_skips_when_handler_already_declares_same_header_case_insensitive() {
        // Pre-populate the operation with a manually declared header
        // whose name differs only in case.
        let manual = ParameterBuilder::new()
            .name("x-api-key")
            .parameter_in(ParameterIn::Header)
            .required(Required::False)
            .build();
        let mut op = OperationBuilder::new().build();
        op.parameters = Some(vec![manual]);

        apply_headers_to_operation(&mut op, &[HeaderParam::typed::<XApiKey>()]);

        let params = op.parameters.expect("parameters set");
        assert_eq!(params.len(), 1, "manual header should suppress injection");
        assert_eq!(params[0].name, "x-api-key");
        assert!(matches!(params[0].required, Required::False));
    }

    #[test]
    fn apply_headers_preserves_existing_path_and_query_params() {
        let path_param = ParameterBuilder::new()
            .name("id")
            .parameter_in(ParameterIn::Path)
            .required(Required::True)
            .build();
        let query_param = ParameterBuilder::new()
            .name("page")
            .parameter_in(ParameterIn::Query)
            .required(Required::False)
            .build();
        let mut op = OperationBuilder::new().build();
        op.parameters = Some(vec![path_param, query_param]);

        apply_headers_to_operation(&mut op, &[HeaderParam::typed::<XApiKey>()]);

        let params = op.parameters.expect("parameters set");
        assert_eq!(params.len(), 3);
        assert!(params.iter().any(|p| p.name == "id"));
        assert!(params.iter().any(|p| p.name == "page"));
        assert!(params.iter().any(|p| p.name == "X-Api-Key"));
    }

    #[test]
    fn apply_headers_with_empty_slice_is_noop() {
        let mut op = OperationBuilder::new().build();
        apply_headers_to_operation(&mut op, &[]);
        assert!(op.parameters.is_none());
    }
}
