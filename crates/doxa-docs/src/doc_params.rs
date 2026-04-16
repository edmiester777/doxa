//! [`DocHeaderEntry<H>`] — zero-sized marker type that implements
//! [`utoipa::IntoParams`] via runtime resolution of
//! [`DocumentedHeader::name`]. Used by the
//! [`doxa-macros`](../../doxa_macros/index.html) macro
//! pass to inject typed headers into a handler's `params(...)` block.

use std::marker::PhantomData;

use utoipa::openapi::path::{Parameter, ParameterBuilder, ParameterIn};
use utoipa::openapi::{Object, RefOr, Required, Schema, Type};
use utoipa::IntoParams;

use crate::headers::DocumentedHeader;

/// Generic [`IntoParams`] implementor that produces one header
/// parameter from a [`DocumentedHeader`] marker, calling
/// [`H::name`](DocumentedHeader::name),
/// [`H::description`](DocumentedHeader::description), and
/// [`H::example`](DocumentedHeader::example) at runtime.
///
/// You don't usually construct this yourself — the `#[get]` /
/// `#[post]` / etc. macros emit it inside the synthesized
/// `#[utoipa::path(params(...))]` block whenever a handler signature
/// contains a [`crate::Header<H>`] extractor or a `headers(H, ...)`
/// macro argument is supplied.
///
/// The runtime-name design (a fn on [`DocumentedHeader`], not a
/// const) is what makes this possible: the proc-macro can't call
/// `H::name()` during expansion, but the generated `params(DocHeaderEntry<H>)`
/// reaches runtime where the call resolves cheaply.
pub struct DocHeaderEntry<H: DocumentedHeader>(PhantomData<H>);

impl<H: DocumentedHeader> IntoParams for DocHeaderEntry<H> {
    fn into_params(_parameter_in_provider: impl Fn() -> Option<ParameterIn>) -> Vec<Parameter> {
        let desc = H::description();
        let mut b = ParameterBuilder::new()
            .name(H::name())
            .parameter_in(ParameterIn::Header)
            .required(Required::True)
            .schema(Some(RefOr::T(Schema::Object(Object::with_type(
                Type::String,
            )))));
        if !desc.is_empty() {
            b = b.description(Some(desc.to_string()));
        }
        if let Some(ex) = H::example() {
            b = b.example(Some(serde_json::Value::String(ex.to_string())));
        }
        vec![b.build()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn doc_header_entry_into_params_uses_runtime_name() {
        let params = DocHeaderEntry::<XApiKey>::into_params(|| None);
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].name, "X-Api-Key");
        assert!(matches!(params[0].parameter_in, ParameterIn::Header));
        assert!(matches!(params[0].required, Required::True));
    }

    #[test]
    fn doc_header_entry_into_params_emits_description_when_provided() {
        let params = DocHeaderEntry::<XApiKey>::into_params(|| None);
        assert_eq!(params[0].description.as_deref(), Some("Tenant API key"));
    }

    #[test]
    fn doc_header_entry_into_params_omits_description_when_empty() {
        let params = DocHeaderEntry::<BareHeader>::into_params(|| None);
        assert!(params[0].description.is_none());
    }

    #[test]
    fn doc_header_entry_into_params_emits_example_when_provided() {
        let params = DocHeaderEntry::<XApiKey>::into_params(|| None);
        // Parameter::example is private, so round-trip via JSON.
        let json = serde_json::to_value(&params[0]).unwrap();
        assert_eq!(json["example"], "ak_live_42");
    }
}
