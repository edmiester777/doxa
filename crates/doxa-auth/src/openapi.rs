//! OpenAPI metadata for [`crate::AuthLayer`].
//!
//! [`auth_contribution`] returns the bundle of [`HeaderParam`],
//! security scheme, and 401 response that the auth pipeline adds to
//! every operation behind it. [`crate::AuthLayer`] reads this via the
//! [`doxa::DocumentedLayer`] trait so the layer is fully
//! self-describing — call sites use
//! [`doxa::OpenApiRouterExt::layer_documented`] with a single
//! argument and the contribution is inferred automatically.

use doxa::{
    DocumentedHeader, HeaderParam, LayerContribution, ResponseContribution, SecurityContribution,
};

/// Marker type for the `Authorization` header carrying a Bearer JWT.
///
/// Implements [`DocumentedHeader`] so the same marker can be reused
/// on the layer side via [`HeaderParam::typed`] and on the
/// handler side via [`doxa::Header`] / the `headers(...)`
/// macro argument once those land in commits 6–7.
pub struct BearerAuthorization;

impl DocumentedHeader for BearerAuthorization {
    fn name() -> &'static str {
        "Authorization"
    }
    fn description() -> &'static str {
        "Bearer JWT issued by the configured identity provider."
    }
    fn example() -> Option<&'static str> {
        Some("Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")
    }
}

/// Full OpenAPI contribution made by [`crate::AuthLayer`]: the
/// `Authorization` header parameter and a security requirement naming the
/// scheme `scheme_name`.
///
/// The 401 response schema is no longer declared here — it is inferred
/// from [`AuthError`](doxa_policy::AuthError)'s `#[derive(ApiError)]`
/// which generates typed per-status-code schemas directly on the error
/// enum.
///
/// `scheme_name` must match a security scheme already registered on the
/// [`doxa::ApiDocBuilder`] via
/// [`bearer_security`](doxa::ApiDocBuilder::bearer_security) (or
/// [`bearer_security_with_format`](doxa::ApiDocBuilder::bearer_security_with_format))
/// before the handlers returning `AuthError` are mounted. The conventional
/// value is `"bearer"`.
pub fn auth_contribution(scheme_name: impl Into<String>) -> LayerContribution {
    LayerContribution::new()
        .with_header(HeaderParam::typed::<BearerAuthorization>())
        .with_security(SecurityContribution::new(scheme_name))
        .with_response(ResponseContribution::unauthorized())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_authorization_uses_titlecase_name_at_runtime() {
        assert_eq!(BearerAuthorization::name(), "Authorization");
    }

    #[test]
    fn bearer_authorization_has_description_and_example() {
        assert!(!BearerAuthorization::description().is_empty());
        assert!(BearerAuthorization::example().is_some());
    }

    #[test]
    fn auth_contribution_lists_authorization_header_required() {
        let c = auth_contribution("bearer");
        // Round-trip via apply_contribution to confirm the header
        // ends up with `in: header, required: true`.
        let mut openapi = utoipa::openapi::OpenApiBuilder::new().build();
        openapi.paths.paths.insert(
            "/x".to_string(),
            utoipa::openapi::path::PathItem::new(
                utoipa::openapi::path::HttpMethod::Get,
                utoipa::openapi::path::OperationBuilder::new().build(),
            ),
        );
        doxa::apply_contribution(&mut openapi, &c);
        let op = openapi.paths.paths["/x"].get.as_ref().unwrap();
        let params = op.parameters.as_ref().expect("parameters");
        let auth = params
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case("authorization"))
            .expect("authorization header present");
        assert!(matches!(
            auth.parameter_in,
            utoipa::openapi::path::ParameterIn::Header
        ));
        assert!(matches!(auth.required, utoipa::openapi::Required::True));
    }

    #[test]
    fn auth_contribution_includes_401_response() {
        let c = auth_contribution("bearer");
        let mut openapi = utoipa::openapi::OpenApiBuilder::new().build();
        openapi.paths.paths.insert(
            "/x".to_string(),
            utoipa::openapi::path::PathItem::new(
                utoipa::openapi::path::HttpMethod::Get,
                utoipa::openapi::path::OperationBuilder::new().build(),
            ),
        );
        doxa::apply_contribution(&mut openapi, &c);
        let op = openapi.paths.paths["/x"].get.as_ref().unwrap();
        assert!(op.responses.responses.contains_key("401"));
    }

    #[test]
    fn auth_contribution_uses_supplied_scheme_name() {
        let c = auth_contribution("jwt");
        let mut openapi = utoipa::openapi::OpenApiBuilder::new().build();
        openapi.paths.paths.insert(
            "/x".to_string(),
            utoipa::openapi::path::PathItem::new(
                utoipa::openapi::path::HttpMethod::Get,
                utoipa::openapi::path::OperationBuilder::new().build(),
            ),
        );
        doxa::apply_contribution(&mut openapi, &c);
        let op = openapi.paths.paths["/x"].get.as_ref().unwrap();
        let security = op.security.as_ref().expect("security set");
        // Serialize and look for the scheme name to confirm override.
        let rendered = serde_json::to_string(security).unwrap();
        assert!(
            rendered.contains("\"jwt\""),
            "expected 'jwt' scheme name in {rendered}"
        );
    }

    #[test]
    fn auth_contribution_includes_bearer_security() {
        let c = auth_contribution("bearer");
        let mut openapi = utoipa::openapi::OpenApiBuilder::new().build();
        openapi.paths.paths.insert(
            "/x".to_string(),
            utoipa::openapi::path::PathItem::new(
                utoipa::openapi::path::HttpMethod::Get,
                utoipa::openapi::path::OperationBuilder::new().build(),
            ),
        );
        doxa::apply_contribution(&mut openapi, &c);
        let op = openapi.paths.paths["/x"].get.as_ref().unwrap();
        let security = op.security.as_ref().expect("security set");
        assert_eq!(security.len(), 1);
    }
}
