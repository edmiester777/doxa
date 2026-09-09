//! OpenAPI metadata for [`crate::AuthLayer`].
//!
//! [`auth_contribution`] returns the bundle of security requirement and
//! 401 response that the auth pipeline adds to every operation behind
//! it. [`crate::AuthLayer`] reads this via the
//! [`doxa::DocumentedLayer`] trait so the layer is fully
//! self-describing — call sites use
//! [`doxa::OpenApiRouterExt::layer_documented`] with a single
//! argument and the contribution is inferred automatically.
//!
//! # Why there is no `Authorization` header parameter
//!
//! The credential is a security scheme, and a security scheme only.
//! OpenAPI reserves `Authorization` as an `in: header` parameter name —
//! a definition using it SHALL be ignored — because `securitySchemes`
//! already describes the credential, and describes it better: the
//! scheme's type and the scopes the operation needs are both things a
//! header parameter has no way to say.
//!
//! Declaring both stated the same requirement twice with nothing
//! reconciling the two, and the copies drifted. Worse, generators that
//! overlook the reserved-name rule read the parameter literally: every
//! operation grew a mandatory `Authorization` argument, so callers had
//! to thread a raw token through each call site to satisfy a header
//! their client already set centrally.

use doxa::{LayerContribution, ResponseContribution, SecurityContribution};

/// Full OpenAPI contribution made by [`crate::AuthLayer`]: a security
/// requirement naming the scheme `scheme_name`, and the 401 the pipeline
/// returns when no acceptable credential arrives.
///
/// The 401 response schema is not declared here — it is inferred
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
        .with_security(SecurityContribution::new(scheme_name))
        .with_response(ResponseContribution::unauthorized())
}

#[cfg(test)]
mod tests {
    use super::*;
    use utoipa::openapi::path::{HttpMethod, Operation, OperationBuilder, PathItem};

    /// Apply `c` to a lone `GET /x` and hand back the operation it
    /// landed on. What the contribution *means* is only visible once
    /// stamped, so every assertion below reads the applied form.
    fn applied(c: &LayerContribution) -> Operation {
        let mut openapi = utoipa::openapi::OpenApiBuilder::new().build();
        openapi.paths.paths.insert(
            "/x".to_string(),
            PathItem::new(HttpMethod::Get, OperationBuilder::new().build()),
        );
        doxa::apply_contribution(&mut openapi, c);
        openapi.paths.paths["/x"]
            .get
            .as_ref()
            .expect("the operation applied to")
            .clone()
    }

    /// The credential travels as `security` alone. A header parameter
    /// naming it is the thing OpenAPI reserves and every generator
    /// reads differently, so the contribution must not contain one —
    /// asserted here rather than left to the document builder's refusal,
    /// which would only catch it once someone assembled a whole spec.
    #[test]
    fn auth_contribution_declares_no_authorization_header_parameter() {
        let op = applied(&auth_contribution("bearer"));
        let declared: Vec<&str> = op
            .parameters
            .iter()
            .flatten()
            .map(|p| p.name.as_str())
            .collect();
        assert!(
            !declared
                .iter()
                .any(|name| name.eq_ignore_ascii_case("authorization")),
            "the credential is a security scheme, not a parameter: {declared:?}",
        );
    }

    #[test]
    fn auth_contribution_includes_401_response() {
        let op = applied(&auth_contribution("bearer"));
        assert!(op.responses.responses.contains_key("401"));
    }

    #[test]
    fn auth_contribution_uses_supplied_scheme_name() {
        let op = applied(&auth_contribution("jwt"));
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
        let op = applied(&auth_contribution("bearer"));
        let security = op.security.as_ref().expect("security set");
        assert_eq!(security.len(), 1);
    }
}
