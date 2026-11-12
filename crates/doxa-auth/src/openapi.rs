//! OpenAPI metadata for [`crate::AuthLayer`]: a security requirement and a 401 on each
//! operation behind it. The credential is the security scheme only; OpenAPI reserves an
//! `Authorization` header parameter.

use doxa::{DocumentedLayer, LayerContribution, ResponseContribution, SecurityContribution};

/// [`auth_contribution`] under the `"bearer"` scheme, for `#[doxa::layers(docs = [AuthDocs])]`.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuthDocs;

impl DocumentedLayer for AuthDocs {
    fn contribution(&self) -> LayerContribution {
        auth_contribution("bearer")
    }
}

/// [`crate::AuthLayer`]'s contribution: a requirement on `scheme_name`, which must be registered
/// on the [`doxa::ApiDocBuilder`], and a 401.
pub fn auth_contribution(scheme_name: impl Into<String>) -> LayerContribution {
    LayerContribution::new()
        .with_security(SecurityContribution::new(scheme_name))
        .with_response(ResponseContribution::unauthorized())
}

#[cfg(test)]
mod tests {
    use super::*;
    use utoipa::openapi::path::{HttpMethod, Operation, OperationBuilder, PathItem};

    /// The operation `c` produces when applied to a lone `GET /x`.
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
