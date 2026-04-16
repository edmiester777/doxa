//! Cedar entity UID builder with input validation.
//!
//! This module exposes the minimal primitives needed to construct Cedar
//! [`EntityUid`]s safely. Consumer crates layer their own typed helpers
//! on top — for example, a document-management service might define
//! `document_uid` and `folder_uid` helpers that call [`build_uid`] with
//! `"Document"` and `"Folder"` as the entity type, respectively.
//!
//! ## Allowed Characters
//!
//! Component values (tenant ids, role names, resource names) may contain:
//! - ASCII alphanumeric characters (`a-z`, `A-Z`, `0-9`)
//! - Hyphens (`-`), underscores (`_`), and periods (`.`)
//!
//! Everything else — including Cedar delimiters (`"`, `\`, `:`), whitespace,
//! and non-ASCII — is rejected.

use cedar_policy::{EntityId, EntityTypeName, EntityUid};

use crate::error::AuthError;

/// Validate that a component contains only safe characters.
///
/// Rejects empty strings, Cedar delimiters (`"`, `\`, `:`), whitespace, and
/// non-ASCII codepoints. Allowed: `[a-zA-Z0-9_\-.]`.
pub fn validate_component(value: &str, label: &str) -> Result<(), AuthError> {
    if value.is_empty() {
        return Err(AuthError::PolicyFailed(format!(
            "{label} must not be empty"
        )));
    }

    for ch in value.chars() {
        if !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.') {
            return Err(AuthError::PolicyFailed(format!(
                "{label} contains invalid character '{ch}'"
            )));
        }
    }

    Ok(())
}

/// Build a Cedar [`EntityUid`] from a type name and an entity ID string.
///
/// `type_name` must be a valid Cedar type name (single namespace component
/// like `"Model"` or fully qualified like `"acme::Model"`). `eid` is the
/// entity identifier — note that this function does **not** validate `eid`
/// against the safe-character allowlist; callers should run
/// [`validate_component`] on user-supplied id components first if they want
/// injection safety.
pub fn build_uid(type_name: &str, eid: &str) -> Result<EntityUid, AuthError> {
    let tn: EntityTypeName = type_name.parse().map_err(|e| {
        AuthError::PolicyFailed(format!("invalid Cedar type name '{type_name}': {e}"))
    })?;
    let id = eid
        .parse::<EntityId>()
        .map_err(|e| AuthError::PolicyFailed(format!("invalid Cedar entity ID '{eid}': {e}")))?;
    Ok(EntityUid::from_type_name_and_id(tn, id))
}

/// Build a principal entity UID using the given type. Validates the id
/// component before constructing the UID. Used by the Cedar evaluator
/// internally to construct the synthetic per-request principal.
pub(crate) fn principal_uid(type_name: &str, user_id: &str) -> Result<EntityUid, AuthError> {
    validate_component(user_id, "user_id")?;
    build_uid(type_name, user_id)
}

/// Build an action entity UID using the given type. Validates the action
/// name before constructing the UID. Used by the Cedar evaluator to look
/// up actions in the policy set.
pub(crate) fn action_uid(type_name: &str, action_name: &str) -> Result<EntityUid, AuthError> {
    validate_component(action_name, "action_name")?;
    build_uid(type_name, action_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_uid_simple_type() {
        let uid = build_uid("Model", "acme::orders").unwrap();
        assert_eq!(uid.to_string(), r#"Model::"acme::orders""#);
    }

    #[test]
    fn build_uid_rejects_invalid_type_name() {
        let err = build_uid("Has Spaces", "x").unwrap_err();
        assert!(err.to_string().contains("invalid Cedar type name"));
    }

    #[test]
    fn validate_component_allows_alphanumeric_and_punctuation() {
        validate_component("acme-corp_v2.0", "label").unwrap();
    }

    #[test]
    fn validate_component_rejects_empty() {
        let err = validate_component("", "label").unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn validate_component_rejects_double_quote() {
        let err = validate_component("a\"b", "label").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn validate_component_rejects_colon() {
        let err = validate_component("a:b", "label").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn validate_component_rejects_whitespace() {
        let err = validate_component("a b", "label").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn validate_component_rejects_non_ascii() {
        let err = validate_component("acmé", "label").unwrap_err();
        assert!(err.to_string().contains("invalid character"));
    }

    #[test]
    fn principal_uid_uses_given_type() {
        let uid = principal_uid("User", "user_123").unwrap();
        assert_eq!(uid.to_string(), r#"User::"user_123""#);

        let uid = principal_uid("Principal", "user_123").unwrap();
        assert_eq!(uid.to_string(), r#"Principal::"user_123""#);
    }

    #[test]
    fn action_uid_uses_given_type() {
        let uid = action_uid("Action", "query").unwrap();
        assert_eq!(uid.to_string(), r#"Action::"query""#);

        let uid = action_uid("Svc::Action", "query").unwrap();
        assert_eq!(uid.to_string(), r#"Svc::Action::"query""#);
    }
}
