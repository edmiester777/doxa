//! Protected string wrapper for secrets that must not leak into logs or traces.
//!
//! [`ProtectedString`] wraps a [`secrecy::SecretString`] in an [`Arc`] for
//! cheap cloning (config structs are cloned freely throughout downstream
//! codebases). The inner value is zeroized on drop via the `secrecy` crate.
//!
//! # Masking behaviour
//!
//! Both [`fmt::Display`] and [`fmt::Debug`] emit `[REDACTED]` instead of the
//! inner value, making it safe to include in tracing spans, error messages, and
//! serialized API responses without accidentally leaking credentials.
//!
//! # Access
//!
//! Use [`ProtectedString::expose`] to access the inner `&str`. This makes
//! every secret-access site grep-able and auditable.

#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::fmt;
use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utoipa::openapi::{
    schema::SchemaType, KnownFormat, ObjectBuilder, RefOr, Schema, SchemaFormat, Type,
};
use utoipa::{PartialSchema, ToSchema};

/// A string value that is masked in `Debug`, `Display`, and serialized output.
///
/// Backed by [`Arc<SecretString>`](std::sync::Arc) for cheap cloning and
/// `zeroize`-on-drop. Use [`expose`](Self::expose) to access the inner `&str`
/// — this makes every secret-access site explicit and auditable.
///
/// # Serde
///
/// Deserializes transparently from a plain string (YAML/JSON config files).
/// Serialization emits `"[REDACTED]"` to prevent accidental leakage through
/// JSON API responses or serialized config dumps.
#[derive(Clone)]
pub struct ProtectedString(Arc<SecretString>);

impl ProtectedString {
    /// Access the secret value. Every call site is grep-able for auditing.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Display for ProtectedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Debug for ProtectedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProtectedString")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl PartialEq for ProtectedString {
    fn eq(&self, other: &Self) -> bool {
        self.expose() == other.expose()
    }
}

impl From<String> for ProtectedString {
    fn from(s: String) -> Self {
        Self(Arc::new(SecretString::from(s)))
    }
}

impl From<&str> for ProtectedString {
    fn from(s: &str) -> Self {
        Self(Arc::new(SecretString::from(s.to_owned())))
    }
}

impl Serialize for ProtectedString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for ProtectedString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from(s))
    }
}

/// OpenAPI schema for [`ProtectedString`].
///
/// Described as a `string` with `format: password` so documentation
/// viewers render it masked. The serialized form (always `"[REDACTED]"`)
/// matches this contract — clients should never expect the real value
/// over the wire.
impl PartialSchema for ProtectedString {
    fn schema() -> RefOr<Schema> {
        RefOr::T(Schema::Object(
            ObjectBuilder::new()
                .schema_type(SchemaType::Type(Type::String))
                .format(Some(SchemaFormat::KnownFormat(KnownFormat::Password)))
                .description(Some(
                    "Secret value. Always serialized as `\"[REDACTED]\"` — \
                     the real value is never returned in responses.",
                ))
                .build(),
        ))
    }
}

impl ToSchema for ProtectedString {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_is_redacted() {
        let ps = ProtectedString::from("super-secret-key");
        let debug = format!("{:?}", ps);
        assert!(
            !debug.contains("super-secret-key"),
            "Debug output must not contain the secret"
        );
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn display_output_is_redacted() {
        let ps = ProtectedString::from("super-secret-key");
        let display = format!("{}", ps);
        assert_eq!(display, "[REDACTED]");
    }

    #[test]
    fn expose_returns_inner_value() {
        let ps = ProtectedString::from("my-api-key");
        assert_eq!(ps.expose(), "my-api-key");
    }

    #[test]
    fn deserialize_from_plain_string() {
        let ps: ProtectedString = serde_json::from_str(r#""my-secret""#).unwrap();
        assert_eq!(ps.expose(), "my-secret");
    }

    #[test]
    fn serialize_produces_redacted() {
        let ps = ProtectedString::from("my-secret");
        let json = serde_json::to_string(&ps).unwrap();
        assert_eq!(json, r#""[REDACTED]""#);
    }

    #[test]
    fn clone_preserves_value() {
        let ps = ProtectedString::from("secret");
        let cloned = ps.clone();
        assert_eq!(cloned.expose(), "secret");
    }

    #[test]
    fn partial_eq_compares_inner_values() {
        let a = ProtectedString::from("same");
        let b = ProtectedString::from("same");
        let c = ProtectedString::from("different");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn from_string_and_from_str() {
        let from_str = ProtectedString::from("test");
        let from_string = ProtectedString::from("test".to_string());
        assert_eq!(from_str, from_string);
    }
}
