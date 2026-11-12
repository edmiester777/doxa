//! [`ProtectedString`]: a secret that `Debug`, `Display` and serialized responses show as
//! `[REDACTED]`, zeroized on drop. [`ProtectedString::expose`] is the one way to read it.

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

/// A string masked as `"[REDACTED]"` in `Debug`, `Display` and serde, except a browser build sends
/// the real value. Deserializing `"[REDACTED]"` fails, so a form can't store the mask.
#[derive(Clone)]
pub struct ProtectedString(Arc<SecretString>);

const REDACTED: &str = "[REDACTED]";

impl ProtectedString {
    /// Access the secret value. Every call site is grep-able for auditing.
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }

    /// A browser sends what its user typed; everything else redacts.
    fn on_the_wire(&self, browser: bool) -> &str {
        if browser {
            self.expose()
        } else {
            REDACTED
        }
    }
}

impl fmt::Display for ProtectedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Debug for ProtectedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProtectedString").field(&REDACTED).finish()
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
        let browser = cfg!(all(target_arch = "wasm32", target_os = "unknown"));
        serializer.serialize_str(self.on_the_wire(browser))
    }
}

impl<'de> Deserialize<'de> for ProtectedString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == REDACTED {
            return Err(serde::de::Error::custom(
                "`[REDACTED]` is the mask a response carries, not a secret; leave the field out to keep it",
            ));
        }
        Ok(Self::from(s))
    }
}

/// OpenAPI schema for [`ProtectedString`]: a `string` with `format: password`,
/// so documentation viewers render it masked.
impl PartialSchema for ProtectedString {
    fn schema() -> RefOr<Schema> {
        RefOr::T(Schema::Object(
            ObjectBuilder::new()
                .schema_type(SchemaType::Type(Type::String))
                .format(Some(SchemaFormat::KnownFormat(KnownFormat::Password)))
                .description(Some(
                    "Secret value. Responses carry `\"[REDACTED]\"`, never the real value.",
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
    fn the_mask_is_refused_as_a_value() {
        assert!(serde_json::from_str::<ProtectedString>(r#""[REDACTED]""#).is_err());
        assert!(serde_json::from_str::<ProtectedString>(r#""[REDACTED] ""#).is_ok());
    }

    #[test]
    fn serialize_produces_redacted() {
        let ps = ProtectedString::from("my-secret");
        let json = serde_json::to_string(&ps).unwrap();
        assert_eq!(json, r#""[REDACTED]""#);
    }

    #[test]
    fn only_a_browser_build_puts_the_value_on_the_wire() {
        let ps = ProtectedString::from("my-secret");
        assert_eq!(ps.on_the_wire(true), "my-secret");
        assert_eq!(ps.on_the_wire(false), "[REDACTED]");
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
