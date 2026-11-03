//! [`Validates`]: one check, run by the server's extractor and by the client before it sends.

#[allow(unused_imports)]
use crate::{FieldError, FieldErrors};

/// A validating extractor wrapper, such as `Valid<Json<T>>`: the rules its `Value` must pass.
///
/// The server answers `422` with these [`FieldErrors`]; the client refuses the call with the
/// same ones, without sending it.
#[diagnostic::on_unimplemented(
    message = "`{Self}` doesn't say how to check its value",
    note = "implement `doxa::wire::Validates` for it in code both halves compile, and \
            `#[derive(doxa::Validator)]` on the wrapper"
)]
pub trait Validates {
    /// The value the rules are about: `T` in `Valid<Json<T>>`.
    type Value;
    /// `Ok` when `value` passes every rule.
    fn check(value: &Self::Value) -> Result<(), FieldErrors>;
}

#[cfg(any(feature = "garde", feature = "validator", feature = "serde_valid"))]
impl FieldErrors {
    fn push(&mut self, path: String, message: impl Into<String>) {
        self.0.push(FieldError {
            path,
            message: message.into(),
        });
    }
}

#[cfg(any(feature = "validator", feature = "serde_valid"))]
fn join(prefix: &str, field: &str) -> String {
    match prefix {
        "" => field.to_owned(),
        p => format!("{p}.{field}"),
    }
}

#[cfg(feature = "garde")]
impl From<garde::Report> for FieldErrors {
    fn from(report: garde::Report) -> Self {
        let mut out = FieldErrors::default();
        for (path, e) in report.iter() {
            out.push(path.to_string(), e.message());
        }
        out
    }
}

#[cfg(feature = "validator")]
impl From<validator::ValidationErrors> for FieldErrors {
    fn from(errors: validator::ValidationErrors) -> Self {
        fn walk(prefix: &str, errors: &validator::ValidationErrors, out: &mut FieldErrors) {
            // A HashMap underneath; sorted so the same input always reads the same way.
            let mut fields: Vec<_> = errors.errors().iter().collect();
            fields.sort_by(|a, b| a.0.cmp(b.0));
            for (field, kind) in fields {
                let path = join(prefix, field);
                match kind {
                    validator::ValidationErrorsKind::Field(es) => {
                        for e in es {
                            let message = e.message.as_deref().unwrap_or(&e.code);
                            out.push(path.clone(), message);
                        }
                    }
                    validator::ValidationErrorsKind::Struct(inner) => walk(&path, inner, out),
                    validator::ValidationErrorsKind::List(items) => {
                        for (i, inner) in items {
                            walk(&format!("{path}[{i}]"), inner, out);
                        }
                    }
                }
            }
        }
        let mut out = FieldErrors::default();
        walk("", &errors, &mut out);
        out
    }
}

#[cfg(feature = "serde_valid")]
impl From<serde_valid::validation::Errors> for FieldErrors {
    fn from(errors: serde_valid::validation::Errors) -> Self {
        use serde_valid::validation::Errors;
        fn walk(path: &str, errors: &Errors, out: &mut FieldErrors) {
            match errors {
                Errors::Object(o) => {
                    for e in &o.errors {
                        out.push(path.to_owned(), e.to_string());
                    }
                    for (field, inner) in &o.properties {
                        walk(&join(path, field), inner, out);
                    }
                }
                Errors::Array(a) => {
                    for e in &a.errors {
                        out.push(path.to_owned(), e.to_string());
                    }
                    for (i, inner) in &a.items {
                        walk(&format!("{path}[{i}]"), inner, out);
                    }
                }
                Errors::NewType(es) => {
                    for e in es {
                        out.push(path.to_owned(), e.to_string());
                    }
                }
            }
        }
        let mut out = FieldErrors::default();
        walk("", &errors, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[cfg(feature = "validator")]
    #[test]
    fn validator_paths_flatten_nested_and_list_fields() {
        use validator::Validate;

        #[derive(Validate)]
        struct Line {
            #[validate(length(min = 1, message = "required"))]
            sku: String,
        }
        #[derive(Validate)]
        struct Order {
            #[validate(length(min = 1))]
            name: String,
            #[validate(nested)]
            lines: Vec<Line>,
        }
        let order = Order {
            name: String::new(),
            lines: vec![Line { sku: "a".into() }, Line { sku: String::new() }],
        };
        let errors = FieldErrors::from(order.validate().unwrap_err());
        assert_eq!(errors.get("lines[1].sku"), Some("required"));
        assert_eq!(errors.get("name"), Some("length"));
    }

    #[cfg(feature = "serde_valid")]
    #[test]
    fn serde_valid_paths_flatten_nested_fields() {
        use serde_valid::Validate;

        #[derive(Validate)]
        struct Line {
            #[validate(min_length = 1)]
            sku: String,
        }
        #[derive(Validate)]
        struct Order {
            #[validate]
            lines: Vec<Line>,
        }
        let order = Order {
            lines: vec![Line { sku: String::new() }],
        };
        let errors = FieldErrors::from(order.validate().unwrap_err());
        assert!(errors.get("lines[0].sku").is_some(), "{errors:?}");
    }
}
