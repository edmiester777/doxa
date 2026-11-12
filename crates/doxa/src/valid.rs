//! The validating wrappers doxa ships, one per validation library. Each checks the same
//! rules in the server's extractor and in the client before it sends.

use doxa_wire::{FieldErrors, Validates};

/// `Validates` for `$wrapper` around each extractor named, in whichever halves are built.
macro_rules! validates {
    ($wrapper:ident, $value:ident: $bound:path, [$($where:tt)*], $check:expr) => {
        validates!(@each $wrapper, $value: $bound, [$($where)*], $check;
            #[cfg(all(feature = "docs", not(target_arch = "wasm32")))] axum::Json,
            #[cfg(all(feature = "docs", not(target_arch = "wasm32")))] axum::extract::Query,
            #[cfg(all(feature = "docs", not(target_arch = "wasm32")))] axum::extract::Form,
            #[cfg(feature = "client")] doxa_client::Json,
            #[cfg(feature = "client")] doxa_client::Query,
            #[cfg(feature = "client")] doxa_client::Form
        );
    };
    (@each $wrapper:ident, $value:ident: $bound:path, $where:tt, $check:expr;
        $(#[$cfg:meta] $($x:ident)::+),*) => {
        $(
            validates!(@one #[$cfg] $wrapper, $value: $bound, $where, $check, $($x)::+);
        )*
    };
    (@one #[$cfg:meta] $wrapper:ident, $value:ident: $bound:path, [$($where:tt)*], $check:expr, $($x:ident)::+) => {
            #[$cfg]
            impl<$value: $bound> Validates for $wrapper<$($x)::+<$value>>
            $($where)*
            {
                type Value = $value;
                fn check(value: &$value) -> Result<(), FieldErrors> {
                    $check(value)
                }
            }

            /// An optional body: `None` isn't checked.
            #[$cfg]
            impl<$value: $bound> Validates for $wrapper<Option<$($x)::+<$value>>>
            $($where)*
            {
                type Value = Option<$value>;
                fn check(value: &Option<$value>) -> Result<(), FieldErrors> {
                    value.as_ref().map_or(Ok(()), $check)
                }
            }
    };
}

/// An extractor whose value passed its garde rules: `Valid(Json(o)): Valid<Json<NewOrder>>`.
#[cfg(feature = "garde")]
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(
    all(feature = "docs", feature = "macros", not(target_arch = "wasm32")),
    derive(doxa_macros::Validator)
)]
pub struct Valid<E>(pub E);

#[cfg(feature = "garde")]
validates!(Valid, T: ::garde::Validate, [where T::Context: Default], |v: &T| {
    ::garde::Validate::validate(v).map_err(FieldErrors::from)
});

/// Wrappers checked by the `validator` crate.
#[cfg(feature = "validator")]
pub mod validator {
    use super::*;

    /// An extractor whose value passed its `validator` rules.
    #[derive(Debug, Clone, Copy, Default)]
    #[cfg_attr(
        all(feature = "docs", feature = "macros", not(target_arch = "wasm32")),
        derive(doxa_macros::Validator)
    )]
    pub struct Valid<E>(pub E);

    validates!(Valid, T: ::validator::Validate, [], |v: &T| {
        ::validator::Validate::validate(v).map_err(FieldErrors::from)
    });
}

/// Wrappers checked by the `serde_valid` crate.
#[cfg(feature = "serde-valid")]
pub mod serde_valid {
    use super::*;

    /// An extractor whose value passed its `serde_valid` rules.
    #[derive(Debug, Clone, Copy, Default)]
    #[cfg_attr(
        all(feature = "docs", feature = "macros", not(target_arch = "wasm32")),
        derive(doxa_macros::Validator)
    )]
    pub struct Valid<E>(pub E);

    validates!(Valid, T: ::serde_valid::Validate, [], |v: &T| {
        ::serde_valid::Validate::validate(v).map_err(FieldErrors::from)
    });
}
