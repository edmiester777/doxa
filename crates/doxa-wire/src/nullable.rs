//! [`Nullable<T>`]: a field that is left out, sent as `null`, or sent with a value.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A field that is left out, sent as `null`, or sent with a value.
///
/// A struct field needs `#[serde(default, skip_serializing_if = "Nullable::is_absent")]`;
/// `#[dto]` adds both. Without `default` serde reads a missing field as `Null`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Nullable<T> {
    /// Not sent: leave the stored value alone.
    #[default]
    Absent,
    /// Sent as `null`: clear it.
    Null,
    /// Sent with a value.
    Value(T),
}

// Derived `Default` would require `T: Default`.

impl<T> Nullable<T> {
    /// `true` when the field was left out.
    pub fn is_absent(&self) -> bool {
        matches!(self, Nullable::Absent)
    }

    /// Borrows the value.
    pub fn as_ref(&self) -> Nullable<&T> {
        match self {
            Nullable::Absent => Nullable::Absent,
            Nullable::Null => Nullable::Null,
            Nullable::Value(v) => Nullable::Value(v),
        }
    }

    /// Maps the value, keeping `Absent` and `Null`.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Nullable<U> {
        match self {
            Nullable::Absent => Nullable::Absent,
            Nullable::Null => Nullable::Null,
            Nullable::Value(v) => Nullable::Value(f(v)),
        }
    }
}

impl<T: Serialize> Serialize for Nullable<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Nullable::Value(v) => s.serialize_some(v),
            Nullable::Null => s.serialize_none(),
            // As `null` it would clear the field it was meant to leave alone.
            Nullable::Absent => Err(serde::ser::Error::custom(
                "`Nullable::Absent` must be skipped: add `skip_serializing_if = \"Nullable::is_absent\"`",
            )),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Nullable<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match Option::<T>::deserialize(d)? {
            Some(v) => Nullable::Value(v),
            None => Nullable::Null,
        })
    }
}

#[cfg(feature = "garde")]
mod garde_rules {
    use garde::error::NoKey;
    use garde::rules::{
        alphanumeric::Alphanumeric,
        ascii::Ascii,
        contains::Contains,
        inner::Inner,
        ip::{Ip, IpKind},
        length::{bytes::Bytes, chars::Chars, simple::Simple, utf16::Utf16CodeUnits},
        pattern::{Matcher, Pattern},
        prefix::Prefix,
        range::{Bounds, OutOfBounds},
        suffix::Suffix,
    };
    use garde::{Error, Path, Report, Validate};

    use super::Nullable;

    /// One rule trait, checked on `Value` only, the way garde checks `Option<T>`.
    macro_rules! on_value {
        ($trait:ident :: $method:ident ($($arg:ident: $ty:ty),*) -> $ret:ty = $ok:expr) => {
            impl<T: $trait> $trait for Nullable<T> {
                fn $method(&self, $($arg: $ty),*) -> $ret {
                    match self {
                        Nullable::Value(v) => v.$method($($arg),*),
                        _ => $ok,
                    }
                }
            }
        };
    }

    on_value!(Simple::validate_length(min: usize, max: usize) -> Result<(), Error> = Ok(()));
    on_value!(Chars::validate_num_chars(min: usize, max: usize) -> Result<(), Error> = Ok(()));
    on_value!(Bytes::validate_num_bytes(min: usize, max: usize) -> Result<(), Error> = Ok(()));
    on_value!(Utf16CodeUnits::validate_num_code_units(min: usize, max: usize) -> Result<(), Error> = Ok(()));
    on_value!(Ascii::validate_ascii() -> bool = true);
    on_value!(Alphanumeric::validate_alphanumeric() -> bool = true);
    on_value!(Contains::validate_contains(pat: &str) -> bool = true);
    on_value!(Prefix::validate_prefix(pat: &str) -> bool = true);
    on_value!(Suffix::validate_suffix(pat: &str) -> bool = true);
    #[cfg(feature = "garde-unicode")]
    on_value!(Graphemes::validate_num_graphemes(min: usize, max: usize) -> Result<(), Error> = Ok(()));
    #[cfg(feature = "garde-unicode")]
    use garde::rules::length::graphemes::Graphemes;
    #[cfg(feature = "garde-email")]
    on_value!(Email::validate_email() -> Result<(), InvalidEmail> = Ok(()));
    #[cfg(feature = "garde-email")]
    use garde::rules::email::{Email, InvalidEmail};
    #[cfg(feature = "garde-url")]
    on_value!(Url::validate_url() -> Result<(), InvalidUrl> = Ok(()));
    #[cfg(feature = "garde-url")]
    use garde::rules::url::{InvalidUrl, Url};
    #[cfg(feature = "garde-credit-card")]
    on_value!(CreditCard::validate_credit_card() -> Result<(), InvalidCreditCard> = Ok(()));
    #[cfg(feature = "garde-credit-card")]
    use garde::rules::credit_card::{CreditCard, InvalidCreditCard};
    #[cfg(feature = "garde-phone-number")]
    on_value!(PhoneNumber::validate_phone_number() -> Result<(), InvalidPhoneNumber> = Ok(()));
    #[cfg(feature = "garde-phone-number")]
    use garde::rules::phone_number::{InvalidPhoneNumber, PhoneNumber};

    impl<T: Pattern> Pattern for Nullable<T> {
        fn validate_pattern<M: Matcher>(&self, matcher: &M) -> bool {
            match self {
                Nullable::Value(v) => v.validate_pattern(matcher),
                _ => true,
            }
        }
    }

    impl<T: Ip> Ip for Nullable<T> {
        type Error = T::Error;

        fn validate_ip(&self, kind: IpKind) -> Result<(), Self::Error> {
            match self {
                Nullable::Value(v) => v.validate_ip(kind),
                _ => Ok(()),
            }
        }
    }

    impl<T: Bounds> Bounds for Nullable<T> {
        type Size = T::Size;

        const MIN: Self::Size = T::MIN;
        const MAX: Self::Size = T::MAX;

        fn validate_bounds(&self, lower: Self::Size, upper: Self::Size) -> Result<(), OutOfBounds> {
            match self {
                Nullable::Value(v) => v.validate_bounds(lower, upper),
                _ => Ok(()),
            }
        }
    }

    impl<T> Inner<T> for Nullable<T> {
        type Key = NoKey;

        fn validate_inner<F: FnMut(&T, &Self::Key)>(&self, mut f: F) {
            if let Nullable::Value(v) = self {
                f(v, &NoKey::default())
            }
        }
    }

    impl<T: Validate> Validate for Nullable<T> {
        type Context = T::Context;

        fn validate_into(
            &self,
            ctx: &Self::Context,
            parent: &mut dyn FnMut() -> Path,
            report: &mut Report,
        ) {
            if let Nullable::Value(v) = self {
                v.validate_into(ctx, parent, report)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Body {
        #[serde(default, skip_serializing_if = "Nullable::is_absent")]
        note: Nullable<String>,
    }

    #[test]
    fn three_states_round_trip() {
        let read = |s: &str| serde_json::from_str::<Body>(s).unwrap().note;
        assert_eq!(read("{}"), Nullable::Absent);
        assert_eq!(read(r#"{"note":null}"#), Nullable::Null);
        assert_eq!(read(r#"{"note":"n"}"#), Nullable::Value("n".to_owned()));
        let write = |note| serde_json::to_string(&Body { note }).unwrap();
        assert_eq!(write(Nullable::Absent), "{}");
        assert_eq!(write(Nullable::Null), r#"{"note":null}"#);
        assert_eq!(write(Nullable::Value("n".into())), r#"{"note":"n"}"#);
    }

    #[test]
    fn an_unskipped_absent_refuses_to_serialize() {
        let err = serde_json::to_string(&Nullable::<u8>::Absent).unwrap_err();
        assert!(err.to_string().contains("must be skipped"), "{err}");
    }
}
