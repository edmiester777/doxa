//! Call doxa routes from the browser as plain async functions.
//!
//! In a crate whose `build.rs` calls `doxa_role::client()`, every `#[get]` /
//! `#[post]` / … handler becomes a function of the same name that sends a
//! request to that same route and decodes the answer.

#![deny(missing_docs)]

mod arg;
pub mod cache;
mod cached;
mod call;
mod can;
mod client;
mod fetch;
mod response;
mod sse;
pub mod task;
pub mod transport;

pub use arg::{Arg, ArgFor, ClientArg, Foreign, Form, Granted, Json, Outgoing, Path, Query};
pub use cache::{invalidate, invalidate_all, CacheConfig};
pub use cached::Cached;
pub use call::Call;
pub use can::{Permission, Probe};
pub use client::{Client, ClientConfig};
pub use fetch::{Fetch, NoError};
pub use response::{AliasedResult, FromResponse, SseStream, StatusCode, Unsupported};
pub use sse::{Backoff, EventStream};

#[doc(hidden)]
pub use doxa_wire as __wire;

/// Declare a route key shared by server and client.
///
/// ```
/// doxa_client::route_key!(pub WidgetKey { name: String });
///
/// let key: WidgetKey = doxa_client::Arg::into_arg("sprocket");
/// assert_eq!(key.name, "sprocket");
/// ```
#[macro_export]
macro_rules! route_key {
    (
        $(#[$meta:meta])*
        $vis:vis $name:ident { $($field:ident : $ty:ty),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, ::serde::Serialize, ::serde::Deserialize)]
        $vis struct $name {
            $(
                #[allow(missing_docs)]
                pub $field: $ty,
            )+
        }

        impl $crate::__wire::KeyNames for $name {
            const NAMES: &'static [&'static str] = &[$(::core::stringify!($field)),+];
        }

        $crate::__single_field_key!($name; $($field: $ty),+);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __single_field_key {
    ($name:ident; $field:ident : $ty:ty) => {
        impl<'a> $crate::Arg<$name> for &'a str
        where
            $ty: ::core::convert::From<&'a str>,
        {
            fn into_arg(self) -> $name {
                $name {
                    $field: ::core::convert::From::from(self),
                }
            }
        }

        impl $crate::Arg<$name> for $ty {
            fn into_arg(self) -> $name {
                $name { $field: self }
            }
        }

        impl<'a> $crate::Arg<$name> for &'a $ty {
            fn into_arg(self) -> $name {
                $name {
                    $field: ::core::clone::Clone::clone(self),
                }
            }
        }
    };
    ($name:ident; $($rest:tt)*) => {};
}
