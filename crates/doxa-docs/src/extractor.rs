//! [`Header<H>`] — typed header extractor that doubles as a marker
//! the macro pass can recognize in handler signatures. Pairs with
//! [`DocumentedHeader`] so the wire name is resolved at runtime.

use std::marker::PhantomData;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;

use crate::headers::DocumentedHeader;

/// Extracts a header value by name, where the name is supplied
/// type-level via [`DocumentedHeader::name`]. Modeled after
/// [`axum_extra::TypedHeader`](https://docs.rs/axum-extra/latest/axum_extra/typed_header/struct.TypedHeader.html)
/// but using our own [`DocumentedHeader`] trait so the macro pass
/// can resolve the wire name at runtime without depending on the
/// foreign [`headers`](https://docs.rs/headers) crate.
///
/// # Example
///
/// ```ignore
/// use doxa::{DocumentedHeader, Header};
///
/// pub struct XApiKey;
/// impl DocumentedHeader for XApiKey {
///     fn name() -> &'static str { "X-Api-Key" }
///     fn description() -> &'static str { "Tenant API key" }
/// }
///
/// async fn handler(Header(key): Header<XApiKey>) -> &'static str {
///     // `key` is the raw header value as a String.
///     "ok"
/// }
/// ```
///
/// Handlers extracting via [`Header<H>`] are auto-registered in the
/// OpenAPI spec by the `#[get]` / `#[post]` / etc. macros — the
/// macro recognizes the wrapper type and emits a
/// `params(DocHeaderEntry<H>)` entry. No explicit `headers(...)`
/// annotation is needed for the documented case.
pub struct Header<H: DocumentedHeader>(pub String, pub PhantomData<H>);

impl<S, H> FromRequestParts<S> for Header<H>
where
    S: Send + Sync,
    H: DocumentedHeader,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let value = parts
            .headers
            .get(H::name())
            .ok_or((StatusCode::BAD_REQUEST, "missing required header"))?
            .to_str()
            .map_err(|_| (StatusCode::BAD_REQUEST, "header is not valid UTF-8"))?
            .to_string();
        Ok(Self(value, PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::Request;

    struct XApiKey;
    impl DocumentedHeader for XApiKey {
        fn name() -> &'static str {
            "X-Api-Key"
        }
    }

    fn parts_with_header(name: &str, value: &str) -> Parts {
        let req = Request::builder()
            .uri("/x")
            .header(name, value)
            .body(())
            .unwrap();
        req.into_parts().0
    }

    #[tokio::test]
    async fn header_extractor_returns_value_when_header_present() {
        let mut parts = parts_with_header("X-Api-Key", "ak_live_42");
        let h = Header::<XApiKey>::from_request_parts(&mut parts, &())
            .await
            .expect("present");
        assert_eq!(h.0, "ak_live_42");
    }

    #[tokio::test]
    async fn header_extractor_returns_400_when_header_missing() {
        let req = Request::builder().uri("/x").body(()).unwrap();
        let mut parts = req.into_parts().0;
        let res = Header::<XApiKey>::from_request_parts(&mut parts, &()).await;
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn header_extractor_returns_400_when_header_not_utf8() {
        let req = Request::builder()
            .uri("/x")
            .header("X-Api-Key", &[0xff, 0xfe][..])
            .body(())
            .unwrap();
        let mut parts = req.into_parts().0;
        let res = Header::<XApiKey>::from_request_parts(&mut parts, &()).await;
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn header_extractor_lookup_is_case_insensitive() {
        // axum stores header names case-insensitively, so this is a
        // sanity-check on the round-trip.
        let mut parts = parts_with_header("x-api-key", "lower");
        let h = Header::<XApiKey>::from_request_parts(&mut parts, &())
            .await
            .expect("present");
        assert_eq!(h.0, "lower");
    }
}
