//! `Tenant<T>`: the caller's scope, refused when absent or unparseable.

use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;

use doxa::auth::{CapabilityContext, Tenant};

fn parts(tenant: Option<&str>) -> axum::http::request::Parts {
    let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
    request.extensions_mut().insert(CapabilityContext {
        tenant_id: tenant.map(String::from),
        roles: Vec::new(),
    });
    request.into_parts().0
}

async fn status<T>(mut parts: axum::http::request::Parts) -> StatusCode
where
    T: std::str::FromStr + Send,
    T::Err: std::fmt::Display,
{
    match Tenant::<T>::from_request_parts(&mut parts, &()).await {
        Ok(_) => StatusCode::OK,
        Err(e) => e.into_response().status(),
    }
}

#[tokio::test]
async fn the_scope_is_the_tenant() {
    let tenant = Tenant::<String>::from_request_parts(&mut parts(Some("acme")), &())
        .await
        .expect("scoped");
    assert_eq!(&*tenant, "acme");
    assert_eq!(tenant.to_string(), "acme");
}

#[tokio::test]
async fn a_typed_tenant_parses_the_scope() {
    let Tenant(id) = Tenant::<u32>::from_request_parts(&mut parts(Some("42")), &())
        .await
        .expect("a number");
    assert_eq!(id, 42);
    assert_eq!(
        status::<u32>(parts(Some("acme"))).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn no_scope_is_forbidden_and_no_auth_is_unauthorized() {
    assert_eq!(status::<String>(parts(None)).await, StatusCode::FORBIDDEN);
    let mut bare = Request::builder()
        .uri("/")
        .body(Body::empty())
        .unwrap()
        .into_parts()
        .0;
    let rejection = Tenant::<String>::from_request_parts(&mut bare, &())
        .await
        .expect_err("no auth layer ran");
    assert_eq!(rejection.into_response().status(), StatusCode::UNAUTHORIZED);
}
