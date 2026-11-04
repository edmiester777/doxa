//! Sign-in against a fake issuer: redirect, callback, bearer, refresh on the manual clock,
//! one refresh across tabs, and a failed refresh ending every session.

use std::future::IntoFuture;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use doxa::client::layer::transport;
use doxa::client::oidc::{MemoryHost, Oidc, Session, SERVICE};
use doxa::client::transport::RouterTransport;
use doxa::client::{clock, service, task, Call};
use doxa::wire::{Method, RouteSpec};
use serde::Deserialize;
use serde_json::json;

const ISSUER: &str = "https://id.example.com/realms/acme";
const APP: &str = "https://app.example.com";

#[derive(Debug, Clone, Deserialize)]
struct Claims {
    name: String,
}

#[derive(Default)]
struct Issuer {
    challenge: Option<String>,
    nonce: Option<String>,
    refreshes: u32,
    refuse_refresh: bool,
}

type Shared = Arc<Mutex<Issuer>>;

fn b64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = c.iter().fold(0u32, |n, b| (n << 8) | *b as u32) << (8 * (3 - c.len()));
        for i in 0..=c.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

fn id_token(nonce: Option<&str>) -> String {
    let claims = json!({ "name": "Ada", "nonce": nonce });
    format!("e30.{}.sig", b64(claims.to_string().as_bytes()))
}

async fn token(State(s): State<Shared>, Form(f): Form<Vec<(String, String)>>) -> impl IntoResponse {
    let get = |k: &str| f.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let mut s = s.lock().unwrap();
    match get("grant_type").as_deref() {
        Some("authorization_code") => {
            use sha2::Digest;
            let verifier = get("code_verifier").unwrap_or_default();
            let challenge = b64(&sha2::Sha256::digest(verifier.as_bytes()));
            if Some(challenge) != s.challenge || get("code").as_deref() != Some("the-code") {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "invalid_grant" })),
                );
            }
            let id = id_token(s.nonce.as_deref());
            (
                StatusCode::OK,
                Json(
                    json!({ "access_token": "a0", "refresh_token": "r0", "id_token": id, "expires_in": 300 }),
                ),
            )
        }
        Some("refresh_token") if !s.refuse_refresh => {
            s.refreshes += 1;
            let n = s.refreshes;
            (
                StatusCode::OK,
                Json(
                    json!({ "access_token": format!("a{n}"), "refresh_token": format!("r{n}"), "id_token": id_token(None), "expires_in": 300 }),
                ),
            )
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_grant" })),
        ),
    }
}

fn issuer(shared: Shared) -> RouterTransport {
    let router = Router::new()
        .route(
            "/realms/acme/.well-known/openid-configuration",
            get(|| async {
                Json(json!({
                    "authorization_endpoint": format!("{ISSUER}/auth"),
                    "token_endpoint": format!("{ISSUER}/token"),
                    "end_session_endpoint": format!("{ISSUER}/logout"),
                }))
            }),
        )
        .route("/realms/acme/token", post(token))
        .with_state(shared);
    RouterTransport::new(router)
}

fn query(url: &str, key: &str) -> String {
    let q = url.split_once('?').unwrap().1;
    serde_urlencoded::from_str::<Vec<(String, String)>>(q)
        .unwrap()
        .into_iter()
        .find(|(k, _)| k == key)
        .unwrap()
        .1
}

fn start(host: &MemoryHost) -> Oidc<Claims> {
    Oidc::<Claims>::issuer(ISSUER)
        .client_id("web")
        .scopes(["openid", "profile"])
        .host(host.clone())
        .install()
}

/// A signed-in tab: sign-in, the issuer, and the callback.
fn signed_in(shared: &Shared) -> (MemoryHost, Oidc<Claims>) {
    service(SERVICE)
        .layers()
        .push(transport(issuer(shared.clone())));
    let host = MemoryHost::new(&format!("{APP}/orders?page=2"));
    let oidc = start(&host);
    task::run_until_stalled();
    assert!(matches!(oidc.session(), Session::SignedOut));

    oidc.sign_in();
    task::run_until_stalled();
    let auth = host.left_for().expect("left for the issuer");
    assert!(auth.starts_with(&format!("{ISSUER}/auth?")), "{auth}");
    assert_eq!(query(&auth, "code_challenge_method"), "S256");
    {
        let mut s = shared.lock().unwrap();
        s.challenge = Some(query(&auth, "code_challenge"));
        s.nonce = Some(query(&auth, "nonce"));
    }
    let state = query(&auth, "state");

    // The issuer sends the browser back, and the page loads again.
    host.arrive(&format!("{APP}/?code=the-code&state={state}"));
    let oidc = start(&host);
    task::run_until_stalled();
    (host, oidc)
}

#[test]
fn a_callback_signs_in_and_returns_to_where_sign_in_began() {
    let _clock = clock::manual();
    let shared = Shared::default();
    let (host, oidc) = signed_in(&shared);
    let Session::SignedIn(tokens) = oidc.session() else {
        panic!("{:?}", oidc.session())
    };
    assert_eq!(tokens.claims().name, "Ada");
    assert_eq!(tokens.access_token(), "a0");
    assert_eq!(
        doxa::client::oidc::Host::url(&host),
        format!("{APP}/orders?page=2")
    );
}

#[test]
fn a_callback_with_the_wrong_state_signs_nobody_in() {
    let _clock = clock::manual();
    let shared = Shared::default();
    service(SERVICE)
        .layers()
        .push(transport(issuer(shared.clone())));
    let host = MemoryHost::new(&format!("{APP}/"));
    let oidc = start(&host);
    task::run_until_stalled();
    oidc.sign_in();
    task::run_until_stalled();
    host.arrive(&format!("{APP}/?code=the-code&state=forged"));
    let oidc = start(&host);
    task::run_until_stalled();
    assert!(matches!(oidc.session(), Session::SignedOut));
}

static ME: RouteSpec = RouteSpec {
    method: Method::Get,
    path: "/me",
    operation_id: "me",
    entities: &[],
    dry_run: false,
    invalidates: true,
    package: "app",
};

#[test]
fn calls_carry_the_access_token_and_a_refresh_lands_before_it_expires() {
    let clock = clock::manual();
    let shared = Shared::default();
    let (_host, oidc) = signed_in(&shared);
    let app = Router::new().route(
        "/me",
        get(|h: HeaderMap| async move {
            Json(
                h.get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_owned(),
            )
        }),
    );
    let s = service("app");
    s.layers().push(oidc.bearer());
    s.layers().push(transport(RouterTransport::new(app)));
    let seen = task::block_on(
        Call::<doxa::client::Json<String>>::new(&ME)
            .fresh()
            .into_future(),
    );
    assert_eq!(*seen.unwrap(), "Bearer a0");

    // A tenth of five minutes early, at most thirty seconds.
    clock.advance(Duration::from_secs(269));
    task::run_until_stalled();
    assert_eq!(shared.lock().unwrap().refreshes, 0);
    clock.advance(Duration::from_secs(2));
    task::run_until_stalled();
    assert_eq!(shared.lock().unwrap().refreshes, 1);
    assert_eq!(oidc.session().tokens().unwrap().access_token(), "a1");
    let seen = task::block_on(
        Call::<doxa::client::Json<String>>::new(&ME)
            .fresh()
            .into_future(),
    );
    assert_eq!(*seen.unwrap(), "Bearer a1");
}

#[test]
fn two_tabs_refresh_once() {
    let clock = clock::manual();
    let shared = Shared::default();
    let (host, first) = signed_in(&shared);
    // A second tab of the same app, resuming its own stored session.
    let tab = host.tab(&format!("{APP}/"));
    doxa::client::oidc::Host::store(&tab, "doxa-oidc:refresh", "r0");
    let second = Oidc::<Claims>::issuer(ISSUER)
        .client_id("web")
        .host(tab.clone())
        .install();
    task::run_until_stalled();
    let resumed = shared.lock().unwrap().refreshes;
    // The resume told the first tab, so both hold the same tokens and expire together.
    let held = |o: &Oidc<Claims>| o.session().tokens().unwrap().access_token().to_owned();
    assert_eq!(held(&first), held(&second));

    clock.advance(Duration::from_secs(300));
    task::run_until_stalled();
    clock.advance(Duration::from_secs(11));
    task::run_until_stalled();
    assert_eq!(shared.lock().unwrap().refreshes, resumed + 1);
    assert_eq!(held(&first), held(&second));
}

#[test]
fn a_failed_refresh_signs_out_and_ends_every_services_session() {
    let clock = clock::manual();
    let shared = Shared::default();
    let (_host, oidc) = signed_in(&shared);
    let ended = std::rc::Rc::new(std::cell::Cell::new(false));
    let flag = ended.clone();
    service("orders").on_session_change(move || flag.set(true));
    shared.lock().unwrap().refuse_refresh = true;
    clock.advance(Duration::from_secs(300));
    task::run_until_stalled();
    assert!(matches!(oidc.session(), Session::SignedOut));
    assert!(ended.get());
}

#[doxa::ui::page("/orders")]
fn OrdersPage() -> doxa::ui::View {
    use doxa::ui::prelude::*;
    let session = doxa::ui::oidc::session::<Claims>();
    let name = session
        .tokens()
        .map(|t| t.claims().name.clone())
        .unwrap_or_default();
    view! { <p>{name}</p> }
}

#[test]
fn the_guard_sends_a_visitor_to_sign_in_and_shows_the_page_once_back() {
    use doxa::ui::dom::MemDom;
    use doxa::ui::oidc::SignInGuard;
    use doxa::ui::prelude::*;

    let _clock = clock::manual();
    let shared = Shared::default();
    service(SERVICE)
        .layers()
        .push(transport(issuer(shared.clone())));
    let host = MemoryHost::new(&format!("{APP}/orders"));
    let oidc = start(&host);
    let dom = MemDom::new();
    App::new(Router::new().guard(oidc.required()).page::<OrdersPage>())
        .mount_on(std::rc::Rc::new(dom.clone()), dom.body())
        .keep();
    navigate(OrdersPage::route());
    task::run_until_stalled();
    let auth = host.left_for().expect("sent to sign in");
    assert_eq!(dom.text(dom.body()), "", "nothing behind the guard shows");
    {
        let mut s = shared.lock().unwrap();
        s.challenge = Some(query(&auth, "code_challenge"));
        s.nonce = Some(query(&auth, "nonce"));
    }
    let state = query(&auth, "state");

    host.arrive(&format!("{APP}/?code=the-code&state={state}"));
    let oidc = start(&host);
    let dom = MemDom::new();
    App::new(Router::new().guard(oidc.required()).page::<OrdersPage>())
        .mount_on(std::rc::Rc::new(dom.clone()), dom.body())
        .keep();
    task::run_until_stalled();
    assert_eq!(doxa::ui::location(), "/orders");
    assert_eq!(dom.text(dom.body()), "Ada");
}
