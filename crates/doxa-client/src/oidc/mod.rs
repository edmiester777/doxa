//! Sign-in in the browser: OpenID Connect's authorization code flow with PKCE.
//!
//! One [`Oidc`] per app holds the session, refreshes it ahead of expiry on the doxa clock,
//! and agrees with the app's other tabs so only one of them refreshes.

mod host;
mod pkce;
mod session;

use std::any::{Any, TypeId};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use doxa_wire::Method;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::layer::Layer;
use crate::transport::{Payload, Request};

pub use host::{Host, MemoryHost};
pub use session::{Session, Tokens};

use session::TokenResponse;

/// The service sign-in's own requests go through; push a transport on it to fake an issuer.
pub const SERVICE: &str = "doxa-oidc";

const PENDING: &str = "doxa-oidc:pending";
const REFRESH: &str = "doxa-oidc:refresh";
const ID_TOKEN: &str = "doxa-oidc:id";
/// How long a tab waits to hear another tab's claim before refreshing itself.
const CLAIM_WINDOW: Duration = Duration::from_millis(200);
/// How long a tab that lost the claim waits for the winner's tokens.
const FOLLOW_WAIT: Duration = Duration::from_secs(10);

/// Where the refresh token lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Store {
    /// `sessionStorage`: a reload keeps the session; closing the tab ends it.
    #[default]
    Session,
    /// Memory only: a reload signs in again.
    Memory,
}

/// How to reach the issuer; from [`Oidc::issuer`].
pub struct OidcBuilder<C> {
    issuer: String,
    client_id: String,
    scopes: Vec<String>,
    redirect_uri: Option<String>,
    store: Store,
    host: Option<Rc<dyn Host>>,
    _claims: PhantomData<fn() -> C>,
}

impl<C> OidcBuilder<C>
where
    C: DeserializeOwned + Clone + 'static,
{
    /// The client this app is registered as.
    pub fn client_id(mut self, id: impl Into<String>) -> Self {
        self.client_id = id.into();
        self
    }

    /// The scopes to ask for; `openid` is added if missing.
    pub fn scopes<S: Into<String>>(mut self, scopes: impl IntoIterator<Item = S>) -> Self {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    /// Where the issuer sends the browser back; the page's origin and `/` unless set.
    pub fn redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(uri.into());
        self
    }

    /// Where the refresh token lives.
    pub fn store(mut self, store: Store) -> Self {
        self.store = store;
        self
    }

    /// The page to run in; the browser's, unless a test gives a [`MemoryHost`].
    pub fn host(mut self, host: impl Host) -> Self {
        self.host = Some(Rc::new(host));
        self
    }

    /// Start: finish a callback if the page is one, resume a stored session, or sign out.
    /// The app's one `Oidc<C>`, which [`Oidc::get`] returns from then on.
    pub fn install(self) -> Oidc<C> {
        let host = self.host.unwrap_or_else(default_host);
        let mut scopes = self.scopes;
        if !scopes.iter().any(|s| s == "openid") {
            scopes.insert(0, "openid".into());
        }
        let redirect_uri = self
            .redirect_uri
            .unwrap_or_else(|| format!("{}/", origin(&host.url())));
        let tab = pkce::random(&*host);
        let oidc = Oidc(Rc::new(Inner {
            issuer: self.issuer.trim_end_matches('/').to_owned(),
            client_id: self.client_id,
            scopes: scopes.join(" "),
            redirect_uri,
            store: self.store,
            host,
            tab,
            endpoints: RefCell::new(None),
            session: RefCell::new(Session::Starting),
            listeners: RefCell::default(),
            wakers: RefCell::default(),
            generation: Cell::new(0),
            claims: RefCell::default(),
            returned: RefCell::default(),
        }));
        INSTALLED.with(|i| {
            i.borrow_mut()
                .insert(TypeId::of::<C>(), Rc::new(oidc.clone()) as Rc<dyn Any>)
        });
        let heard = oidc.clone();
        oidc.0
            .host
            .listen(Box::new(move |message| heard.hear(&message)));
        let started = oidc.clone();
        crate::task::spawn(async move { started.start().await });
        oidc
    }
}

thread_local! {
    static INSTALLED: RefCell<HashMap<TypeId, Rc<dyn Any>>> = RefCell::default();
}

/// The issuer's endpoints, from its discovery document.
#[derive(Debug, Clone, Deserialize)]
struct Endpoints {
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    end_session_endpoint: Option<String>,
}

/// What the page stored before leaving for the issuer.
#[derive(Debug, Serialize, Deserialize)]
struct Pending {
    state: String,
    nonce: String,
    verifier: String,
    return_to: String,
}

/// What tabs tell each other.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Message {
    Claim { tab: String },
    Tokens { tokens: TokenResponse },
    SignedOut,
}

struct Inner<C> {
    issuer: String,
    client_id: String,
    scopes: String,
    redirect_uri: String,
    store: Store,
    host: Rc<dyn Host>,
    tab: String,
    endpoints: RefCell<Option<Endpoints>>,
    session: RefCell<Session<C>>,
    listeners: RefCell<Vec<Rc<dyn Fn()>>>,
    wakers: RefCell<Vec<Waker>>,
    /// Bumped on sign-out, so a refresh begun before it is dropped when it lands.
    generation: Cell<u64>,
    /// Other tabs' refresh claims, and when they were heard.
    claims: RefCell<Vec<(String, Duration)>>,
    /// Where a finished callback came back to, until the router takes it.
    returned: RefCell<Option<String>>,
}

/// The app's sign-in. `Clone` is cheap: every clone is the same session.
pub struct Oidc<C>(Rc<Inner<C>>);

impl<C> Clone for Oidc<C> {
    fn clone(&self) -> Self {
        Oidc(self.0.clone())
    }
}

/// Why the issuer's configuration or tokens couldn't be had.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Failed {
    Network(String),
    Status(u16),
    Unreadable,
    Rejected,
}

impl<C> Oidc<C>
where
    C: DeserializeOwned + Clone + 'static,
{
    /// Configure sign-in against the issuer at `url`, e.g. a Keycloak realm.
    pub fn issuer(url: impl Into<String>) -> OidcBuilder<C> {
        OidcBuilder {
            issuer: url.into(),
            client_id: String::new(),
            scopes: vec!["openid".into()],
            redirect_uri: None,
            store: Store::default(),
            host: None,
            _claims: PhantomData,
        }
    }

    /// The app's `Oidc<C>`. Panics if `install()` hasn't run.
    pub fn get() -> Self {
        Self::try_get().expect("`Oidc::<C>::issuer(…).install()` has not run")
    }

    /// The app's `Oidc<C>`, if it has been installed.
    pub fn try_get() -> Option<Self> {
        INSTALLED.with(|i| {
            i.borrow()
                .get(&TypeId::of::<C>())
                .and_then(|o| o.downcast_ref::<Oidc<C>>().cloned())
        })
    }

    /// Where sign-in stands now.
    pub fn session(&self) -> Session<C> {
        self.0.session.borrow().clone()
    }

    /// Run `f` whenever the session changes.
    pub fn on_change(&self, f: impl Fn() + 'static) {
        self.0.listeners.borrow_mut().push(Rc::new(f));
    }

    /// Resolves once the session is settled: signed in, out or expired.
    pub async fn settled(&self) -> Session<C> {
        loop {
            let now = self.session();
            if now.settled() {
                return now;
            }
            self.changed().await;
        }
    }

    /// Resolves the next time the session changes.
    pub async fn changed(&self) {
        Changed {
            oidc: self,
            seen: false,
        }
        .await
    }

    /// The page a just-finished sign-in came back to, once; the router goes there.
    pub fn take_return(&self) -> Option<String> {
        self.0.returned.borrow_mut().take()
    }

    /// `Authorization: Bearer` with the current access token, on every request it covers.
    pub fn bearer(&self) -> impl Layer {
        let this = self.clone();
        crate::layer::bearer(move || {
            this.0
                .session
                .borrow()
                .tokens()
                .map(|t| t.access_token().to_owned())
        })
    }

    /// Leave for the issuer's sign-in page; the page comes back to where it is now.
    pub fn sign_in(&self) {
        if matches!(*self.0.session.borrow(), Session::Redirecting) {
            return;
        }
        self.set(Session::Redirecting);
        let this = self.clone();
        crate::task::spawn(async move {
            let Ok(endpoints) = this.endpoints().await else {
                this.set(Session::SignedOut);
                return;
            };
            let host = &*this.0.host;
            let pending = Pending {
                state: pkce::random(host),
                nonce: pkce::random(host),
                verifier: pkce::random(host),
                return_to: host.url(),
            };
            let challenge = pkce::challenge(&pending.verifier);
            let query = pkce::form(&[
                ("response_type", "code"),
                ("client_id", &this.0.client_id),
                ("redirect_uri", &this.0.redirect_uri),
                ("scope", &this.0.scopes),
                ("state", &pending.state),
                ("nonce", &pending.nonce),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ]);
            host.store(
                PENDING,
                &serde_json::to_string(&pending).unwrap_or_default(),
            );
            host.redirect(&format!("{}?{query}", endpoints.authorization_endpoint));
        });
    }

    /// Forget the session here and in every tab, end every service's, and sign out at the
    /// issuer if it says how.
    pub fn sign_out(&self) {
        let hint = self
            .session()
            .tokens()
            .and_then(|t| t.id_token().map(str::to_owned));
        self.end_locally();
        self.0.host.post(&encode(&Message::SignedOut));
        let end = self
            .0
            .endpoints
            .borrow()
            .as_ref()
            .and_then(|e| e.end_session_endpoint.clone());
        if let Some(end) = end {
            let mut pairs = vec![
                ("client_id", self.0.client_id.as_str()),
                ("post_logout_redirect_uri", self.0.redirect_uri.as_str()),
            ];
            if let Some(hint) = &hint {
                pairs.push(("id_token_hint", hint));
            }
            self.0
                .host
                .redirect(&format!("{end}?{}", pkce::form(&pairs)));
        }
    }

    fn end_locally(&self) {
        self.0.generation.set(self.0.generation.get() + 1);
        self.0.host.forget(REFRESH);
        self.0.host.forget(ID_TOKEN);
        self.set(Session::SignedOut);
        crate::service::each(|s| s.end_session());
    }

    fn set(&self, session: Session<C>) {
        *self.0.session.borrow_mut() = session;
        let wakers: Vec<Waker> = self.0.wakers.borrow_mut().drain(..).collect();
        wakers.into_iter().for_each(Waker::wake);
        let listeners: Vec<_> = self.0.listeners.borrow().clone();
        listeners.iter().for_each(|f| f());
    }

    async fn start(&self) {
        let host = &*self.0.host;
        let url = host.url();
        let query = pkce::query(&url);
        let get = |k: &str| query.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
        let pending: Option<Pending> = host
            .load(PENDING)
            .and_then(|p| serde_json::from_str(&p).ok());
        let without_query = |u: &str| u.split(['?', '#']).next().unwrap_or_default().to_owned();
        let at_callback = without_query(&url) == without_query(&self.0.redirect_uri);
        if let (true, Some(state), Some(pending)) = (at_callback, get("state"), pending) {
            host.forget(PENDING);
            // Back where sign-in started, without the callback's query.
            host.replace(&pending.return_to);
            *self.0.returned.borrow_mut() = Some(pending.return_to.clone());
            let tokens = match get("code") {
                Some(code) if state == pending.state => self.exchange(&code, &pending).await,
                _ => Err(Failed::Rejected),
            };
            match tokens {
                Ok(tokens) => self.signed_in(tokens),
                Err(_) => self.set(Session::SignedOut),
            }
            return;
        }
        let stored = (self.0.store == Store::Session)
            .then(|| host.load(REFRESH))
            .flatten();
        match stored {
            Some(refresh) => match self.refresh_with(&refresh, None).await {
                Ok(tokens) => self.signed_in(tokens),
                Err(_) => self.end_locally(),
            },
            None => self.set(Session::SignedOut),
        }
    }

    fn signed_in(&self, tokens: Tokens<C>) {
        if self.0.store == Store::Session {
            if let Some(r) = tokens.refresh_token() {
                self.0.host.store(REFRESH, r);
            }
            if let Some(id) = tokens.id_token() {
                self.0.host.store(ID_TOKEN, id);
            }
        }
        self.set(Session::SignedIn(tokens.clone()));
        self.schedule(tokens);
    }

    /// Refresh ahead of expiry: a tenth of the lifetime early, at most thirty seconds.
    fn schedule(&self, tokens: Tokens<C>) {
        let now = crate::clock::now();
        let left = tokens.expires_at().saturating_sub(now);
        let lead = (left / 10).min(Duration::from_secs(30));
        let this = self.clone();
        let generation = self.0.generation.get();
        crate::task::spawn(async move {
            crate::clock::sleep(left - lead).await;
            let current = this.session().tokens().is_some_and(|t| t.same(&tokens));
            if current && this.0.generation.get() == generation {
                this.refresh(tokens).await;
            }
        });
    }

    /// Refresh once across tabs: claim it, and back off for an earlier claim.
    async fn refresh(&self, tokens: Tokens<C>) {
        let Some(refresh) = tokens.refresh_token().map(str::to_owned) else {
            self.set(Session::Expired);
            return;
        };
        let claimed_at = crate::clock::now();
        self.0.host.post(&encode(&Message::Claim {
            tab: self.0.tab.clone(),
        }));
        crate::clock::sleep(CLAIM_WINDOW).await;
        let outranked = self
            .0
            .claims
            .borrow()
            .iter()
            .any(|(tab, at)| *at + CLAIM_WINDOW >= claimed_at && *tab < self.0.tab);
        if outranked {
            crate::clock::sleep(FOLLOW_WAIT).await;
            let still_old = self.session().tokens().is_some_and(|t| t.same(&tokens));
            if !still_old {
                return;
            }
        }
        let generation = self.0.generation.get();
        self.set(Session::Refreshing(tokens.clone()));
        let result = self.refresh_with(&refresh, Some(&tokens)).await;
        if self.0.generation.get() != generation {
            return;
        }
        match result {
            Ok(fresh) => self.signed_in(fresh),
            Err(_) => self.end_locally(),
        }
    }

    async fn endpoints(&self) -> Result<Endpoints, Failed> {
        if let Some(e) = self.0.endpoints.borrow().clone() {
            return Ok(e);
        }
        let url = format!("{}/.well-known/openid-configuration", self.0.issuer);
        let bytes = send(Method::Get, url, None).await?;
        let endpoints: Endpoints =
            serde_json::from_slice(&bytes).map_err(|_| Failed::Unreadable)?;
        *self.0.endpoints.borrow_mut() = Some(endpoints.clone());
        Ok(endpoints)
    }

    async fn exchange(&self, code: &str, pending: &Pending) -> Result<Tokens<C>, Failed> {
        let response = self
            .token(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &self.0.redirect_uri),
                ("client_id", &self.0.client_id),
                ("code_verifier", &pending.verifier),
            ])
            .await?;
        // Received straight from the token endpoint over TLS, which OIDC Core (3.1.3.7)
        // accepts in place of checking the ID token's signature.
        response
            .tokens(crate::clock::now(), Some(&pending.nonce), None)
            .map_err(|_| Failed::Rejected)
    }

    async fn refresh_with(
        &self,
        refresh: &str,
        previous: Option<&Tokens<C>>,
    ) -> Result<Tokens<C>, Failed> {
        let mut response = self
            .token(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh),
                ("client_id", &self.0.client_id),
            ])
            .await?;
        // Resuming from storage, with no tokens yet to take the claims from.
        if response.id_token.is_none() && previous.is_none() {
            response.id_token = self.0.host.load(ID_TOKEN);
        }
        let tokens = response
            .clone()
            .tokens(crate::clock::now(), None, previous)
            .map_err(|_| Failed::Rejected)?;
        // With the ID token kept from before, so another tab can check whose tokens these are.
        response.id_token = tokens.id_token().map(str::to_owned);
        self.0
            .host
            .post(&encode(&Message::Tokens { tokens: response }));
        Ok(tokens)
    }

    async fn token(&self, form: &[(&str, &str)]) -> Result<TokenResponse, Failed> {
        let endpoint = self.endpoints().await?.token_endpoint;
        let body = pkce::form(form).into_bytes();
        let bytes = send(Method::Post, endpoint, Some(body)).await?;
        serde_json::from_slice(&bytes).map_err(|_| Failed::Unreadable)
    }

    fn hear(&self, message: &str) {
        let Ok(message) = serde_json::from_str::<Message>(message) else {
            return;
        };
        match message {
            Message::Claim { tab } => self.0.claims.borrow_mut().push((tab, crate::clock::now())),
            Message::Tokens { tokens } => {
                // A tab takes another's tokens only when it is signed in as the same subject.
                let Some(previous) = self.session().tokens().cloned() else {
                    return;
                };
                let theirs = tokens.id_token.as_deref().and_then(session::subject);
                let ours = previous.id_token().and_then(session::subject);
                if theirs.is_none() || theirs != ours {
                    return;
                }
                let previous = Some(previous);
                if let Ok(fresh) = tokens.tokens(crate::clock::now(), None, previous.as_ref()) {
                    self.signed_in(fresh);
                }
            }
            Message::SignedOut => {
                if self.session().tokens().is_some() {
                    self.end_locally();
                }
            }
        }
    }
}

/// One request to the issuer, through the [`SERVICE`] service's own layers only, so an app's
/// bearer or 401 handling never wraps it.
async fn send(method: Method, url: String, form: Option<Vec<u8>>) -> Result<Vec<u8>, Failed> {
    let mut headers = vec![("accept".to_owned(), "application/json".to_owned())];
    if form.is_some() {
        headers.push((
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        ));
    }
    let request = Request {
        method,
        url,
        headers,
        body: form.map(Payload::Bytes),
        credentials: false,
    };
    let response = crate::service::service(SERVICE)
        .send_own(request)
        .await
        .map_err(|e| Failed::Network(e.to_string()))?;
    if !(200..300).contains(&response.status) {
        return Err(Failed::Status(response.status));
    }
    response.body.bytes().await.map_err(Failed::Network)
}

fn encode(message: &Message) -> String {
    serde_json::to_string(message).unwrap_or_default()
}

/// `https://app.example.com:8443` from any URL on it.
fn origin(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return String::new();
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    format!("{scheme}://{host}")
}

#[cfg(target_arch = "wasm32")]
fn default_host() -> Rc<dyn Host> {
    Rc::new(host::Browser::new())
}

#[cfg(not(target_arch = "wasm32"))]
fn default_host() -> Rc<dyn Host> {
    Rc::new(MemoryHost::new("http://localhost/"))
}

/// Resolves the next time the session changes.
struct Changed<'a, C> {
    oidc: &'a Oidc<C>,
    seen: bool,
}

impl<C> Future for Changed<'_, C> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.seen {
            return Poll::Ready(());
        }
        self.seen = true;
        self.oidc.0.wakers.borrow_mut().push(cx.waker().clone());
        Poll::Pending
    }
}
