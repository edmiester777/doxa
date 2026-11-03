//! Sign-in in components and the router: the session as state, and a guard that signs in.

use doxa_client::oidc::{Oidc, Session};
use serde::de::DeserializeOwned;

use crate::hooks::{effect, state};
use crate::router::Route;

/// The app's sign-in session, re-rendering this component when it changes.
#[track_caller]
pub fn session<C: DeserializeOwned + Clone + 'static>() -> Session<C> {
    let oidc = Oidc::<C>::get();
    let current = state(oidc.session());
    effect((), async move |_| loop {
        oidc.changed().await;
        current.set(oidc.session());
    });
    current.get()
}

/// A router guard from an [`Oidc`]: `router().guard(auth.required())`.
pub trait SignInGuard {
    /// Let a page show once someone is signed in; send everyone else to sign in.
    fn required(&self) -> impl AsyncFn(&str) -> Option<Route> + 'static;
}

impl<C: DeserializeOwned + Clone + 'static> SignInGuard for Oidc<C> {
    fn required(&self) -> impl AsyncFn(&str) -> Option<Route> + 'static {
        let oidc = self.clone();
        async move |_url: &str| {
            let session = oidc.settled().await;
            if session.tokens().is_none() {
                oidc.sign_in();
                // The page is leaving; nothing behind the guard shows meanwhile.
                std::future::pending::<()>().await;
            }
            oidc.take_return().map(|to| Route::raw(path_of(&to)))
        }
    }
}

/// `/orders?page=2` from `https://app.example.com/orders?page=2`.
fn path_of(url: &str) -> String {
    match url.split_once("://") {
        Some((_, rest)) => match rest.find('/') {
            Some(i) => rest[i..].to_owned(),
            None => "/".to_owned(),
        },
        None => url.to_owned(),
    }
}
