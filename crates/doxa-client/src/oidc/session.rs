//! Where sign-in stands, and the tokens it holds once it is done.

use std::rc::Rc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::pkce;

/// Where sign-in stands.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Session<C> {
    /// Reading the issuer's configuration, or finishing a callback; nothing is known yet.
    Starting,
    /// No one is signed in.
    SignedOut,
    /// On the way to the issuer.
    Redirecting,
    /// Signed in.
    SignedIn(Tokens<C>),
    /// Signed in, with a refresh on the way; these tokens still work.
    Refreshing(Tokens<C>),
    /// The tokens ran out and couldn't be refreshed.
    Expired,
}

impl<C> Session<C> {
    /// The tokens, while they work.
    pub fn tokens(&self) -> Option<&Tokens<C>> {
        match self {
            Session::SignedIn(t) | Session::Refreshing(t) => Some(t),
            _ => None,
        }
    }

    /// Whether anything is still to be decided.
    pub fn settled(&self) -> bool {
        !matches!(self, Session::Starting | Session::Redirecting)
    }
}

/// A signed-in session's tokens and the ID token's claims. Cheap to clone.
#[derive(Debug)]
pub struct Tokens<C>(Rc<Held<C>>);

impl<C> Clone for Tokens<C> {
    fn clone(&self) -> Self {
        Tokens(self.0.clone())
    }
}

#[derive(Debug)]
struct Held<C> {
    access: String,
    refresh: Option<String>,
    id: Option<String>,
    /// On this thread's clock.
    expires_at: Duration,
    claims: C,
}

impl<C> Tokens<C> {
    /// The access token, for `Authorization: Bearer`.
    pub fn access_token(&self) -> &str {
        &self.0.access
    }

    /// The ID token's claims.
    pub fn claims(&self) -> &C {
        &self.0.claims
    }

    /// The raw ID token, as `end_session` takes it.
    pub fn id_token(&self) -> Option<&str> {
        self.0.id.as_deref()
    }

    /// Whether `other` is these very tokens, not a refresh of them.
    pub(crate) fn same(&self, other: &Tokens<C>) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }

    pub(crate) fn refresh_token(&self) -> Option<&str> {
        self.0.refresh.as_deref()
    }

    /// When the access token stops working, on [`crate::clock::now`]'s clock.
    pub fn expires_at(&self) -> Duration {
        self.0.expires_at
    }
}

/// A token endpoint's answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
}

/// Why the issuer's answer couldn't be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Rejected {
    NoIdToken,
    Malformed,
    WrongNonce,
}

impl TokenResponse {
    /// The tokens, with the ID token's claims; `nonce` is checked when there is one to check.
    pub fn tokens<C: DeserializeOwned + Clone>(
        self,
        now: Duration,
        nonce: Option<&str>,
        previous: Option<&Tokens<C>>,
    ) -> Result<Tokens<C>, Rejected> {
        let id = self
            .id_token
            .or_else(|| previous.and_then(|p| p.0.id.clone()));
        let claims: C = match (&id, previous) {
            (Some(id), _) => {
                let payload = id.split('.').nth(1).ok_or(Rejected::Malformed)?;
                let bytes = pkce::decode(payload).ok_or(Rejected::Malformed)?;
                if let Some(expected) = nonce {
                    #[derive(Deserialize)]
                    struct Nonce {
                        nonce: Option<String>,
                    }
                    let got: Nonce =
                        serde_json::from_slice(&bytes).map_err(|_| Rejected::Malformed)?;
                    if got.nonce.as_deref() != Some(expected) {
                        return Err(Rejected::WrongNonce);
                    }
                }
                serde_json::from_slice(&bytes).map_err(|_| Rejected::Malformed)?
            }
            (None, Some(p)) => p.0.claims.clone(),
            (None, None) => return Err(Rejected::NoIdToken),
        };
        Ok(Tokens(Rc::new(Held {
            access: self.access_token,
            refresh: self
                .refresh_token
                .or_else(|| previous.and_then(|p| p.0.refresh.clone())),
            id,
            expires_at: now + Duration::from_secs(self.expires_in.unwrap_or(300)),
            claims,
        })))
    }
}
