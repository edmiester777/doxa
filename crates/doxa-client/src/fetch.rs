//! What can go wrong calling a route.

use std::fmt;

use doxa_wire::ApiErrorBody;
use serde::de::DeserializeOwned;

/// A route that declares no error type of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub enum NoError {}

impl fmt::Display for NoError {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {}
    }
}

/// A failed call. `E` is the route's own error enum.
#[derive(Debug, Clone)]
pub enum Fetch<E = NoError> {
    /// The route returned its own error.
    Api(Box<ApiErrorBody<E>>),
    /// `404`: the guard found nothing for the key, or no such route.
    NotFound(Option<Box<ApiErrorBody>>),
    /// `401`: no credentials, or bad ones.
    Unauthorized(Option<Box<ApiErrorBody>>),
    /// `403`: the policy refused.
    Forbidden(Option<Box<ApiErrorBody>>),
    /// Any other error status.
    Status {
        /// The status code.
        code: u16,
        /// The body, when it was doxa's error envelope.
        body: Option<Box<ApiErrorBody>>,
    },
    /// An argument could not be encoded into the request.
    Encode(String),
    /// The response did not decode as the route's return type.
    Decode(String),
    /// The request never got an answer, or the connection dropped.
    Network(String),
    /// The server ended an event stream with an error.
    Stream(String),
    /// The call was dropped before it finished.
    Aborted,
}

impl<E> Fetch<E> {
    /// The route's own error, if that is what came back.
    pub fn api(&self) -> Option<&E> {
        match self {
            Fetch::Api(body) => Some(&body.error),
            _ => None,
        }
    }

    /// Whether the route answered `404`.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Fetch::NotFound(_)) || self.status() == Some(404)
    }

    /// The HTTP status, when there was one.
    pub fn status(&self) -> Option<u16> {
        match self {
            Fetch::Api(body) => Some(body.status),
            Fetch::NotFound(_) => Some(404),
            Fetch::Unauthorized(_) => Some(401),
            Fetch::Forbidden(_) => Some(403),
            Fetch::Status { code, .. } => Some(*code),
            _ => None,
        }
    }

    /// Drop the route's error type, keeping its message.
    pub fn erase(self) -> Fetch<NoError>
    where
        E: serde::Serialize,
    {
        match self {
            Fetch::Api(body) => {
                let erased = ApiErrorBody {
                    message: body.message,
                    status: body.status,
                    code: body.code,
                    error: serde_json::to_value(&body.error).unwrap_or_default(),
                };
                Fetch::Status {
                    code: erased.status,
                    body: Some(Box::new(erased)),
                }
            }
            Fetch::NotFound(b) => Fetch::NotFound(b),
            Fetch::Unauthorized(b) => Fetch::Unauthorized(b),
            Fetch::Forbidden(b) => Fetch::Forbidden(b),
            Fetch::Status { code, body } => Fetch::Status { code, body },
            Fetch::Encode(m) => Fetch::Encode(m),
            Fetch::Decode(m) => Fetch::Decode(m),
            Fetch::Network(m) => Fetch::Network(m),
            Fetch::Stream(m) => Fetch::Stream(m),
            Fetch::Aborted => Fetch::Aborted,
        }
    }

    /// Decode an error response for a route whose error type is `E`.
    pub(crate) fn from_status(status: u16, body: &[u8]) -> Self
    where
        E: DeserializeOwned,
    {
        if let Ok(typed) = serde_json::from_slice::<ApiErrorBody<E>>(body) {
            return Fetch::Api(Box::new(typed));
        }
        let body = serde_json::from_slice::<ApiErrorBody>(body)
            .ok()
            .map(Box::new);
        match status {
            404 => Fetch::NotFound(body),
            401 => Fetch::Unauthorized(body),
            403 => Fetch::Forbidden(body),
            code => Fetch::Status { code, body },
        }
    }
}

fn message(body: &Option<Box<ApiErrorBody>>) -> Option<&str> {
    body.as_ref().map(|b| b.message.as_str())
}

impl<E: fmt::Display> fmt::Display for Fetch<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fetch::Api(body) => write!(f, "{}", body.error),
            Fetch::NotFound(b) => f.write_str(message(b).unwrap_or("not found")),
            Fetch::Unauthorized(b) => f.write_str(message(b).unwrap_or("not signed in")),
            Fetch::Forbidden(b) => f.write_str(message(b).unwrap_or("not allowed")),
            Fetch::Status { code, body } => match message(body) {
                Some(m) => f.write_str(m),
                None => write!(f, "request failed with status {code}"),
            },
            Fetch::Encode(m) => write!(f, "could not encode the request: {m}"),
            Fetch::Decode(m) => write!(f, "could not decode the response: {m}"),
            Fetch::Network(m) => write!(f, "network error: {m}"),
            Fetch::Stream(m) => write!(f, "stream error: {m}"),
            Fetch::Aborted => f.write_str("request aborted"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for Fetch<E> {}
