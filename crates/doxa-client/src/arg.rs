//! Turning a call's arguments into a request.

use std::marker::PhantomData;

use doxa_wire::{KeyNames, Keyed};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::Serialize;
use serde_json::Value;

/// A value that can stand in for a `T` argument: `T`, `&T`, `&str` for `String`, `&[T]` for `Vec<T>`.
pub trait Arg<T> {
    /// The owned value.
    fn into_arg(self) -> T;
}

impl<T> Arg<T> for T {
    fn into_arg(self) -> T {
        self
    }
}

impl<T: Clone> Arg<T> for &T {
    fn into_arg(self) -> T {
        self.clone()
    }
}

impl Arg<String> for &str {
    fn into_arg(self) -> String {
        self.to_owned()
    }
}

impl<T: Clone> Arg<Vec<T>> for &[T] {
    fn into_arg(self) -> Vec<T> {
        self.to_vec()
    }
}

/// How one handler argument travels: a path segment, a query string, a body.
#[diagnostic::on_unimplemented(
    message = "`{Self}` isn't sent by the browser",
    note = "implement `doxa::client::ClientArg` for it, or set `client = false` on the route"
)]
pub trait ClientArg {
    /// What the caller passes.
    type Value;
    /// Write `value` into the request.
    fn apply(value: Self::Value, out: &mut Outgoing) -> Result<(), String>;
}

/// An argument for a parameter whose extractor is `X`.
#[diagnostic::on_unimplemented(
    message = "`{Self}` can't be passed where the route reads `{X}`",
    note = "pass the extractor's inner value, owned or borrowed"
)]
pub trait ArgFor<X> {
    #[doc(hidden)]
    fn encode(self, out: &mut Outgoing) -> Result<(), String>;
}

impl<X: ClientArg, A: Arg<X::Value>> ArgFor<X> for A {
    fn encode(self, out: &mut Outgoing) -> Result<(), String> {
        X::apply(self.into_arg(), out)
    }
}

/// The request being assembled from a call's arguments.
#[derive(Debug, Default, Clone)]
pub struct Outgoing {
    template: &'static str,
    named: Vec<(String, String)>,
    positional: Vec<String>,
    query: Vec<(String, String)>,
    keys: Vec<Value>,
    body: Option<(&'static str, Vec<u8>)>,
    headers: Vec<(String, String)>,
}

impl Outgoing {
    /// An empty request for the route at `template`.
    pub fn new(template: &'static str) -> Self {
        Self {
            template,
            ..Self::default()
        }
    }

    /// Fill path parameters from `value`: a struct by field name, a tuple or scalar by position.
    pub fn path(&mut self, value: &impl Serialize) -> Result<(), String> {
        match to_value(value)? {
            Value::Object(map) => {
                for (k, v) in map {
                    if let Some(s) = scalar(&v)? {
                        self.named.push((k, s));
                    }
                }
            }
            Value::Array(items) => {
                for v in items {
                    self.positional.push(scalar(&v)?.unwrap_or_default());
                }
            }
            v => self.positional.push(scalar(&v)?.unwrap_or_default()),
        }
        Ok(())
    }

    /// Add `value`'s fields to the query string.
    pub fn query(&mut self, value: &impl Serialize) -> Result<(), String> {
        let encoded = serde_urlencoded::to_string(value).map_err(|e| e.to_string())?;
        let pairs: Vec<(String, String)> =
            serde_urlencoded::from_str(&encoded).map_err(|e| e.to_string())?;
        self.query.extend(pairs);
        Ok(())
    }

    /// Each field of a key goes to the path parameter of that name, or else the query string.
    pub fn key(&mut self, value: &impl Serialize) -> Result<(), String> {
        let Value::Object(map) = to_value(value)? else {
            return Err("a route key must serialize as a struct".to_owned());
        };
        self.keys.push(Value::Object(map.clone()));
        let names: Vec<&str> = doxa_wire::path_names(self.template).collect();
        for (k, v) in map {
            let Some(s) = scalar(&v)? else { continue };
            if names.contains(&k.as_str()) {
                self.named.push((k, s));
            } else {
                self.query.push((k, s));
            }
        }
        Ok(())
    }

    /// Set a JSON body.
    pub fn json(&mut self, value: &impl Serialize) -> Result<(), String> {
        let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        self.body = Some(("application/json", bytes));
        Ok(())
    }

    /// Set a form body.
    pub fn form(&mut self, value: &impl Serialize) -> Result<(), String> {
        let encoded = serde_urlencoded::to_string(value).map_err(|e| e.to_string())?;
        self.body = Some(("application/x-www-form-urlencoded", encoded.into_bytes()));
        Ok(())
    }

    /// Add a request header.
    pub fn header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.push((name.into(), value.into()));
    }

    pub(crate) fn first_key(&self) -> Option<&Value> {
        self.keys.first()
    }

    pub(crate) fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    pub(crate) fn body(&self) -> Option<&(&'static str, Vec<u8>)> {
        self.body.as_ref()
    }

    /// The path and query, failing on any parameter left unfilled.
    pub fn url(&self) -> Result<String, String> {
        let template = self.template;
        let mut out = String::with_capacity(template.len());
        let mut positional = self.positional.iter();
        let mut rest = template;
        while let Some(open) = rest.find('{') {
            out.push_str(&rest[..open]);
            let close = rest[open..]
                .find('}')
                .map(|c| open + c)
                .ok_or_else(|| format!("unclosed `{{` in `{template}`"))?;
            let raw = &rest[open + 1..close];
            let name = raw.trim_start_matches('*');
            let value = self
                .named
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v)
                .or_else(|| positional.next())
                .ok_or_else(|| format!("no argument fills `{{{name}}}` in `{template}`"))?;
            if raw.starts_with('*') {
                out.push_str(&value.split('/').map(segment).collect::<Vec<_>>().join("/"));
            } else {
                out.push_str(&segment(value));
            }
            rest = &rest[close + 1..];
        }
        out.push_str(rest);
        if !self.query.is_empty() {
            out.push('?');
            out.push_str(&serde_urlencoded::to_string(&self.query).map_err(|e| e.to_string())?);
        }
        Ok(out)
    }
}

const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

fn segment(s: &str) -> String {
    utf8_percent_encode(s, SEGMENT).to_string()
}

fn to_value(value: &impl Serialize) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|e| e.to_string())
}

fn scalar(v: &Value) -> Result<Option<String>, String> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some(s.clone())),
        Value::Bool(b) => Ok(Some(b.to_string())),
        Value::Number(n) => Ok(Some(n.to_string())),
        _ => Err("a path or key value must be a string, number or bool".to_owned()),
    }
}

/// `axum::extract::Path<T>`, as the client sends it.
pub struct Path<T>(PhantomData<fn() -> T>);
/// `axum::extract::Query<T>`, as the client sends it.
pub struct Query<T>(PhantomData<fn() -> T>);
/// `axum::Json<T>`, as the client sends or receives it.
pub struct Json<T>(PhantomData<fn() -> T>);
/// `axum::Form<T>`, as the client sends it.
pub struct Form<T>(PhantomData<fn() -> T>);
/// `Granted<W>`: the caller passes the asset's key.
pub struct Granted<W>(PhantomData<fn() -> W>);
/// An extractor doxa does not know; it needs its own [`ClientArg`] impl.
pub struct Foreign<T>(PhantomData<fn() -> T>);

impl<T: Serialize> ClientArg for Path<T> {
    type Value = T;
    fn apply(value: T, out: &mut Outgoing) -> Result<(), String> {
        out.path(&value)
    }
}

impl<T: Serialize> ClientArg for Query<T> {
    type Value = T;
    fn apply(value: T, out: &mut Outgoing) -> Result<(), String> {
        out.query(&value)
    }
}

impl<T: Serialize> ClientArg for Json<T> {
    type Value = T;
    fn apply(value: T, out: &mut Outgoing) -> Result<(), String> {
        out.json(&value)
    }
}

impl<T: Serialize> ClientArg for Form<T> {
    type Value = T;
    fn apply(value: T, out: &mut Outgoing) -> Result<(), String> {
        out.form(&value)
    }
}

impl<W> ClientArg for Granted<W>
where
    W: Keyed,
    W::Key: Serialize + KeyNames,
{
    type Value = W::Key;
    fn apply(value: W::Key, out: &mut Outgoing) -> Result<(), String> {
        out.key(&value)
    }
}

impl<T> ClientArg for Foreign<T>
where
    T: ClientArg,
{
    type Value = T::Value;
    fn apply(value: T::Value, out: &mut Outgoing) -> Result<(), String> {
        T::apply(value, out)
    }
}
