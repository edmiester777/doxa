//! Layers: middleware every request passes through on its way to the transport.
//!
//! ```
//! use doxa_client::layer::{bearer, layers, on_status};
//!
//! layers()
//!     .push(bearer(|| Some("token".to_owned())))
//!     .push(on_status(401, |_| { /* sign out */ }));
//! ```

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::rc::Rc;

use futures_util::future::LocalBoxFuture;

use crate::fetch::Fetch;
use crate::transport::{Body, Request, Response, Transport};

/// A step every request passes through. `next` sends it on; a layer may change the
/// request, read or replace the response, call `next` again, or answer itself.
pub trait Layer: 'static {
    /// Handle `req`.
    fn call(&self, req: Request, next: Next) -> LocalBoxFuture<'static, Result<Response, Fetch>>;
}

/// The rest of the stack below a layer, ending in the transport.
#[derive(Clone)]
pub struct Next {
    stack: Rc<[Rc<dyn Layer>]>,
    at: usize,
    transport: Rc<dyn Transport>,
}

impl Next {
    pub(crate) fn new(stack: Rc<[Rc<dyn Layer>]>, transport: Rc<dyn Transport>) -> Self {
        Self {
            stack,
            at: 0,
            transport,
        }
    }

    /// Send `req` through the rest of the stack.
    pub fn run(&self, req: Request) -> LocalBoxFuture<'static, Result<Response, Fetch>> {
        match self.stack.get(self.at) {
            Some(layer) => {
                let rest = Next {
                    stack: self.stack.clone(),
                    at: self.at + 1,
                    transport: self.transport.clone(),
                };
                layer.call(req, rest)
            }
            None => {
                let sent = self.transport.send(req);
                Box::pin(async move { sent.await.map_err(Fetch::Network) })
            }
        }
    }
}

/// An ordered stack of layers; the first pushed runs first.
#[derive(Clone, Default)]
pub struct Layers(Rc<Stack>);

#[derive(Default)]
struct Stack {
    entries: RefCell<Vec<(u64, Rc<dyn Layer>)>>,
    next_id: Cell<u64>,
}

impl Layers {
    /// Add `layer` below the ones already pushed.
    pub fn push(&self, layer: impl Layer) -> &Self {
        self.insert(layer);
        self
    }

    /// Add `layer` until the returned guard is dropped.
    pub fn push_scoped(&self, layer: impl Layer) -> Scoped {
        Scoped {
            stack: self.0.clone(),
            id: self.insert(layer),
        }
    }

    fn insert(&self, layer: impl Layer) -> u64 {
        let id = self.0.next_id.get();
        self.0.next_id.set(id + 1);
        self.0.entries.borrow_mut().push((id, Rc::new(layer)));
        id
    }

    /// The layers as they are now, so a push mid-request doesn't reach that request.
    pub(crate) fn snapshot(&self) -> Vec<Rc<dyn Layer>> {
        self.0
            .entries
            .borrow()
            .iter()
            .map(|(_, l)| l.clone())
            .collect()
    }
}

/// Removes its layer when dropped.
#[must_use = "the layer is removed when this guard is dropped"]
pub struct Scoped {
    stack: Rc<Stack>,
    id: u64,
}

impl Drop for Scoped {
    fn drop(&mut self) {
        self.stack
            .entries
            .borrow_mut()
            .retain(|(id, _)| *id != self.id);
    }
}

thread_local! {
    static GLOBAL: Layers = Layers::default();
}

/// The layers every request on this thread passes through first.
pub fn layers() -> Layers {
    GLOBAL.with(Layers::clone)
}

struct FnLayer<F>(F);

impl<F, Fut> Layer for FnLayer<F>
where
    F: Fn(Request, Next) -> Fut + 'static,
    Fut: Future<Output = Result<Response, Fetch>> + 'static,
{
    fn call(&self, req: Request, next: Next) -> LocalBoxFuture<'static, Result<Response, Fetch>> {
        Box::pin((self.0)(req, next))
    }
}

/// A layer from a function.
///
/// ```
/// use doxa_client::layer::{layer_fn, layers};
///
/// layers().push(layer_fn(async move |req, next| {
///     let res = next.run(req.clone()).await?;
///     if res.status == 503 { return next.run(req).await }
///     Ok(res)
/// }));
/// ```
pub fn layer_fn<F, Fut>(f: F) -> impl Layer
where
    F: Fn(Request, Next) -> Fut + 'static,
    Fut: Future<Output = Result<Response, Fetch>> + 'static,
{
    FnLayer(f)
}

/// Send `Authorization: Bearer <token>`, asking `token` for every request.
pub fn bearer(token: impl Fn() -> Option<String> + 'static) -> impl Layer {
    header("authorization", move || {
        token().map(|t| format!("Bearer {t}"))
    })
}

/// Send header `name` with every request, asking `value` each time; `None` sends nothing.
pub fn header(name: &'static str, value: impl Fn() -> Option<String> + 'static) -> impl Layer {
    layer_fn(move |mut req: Request, next: Next| {
        if req.header(name).is_none() {
            if let Some(v) = value() {
                req.headers.push((name.into(), v));
            }
        }
        next.run(req)
    })
}

/// Send the browser's cookies, with the CSRF header on mutations and dry runs.
pub fn cookies() -> impl Layer {
    layer_fn(|mut req: Request, next: Next| {
        req.credentials = true;
        if !req.method.is_safe() || req.header(doxa_wire::DRY_RUN_HEADER).is_some() {
            req.headers
                .push((doxa_wire::CSRF_HEADER.into(), "1".into()));
        }
        next.run(req)
    })
}

/// Run `f` on every response with status `status`.
pub fn on_status(status: u16, f: impl Fn(&Response) + 'static) -> impl Layer {
    let f = Rc::new(f);
    layer_fn(move |req: Request, next: Next| {
        let f = f.clone();
        async move {
            let res = next.run(req).await?;
            if res.status == status {
                f(&res);
            }
            Ok(res)
        }
    })
}

/// Run `f` on every response with status `status` whose error body carries `code`.
pub fn on_error_code(
    status: u16,
    code: &'static str,
    f: impl Fn(&doxa_wire::ApiErrorBody) + 'static,
) -> impl Layer {
    let f = Rc::new(f);
    layer_fn(move |req: Request, next: Next| {
        let f = f.clone();
        async move {
            let mut res = next.run(req).await?;
            if res.status != status {
                return Ok(res);
            }
            let body = std::mem::replace(&mut res.body, Body::Full(Vec::new()));
            let bytes = body.bytes().await.map_err(Fetch::Network)?;
            if let Ok(err) = serde_json::from_slice::<doxa_wire::ApiErrorBody>(&bytes) {
                if err.code == code {
                    f(&err);
                }
            }
            res.body = Body::Full(bytes);
            Ok(res)
        }
    })
}

/// Answer every request with `transport` rather than the one below.
pub fn transport(transport: impl Transport) -> impl Layer {
    let transport = Rc::new(transport);
    layer_fn(move |req: Request, _: Next| {
        let sent = transport.send(req);
        async move { sent.await.map_err(Fetch::Network) }
    })
}
