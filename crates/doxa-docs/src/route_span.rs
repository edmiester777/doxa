//! The span every mounted route runs under, made by its route macro: handler, route, the
//! caller's tenant and each path parameter. A handler's own `#[instrument]` nests inside it.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use axum::extract::{FromRequestParts, RawPathParams, Request};
use tower::{Layer, Service};
use tracing::instrument::{Instrument, Instrumented};
use tracing::Span;

use crate::__private::SpanTenant;

/// Wraps one route in the span its macro declared.
#[derive(Clone, Copy)]
pub struct RouteSpanLayer(pub fn() -> Span);

impl<S> Layer<S> for RouteSpanLayer {
    type Service = RouteSpanService<S>;

    fn layer(&self, inner: S) -> RouteSpanService<S> {
        RouteSpanService {
            inner,
            make: self.0,
        }
    }
}

/// [`RouteSpanLayer`]'s service.
#[derive(Clone)]
pub struct RouteSpanService<S> {
    inner: S,
    make: fn() -> Span,
}

impl<S: Service<Request>> Service<Request> for RouteSpanService<S> {
    type Response = S::Response;
    type Error = S::Error;
    type Future = Instrumented<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let span = (self.make)();
        let (mut parts, body) = request.into_parts();
        if let Some(SpanTenant(tenant)) = parts.extensions.get::<SpanTenant>() {
            span.record("tenant", tenant.as_str());
        }
        // Reading the router's params never waits.
        if let Some(Ok(params)) = now(RawPathParams::from_request_parts(&mut parts, &())) {
            for (name, value) in &params {
                span.record(name, value);
            }
        }
        self.inner
            .call(Request::from_parts(parts, body))
            .instrument(span)
    }
}

fn now<F: Future>(future: F) -> Option<F::Output> {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}
