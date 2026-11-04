//! `<Can>`: ask the real route whether this caller may call it, without calling it.

use std::future::IntoFuture;
use std::rc::Rc;

use doxa_wire::{Capability, RouteSpec};
use futures_util::future::LocalBoxFuture;

use crate::arg::{ArgFor, Outgoing};
use crate::cache::Meta;
use crate::service::{now, service};
use crate::transport::Request;

/// What a dry run of a route said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// The route's guards passed.
    Allowed,
    /// A guard refused: `401`, `403` or `404`.
    Denied,
    /// The route can't answer a dry run, or the answer was ambiguous.
    Unknown,
}

impl Permission {
    /// Only an explicit yes counts.
    pub fn allowed(self) -> bool {
        self == Permission::Allowed
    }
}

/// A dry run of one route with one set of arguments, or a question about one capability.
/// Await it for a [`Permission`].
#[must_use = "a probe does nothing until it is awaited"]
#[derive(Clone)]
pub struct Probe {
    route: Option<&'static RouteSpec>,
    out: Outgoing,
    error: bool,
    /// `(package, name)` of the capability that answers it from the caller's set.
    capability: Option<(&'static str, &'static str)>,
}

impl Probe {
    /// A dry run of `route`, generated as `route_name::can(…)`.
    pub fn new(route: &'static RouteSpec) -> Self {
        Self {
            route: Some(route),
            out: Outgoing::new(route.path),
            error: false,
            capability: None,
        }
    }

    /// Whether the caller holds the capability `M`, as `<Can cap={…}>` asks.
    pub fn capability<M: Capability>(_: M) -> Self {
        Self {
            route: None,
            out: Outgoing::new(""),
            error: false,
            capability: Some((M::PACKAGE, M::NAME)),
        }
    }

    /// Answer from the caller's capabilities: `M` is the route's one guard.
    pub fn by_capability<M: Capability>(mut self) -> Self {
        self.capability = Some((M::PACKAGE, M::NAME));
        self
    }

    /// Add the argument for a parameter the route reads with extractor `X`.
    pub fn arg<X, A: ArgFor<X>>(mut self, value: A) -> Self {
        self.error |= value.encode(&mut self.out).is_err();
        self
    }
}

/// Whether the caller holds the capability `M`; `false` when the server couldn't say.
pub async fn has<M: Capability>(_: M) -> bool {
    service(M::PACKAGE).holds(M::NAME).await == Some(true)
}

impl IntoFuture for Probe {
    type Output = Permission;
    type IntoFuture = LocalBoxFuture<'static, Permission>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            if let Some((package, name)) = self.capability {
                return match service(package).holds(name).await {
                    Some(true) => Permission::Allowed,
                    Some(false) => Permission::Denied,
                    None => Permission::Unknown,
                };
            }
            let Some(route) = self.route.filter(|r| r.dry_run && !self.error) else {
                return Permission::Unknown;
            };
            let Ok(url) = self.out.url() else {
                return Permission::Unknown;
            };
            let client = service(route.package);
            let key = format!("CAN {} {url}", route.method.as_str());
            let permission = loop {
                if let Some(v) = client.cache.fresh(&key, now()) {
                    if let Some(p) = v.downcast_ref::<Permission>() {
                        return *p;
                    }
                }
                client.cache.count_request();
                let request = Request {
                    method: route.method,
                    url: url.clone(),
                    headers: vec![(doxa_wire::DRY_RUN_HEADER.into(), "1".into())],
                    body: None,
                    credentials: false,
                };
                let session = client.session();
                let Ok(resp) = client.send(request).await else {
                    break Permission::Unknown;
                };
                if !client.observe_session(&resp, session) {
                    continue;
                }
                let echoed = resp.header(doxa_wire::DRY_RUN_HEADER) == Some(doxa_wire::DRY_RUN_OK);
                break match resp.status {
                    204 if echoed => Permission::Allowed,
                    401 | 403 | 404 => Permission::Denied,
                    _ => Permission::Unknown,
                };
            };
            client.cache.store(
                key,
                route,
                self.out.first_key().cloned(),
                Rc::new(permission),
                Meta {
                    now: now(),
                    max_age: Some(std::time::Duration::from_secs(60)),
                    etag: None,
                    digest: None,
                },
            );
            permission
        })
    }
}
