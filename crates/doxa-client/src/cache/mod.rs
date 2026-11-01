//! The request cache: one entry per GET, shared by every caller, revalidated
//! in the background once stale, and cleared when the session changes.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::{Rc, Weak};
use std::task::Waker;
use std::time::Duration;

use doxa_wire::RouteSpec;

/// Something that re-renders when a query it read changes.
pub trait Observer {
    /// A query this observer read has a new value, or went stale.
    fn changed(&self);
}

thread_local! {
    static OBSERVER: RefCell<Option<Rc<dyn Observer>>> = const { RefCell::new(None) };
}

/// Make `observer` the one subsequent reads are recorded against; returns the previous one.
pub fn set_observer(observer: Option<Rc<dyn Observer>>) -> Option<Rc<dyn Observer>> {
    OBSERVER.with(|o| o.replace(observer))
}

fn current_observer() -> Option<Rc<dyn Observer>> {
    OBSERVER.with(|o| o.borrow().clone())
}

/// How long data stays fresh, globally and per route.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    stale_time: Duration,
    gc_time: Duration,
    routes: Vec<(&'static RouteSpec, Duration)>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            stale_time: Duration::ZERO,
            gc_time: Duration::from_secs(300),
            routes: Vec::new(),
        }
    }
}

impl CacheConfig {
    /// How long a response is served without asking the server again.
    pub fn stale_time(mut self, d: Duration) -> Self {
        self.stale_time = d;
        self
    }

    /// How long an unread response is kept.
    pub fn gc_time(mut self, d: Duration) -> Self {
        self.gc_time = d;
        self
    }

    /// A different stale time for one route: `.route(&get_widget::ROUTE, …)`.
    pub fn route(mut self, route: &'static RouteSpec, stale_time: Duration) -> Self {
        self.routes.push((route, stale_time));
        self
    }

    fn stale_time_for(&self, route: &'static RouteSpec) -> Duration {
        self.routes
            .iter()
            .find(|(r, _)| std::ptr::eq(*r, route))
            .map_or(self.stale_time, |(_, d)| *d)
    }
}

pub(crate) struct Entry {
    pub value: Rc<dyn Any>,
    pub route: &'static RouteSpec,
    pub at: f64,
    pub stale: bool,
    pub max_age: Option<Duration>,
    pub etag: Option<String>,
    observers: Vec<Weak<dyn Observer>>,
}

/// What a waiter on an in-flight request gets.
pub(crate) enum Outcome {
    Value(Rc<dyn Any>),
    Status(u16, Rc<[u8]>),
    Failed(crate::fetch::Fetch),
}

#[derive(Default)]
pub(crate) struct Slot {
    pub outcome: RefCell<Option<Rc<Outcome>>>,
    wakers: RefCell<Vec<Waker>>,
}

impl Slot {
    pub fn finish(&self, outcome: Outcome) {
        *self.outcome.borrow_mut() = Some(Rc::new(outcome));
        for w in self.wakers.borrow_mut().drain(..) {
            w.wake();
        }
    }

    pub async fn wait(self: Rc<Self>) -> Rc<Outcome> {
        std::future::poll_fn(|cx| match self.outcome.borrow().clone() {
            Some(o) => std::task::Poll::Ready(o),
            None => {
                self.wakers.borrow_mut().push(cx.waker().clone());
                std::task::Poll::Pending
            }
        })
        .await
    }
}

/// What a read found.
pub(crate) enum Lookup {
    Fresh(Rc<dyn Any>),
    Stale(Rc<dyn Any>, Option<String>),
    Pending(Rc<Slot>),
    Miss,
}

#[derive(Default)]
pub(crate) struct Cache {
    pub config: RefCell<CacheConfig>,
    entries: RefCell<HashMap<String, Entry>>,
    inflight: RefCell<HashMap<String, Rc<Slot>>>,
    revalidating: RefCell<Vec<String>>,
    requests: Cell<u64>,
}

impl Cache {
    pub fn lookup(&self, key: &str, now: f64) -> Lookup {
        let observer = current_observer();
        let mut entries = self.entries.borrow_mut();
        if let Some(entry) = entries.get_mut(key) {
            if let Some(o) = &observer {
                if !entry.observers.iter().any(|w| ptr_eq(w, o)) {
                    entry.observers.push(Rc::downgrade(o));
                }
            }
            let fresh_for = entry
                .max_age
                .unwrap_or_else(|| self.config.borrow().stale_time_for(entry.route));
            if !entry.stale && now - entry.at < fresh_for.as_secs_f64() * 1000.0 {
                return Lookup::Fresh(entry.value.clone());
            }
            return Lookup::Stale(entry.value.clone(), entry.etag.clone());
        }
        drop(entries);
        match self.inflight.borrow().get(key) {
            Some(slot) => Lookup::Pending(slot.clone()),
            None => Lookup::Miss,
        }
    }

    /// Record `observer` as a reader of `key` without reading it.
    pub fn watch(&self, key: &str) {
        let Some(o) = current_observer() else { return };
        if let Some(e) = self.entries.borrow_mut().get_mut(key) {
            if !e.observers.iter().any(|w| ptr_eq(w, &o)) {
                e.observers.push(Rc::downgrade(&o));
            }
        }
    }

    pub fn count_request(&self) {
        self.requests.set(self.requests.get() + 1);
    }

    pub fn begin(&self, key: &str) -> Rc<Slot> {
        self.count_request();
        let slot = Rc::new(Slot::default());
        self.inflight
            .borrow_mut()
            .insert(key.to_owned(), slot.clone());
        slot
    }

    pub fn end(&self, key: &str) {
        self.inflight.borrow_mut().remove(key);
    }

    /// Start a background revalidation unless one is already running.
    pub fn claim_revalidation(&self, key: &str) -> bool {
        let mut running = self.revalidating.borrow_mut();
        if running.iter().any(|k| k == key) {
            return false;
        }
        running.push(key.to_owned());
        true
    }

    pub fn release_revalidation(&self, key: &str) {
        self.revalidating.borrow_mut().retain(|k| k != key);
    }

    pub fn store(&self, key: String, route: &'static RouteSpec, value: Rc<dyn Any>, meta: Meta) {
        let observer = current_observer();
        let mut entries = self.entries.borrow_mut();
        let mut observers = entries
            .remove(&key)
            .map(|e| e.observers)
            .unwrap_or_default();
        if let Some(o) = &observer {
            if !observers.iter().any(|w| ptr_eq(w, o)) {
                observers.push(Rc::downgrade(o));
            }
        }
        entries.insert(
            key,
            Entry {
                value,
                route,
                at: meta.now,
                stale: false,
                max_age: meta.max_age,
                etag: meta.etag,
                observers,
            },
        );
        drop(entries);
        self.collect(meta.now);
    }

    /// A `304`: the entry is fresh again with the same value.
    pub fn touch(&self, key: &str, now: f64) {
        if let Some(e) = self.entries.borrow_mut().get_mut(key) {
            e.at = now;
            e.stale = false;
        }
    }

    /// Replace a value after revalidation, telling everyone who read it.
    pub fn replace(&self, key: &str, value: Rc<dyn Any>, meta: Meta) {
        let observers = {
            let mut entries = self.entries.borrow_mut();
            let Some(e) = entries.get_mut(key) else {
                return;
            };
            e.value = value;
            e.at = meta.now;
            e.stale = false;
            e.max_age = meta.max_age;
            e.etag = meta.etag;
            e.observers.clone()
        };
        notify(&observers);
    }

    /// Mark stale every query about any of `entities`, and tell their readers.
    pub fn invalidate(&self, entities: &[&str]) {
        let observers: Vec<_> = {
            let mut entries = self.entries.borrow_mut();
            entries
                .values_mut()
                .filter(|e| e.route.entities.iter().any(|t| entities.contains(t)))
                .flat_map(|e| {
                    e.stale = true;
                    e.observers.clone()
                })
                .collect()
        };
        notify(&observers);
    }

    /// Run `f` over every cached value, telling readers of the ones it changed.
    pub fn patch(
        &self,
        mut f: impl FnMut(&Rc<dyn Any>) -> Option<Rc<dyn Any>>,
    ) -> Vec<(String, Rc<dyn Any>)> {
        let mut previous = Vec::new();
        let observers: Vec<_> = {
            let mut entries = self.entries.borrow_mut();
            entries
                .iter_mut()
                .filter_map(|(k, e)| {
                    let next = f(&e.value)?;
                    previous.push((k.clone(), std::mem::replace(&mut e.value, next)));
                    Some(e.observers.clone())
                })
                .flatten()
                .collect()
        };
        notify(&observers);
        previous
    }

    pub fn restore(&self, previous: Vec<(String, Rc<dyn Any>)>) {
        let observers: Vec<_> = {
            let mut entries = self.entries.borrow_mut();
            previous
                .into_iter()
                .filter_map(|(k, v)| {
                    let e = entries.get_mut(&k)?;
                    e.value = v;
                    Some(e.observers.clone())
                })
                .flatten()
                .collect()
        };
        notify(&observers);
    }

    /// Forget everything, e.g. on a new session.
    pub fn clear(&self) {
        let observers: Vec<_> = self
            .entries
            .borrow_mut()
            .drain()
            .flat_map(|(_, e)| e.observers)
            .collect();
        notify(&observers);
    }

    /// Drop entries nobody has read for longer than the gc time.
    fn collect(&self, now: f64) {
        let gc = self.config.borrow().gc_time.as_secs_f64() * 1000.0;
        self.entries.borrow_mut().retain(|_, e| {
            e.observers.retain(|w| w.strong_count() > 0);
            !e.observers.is_empty() || now - e.at < gc
        });
    }

    /// Requests sent to the network, for tests and diagnostics.
    pub fn requests(&self) -> u64 {
        self.requests.get()
    }
}

pub(crate) struct Meta {
    pub now: f64,
    pub max_age: Option<Duration>,
    pub etag: Option<String>,
}

fn ptr_eq(w: &Weak<dyn Observer>, o: &Rc<dyn Observer>) -> bool {
    std::ptr::addr_eq(w.as_ptr(), Rc::as_ptr(o))
}

fn notify(observers: &[Weak<dyn Observer>]) {
    let mut seen: Vec<*const dyn Observer> = Vec::new();
    for o in observers.iter().filter_map(Weak::upgrade) {
        let p = Rc::as_ptr(&o);
        if !seen.iter().any(|s| std::ptr::addr_eq(*s, p)) {
            seen.push(p);
            o.changed();
        }
    }
}

/// `max-age` from a `Cache-Control` header.
pub(crate) fn max_age(cache_control: Option<&str>) -> Option<Duration> {
    let cc = cache_control?;
    if cc.contains("no-store") || cc.contains("no-cache") {
        return Some(Duration::ZERO);
    }
    cc.split(',')
        .find_map(|d| d.trim().strip_prefix("max-age="))
        .and_then(|s| s.parse().ok())
        .map(Duration::from_secs)
}
