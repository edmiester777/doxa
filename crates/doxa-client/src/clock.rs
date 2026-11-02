//! Time for timers and backoff: the platform's, or a manual clock a test advances.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

struct ManualState {
    now: Duration,
    next: u64,
    timers: BTreeMap<(Duration, u64), Waker>,
}

thread_local! {
    static MANUAL: RefCell<Option<Rc<RefCell<ManualState>>>> = const { RefCell::new(None) };
}

fn manual_state() -> Option<Rc<RefCell<ManualState>>> {
    MANUAL.with(|m| m.borrow().clone())
}

/// Time since this thread's clock started.
pub fn now() -> Duration {
    if let Some(m) = manual_state() {
        return m.borrow().now;
    }
    imp::now()
}

/// Resolves once `d` has passed on this thread's clock.
pub fn sleep(d: Duration) -> Sleep {
    match manual_state() {
        Some(m) => {
            let at = m.borrow().now + d;
            Sleep(Inner::Manual { at, id: None, m })
        }
        None => Sleep(Inner::Real(futures_timer::Delay::new(d))),
    }
}

/// The future [`sleep`] returns.
pub struct Sleep(Inner);

enum Inner {
    Real(futures_timer::Delay),
    Manual {
        at: Duration,
        id: Option<u64>,
        m: Rc<RefCell<ManualState>>,
    },
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        match &mut self.0 {
            Inner::Real(d) => Pin::new(d).poll(cx),
            Inner::Manual { at, id, m } => {
                let mut s = m.borrow_mut();
                if s.now >= *at {
                    if let Some(i) = id.take() {
                        s.timers.remove(&(*at, i));
                    }
                    return Poll::Ready(());
                }
                let i = *id.get_or_insert_with(|| {
                    s.next += 1;
                    s.next
                });
                s.timers.insert((*at, i), cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Inner::Manual { at, id: Some(i), m } = &self.0 {
            m.borrow_mut().timers.remove(&(*at, *i));
        }
    }
}

/// A clock that only moves when [`Manual::advance`] is called; see [`manual`].
#[derive(Clone)]
pub struct Manual(Rc<RefCell<ManualState>>);

/// Switch this thread to a manual clock starting at zero, or return the one already in use.
pub fn manual() -> Manual {
    MANUAL.with(|cell| {
        let mut cell = cell.borrow_mut();
        let m = cell.get_or_insert_with(|| {
            Rc::new(RefCell::new(ManualState {
                now: Duration::ZERO,
                next: 0,
                timers: BTreeMap::new(),
            }))
        });
        Manual(m.clone())
    })
}

impl Manual {
    /// Move time forward by `d`, waking each timer at its own deadline in turn.
    ///
    /// Natively, background tasks run after each deadline, so an interval ticks once per period.
    pub fn advance(&self, d: Duration) {
        let end = self.0.borrow().now + d;
        loop {
            let due = {
                let mut s = self.0.borrow_mut();
                match s.timers.keys().next().copied() {
                    Some(k) if k.0 <= end => {
                        s.now = s.now.max(k.0);
                        s.timers.remove(&k)
                    }
                    _ => {
                        s.now = end;
                        None
                    }
                }
            };
            let Some(w) = due else { break };
            w.wake();
            #[cfg(not(target_arch = "wasm32"))]
            crate::task::run_until_stalled();
        }
        #[cfg(not(target_arch = "wasm32"))]
        crate::task::run_until_stalled();
    }

    /// Where the clock is.
    pub fn now(&self) -> Duration {
        self.0.borrow().now
    }
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use std::time::Duration;

    pub fn now() -> Duration {
        let ms = web_sys::window()
            .and_then(|w| w.performance())
            .map_or(0.0, |p| p.now());
        Duration::from_secs_f64(ms / 1000.0)
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use std::time::{Duration, Instant};

    thread_local! {
        static START: Instant = Instant::now();
    }

    pub fn now() -> Duration {
        START.with(Instant::elapsed)
    }
}
