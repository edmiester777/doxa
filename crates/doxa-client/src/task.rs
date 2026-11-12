//! A single-threaded executor: the browser's microtask queue on wasm, a
//! thread-local queue natively, so the same code runs in both.

use std::future::Future;

/// Run `fut` in the background on this thread.
pub fn spawn(fut: impl Future<Output = ()> + 'static) {
    imp::spawn(fut)
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use std::future::Future;

    pub fn spawn(fut: impl Future<Output = ()> + 'static) {
        wasm_bindgen_futures::spawn_local(fut)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use imp::{block_on, run_until_stalled};

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Wake, Waker};
    use std::thread::Thread;

    type Task = Pin<Box<dyn Future<Output = ()>>>;

    struct Ready {
        queue: Mutex<Vec<usize>>,
        thread: Thread,
    }

    struct TaskWaker {
        id: usize,
        ready: Arc<Ready>,
    }

    impl Wake for TaskWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref()
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.ready.queue.lock().unwrap().push(self.id);
            self.ready.thread.unpark();
        }
    }

    struct Executor {
        tasks: HashMap<usize, Task>,
        next: usize,
        ready: Arc<Ready>,
    }

    thread_local! {
        static EXEC: RefCell<Executor> = RefCell::new(Executor {
            tasks: HashMap::new(),
            next: 0,
            ready: Arc::new(Ready { queue: Mutex::new(Vec::new()), thread: std::thread::current() }),
        });
    }

    pub fn spawn(fut: impl Future<Output = ()> + 'static) {
        EXEC.with(|e| {
            let mut e = e.borrow_mut();
            let id = e.next;
            e.next += 1;
            e.tasks.insert(id, Box::pin(fut));
            e.ready.queue.lock().unwrap().push(id);
        });
    }

    /// Poll every background task that can make progress, until none can.
    pub fn run_until_stalled() {
        loop {
            let (ids, ready) = EXEC.with(|e| {
                let e = e.borrow();
                let ids = std::mem::take(&mut *e.ready.queue.lock().unwrap());
                (ids, e.ready.clone())
            });
            if ids.is_empty() {
                return;
            }
            for id in ids {
                let Some(mut task) = EXEC.with(|e| e.borrow_mut().tasks.remove(&id)) else {
                    continue;
                };
                let waker = Waker::from(Arc::new(TaskWaker {
                    id,
                    ready: ready.clone(),
                }));
                if task
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
                {
                    EXEC.with(|e| e.borrow_mut().tasks.insert(id, task));
                }
            }
        }
    }

    struct Unpark(Thread);

    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark()
        }
    }

    /// Drive `fut` to completion on this thread, running background tasks alongside it.
    pub fn block_on<F: Future>(fut: F) -> F::Output {
        let mut fut = std::pin::pin!(fut);
        let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        loop {
            if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                run_until_stalled();
                return out;
            }
            run_until_stalled();
            if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                run_until_stalled();
                return out;
            }
            std::thread::park_timeout(std::time::Duration::from_millis(50));
        }
    }
}
