//! `server = "local"`: the app's own server, in-process on `127.0.0.1`.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::thread::JoinHandle;

use doxa::boot::{self, BoxError, Serve, Stopping};
use tokio::sync::oneshot;

/// What `.local(…)` runs. It needn't be `Send`: it runs on the server's own thread.
pub(crate) type Start =
    Box<dyn FnOnce(Stopping) -> Pin<Box<dyn Future<Output = Result<Serve, BoxError>>>> + Send>;

/// The listener, bound before the window opens so the page never races the server.
pub(crate) struct Bound {
    listener: TcpListener,
    /// The port actually bound.
    pub port: u16,
    /// Whether the configured port was taken, so the origin (and its storage) changed.
    pub moved: bool,
}

/// Binds `127.0.0.1:port`, or the next free port if it's taken.
pub(crate) fn bind(port: u16) -> io::Result<Bound> {
    let (listener, moved) = match TcpListener::bind((Ipv4Addr::LOCALHOST, port)) {
        Ok(l) => (l, false),
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
            (TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?, true)
        }
        Err(e) => return Err(e),
    };
    let port = listener.local_addr()?.port();
    Ok(Bound {
        listener,
        port,
        moved,
    })
}

/// The running server.
pub(crate) struct Server {
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    /// Runs `start` on its own thread and serves `bound`. `ready` hears whether `start`
    /// succeeded; `ended`, how serving ended.
    pub(crate) fn spawn(
        start: Start,
        bound: Bound,
        wrap: impl FnOnce(axum::Router) -> axum::Router + Send + 'static,
        ready: impl FnOnce(Result<(), String>) + Send + 'static,
        ended: impl FnOnce(Result<(), String>) + Send + 'static,
    ) -> io::Result<Server> {
        let (stop, stopped) = oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("doxa-server".into())
            .spawn(move || {
                let mut ready = Some(ready);
                let served = std::panic::catch_unwind(AssertUnwindSafe(|| {
                    serve(start, bound, wrap, stopped, |r| {
                        if let Some(ready) = ready.take() {
                            ready(r);
                        }
                    })
                }));
                let result = served.unwrap_or_else(|_| Err("the server panicked".into()));
                match ready.take() {
                    Some(ready) => ready(result),
                    None => ended(result),
                }
            })?;
        Ok(Server {
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// Begins shutdown: the server stops accepting, drains and tears down.
    pub(crate) fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }

    /// Waits for the drain and teardown to finish.
    pub(crate) fn join(&mut self) {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn serve(
    start: Start,
    bound: Bound,
    wrap: impl FnOnce(axum::Router) -> axum::Router,
    stopped: oneshot::Receiver<()>,
    mut ready: impl FnMut(Result<(), String>),
) -> Result<(), String> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("starting the server's runtime: {e}"))?;
    rt.block_on(async move {
        let (stop, stopping) = boot::stopping();
        let serve = start(stopping).await.map_err(|e| e.to_string())?;
        bound
            .listener
            .set_nonblocking(true)
            .map_err(|e| e.to_string())?;
        let listener =
            tokio::net::TcpListener::from_std(bound.listener).map_err(|e| e.to_string())?;
        ready(Ok(()));
        boot::serve_listener(serve.map_router(wrap), listener, stop, async move {
            let _ = stopped.await;
        })
        .await
        .map_err(|e| e.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::mpsc;

    fn start(router: axum::Router) -> Start {
        Box::new(move |_| Box::pin(async move { Ok(Serve::new(router)) }))
    }

    #[test]
    fn a_taken_port_moves_to_a_free_one() {
        let taken = bind(0).unwrap();
        let again = bind(taken.port).unwrap();
        assert!(again.moved);
        assert_ne!(again.port, taken.port);
        assert!(!taken.moved);
    }

    #[test]
    fn serves_until_stopped_and_reports_readiness() {
        let bound = bind(0).unwrap();
        let port = bound.port;
        let (tx, rx) = mpsc::channel();
        let ended = tx.clone();
        let router = axum::Router::new().route("/", axum::routing::get(|| async { "hi" }));
        let mut server = Server::spawn(
            start(router),
            bound,
            |r| r,
            move |r| tx.send(("ready", r)).unwrap(),
            move |r| ended.send(("ended", r)).unwrap(),
        )
        .unwrap();
        assert_eq!(rx.recv().unwrap(), ("ready", Ok(())));
        let mut conn = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        conn.write_all(b"GET / HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
            .unwrap();
        let mut body = String::new();
        conn.read_to_string(&mut body).unwrap();
        assert!(body.ends_with("hi"), "{body}");
        server.stop();
        server.join();
        assert_eq!(rx.recv().unwrap(), ("ended", Ok(())));
    }

    #[test]
    fn a_failed_start_reaches_ready() {
        let (tx, rx) = mpsc::channel();
        let failing: Start = Box::new(|_| Box::pin(async { Err("no database".into()) }));
        let mut server = Server::spawn(
            failing,
            bind(0).unwrap(),
            |r| r,
            move |r| tx.send(r).unwrap(),
            |_| panic!("never served"),
        )
        .unwrap();
        assert_eq!(rx.recv().unwrap(), Err("no database".into()));
        server.join();
    }
}
