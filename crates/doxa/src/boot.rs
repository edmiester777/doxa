//! What `#[doxa::main]` runs: the app's own CLI, plus a reserved `start` that binds the port
//! `doxa dev` gives it.

use std::ffi::OsString;
use std::future::{Future, IntoFuture};
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::process::ExitCode;
use std::time::Duration;

use axum::Router;
use tokio::sync::watch;

/// The error `start` and `main` return.
pub type BoxError = Box<dyn std::error::Error>;
type Teardown = Pin<Box<dyn Future<Output = ()>>>;

/// Resolves once shutdown begins.
#[derive(Clone)]
pub struct Stopping(watch::Receiver<bool>);

impl Stopping {
    /// Wait until shutdown begins.
    pub async fn wait(mut self) {
        let _ = self.0.wait_for(|s| *s).await;
    }
}

/// Begins shutdown for the [`Stopping`] made with it.
pub struct Stop(watch::Sender<bool>);

impl Stop {
    /// Begin shutdown.
    pub fn stop(&self) {
        let _ = self.0.send(true);
    }
}

/// A linked [`Stop`] and [`Stopping`], for a host that runs `start` itself.
pub fn stopping() -> (Stop, Stopping) {
    let (tx, rx) = watch::channel(false);
    (Stop(tx), Stopping(rx))
}

/// What `start` serves.
pub struct Serve {
    router: Router,
    addr: String,
    drain: Duration,
    teardown: Option<Teardown>,
    exit_on_second_signal: bool,
}

impl Serve {
    /// Serve `router` on `127.0.0.1:3000` with a 5 s drain.
    pub fn new(router: Router) -> Self {
        Serve {
            router,
            addr: "127.0.0.1:3000".into(),
            drain: Duration::from_secs(5),
            teardown: None,
            exit_on_second_signal: true,
        }
    }

    /// Whether a second signal exits at once, skipping teardown (the default). Off ignores it, so
    /// only SIGKILL stops a hung teardown; `doxa dev` still kills its services on a second Ctrl-C.
    pub fn exit_on_second_signal(mut self, exit: bool) -> Self {
        self.exit_on_second_signal = exit;
        self
    }

    /// `host:port` to bind when neither `--port` nor `$PORT` is given.
    pub fn addr(mut self, addr: impl Into<String>) -> Self {
        self.addr = addr.into();
        self
    }

    /// How long open connections get before teardown runs anyway.
    pub fn drain(mut self, d: Duration) -> Self {
        self.drain = d;
        self
    }

    /// Runs after serving stops, however it stopped.
    pub fn teardown(mut self, f: impl Future<Output = ()> + 'static) -> Self {
        self.teardown = Some(Box::pin(f));
        self
    }

    #[doc(hidden)]
    pub fn map_router(mut self, f: impl FnOnce(Router) -> Router) -> Self {
        self.router = f(self.router);
        self
    }
}

/// What a reserved `start` may return.
#[diagnostic::on_unimplemented(
    message = "`start` must return `Serve`, `Router` (stateless), or a `Result` of either"
)]
pub trait IntoServe {
    /// The `Serve` to run.
    fn into_serve(self) -> Result<Serve, BoxError>;
}

impl IntoServe for Serve {
    fn into_serve(self) -> Result<Serve, BoxError> {
        Ok(self)
    }
}

impl IntoServe for Router {
    fn into_serve(self) -> Result<Serve, BoxError> {
        Ok(Serve::new(self))
    }
}

impl<T: IntoServe, E: Into<BoxError>> IntoServe for Result<T, E> {
    fn into_serve(self) -> Result<Serve, BoxError> {
        match self {
            Ok(t) => t.into_serve(),
            Err(e) => Err(e.into()),
        }
    }
}

#[doc(hidden)]
pub trait IntoMainResult {
    fn into_main_result(self) -> Result<(), BoxError>;
}

impl IntoMainResult for () {
    fn into_main_result(self) -> Result<(), BoxError> {
        Ok(())
    }
}

impl<E: Into<BoxError>> IntoMainResult for Result<(), E> {
    fn into_main_result(self) -> Result<(), BoxError> {
        self.map_err(Into::into)
    }
}

#[doc(hidden)]
pub struct __Package {
    pub bin: &'static str,
    pub version: &'static str,
    pub about: &'static str,
}

#[doc(hidden)]
#[derive(clap::Parser)]
pub struct __NoCli {}

const START: &str = "start";
const PORT: &str = "doxa-port";

/// The app's command with doxa's reserved `start` added; no subcommand also means `start`.
fn command<C: clap::CommandFactory>(pkg: &__Package) -> clap::Command {
    let mut app = C::command();
    assert!(
        app.find_subcommand(START).is_none(),
        "`start` is reserved by #[doxa::main]; rename the app's own"
    );
    // The derive marks a non-`Option` subcommand field required; `start` needs `None`.
    assert!(
        !app.is_subcommand_required_set(),
        "#[doxa::main]: the Cli must be a struct whose #[command(subcommand)] field is an Option; None means `start`"
    );
    assert!(
        app.get_arguments().all(|a| a.get_long() != Some("port")),
        "#[doxa::main]: `--port` is reserved for `start`"
    );
    if app.get_version().is_none() {
        app = app.version(pkg.version);
    }
    if app.get_about().is_none() && !pkg.about.is_empty() {
        app = app.about(pkg.about);
    }
    app.name(pkg.bin)
        .bin_name(pkg.bin)
        .subcommand_required(false)
        .arg_required_else_help(false)
        .subcommand(
            clap::Command::new(START)
                .about("Serve HTTP; the default")
                .arg(
                    // A private id, so an app arg with id `port` isn't filled from this one.
                    clap::Arg::new(PORT)
                        .long("port")
                        .value_parser(clap::value_parser!(u16))
                        .help(
                            "Bind 127.0.0.1 on this port. `$PORT` alone keeps the configured host",
                        ),
                ),
        )
}

enum Parsed<C> {
    Start(C, Option<u16>),
    Main(C),
}

fn parse<C: clap::Parser>(
    pkg: &__Package,
    argv: impl IntoIterator<Item = OsString>,
) -> Result<Parsed<C>, clap::Error> {
    let mut cmd = command::<C>(pkg);
    let m = cmd.try_get_matches_from_mut(argv)?;
    let cli = C::from_arg_matches(&m).map_err(|e| e.format(&mut cmd))?;
    Ok(match m.subcommand() {
        None => Parsed::Start(cli, None),
        Some((START, sub)) => Parsed::Start(cli, sub.get_one::<u16>(PORT).copied()),
        Some(_) => Parsed::Main(cli),
    })
}

#[doc(hidden)]
pub fn __run<C, S, SF, M, MF>(pkg: __Package, init: Option<fn()>, start: S, main: M) -> ExitCode
where
    C: clap::Parser,
    S: FnOnce(C, Stopping) -> SF,
    SF: Future<Output: IntoServe>,
    M: FnOnce(C) -> MF,
    MF: Future<Output: IntoMainResult>,
{
    if let Some(init) = init {
        init();
    }
    let parsed = parse::<C>(&pkg, std::env::args_os()).unwrap_or_else(|e| e.exit());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let result = rt.block_on(async move {
        match parsed {
            Parsed::Start(cli, port) => serve_with(port, |stop| start(cli, stop)).await,
            Parsed::Main(cli) => main(cli).await.into_main_result(),
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn serve_with<F, Fut>(port: Option<u16>, start: F) -> Result<(), BoxError>
where
    F: FnOnce(Stopping) -> Fut,
    Fut: Future<Output: IntoServe>,
{
    let (stop, stopping) = stopping();
    let serve = start(stopping).await.into_serve()?;
    let env_port = std::env::var("PORT").ok().and_then(|p| p.parse().ok());
    // Under `doxa dev`, its SIGKILL after 10 s is the backstop instead.
    let exit_early = serve.exit_on_second_signal && std::env::var_os("DOXA_DEV_CHILD").is_none();
    let signal = async move {
        shutdown_signal().await;
        if exit_early {
            tokio::spawn(exit_on_second_signal());
        }
    };
    run_serve(serve, port, env_port, stop, signal).await
}

/// Where to bind: `--port` on loopback, else `$PORT` on the configured host, else as configured.
fn bind_addr(port: Option<u16>, env_port: Option<u16>, configured: SocketAddr) -> SocketAddr {
    match (port, env_port) {
        (Some(p), _) => SocketAddr::from((Ipv4Addr::LOCALHOST, p)),
        (None, Some(p)) => SocketAddr::new(configured.ip(), p),
        (None, None) => configured,
    }
}

async fn run_serve(
    serve: Serve,
    port: Option<u16>,
    env_port: Option<u16>,
    stop: Stop,
    signal: impl Future<Output = ()> + Send + 'static,
) -> Result<(), BoxError> {
    let bound = async {
        let addr = serve.addr.as_str();
        let configured = tokio::net::lookup_host(addr)
            .await?
            .next()
            .ok_or_else(|| format!("{addr} resolves to no address"))?;
        let addr = bind_addr(port, env_port, configured);
        Ok::<_, BoxError>(tokio::net::TcpListener::bind(addr).await?)
    }
    .await;
    match bound {
        Ok(listener) => serve_listener(serve, listener, stop, signal).await,
        Err(e) => {
            if let Some(t) = serve.teardown {
                t.await;
            }
            Err(e)
        }
    }
}

/// Serve on an already-bound `listener` until `signal` resolves, then drain and tear down.
pub async fn serve_listener(
    serve: Serve,
    listener: impl axum::serve::Listener<Addr = SocketAddr>,
    stop: Stop,
    signal: impl Future<Output = ()> + Send + 'static,
) -> Result<(), BoxError> {
    use axum::serve::ListenerExt;
    let Serve {
        router,
        drain,
        teardown,
        ..
    } = serve;
    let rx = stop.0.subscribe();
    let result = async {
        if let Ok(addr) = listener.local_addr() {
            tracing::info!(%addr, "listening");
        }
        // `tap_io` is axum's route to `ConnectInfo<SocketAddr>` for any listener.
        let server = axum::serve(
            listener.tap_io(|_| {}),
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            signal.await;
            stop.stop();
        })
        .into_future();
        let drained = async {
            Stopping(rx).wait().await;
            tokio::time::sleep(drain).await;
        };
        tokio::select! {
            r = server => r?,
            () = drained => tracing::warn!("connections still open after the drain period"),
        }
        Ok::<(), BoxError>(())
    }
    .await;
    if let Some(t) = teardown {
        t.await;
    }
    result
}

/// `doxa dev` follows a terminal's Ctrl-C with SIGTERM, so only a signal a second later counts.
async fn exit_on_second_signal() {
    let first = tokio::time::Instant::now();
    loop {
        shutdown_signal().await;
        if first.elapsed() >= Duration::from_secs(1) {
            std::process::exit(130);
        }
    }
}

/// Resolves on Ctrl-C or SIGTERM; for subcommands that run until stopped.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[derive(clap::Parser)]
    struct Cli {
        #[arg(short, long, default_value = "config.yaml", global = true)]
        config: PathBuf,
        #[command(subcommand)]
        command: Option<Command>,
    }

    #[derive(clap::Subcommand)]
    enum Command {
        Schema,
    }

    const PKG: __Package = __Package {
        bin: "srv",
        version: "1.0.0",
        about: "",
    };

    fn argv(args: &[&str]) -> Vec<OsString> {
        args.iter().map(Into::into).collect()
    }

    fn config(p: Parsed<Cli>) -> (bool, Option<u16>, PathBuf, bool) {
        match p {
            Parsed::Start(c, port) => (true, port, c.config, c.command.is_some()),
            Parsed::Main(c) => (false, None, c.config, c.command.is_some()),
        }
    }

    #[test]
    fn no_subcommand_or_start_runs_start_and_others_run_main() {
        let p = |a: &[&str]| config(parse::<Cli>(&PKG, argv(a)).unwrap());
        assert_eq!(p(&["srv"]), (true, None, "config.yaml".into(), false));
        assert_eq!(
            p(&["srv", "start", "--port", "8081"]),
            (true, Some(8081), "config.yaml".into(), false)
        );
        assert_eq!(
            p(&["srv", "schema", "-c", "a.yaml"]),
            (false, None, "a.yaml".into(), true)
        );
        assert_eq!(
            p(&["srv", "-c", "b.yaml", "start"]),
            (true, None, "b.yaml".into(), false)
        );
        assert_eq!(
            p(&["srv", "start", "-c", "c.yaml"]),
            (true, None, "c.yaml".into(), false)
        );
    }

    #[test]
    fn an_app_without_a_cli_has_only_start() {
        let p = |a: &[&str]| parse::<__NoCli>(&PKG, argv(a));
        assert!(matches!(p(&["srv"]), Ok(Parsed::Start(_, None))));
        assert!(matches!(
            p(&["srv", "start", "--port", "1"]),
            Ok(Parsed::Start(_, Some(1)))
        ));
        assert!(p(&["srv", "other"]).is_err());
        assert_eq!(
            p(&["srv", "start", "--help"]).err().unwrap().kind(),
            ErrorKind::DisplayHelp
        );
    }

    #[test]
    fn version_names_the_app_not_doxa() {
        let pkg = __Package {
            bin: "backend-server",
            version: "2.3.4",
            about: "",
        };
        let err = parse::<__NoCli>(&pkg, argv(&["x", "--version"]))
            .err()
            .unwrap();
        assert_eq!(err.kind(), ErrorKind::DisplayVersion);
        assert_eq!(err.to_string().trim(), "backend-server 2.3.4");
    }

    #[test]
    fn the_apps_own_about_and_version_win() {
        /// mine
        #[derive(clap::Parser)]
        #[command(version = "9.9.9")]
        struct Own {}
        let pkg = __Package {
            about: "pkg",
            ..PKG
        };
        let cmd = command::<Own>(&pkg);
        assert_eq!(cmd.get_version(), Some("9.9.9"));
        assert_eq!(cmd.get_about().unwrap().to_string(), "mine");
        let cmd = command::<__NoCli>(&pkg);
        assert_eq!(cmd.get_version(), Some("1.0.0"));
        assert_eq!(cmd.get_about().unwrap().to_string(), "pkg");
    }

    #[test]
    #[should_panic(expected = "`start` is reserved")]
    fn an_app_start_subcommand_panics() {
        #[derive(clap::Parser)]
        struct Clash {
            #[command(subcommand)]
            command: Option<ClashCommand>,
        }
        #[derive(clap::Subcommand)]
        enum ClashCommand {
            Start,
        }
        command::<Clash>(&PKG);
    }

    #[test]
    #[should_panic(expected = "field is an Option")]
    fn a_required_subcommand_panics() {
        #[derive(clap::Parser)]
        struct Required {
            #[command(subcommand)]
            command: Command,
        }
        command::<Required>(&PKG);
    }

    #[test]
    #[should_panic(expected = "field is an Option")]
    fn an_enum_cli_panics() {
        #[derive(clap::Parser)]
        enum Bare {
            Schema,
        }
        command::<Bare>(&PKG);
    }

    #[test]
    #[should_panic(expected = "`--port` is reserved")]
    fn a_global_port_panics() {
        #[derive(clap::Parser)]
        struct Ported {
            #[arg(long, global = true)]
            port: Option<u16>,
        }
        command::<Ported>(&PKG);
    }

    #[test]
    fn start_may_return_a_router_a_serve_or_a_result() {
        assert!(Router::new().into_serve().is_ok());
        assert!(Serve::new(Router::new()).into_serve().is_ok());
        assert!(Ok::<_, String>(Router::new()).into_serve().is_ok());
        let err = Err::<Router, _>("no db".to_string()).into_serve().err();
        assert_eq!(err.unwrap().to_string(), "no db");
    }

    #[test]
    fn port_flag_binds_loopback_and_env_port_keeps_the_host() {
        let configured: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        assert_eq!(
            bind_addr(Some(9000), Some(7000), configured),
            "127.0.0.1:9000".parse().unwrap()
        );
        assert_eq!(
            bind_addr(None, Some(7000), configured),
            "0.0.0.0:7000".parse().unwrap()
        );
        assert_eq!(bind_addr(None, None, configured), configured);
    }

    fn torn_down(flag: &Arc<AtomicBool>) -> impl Future<Output = ()> + 'static {
        let flag = flag.clone();
        async move { flag.store(true, Ordering::SeqCst) }
    }

    #[tokio::test]
    async fn teardown_runs_when_the_drain_runs_out() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let flag = Arc::new(AtomicBool::new(false));
        let router = Router::new().route(
            "/hang",
            axum::routing::get(std::future::pending::<&'static str>),
        );
        let serve = Serve::new(router)
            .addr(format!("127.0.0.1:{port}"))
            .drain(Duration::from_millis(50))
            .teardown(torn_down(&flag));
        let (go, went) = tokio::sync::oneshot::channel::<()>();
        let signal = async move {
            let _ = went.await;
        };
        let served = tokio::task::LocalSet::new();
        let run = served.run_until(async move {
            let task = tokio::task::spawn_local(run_serve(serve, None, None, stopping().0, signal));
            let mut conn = loop {
                if let Ok(c) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                    break c;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            };
            use tokio::io::AsyncWriteExt;
            conn.write_all(b"GET /hang HTTP/1.1\r\nhost: x\r\n\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            go.send(()).unwrap();
            task.await.unwrap()
        });
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("the drain bounds shutdown")
            .unwrap();
        assert!(flag.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn serve_listener_serves_a_prebound_listener_and_signals_stopping() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stop, stopping) = stopping();
        let flag = Arc::new(AtomicBool::new(false));
        let serve = Serve::new(Router::new().route("/", axum::routing::get(|| async { "hi" })))
            .map_router(|r| r.route("/extra", axum::routing::get(|| async { "extra" })))
            .drain(Duration::from_millis(50))
            .teardown(torn_down(&flag));
        let (go, went) = tokio::sync::oneshot::channel::<()>();
        let served = tokio::task::LocalSet::new();
        let run = served.run_until(async move {
            let task =
                tokio::task::spawn_local(serve_listener(serve, listener, stop, async move {
                    let _ = went.await;
                }));
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            conn.write_all(b"GET /extra HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut body = String::new();
            conn.read_to_string(&mut body).await.unwrap();
            assert!(body.ends_with("extra"), "{body}");
            go.send(()).unwrap();
            stopping.wait().await;
            task.await.unwrap()
        });
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("shutdown completes")
            .unwrap();
        assert!(flag.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn teardown_runs_when_binding_fails() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = taken.local_addr().unwrap();
        let flag = Arc::new(AtomicBool::new(false));
        let serve = Serve::new(Router::new())
            .addr(addr.to_string())
            .teardown(torn_down(&flag));
        let result = run_serve(serve, None, None, stopping().0, std::future::pending()).await;
        assert!(result.is_err());
        assert!(flag.load(Ordering::SeqCst));
    }
}
