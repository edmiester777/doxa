//! A dev service: built with cargo, run with `start`, rebuilt and restarted on change.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use doxa_build::config::{DevConfig, Workspace};
use doxa_build::local::Patches;
use futures::future::BoxFuture;
use notify_debouncer_mini::notify::{RecommendedWatcher, RecursiveMode};
use notify_debouncer_mini::{new_debouncer, DebounceEventResult, Debouncer};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{broadcast, mpsc, watch, OwnedSemaphorePermit};

use super::log::{self, Tag};
use super::proxy::Reload;
use super::tui::Status;
use super::watch::{canonical, outermost};

/// `Service::sibling` runs under `spawn_blocking`, so its error crosses threads.
pub type SendError = Box<dyn std::error::Error + Send + Sync>;

pub type Watcher = Debouncer<RecommendedWatcher>;

/// Resolves to the startup build slot, once it's this service's turn.
pub type Turn = BoxFuture<'static, Option<OwnedSemaphorePermit>>;

/// How a service is run.
struct Run {
    bin: String,
    port: u16,
    /// `start --port N` for a `#[doxa::main]` service; none for an in-workspace server without `dev`.
    args: Vec<String>,
    dist: Option<PathBuf>,
    /// Sibling builds use their own toolchain.
    sibling: bool,
    /// `--config` patches to local checkouts.
    cargo_config: Vec<String>,
}

/// Which changed paths rebuild a service.
#[derive(Debug, Clone)]
pub struct Feeds {
    root: PathBuf,
    dirs: Vec<PathBuf>,
    target: PathBuf,
}

impl Feeds {
    pub fn feeds(&self, path: &Path) -> bool {
        let noise = path.starts_with(&self.target)
            || path
                .components()
                .any(|c| matches!(c.as_os_str().to_str(), Some(".git" | "node_modules")));
        let root_manifest = path.parent() == Some(self.root.as_path())
            && matches!(
                path.file_name().and_then(|n| n.to_str()),
                Some("Cargo.toml" | "Cargo.lock")
            );
        !noise && (root_manifest || self.dirs.iter().any(|d| path.starts_with(d)))
    }
}

pub struct Service {
    pub name: String,
    pub tag: Tag,
    run: Run,
    feeds: Feeds,
    child: Option<Child>,
    /// Held through the first build, so startup bounds how many build at once.
    permit: Option<OwnedSemaphorePermit>,
    /// `true` once it has listened.
    up: watch::Sender<bool>,
    /// Services to wait on before the first launch.
    after: Vec<(String, watch::Receiver<bool>)>,
}

impl Service {
    /// A sibling workspace's package, per `[workspace.metadata.doxa.dev.services]`.
    pub fn sibling(name: &str, root: &Path, tag: Tag) -> Result<(Service, Workspace), SendError> {
        let hint = format!("check [workspace.metadata.doxa.dev.services] {name}.path");
        let ws = Workspace::load_sibling(root, &hint)?;
        let pkg = ws.package(name).ok_or_else(|| {
            format!(
                "no package `{name}` in {}\n  fix: {hint}, or rename the entry",
                root.display()
            )
        })?;
        let dev = pkg.dev()?.ok_or_else(|| {
            format!("`{name}` has no dev port\n  fix: add [package.metadata.doxa.dev] port = <port> to its Cargo.toml")
        })?;
        let run = Run {
            bin: pkg.dev_bin(dev.bin.as_deref())?,
            port: dev.port,
            args: start_args(dev.port),
            dist: None,
            sibling: true,
            cargo_config: Vec::new(),
        };
        Ok((Service::new(&ws, name, run, tag), ws))
    }

    /// This workspace's `server =` package; `doxa dev` passes it the dist.
    pub fn in_workspace(
        ws: &Workspace,
        name: &str,
        dist: PathBuf,
        tag: Tag,
    ) -> Result<Service, SendError> {
        let pkg = ws
            .package(name)
            .ok_or_else(|| format!("no package `{name}` in the workspace"))?;
        let dev: Option<DevConfig> = pkg.dev()?;
        let port = match &dev {
            Some(d) => d.port,
            None => free_port()?,
        };
        let run = Run {
            bin: pkg.dev_bin(dev.as_ref().and_then(|d| d.bin.as_deref()))?,
            port,
            args: match dev {
                Some(_) => start_args(port),
                None => Vec::new(),
            },
            dist: Some(dist),
            sibling: false,
            cargo_config: Vec::new(),
        };
        Ok(Service::new(ws, name, run, tag))
    }

    fn new(ws: &Workspace, name: &str, run: Run, tag: Tag) -> Service {
        let feeds = Feeds {
            root: canonical(&ws.workspace_root),
            dirs: ws.source_dirs(name).iter().map(|d| canonical(d)).collect(),
            target: canonical(&ws.target_directory),
        };
        Service {
            name: name.to_owned(),
            tag,
            run,
            feeds,
            child: None,
            permit: None,
            up: watch::Sender::new(false),
            after: Vec::new(),
        }
    }

    pub fn port(&self) -> u16 {
        self.run.port
    }

    /// Turns `true` once it has listened, or found its port already served.
    pub fn up(&self) -> watch::Receiver<bool> {
        self.up.subscribe()
    }

    /// Build against `patches` and rebuild when a patched crate changes, noting what it can't patch.
    pub fn patch(&mut self, patches: Patches) {
        for (name, source) in &patches.unpatchable {
            self.tag.note(format!(
                "{name} comes from {source}, which doxa can't patch; it builds without local edits"
            ));
        }
        self.feeds
            .dirs
            .extend(patches.patched.iter().map(|(_, dir)| canonical(dir)));
        self.run.cargo_config = patches.config;
    }

    /// Hold the first launch until each of `after` is up.
    pub fn launch_after(&mut self, after: Vec<(String, watch::Receiver<bool>)>) {
        self.after = after;
    }

    fn cargo(&self) -> Command {
        let mut cmd = match self.run.sibling {
            true => {
                let mut c = Command::new("cargo");
                c.env_remove("CARGO").env_remove("RUSTUP_TOOLCHAIN");
                c
            }
            false => Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into())),
        };
        cmd.current_dir(&self.feeds.root).stdin(Stdio::null());
        cmd
    }

    /// `cargo build` the binary: the path it wrote and whether it was already fresh, or `None`.
    async fn build(&self) -> std::io::Result<Option<(PathBuf, bool)>> {
        self.tag.line("compiling…");
        let started = Instant::now();
        let format = match log::color() {
            true => "--message-format=json-diagnostic-rendered-ansi",
            false => "--message-format=json",
        };
        let mut cmd = self.cargo();
        for c in &self.run.cargo_config {
            cmd.args(["--config", c]);
        }
        let mut child = cmd
            .args(["build", "-p", &self.name, "--bin", &self.run.bin, format])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        log::pipe(self.tag.clone(), child.stderr.take().expect("piped"));
        let mut exe = None;
        let mut out = BufReader::new(child.stdout.take().expect("piped")).lines();
        while let Some(l) = out.next_line().await? {
            let Ok(msg) = serde_json::from_str::<serde_json::Value>(&l) else {
                continue;
            };
            match msg["reason"].as_str() {
                Some("compiler-message") => {
                    if let Some(r) = msg["message"]["rendered"].as_str() {
                        r.lines().for_each(|l| self.tag.line(l));
                    }
                }
                Some("compiler-artifact") if msg["target"]["name"] == self.run.bin.as_str() => {
                    if let Some(e) = msg["executable"].as_str() {
                        exe = Some((PathBuf::from(e), msg["fresh"] == true));
                    }
                }
                _ => {}
            }
        }
        match (child.wait().await?.success(), exe) {
            (true, Some(exe)) => {
                let secs = started.elapsed().as_secs_f32();
                self.tag.line(format!("compiled in {secs:.1}s"));
                Ok(Some(exe))
            }
            _ => {
                self.tag.line("build failed — waiting for changes");
                Ok(None)
            }
        }
    }

    /// Run a copy of `exe`, so the next build can replace it while this one runs (Windows).
    fn spawn(&mut self, exe: &Path) -> std::io::Result<()> {
        let dir = self.feeds.target.join("doxa/dev");
        std::fs::create_dir_all(&dir)?;
        let copy = dir.join(format!("{}{}", self.run.bin, std::env::consts::EXE_SUFFIX));
        // A new file each run: macOS kills a binary rewritten in place after it has run.
        let _ = std::fs::remove_file(&copy);
        std::fs::copy(exe, &copy)?;
        let mut cmd = Command::new(&copy);
        cmd.args(&self.run.args)
            .env("PORT", self.run.port.to_string())
            .env("DOXA_DEV_CHILD", "1")
            .current_dir(&self.feeds.root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(dist) = &self.run.dist {
            cmd.env("DOXA_DIST", dist);
        }
        let mut child = cmd.spawn()?;
        log::pipe(self.tag.clone(), child.stdout.take().expect("piped"));
        log::pipe(self.tag.clone(), child.stderr.take().expect("piped"));
        self.child = Some(child);
        Ok(())
    }

    /// Build, then swap the running process for the new one, even a fresh build's when `force`.
    /// `true` once it listens.
    pub async fn rebuild(&mut self, force: bool) -> bool {
        self.tag.status(Status::Compiling);
        let built = self.build().await;
        self.permit = None;
        let exe = match built {
            Ok(Some((_, true))) if !force && self.running() => {
                self.tag.status(Status::Running(self.run.port));
                return false;
            }
            Ok(Some((exe, _))) => exe,
            Ok(None) => return self.failed(),
            Err(e) => {
                self.tag.line(format!("error: running cargo: {e}"));
                return self.failed();
            }
        };
        for (name, mut up) in std::mem::take(&mut self.after) {
            if !*up.borrow() {
                self.tag.line(format!("waiting for {name} to listen"));
                self.tag.status(Status::Waiting);
                let _ = up.wait_for(|up| *up).await;
            }
        }
        self.stop().await;
        if let Err(e) = self.spawn(&exe) {
            self.tag
                .line(format!("error: starting {}: {e}", exe.display()));
            self.tag.status(Status::Exited);
            return false;
        }
        self.wait_ready().await
    }

    fn failed(&mut self) -> bool {
        let running = self.running();
        self.tag.status(Status::Failed { running });
        false
    }

    /// Until the port answers (`true`), the process exits, or two minutes pass.
    async fn wait_ready(&mut self) -> bool {
        for _ in 0..1200 {
            if port_taken(self.run.port).await {
                self.tag.line(format!("ready on :{}", self.run.port));
                self.tag.status(Status::Running(self.run.port));
                self.up.send_replace(true);
                return true;
            }
            if let Some(Ok(Some(status))) = self.child.as_mut().map(|c| c.try_wait()) {
                self.tag.line(format!(
                    "exited with {status}; will restart on the next change"
                ));
                self.tag.status(Status::Exited);
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        self.tag.line(format!(
            "not listening on :{} after 2 minutes — does its main use #[doxa::main]?",
            self.run.port
        ));
        self.tag.status(Status::Unready);
        false
    }

    /// Once the running process exits on its own; never when none runs.
    async fn exited(&mut self) {
        match &mut self.child {
            Some(child) => {
                let _ = child.wait().await;
                self.child = None;
                self.tag.status(Status::Exited);
            }
            None => std::future::pending().await,
        }
    }

    fn running(&mut self) -> bool {
        self.child
            .as_mut()
            .is_some_and(|c| matches!(c.try_wait(), Ok(None)))
    }

    /// SIGTERM, so teardown runs; SIGKILL after 10 s, past `Serve`'s default 5 s drain.
    pub async fn stop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        #[cfg(unix)]
        if let Some(pid) = child.id() {
            if let Ok(pid) = libc::pid_t::try_from(pid) {
                // SAFETY: `id()` is `None` once tokio has reaped the child, so the pid is still ours.
                unsafe { libc::kill(pid, libc::SIGTERM) };
            }
            if tokio::time::timeout(Duration::from_secs(10), child.wait())
                .await
                .is_ok()
            {
                return;
            }
        }
        let _ = child.kill().await;
    }
}

fn start_args(port: u16) -> Vec<String> {
    vec!["start".into(), "--port".into(), port.to_string()]
}

fn free_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

pub async fn port_taken(port: u16) -> bool {
    tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
}

/// Watch `svc`'s sources; one unforced kick per batch that needs a rebuild.
pub fn watch_sources(svc: &Service) -> Result<(Watcher, mpsc::UnboundedReceiver<bool>), SendError> {
    let (tx, rx) = mpsc::unbounded_channel();
    svc.tag.kicks(&tx);
    let feeds = svc.feeds.clone();
    let mut d = new_debouncer(
        Duration::from_millis(200),
        move |res: DebounceEventResult| {
            if res.is_ok_and(|ev| ev.iter().any(|e| feeds.feeds(&e.path))) {
                let _ = tx.send(false);
            }
        },
    )?;
    let dirs = outermost(&svc.feeds.dirs);
    if !dirs.contains(&svc.feeds.root) {
        d.watcher()
            .watch(&svc.feeds.root, RecursiveMode::NonRecursive)?;
    }
    for dir in dirs {
        d.watcher().watch(&dir, RecursiveMode::Recursive)?;
    }
    Ok((d, rx))
}

/// Once `turn` resolves, build and run `svc`, then again on each kick, until `stop` fires.
/// Holds `_watcher` alive.
pub async fn supervise(
    mut svc: Service,
    _watcher: Option<Watcher>,
    mut kicks: mpsc::UnboundedReceiver<bool>,
    turn: Option<Turn>,
    mut stop: watch::Receiver<u32>,
    reload: broadcast::Sender<Reload>,
) {
    if port_taken(svc.port()).await {
        svc.tag.line(format!(
            "port {0} is in use — using what's there, not starting it\n  fix: `lsof -i :{0}` shows what holds it",
            svc.port()
        ));
        svc.tag.status(Status::External(svc.port()));
        svc.up.send_replace(true);
        return;
    }
    let mut force = false;
    if let Some(turn) = turn {
        tokio::select! {
            _ = stop.changed() => return svc.tag.status(Status::Stopped),
            permit = turn => svc.permit = permit,
        }
        // The first build sees every change made while it waited.
        while kicks.try_recv().is_ok() {}
    }
    'run: loop {
        // Dropping the build on stop drops its cargo child, which is kill_on_drop.
        let up = tokio::select! {
            _ = stop.changed() => break,
            up = svc.rebuild(force) => up,
        };
        if up {
            let _ = reload.send(Reload::Page);
        }
        loop {
            tokio::select! {
                _ = stop.changed() => break 'run,
                () = svc.exited() => {}
                Some(f) = kicks.recv() => {
                    force = f;
                    // Whatever arrived during the last build joins this one.
                    while let Ok(f) = kicks.try_recv() {
                        force |= f;
                    }
                    break;
                }
            }
        }
    }
    svc.tag.status(Status::Stopping);
    svc.stop().await;
    svc.tag.status(Status::Stopped);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::log::Console;

    #[test]
    fn a_service_rebuilds_for_its_sources_and_root_manifests_only() {
        let feeds = Feeds {
            root: "/b".into(),
            dirs: vec!["/b/crates/api".into(), "/b/crates/types".into()],
            target: "/b/target".into(),
        };
        assert!(feeds.feeds(Path::new("/b/crates/api/src/routes.rs")));
        assert!(feeds.feeds(Path::new("/b/crates/api/prompts/system.md")));
        assert!(feeds.feeds(Path::new("/b/Cargo.lock")));
        assert!(feeds.feeds(Path::new("/b/Cargo.toml")));
        assert!(!feeds.feeds(Path::new("/b/README.md")));
        assert!(!feeds.feeds(Path::new("/b/target/debug/api")));
        assert!(!feeds.feeds(Path::new("/b/crates/api/.git/HEAD")));
        assert!(!feeds.feeds(Path::new("/b/crates/api/node_modules/x.js")));
        assert!(!feeds.feeds(Path::new("/b/crates/engine/src/lib.rs")));
    }

    #[test]
    fn a_patched_crate_feeds_the_service_and_its_build() {
        let ws = Workspace::from_json(
            r#"{"workspace_root": "/b", "target_directory": "/b/target", "packages": [
              {"name": "api", "manifest_path": "/b/api/Cargo.toml", "targets": [], "dependencies": []}]}"#,
        )
        .unwrap();
        let run = Run {
            bin: "api".into(),
            port: 1,
            args: Vec::new(),
            dist: None,
            sibling: false,
            cargo_config: Vec::new(),
        };
        let mut svc = Service::new(&ws, "api", run, Console::Stderr.web());
        assert!(!svc.feeds.feeds(Path::new("/lib/core/src/lib.rs")));
        svc.patch(Patches {
            config: vec!["patch.crates-io.core.path=\"/lib/core\"".into()],
            patched: vec![("core".into(), "/lib/core".into())],
            unpatchable: Vec::new(),
        });
        assert!(svc.feeds.feeds(Path::new("/lib/core/src/lib.rs")));
        assert_eq!(svc.run.cargo_config.len(), 1);
    }

    /// A std-only server: `start --port N` answers every request with `reply`.
    fn server_source(reply: &str) -> String {
        format!(
            r#"use std::io::{{Read, Write}};
fn main() {{
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args[1], "start");
    let port = &args[3];
    let listener = std::net::TcpListener::bind(format!("127.0.0.1:{{port}}")).unwrap();
    for conn in listener.incoming() {{
        let mut conn = conn.unwrap();
        let mut buf = [0u8; 1024];
        let _ = conn.read(&mut buf);
        let _ = conn.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{reply}");
    }}
}}
"#
        )
    }

    async fn get(port: u16) -> Option<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .ok()?;
        c.write_all(b"GET / HTTP/1.1\r\nhost: x\r\n\r\n")
            .await
            .ok()?;
        let mut out = String::new();
        c.read_to_string(&mut out).await.ok()?;
        out.rsplit("\r\n\r\n").next().map(str::to_owned)
    }

    async fn until(port: u16, want: &str) {
        for _ in 0..1200 {
            if get(port).await.as_deref() == Some(want) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("never answered {want}");
    }

    #[tokio::test]
    #[ignore = "builds a crate with cargo"]
    async fn a_compile_error_keeps_the_last_good_server_and_a_fix_restarts_it() {
        let tmp = tempfile::tempdir().unwrap();
        let root = canonical(tmp.path());
        let port = free_port().unwrap();
        std::fs::create_dir_all(root.join("srv/src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"srv\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        std::fs::write(
            root.join("srv/Cargo.toml"),
            format!("[package]\nname = \"srv\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[package.metadata.doxa.dev]\nport = {port}\n"),
        )
        .unwrap();
        let main = root.join("srv/src/main.rs");
        std::fs::write(&main, server_source("v1")).unwrap();

        let (svc, _) = Service::sibling("srv", &root, Console::Stderr.tag("srv", 0, 3)).unwrap();
        let (watcher, kicks) = watch_sources(&svc).unwrap();
        let (stop, stopped) = tokio::sync::watch::channel(0);
        let (reload, _) = broadcast::channel(16);
        let task = tokio::spawn(supervise(svc, Some(watcher), kicks, None, stopped, reload));
        until(port, "v1").await;

        std::fs::write(&main, "fn main() { this is not rust }").unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(get(port).await.as_deref(), Some("v1"));

        for reply in ["v2", "v3"] {
            std::fs::write(&main, server_source(reply)).unwrap();
            until(port, reply).await;
        }

        stop.send(1).unwrap();
        task.await.unwrap();
        assert!(!port_taken(port).await);
    }
}
