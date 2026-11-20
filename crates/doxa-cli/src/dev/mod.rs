//! `doxa dev` and `doxa gallery`: build once, serve behind a reloading proxy, and rebuild only
//! what a change touches. `doxa dev` also runs the server and each dev service beside it.

mod log;
mod proxy;
mod service;
mod siblings;
mod tui;
mod watch;

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use doxa_build::config::Workspace;
use doxa_build::dist::Dist;
use doxa_build::hot::Patched;
use doxa_build::{BuildOptions, Pipeline};
use futures::FutureExt;
use notify_debouncer_mini::{new_debouncer, DebounceEventResult};
use tokio::sync::{broadcast, mpsc, oneshot, watch as signal, OwnedSemaphorePermit, Semaphore};

use log::{Console, Tag};
use proxy::{
    allowed_hosts, forward, guard_host, lan_ip, reload_events, routes, urls, Proxy, Reload,
    RELOAD_PATH,
};
use service::{SendError, Service};
use siblings::LockGuard;
use tui::{Status, Tui};
use watch::{canonical, classify, Plan, Watch};

fn rebuild(p: &mut Pipeline, plan: Plan) -> doxa_build::Result<Option<Dist>> {
    if plan.wasm {
        p.npm()?;
        p.wasm()?;
        p.js()?;
        p.css()?;
    } else {
        if plan.bundle {
            p.js()?;
        }
        if plan.css {
            p.css()?;
        }
    }
    if plan.wasm || plan.bundle || plan.css {
        p.assemble().map(Some)
    } else {
        Ok(None)
    }
}

/// Startup builds at once when neither the flag nor `[workspace.metadata.doxa.dev]` says.
const MAX_PARALLEL_BUILD: NonZeroUsize = NonZeroUsize::new(4).expect("nonzero");

/// Run `doxa dev` until interrupted; `hot` patches web crate changes into the page, and `tui`
/// gives each service a pane.
pub async fn run(
    package: Option<String>,
    port: u16,
    locked: bool,
    hot: bool,
    tui: bool,
    max_parallel: Option<NonZeroUsize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let console = match (tui, tui::available()) {
        (true, true) => Console::Tui(tui::Shared::new()),
        (true, false) => {
            Console::Stderr
                .web()
                .note("--tui needs an interactive terminal; showing plain output");
            Console::Stderr
        }
        (false, _) => Console::Stderr,
    };
    // Dropped before main prints an error, so the error lands on the restored screen.
    let _screen = match &console {
        Console::Tui(s) => Some(Tui::start(s.clone())?),
        Console::Stderr => None,
    };
    let opts = BuildOptions {
        package,
        locked,
        hot,
        output: console.output(),
        ..BuildOptions::default()
    };
    serve(opts, port, console, max_parallel)
        .await
        .map_err(|e| e as Box<dyn std::error::Error>)
}

/// Run `doxa gallery` until interrupted. Stories have no API to reach, so nothing is proxied.
pub async fn gallery(
    package: Option<String>,
    port: u16,
    locked: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let opts = BuildOptions {
        package,
        locked,
        hot: true,
        gallery: true,
        ..BuildOptions::default()
    };
    serve(opts, port, Console::Stderr, None)
        .await
        .map_err(|e| e as Box<dyn std::error::Error>)
}

/// The web crate's pipeline, compiled against each dev service's local source.
struct Loaded {
    pipeline: Pipeline,
    siblings: Vec<(Service, Workspace)>,
    foreign: watch::Foreign,
    lock: Option<LockGuard>,
    width: usize,
}

fn load(cwd: PathBuf, opts: BuildOptions, console: &Console) -> Result<Loaded, SendError> {
    let mut pipeline = Pipeline::new(&cwd, opts.clone())?;
    let services = match opts.gallery {
        true => Vec::new(),
        false => pipeline.workspace.dev_services()?,
    };
    let server = pipeline
        .web
        .config
        .server
        .as_deref()
        .filter(|_| !opts.gallery);
    let width = services
        .iter()
        .map(|(name, _)| name.len())
        .chain(server.map(str::len))
        .max()
        .unwrap_or(0);
    let mut siblings = Vec::with_capacity(services.len());
    let mut ups: BTreeMap<String, signal::Receiver<bool>> = BTreeMap::new();
    // In build order, so each `after` entry is already in `ups`.
    for (i, (name, s)) in services.iter().enumerate() {
        let (mut svc, ws) = Service::sibling(name, &s.path, console.tag(name, i, width))?;
        svc.launch_after(
            s.after
                .iter()
                .map(|a| (a.clone(), ups[a].clone()))
                .collect(),
        );
        ups.insert(name.clone(), svc.up());
        siblings.push((svc, ws));
    }
    let workspaces: Vec<&Workspace> = siblings.iter().map(|(_, ws)| ws).collect();
    let (patches, foreign) = siblings::wire(&pipeline.graph, &workspaces, &console.web())?;
    let lock = match patches.is_empty() {
        true => None,
        false => {
            let lock = LockGuard::take(&pipeline.workspace.workspace_root);
            console.web().note(format!(
                "compiling {} against the dev services' local source; Cargo.lock is restored on exit (`git checkout Cargo.lock` if doxa is killed)",
                pipeline.web.name
            ));
            pipeline = Pipeline::new(
                &cwd,
                BuildOptions {
                    cargo_config: patches,
                    ..opts
                },
            )?;
            Some(lock)
        }
    };
    Ok(Loaded {
        pipeline,
        siblings,
        foreign,
        lock,
        width,
    })
}

async fn serve(
    opts: BuildOptions,
    port: u16,
    console: Console,
    max_parallel: Option<NonZeroUsize>,
) -> Result<(), SendError> {
    let cwd = std::env::current_dir()?;
    let (hot, gallery) = (opts.hot, opts.gallery);
    let web = console.web();
    let (stops, mut stop) = signal::channel(0);
    console.stops(stops.clone());
    let loading = console.clone();
    let Loaded {
        pipeline,
        siblings,
        foreign,
        lock: _lock,
        width,
    } = tokio::task::spawn_blocking(move || load(cwd, opts, &loading)).await??;
    web.rename(&pipeline.web.name);
    let max_parallel = match max_parallel {
        Some(n) => n,
        None => pipeline
            .workspace
            .max_parallel_build()?
            .unwrap_or(MAX_PARALLEL_BUILD),
    };
    let server_pkg = match gallery {
        true => None,
        false => pipeline.web.config.server.clone(),
    };
    let dist = canonical(&pipeline.dist_dir());
    let server = match &server_pkg {
        Some(pkg) => Some(Service::in_workspace(
            &pipeline.workspace,
            pkg,
            dist.clone(),
            console.server_tag(pkg, siblings.len(), width),
        )?),
        None => None,
    };

    // Every check before anything is spawned.
    let mut ports = BTreeMap::new();
    for svc in siblings.iter().map(|(s, _)| s).chain(&server) {
        if svc.port() == port {
            return Err(format!(
                "{} declares port {port}, which doxa dev serves on\n  fix: pass --port",
                svc.name
            )
            .into());
        }
        if let Some((other, _)) = ports.iter().find(|(_, p)| **p == svc.port()) {
            return Err(format!(
                "{} and {other} both declare dev port {}",
                svc.name,
                svc.port()
            )
            .into());
        }
        ports.insert(svc.name.clone(), svc.port());
    }
    let routes = match gallery {
        true => Vec::new(),
        false => routes(&pipeline.web.config.proxy, &ports, |name| {
            std::env::var(name).ok()
        })?,
    };
    if !gallery && server.is_none() && routes.is_empty() {
        return Err("nothing to serve the API\n  fix: set server = \"<server package>\" or add a [package.metadata.doxa.proxy] table to the web crate".into());
    }
    let patches = pipeline.patch_dir();
    let watch = Watch::new(
        &pipeline.workspace,
        &pipeline.web,
        server_pkg.as_deref(),
        foreign,
    );
    let mut views = watch.client_views();
    let pipeline = Arc::new(Mutex::new(pipeline));
    for route in &routes {
        web.note(format!("proxying {} to {}", route.prefix, route.target));
    }

    let (reload, _) = broadcast::channel(16);
    let proxy = Arc::new(Proxy {
        dist,
        patches,
        upstream: server
            .as_ref()
            .map(|s| format!("http://127.0.0.1:{}", s.port())),
        routes,
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        reload: reload.clone(),
        latest_patch: Mutex::new(None),
    });
    let host = match std::env::var("DOXA_HOST") {
        Ok(h) => h
            .parse::<IpAddr>()
            .map_err(|_| format!("DOXA_HOST={h} is not an IP address"))?,
        Err(_) => Ipv4Addr::LOCALHOST.into(),
    };
    let allowed = Arc::new(allowed_hosts(
        host,
        lan_ip(),
        std::env::var("DOXA_ALLOWED_HOSTS").ok().as_deref(),
    ));
    let app = Router::new()
        .route(RELOAD_PATH, get(reload_events))
        .fallback(forward)
        .with_state(proxy.clone())
        .layer(axum::middleware::from_fn_with_state(allowed, guard_host));
    let listener = tokio::net::TcpListener::bind((host, port)).await?;
    let served_port = listener.local_addr()?.port();
    let served = urls(host, lan_ip(), served_port);
    for url in &served {
        web.note(format!("serving {url}"));
    }
    console.header(served);
    tokio::spawn(async move { axum::serve(listener, app).await });

    // Services stop on the signal itself, not when this loop next breaks.
    listen(stops)?;
    let mut tasks = Vec::new();
    // Startup build slots go out in order: the services, the web crate, its server.
    let mut turns = Vec::new();
    let mut turn = || {
        let (tx, rx) = oneshot::channel();
        turns.push(tx);
        rx.map(Result::ok)
    };
    for (svc, _) in siblings {
        let (watcher, kicks) = service::watch_sources(&svc)?;
        tasks.push(tokio::spawn(service::supervise(
            svc,
            Some(watcher),
            kicks,
            Some(turn().boxed()),
            stop.clone(),
            reload.clone(),
        )));
    }
    let web_turn = turn();
    let (web_built, web_done) = oneshot::channel::<()>();
    // The web crate's classify() decides when the in-workspace server rebuilds.
    let kick = server.map(|svc| {
        let (kick, kicks) = mpsc::unbounded_channel();
        svc.tag.kicks(&kick);
        let slot = turn();
        let server_turn = async move {
            let _ = web_done.await;
            slot.await
        };
        tasks.push(tokio::spawn(service::supervise(
            svc,
            None,
            kicks,
            Some(server_turn.boxed()),
            stop.clone(),
            reload.clone(),
        )));
        kick
    });
    hand_out(turns, max_parallel);

    let (changed, mut changes) = mpsc::unbounded_channel::<Vec<PathBuf>>();
    let watching = web.clone();
    let mut debouncer = new_debouncer(
        Duration::from_millis(200),
        move |res: DebounceEventResult| match res {
            Ok(events) => {
                let _ = changed.send(events.into_iter().map(|e| e.path).collect());
            }
            Err(e) => watching.line(format!("error: watching for changes: {e}")),
        },
    )?;
    for (dir, mode) in watch.roots() {
        debouncer.watcher().watch(&dir, mode)?;
    }
    // Only the TUI holds a sender; without one, `recv` is `None` and its arm never fires.
    let mut web_kicks = {
        let (kick, kicks) = mpsc::unbounded_channel::<bool>();
        web.kicks(&kick);
        kicks
    };

    let p = pipeline.clone();
    let starting = web.clone();
    let first = async move {
        let permit = web_turn.await;
        starting.status(Status::Compiling);
        let r = tokio::task::spawn_blocking(move || p.lock().expect("pipeline").build().map(drop))
            .await;
        drop((permit, web_built));
        r
    };
    let mut built = tokio::select! {
        _ = stop.changed() => return finish(tasks, stop, &web).await,
        r = first => match r? {
            Ok(()) => {
                web.status(Status::Running(served_port));
                true
            }
            Err(e) => {
                web.line(format!("error: {e}"));
                web.note("waiting for changes");
                web.status(Status::Failed { running: false });
                false
            }
        },
    };

    loop {
        let (mut paths, forced) = tokio::select! {
            _ = stop.changed() => break,
            Some(paths) = changes.recv() => (paths, false),
            Some(_) = web_kicks.recv() => (Vec::new(), true),
        };
        while let Ok(more) = changes.try_recv() {
            paths.extend(more);
        }
        let plan = classify(paths.iter().map(PathBuf::as_path), &watch, &mut views);
        if plan.is_empty() && !forced {
            continue;
        }
        // The server rebuilds on its own; a failed web build mustn't swallow its change.
        if let (true, Some(kick)) = (plan.server, &kick) {
            let _ = kick.send(false);
        }
        if !built || forced {
            web.status(Status::Compiling);
            let p = pipeline.clone();
            let full = tokio::select! {
                _ = stop.changed() => break,
                r = tokio::task::spawn_blocking(move || p.lock().expect("pipeline").build().map(drop)) => r?,
            };
            match full {
                Ok(()) => {
                    built = true;
                    web.status(Status::Running(served_port));
                    *proxy.latest_patch.lock().expect("patch") = None;
                    let _ = reload.send(Reload::Page);
                }
                Err(e) => {
                    web.line(format!("error: {e}"));
                    web.status(Status::Failed { running: built });
                }
            }
            continue;
        }
        if hot && plan.patch && !plan.bundle && !plan.css && !plan.server {
            web.status(Status::Patching);
            let p = pipeline.clone();
            match tokio::task::spawn_blocking(move || p.lock().expect("pipeline").patch()).await? {
                Ok(Patched::Table(table)) => {
                    *proxy.latest_patch.lock().expect("patch") = Some(table.clone());
                    let _ = reload.send(Reload::Patch(table));
                    web.status(Status::Running(served_port));
                    continue;
                }
                Ok(Patched::NotCompiled) => {
                    web.status(Status::Failed { running: true });
                    continue;
                }
                Ok(Patched::NeedsRebuild(why)) => web.note(format!("{why}; rebuilding")),
                Err(e) => {
                    web.line(format!("error: {e}"));
                    web.note("rebuilding instead");
                }
            }
        }
        if !(plan.wasm || plan.bundle || plan.css) {
            continue;
        }
        web.status(Status::Compiling);
        let p = pipeline.clone();
        let rebuilt =
            tokio::task::spawn_blocking(move || rebuild(&mut p.lock().expect("pipeline"), plan))
                .await?;
        let dist = match rebuilt {
            Ok(dist) => dist,
            Err(e) => {
                web.line(format!("error: {e}"));
                web.status(Status::Failed { running: true });
                continue;
            }
        };
        web.status(Status::Running(served_port));
        if plan.wasm {
            *proxy.latest_patch.lock().expect("patch") = None;
        }
        // The server's own task reloads the page once it's back up.
        let event = match dist {
            Some(d) if !plan.wasm && !plan.bundle => {
                Reload::Css(d.stylesheets.iter().map(|s| format!("/{s}")).collect())
            }
            _ => Reload::Page,
        };
        let _ = reload.send(event);
    }
    finish(tasks, stop, &web).await
}

/// Give each of `turns` a build slot in order, `max` in use at once.
fn hand_out(turns: Vec<oneshot::Sender<OwnedSemaphorePermit>>, max: NonZeroUsize) {
    let slots = Arc::new(Semaphore::new(max.get()));
    tokio::spawn(async move {
        for turn in turns {
            let Ok(permit) = slots.clone().acquire_owned().await else {
                return;
            };
            // A service that never builds, its port already served, hands the slot straight back.
            let _ = turn.send(permit);
        }
    });
}

/// Wait for every service to stop; another stop a second or more later stops waiting, and
/// dropping the runtime then kills each child.
async fn finish(
    tasks: Vec<tokio::task::JoinHandle<()>>,
    mut stop: signal::Receiver<u32>,
    web: &Tag,
) -> Result<(), SendError> {
    web.status(Status::Stopping);
    stop.borrow_and_update();
    tokio::select! {
        _ = futures::future::join_all(tasks) => {}
        _ = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = stop.changed().await;
        } => web.note("stopping now"),
    }
    web.status(Status::Stopped);
    Ok(())
}

/// Count each Ctrl-C and SIGTERM from now on into `stops`.
fn listen(stops: signal::Sender<u32>) -> std::io::Result<()> {
    #[cfg(unix)]
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::spawn(async move {
        loop {
            #[cfg(unix)]
            tokio::select! {
                r = tokio::signal::ctrl_c() => if r.is_err() { break },
                Some(()) = term.recv() => {}
            }
            #[cfg(not(unix))]
            if tokio::signal::ctrl_c().await.is_err() {
                break;
            }
            stops.send_modify(|n| *n += 1);
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn build_slots_go_out_in_order_and_no_more_than_max_at_once() {
        let (txs, mut rxs): (Vec<_>, Vec<_>) = (0..3).map(|_| oneshot::channel()).unzip();
        hand_out(txs, NonZeroUsize::new(2).unwrap());
        let first = (&mut rxs[0]).await.unwrap();
        let _second = (&mut rxs[1]).await.unwrap();
        tokio::task::yield_now().await;
        assert!(rxs[2].try_recv().is_err());
        drop(first);
        assert!((&mut rxs[2]).await.is_ok());
    }
}
