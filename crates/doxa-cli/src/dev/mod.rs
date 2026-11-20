//! `doxa dev` and `doxa gallery`: build once, serve behind a reloading proxy, and rebuild only
//! what a change touches. `doxa dev` also runs the server and each dev service beside it.

mod log;
mod proxy;
mod service;
mod siblings;
mod watch;

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use doxa_build::config::Workspace;
use doxa_build::dist::Dist;
use doxa_build::hot::Patched;
use doxa_build::pipeline::note;
use doxa_build::{BuildOptions, Pipeline};
use notify_debouncer_mini::{new_debouncer, DebounceEventResult};
use tokio::sync::{broadcast, mpsc};

use log::Tag;
use proxy::{
    allowed_hosts, forward, guard_host, lan_ip, reload_events, routes, urls, Proxy, Reload,
    RELOAD_PATH,
};
use service::{SendError, Service};
use siblings::LockGuard;
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

/// Run `doxa dev` until interrupted; `hot` patches web crate changes into the page.
pub async fn run(
    package: Option<String>,
    port: u16,
    locked: bool,
    hot: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let opts = BuildOptions {
        package,
        locked,
        hot,
        ..BuildOptions::default()
    };
    serve(opts, port)
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
    serve(opts, port)
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

fn load(cwd: PathBuf, opts: BuildOptions) -> Result<Loaded, SendError> {
    let mut pipeline = Pipeline::new(&cwd, opts.clone())?;
    let services = match opts.gallery {
        true => BTreeMap::new(),
        false => pipeline.workspace.dev_services()?,
    };
    let server = pipeline
        .web
        .config
        .server
        .as_deref()
        .filter(|_| !opts.gallery);
    let width = services
        .keys()
        .map(String::len)
        .chain(server.map(str::len))
        .max()
        .unwrap_or(0);
    let siblings = services
        .iter()
        .enumerate()
        .map(|(i, (name, s))| Service::sibling(name, &s.path, Tag::new(name, i, width)))
        .collect::<Result<Vec<_>, _>>()?;
    let workspaces: Vec<&Workspace> = siblings.iter().map(|(_, ws)| ws).collect();
    let (patches, foreign) = siblings::wire(&pipeline.graph, &workspaces)?;
    let lock = match patches.is_empty() {
        true => None,
        false => {
            let lock = LockGuard::take(&pipeline.workspace.workspace_root);
            note(format!(
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

async fn serve(opts: BuildOptions, port: u16) -> Result<(), SendError> {
    let cwd = std::env::current_dir()?;
    let (hot, gallery) = (opts.hot, opts.gallery);
    let Loaded {
        pipeline,
        siblings,
        foreign,
        lock: _lock,
        width,
    } = tokio::task::spawn_blocking(move || load(cwd, opts)).await??;
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
            Tag::new(pkg, siblings.len(), width),
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
        note(format!("proxying {} to {}", route.prefix, route.target));
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
    for url in urls(host, lan_ip(), port) {
        note(format!("serving {url}"));
    }
    tokio::spawn(async move { axum::serve(listener, app).await });

    // Services stop on the signal itself, not when this loop next breaks.
    let mut stop = stop_signal()?;
    let mut tasks = Vec::new();
    for (svc, _) in siblings {
        let (watcher, kicks) = service::watch_sources(&svc)?;
        tasks.push(tokio::spawn(service::supervise(
            svc,
            Some(watcher),
            kicks,
            stop.clone(),
            reload.clone(),
        )));
    }
    // The web crate's classify() decides when the in-workspace server rebuilds.
    let kick = server.map(|svc| {
        let (kick, kicks) = mpsc::unbounded_channel();
        tasks.push(tokio::spawn(service::supervise(
            svc,
            None,
            kicks,
            stop.clone(),
            reload.clone(),
        )));
        kick
    });

    let (changed, mut changes) = mpsc::unbounded_channel::<Vec<PathBuf>>();
    let mut debouncer = new_debouncer(
        Duration::from_millis(200),
        move |res: DebounceEventResult| match res {
            Ok(events) => {
                let _ = changed.send(events.into_iter().map(|e| e.path).collect());
            }
            Err(e) => eprintln!("error: watching for changes: {e}"),
        },
    )?;
    for (dir, mode) in watch.roots() {
        debouncer.watcher().watch(&dir, mode)?;
    }

    let p = pipeline.clone();
    let first = tokio::task::spawn_blocking(move || p.lock().expect("pipeline").build().map(drop));
    let mut built = tokio::select! {
        _ = stop.changed() => return finish(tasks).await,
        r = first => match r? {
            Ok(()) => true,
            Err(e) => {
                eprintln!("error: {e}");
                note("waiting for changes");
                false
            }
        },
    };

    loop {
        let mut paths = tokio::select! {
            _ = stop.changed() => break,
            Some(paths) = changes.recv() => paths,
        };
        while let Ok(more) = changes.try_recv() {
            paths.extend(more);
        }
        let plan = classify(paths.iter().map(PathBuf::as_path), &watch, &mut views);
        if plan.is_empty() {
            continue;
        }
        // The server rebuilds on its own; a failed web build mustn't swallow its change.
        if let (true, Some(kick)) = (plan.server, &kick) {
            let _ = kick.send(());
        }
        if !built {
            let p = pipeline.clone();
            let full = tokio::select! {
                _ = stop.changed() => break,
                r = tokio::task::spawn_blocking(move || p.lock().expect("pipeline").build().map(drop)) => r?,
            };
            match full {
                Ok(()) => {
                    built = true;
                    *proxy.latest_patch.lock().expect("patch") = None;
                    let _ = reload.send(Reload::Page);
                }
                Err(e) => eprintln!("error: {e}"),
            }
            continue;
        }
        if hot && plan.patch && !plan.bundle && !plan.css && !plan.server {
            let p = pipeline.clone();
            match tokio::task::spawn_blocking(move || p.lock().expect("pipeline").patch()).await? {
                Ok(Patched::Table(table)) => {
                    *proxy.latest_patch.lock().expect("patch") = Some(table.clone());
                    let _ = reload.send(Reload::Patch(table));
                    continue;
                }
                Ok(Patched::NotCompiled) => continue,
                Ok(Patched::NeedsRebuild(why)) => note(format!("{why}; rebuilding")),
                Err(e) => {
                    eprintln!("error: {e}");
                    note("rebuilding instead");
                }
            }
        }
        if !(plan.wasm || plan.bundle || plan.css) {
            continue;
        }
        let p = pipeline.clone();
        let rebuilt =
            tokio::task::spawn_blocking(move || rebuild(&mut p.lock().expect("pipeline"), plan))
                .await?;
        let dist = match rebuilt {
            Ok(dist) => dist,
            Err(e) => {
                eprintln!("error: {e}");
                continue;
            }
        };
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
    finish(tasks).await
}

/// Wait for every service to stop; a second signal stops waiting, and dropping the runtime
/// then kills each child.
async fn finish(tasks: Vec<tokio::task::JoinHandle<()>>) -> Result<(), SendError> {
    let mut again = stop_signal()?;
    tokio::select! {
        _ = futures::future::join_all(tasks) => {}
        _ = async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = again.changed().await;
        } => note("stopping now"),
    }
    Ok(())
}

/// Changes once Ctrl-C or SIGTERM arrives, at any point after this call.
fn stop_signal() -> std::io::Result<tokio::sync::watch::Receiver<()>> {
    let (tx, rx) = tokio::sync::watch::channel(());
    #[cfg(unix)]
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::spawn(async move {
        #[cfg(unix)]
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        let _ = tx.send(());
    });
    Ok(rx)
}
