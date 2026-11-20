//! `doxa`: scaffold, build, and develop a doxa app.

mod check;
mod dev;
mod new;
mod patch;
mod view;

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use clap::{Args, Parser, Subcommand};
use doxa_build::config::Workspace;
use doxa_build::local::{self, Locals, LockGuard};
use doxa_build::{BuildOptions, Pipeline};

/// The system allocator holds what bindgen frees, so the split's parses stack on top of it.
#[cfg(not(windows))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Debug, Parser)]
#[command(
    name = "doxa",
    version,
    about = "Scaffold, build, and develop a doxa app"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new app: api, server, and web crates.
    New {
        /// The app's name, used as the directory and package prefix.
        name: String,
    },
    /// Build the web crate into target/doxa/dist, then the server with it embedded.
    Build(BuildArgs),
    /// `doxa build` against the local checkouts `[workspace.metadata.doxa.dev]` lists; without
    /// a web crate, builds the `role = "server"` crate.
    BuildDev(BuildArgs),
    /// Build, run the server, and rebuild and reload on change.
    Dev {
        /// The web crate; defaults to the one with role = "client".
        #[arg(short, long)]
        package: Option<String>,
        /// The port to serve on, at `$DOXA_HOST` (default 127.0.0.1).
        #[arg(long, default_value_t = 3000)]
        port: u16,
        /// Install npm dependencies from the lockfile only.
        #[arg(long)]
        locked: bool,
        /// Rebuild and reload on a web crate change instead of patching the running page.
        #[arg(long)]
        no_hot: bool,
        /// Print plain tagged lines instead of a pane per service; implied without a terminal.
        #[arg(long)]
        no_tui: bool,
        /// Run at most N startup builds at once [default: 4].
        #[arg(long, value_name = "N")]
        max_parallel_build: Option<NonZeroUsize>,
        /// Run startup builds one at a time, in `after` order; `--max-parallel-build 1`.
        #[arg(long, conflicts_with = "max_parallel_build")]
        serial: bool,
    },
    /// Build the `#[story]` functions into a gallery, serve it, and patch in each change.
    Gallery {
        /// The web crate; defaults to the one with role = "client".
        #[arg(short, long)]
        package: Option<String>,
        /// The port to serve on, at `$DOXA_HOST` (default 127.0.0.1).
        #[arg(long, default_value_t = 4710)]
        port: u16,
        /// Install npm dependencies from the lockfile only.
        #[arg(long)]
        locked: bool,
        /// The path the gallery is served under, with `--out`.
        #[arg(long, requires = "out")]
        base: Option<String>,
        /// Write the gallery as a static site to this directory instead of serving it.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Check an API crate builds for the browser, naming the dependency that doesn't.
    Check {
        /// Build the crate for wasm32-unknown-unknown.
        #[arg(long, required = true)]
        wire: bool,
        /// The API crate.
        #[arg(short, long)]
        package: String,
    },
    /// Run a command, e.g. `cargo test`, against the local checkouts `[workspace.metadata.doxa.dev]`
    /// lists, via `.cargo/config.toml`; it and `Cargo.lock` are put back after.
    Patch {
        /// The command and its arguments.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Format Rust sources, including view markup.
    Fmt {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        args: Vec<String>,
    },
}

#[derive(Debug, Args)]
struct BuildArgs {
    /// Optimize, minify, and run wasm-opt when it is on PATH.
    #[arg(long)]
    release: bool,
    /// The web crate; defaults to the one with role = "client".
    #[arg(short, long)]
    package: Option<String>,
    /// Install npm dependencies from the lockfile only.
    #[arg(long)]
    locked: bool,
    /// Write the `#[component(export)]` components as an npm package in target/doxa/lib.
    #[arg(long)]
    lib: bool,
    /// The path the app is served under, e.g. /docs/; overrides the web crate's `base`.
    #[arg(long)]
    base: Option<String>,
    /// Write a static site to this directory instead of building the server.
    #[arg(long, conflicts_with = "lib")]
    out: Option<PathBuf>,
}

impl BuildArgs {
    fn options(&self) -> BuildOptions {
        BuildOptions {
            release: self.release,
            package: self.package.clone(),
            locked: self.locked,
            compress: self.release && !self.lib && self.out.is_none(),
            base: self.base.clone(),
            ..BuildOptions::default()
        }
    }
}

fn main() -> ExitCode {
    if let Some(code) = doxa_build::hot::intercept() {
        return code;
    }
    let cli = Cli::parse();
    let result: Result<(), Box<dyn std::error::Error>> = match cli.command {
        Command::New { name } => std::env::current_dir()
            .map_err(Into::into)
            .and_then(|cwd| new::scaffold(&cwd, &name).map_err(Into::into)),
        Command::Build(args) => build(args.options(), args.lib, args.out.as_deref()),
        Command::BuildDev(args) => build_dev(&args),
        Command::Dev {
            package,
            port,
            locked,
            no_hot,
            no_tui,
            max_parallel_build,
            serial,
        } => {
            let max = serial.then_some(NonZeroUsize::MIN).or(max_parallel_build);
            tokio::runtime::Runtime::new()
                .map_err(Into::into)
                .and_then(|rt| rt.block_on(dev::run(package, port, locked, !no_hot, !no_tui, max)))
        }
        Command::Gallery {
            package,
            locked,
            base,
            out: Some(out),
            ..
        } => export(
            BuildOptions {
                release: true,
                package,
                locked,
                gallery: true,
                base,
                ..BuildOptions::default()
            },
            &out,
        ),
        Command::Gallery {
            package,
            port,
            locked,
            ..
        } => tokio::runtime::Runtime::new()
            .map_err(Into::into)
            .and_then(|rt| rt.block_on(dev::gallery(package, port, locked))),
        Command::Check { package, .. } => check::wire(&package),
        Command::Patch { command } => return patch::run(command),
        Command::Fmt { args } => return doxa_fmt::run(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn build(
    opts: BuildOptions,
    lib: bool,
    out: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(out) = out {
        return export(opts, out);
    }
    let mut pipeline = Pipeline::new(&std::env::current_dir()?, opts)?;
    let config = pipeline.cargo_config();
    check::one_copy(&pipeline.web.name, Some(check::TARGET), config)?;
    if let Some(server) = &pipeline.web.config.server {
        check::one_copy(server, None, config)?;
    }
    if lib {
        pipeline.build_library()?;
        return Ok(());
    }
    let _ = pipeline.build()?;
    if let Some(server) = pipeline.web.config.server.clone() {
        pipeline.build_server(&server)?;
    }
    Ok(())
}

/// Build the app or gallery, and write it to `out` as a static site.
fn export(opts: BuildOptions, out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut pipeline = Pipeline::new(&std::env::current_dir()?, opts)?;
    check::one_copy(
        &pipeline.web.name,
        Some(check::TARGET),
        pipeline.cargo_config(),
    )?;
    let _ = pipeline.build()?;
    doxa_build::dist::export(&pipeline.dist_dir(), out)?;
    eprintln!("wrote {}", out.display());
    Ok(())
}

/// `doxa build` with this workspace's dependencies patched to the local checkouts; or, without
/// a web crate, the `role = "server"` crate alone.
fn build_dev(args: &BuildArgs) -> Result<(), Box<dyn std::error::Error>> {
    let ws = Workspace::load(&std::env::current_dir()?)?;
    let locals = Locals::all(&ws)?;
    let patches = local::for_workspace(&ws.workspace_root, local::cargo(), &locals.refs())?;
    let mut opts = args.options();
    for a in &locals.absent {
        opts.output.note(a);
    }
    for p in &patches.patched {
        opts.output
            .note(format!("{} from {}", p.name, p.dir.display()));
    }
    for (name, source) in &patches.unpatchable {
        opts.output.note(format!(
            "{name} comes from {source}, which doxa can't patch; it builds without local edits"
        ));
    }
    let _lock = match patches.config.is_empty() {
        true => None,
        false => Some(HeldLock::take(&ws.workspace_root)?),
    };
    opts.cargo_config = patches.config;
    if args.package.is_some() || ws.has_client()? {
        return build(opts, args.lib, args.out.as_deref());
    }
    if args.lib || args.out.is_some() || args.base.is_some() {
        return Err("--lib, --out and --base need a web crate with role = \"client\"".into());
    }
    let server = ws.server_crate()?.name.clone();
    check::one_copy(&server, None, &opts.cargo_config)?;
    local::build_server(&ws, &server, &opts)?;
    Ok(())
}

/// A [`LockGuard`] that also restores the lockfile, then exits, on Ctrl-C or SIGTERM.
struct HeldLock(Arc<Mutex<Option<LockGuard>>>);

impl HeldLock {
    fn take(root: &Path) -> std::io::Result<HeldLock> {
        let held = Arc::new(Mutex::new(Some(LockGuard::take(root))));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        // Registered here, before the build starts, so a signal can't kill doxa first.
        let interrupted = {
            let _in = rt.enter();
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let (mut int, mut term) = (
                    signal(SignalKind::interrupt())?,
                    signal(SignalKind::terminate())?,
                );
                async move {
                    tokio::select! {
                        _ = int.recv() => {}
                        _ = term.recv() => {}
                    }
                }
            }
            #[cfg(not(unix))]
            {
                let mut int = tokio::signal::windows::ctrl_c()?;
                async move {
                    int.recv().await;
                }
            }
        };
        let restore = held.clone();
        std::thread::spawn(move || {
            rt.block_on(interrupted);
            drop(restore.lock().unwrap_or_else(|e| e.into_inner()).take());
            std::process::exit(130);
        });
        Ok(HeldLock(held))
    }
}

impl Drop for HeldLock {
    fn drop(&mut self) {
        drop(self.0.lock().unwrap_or_else(|e| e.into_inner()).take());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Command {
        Cli::try_parse_from(args).unwrap().command
    }

    #[test]
    fn build_flags() {
        assert!(matches!(
            parse(&["doxa", "build", "--release", "-p", "web", "--locked"]),
            Command::Build(BuildArgs { release: true, package: Some(p), locked: true, lib: false, .. }) if p == "web"
        ));
        assert!(matches!(
            parse(&["doxa", "build", "--base", "/docs/", "--out", "site"]),
            Command::Build(BuildArgs { base: Some(b), out: Some(o), .. }) if b == "/docs/" && o == Path::new("site")
        ));
        assert!(Cli::try_parse_from(["doxa", "build", "--lib", "--out", "s"]).is_err());
        assert!(matches!(
            parse(&["doxa", "build", "--lib"]),
            Command::Build(BuildArgs { lib: true, .. })
        ));
        assert!(matches!(
            parse(&["doxa", "build"]),
            Command::Build(BuildArgs {
                release: false,
                package: None,
                locked: false,
                lib: false,
                base: None,
                out: None,
            })
        ));
    }

    #[test]
    fn patch_passes_the_whole_command_through() {
        assert!(matches!(
            parse(&["doxa", "patch", "cargo", "test", "--release", "-p", "api"]),
            Command::Patch { command } if command == ["cargo", "test", "--release", "-p", "api"]
        ));
        assert!(Cli::try_parse_from(["doxa", "patch"]).is_err());
    }

    #[test]
    fn build_dev_takes_builds_flags() {
        assert!(matches!(
            parse(&["doxa", "build-dev", "--release", "-p", "web"]),
            Command::BuildDev(BuildArgs { release: true, package: Some(p), .. }) if p == "web"
        ));
        assert!(Cli::try_parse_from(["doxa", "build-dev", "--lib", "--out", "s"]).is_err());
    }

    #[test]
    fn dev_defaults_to_port_3000() {
        assert!(matches!(
            parse(&["doxa", "dev"]),
            Command::Dev { port: 3000, .. }
        ));
        assert!(matches!(
            parse(&["doxa", "dev", "--port", "8080", "--package", "w"]),
            Command::Dev { port: 8080, package: Some(p), no_hot: false, .. } if p == "w"
        ));
        assert!(matches!(
            parse(&["doxa", "dev", "--no-hot"]),
            Command::Dev {
                no_hot: true,
                no_tui: false,
                ..
            }
        ));
        assert!(matches!(
            parse(&["doxa", "dev", "--no-tui"]),
            Command::Dev { no_tui: true, .. }
        ));
        assert!(matches!(
            parse(&["doxa", "dev"]),
            Command::Dev {
                max_parallel_build: None,
                serial: false,
                ..
            }
        ));
        assert!(matches!(
            parse(&["doxa", "dev", "--max-parallel-build", "2"]),
            Command::Dev { max_parallel_build: Some(n), .. } if n.get() == 2
        ));
        assert!(matches!(
            parse(&["doxa", "dev", "--serial"]),
            Command::Dev { serial: true, .. }
        ));
        for bad in [
            &["doxa", "dev", "--max-parallel-build", "0"][..],
            &["doxa", "dev", "--serial", "--max-parallel-build", "2"],
        ] {
            assert!(Cli::try_parse_from(bad).is_err(), "{bad:?}");
        }
        assert!(matches!(
            parse(&["doxa", "gallery"]),
            Command::Gallery {
                port: 4710,
                out: None,
                ..
            }
        ));
        assert!(matches!(
            parse(&["doxa", "gallery", "--out", "g", "--base", "/doxa/gallery/"]),
            Command::Gallery {
                out: Some(_),
                base: Some(_),
                ..
            }
        ));
        assert!(Cli::try_parse_from(["doxa", "gallery", "--base", "/g/"]).is_err());
    }

    #[test]
    fn check_needs_wire_and_a_package() {
        assert!(matches!(
            parse(&["doxa", "check", "--wire", "-p", "api"]),
            Command::Check { wire: true, package } if package == "api"
        ));
        assert!(Cli::try_parse_from(["doxa", "check", "-p", "api"]).is_err());
        assert!(Cli::try_parse_from(["doxa", "check", "--wire"]).is_err());
    }

    #[test]
    fn new_takes_a_name_and_fmt_takes_anything() {
        assert!(matches!(parse(&["doxa", "new", "shop"]), Command::New { name } if name == "shop"));
        assert!(Cli::try_parse_from(["doxa", "new"]).is_err());
        assert!(matches!(
            parse(&["doxa", "fmt", "--stdin", "--edition", "2021"]),
            Command::Fmt { args } if args == ["--stdin", "--edition", "2021"]
        ));
    }
}
