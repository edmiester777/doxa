//! `doxa`: scaffold, build, and develop a doxa app.

mod check;
mod dev;
mod new;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use doxa_build::{BuildOptions, Pipeline};

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
    Build {
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
    },
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
    /// Format Rust sources, including view markup.
    Fmt {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        args: Vec<String>,
    },
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
        Command::Build {
            release,
            package,
            locked,
            lib,
            base,
            out,
        } => build(
            BuildOptions {
                release,
                package,
                locked,
                compress: !lib && out.is_none(),
                base,
                ..BuildOptions::default()
            },
            lib,
            out.as_deref(),
        ),
        Command::Dev {
            package,
            port,
            locked,
            no_hot,
        } => tokio::runtime::Runtime::new()
            .map_err(Into::into)
            .and_then(|rt| rt.block_on(dev::run(package, port, locked, !no_hot))),
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
    check::one_copy(&pipeline.web.name, Some(check::TARGET))?;
    if let Some(server) = &pipeline.web.config.server {
        check::one_copy(server, None)?;
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
    check::one_copy(&pipeline.web.name, Some(check::TARGET))?;
    let _ = pipeline.build()?;
    doxa_build::dist::export(&pipeline.dist_dir(), out)?;
    eprintln!("wrote {}", out.display());
    Ok(())
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
            Command::Build { release: true, package: Some(p), locked: true, lib: false, .. } if p == "web"
        ));
        assert!(matches!(
            parse(&["doxa", "build", "--base", "/docs/", "--out", "site"]),
            Command::Build { base: Some(b), out: Some(o), .. } if b == "/docs/" && o == Path::new("site")
        ));
        assert!(Cli::try_parse_from(["doxa", "build", "--lib", "--out", "s"]).is_err());
        assert!(matches!(
            parse(&["doxa", "build", "--lib"]),
            Command::Build { lib: true, .. }
        ));
        assert!(matches!(
            parse(&["doxa", "build"]),
            Command::Build {
                release: false,
                package: None,
                locked: false,
                lib: false,
                base: None,
                out: None,
            }
        ));
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
            Command::Dev { no_hot: true, .. }
        ));
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
