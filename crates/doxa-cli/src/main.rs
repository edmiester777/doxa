//! `doxa`: scaffold, build, and develop a doxa app.

mod dev;
mod new;

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
    /// Create a new app: api, client, server, and web crates.
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
    },
    /// Build, run the server, and rebuild and reload on change.
    Dev {
        /// The web crate; defaults to the one with role = "client".
        #[arg(short, long)]
        package: Option<String>,
        /// The port to serve on.
        #[arg(long, default_value_t = 3000)]
        port: u16,
        /// Install npm dependencies from the lockfile only.
        #[arg(long)]
        locked: bool,
    },
    /// Format Rust sources, including view markup.
    Fmt {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        args: Vec<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result: Result<(), Box<dyn std::error::Error>> = match cli.command {
        Command::New { name } => std::env::current_dir()
            .map_err(Into::into)
            .and_then(|cwd| new::scaffold(&cwd, &name).map_err(Into::into)),
        Command::Build {
            release,
            package,
            locked,
        } => build(BuildOptions {
            release,
            package,
            locked,
            compress: true,
        }),
        Command::Dev {
            package,
            port,
            locked,
        } => tokio::runtime::Runtime::new()
            .map_err(Into::into)
            .and_then(|rt| rt.block_on(dev::run(package, port, locked))),
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

fn build(opts: BuildOptions) -> Result<(), Box<dyn std::error::Error>> {
    let mut pipeline = Pipeline::new(&std::env::current_dir()?, opts)?;
    let _ = pipeline.build()?;
    if let Some(server) = pipeline.web.config.server.clone() {
        pipeline.build_server(&server)?;
    }
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
            Command::Build { release: true, package: Some(p), locked: true } if p == "web"
        ));
        assert!(matches!(
            parse(&["doxa", "build"]),
            Command::Build {
                release: false,
                package: None,
                locked: false
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
            Command::Dev { port: 8080, package: Some(p), .. } if p == "w"
        ));
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
