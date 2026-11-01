use std::path::{Path, PathBuf};
use std::process::Command;

/// What went wrong in a build step.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An external tool ran and failed, or could not be started.
    #[error("{tool} failed\n  command: {command}\n  {detail}\n  fix: {fix}")]
    Tool {
        /// The tool's name, e.g. `esbuild`.
        tool: &'static str,
        /// The command line that was run.
        command: String,
        /// What the tool said, or why it could not start.
        detail: String,
        /// What the user can do about it.
        fix: String,
    },
    /// The app's configuration is missing or inconsistent.
    #[error("{message}\n  fix: {fix}")]
    Config {
        /// What is wrong.
        message: String,
        /// What the user can do about it.
        fix: String,
    },
    /// The app's `wasm-bindgen` is not the version this build links.
    #[error(
        "wasm-bindgen version mismatch: Cargo.lock has {locked}, doxa-build uses {expected}\n  \
         fix: cargo update -p wasm-bindgen --precise {expected}"
    )]
    WasmBindgenMismatch {
        /// The version in the app's Cargo.lock.
        locked: String,
        /// The version doxa-build is pinned to.
        expected: &'static str,
    },
    /// A download failed or did not verify.
    #[error("downloading {what} from {url} failed: {detail}\n  fix: {fix}")]
    Download {
        /// What was being downloaded.
        what: String,
        /// Where from.
        url: String,
        /// Why it failed.
        detail: String,
        /// What the user can do about it.
        fix: String,
    },
    /// A filesystem operation failed.
    #[error("{path}: {source}")]
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
}

/// `Result` with [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub(crate) fn config(message: impl Into<String>, fix: impl Into<String>) -> Self {
        Error::Config {
            message: message.into(),
            fix: fix.into(),
        }
    }

    pub(crate) fn tool(
        tool: &'static str,
        command: &Command,
        detail: impl Into<String>,
        fix: impl Into<String>,
    ) -> Self {
        Error::Tool {
            tool,
            command: display_command(command),
            detail: detail.into(),
            fix: fix.into(),
        }
    }
}

/// Attach a path to an `io::Result`.
pub(crate) trait IoContext<T> {
    fn at(self, path: &Path) -> Result<T>;
}

impl<T> IoContext<T> for std::io::Result<T> {
    fn at(self, path: &Path) -> Result<T> {
        self.map_err(|source| Error::Io {
            path: path.to_owned(),
            source,
        })
    }
}

pub(crate) fn display_command(command: &Command) -> String {
    let mut out = command.get_program().to_string_lossy().into_owned();
    for arg in command.get_args() {
        out.push(' ');
        out.push_str(&arg.to_string_lossy());
    }
    out
}

/// Run `command`, failing with a [`Error::Tool`] that names `tool` and `fix`.
pub(crate) fn run(tool: &'static str, command: &mut Command, fix: &str) -> Result<()> {
    let status = command
        .status()
        .map_err(|e| Error::tool(tool, command, format!("could not start: {e}"), fix))?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::tool(
            tool,
            command,
            format!("exited with {status}"),
            fix,
        ))
    }
}
