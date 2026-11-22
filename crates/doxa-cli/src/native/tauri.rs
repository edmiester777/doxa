//! The Tauri CLI, linked in: `doxa tauri <args>` runs it, and doxa runs that as a child so every
//! line it and its cargo, Gradle and Xcode runs write is tagged `[tauri]`.

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, ExitCode};

use doxa_build::Output;

/// `doxa tauri <args>`. The Xcode and Gradle projects Tauri generates call back into this.
pub fn passthrough(args: Vec<OsString>) -> ExitCode {
    tauri_cli::run(args, Some("doxa tauri".into()));
    ExitCode::SUCCESS
}

/// The linked Tauri CLI's version, as `doxa tauri --version` prints it.
pub fn version() -> String {
    let out = std::env::current_exe()
        .and_then(|exe| Command::new(exe).args(["tauri", "--version"]).output());
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .split_whitespace()
            .last()
            .unwrap_or("2")
            .to_owned(),
        Err(_) => "2".into(),
    }
}

/// Runs `doxa tauri <args>` for the app at `dir`, its output tagged. `env` is set on the child,
/// which cargo inherits.
pub fn run(
    dir: &Path,
    args: &[OsString],
    env: &[(&str, OsString)],
    out: &Output,
) -> Result<(), Box<dyn std::error::Error>> {
    let status = out.run_tagged("tauri", &mut command(dir, args, env)?)?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`doxa tauri {}` exited with {status}", display(args)).into())
    }
}

/// `doxa tauri <args>` for the app at `dir`, not yet started.
pub fn command(
    dir: &Path,
    args: &[OsString],
    env: &[(&str, OsString)],
) -> std::io::Result<Command> {
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg("tauri")
        .args(args)
        .current_dir(dir)
        .env("TAURI_APP_PATH", dir);
    for k in doxa_build::hot::ENV {
        cmd.env_remove(k);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    Ok(cmd)
}

pub fn display(args: &[OsString]) -> String {
    args.iter()
        .map(|a| a.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
}
