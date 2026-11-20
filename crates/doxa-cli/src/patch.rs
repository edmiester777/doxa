//! `doxa patch <command>`: run any command with the workspace patched to its local checkouts.

use std::process::{ExitCode, ExitStatus};

use doxa_build::config::Workspace;
use doxa_build::local::{self, ConfigGuard, Locals, LockGuard};

/// Run `command` with the patches in `.cargo/config.toml`, then put it and `Cargo.lock` back;
/// exits as the command did.
pub fn run(command: Vec<String>) -> ExitCode {
    match patched(&command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn patched(command: &[String]) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let ws = Workspace::load(&std::env::current_dir()?)?;
    let locals = Locals::all(&ws)?;
    let patches = local::for_workspace(&ws.workspace_root, local::cargo(), &locals.refs())?;
    for a in &locals.absent {
        eprintln!("[doxa] {a}");
    }
    for p in &patches.patched {
        eprintln!("[doxa] {} from {}", p.name, p.dir.display());
    }
    for (name, source) in &patches.unpatchable {
        eprintln!(
            "[doxa] {name} comes from {source}, which doxa can't patch; it builds without local edits"
        );
    }
    // Dropped in reverse, after the command and its children exit.
    let _guards = match patches.patched.is_empty() {
        true => None,
        false => Some((
            LockGuard::take(&ws.workspace_root),
            ConfigGuard::write(&ws.workspace_root, &patches.patched)?,
        )),
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let status = rt.block_on(supervise(command))?;
    Ok(exit_code(status))
}

/// Wait for `command`, outliving Ctrl-C (the terminal sends it to the command as well) and
/// passing SIGTERM on as a kill.
async fn supervise(command: &[String]) -> Result<ExitStatus, Box<dyn std::error::Error>> {
    let (program, args) = command.split_first().ok_or("no command to run")?;
    #[cfg(unix)]
    let (mut int, mut term) = {
        use tokio::signal::unix::{signal, SignalKind};
        (
            signal(SignalKind::interrupt())?,
            signal(SignalKind::terminate())?,
        )
    };
    #[cfg(not(unix))]
    let mut int = tokio::signal::windows::ctrl_c()?;
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .spawn()
        .map_err(|e| format!("could not run `{program}`: {e}"))?;
    loop {
        #[cfg(unix)]
        tokio::select! {
            status = child.wait() => return Ok(status?),
            _ = int.recv() => {}
            _ = term.recv() => child.start_kill()?,
        }
        #[cfg(not(unix))]
        tokio::select! {
            status = child.wait() => return Ok(status?),
            _ = int.recv() => {}
        }
    }
}

fn exit_code(status: ExitStatus) -> ExitCode {
    if let Some(code) = status.code() {
        return ExitCode::from(code as u8);
    }
    #[cfg(unix)]
    if let Some(signal) = std::os::unix::process::ExitStatusExt::signal(&status) {
        return ExitCode::from(128u8.wrapping_add(signal as u8));
    }
    ExitCode::FAILURE
}
