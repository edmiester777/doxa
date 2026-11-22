//! `doxa dev --<target>`: Tauri's `dev` beside the dev server, its window opening the page.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use doxa_role::Target;
use tokio::process::{Child, Command};
use tokio::sync::watch as signal;

use super::log::{self, Tag};
use super::tui::Status;
use crate::native;

/// Runs the shell, opening the dev server on `port`, until `doxa dev` stops; quitting the app
/// stops `doxa dev`.
pub async fn run(
    dir: PathBuf,
    port: u16,
    target: Target,
    tag: Tag,
    mut stop: signal::Receiver<u32>,
    stops: signal::Sender<u32>,
) {
    tag.status(Status::Compiling);
    tag.note(format!(
        "running the native app with Tauri {} (https://tauri.app)",
        native::tauri::version()
    ));
    let env = [(doxa_role::TARGET_ENV, target.as_str().into())];
    let url = format!("http://127.0.0.1:{port}/");
    let spawned = native::tauri::command(&dir, &native::dev_args(&url), &env).and_then(|c| {
        let mut c = Command::from(c);
        // Its own group, so stopping reaches the app too: Tauri's `dev` doesn't pass signals on.
        #[cfg(unix)]
        c.process_group(0);
        c.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
    });
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            tag.line(format!("error: starting `doxa tauri dev`: {e}"));
            tag.status(Status::Exited);
            return;
        }
    };
    for from in [
        Box::new(child.stdout.take().expect("piped"))
            as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        Box::new(child.stderr.take().expect("piped")),
    ] {
        let tag = tag.clone();
        tokio::spawn(log::lines(from, move |l| {
            let Some(l) = doxa_build::settled(l) else {
                return;
            };
            // Cargo's line as it starts the app.
            if doxa_build::plain(l).trim_start().starts_with("Running `") {
                tag.status(Status::Running(port));
            }
            tag.line(l);
        }));
    }
    tokio::select! {
        _ = stop.changed() => {
            tag.status(Status::Stopping);
            interrupt(&mut child).await;
            tag.status(Status::Stopped);
        }
        status = child.wait() => {
            match status {
                Ok(s) => tag.line(format!("exited with {s}; stopping doxa dev")),
                Err(e) => tag.line(format!("error: waiting for `doxa tauri dev`: {e}")),
            }
            tag.status(Status::Exited);
            stops.send_modify(|n| *n += 1);
        }
    }
}

/// SIGINT to Tauri's group, as a terminal's Ctrl-C would send; SIGKILL after 10 s.
async fn interrupt(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id().and_then(|p| libc::pid_t::try_from(p).ok()) {
        // SAFETY: `id()` is `None` once tokio has reaped the child, so the group is still ours.
        unsafe { libc::kill(-pid, libc::SIGINT) };
        let waited = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
        // SAFETY: the app may outlive the CLI; while it does, its group keeps the id from reuse.
        unsafe {
            libc::kill(
                -pid,
                if waited.is_ok() {
                    libc::SIGTERM
                } else {
                    libc::SIGKILL
                },
            )
        };
        if waited.is_ok() {
            return;
        }
    }
    let _ = child.kill().await;
}
