//! Where a build's notes and its tools' output go.

use std::fmt;
use std::io::{BufRead, BufReader, Read};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;

use crate::error::{Error, Result};

/// Where a build's notes and its tools' output go: the terminal by default, or a callback a
/// line at a time.
#[derive(Clone, Default)]
pub struct Output(Option<Sink>);

#[derive(Clone)]
struct Sink {
    each: Arc<dyn Fn(&str) + Send + Sync>,
    ansi: bool,
}

impl Output {
    /// Each line to `each`, tools' stdin closed; `ansi` keeps cargo's colour though it is piped.
    pub fn lines(ansi: bool, each: impl Fn(&str) + Send + Sync + 'static) -> Output {
        Output(Some(Sink {
            each: Arc::new(each),
            ansi,
        }))
    }

    /// A progress line, `[doxa] msg`.
    pub fn note(&self, msg: impl fmt::Display) {
        self.tagged("doxa", msg);
    }

    /// A line another tool wrote, `[tag] msg`, so its output is credited to it.
    pub fn tagged(&self, tag: &str, msg: impl fmt::Display) {
        self.line(&format!("[{tag}] {msg}"));
    }

    /// Run `command` with each line it and its children write tagged `[tag]`.
    pub fn run_tagged(&self, tag: &str, command: &mut Command) -> std::io::Result<ExitStatus> {
        let out = self.clone();
        let tag = tag.to_owned();
        Sink {
            each: Arc::new(move |l: &str| {
                if let Some(l) = settled(l) {
                    out.tagged(&tag, l)
                }
            }),
            ansi: self.0.as_ref().map_or_else(stderr_is_terminal, |s| s.ansi),
        }
        .pipe(command)
    }
}

/// What a line says once a progress bar's redraws (`\r`, erase-line) are dropped; `None` when
/// it was only the bar. Tauri runs cargo with its progress bar forced on.
pub fn settled(line: &str) -> Option<&str> {
    let last = [
        line.rfind('\r').map(|i| i + 1),
        line.rfind("\x1b[K").map(|i| i + 3),
    ]
    .into_iter()
    .flatten()
    .max()
    .unwrap_or(0);
    let rest = &line[last..];
    let bare = plain(rest);
    let bar = bare.trim_start().starts_with("Building [");
    (!bare.trim().is_empty() && !bar).then_some(rest)
}

/// `s` without its ANSI escape sequences.
pub fn plain(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        if chars.next() == Some('[') {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        }
    }
    out
}

impl Output {
    pub(crate) fn line(&self, line: &str) {
        match &self.0 {
            Some(s) => (s.each)(line),
            None => eprintln!("{line}"),
        }
    }

    /// Text that carries its own newlines, such as a rendered diagnostic.
    pub(crate) fn text(&self, text: &str) {
        match &self.0 {
            Some(s) => text.lines().for_each(|l| (s.each)(l)),
            None => eprint!("{text}"),
        }
    }

    /// Run `command`, failing with a [`Error::Tool`] that names `tool` and `fix`.
    pub(crate) fn run(&self, tool: &'static str, command: &mut Command, fix: &str) -> Result<()> {
        let status = match &self.0 {
            Some(s) => s.pipe(command),
            None => command.status(),
        }
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
}

impl Sink {
    fn pipe(&self, command: &mut Command) -> std::io::Result<ExitStatus> {
        if self.ansi && std::env::var_os("CARGO_TERM_COLOR").is_none() {
            command.env("CARGO_TERM_COLOR", "always");
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stderr = child.stderr.take().expect("piped");
        let each = self.each.clone();
        let errs = std::thread::spawn(move || forward(stderr, &*each));
        forward(child.stdout.take().expect("piped"), &*self.each);
        let _ = errs.join();
        child.wait()
    }
}

fn stderr_is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stderr().is_terminal()
}

/// Whole lines until `from` closes; invalid UTF-8 is replaced, not fatal.
fn forward(from: impl Read, each: &dyn Fn(&str)) {
    let mut from = BufReader::new(from);
    let mut buf = Vec::new();
    while from.read_until(b'\n', &mut buf).is_ok_and(|n| n > 0) {
        each(String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']));
        buf.clear();
    }
}

impl fmt::Debug for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            Some(_) => "Output::lines",
            None => "Output::stderr",
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn a_progress_bar_is_dropped_and_what_follows_it_kept() {
        let bar = "\x1b[1m\x1b[96m    Building\x1b[0m [==>  ] 741/746: doxa";
        assert_eq!(settled(bar), None);
        let then = format!("{bar}\x1b[K\x1b[1m\x1b[92m   Compiling\x1b[0m shop-api");
        assert_eq!(
            settled(&then),
            Some("\x1b[1m\x1b[92m   Compiling\x1b[0m shop-api")
        );
        assert_eq!(settled("plain\rredrawn"), Some("redrawn"));
        assert_eq!(settled("  Finished `dev`"), Some("  Finished `dev`"));
        assert_eq!(settled("\x1b[K"), None);
    }

    #[test]
    fn a_sink_gets_both_streams_and_the_exit_status_still_counts() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let out = Output::lines(false, {
            let seen = seen.clone();
            move |l| seen.lock().unwrap().push(l.to_owned())
        });
        let mut ok = Command::new("sh");
        ok.args(["-c", "echo out; echo err >&2"]);
        out.run("sh", &mut ok, "").unwrap();
        out.note("done");
        let mut seen_now = seen.lock().unwrap().clone();
        seen_now.sort();
        assert_eq!(seen_now, ["[doxa] done", "err", "out"]);

        let mut bad = Command::new("sh");
        bad.args(["-c", "exit 3"]);
        assert!(out.run("sh", &mut bad, "").is_err());
    }

    #[test]
    fn a_tagged_run_credits_every_line_to_its_tool() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let out = Output::lines(false, {
            let seen = seen.clone();
            move |l| seen.lock().unwrap().push(l.to_owned())
        });
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo built; sh -c 'echo child >&2'; exit 2"]);
        let status = out.run_tagged("tauri", &mut cmd).unwrap();
        assert_eq!(status.code(), Some(2));
        let mut seen_now = seen.lock().unwrap().clone();
        seen_now.sort();
        assert_eq!(seen_now, ["[tauri] built", "[tauri] child"]);
    }
}
