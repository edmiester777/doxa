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
        self.line(&format!("[doxa] {msg}"));
    }

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
}
