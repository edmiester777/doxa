//! Each child's output, a whole line at a time: behind a `[name]` tag, or in its TUI pane.

use std::fmt::Display;
use std::io::{IsTerminal, Write};
use std::sync::Arc;

use doxa_build::Output;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::sync::{mpsc, watch};

use super::tui::{Pane, Shared, Status};

const COLORS: [u8; 6] = [36, 35, 33, 32, 34, 31];

/// Whether stderr takes ANSI colour.
pub fn color() -> bool {
    std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

/// Where `doxa dev` writes.
#[derive(Clone)]
pub enum Console {
    Stderr,
    Tui(Arc<Shared>),
}

impl Console {
    /// A dev service's tag, padded to `width` on stderr; its pane goes above the web crate's.
    pub fn tag(&self, name: &str, index: usize, width: usize) -> Tag {
        match self {
            Console::Stderr => Tag(Inner::Stderr(styled(name, index, width, color()))),
            Console::Tui(s) => Tag(Inner::Pane(s.add(name, false))),
        }
    }

    /// The in-workspace server's tag; its pane goes below the web crate's.
    pub fn server_tag(&self, name: &str, index: usize, width: usize) -> Tag {
        match self {
            Console::Stderr => self.tag(name, index, width),
            Console::Tui(s) => Tag(Inner::Pane(s.add(name, true))),
        }
    }

    /// The web crate's build, and doxa's own notes.
    pub fn web(&self) -> Tag {
        match self {
            Console::Stderr => Tag(Inner::Stderr(String::new())),
            Console::Tui(s) => Tag(Inner::Pane(s.web())),
        }
    }

    /// Where the web crate's pipeline writes.
    pub fn output(&self) -> Output {
        match self {
            Console::Stderr => Output::default(),
            Console::Tui(_) => {
                let web = self.web();
                Output::lines(true, move |l| web.line(l))
            }
        }
    }

    /// The URLs served, for the TUI's header.
    pub fn header(&self, urls: Vec<String>) {
        if let Console::Tui(s) = self {
            s.lock().header = urls;
        }
    }

    /// Lets the TUI's `q` stop `doxa dev` as Ctrl-C would.
    pub fn stops(&self, stop: watch::Sender<u32>) {
        if let Console::Tui(s) = self {
            s.lock().stop = Some(stop);
        }
    }
}

#[derive(Clone)]
pub struct Tag(Inner);

#[derive(Clone)]
enum Inner {
    /// The coloured `[name]`, or empty for doxa's own lines.
    Stderr(String),
    Pane(Pane),
}

fn styled(name: &str, index: usize, width: usize, color: bool) -> String {
    match color {
        true => format!(
            "\x1b[{}m[{name:<width$}]\x1b[0m",
            COLORS[index % COLORS.len()]
        ),
        false => format!("[{name:<width$}]"),
    }
}

fn render(tag: &str, msg: impl Display) -> String {
    match tag.is_empty() {
        true => msg.to_string(),
        false => format!("{tag} {msg}"),
    }
}

impl Tag {
    pub fn line(&self, msg: impl Display) {
        match &self.0 {
            // The lock keeps lines from different children whole.
            Inner::Stderr(tag) => {
                let _ = writeln!(std::io::stderr().lock(), "{}", render(tag, msg));
            }
            Inner::Pane(p) => p.line(&msg.to_string()),
        }
    }

    /// A progress line, `[doxa] msg`.
    pub fn note(&self, msg: impl Display) {
        self.line(format_args!("[doxa] {msg}"));
    }

    /// Shown in the pane's title; the lines already say it on stderr.
    pub fn status(&self, status: Status) {
        if let Inner::Pane(p) = &self.0 {
            p.status(status);
        }
    }

    pub fn rename(&self, name: &str) {
        if let Inner::Pane(p) = &self.0 {
            p.rename(name);
        }
    }

    /// Where the TUI's `r` sends a forced rebuild.
    pub fn kicks(&self, tx: &mpsc::UnboundedSender<bool>) {
        if let Inner::Pane(p) = &self.0 {
            p.kicks(tx.clone());
        }
    }
}

/// Copy `from` to the tag line by line until it closes; invalid UTF-8 is replaced, not fatal.
pub fn pipe(tag: Tag, from: impl AsyncRead + Unpin + Send + 'static) {
    tokio::spawn(lines(from, move |l| tag.line(l)));
}

pub async fn lines(from: impl AsyncRead + Unpin, mut each: impl FnMut(&str)) {
    let mut from = BufReader::new(from);
    let mut buf = Vec::new();
    while from.read_until(b'\n', &mut buf).await.is_ok_and(|n| n > 0) {
        each(String::from_utf8_lossy(&buf).trim_end_matches(['\r', '\n']));
        buf.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_pads_to_the_widest_name_and_colours_only_when_asked() {
        assert_eq!(render(&styled("api", 0, 6, false), "up"), "[api   ] up");
        assert_eq!(
            render(&styled("api", 1, 3, true), "up"),
            "\x1b[35m[api]\x1b[0m up"
        );
        assert_eq!(render("", "[doxa] up"), "[doxa] up");
    }

    #[tokio::test]
    async fn invalid_utf8_is_replaced_and_reading_goes_on() {
        let input: &[u8] = b"one\r\n\xff two\nthree";
        let mut seen = Vec::new();
        lines(input, |l| seen.push(l.to_owned())).await;
        assert_eq!(seen, ["one", "\u{fffd} two", "three"]);
    }
}
