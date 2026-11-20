//! Each child's output, a whole line at a time, behind a `[name]` tag.

use std::io::{IsTerminal, Write};

use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

const COLORS: [u8; 6] = [36, 35, 33, 32, 34, 31];

/// Whether stderr takes ANSI colour.
pub fn color() -> bool {
    std::io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

#[derive(Debug, Clone)]
pub struct Tag(String);

impl Tag {
    /// `name` padded to `width`, coloured by `index` when stderr takes colour.
    pub fn new(name: &str, index: usize, width: usize) -> Tag {
        Tag::styled(name, index, width, color())
    }

    fn styled(name: &str, index: usize, width: usize, color: bool) -> Tag {
        Tag(match color {
            true => format!(
                "\x1b[{}m[{name:<width$}]\x1b[0m",
                COLORS[index % COLORS.len()]
            ),
            false => format!("[{name:<width$}]"),
        })
    }

    fn render(&self, msg: impl std::fmt::Display) -> String {
        format!("{} {msg}", self.0)
    }

    pub fn line(&self, msg: impl std::fmt::Display) {
        // The lock keeps lines from different children whole.
        let _ = writeln!(std::io::stderr().lock(), "{}", self.render(msg));
    }
}

/// Copy `from` to stderr line by line until it closes; invalid UTF-8 is replaced, not fatal.
pub fn pipe(tag: Tag, from: impl AsyncRead + Unpin + Send + 'static) {
    tokio::spawn(lines(from, move |l| tag.line(l)));
}

async fn lines(from: impl AsyncRead + Unpin, mut each: impl FnMut(&str)) {
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
        assert_eq!(Tag::styled("api", 0, 6, false).render("up"), "[api   ] up");
        assert_eq!(
            Tag::styled("api", 1, 3, true).render("up"),
            "\x1b[35m[api]\x1b[0m up"
        );
    }

    #[tokio::test]
    async fn invalid_utf8_is_replaced_and_reading_goes_on() {
        let input: &[u8] = b"one\r\n\xff two\nthree";
        let mut seen = Vec::new();
        lines(input, |l| seen.push(l.to_owned())).await;
        assert_eq!(seen, ["one", "\u{fffd} two", "three"]);
    }
}
