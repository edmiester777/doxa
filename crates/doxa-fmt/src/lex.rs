use std::ops::Range;

pub(crate) struct Comment {
    pub range: Range<usize>,
    pub line: bool,
}

/// Finds `//` and `/* */` comments, skipping string, raw string and char literals.
pub(crate) fn comments(text: &str) -> Vec<Comment> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                let end = text[i..].find('\n').map_or(b.len(), |n| i + n);
                out.push(Comment {
                    range: i..end,
                    line: true,
                });
                i = end;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let mut depth = 1;
                let mut j = i + 2;
                while j < b.len() && depth > 0 {
                    if b[j] == b'/' && b.get(j + 1) == Some(&b'*') {
                        depth += 1;
                        j += 2;
                    } else if b[j] == b'*' && b.get(j + 1) == Some(&b'/') {
                        depth -= 1;
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                out.push(Comment {
                    range: i..j,
                    line: false,
                });
                i = j;
            }
            b'"' => i = skip_str(b, i + 1),
            b'r' if raw_prefix_ok(b, i) => i = skip_raw(b, i),
            b'\'' => i = skip_char(text, i),
            _ => i += 1,
        }
    }
    out
}

fn is_ident(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c >= 0x80
}

fn skip_str(b: &[u8], mut i: usize) -> usize {
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    b.len()
}

fn raw_prefix_ok(b: &[u8], i: usize) -> bool {
    let ident_start = match i.checked_sub(1).map(|p| b[p]) {
        None => true,
        Some(p) if !is_ident(p) => true,
        Some(b'b' | b'c') => i < 2 || !is_ident(b[i - 2]),
        _ => false,
    };
    let mut j = i + 1;
    while b.get(j) == Some(&b'#') {
        j += 1;
    }
    ident_start && b.get(j) == Some(&b'"')
}

fn skip_raw(b: &[u8], i: usize) -> usize {
    let mut j = i + 1;
    let mut hashes = 0;
    while b[j] == b'#' {
        hashes += 1;
        j += 1;
    }
    j += 1;
    while j < b.len() {
        if b[j] == b'"'
            && b[j + 1..]
                .iter()
                .take(hashes)
                .filter(|&&c| c == b'#')
                .count()
                == hashes
        {
            return j + 1 + hashes;
        }
        j += 1;
    }
    b.len()
}

/// Skips a char literal, or just the quote of a lifetime.
fn skip_char(text: &str, i: usize) -> usize {
    let b = text.as_bytes();
    if b.get(i + 1) == Some(&b'\\') {
        return text[i + 2..].find('\'').map_or(b.len(), |n| i + 2 + n + 1);
    }
    match text[i + 1..].chars().next() {
        Some(c) if b.get(i + 1 + c.len_utf8()) == Some(&b'\'') => i + 2 + c.len_utf8(),
        _ => i + 1,
    }
}

#[cfg(test)]
mod tests {
    use super::comments;

    #[test]
    fn skips_literals() {
        let src = r##"a("// no", r#"/* no */"#, '"', 'a) // yes
/* yes /* nested */ */"##;
        let found: Vec<_> = comments(src)
            .iter()
            .map(|c| &src[c.range.clone()])
            .collect();
        assert_eq!(found, ["// yes", "/* yes /* nested */ */"]);
    }
}
