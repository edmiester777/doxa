//! Rust source split into lines of classed tokens, for the gallery's source panel.

/// One run of text and the class it is drawn with, if any.
pub(crate) type Token = (Option<&'static str>, String);

const KEYWORDS: [&str; 39] = [
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub",
    "ref", "return", "self", "Self", "static", "struct", "super", "trait", "true", "type",
    "unsafe", "use", "where", "while", "yield",
];

/// `src` as lines of tokens; a token spanning lines is cut at each newline.
pub(crate) fn highlight(src: &str) -> Vec<Vec<Token>> {
    let c: Vec<char> = src.chars().collect();
    let mut lines = vec![Vec::new()];
    let mut i = 0;
    while i < c.len() {
        let start = i;
        let at = |j: usize| c.get(j).copied().unwrap_or('\0');
        let class = match c[i] {
            '/' if at(i + 1) == '/' => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
                Some("t-com")
            }
            '/' if at(i + 1) == '*' => {
                i += 2;
                while i < c.len() && !(c[i] == '*' && at(i + 1) == '/') {
                    i += 1;
                }
                i = (i + 2).min(c.len());
                Some("t-com")
            }
            'r' | 'b' if raw_string(&c, i).is_some() => {
                i = raw_string(&c, i).unwrap_or(i + 1);
                Some("t-str")
            }
            'b' if at(i + 1) == '"' => {
                i = string(&c, i + 1);
                Some("t-str")
            }
            '"' => {
                i = string(&c, i);
                Some("t-str")
            }
            '\'' if at(i + 1) == '\\' => {
                i += 2;
                while i < c.len() && c[i] != '\'' {
                    i += 1;
                }
                i = (i + 1).min(c.len());
                Some("t-str")
            }
            '\'' if at(i + 2) == '\'' => {
                i += 3;
                Some("t-str")
            }
            '\'' if is_ident_start(at(i + 1)) => {
                i += 1;
                while i < c.len() && is_ident(c[i]) {
                    i += 1;
                }
                Some("t-life")
            }
            '#' if at(i + 1) == '[' || (at(i + 1) == '!' && at(i + 2) == '[') => {
                let mut depth = 0;
                while i < c.len() {
                    match c[i] {
                        '[' => depth += 1,
                        ']' => {
                            depth -= 1;
                            if depth == 0 {
                                i += 1;
                                break;
                            }
                        }
                        '\n' => break,
                        _ => {}
                    }
                    i += 1;
                }
                Some("t-attr")
            }
            d if d.is_ascii_digit() => {
                while i < c.len() && (is_ident(c[i]) || (c[i] == '.' && at(i + 1).is_ascii_digit()))
                {
                    i += 1;
                }
                Some("t-num")
            }
            s if is_ident_start(s) => {
                while i < c.len() && is_ident(c[i]) {
                    i += 1;
                }
                let word: String = c[start..i].iter().collect();
                if at(i) == '!' && at(i + 1) != '=' {
                    i += 1;
                    Some("t-mac")
                } else if KEYWORDS.contains(&word.as_str()) {
                    Some("t-kw")
                } else if word.starts_with(|ch: char| ch.is_ascii_uppercase()) {
                    Some("t-ty")
                } else {
                    None
                }
            }
            _ => {
                i += 1;
                None
            }
        };
        push(&mut lines, class, c[start..i].iter().collect());
    }
    lines
}

fn push(lines: &mut Vec<Vec<Token>>, class: Option<&'static str>, text: String) {
    for (n, part) in text.split('\n').enumerate() {
        if n > 0 {
            lines.push(Vec::new());
        }
        if part.is_empty() {
            continue;
        }
        let line = lines.last_mut().expect("one line at least");
        match line.last_mut() {
            Some((prev, run)) if *prev == class => run.push_str(part),
            _ => line.push((class, part.to_owned())),
        }
    }
}

fn is_ident_start(c: char) -> bool {
    c.is_alphabetic() || c == '_'
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The end of the `"…"` starting at `i`.
fn string(c: &[char], mut i: usize) -> usize {
    i += 1;
    while i < c.len() && c[i] != '"' {
        i += if c[i] == '\\' { 2 } else { 1 };
    }
    (i + 1).min(c.len())
}

/// The end of the `r#"…"#` (or `br…`) starting at `i`, if one starts there.
fn raw_string(c: &[char], i: usize) -> Option<usize> {
    let mut j = i + usize::from(c[i] == 'b');
    if c.get(j) != Some(&'r') {
        return None;
    }
    j += 1;
    let hashes = c[j..].iter().take_while(|&&ch| ch == '#').count();
    j += hashes;
    if c.get(j) != Some(&'"') {
        return None;
    }
    j += 1;
    while j < c.len() {
        if c[j] == '"'
            && c[j + 1..]
                .iter()
                .take(hashes)
                .filter(|&&ch| ch == '#')
                .count()
                == hashes
        {
            return Some(j + 1 + hashes);
        }
        j += 1;
    }
    Some(c.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes(src: &str) -> Vec<(Option<&'static str>, String)> {
        highlight(src).into_iter().flatten().collect()
    }

    #[test]
    fn rust_tokens_get_their_classes() {
        let got = classes("pub fn a<'x>(n: u8) -> Vec<char> { vec!['}', \"{\"]; 1_000 }");
        let class_of = |text: &str| got.iter().find(|(_, t)| t == text).map(|(c, _)| *c);
        assert_eq!(class_of("pub"), Some(Some("t-kw")));
        assert_eq!(class_of("'x"), Some(Some("t-life")));
        assert_eq!(class_of("Vec"), Some(Some("t-ty")));
        assert_eq!(class_of("vec!"), Some(Some("t-mac")));
        assert_eq!(class_of("'}'"), Some(Some("t-str")));
        assert_eq!(class_of("\"{\""), Some(Some("t-str")));
        assert_eq!(class_of("1_000"), Some(Some("t-num")));
    }

    #[test]
    fn comments_attributes_and_raw_strings_are_one_token() {
        let got = classes("/// doc\n#[story(x = [1])]\nlet s = r#\"a \"b\" c\"#;");
        assert!(got.contains(&(Some("t-com"), "/// doc".into())), "{got:?}");
        assert!(
            got.contains(&(Some("t-attr"), "#[story(x = [1])]".into())),
            "{got:?}"
        );
        assert!(
            got.contains(&(Some("t-str"), "r#\"a \"b\" c\"#".into())),
            "{got:?}"
        );
    }

    #[test]
    fn a_block_comment_is_cut_at_each_line() {
        let lines = highlight("a /* one\ntwo */ b");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].last(), Some(&(Some("t-com"), "/* one".into())));
        assert_eq!(lines[1][0], (Some("t-com"), "two */".into()));
    }
}
