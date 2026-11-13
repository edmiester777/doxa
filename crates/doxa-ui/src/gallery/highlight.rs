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
    let mut lx = Lexer {
        c: src.chars().collect(),
        i: 0,
        lines: vec![Vec::new()],
    };
    while lx.i < lx.c.len() {
        lx.rust();
        // An unmatched closer stops `rust`; step over it.
        lx.take(None, 1);
    }
    lx.lines
}

struct Lexer {
    c: Vec<char>,
    i: usize,
    lines: Vec<Vec<Token>>,
}

impl Lexer {
    fn at(&self, j: usize) -> char {
        self.c.get(j).copied().unwrap_or('\0')
    }

    fn done(&self) -> bool {
        self.i >= self.c.len()
    }

    /// Emits `c[start..i]` as one token of `class`.
    fn emit(&mut self, class: Option<&'static str>, start: usize) {
        let text: String = self.c[start..self.i].iter().collect();
        for (n, part) in text.split('\n').enumerate() {
            if n > 0 {
                self.lines.push(Vec::new());
            }
            if part.is_empty() {
                continue;
            }
            let line = self.lines.last_mut().expect("one line at least");
            match line.last_mut() {
                Some((prev, run)) if *prev == class => run.push_str(part),
                _ => line.push((class, part.to_owned())),
            }
        }
    }

    fn take(&mut self, class: Option<&'static str>, n: usize) {
        let start = self.i;
        self.i = (self.i + n).min(self.c.len());
        self.emit(class, start);
    }

    fn take_while(&mut self, class: Option<&'static str>, f: impl Fn(char) -> bool) {
        let start = self.i;
        while !self.done() && f(self.c[self.i]) {
            self.i += 1;
        }
        self.emit(class, start);
    }

    /// Rust up to the first unmatched `)`, `]` or `}`, which is left unread.
    fn rust(&mut self) {
        let mut depth = 0usize;
        while !self.done() {
            match self.c[self.i] {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' if depth == 0 => return,
                ')' | ']' | '}' => depth -= 1,
                _ => {
                    self.token();
                    continue;
                }
            }
            self.take(None, 1);
        }
    }

    /// One Rust token; always advances.
    fn token(&mut self) {
        let (i, start) = (self.i, self.i);
        let c = self.c[i];
        let class = match c {
            '/' if self.at(i + 1) == '/' => {
                self.take_while(Some("t-com"), |ch| ch != '\n');
                return;
            }
            '/' if self.at(i + 1) == '*' => {
                let mut j = i + 2;
                while j < self.c.len() && !(self.c[j] == '*' && self.at(j + 1) == '/') {
                    j += 1;
                }
                self.i = (j + 2).min(self.c.len());
                Some("t-com")
            }
            'r' | 'b' if raw_string(&self.c, i).is_some() => {
                self.i = raw_string(&self.c, i).unwrap_or(i + 1);
                Some("t-str")
            }
            'b' if self.at(i + 1) == '"' => {
                self.i = string(&self.c, i + 1);
                Some("t-str")
            }
            '"' => {
                self.i = string(&self.c, i);
                Some("t-str")
            }
            '\'' if self.at(i + 1) == '\\' => {
                let mut j = i + 2;
                while j < self.c.len() && self.c[j] != '\'' {
                    j += 1;
                }
                self.i = (j + 1).min(self.c.len());
                Some("t-str")
            }
            '\'' if self.at(i + 2) == '\'' => {
                self.i = i + 3;
                Some("t-str")
            }
            '\'' if is_ident_start(self.at(i + 1)) => {
                let mut j = i + 1;
                while j < self.c.len() && is_ident(self.c[j]) {
                    j += 1;
                }
                self.i = j;
                Some("t-life")
            }
            '#' if self.at(i + 1) == '[' || (self.at(i + 1) == '!' && self.at(i + 2) == '[') => {
                self.attribute();
                return;
            }
            d if d.is_ascii_digit() => {
                let mut j = i;
                while j < self.c.len()
                    && (is_ident(self.c[j])
                        || (self.c[j] == '.' && self.at(j + 1).is_ascii_digit()))
                {
                    j += 1;
                }
                self.i = j;
                Some("t-num")
            }
            s if is_ident_start(s) => {
                let mut j = i;
                while j < self.c.len() && is_ident(self.c[j]) {
                    j += 1;
                }
                let word: String = self.c[i..j].iter().collect();
                self.i = j;
                if self.at(j) == '!' && self.at(j + 1) != '=' {
                    self.i += 1;
                    self.emit(Some("t-mac"), start);
                    if word == "view" {
                        self.view_body();
                    }
                    return;
                }
                if KEYWORDS.contains(&word.as_str()) {
                    Some("t-kw")
                } else if word.starts_with(|ch: char| ch.is_ascii_uppercase()) {
                    Some("t-ty")
                } else {
                    None
                }
            }
            _ => {
                self.i = i + 1;
                None
            }
        };
        self.emit(class, start);
    }

    /// `#[name(args)]`: the name drawn as a macro, the args as Rust.
    fn attribute(&mut self) {
        let open = if self.at(self.i + 1) == '!' { 3 } else { 2 };
        self.take(Some("t-pun"), open);
        self.take_while(None, char::is_whitespace);
        let start = self.i;
        while !self.done()
            && (is_ident(self.c[self.i]) || (self.c[self.i] == ':' && self.at(self.i + 1) == ':'))
        {
            self.i += if self.c[self.i] == ':' { 2 } else { 1 };
        }
        self.emit(Some("t-mac"), start);
        self.rust();
        if self.at(self.i) == ']' {
            self.take(Some("t-pun"), 1);
        }
    }

    /// After `view!`: its delimited body read as markup.
    fn view_body(&mut self) {
        self.take_while(None, char::is_whitespace);
        if !matches!(self.at(self.i), '{' | '(' | '[') {
            return;
        }
        self.take(None, 1);
        self.markup();
        if matches!(self.at(self.i), '}' | ')' | ']') {
            self.take(None, 1);
        }
    }

    /// `view!` markup up to the first unmatched closer, which is left unread.
    fn markup(&mut self) {
        while !self.done() {
            match self.c[self.i] {
                '}' | ')' | ']' => return,
                '{' => self.block(),
                '<' => self.tag(),
                '"' | '/' => self.token(),
                _ => self.take(None, 1),
            }
        }
    }

    /// `{ rust }` inside markup.
    fn block(&mut self) {
        self.take(None, 1);
        self.rust();
        if self.at(self.i) == '}' {
            self.take(None, 1);
        }
    }

    /// `<tag attr={v}>`, `</tag>`, `<!-- … -->` or a fragment's `<>`.
    fn tag(&mut self) {
        if self.c[self.i..].starts_with(&['<', '!', '-', '-']) {
            let start = self.i;
            while !self.done() && !self.c[self.i..].starts_with(&['-', '-', '>']) {
                self.i += 1;
            }
            self.i = (self.i + 3).min(self.c.len());
            self.emit(Some("t-com"), start);
            return;
        }
        let open = if self.at(self.i + 1) == '/' { 2 } else { 1 };
        self.take(Some("t-pun"), open);
        let start = self.i;
        while !self.done() && is_name(self.c[self.i]) {
            self.i += 1;
        }
        let name: String = self.c[start..self.i].iter().collect();
        let component = name.contains("::") || name.starts_with(|c: char| c.is_ascii_uppercase());
        self.emit(Some(if component { "t-ty" } else { "t-tag" }), start);

        let mut value = false;
        while !self.done() {
            let c = self.c[self.i];
            match c {
                '>' => return self.take(Some("t-pun"), 1),
                '/' if self.at(self.i + 1) == '>' => return self.take(Some("t-pun"), 2),
                '}' | ')' | ']' => return,
                c if c.is_whitespace() => {
                    self.take(None, 1);
                    continue;
                }
                '=' => {
                    self.take(None, 1);
                    value = true;
                    continue;
                }
                '{' => self.block(),
                c if is_ident_start(c) && !value => {
                    self.take_while(Some("t-at"), is_name);
                }
                _ => self.token(),
            }
            value = false;
        }
    }
}

fn is_ident_start(c: char) -> bool {
    c.is_alphabetic() || c == '_'
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// A character of a markup element or attribute name: `on:click`, `data-level`, `a::B`.
fn is_name(c: char) -> bool {
    is_ident(c) || c == ':' || c == '-'
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

    fn class_of(got: &[Token], text: &str) -> Option<Option<&'static str>> {
        got.iter().find(|(_, t)| t == text).map(|(c, _)| *c)
    }

    #[test]
    fn rust_tokens_get_their_classes() {
        let got = classes("pub fn a<'x>(n: u8) -> Vec<char> { vec!['}', \"{\"]; 1_000 }");
        assert_eq!(class_of(&got, "pub"), Some(Some("t-kw")));
        assert_eq!(class_of(&got, "'x"), Some(Some("t-life")));
        assert_eq!(class_of(&got, "Vec"), Some(Some("t-ty")));
        assert_eq!(class_of(&got, "vec!"), Some(Some("t-mac")));
        assert_eq!(class_of(&got, "'}'"), Some(Some("t-str")));
        assert_eq!(class_of(&got, "\"{\""), Some(Some("t-str")));
        assert_eq!(class_of(&got, "1_000"), Some(Some("t-num")));
    }

    #[test]
    fn an_attribute_names_its_macro_and_highlights_its_args() {
        let got =
            classes("/// doc\n#[npm(module = \"./a.js\", n = [1])]\nlet s = r#\"a \"b\" c\"#;");
        assert!(got.contains(&(Some("t-com"), "/// doc".into())), "{got:?}");
        assert_eq!(class_of(&got, "#["), Some(Some("t-pun")));
        assert_eq!(class_of(&got, "npm"), Some(Some("t-mac")));
        assert_eq!(class_of(&got, "\"./a.js\""), Some(Some("t-str")));
        assert_eq!(class_of(&got, "1"), Some(Some("t-num")));
        assert_eq!(class_of(&got, "]"), Some(Some("t-pun")));
        assert_eq!(class_of(&got, "r#\"a \"b\" c\"#"), Some(Some("t-str")));
    }

    #[test]
    fn view_markup_gets_tags_attributes_and_rust_blocks() {
        let got = classes(
            "view! { <p class=\"x\" on:click={move |_| go(1)}>{n}<Card data-a=v/> </p> }; let y = 2;",
        );
        assert_eq!(class_of(&got, "view!"), Some(Some("t-mac")));
        assert_eq!(class_of(&got, "p"), Some(Some("t-tag")));
        assert_eq!(class_of(&got, "class"), Some(Some("t-at")));
        assert_eq!(class_of(&got, "\"x\""), Some(Some("t-str")));
        assert_eq!(class_of(&got, "on:click"), Some(Some("t-at")));
        assert_eq!(class_of(&got, "move"), Some(Some("t-kw")));
        assert_eq!(class_of(&got, "Card"), Some(Some("t-ty")));
        assert_eq!(class_of(&got, "data-a"), Some(Some("t-at")));
        assert_eq!(
            class_of(&got, "=v"),
            Some(None),
            "a bare value is not an attribute"
        );
        assert_eq!(class_of(&got, "/>"), Some(Some("t-pun")));
        assert_eq!(class_of(&got, "</"), Some(Some("t-pun")));
        assert_eq!(
            class_of(&got, "let"),
            Some(Some("t-kw")),
            "markup ends with the macro"
        );
    }

    #[test]
    fn a_view_nested_in_a_block_is_markup_too() {
        let got = classes("view! { <ul>{xs.map(|x| view! { <li>{x}</li> })}</ul> }");
        assert_eq!(class_of(&got, "li"), Some(Some("t-tag")));
        assert_eq!(class_of(&got, "ul"), Some(Some("t-tag")));
    }

    #[test]
    fn real_source_comes_back_line_for_line() {
        let src = include_str!("app.rs");
        let got: Vec<String> = highlight(src)
            .into_iter()
            .map(|l| l.into_iter().map(|(_, t)| t).collect())
            .collect();
        assert_eq!(got, src.split('\n').collect::<Vec<_>>());
    }

    #[test]
    fn a_block_comment_is_cut_at_each_line() {
        let lines = highlight("a /* one\ntwo */ b");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].last(), Some(&(Some("t-com"), "/* one".into())));
        assert_eq!(lines[1][0], (Some("t-com"), "two */".into()));
    }
}
