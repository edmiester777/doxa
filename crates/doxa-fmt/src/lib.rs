//! Formats the bodies of `view! { … }` invocations in Rust source, which rustfmt leaves alone.
//!
//! Only `view!` bodies are rewritten; everything else is left byte-for-byte as rustfmt produced it.

mod cli;
mod lex;
mod print;

pub use cli::run;

use std::path::Path;
use std::str::FromStr;

use syn::visit::Visit;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub max_width: usize,
    pub tab_spaces: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_width: 100,
            tab_spaces: 4,
        }
    }
}

impl Config {
    /// Reads `max_width` / `tab_spaces` from the nearest `rustfmt.toml` or `.rustfmt.toml`
    /// at or above `start`.
    pub fn discover(start: &Path) -> Config {
        let start = start.canonicalize().unwrap_or_else(|_| start.to_path_buf());
        let dir = if start.is_file() {
            start.parent().map(Path::to_path_buf).unwrap_or(start)
        } else {
            start
        };
        for ancestor in dir.ancestors() {
            for name in ["rustfmt.toml", ".rustfmt.toml"] {
                if let Ok(text) = std::fs::read_to_string(ancestor.join(name)) {
                    return Config::parse(&text);
                }
            }
        }
        Config::default()
    }

    fn parse(text: &str) -> Config {
        let mut config = Config::default();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let Ok(value) = value.trim().parse::<usize>() else {
                continue;
            };
            match key.trim() {
                "max_width" => config.max_width = value,
                "tab_spaces" => config.tab_spaces = value,
                _ => {}
            }
        }
        config
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Formatted {
    pub output: String,
    pub warnings: Vec<String>,
    pub changed: bool,
}

pub fn format_source(src: &str, config: &Config) -> Formatted {
    let mut warnings = Vec::new();
    let unchanged = |warnings| Formatted {
        output: src.to_string(),
        warnings,
        changed: false,
    };

    let file = match parse_file(src) {
        Ok(file) => file,
        Err(e) => {
            warnings.push(format!("could not parse file: {e}"));
            return unchanged(warnings);
        }
    };
    let mut finder = ViewFinder::default();
    finder.visit_file(&file);

    let printer = print::Printer::new(src, config);
    let mut edits = Vec::new();
    for mac in finder.found {
        match printer.format_macro(mac, None, None) {
            Ok(edit) => edits.push(edit),
            Err(e) => printer.warn(mac, e),
        }
    }
    warnings.extend(printer.take_warnings());

    let mut output = src.to_string();
    edits.sort_by_key(|(range, _)| std::cmp::Reverse(range.start));
    for (range, text) in edits {
        output.replace_range(range, &text);
    }
    let changed = output != src;
    Formatted {
        output,
        warnings,
        changed,
    }
}

/// Parses `src` so that span byte offsets index into `src` itself.
fn parse_file(src: &str) -> syn::Result<syn::File> {
    let mut clean = src.to_string();
    if clean.starts_with('\u{feff}') {
        clean.replace_range(..3, "   ");
    }
    let body = clean.trim_start();
    if body.starts_with("#!") && !body.starts_with("#![") {
        let start = clean.len() - body.len();
        let end = clean[start..].find('\n').map_or(clean.len(), |n| start + n);
        clean.replace_range(start..end, &" ".repeat(end - start));
    }
    let tokens = proc_macro2::TokenStream::from_str(&clean)?;
    syn::parse2(tokens)
}

pub(crate) fn is_view(mac: &syn::Macro) -> bool {
    mac.path.segments.last().is_some_and(|s| s.ident == "view")
}

#[derive(Default)]
struct ViewFinder<'ast> {
    found: Vec<&'ast syn::Macro>,
}

impl<'ast> Visit<'ast> for ViewFinder<'ast> {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if is_view(mac) {
            self.found.push(mac);
        }
    }
}
