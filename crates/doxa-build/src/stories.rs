//! The `#[story]` list `doxa gallery` shows: each story's module, file and source.

use std::path::Path;

use serde::Serialize;
use syn::spanned::Spanned;

use crate::split;

/// The custom section `#[story]` writes `key\tname\tmodule\tfile\tline` lines into.
const SECTION: &str = "doxa_stories";

/// One story, as the gallery page reads it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Story {
    /// Its export's suffix: the function's name and a hash of where it is.
    pub name: String,
    /// The function's name.
    pub title: String,
    /// Its `module_path!()`.
    pub module: String,
    /// Its file, as rustc named it.
    pub file: String,
    /// The line of its `#[story]`.
    pub line: usize,
    /// Its function's text, doc comments included; empty when the file can't be read.
    pub source: String,
}

/// The stories in the linked `wasm`, their files read relative to `root`.
pub fn stories(wasm: &[u8], root: &Path) -> Vec<Story> {
    let mut out: Vec<Story> = String::from_utf8_lossy(&split::custom_section(wasm, SECTION))
        .lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            let (key, name, module, file) = (f.next()?, f.next()?, f.next()?, f.next()?);
            let line = f.next()?.parse().ok()?;
            let source = std::fs::read_to_string(root.join(file))
                .ok()
                .and_then(|text| source_of(&text, name, line))
                .unwrap_or_default();
            Some(Story {
                name: key.into(),
                title: name.into(),
                module: module.into(),
                file: file.into(),
                line,
                source,
            })
        })
        .collect();
    out.sort_by(|a, b| (&a.module, &a.title, &a.name).cmp(&(&b.module, &b.title, &b.name)));
    out.dedup_by(|a, b| a.name == b.name);
    out
}

/// The text of the `#[story] fn name` nearest `line` in `text`, dedented.
fn source_of(text: &str, name: &str, line: usize) -> Option<String> {
    use syn::visit::Visit;

    struct Find<'a>(&'a str, Vec<(usize, usize)>);
    impl<'ast> Visit<'ast> for Find<'_> {
        fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
            let story = f
                .attrs
                .iter()
                .any(|a| a.path().segments.last().is_some_and(|s| s.ident == "story"));
            if story && f.sig.ident == self.0 {
                let start = f.attrs.first().map_or(f.sig.span(), |a| a.span());
                self.1.push((start.start().line, f.block.span().end().line));
            }
        }
    }

    let file = syn::parse_file(text).ok()?;
    let mut find = Find(name, Vec::new());
    find.visit_file(&file);
    let (start, end) = find.1.into_iter().min_by_key(|(s, e)| {
        if (*s..=*e).contains(&line) {
            0
        } else {
            s.abs_diff(line)
        }
    })?;
    let lines: Vec<&str> = text.lines().skip(start - 1).take(end + 1 - start).collect();
    let indent = lines
        .iter()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.len() - l.trim_start().len())
        .min()
        .unwrap_or(0);
    Some(
        lines
            .iter()
            .map(|l| l.get(indent..).unwrap_or("").trim_end())
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "\
use doxa::ui::story;

mod inner {
    /// Shown first.
    #[story]
    pub fn empty() -> View {
        view! { <p>{\"}\"}</p> }
    }
}

#[story]
fn empty() -> View { view! {} }
";

    #[test]
    fn the_story_nearest_its_line_is_read_with_its_docs() {
        assert_eq!(
            source_of(FILE, "empty", 5).as_deref(),
            Some("/// Shown first.\n#[story]\npub fn empty() -> View {\n    view! { <p>{\"}\"}</p> }\n}")
        );
        assert_eq!(
            source_of(FILE, "empty", 11).as_deref(),
            Some("#[story]\nfn empty() -> View { view! {} }")
        );
        assert_eq!(source_of(FILE, "missing", 1), None);
    }

    fn section(body: &str) -> Vec<u8> {
        let mut wasm = b"\0asm\x01\0\0\0".to_vec();
        let mut payload = vec![SECTION.len() as u8];
        payload.extend_from_slice(SECTION.as_bytes());
        payload.extend_from_slice(body.as_bytes());
        wasm.push(0);
        wasm.push(payload.len() as u8);
        wasm.extend(payload);
        wasm
    }

    #[test]
    fn stories_are_read_from_the_section_and_their_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("s.rs"), FILE).unwrap();
        let wasm =
            section("empty_1\tempty\tapp::inner\ts.rs\t5\nempty_2\tempty\tapp\tgone.rs\t1\n");
        let got = stories(&wasm, dir.path());
        assert_eq!(got.len(), 2);
        assert_eq!(
            (got[0].module.as_str(), got[0].source.is_empty()),
            ("app", true)
        );
        assert_eq!(
            (got[0].name.as_str(), got[0].title.as_str()),
            ("empty_2", "empty")
        );
        assert_eq!(got[1].module, "app::inner");
        assert!(
            got[1].source.starts_with("/// Shown first."),
            "{}",
            got[1].source
        );
    }
}
