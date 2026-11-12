//! What a story is built from: the items of its own crate it names, followed through `use`
//! and from item to item, plus the files they point at, such as a `#[react(module)]`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use serde::Serialize;

/// A file a story is built from, and the pieces of it the story reaches.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Part {
    /// Its path in its crate, `src/` dropped: the tab's label.
    pub title: String,
    /// Its path, written as the story's `file` is.
    pub file: String,
    /// Whether it is Rust.
    pub rust: bool,
    /// The pieces shown, in file order.
    pub snippets: Vec<Snippet>,
}

/// Consecutive lines of a file.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Snippet {
    /// The first one's number, from 1.
    pub line: usize,
    /// Their text.
    pub source: String,
}

/// A file's top-level items and imports; an `impl` counts as an item named after its type.
struct Module {
    dir: PathBuf,
    path: Vec<String>,
    lines: Vec<String>,
    items: Vec<Item>,
    /// A local name, the module it is imported from, and its name there.
    uses: HashMap<String, (Vec<String>, String)>,
    globs: Vec<Vec<String>>,
}

struct Item {
    name: String,
    story: bool,
    start: usize,
    end: usize,
    tokens: TokenStream,
}

/// Parsed files, kept across stories.
#[derive(Default)]
pub struct Sources {
    modules: HashMap<PathBuf, Option<Module>>,
}

/// An item reached: its file and its index there.
type Found = (PathBuf, usize);

impl Sources {
    /// The parts of story `name`, the `#[story] fn` nearest `line` in `file`; `root` is where
    /// `file` is relative to.
    pub fn parts(&mut self, root: &Path, file: &str, name: &str, line: usize) -> Vec<Part> {
        let path = root.join(file);
        let Some(krate) = path
            .ancestors()
            .skip(1)
            .find(|d| d.join("Cargo.toml").is_file())
        else {
            return Vec::new();
        };
        let krate = krate.to_path_buf();
        let Some(story) = self.module(&krate, &path).and_then(|m| {
            (m.items.iter().enumerate())
                .filter(|(_, i)| i.story && i.name == name)
                .min_by_key(|(_, i)| i.start.abs_diff(line))
                .map(|(at, _)| at)
        }) else {
            return Vec::new();
        };

        let mut seen: HashSet<Found> = HashSet::from([(path.clone(), story)]);
        let mut queue = vec![(path.clone(), story)];
        let mut order: Vec<PathBuf> = Vec::new();
        let mut shown: HashMap<PathBuf, Vec<usize>> = HashMap::new();
        let mut at = 0;
        while let Some((file, item)) = queue.get(at).cloned() {
            at += 1;
            let (mut idents, mut strings, mut assets) = (Vec::new(), Vec::new(), Vec::new());
            if let Some(m) = self.module(&krate, &file) {
                scan(m.items[item].tokens.clone(), &mut idents, &mut strings);
                assets = (strings.iter())
                    .filter_map(|s| {
                        [m.dir.join(s), krate.join(s)]
                            .into_iter()
                            .find_map(|p| asset(&krate, &p))
                    })
                    .collect();
            }
            for ident in idents {
                for found in self.resolve(&krate, &file, &ident) {
                    if seen.insert(found.clone()) {
                        if !order.contains(&found.0) {
                            order.push(found.0.clone());
                        }
                        shown.entry(found.0.clone()).or_default().push(found.1);
                        queue.push(found);
                    }
                }
            }
            for f in assets {
                if !order.contains(&f) {
                    order.push(f);
                }
            }
        }

        let label = |p: &Path| {
            let rel = p.strip_prefix(&krate).unwrap_or(p);
            let rel = rel.strip_prefix("src").unwrap_or(rel);
            rel.to_string_lossy().replace('\\', "/")
        };
        let written = |p: &Path| {
            let rel = p.strip_prefix(root).unwrap_or(p);
            rel.to_string_lossy().replace('\\', "/")
        };
        order
            .into_iter()
            .filter_map(|p| {
                let snippets = match shown.get(&p) {
                    Some(items) => self.snippets(&krate, &p, items),
                    None => vec![Snippet {
                        line: 1,
                        source: std::fs::read_to_string(&p).ok()?.trim_end().to_owned(),
                    }],
                };
                Some(Part {
                    title: label(&p),
                    file: written(&p),
                    rust: p.extension().is_some_and(|e| e == "rs"),
                    snippets,
                })
            })
            .collect()
    }

    /// `items` of `file` as their text; those only blank lines apart are one snippet.
    fn snippets(&mut self, krate: &Path, file: &Path, items: &[usize]) -> Vec<Snippet> {
        let Some(m) = self.module(krate, file) else {
            return Vec::new();
        };
        let mut spans: Vec<(usize, usize)> = items
            .iter()
            .map(|&i| (m.items[i].start, m.items[i].end))
            .collect();
        spans.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for (s, e) in spans {
            match merged.last_mut() {
                Some(last)
                    if (m.lines.get(last.1..s.saturating_sub(1)))
                        .is_none_or(|gap| gap.iter().all(|l| l.trim().is_empty())) =>
                {
                    last.1 = last.1.max(e)
                }
                _ => merged.push((s, e)),
            }
        }
        merged
            .into_iter()
            .map(|(s, e)| Snippet {
                line: s,
                source: m.lines[s - 1..e.min(m.lines.len())].join("\n"),
            })
            .collect()
    }

    /// The crate-local items `name` means in `file`, which aren't stories.
    fn resolve(&mut self, krate: &Path, file: &Path, name: &str) -> Vec<Found> {
        let Some(m) = self.module(krate, file) else {
            return Vec::new();
        };
        let here = own(m, file, name);
        if !here.is_empty() {
            return here;
        }
        let (imported, globs) = (m.uses.get(name).cloned(), m.globs.clone());
        if let Some((module, orig)) = imported {
            return self.lookup(krate, &module, &orig, 0);
        }
        globs
            .iter()
            .map(|g| self.lookup(krate, g, name, 0))
            .find(|f| !f.is_empty())
            .unwrap_or_default()
    }

    /// Item `name` of the module at `path`, through its re-exports.
    fn lookup(&mut self, krate: &Path, path: &[String], name: &str, depth: u8) -> Vec<Found> {
        let Some(file) = module_file(krate, path) else {
            return Vec::new();
        };
        let Some(m) = self.module(krate, &file) else {
            return Vec::new();
        };
        let here = own(m, &file, name);
        if !here.is_empty() || depth > 4 {
            return here;
        }
        let (imported, globs) = (m.uses.get(name).cloned(), m.globs.clone());
        if let Some((module, orig)) = imported {
            return self.lookup(krate, &module, &orig, depth + 1);
        }
        globs
            .iter()
            .map(|g| self.lookup(krate, g, name, depth + 1))
            .find(|f| !f.is_empty())
            .unwrap_or_default()
    }

    fn module(&mut self, krate: &Path, file: &Path) -> Option<&Module> {
        self.modules
            .entry(file.to_path_buf())
            .or_insert_with(|| parse(krate, file))
            .as_ref()
    }
}

fn own(m: &Module, file: &Path, name: &str) -> Vec<Found> {
    (m.items.iter().enumerate())
        .filter(|(_, i)| i.name == name && !i.story)
        .map(|(at, _)| (file.to_path_buf(), at))
        .collect()
}

/// The file of module `path` in the crate at `krate`; `[]` is its root.
fn module_file(krate: &Path, path: &[String]) -> Option<PathBuf> {
    let src = krate.join("src");
    let candidates = if path.is_empty() {
        vec![src.join("lib.rs"), src.join("main.rs")]
    } else {
        let dir = path.iter().fold(src, |d, s| d.join(s));
        vec![dir.with_extension("rs"), dir.join("mod.rs")]
    };
    candidates.into_iter().find(|p| p.is_file())
}

/// The module path of `file` in the crate at `krate`.
fn module_path(krate: &Path, file: &Path) -> Option<Vec<String>> {
    let rel = file.strip_prefix(krate.join("src")).ok()?;
    let mut path: Vec<String> = rel
        .with_extension("")
        .iter()
        .map(|s| s.to_string_lossy().into_owned())
        .collect();
    if path.len() == 1 && (path[0] == "lib" || path[0] == "main") || path.last()? == "mod" {
        path.pop();
    }
    Some(path)
}

/// `path` as a file in the crate shown with the story; Rust files are reached as items.
fn asset(krate: &Path, path: &Path) -> Option<PathBuf> {
    let mut clean = PathBuf::new();
    for c in path.components() {
        match c {
            std::path::Component::ParentDir => {
                clean.pop();
            }
            std::path::Component::CurDir => {}
            c => clean.push(c),
        }
    }
    let small = std::fs::metadata(&clean).ok()?.len() <= 64 * 1024;
    let shown = clean.is_file() && clean.extension().is_some_and(|e| e != "rs");
    (clean.starts_with(krate) && small && shown).then_some(clean)
}

fn parse(krate: &Path, file: &Path) -> Option<Module> {
    let text = std::fs::read_to_string(file).ok()?;
    let ast = syn::parse_file(&text).ok()?;
    let path = module_path(krate, file)?;
    let mut m = Module {
        dir: file.parent()?.to_path_buf(),
        path,
        lines: text.lines().map(str::to_owned).collect(),
        items: Vec::new(),
        uses: HashMap::new(),
        globs: Vec::new(),
    };
    for item in &ast.items {
        let names: Vec<String> = match item {
            syn::Item::Use(u) => {
                let base = m.path.clone();
                imports(krate, &base, &mut Vec::new(), &u.tree, &mut m);
                continue;
            }
            syn::Item::Fn(f) => vec![f.sig.ident.to_string()],
            syn::Item::Struct(s) => vec![s.ident.to_string()],
            syn::Item::Enum(e) => vec![e.ident.to_string()],
            syn::Item::Union(u) => vec![u.ident.to_string()],
            syn::Item::Trait(t) => vec![t.ident.to_string()],
            syn::Item::Type(t) => vec![t.ident.to_string()],
            syn::Item::Const(c) => vec![c.ident.to_string()],
            syn::Item::Static(s) => vec![s.ident.to_string()],
            syn::Item::Macro(mac) => mac.ident.iter().map(ToString::to_string).collect(),
            syn::Item::Impl(i) => match &*i.self_ty {
                syn::Type::Path(p) => p
                    .path
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .into_iter()
                    .collect(),
                _ => Vec::new(),
            },
            syn::Item::ForeignMod(f) => f
                .items
                .iter()
                .filter_map(|i| match i {
                    syn::ForeignItem::Fn(f) => Some(f.sig.ident.to_string()),
                    syn::ForeignItem::Type(t) => Some(t.ident.to_string()),
                    syn::ForeignItem::Static(s) => Some(s.ident.to_string()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        let story = matches!(item, syn::Item::Fn(f) if f.attrs.iter()
            .any(|a| a.path().segments.last().is_some_and(|s| s.ident == "story")));
        let tokens = item.to_token_stream();
        let Some((start, end)) = lines(&tokens) else {
            continue;
        };
        for name in names {
            m.items.push(Item {
                name,
                story,
                start,
                end,
                tokens: tokens.clone(),
            });
        }
    }
    Some(m)
}

/// The first and last line `tokens` cover.
fn lines(tokens: &TokenStream) -> Option<(usize, usize)> {
    let mut it = tokens.clone().into_iter();
    let first = it.next()?;
    let last = it.last().unwrap_or_else(|| first.clone());
    Some((first.span().start().line, last.span().end().line))
}

/// Record the crate-local names `tree` imports into `m`; `prefix` is the path so far.
fn imports(
    krate: &Path,
    base: &[String],
    prefix: &mut Vec<String>,
    tree: &syn::UseTree,
    m: &mut Module,
) {
    match tree {
        syn::UseTree::Path(p) => {
            prefix.push(p.ident.to_string());
            imports(krate, base, prefix, &p.tree, m);
            prefix.pop();
        }
        syn::UseTree::Group(g) => {
            for t in &g.items {
                imports(krate, base, prefix, t, m);
            }
        }
        syn::UseTree::Name(n) => {
            if let Some(module) = local(krate, base, prefix) {
                let name = n.ident.to_string();
                m.uses.insert(name.clone(), (module, name));
            }
        }
        syn::UseTree::Rename(r) => {
            if let Some(module) = local(krate, base, prefix) {
                m.uses
                    .insert(r.rename.to_string(), (module, r.ident.to_string()));
            }
        }
        syn::UseTree::Glob(_) => {
            if let Some(module) = local(krate, base, prefix) {
                m.globs.push(module);
            }
        }
    }
}

/// `path`, written in module `base`, as a module path from the crate root; `None` when it
/// leaves the crate.
fn local(krate: &Path, base: &[String], path: &[String]) -> Option<Vec<String>> {
    let mut out = base.to_vec();
    let mut rest = path.iter().peekable();
    match rest.peek().map(|s| s.as_str()) {
        Some("crate") => {
            out.clear();
            rest.next();
        }
        Some("self") => {
            rest.next();
        }
        Some("super") => {
            while rest.peek().is_some_and(|s| *s == "super") {
                out.pop()?;
                rest.next();
            }
        }
        Some(child) => {
            let mut sub = base.to_vec();
            sub.push(child.to_owned());
            module_file(krate, &sub)?;
        }
        None => {}
    }
    out.extend(rest.cloned());
    Some(out)
}

/// Every identifier and string literal in `tokens`, macro bodies included.
fn scan(tokens: TokenStream, idents: &mut Vec<String>, strings: &mut Vec<String>) {
    for t in tokens {
        match t {
            TokenTree::Ident(i) => {
                let i = i.to_string();
                if !idents.contains(&i) {
                    idents.push(i);
                }
            }
            TokenTree::Group(g) => scan(g.stream(), idents, strings),
            TokenTree::Literal(l) => {
                if let Ok(s) = syn::parse2::<syn::LitStr>(TokenTree::Literal(l).into()) {
                    let s = s.value();
                    if !s.is_empty() && !s.contains(char::is_whitespace) && s.contains('.') {
                        strings.push(s);
                    }
                }
            }
            TokenTree::Punct(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, path: &str, text: &str) {
        let p = dir.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    fn krate() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("web");
        write(&d, "Cargo.toml", "[package]\nname = \"web\"\n");
        write(
            &d,
            "src/lib.rs",
            "pub mod kit;\npub mod stories;\n\npub fn unused() {}\n",
        );
        write(
            &d,
            "src/kit.rs",
            "use doxa::ui::prelude::*;\n\n/// A picker.\n#[component]\npub fn Picker() -> View {\n    view! { <Badge/> }\n}\n\n/// From React.\n#[react(module = \"./ts/badge.tsx\")]\npub struct Badge {}\n",
        );
        write(&d, "ts/badge.tsx", "export const Badge = () => null;\n");
        write(
            &d,
            "src/stories/mod.rs",
            "pub mod data;\n\npub struct Slow;\n\nimpl Transport for Slow {}\n\npub struct Unused;\n\nfn far() {}\n",
        );
        write(
            &d,
            "src/stories/data.rs",
            "use super::{far, Slow};\nuse crate::kit::*;\n\n#[component]\nfn Feed() -> View { view! {} }\n\n#[story]\nfn other() -> View { view! { <Feed/> } }\n\n#[story]\nfn picker() -> View {\n    let _ = (Slow, far);\n    view! { <Picker/> <Feed/> }\n}\n",
        );
        dir
    }

    #[test]
    fn a_story_shows_the_items_it_reaches_and_their_files() {
        let dir = krate();
        let parts = Sources::default().parts(dir.path(), "web/src/stories/data.rs", "picker", 11);
        let got: Vec<(&str, &str, Vec<usize>)> = parts
            .iter()
            .map(|p| {
                (
                    p.title.as_str(),
                    p.file.as_str(),
                    p.snippets.iter().map(|s| s.line).collect(),
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                ("stories/mod.rs", "web/src/stories/mod.rs", vec![3, 9]),
                ("kit.rs", "web/src/kit.rs", vec![3]),
                ("stories/data.rs", "web/src/stories/data.rs", vec![4]),
                ("ts/badge.tsx", "web/ts/badge.tsx", vec![1]),
            ]
        );
        assert_eq!(
            parts[0].snippets[0].source,
            "pub struct Slow;\n\nimpl Transport for Slow {}"
        );
        assert!(parts[1].snippets[0].source.starts_with("/// A picker."));
        assert!(!parts[3].rust && parts[1].rust);
    }

    #[test]
    fn a_story_outside_a_crate_has_no_parts() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            "s.rs",
            "#[story]\nfn s() -> View { view! {} }\n",
        );
        assert!(Sources::default()
            .parts(dir.path(), "s.rs", "s", 1)
            .is_empty());
    }
}
