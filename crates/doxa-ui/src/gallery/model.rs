//! What the gallery shows, apart from how: the story tree and the URL state.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One `#[story]`, as `doxa build` read it from the wasm and its file.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct StoryMeta {
    /// Its export's suffix: the function's name and a hash of where it is.
    pub name: String,
    /// The function's name; empty for an export the build had no metadata for.
    #[serde(default)]
    pub title: String,
    /// Its `module_path!()`.
    pub module: String,
    /// Its file, as rustc named it.
    pub file: String,
    /// The line of its `#[story]`.
    pub line: usize,
    /// Its function's text; empty when the file couldn't be read.
    pub source: String,
    /// The crate's own code it is built from, a file each.
    #[serde(default)]
    pub parts: Vec<Part>,
}

/// A file a story is built from, and the pieces of it the story reaches.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Part {
    /// Its path in its crate: the tab's label.
    pub title: String,
    /// Its path, written as [`StoryMeta::file`] is.
    pub file: String,
    /// Whether it is Rust, and so highlighted.
    pub rust: bool,
    /// The pieces shown, in file order.
    pub snippets: Vec<Snippet>,
}

/// Consecutive lines of a file.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Snippet {
    /// The first one's number, from 1.
    pub line: usize,
    /// Their text.
    pub source: String,
}

impl StoryMeta {
    /// What the gallery calls it: its function's name.
    pub fn title(&self) -> &str {
        if self.title.is_empty() {
            &self.name
        } else {
            &self.title
        }
    }
}

/// The story `wanted` names: its export suffix, or else the first with that function name.
pub(crate) fn find_story<'a>(entries: &'a [StoryMeta], wanted: &str) -> Option<&'a StoryMeta> {
    (entries.iter().find(|e| e.name == wanted))
        .or_else(|| entries.iter().find(|e| e.title() == wanted))
}

/// Every exported story, with what the build knew of it; sorted by name.
pub fn entries(mut names: Vec<String>, meta: Vec<StoryMeta>) -> Vec<StoryMeta> {
    names.sort();
    names
        .into_iter()
        .map(|name| {
            meta.iter()
                .find(|m| m.name == name)
                .cloned()
                .unwrap_or(StoryMeta {
                    name,
                    title: String::new(),
                    module: String::new(),
                    file: String::new(),
                    line: 0,
                    source: String::new(),
                    parts: Vec::new(),
                })
        })
        .collect()
}

/// What the story frame sends the gallery.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "doxa", rename_all = "lowercase")]
pub(crate) enum Message {
    /// A gallery shortcut pressed while the story had focus.
    Key { key: String },
}

/// The keys the story frame forwards.
#[cfg(target_arch = "wasm32")]
pub(crate) const FORWARDED: [&str; 4] = ["/", "t", "r", "p"];

/// The canvas size a story is shown at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Viewport {
    /// The whole canvas.
    Fill,
    /// 390 × 844.
    Phone,
    /// 768 × 1024.
    Tablet,
    /// 1280 × 800.
    Desktop,
}

impl Viewport {
    pub(crate) const ALL: [Viewport; 4] = [Self::Fill, Self::Phone, Self::Tablet, Self::Desktop];

    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Fill => "full",
            Self::Phone => "phone",
            Self::Tablet => "tablet",
            Self::Desktop => "desktop",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Fill => "Fill",
            Self::Phone => "Phone",
            Self::Tablet => "Tablet",
            Self::Desktop => "Desktop",
        }
    }

    /// Width and height in CSS pixels; `None` fills the canvas.
    pub(crate) fn size(self) -> Option<(u32, u32)> {
        match self {
            Self::Fill => None,
            Self::Phone => Some((390, 844)),
            Self::Tablet => Some((768, 1024)),
            Self::Desktop => Some((1280, 800)),
        }
    }
}

/// Where the gallery starts, from its URL.
#[derive(Debug, Clone, PartialEq)]
pub struct Initial {
    /// The story shown.
    pub story: Option<String>,
    /// Whether the story renders in its dark theme.
    pub dark: bool,
    /// The canvas size.
    pub viewport: Viewport,
}

impl Initial {
    /// From the query's pairs: `show`, `theme` and `viewport`.
    pub fn from_query(pairs: &[(String, String)]) -> Self {
        let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        Initial {
            story: get("show").filter(|s| !s.is_empty()).map(str::to_owned),
            dark: get("theme") == Some("dark"),
            viewport: Viewport::ALL
                .into_iter()
                .find(|v| Some(v.key()) == get("viewport"))
                .unwrap_or(Viewport::Fill),
        }
    }

    /// The query the gallery keeps its URL at.
    pub(crate) fn query(&self) -> String {
        let story = self.story.as_deref().unwrap_or("");
        let theme = if self.dark { "dark" } else { "light" };
        let pairs = [
            ("show", story),
            ("theme", theme),
            ("viewport", self.viewport.key()),
        ];
        format!(
            "?{}",
            serde_urlencoded::to_string(pairs).unwrap_or_default()
        )
    }
}

/// The story frame's URL; `remount` changes it so the frame reloads.
pub(crate) fn story_url(name: &str, dark: bool, remount: u64) -> String {
    let theme = if dark { "dark" } else { "light" };
    let remount = remount.to_string();
    let pairs = [("story", name), ("theme", theme), ("r", remount.as_str())];
    format!(
        "?{}",
        serde_urlencoded::to_string(pairs).unwrap_or_default()
    )
}

/// `snake_case` as a sentence: `picker_three` → `Picker three`.
pub(crate) fn human(s: &str) -> String {
    let t = s.replace('_', " ");
    let mut chars = t.trim().chars();
    chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

/// The folders a story sits in: its module path, below the crate every story shares.
pub(crate) fn folders(story: &StoryMeta, entries: &[StoryMeta]) -> Vec<String> {
    let root = |s: &StoryMeta| s.module.split("::").next().unwrap_or("").to_owned();
    let shared = entries.iter().all(|s| root(s) == root(story));
    story
        .module
        .split("::")
        .filter(|p| !p.is_empty())
        .skip(usize::from(shared))
        .map(str::to_owned)
        .collect()
}

/// One row of the sidebar's tree.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Row {
    /// A module, open unless folded.
    Dir {
        id: String,
        label: String,
        depth: usize,
        open: bool,
    },
    /// A story.
    Leaf {
        name: String,
        label: String,
        depth: usize,
    },
}

/// The tree's rows: folders by name, then their stories; all open while `query` filters.
pub(crate) fn tree_rows(entries: &[StoryMeta], query: &str, closed: &[String]) -> Vec<Row> {
    #[derive(Default)]
    struct Node<'a> {
        dirs: BTreeMap<String, Node<'a>>,
        leaves: Vec<&'a StoryMeta>,
    }
    fn walk(
        node: &Node,
        depth: usize,
        key: &str,
        filtering: bool,
        closed: &[String],
        out: &mut Vec<Row>,
    ) {
        for (part, dir) in &node.dirs {
            let id = if key.is_empty() {
                part.clone()
            } else {
                format!("{key}::{part}")
            };
            let open = filtering || !closed.contains(&id);
            out.push(Row::Dir {
                id: id.clone(),
                label: human(part),
                depth,
                open,
            });
            if open {
                walk(dir, depth + 1, &id, filtering, closed, out);
            }
        }
        out.extend(node.leaves.iter().map(|s| Row::Leaf {
            name: s.name.clone(),
            label: human(s.title()),
            depth,
        }));
    }

    let query = query.trim().to_lowercase();
    let mut top = Node::default();
    for s in entries {
        if !query.is_empty() && !human(s.title()).to_lowercase().contains(&query) {
            continue;
        }
        let mut node = &mut top;
        for part in folders(s, entries) {
            node = node.dirs.entry(part).or_default();
        }
        node.leaves.push(s);
    }
    let mut out = Vec::new();
    walk(&top, 0, "", !query.is_empty(), closed, &mut out);
    out
}

/// The stories the tree shows, in order.
pub(crate) fn visible(rows: &[Row]) -> Vec<String> {
    rows.iter()
        .filter_map(|r| match r {
            Row::Leaf { name, .. } => Some(name.clone()),
            Row::Dir { .. } => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn story(name: &str, module: &str) -> StoryMeta {
        StoryMeta {
            name: name.into(),
            title: String::new(),
            module: module.into(),
            file: String::new(),
            line: 0,
            source: String::new(),
            parts: Vec::new(),
        }
    }

    fn labels(rows: &[Row]) -> Vec<String> {
        rows.iter()
            .map(|r| match r {
                Row::Dir {
                    label, depth, open, ..
                } => format!("{depth}{}{label}", if *open { "v" } else { ">" }),
                Row::Leaf { label, depth, .. } => format!("{depth} {label}"),
            })
            .collect()
    }

    #[test]
    fn stories_nest_by_module_below_the_shared_crate() {
        let all = vec![
            story("empty_list", "app::lists"),
            story("full_list", "app::lists"),
            story("button", "app::forms::inputs"),
            story("top", "app"),
        ];
        assert_eq!(
            labels(&tree_rows(&all, "", &[])),
            [
                "0vForms",
                "1vInputs",
                "2 Button",
                "0vLists",
                "1 Empty list",
                "1 Full list",
                "0 Top"
            ]
        );
        assert_eq!(
            labels(&tree_rows(&all, "", &["forms".into()])),
            ["0>Forms", "0vLists", "1 Empty list", "1 Full list", "0 Top"]
        );
    }

    #[test]
    fn a_query_keeps_matching_stories_and_opens_their_folders() {
        let all = vec![
            story("empty_list", "app::lists"),
            story("button", "app::forms"),
        ];
        let rows = tree_rows(&all, " LIST", &["lists".into()]);
        assert_eq!(labels(&rows), ["0vLists", "1 Empty list"]);
        assert_eq!(visible(&rows), ["empty_list"]);
    }

    #[test]
    fn stories_from_two_crates_keep_their_crate_folder() {
        let all = vec![story("a", "one::x"), story("b", "two")];
        assert_eq!(
            labels(&tree_rows(&all, "", &[])),
            ["0vOne", "1vX", "2 A", "0vTwo", "1 B"]
        );
    }

    #[test]
    fn the_url_round_trips_and_unknown_values_fall_back() {
        let start = Initial {
            story: Some("picker three".into()),
            dark: true,
            viewport: Viewport::Phone,
        };
        let pairs: Vec<(String, String)> =
            serde_urlencoded::from_str(start.query().trim_start_matches('?')).unwrap();
        assert_eq!(Initial::from_query(&pairs), start);
        let odd = [("viewport".to_owned(), "watch".to_owned())];
        assert_eq!(Initial::from_query(&odd).viewport, Viewport::Fill);
    }

    #[test]
    fn exports_without_metadata_are_still_listed() {
        let got = entries(vec!["b".into(), "a".into()], vec![story("b", "app::x")]);
        assert_eq!(
            got.iter()
                .map(|s| (s.name.as_str(), s.module.as_str()))
                .collect::<Vec<_>>(),
            [("a", ""), ("b", "app::x")]
        );
    }

    #[test]
    fn messages_are_tagged_json() {
        let m: Message = serde_json::from_str(r#"{"doxa":"key","key":"t"}"#).unwrap();
        assert_eq!(m, Message::Key { key: "t".into() });
        assert_eq!(human("picker_three"), "Picker three");
    }
}
