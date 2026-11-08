//! What the gallery shows, apart from how: the story tree, the logged actions, the URL state.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One `#[story]`, as `doxa build` read it from the wasm and its file.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct StoryMeta {
    /// The function's name, and its export's suffix.
    pub name: String,
    /// Its `module_path!()`.
    pub module: String,
    /// Its file, as rustc named it.
    pub file: String,
    /// The line of its `#[story]`.
    pub line: usize,
    /// Its function's text; empty when the file couldn't be read.
    pub source: String,
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
                    module: String::new(),
                    file: String::new(),
                    line: 0,
                    source: String::new(),
                })
        })
        .collect()
}

/// What the story frame sends the gallery.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "doxa", rename_all = "lowercase")]
pub(crate) enum Message {
    /// A component called a function prop.
    Action {
        story: String,
        component: String,
        prop: String,
        args: Vec<String>,
    },
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

/// The panel under the canvas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    /// Calls the story's components made to their function props.
    Actions,
    /// The story's source.
    Source,
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
    /// The open panel.
    pub tab: Tab,
}

impl Initial {
    /// From the query's pairs: `show`, `theme`, `viewport` and `panel`.
    pub fn from_query(pairs: &[(String, String)]) -> Self {
        let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        Initial {
            story: get("show").filter(|s| !s.is_empty()).map(str::to_owned),
            dark: get("theme") == Some("dark"),
            viewport: Viewport::ALL
                .into_iter()
                .find(|v| Some(v.key()) == get("viewport"))
                .unwrap_or(Viewport::Fill),
            tab: if get("panel") == Some("source") {
                Tab::Source
            } else {
                Tab::Actions
            },
        }
    }

    /// The query the gallery keeps its URL at.
    pub(crate) fn query(&self) -> String {
        let tab = match self.tab {
            Tab::Actions => "actions",
            Tab::Source => "source",
        };
        let story = self.story.as_deref().unwrap_or("");
        let theme = if self.dark { "dark" } else { "light" };
        let pairs = [
            ("show", story),
            ("theme", theme),
            ("viewport", self.viewport.key()),
            ("panel", tab),
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
            label: human(&s.name),
            depth,
        }));
    }

    let query = query.trim().to_lowercase();
    let mut top = Node::default();
    for s in entries {
        if !query.is_empty() && !human(&s.name).to_lowercase().contains(&query) {
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

/// One logged call, newest first in the panel.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Logged {
    pub id: u64,
    pub component: String,
    pub prop: String,
    pub args: Vec<String>,
    /// How many times in a row it was made.
    pub count: u32,
    pub at: String,
}

/// The most calls the panel keeps.
const KEPT: usize = 500;

/// Log a call at the front, folding it into the newest one when it repeats that exactly.
pub(crate) fn log(
    list: &mut Vec<Logged>,
    component: String,
    prop: String,
    args: Vec<String>,
    at: String,
) {
    if let Some(last) = list.first_mut() {
        if last.component == component && last.prop == prop && last.args == args {
            last.count += 1;
            last.at = at;
            return;
        }
    }
    let id = list.iter().map(|l| l.id + 1).max().unwrap_or(0);
    list.insert(
        0,
        Logged {
            id,
            component,
            prop,
            args,
            count: 1,
            at,
        },
    );
    list.truncate(KEPT);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn story(name: &str, module: &str) -> StoryMeta {
        StoryMeta {
            name: name.into(),
            module: module.into(),
            file: String::new(),
            line: 0,
            source: String::new(),
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
    fn a_repeated_call_is_counted_on_the_newest_row() {
        let mut list = Vec::new();
        let call = |list: &mut Vec<Logged>, arg: &str, at: &str| {
            log(
                list,
                "Picker".into(),
                "on_open".into(),
                vec![arg.into()],
                at.into(),
            )
        };
        call(&mut list, "\"gear\"", "1");
        call(&mut list, "\"gear\"", "2");
        call(&mut list, "\"cog\"", "3");
        call(&mut list, "\"gear\"", "4");
        let rows: Vec<_> = list
            .iter()
            .map(|l| (l.args[0].as_str(), l.count, l.at.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("\"gear\"", 1, "4"),
                ("\"cog\"", 1, "3"),
                ("\"gear\"", 2, "2")
            ]
        );
        assert_eq!(list.iter().map(|l| l.id).collect::<Vec<_>>(), [2, 1, 0]);
    }

    #[test]
    fn the_url_round_trips_and_unknown_values_fall_back() {
        let start = Initial {
            story: Some("picker three".into()),
            dark: true,
            viewport: Viewport::Phone,
            tab: Tab::Source,
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
