//! `cn![…]`: a class list where, of two Tailwind classes that set the same thing, the later one
//! wins. A port of tailwind-merge 3.5's default rules; its MIT licence is in `data/`.

mod trie;
mod validators;

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use trie::{config, Extra, Trie};

/// `cn!["px-4 py-2", rest.class()]`: the parts joined as `classes!` joins them, then merged.
#[macro_export]
macro_rules! cn {
    ($($part:expr),* $(,)?) => {
        $crate::merge(&$crate::__private::classes![$($part),*])
    };
}

#[doc(hidden)]
pub mod __private {
    pub use doxa_ui::classes;
}

/// Merge `classes` with the default rules, cached by input.
pub fn merge(classes: &str) -> String {
    thread_local! {
        static DEFAULT: Merger = Merger::default();
    }
    DEFAULT.with(|m| m.merge(classes))
}

/// Theme scales, class groups and conflicts beyond tailwind-merge's defaults.
#[derive(Default)]
pub struct Extension {
    extra: Extra,
    conflicts: Vec<(String, Vec<String>)>,
}

impl Extension {
    pub fn new() -> Self {
        Self::default()
    }

    /// More values on a theme scale, e.g. `theme("spacing", ["18"])` so `p-18` is padding.
    pub fn theme<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        key: &str,
        values: I,
    ) -> Self {
        self.extra
            .theme
            .entry(key.to_owned())
            .or_default()
            .extend(values.into_iter().map(Into::into));
        self
    }

    /// Classes in a group, new or existing: `group("shadow", ["shadow-glow"])`.
    pub fn group<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        id: &str,
        classes: I,
    ) -> Self {
        let classes = classes.into_iter().map(Into::into).collect();
        self.extra.groups.push((id.to_owned(), classes));
        self
    }

    /// Groups that a class of `id` overrides.
    pub fn conflicts<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        id: &str,
        groups: I,
    ) -> Self {
        self.conflicts
            .push((id.to_owned(), groups.into_iter().map(Into::into).collect()));
        self
    }
}

/// tailwind-merge's rules, ready to merge class lists; one pass over the classes per new input.
pub struct Merger {
    trie: Trie,
    conflicts: HashMap<String, Vec<String>>,
    modifier_conflicts: HashMap<String, Vec<String>>,
    order_sensitive: HashSet<&'static str>,
    cache: RefCell<Cache>,
}

impl Default for Merger {
    fn default() -> Self {
        Merger::extend(Extension::default())
    }
}

impl Merger {
    /// The default rules with `ext` added.
    pub fn extend(ext: Extension) -> Merger {
        let pairs = |t: &[(&str, &[&str])]| -> HashMap<String, Vec<String>> {
            t.iter()
                .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
                .collect()
        };
        let mut conflicts = pairs(config::CONFLICTS);
        for (id, groups) in ext.conflicts {
            conflicts.entry(id).or_default().extend(groups);
        }
        Merger {
            trie: Trie::new(&ext.extra),
            conflicts,
            modifier_conflicts: pairs(config::MODIFIER_CONFLICTS),
            order_sensitive: config::ORDER_SENSITIVE.iter().copied().collect(),
            cache: RefCell::new(Cache::default()),
        }
    }

    /// `classes` with each class a later one overrides left out, in their order.
    pub fn merge(&self, classes: &str) -> String {
        if let Some(hit) = self.cache.borrow_mut().get(classes) {
            return hit;
        }
        let merged = self.merge_uncached(classes);
        self.cache
            .borrow_mut()
            .set(classes.to_owned(), merged.clone());
        merged
    }

    fn merge_uncached(&self, classes: &str) -> String {
        let mut seen: Vec<String> = Vec::new();
        let mut kept: Vec<&str> = Vec::new();
        for original in classes.split_whitespace().rev() {
            let p = parse(original);
            let mut postfix = p.postfix.is_some();
            let head = match p.postfix {
                Some(at) => p.base.get(..at.min(p.base.len())).unwrap_or(p.base),
                None => p.base,
            };
            let group = match self.trie.group(head) {
                Some(g) => g,
                None if !postfix => {
                    kept.push(original);
                    continue;
                }
                None => match self.trie.group(p.base) {
                    Some(g) => {
                        postfix = false;
                        g
                    }
                    None => {
                        kept.push(original);
                        continue;
                    }
                },
            };
            let variant = match p.modifiers.len() {
                0 => String::new(),
                1 => p.modifiers[0].to_owned(),
                _ => self.sort(&p.modifiers).join(":"),
            };
            let modifier = if p.important { variant + "!" } else { variant };
            let id = format!("{modifier}{group}");
            if seen.contains(&id) {
                continue;
            }
            seen.push(id);
            for g in self.conflicting(&group, postfix) {
                seen.push(format!("{modifier}{g}"));
            }
            kept.push(original);
        }
        kept.reverse();
        kept.join(" ")
    }

    fn conflicting(&self, group: &str, postfix: bool) -> Vec<&String> {
        let base = self.conflicts.get(group).into_iter().flatten();
        if postfix {
            if let Some(m) = self.modifier_conflicts.get(group) {
                return base.chain(m).collect();
            }
        }
        base.collect()
    }

    /// Plain modifiers sort alphabetically between arbitrary and order-sensitive ones, which stay put.
    fn sort<'a>(&self, modifiers: &[&'a str]) -> Vec<&'a str> {
        let mut out = Vec::with_capacity(modifiers.len());
        let mut run: Vec<&str> = Vec::new();
        for m in modifiers {
            if m.starts_with('[') || self.order_sensitive.contains(m) {
                run.sort_unstable();
                out.append(&mut run);
                out.push(*m);
            } else {
                run.push(m);
            }
        }
        run.sort_unstable();
        out.append(&mut run);
        out
    }
}

struct Parsed<'a> {
    modifiers: Vec<&'a str>,
    important: bool,
    base: &'a str,
    /// Where a `/` postfix starts in `base`, e.g. the `/50` of `bg-black/50`.
    postfix: Option<usize>,
}

/// Split modifiers off at top-level `:`, outside `[…]` and `(…)`.
fn parse(class: &str) -> Parsed<'_> {
    let mut modifiers = Vec::new();
    let (mut brackets, mut parens, mut start) = (0i32, 0i32, 0usize);
    let mut slash = None;
    for (i, c) in class.char_indices() {
        if brackets == 0 && parens == 0 {
            if c == ':' {
                modifiers.push(&class[start..i]);
                start = i + 1;
                continue;
            }
            if c == '/' {
                slash = Some(i);
                continue;
            }
        }
        match c {
            '[' => brackets += 1,
            ']' => brackets -= 1,
            '(' => parens += 1,
            ')' => parens -= 1,
            _ => {}
        }
    }
    let with_important = &class[start..];
    let (base, important) = if let Some(b) = with_important.strip_suffix('!') {
        (b, true)
    } else if let Some(b) = with_important.strip_prefix('!') {
        // Tailwind 3's leading `!`, still accepted.
        (b, true)
    } else {
        (with_important, false)
    };
    Parsed {
        modifiers,
        important,
        base,
        postfix: slash.filter(|&s| s > start && s > 0).map(|s| s - start),
    }
}

/// Two generations of results, as tailwind-merge keeps: full ones are dropped together.
#[derive(Default)]
struct Cache {
    now: HashMap<String, String>,
    before: HashMap<String, String>,
}

impl Cache {
    fn get(&mut self, key: &str) -> Option<String> {
        if let Some(v) = self.now.get(key) {
            return Some(v.clone());
        }
        let v = self.before.remove(key)?;
        self.set(key.to_owned(), v.clone());
        Some(v)
    }

    fn set(&mut self, key: String, value: String) {
        self.now.insert(key, value);
        if self.now.len() > config::CACHE_SIZE {
            self.before = std::mem::take(&mut self.now);
        }
    }
}
