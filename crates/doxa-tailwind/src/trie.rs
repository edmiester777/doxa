//! Which class group a class belongs to: a trie over its `-`-separated parts, with validators
//! for the values a part may take, built from tailwind-merge's config.

use std::collections::HashMap;

use crate::validators::Validator;

/// One entry of a class group, as tailwind-merge's config writes it.
pub(crate) enum Def {
    Class(&'static str),
    Valid(Validator),
    Theme(&'static str),
    Parts(&'static [(&'static str, &'static [Def])]),
}

pub(crate) mod config {
    use super::Def;
    use crate::validators::Validator;
    include!(concat!(env!("OUT_DIR"), "/config.rs"));
}

#[derive(Default)]
struct Part {
    next: HashMap<String, Part>,
    validators: Vec<(usize, Validator)>,
    group: Option<usize>,
}

impl Part {
    fn at(&mut self, path: &str) -> &mut Part {
        path.split('-')
            .fold(self, |p, part| p.next.entry(part.to_owned()).or_default())
    }
}

/// Theme scales and groups added to the defaults.
#[derive(Default)]
pub(crate) struct Extra {
    pub theme: HashMap<String, Vec<String>>,
    pub groups: Vec<(String, Vec<String>)>,
}

pub(crate) struct Trie {
    root: Part,
    names: Vec<String>,
}

impl Trie {
    pub(crate) fn new(extra: &Extra) -> Trie {
        let mut t = Trie {
            root: Part::default(),
            names: Vec::new(),
        };
        let mut root = std::mem::take(&mut t.root);
        for (name, defs) in config::GROUPS {
            let id = t.id(name);
            add(&mut root, defs, id, extra);
        }
        for (name, classes) in &extra.groups {
            let id = t.id(name);
            for c in classes {
                root.at(c).group = Some(id);
            }
        }
        t.root = root;
        t
    }

    fn id(&mut self, name: &str) -> usize {
        match self.names.iter().position(|n| n == name) {
            Some(i) => i,
            None => {
                self.names.push(name.to_owned());
                self.names.len() - 1
            }
        }
    }

    /// The group of a class without modifiers, e.g. `px` for `px-4`.
    pub(crate) fn group(&self, class: &str) -> Option<String> {
        if class.starts_with('[') && class.ends_with(']') && class.len() >= 2 {
            let content = &class[1..class.len() - 1];
            let property = &content[..content.find(':')?];
            return (!property.is_empty()).then(|| format!("arbitrary..{property}"));
        }
        let parts: Vec<&str> = class.split('-').collect();
        // `-inset-1`: a negative value's leading `-` isn't a part.
        let start = usize::from(parts[0].is_empty() && parts.len() > 1);
        find(&parts, start, &self.root).map(|i| self.names[i].clone())
    }
}

fn add(part: &mut Part, defs: &[Def], id: usize, extra: &Extra) {
    for d in defs {
        match d {
            Def::Class("") => part.group = Some(id),
            Def::Class(c) => part.at(c).group = Some(id),
            Def::Valid(v) => part.validators.push((id, *v)),
            Def::Theme(key) => {
                if let Some((_, scale)) = config::THEME.iter().find(|(k, _)| k == key) {
                    add(part, scale, id, extra);
                }
                for c in extra.theme.get(*key).into_iter().flatten() {
                    part.at(c).group = Some(id);
                }
            }
            Def::Parts(pairs) => {
                for (key, defs) in *pairs {
                    add(part.at(key), defs, id, extra);
                }
            }
        }
    }
}

fn find(parts: &[&str], at: usize, part: &Part) -> Option<usize> {
    if at == parts.len() {
        return part.group;
    }
    if let Some(found) = part
        .next
        .get(parts[at])
        .and_then(|n| find(parts, at + 1, n))
    {
        return Some(found);
    }
    if part.validators.is_empty() {
        return None;
    }
    let rest = parts[at..].join("-");
    part.validators
        .iter()
        .find(|(_, v)| v.check(&rest))
        .map(|(id, _)| *id)
}
